package stats

import (
	"crypto/x509"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"text/tabwriter"

	"github.com/rolandshoemaker/ctat/common"
	"github.com/rolandshoemaker/ctat/filter"

	ct "github.com/jsha/certificatetransparency"
)

type bucket struct {
	value int
	count int
}

type distribution []bucket

func (d distribution) Len() int           { return len(d) }
func (d distribution) Swap(i, j int)      { d[i], d[j] = d[j], d[i] }
func (d distribution) Less(i, j int) bool { return d[i].value < d[j].value }

func (d distribution) print(valueLabel string, sum int) {
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintf(w, "Count\t\t%s\n", valueLabel)
	maxWidth := 100.0
	for _, b := range d {
		percent := float64(b.count) / float64(sum)
		fmt.Fprintf(w, "%d\t%.4f%%\t%d\t%s\n", b.count, percent*100.0, b.value, strings.Repeat("*", int(maxWidth*percent)))
	}
	w.Flush()
}

var metrics = map[string]metricGenerator{}

type metricGenerator interface {
	process(*x509.Certificate)
	print()
}

type certSizeDistribution struct {
	sizes map[int]int
	mu    sync.Mutex
}

func (csd *certSizeDistribution) process(cert *x509.Certificate) {
	certSize := int(math.Ceil(float64(len(cert.Raw))/100)) * int(100)
	csd.mu.Lock()
	defer csd.mu.Unlock()
	if _, present := csd.sizes[certSize]; !present {
		csd.sizes[certSize] = 0
	}
	csd.sizes[certSize]++
}

func (csd *certSizeDistribution) print() {
	dist := distribution{}
	sum := 0
	for k, v := range csd.sizes {
		dist = append(dist, bucket{count: v, value: k})
		sum += v
	}
	sort.Sort(dist)

	fmt.Println("# Certificate size distribution")
	dist.print("Size (bytes)", sum)
}

type validityDistribution struct {
	periods map[int]int
	mu      sync.Mutex
}

func (vd *validityDistribution) process(cert *x509.Certificate) {
	period := 0
	period = int((cert.NotAfter.Sub(cert.NotBefore)).Hours() / 24 / 30)

	vd.mu.Lock()
	defer vd.mu.Unlock()
	if _, present := vd.periods[period]; !present {
		vd.periods[period] = 0
	}
	vd.periods[period]++
}

func (vd *validityDistribution) print() {
	dist := distribution{}
	sum := 0
	for k, v := range vd.periods {
		dist = append(dist, bucket{count: v, value: k})
		sum += v
	}
	sort.Sort(dist)

	fmt.Println("# Validity period distribution")
	dist.print("Validity period (months)", sum)
}

type nameMetrics struct {
	nMu        sync.Mutex
	names      map[string]int
	totalNames int64

	nsMu          sync.Mutex
	nameSets      map[string]int
	totalNameSets int64
}

func (nm *nameMetrics) process(cert *x509.Certificate) {
	atomic.AddInt64(&nm.totalNameSets, 1)
	atomic.AddInt64(&nm.totalNames, int64(len(cert.DNSNames)))
	sort.Strings(cert.DNSNames)
	nameSet := strings.Join(cert.DNSNames, ",")
	nm.nsMu.Lock()
	if _, present := nm.nameSets[nameSet]; !present {
		nm.nameSets[nameSet] = 0
	}
	nm.nameSets[nameSet]++
	nm.nsMu.Unlock()
	for _, name := range cert.DNSNames {
		nm.nMu.Lock()
		if _, present := nm.names[name]; !present {
			nm.names[name] = 0
		}
		nm.names[name]++
		nm.nMu.Unlock()
	}
}

func (nm *nameMetrics) print() {
	fmt.Printf("# DNS name metrics\n\n")
	fmt.Printf("%d names across %d certificates\n", nm.totalNames, nm.totalNameSets)
	fmt.Printf(
		"%.2f%% of names existed in multiple certificates\n%.2f%% of certificates had duplicate name sets\n",
		(1.0-(float64(len(nm.names))/float64(nm.totalNames)))*100.0,
		(1.0-(float64(len(nm.nameSets))/float64(nm.totalNameSets)))*100.0,
	)
}

func Analyse(cacheFile string, filtersString string) error {
	generators := []metricGenerator{
		&validityDistribution{periods: make(map[int]int)},
		&certSizeDistribution{sizes: make(map[int]int)},
		&nameMetrics{names: make(map[string]int), nameSets: make(map[string]int)},
	}

	entries, err := common.LoadCacheFile(cacheFile)
	if err != nil {
		return err
	}

	cMu := new(sync.Mutex)
	ctErrors := make(map[string]int)
	xMu := new(sync.Mutex)
	x509Errors := make(map[string]int)
	var filters []filter.Filter
	if filtersString != "" {
		filters, err = filter.StringToFilters(filtersString)
		if err != nil {
			return err
		}
	}

	entries.Map(func(ent *ct.EntryAndPosition, err error) {
		if err != nil {
			cMu.Lock()
			if _, present := ctErrors[err.Error()]; !present {
				ctErrors[err.Error()] = 0
			}
			ctErrors[err.Error()]++
			cMu.Unlock()
			return
		}
		// execute CT entry metric stuff (TODO)
		cert, skip, err := common.ParseAndFilter(ent.Entry.X509Cert, filters)
		if !skip && err != nil {
			xMu.Lock()
			if _, present := x509Errors[err.Error()]; present {
				x509Errors[err.Error()] = 0
			}
			x509Errors[err.Error()]++
			xMu.Unlock()
			return
		} else if err == nil && skip {
			return
		}
		// execute leaf metric generators
		for _, g := range generators {
			g.process(cert)
		}
	})

	for _, g := range generators {
		g.print()
		fmt.Println("")
	}

	return nil
}
