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

type intBucket struct {
	value int
	count int
}

type intDistribution []intBucket

func (d intDistribution) Len() int           { return len(d) }
func (d intDistribution) Swap(i, j int)      { d[i], d[j] = d[j], d[i] }
func (d intDistribution) Less(i, j int) bool { return d[i].value < d[j].value }

func (d intDistribution) print(valueLabel string, sum int) {
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

type strBucket struct {
	value string
	count int
}

type strDistribution []strBucket

func (d strDistribution) Len() int           { return len(d) }
func (d strDistribution) Swap(i, j int)      { d[i], d[j] = d[j], d[i] }
func (d strDistribution) Less(i, j int) bool { return d[i].value < d[j].value }

func (d strDistribution) print(valueLabel string, sum int) {
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintf(w, "Count\t\t%s\n", valueLabel)
	maxWidth := 100.0
	for _, b := range d {
		percent := float64(b.count) / float64(sum)
		fmt.Fprintf(w, "%d\t%.4f%%\t%s\t%s\n", b.count, percent*100.0, b.value, strings.Repeat("*", int(maxWidth*percent)))
	}
	w.Flush()
}

var metricsLookup = map[string]metricGenerator{
	"validityDist": &validityDistribution{periods: make(map[int]int)},
	"certSizeDist": &certSizeDistribution{sizes: make(map[int]int)},
	"nameMetrics":  &nameMetrics{names: make(map[string]int), nameSets: make(map[string]int)},
	"sanSizeDist":  &sanSizeDistribution{sizes: make(map[int]int)},
	"pkTypeDist":   &pkAlgDistribution{algs: make(map[string]int)},
	"sigTypeDist":  &sigAlgDistribution{algs: make(map[string]int)},
}

func StringToMetrics(metricsString string) ([]metricGenerator, error) {
	var metrics []metricGenerator
	for _, metricName := range strings.Split(metricsString, ",") {
		if generator, present := metricsLookup[metricName]; present {
			metrics = append(metrics, generator)
		} else if !present {
			return nil, fmt.Errorf("invalid metric name")
		}
	}
	if len(metrics) == 0 {
		return nil, fmt.Errorf("at least one metric is required to continue")
	}
	return metrics, nil
}

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
	dist := intDistribution{}
	sum := 0
	for k, v := range csd.sizes {
		dist = append(dist, intBucket{count: v, value: k})
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
	period := int((cert.NotAfter.Sub(cert.NotBefore)).Hours() / 24 / 30)

	vd.mu.Lock()
	defer vd.mu.Unlock()
	if _, present := vd.periods[period]; !present {
		vd.periods[period] = 0
	}
	vd.periods[period]++
}

func (vd *validityDistribution) print() {
	dist := intDistribution{}
	sum := 0
	for k, v := range vd.periods {
		dist = append(dist, intBucket{count: v, value: k})
		sum += v
	}
	sort.Sort(dist)

	fmt.Println("# Validity period distribution")
	dist.print("Validity period (months)", sum)
}

type sanSizeDistribution struct {
	sizes map[int]int
	mu    sync.Mutex
}

func (ssd *sanSizeDistribution) process(cert *x509.Certificate) {
	size := len(cert.DNSNames)
	ssd.mu.Lock()
	defer ssd.mu.Unlock()
	if _, present := ssd.sizes[size]; !present {
		ssd.sizes[size] = 0
	}
	ssd.sizes[size]++
}

func (ssd *sanSizeDistribution) print() {
	dist := intDistribution{}
	sum := 0
	for k, v := range ssd.sizes {
		dist = append(dist, intBucket{count: v, value: k})
		sum += v
	}
	sort.Sort(dist)

	fmt.Println("# SAN num distribution")
	dist.print("Number of SANs", sum)
}

var pkAlgToString = map[x509.PublicKeyAlgorithm]string{
	0: "Unknown",
	1: "RSA",
	2: "DSA",
	3: "ECDSA",
}

type pkAlgDistribution struct {
	algs map[string]int
	mu   sync.Mutex
}

func (pad *pkAlgDistribution) process(cert *x509.Certificate) {
	alg, ok := pkAlgToString[cert.PublicKeyAlgorithm]
	if !ok {
		return
	}
	pad.mu.Lock()
	defer pad.mu.Unlock()
	if _, present := pad.algs[alg]; !present {
		pad.algs[alg] = 0
	}
	pad.algs[alg]++
}

func (pad *pkAlgDistribution) print() {
	dist := strDistribution{}
	sum := 0
	for k, v := range pad.algs {
		dist = append(dist, strBucket{count: v, value: k})
		sum += v
	}
	sort.Sort(dist)

	fmt.Println("# Public key type distribution")
	dist.print("Type", sum)
}

var sigAlgToString = map[x509.SignatureAlgorithm]string{
	0:  "Unknown",
	1:  "MD2 With RSA",
	2:  "MD5 With RSA",
	3:  "SHA1 With RSA",
	4:  "SHA256 With RSA",
	5:  "SHA384 With RSA",
	6:  "SHA512 With RSA",
	7:  "DSA With SHA1",
	8:  "DSA With SHA256",
	9:  "ECDSA With SHA1",
	10: "ECDSA With SHA256",
	11: "ECDSA With SHA384",
	12: "ECDSA With SHA512",
}

type sigAlgDistribution struct {
	algs map[string]int
	mu   sync.Mutex
}

func (sad *sigAlgDistribution) process(cert *x509.Certificate) {
	alg, ok := sigAlgToString[cert.SignatureAlgorithm]
	if !ok {
		return
	}
	sad.mu.Lock()
	defer sad.mu.Unlock()
	if _, present := sad.algs[alg]; !present {
		sad.algs[alg] = 0
	}
	sad.algs[alg]++
}

func (sad *sigAlgDistribution) print() {
	dist := strDistribution{}
	sum := 0
	for k, v := range sad.algs {
		dist = append(dist, strBucket{count: v, value: k})
		sum += v
	}
	sort.Sort(dist)

	fmt.Println("# Signature type distribution")
	dist.print("Type", sum)
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

func Analyse(cacheFile string, filtersString string, generators []metricGenerator) error {
	entries, err := common.LoadCacheFile(cacheFile)
	if err != nil {
		return err
	}

	var filters []filter.Filter
	if filtersString != "" {
		filters, err = filter.StringToFilters(filtersString)
		if err != nil {
			return err
		}
	}

	cMu := new(sync.Mutex)
	ctErrors := make(map[string]int)
	xMu := new(sync.Mutex)
	x509Errors := make(map[string]int)
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
		wg := new(sync.WaitGroup)
		for _, g := range generators {
			wg.Add(1)
			go func(mg metricGenerator) {
				mg.process(cert)
				wg.Done()
			}(g)
		}
		wg.Wait()
	})

	for _, g := range generators {
		g.print()
		fmt.Println("")
	}

	return nil
}

// features usage metrics
// CT extension OID     -- 1.3.6.1.4.1.11129.2.4.2
// OCSP must staple OID -- 1.3.6.1.5.5.7.1.24
