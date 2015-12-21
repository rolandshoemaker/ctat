package stats

import (
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/rolandshoemaker/ctat/common"
	"github.com/rolandshoemaker/ctat/filter"

	ct "github.com/jsha/certificatetransparency"
)

func ParsingErrors(cacheFile string, filtersString string) error {
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
		}
		if _, skip, err := common.ParseAndFilter(ent.Entry.X509Cert, filters); !skip && err != nil {
			xMu.Lock()
			if _, present := x509Errors[err.Error()]; present {
				x509Errors[err.Error()] = 0
			}
			x509Errors[err.Error()]++
			xMu.Unlock()
		}
	})

	fmt.Println("# CT parsing errors")
	for k, v := range ctErrors {
		fmt.Printf("\t%d\t%s\n", v, k)
	}
	fmt.Println("\n# X509 parsing errors")
	for k, v := range x509Errors {
		fmt.Printf("%d\t%s\n", v, k)
	}
	return nil
}

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

func ValidityDist(cacheFile string, filtersString string, resolution string, countCutoff int) error {
	entries, err := common.LoadCacheFile(cacheFile)
	if err != nil {
		return err
	}

	vMu := new(sync.Mutex)
	validity := make(map[int]int)
	var filters []filter.Filter
	if filtersString != "" {
		filters, err = filter.StringToFilters(filtersString)
		if err != nil {
			return err
		}
	}

	entries.Map(func(ent *ct.EntryAndPosition, err error) {
		if err != nil {
			return
		}
		cert, skip, err := common.ParseAndFilter(ent.Entry.X509Cert, filters)
		if skip || err != nil {
			return
		}
		period := 0
		switch resolution {
		case "hour":
			period = int((cert.NotAfter.Sub(cert.NotBefore)).Hours())
		case "day":
			period = int((cert.NotAfter.Sub(cert.NotBefore)).Hours() / 24)
		case "month":
			period = int((cert.NotAfter.Sub(cert.NotBefore)).Hours() / 24 / 30)
		}

		vMu.Lock()
		defer vMu.Unlock()
		if _, present := validity[period]; !present {
			validity[period] = 0
		}
		validity[period]++
	})

	dist := distribution{}
	sum := 0
	for k, v := range validity {
		if v > countCutoff {
			dist = append(dist, bucket{count: v, value: k})
			sum += v
		}
	}
	sort.Sort(dist)

	fmt.Println("# Validity distribution by", resolution)
	dist.print(fmt.Sprintf("Validity period (%ss)", resolution), sum)

	return nil
}

func EntryLengthDist(cacheFile string, filtersString string, countCutoff int) error {
	entries, err := common.LoadCacheFile(cacheFile)
	if err != nil {
		return err
	}

	lMu := new(sync.Mutex)
	lengths := make(map[int]int)
	var filters []filter.Filter
	if filtersString != "" {
		filters, err = filter.StringToFilters(filtersString)
		if err != nil {
			return err
		}
	}

	entries.Map(func(ent *ct.EntryAndPosition, err error) {
		if err != nil {
			return
		}
		_, skip, err := common.ParseAndFilter(ent.Entry.X509Cert, filters)
		if skip || err != nil {
			return
		}

		chainLen := len(ent.Entry.ExtraCerts) + 1
		lMu.Lock()
		defer lMu.Unlock()
		if _, present := lengths[chainLen]; !present {
			lengths[chainLen] = 0
		}
		lengths[chainLen]++
	})

	fmt.Println(lengths)
	dist := distribution{}
	sum := 0
	for k, v := range lengths {
		if v > countCutoff {
			dist = append(dist, bucket{count: v, value: k})
			sum += v
		}
	}
	sort.Sort(dist)

	fmt.Println("# Entry length distribution")
	dist.print("Num certificates", sum)

	return nil
}

func CertSizeDist(cacheFile string, filtersString string, countCutoff int, resolution int) error {
	entries, err := common.LoadCacheFile(cacheFile)
	if err != nil {
		return err
	}

	sMu := new(sync.Mutex)
	sizes := make(map[int]int)
	var filters []filter.Filter
	if filtersString != "" {
		filters, err = filter.StringToFilters(filtersString)
		if err != nil {
			return err
		}
	}

	factor := math.Pow(10, float64(resolution))
	entries.Map(func(ent *ct.EntryAndPosition, err error) {
		if err != nil {
			return
		}
		_, skip, err := common.ParseAndFilter(ent.Entry.X509Cert, filters)
		if skip || err != nil {
			return
		}

		certSize := int(math.Ceil(float64(len(ent.Entry.X509Cert))/factor)) * int(factor)
		sMu.Lock()
		defer sMu.Unlock()
		if _, present := sizes[certSize]; !present {
			sizes[certSize] = 0
		}
		sizes[certSize]++
	})

	dist := distribution{}
	sum := 0
	for k, v := range sizes {
		if v > countCutoff {
			dist = append(dist, bucket{count: v, value: k})
			sum += v
		}
	}
	sort.Sort(dist)

	fmt.Println("# Certificate size distribution")
	dist.print("Size (bytes)", sum)

	return nil
}
