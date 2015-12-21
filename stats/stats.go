package stats

import (
	"fmt"
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

type validityPeriod struct {
	period int
	count  int
}

type validityDistribution []validityPeriod

func (v validityDistribution) Len() int           { return len(v) }
func (v validityDistribution) Swap(i, j int)      { v[i], v[j] = v[j], v[i] }
func (v validityDistribution) Less(i, j int) bool { return v[i].period < v[j].period }

func ValidityDist(cacheFile string, filtersString string, resolution string) error {
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

	dist := validityDistribution{}
	sum := 0
	for k, v := range validity {
		dist = append(dist, validityPeriod{count: v, period: k})
		sum += v
	}
	sort.Sort(dist)

	fmt.Println("# Validity distribution by", resolution)

	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintf(w, "Count\t\tValidity period (%ss)\n", resolution)
	maxWidth := 100.0
	for _, b := range dist {
		percent := float64(b.count) / float64(sum)
		fmt.Fprintf(w, "%d\t%.4f%%\t%d\t%s\n", b.count, percent*100.0, b.period, strings.Repeat("*", int(maxWidth*percent)))
	}
	w.Flush()

	return nil
}
