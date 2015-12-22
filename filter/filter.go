package filter

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

var FilterMap = map[string]Filter{
	"unexpired": UnexpiredFilter,
	"expired":   ExpiredFilter,
	"caOnly":    CAOnlyFilter,
	"leafOnly":  LeafOnlyFilter,
}

type Filter func(*x509.Certificate) (bool, error)

func StringToFilters(arg string) ([]Filter, error) {
	filters := []Filter{}
	for _, a := range strings.Split(arg, ",") {
		if filter, present := FilterMap[a]; present {
			filters = append(filters, filter)
		} else if !present {
			return nil, fmt.Errorf("invalid filter")
		}
	}
	return filters, nil
}

func UnexpiredFilter(cert *x509.Certificate) (bool, error) {
	if time.Now().After(cert.NotAfter) {
		return true, nil
	}
	return false, nil
}

func ExpiredFilter(cert *x509.Certificate) (bool, error) {
	if !time.Now().After(cert.NotAfter) {
		return true, nil
	}
	return false, nil
}

func CAOnlyFilter(cert *x509.Certificate) (bool, error) {
	if !cert.IsCA {
		return true, nil
	}
	return false, nil
}

func LeafOnlyFilter(cert *x509.Certificate) (bool, error) {
	if cert.IsCA {
		return true, nil
	}
	return false, nil
}
