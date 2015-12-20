package common

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"os"
	"strings"

	"github.com/rolandshoemaker/ctat/filter"

	ct "github.com/jsha/certificatetransparency"
)

func escape(str string) string {
	return strings.Replace(str, ",", " -", -1)
}

func SubjectToString(subject pkix.Name) string {
	out := []string{}
	if subject.CommonName != "" {
		out = append(out, fmt.Sprintf("CN=%s", escape(subject.CommonName)))
	}
	if len(subject.Organization) != 0 {
		out = append(out, fmt.Sprintf("O=[%s]", escape(strings.Join(subject.Organization, " -- "))))
	}
	if len(subject.OrganizationalUnit) != 0 {
		out = append(out, fmt.Sprintf("OU=[%s]", escape(strings.Join(subject.OrganizationalUnit, " -- "))))
	}
	if len(subject.Locality) != 0 {
		out = append(out, fmt.Sprintf("L=[%s]", escape(strings.Join(subject.Locality, " -- "))))
	}
	if len(subject.Province) != 0 {
		out = append(out, fmt.Sprintf("ST=[%s]", escape(strings.Join(subject.Province, " -- "))))
	}
	if len(subject.Country) != 0 {
		out = append(out, fmt.Sprintf("C=[%s]", escape(strings.Join(subject.Country, " -- "))))
	}
	if len(out) == 0 {
		return "???"
	}
	return strings.Join(out, "; ")
}

func ParseAndFilter(rawCert []byte, filters []filter.Filter) (*x509.Certificate, bool, error) {
	cert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		return nil, false, err
	}
	for _, f := range filters {
		if skip, err := f(cert); skip || err != nil {
			return nil, skip, err
		}
	}
	return cert, false, nil
}

func LoadCacheFile(filename string) (*ct.EntriesFile, error) {
	ctFile, err := os.OpenFile(filename, os.O_RDONLY, 0666)
	if err != nil {
		return nil, fmt.Errorf("failed to open CT cache file: %s", err)
	}
	return &ct.EntriesFile{ctFile}, nil
}
