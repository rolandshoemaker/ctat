package filter

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

var FilterMap = map[string]Filter{
	"valid":    ValidityFilter,
	"ocspGood": OCSPGood,
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

func ValidityFilter(cert *x509.Certificate) (bool, error) {
	if time.Now().After(cert.NotAfter) {
		return true, nil
	}
	return false, nil
}

var ilMu = new(sync.Mutex)
var issuerLookupMap = map[string]*x509.Certificate{}

func OCSPGood(cert *x509.Certificate) (bool, error) {
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return false, nil
	}
	if len(cert.OCSPServer) == 0 {
		return false, nil
	}
	ocspServer := cert.OCSPServer[0]
	var issuer *x509.Certificate
	if cert.Subject.CommonName == cert.Issuer.CommonName {
		issuer = cert
	} else if len(cert.IssuingCertificateURL) > 0 {
		ilMu.Lock()
		defer ilMu.Unlock()
		if _, present := issuerLookupMap[cert.IssuingCertificateURL[0]]; !present {
			resp, err := http.Get(cert.IssuingCertificateURL[0])
			if err != nil {
				return true, err
			}
			defer resp.Body.Close()
			rawCert, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return true, err
			}
			issuerLookupMap[cert.IssuingCertificateURL[0]], err = x509.ParseCertificate(rawCert)
			if err != nil {
				return true, err
			}
		}
		issuer = issuerLookupMap[cert.IssuingCertificateURL[0]]
	}
	if issuer == nil {
		// return false since no way to check revocation (at least with OCSP) can be found
		return false, nil
	}

	// check ocsp
	ocspReq, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{})
	if err != nil {
		return true, err
	}
	resp, err := http.Post(ocspServer, "application/ocsp-request", bytes.NewBuffer(ocspReq))
	if err != nil {
		return true, err
	}
	defer resp.Body.Close()
	ocspBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	ocspResp, err := ocsp.ParseResponse(ocspBody, issuer)
	if err != nil {
		return true, err
	}
	if ocspResp.Status != ocsp.Good {
		return true, nil
	}
	return false, nil
}
