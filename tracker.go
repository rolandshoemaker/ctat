package main

import (
	"crypto/sha256"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	ct "github.com/jsha/certificatetransparency"
)

type testEntry struct {
	leaf *x509.Certificate
}

type tester struct {
	totalCerts     int
	processedCerts int64
	totalNames     int
	processedNames int64

	namesUnavailable   int64
	namesHTTPSDisabled int64
	namesCertNotUsed   int64

	certsUnused        int64
	certsPartiallyUsed int64
	certsTotallyUsed   int64

	workers int

	entries chan *testEntry

	client *http.Client
}

type result struct {
	hostAvailable bool
	httpsEnabled  bool
	certUsed      bool
	properlySetup bool
}

func (t *tester) processResults(results []result) {
	used := 0
	for _, r := range results {
		if !r.hostAvailable {
			atomic.AddInt64(&t.namesUnavailable, 1)
			continue
		}
		if !r.httpsEnabled {
			atomic.AddInt64(&t.namesHTTPSDisabled, 1)
			continue
		}
		if !r.certUsed {
			atomic.AddInt64(&t.namesCertNotUsed, 1)
			continue
		}
		used++
	}
	if used == len(results) {
		atomic.AddInt64(&t.certsTotallyUsed, 1)
	} else if used < len(results) && used > 0 {
		atomic.AddInt64(&t.certsPartiallyUsed, 1)
	} else if used == 0 {
		atomic.AddInt64(&t.certsUnused, 1)
	}
}

func (t *tester) printProgress(stop chan bool) {
	prog := ""
	for {
		select {
		case <-stop:
			return
		default:
			processedCerts := atomic.LoadInt64(&t.processedCerts)
			processedNames := atomic.LoadInt64(&t.processedNames)
			namesUnavailable := atomic.LoadInt64(&t.namesUnavailable)
			namesHTTPSDisabled := atomic.LoadInt64(&t.namesHTTPSDisabled)
			namesCertsNotUsed := atomic.LoadInt64(&t.namesCertNotUsed)
			certsUnused := atomic.LoadInt64(&t.certsUnused)
			certsPartiallyUsed := atomic.LoadInt64(&t.certsPartiallyUsed)
			certsTotallyUsed := atomic.LoadInt64(&t.certsTotallyUsed)

			if prog != "" {
				fmt.Fprintf(os.Stdout, strings.Repeat("\b", len(prog)))
			}
			prog = fmt.Sprintf(
				"%d/%d certificates checked (%d/%d names) names unavailable: %d, names redirected to http: %d, names not using expected cert: %d, unused certificates: %d, partially used certificates: %d, totally used certificates: %d",
				processedCerts,
				t.totalCerts,
				processedNames,
				t.totalNames,
				namesUnavailable,
				namesHTTPSDisabled,
				namesCertsNotUsed,
				certsUnused,
				certsPartiallyUsed,
				certsTotallyUsed,
			)
			fmt.Fprintf(os.Stdout, prog)
			time.Sleep(time.Second)
		}
	}
}

func (t *tester) printStats() {
	fmt.Println("\n# adoption statistics")
	fmt.Printf("%d certificates checked (totalling %d DNS names)\n", t.totalCerts, t.totalNames)
	fmt.Printf("%d (%.2f%%) of names couldn't be connected to\n", t.namesUnavailable, float64(t.namesUnavailable)/float64(t.totalNames))
	fmt.Printf("%d (%.2f%%) of names redirected to HTTP\n", t.namesHTTPSDisabled, float64(t.namesHTTPSDisabled)/float64(t.totalNames))
	fmt.Printf("%d (%.2f%%) of names didn't use the expected certificate\n", t.namesCertNotUsed, float64(t.namesCertNotUsed)/float64(t.totalNames))
	fmt.Println()
	fmt.Printf("%d (%.2f%%) of certificates were unused by all their names\n", t.certsUnused, float64(t.certsUnused)/float64(t.totalCerts))
	fmt.Printf("%d (%.2f%%) of certificates were partially used by their names\n", t.certsPartiallyUsed, float64(t.certsPartiallyUsed)/float64(t.totalCerts))
	fmt.Printf("%d (%.2f%%) of certificates were used for all their names\n", t.certsTotallyUsed, float64(t.certsTotallyUsed)/float64(t.totalCerts))
}

func (t *tester) checkName(dnsName string, expectedFP [32]byte) (r result) {
	defer atomic.AddInt64(&t.processedNames, 1)
	resp, err := t.client.Get(fmt.Sprintf("https://%s", dnsName))
	if err != nil {
		// this should probably retry on some set of errors :/
		return
	}
	defer resp.Body.Close()
	r.hostAvailable = true
	if resp.TLS == nil {
		return
	}
	r.httpsEnabled = true
	for _, peer := range resp.TLS.PeerCertificates {
		if sha256.Sum256(peer.Raw) != expectedFP {
			r.certUsed = true
		}
	}
	return
}

func (t *tester) checkCert(cert *x509.Certificate) {
	defer atomic.AddInt64(&t.processedCerts, 1)
	fp := sha256.Sum256(cert.Raw)
	var results []result
	for _, name := range cert.DNSNames {
		results = append(results, t.checkName(name, fp))
	}
	go t.processResults(results)
}

func (t *tester) begin() {
	fmt.Printf("beginning adoption scan [%d certificates, %d names]\n", t.totalCerts, t.totalNames)
	stop := make(chan bool, 1)
	go t.printProgress(stop)
	wg := new(sync.WaitGroup)
	started := time.Now()
	for i := 0; i < t.workers; i++ {
		wg.Add(1)
		go func() {
			for te := range t.entries {
				t.checkCert(te.leaf)
			}
			wg.Done()
		}()
	}
	wg.Wait()
	stop <- true
	fmt.Printf("scan finished, took %s\n", time.Since(started))
}

func loadAndUpdate(logURL, logKey, filename, issuerFilter string, dontUpdate bool) (chan *testEntry, int) {
	pemPublicKey := fmt.Sprintf(`-----BEGIN PUBLIC KEY-----
%s
-----END PUBLIC KEY-----`, logKey)
	ctLog, err := ct.NewLog(logURL, pemPublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize log: %s\n", err)
		os.Exit(1)
	}

	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open entries file: %s\n", err)
		os.Exit(1)
	}
	defer file.Close()

	entriesFile := ct.EntriesFile{file}

	sth, err := ctLog.GetSignedTreeHead()
	if err != nil {
		fmt.Fprintf(os.Stderr, "GetSignedTreeHead: %s\n", err)
		os.Exit(1)
	}

	count, err := entriesFile.Count()
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nFailed to read entries file: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("local entries: %d, remote entries: %d at %s\n", count, sth.Size, sth.Time.Format(time.ANSIC))
	if !dontUpdate && count < sth.Size {
		fmt.Println("updating local cache...")
		_, err = ctLog.DownloadRange(file, nil, count, sth.Size)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nFailed to update CT log: %s\n", err)
			os.Exit(1)
		}
	}
	entriesFile.Seek(0, 0)

	fmt.Printf("filtering local cache for certificates with issuer '%s'\n", issuerFilter)
	filtered := make(chan *testEntry, sth.Size)
	numNames := 0
	entriesFile.Map(func(ent *ct.EntryAndPosition, err error) {
		if err != nil {
			return
		}
		cert, err := x509.ParseCertificate(ent.Entry.X509Cert)
		if err != nil {
			return
		}
		if cert.Issuer.CommonName != issuerFilter {
			return
		}
		if time.Now().After(cert.NotAfter) {
			return
		}
		numNames += len(cert.DNSNames)
		filtered <- &testEntry{leaf: cert}
	})
	close(filtered)
	return filtered, numNames
}

func main() {
	logURL := flag.String("logURL", "https://log.certly.io", "url of CT log")
	logKey := flag.String("logKey", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECyPLhWKYYUgEc+tUXfPQB4wtGS2MNvXrjwFCCnyYJifBtd2Sk7Cu+Js9DNhMTh35FftHaHu6ZrclnNBKwmbbSA==", "base64-encoded CT log key")
	filename := flag.String("cacheFile", "certly.log", "file in which to cache log data.")
	issuerFilter := flag.String("issuerFilter", "Let's Encrypt Authority X1", "common name of issuer to use as a filter")
	scanners := flag.Int("scanners", 50, "number of scanner workers to run")
	dontUpdateCache := flag.Bool("dontUpdateCache", false, "don't update the local log cache")
	flag.Parse()

	entries, numNames := loadAndUpdate(*logURL, *logKey, *filename, *issuerFilter, *dontUpdateCache)
	client := new(http.Client)
	client.Transport = &http.Transport{
		Dial: (&net.Dialer{
			Timeout:   15 * time.Second, // making lots of calls...
			KeepAlive: 5 * time.Second,  // requests for similar names *should* be tightly grouped
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	t := tester{
		entries:    entries,
		totalCerts: len(entries),
		totalNames: numNames,
		client:     new(http.Client),
		workers:    *scanners,
	}
	t.begin()
	t.printStats()
}
