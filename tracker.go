package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
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
	totalNames     int64
	processedNames int64

	progPrintInterval float64

	namesUnavailable      int64
	namesHTTPSDisabled    int64
	namesTLSError         int64
	namesUsingInvalidCert int64
	namesCertNotUsed      int64

	certsUnused        int64
	certsPartiallyUsed int64
	certsTotallyUsed   int64

	workers int

	entries chan *testEntry

	dialerTimeout time.Duration

	debug             bool
	dontPrintProgress bool
}

type result struct {
	skipped          bool
	hostAvailable    bool
	httpsEnabled     bool
	tlsError         bool
	usingInvalidCert bool
	certUsed         bool
	properlySetup    bool
}

func (t *tester) processResults(results []result) {
	used := 0
	for _, r := range results {
		if r.skipped {
			continue
		}
		if !r.hostAvailable {
			atomic.AddInt64(&t.namesUnavailable, 1)
			continue
		}
		if !r.httpsEnabled {
			atomic.AddInt64(&t.namesHTTPSDisabled, 1)
			continue
		}
		if r.tlsError {
			atomic.AddInt64(&t.namesTLSError, 1)
			continue
		}
		if r.usingInvalidCert {
			atomic.AddInt64(&t.namesUsingInvalidCert, 1)
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
	processedCertsLast := int64(0)
	processedNamesLast := int64(0)
	for {
		select {
		case <-stop:
			return
		default:
			processedCerts := atomic.LoadInt64(&t.processedCerts)
			processedNames := atomic.LoadInt64(&t.processedNames)
			newCerts := processedCerts - processedCertsLast
			newNames := processedNames - processedNamesLast
			eta := "???"
			if newNames > 0 {
				eta = (time.Second * time.Duration((float64(t.totalNames) / (float64(newNames) / t.progPrintInterval)))).String()
			}
			if prog != "" {
				fmt.Fprintf(os.Stdout, strings.Repeat("\b", len(prog)))
			}
			prog = fmt.Sprintf(
				"%d/%d certificates checked, %d/%d names [%.2f cps, %.2f nps, eta: %s]",
				atomic.LoadInt64(&t.processedCerts),
				t.totalCerts,
				atomic.LoadInt64(&t.processedNames),
				t.totalNames,
				float64(newCerts)/t.progPrintInterval,
				float64(newNames)/t.progPrintInterval,
				eta,
			)
			fmt.Fprintf(os.Stdout, prog)
			time.Sleep(time.Second * time.Duration(t.progPrintInterval))
			processedCertsLast = processedCerts
			processedNamesLast = processedNames
		}
	}
}

func (t *tester) printStats() {
	fmt.Println("\n# adoption statistics")
	fmt.Printf("%d certificates checked (totalling %d DNS names)\n", t.totalCerts, t.totalNames)
	fmt.Printf("%d (%.2f%%) of names couldn't be connected to\n", t.namesUnavailable, (float64(t.namesUnavailable)/float64(t.totalNames))*100.0)
	fmt.Printf("%d (%.2f%%) of names don't serve HTTPS\n", t.namesHTTPSDisabled, (float64(t.namesHTTPSDisabled)/float64(t.totalNames))*100.0)
	fmt.Printf("%d (%.2f%%) of names threw a TLS error\n", t.namesTLSError, (float64(t.namesTLSError)/float64(t.totalNames))*100.0)
	fmt.Printf("%d (%.2f%%) of names used an invalid certificate\n", t.namesUsingInvalidCert, (float64(t.namesUsingInvalidCert)/float64(t.totalNames))*100.0)
	fmt.Printf("%d (%.2f%%) of names didn't use the expected certificate\n", t.namesCertNotUsed, (float64(t.namesCertNotUsed)/float64(t.totalNames))*100.0)
	fmt.Println()
	fmt.Printf("%d (%.2f%%) of certificates were used by none of their names\n", t.certsUnused, (float64(t.certsUnused)/float64(t.totalCerts))*100.0)
	fmt.Printf("%d (%.2f%%) of certificates were used by some of their names\n", t.certsPartiallyUsed, (float64(t.certsPartiallyUsed)/float64(t.totalCerts))*100.0)
	fmt.Printf("%d (%.2f%%) of certificates were used by all of their names\n", t.certsTotallyUsed, (float64(t.certsTotallyUsed)/float64(t.totalCerts))*100.0)
}

func (t *tester) checkName(dnsName string, expectedFP [32]byte) (r result) {
	defer atomic.AddInt64(&t.processedNames, 1)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: t.dialerTimeout}, "tcp", fmt.Sprintf("%s:443", dnsName), nil)
	if err != nil {
		// this should probably retry on some set of errors :/		// it should also check the error since this provides useful information beyond 'unavailable'
		if t.debug {
			fmt.Printf("Connection to [%s] failed: %s\n", dnsName, err)
		}
		// Check if the error failed because connection was refused / timed out / DNS broke
		if netErr, ok := err.(*net.OpError); ok {
			if netErr.Timeout() || netErr.Temporary() {
				r.skipped = true
			}
			if dnsErr, ok := netErr.Err.(*net.DNSError); ok {
				if dnsErr.Timeout() || dnsErr.Temporary() {
					r.skipped = true
				}
			}
			// Hosts that don't serve HTTPS are marked unavailable (this should be noted elsewhere...)
			return
		}
		r.hostAvailable = true
		if err.Error() == "EOF" {
			// ??? (maybe this indicates not serving HTTPS in some situations? idk)
			return
		}
		r.httpsEnabled = true
		// Check if the error was TLS related
		if strings.HasPrefix(err.Error(), "tls:") {
			r.tlsError = true
			return
		}
		// this should really break down the "x509: " errors more, not-trusted/wrong name/expired etc...
		// can use the x509.XXXError types to easily(ish) check this!
		r.usingInvalidCert = true
		return
	}
	r.hostAvailable = true
	defer conn.Close()
	state := conn.ConnectionState()
	if !state.HandshakeComplete {
		return
	}
	r.httpsEnabled = true
	for _, peer := range state.PeerCertificates {
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
	t.processResults(results)
}

func (t *tester) begin() {
	fmt.Printf("beginning adoption scan of %d certificates (%d names)\n", t.totalCerts, t.totalNames)
	stop := make(chan bool, 1)
	if !t.debug && !t.dontPrintProgress {
		go t.printProgress(stop)
	}
	wg := new(sync.WaitGroup)
	started := time.Now()
	for i := 0; i < t.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for te := range t.entries {
				t.checkCert(te.leaf)
			}
		}()
	}
	wg.Wait()
	stop <- true
	fmt.Printf("\n\nscan finished, took %s\n", time.Since(started))
}

func loadAndUpdate(logURL, logKey, filename, issuerFilter string, dontUpdate bool) (chan *testEntry, int64) {
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

	fmt.Printf("filtering local cache for certificates with issuer \"%s\"\n", issuerFilter)
	filtered := make(chan *testEntry, sth.Size)
	numNames := int64(0)
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
		atomic.AddInt64(&numNames, int64(len(cert.DNSNames)))
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
	debug := flag.Bool("debug", false, "print lots of error messages")
	dontPrintProgress := flag.Bool("dontPrintProgress", false, "don't print progress information")
	scannerTimeout := flag.Duration("scannerTimeout", time.Second*5, "dialer timeout for the tls scanners (uses golang duration format, e.g. 5s)")
	flag.Parse()

	entries, numNames := loadAndUpdate(*logURL, *logKey, *filename, *issuerFilter, *dontUpdateCache)
	t := tester{
		entries:           entries,
		totalCerts:        len(entries),
		totalNames:        numNames,
		workers:           *scanners,
		progPrintInterval: 5.0,
		debug:             *debug,
		dontPrintProgress: *dontPrintProgress,
		dialerTimeout:     *scannerTimeout,
	}
	t.begin()
	t.printStats()
}
