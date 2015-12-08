package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"text/tabwriter"
	"time"

	ct "github.com/jsha/certificatetransparency"
)

var suiteToString = map[uint16]string{
	0x0005: "TLS RSA WITH RC4 128 SHA",
	0x000a: "TLS RSA WITH 3DES EDE CBC SHA",
	0x002f: "TLS RSA WITH AES 128 CBC SHA",
	0x0035: "TLS RSA WITH AES 256 CBC SHA",
	0xc007: "TLS ECDHE ECDSA WITH RC4 128 SHA",
	0xc009: "TLS ECDHE ECDSA WITH AES 128 CBC SHA",
	0xc00a: "TLS ECDHE ECDSA WITH AES 256 CBC SHA",
	0xc011: "TLS ECDHE RSA WITH RC4 128 SHA",
	0xc012: "TLS ECDHE RSA WITH 3DES EDE CBC SHA",
	0xc013: "TLS ECDHE RSA WITH AES 128 CBC SHA",
	0xc014: "TLS ECDHE RSA WITH AES 256 CBC SHA",
	0xc02f: "TLS ECDHE RSA WITH AES 128 GCM SHA256",
	0xc02b: "TLS ECDHE ECDSA WITH AES 128 GCM SHA256",
	0xc030: "TLS ECDHE RSA WITH AES 256 GCM SHA384",
	0xc02c: "TLS ECDHE ECDSA WITH AES 256 GCM SHA384",
}

type collectedResults struct {
	NamesSkipped              int64
	NamesDontExist            int64
	NamesUnavailable          int64
	NamesTLSError             int64
	NamesUsingMiscInvalidCert int64
	NamesUsingExpiredCert     int64
	NamesUsingIncompleteChain int64
	NamesUsingWrongCert       int64
	NamesUsingSelfSignedCert  int64
	NamesWithOCSPStapled      int64
	NamesServingSCTs          int64
	NamesCertNotUsed          int64

	CertsUnused        int64
	CertsPartiallyUsed int64
	CertsTotallyUsed   int64

	chMu       *sync.Mutex
	CipherHist map[string]int64
}

type tester struct {
	// progress stuff
	totalCerts        int
	processedCerts    int64
	totalNames        int64
	processedNames    int64
	progPrintInterval float64
	dontPrintProgress bool

	// important stuff
	results       collectedResults
	workers       int
	entries       chan *x509.Certificate
	dialerTimeout time.Duration

	// misc
	debug bool
}

type result struct {
	skipped              bool
	nameDoesntExist      bool
	hostAvailable        bool
	tlsError             bool
	usingMiscInvalidCert bool
	usingExpiredCert     bool
	usingIncompleteChain bool
	usingWrongCert       bool
	usingSelfSignedCert  bool
	certUsed             bool
	ocspStapled          bool
	servesSCTs           bool

	cipherSuite uint16
}

func (t *tester) processResults(results []result) {
	used := 0
	for _, r := range results {
		if r.skipped {

			atomic.AddInt64(&t.results.NamesSkipped, 1)
			continue
		}
		if r.nameDoesntExist {
			atomic.AddInt64(&t.results.NamesDontExist, 1)
			continue
		}
		if !r.hostAvailable {
			atomic.AddInt64(&t.results.NamesUnavailable, 1)
			continue
		}
		if r.tlsError {
			atomic.AddInt64(&t.results.NamesTLSError, 1)
			continue
		}
		if r.usingMiscInvalidCert {
			atomic.AddInt64(&t.results.NamesUsingMiscInvalidCert, 1)
			continue
		} else if r.usingExpiredCert {
			atomic.AddInt64(&t.results.NamesUsingExpiredCert, 1)
			continue
		} else if r.usingIncompleteChain {
			atomic.AddInt64(&t.results.NamesUsingIncompleteChain, 1)
			continue
		} else if r.usingWrongCert {
			atomic.AddInt64(&t.results.NamesUsingWrongCert, 1)
			continue
		} else if r.usingSelfSignedCert {
			atomic.AddInt64(&t.results.NamesUsingSelfSignedCert, 1)
			continue
		}
		if !r.certUsed {
			atomic.AddInt64(&t.results.NamesCertNotUsed, 1)
			continue
		}
		if r.ocspStapled {
			atomic.AddInt64(&t.results.NamesWithOCSPStapled, 1)
		}
		if r.servesSCTs {
			atomic.AddInt64(&t.results.NamesServingSCTs, 1)
		}
		if r.cipherSuite > 0 {
			t.results.chMu.Lock()
			t.results.CipherHist[suiteToString[r.cipherSuite]]++
			t.results.chMu.Unlock()
		}
		used++
	}
	if used == len(results) {
		atomic.AddInt64(&t.results.CertsTotallyUsed, 1)
	} else if used < len(results) && used > 0 {
		atomic.AddInt64(&t.results.CertsPartiallyUsed, 1)
	} else if used == 0 {
		atomic.AddInt64(&t.results.CertsUnused, 1)
	}
}

func (t *tester) printProgress(stop chan bool) {
	prog := ""
	started := time.Now()
	for {
		select {
		case <-stop:
			return
		default:
			processedCerts := atomic.LoadInt64(&t.processedCerts)
			processedNames := atomic.LoadInt64(&t.processedNames)
			taken := time.Since(started).Seconds()
			cps := float64(processedCerts) / taken
			nps := float64(processedNames) / taken
			eta := "???"
			etaDur := time.Second * time.Duration(float64(t.totalNames-processedNames)/nps)
			if etaDur > time.Second && etaDur < (24*time.Hour) {
				eta = etaDur.String()
			}
			if prog != "" {
				// Assume VT100 because \b is terrible
				fmt.Fprintf(os.Stdout, fmt.Sprintf("\033[1K\033[%dD", len(prog)))
			}
			prog = fmt.Sprintf(
				"%d/%d certificates checked, %d/%d names [%.2f cps, %.2f nps, eta: %s]",
				processedCerts,
				t.totalCerts,
				processedNames,
				t.totalNames,
				cps,
				nps,
				eta,
			)
			fmt.Fprintf(os.Stdout, prog)
			time.Sleep(time.Second * time.Duration(t.progPrintInterval))
		}
	}
}

func percent(n, t int64) float64 {
	return (float64(n) / float64(t)) * 100.0
}

func (t *tester) printStats() {
	fmt.Printf("\n# scan results breakdown\n\n")
	fmt.Printf("\t%d certificates checked (totalling %d DNS names)\n", t.processedCerts, t.processedNames)
	fmt.Println()
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 6, 4, 3, ' ', 0)

	fmt.Printf("\t# name problems\n\n")
	fmt.Fprintf(w, "\tinvalid DNS\t%d\t(%.2f%%)\n", t.results.NamesDontExist, percent(t.results.NamesDontExist, t.processedNames))
	fmt.Fprintf(w, "\trefused/unavailable\t%d\t(%.2f%%)\n", t.results.NamesUnavailable, percent(t.results.NamesUnavailable, t.processedNames))
	fmt.Fprintf(w, "\ttimed out\t%d\t(%.2f%%)\n", t.results.NamesSkipped, percent(t.results.NamesSkipped, t.processedNames))
	fmt.Fprintf(w, "\tTLS error\t%d\t(%.2f%%)\n", t.results.NamesTLSError, percent(t.results.NamesTLSError, t.processedNames))
	fmt.Fprintf(w, "\tsent incomplete chain\t%d\t(%.2f%%)\n", t.results.NamesUsingIncompleteChain, percent(t.results.NamesUsingIncompleteChain, t.processedNames))
	fmt.Fprintf(w, "\texpired cert\t%d\t(%.2f%%)\n", t.results.NamesUsingExpiredCert, percent(t.results.NamesUsingExpiredCert, t.processedNames))
	fmt.Fprintf(w, "\tself-signed cert\t%d\t(%.2f%%)\n", t.results.NamesUsingSelfSignedCert, percent(t.results.NamesUsingSelfSignedCert, t.processedNames))
	fmt.Fprintf(w, "\tcert has wrong names\t%d\t(%.2f%%)\n", t.results.NamesUsingWrongCert, percent(t.results.NamesUsingWrongCert, t.processedNames))
	fmt.Fprintf(w, "\tmisc. invalid cert\t%d\t(%.2f%%)\n", t.results.NamesUsingMiscInvalidCert, percent(t.results.NamesUsingMiscInvalidCert, t.processedNames))
	fmt.Fprintln(w)
	w.Flush()

	fmt.Printf("\t# feature usage\n\n")
	fmt.Fprintf(w, "\tOCSP stapled\t%d\t(%.2f%%)\n", t.results.NamesWithOCSPStapled, percent(t.results.NamesWithOCSPStapled, t.processedNames))
	fmt.Fprintf(w, "\tSCT included\t%d\t(%.2f%%)\n", t.results.NamesServingSCTs, percent(t.results.NamesServingSCTs, t.processedNames))
	fmt.Fprintln(w)
	w.Flush()

	fmt.Printf("\t# adoption statistics\n\n")
	fmt.Fprintf(w, "\tnames using issued cert\t%d\t(%.2f%%)\n", t.processedNames-t.results.NamesCertNotUsed, percent(t.processedNames-t.results.NamesCertNotUsed, t.processedNames))
	fmt.Fprintf(w, "\tcerts used by no names\t%d\t(%.2f%%)\n", t.results.CertsUnused, percent(t.results.CertsUnused, int64(t.processedCerts)))
	fmt.Fprintf(w, "\tcerts used by some names\t%d\t(%.2f%%)\n", t.results.CertsPartiallyUsed, percent(t.results.CertsPartiallyUsed, int64(t.processedCerts)))
	fmt.Fprintf(w, "\tcerts used by all names\t%d\t(%.2f%%)\n", t.results.CertsTotallyUsed, percent(t.results.CertsTotallyUsed, int64(t.processedCerts)))
	fmt.Fprintln(w)
	w.Flush()

	fmt.Printf("\t# cipher suite breakdown\n\n")
	cipherNum := int64(0)
	for _, v := range t.results.CipherHist {
		cipherNum += v
	}
	for k, v := range t.results.CipherHist {
		fmt.Fprintf(w, "\t%d\t(%.2f%%)\t%s\n", v, percent(v, cipherNum), k)
	}
	fmt.Fprintln(w)
	w.Flush()
}

func (t *tester) checkName(dnsName string, expectedFP [32]byte) (r result) {
	defer atomic.AddInt64(&t.processedNames, 1)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: t.dialerTimeout}, "tcp", fmt.Sprintf("%s:443", dnsName), nil)
	if err != nil {
		// this should probably retry on some set of errors :/
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
				r.nameDoesntExist = true
			}
			// Hosts that don't serve HTTPS are marked unavailable (this should be noted elsewhere...)
			return
		}
		r.hostAvailable = true
		// Check if the error was TLS related
		if strings.HasPrefix(err.Error(), "tls:") || err.Error() == "EOF" {
			r.tlsError = true
			return
		}
		if _, ok := err.(x509.UnknownAuthorityError); ok {
			r.usingIncompleteChain = true
			return
		}
		if _, ok := err.(x509.HostnameError); ok {
			r.usingWrongCert = true
			return
		}
		if invErr, ok := err.(x509.CertificateInvalidError); ok {
			if invErr.Reason == x509.Expired {
				r.usingExpiredCert = true
				return
			} else if invErr.Reason == x509.NotAuthorizedToSign {
				r.usingSelfSignedCert = true
				return
			}
		}
		r.usingMiscInvalidCert = true
		return
	}
	r.hostAvailable = true
	defer conn.Close()
	state := conn.ConnectionState()
	if !state.HandshakeComplete {
		return
	}
	for _, peer := range state.PeerCertificates {
		if sha256.Sum256(peer.Raw) == expectedFP {
			r.certUsed = true
			break
		}
	}
	if len(state.OCSPResponse) != 0 {
		r.ocspStapled = true
	}
	if len(state.SignedCertificateTimestamps) != 0 {
		r.servesSCTs = true
	}
	r.cipherSuite = state.CipherSuite
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
	stopProg := make(chan bool, 1)
	if !t.debug && !t.dontPrintProgress {
		go t.printProgress(stopProg)
	}
	wg := new(sync.WaitGroup)
	started := time.Now()
	stopWorkers := []chan bool{}
	for i := 0; i < t.workers; i++ {
		stop := make(chan bool, 1)
		stopWorkers = append(stopWorkers, stop)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for te := range t.entries {
				select {
				case <-stop:
					return
				default:
					t.checkCert(te)
				}
			}
		}()
	}
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		<-sigChan
		stopProg <- true
		fmt.Println("\n\ninterrupted, cleaning up")
		for _, sw := range stopWorkers {
			sw <- true
		}
	}()
	wg.Wait()
	signal.Stop(sigChan)
	stopProg <- true
	fmt.Printf("\n\nscan finished, took %s\n", time.Since(started))
}

func basicFilter(issuerFilter string, checkOCSP bool, ent *ct.EntryAndPosition, err error) *x509.Certificate {
	if err != nil {
		return nil
	}
	cert, err := x509.ParseCertificate(ent.Entry.X509Cert)
	if err != nil {
		return nil
	}
	if cert.Issuer.CommonName != issuerFilter {
		return nil
	}
	if time.Now().After(cert.NotAfter) {
		return nil
	}
	if checkOCSP {
		// do something
	}
	return cert
}

func (t *tester) filterOnIssuer(issuerFilter string) func(*ct.EntryAndPosition, error) {
	return func(ent *ct.EntryAndPosition, err error) {
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
		if cert := basicFilter(issuerFilter, false, ent, err); cert != nil {
			atomic.AddInt64(&t.totalNames, int64(len(cert.DNSNames)))
			t.entries <- cert
		}
	}
}

func (t *tester) filterOnIssuerAndDedup(issuerFilter string) (func(*ct.EntryAndPosition, error), func()) {
	ddMap := make(map[string]*x509.Certificate)
	ddMu := new(sync.Mutex)
	return func(ent *ct.EntryAndPosition, err error) {
			cert := basicFilter(issuerFilter, false, ent, err)
			if cert == nil {
				return
			}
			names := cert.DNSNames
			sort.Strings(names)
			sortedNames := strings.Join(names, ",")
			ddMu.Lock()
			if oldCert, present := ddMap[sortedNames]; present {
				if cert.NotAfter.After(oldCert.NotAfter) {
					ddMap[sortedNames] = cert
				}
			} else {
				ddMap[sortedNames] = cert
			}
			ddMu.Unlock()
		}, func() {
			ddMu.Lock()
			defer ddMu.Unlock()
			for _, c := range ddMap {
				atomic.AddInt64(&t.totalNames, int64(len(c.DNSNames)))
				t.entries <- c
			}
		}
}

func (t *tester) filterOnIssuerAndSample(issuerFilter string) func(*ct.EntryAndPosition, error) {
	return nil
}

func (t *tester) loadAndUpdate(logURL, logKey, filename string, dontUpdate bool, filterFunc func(*ct.EntryAndPosition, error)) error {
	pemPublicKey := fmt.Sprintf(`-----BEGIN PUBLIC KEY-----
%s
-----END PUBLIC KEY-----`, logKey)
	ctLog, err := ct.NewLog(logURL, pemPublicKey)
	if err != nil {
		return err
	}

	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer file.Close()

	entriesFile := ct.EntriesFile{file}

	sth, err := ctLog.GetSignedTreeHead()
	if err != nil {
		return err
	}

	count, err := entriesFile.Count()
	if err != nil {
		return err
	}
	fmt.Printf("local entries: %d, remote entries: %d at %s\n", count, sth.Size, sth.Time.Format(time.ANSIC))
	if !dontUpdate && count < sth.Size {
		fmt.Println("updating local cache...")
		_, err = ctLog.DownloadRange(file, nil, count, sth.Size)
		if err != nil {
			return err
		}
	}
	entriesFile.Seek(0, 0)

	fmt.Println("filtering local cache")
	t.entries = make(chan *x509.Certificate, sth.Size)
	entriesFile.Map(filterFunc)
	if len(t.entries) == 0 {
		return fmt.Errorf("filtered list contains no certificates!")
	}
	close(t.entries)
	t.totalCerts = len(t.entries)
	return nil
}

func main() {
	logURL := flag.String("logURL", "https://log.certly.io", "url of remote CT log to use")
	logKey := flag.String("logKey", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECyPLhWKYYUgEc+tUXfPQB4wtGS2MNvXrjwFCCnyYJifBtd2Sk7Cu+Js9DNhMTh35FftHaHu6ZrclnNBKwmbbSA==", "base64-encoded CT log key")
	filename := flag.String("cacheFile", "certly.log", "file in which to cache log data.")
	issuerFilter := flag.String("issuerFilter", "Let's Encrypt Authority X1", "common name of issuer to use as a filter")
	scanners := flag.Int("scanners", 50, "number of scanner workers to run")
	dontUpdateCache := flag.Bool("dontUpdateCache", false, "don't update the local log cache")
	debug := flag.Bool("debug", false, "print lots of error messages")
	dontPrintProgress := flag.Bool("dontPrintProgress", false, "don't print progress information")
	scannerTimeout := flag.Duration("scannerTimeout", time.Second*5, "dialer timeout for the tls scanners (uses golang duration format, e.g. 5s)")
	flag.Parse()

	t := tester{
		workers:           *scanners,
		progPrintInterval: 5.0,
		debug:             *debug,
		dontPrintProgress: *dontPrintProgress,
		dialerTimeout:     *scannerTimeout,
		results: collectedResults{
			chMu:       new(sync.Mutex),
			CipherHist: make(map[string]int64),
		},
	}

	err := t.loadAndUpdate(*logURL, *logKey, *filename, *dontUpdateCache, t.filterOnIssuer(*issuerFilter))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load, update, and filter the local CT cache file: %s\n", err)
		os.Exit(1)
	}

	t.begin()
	t.printStats()
}
