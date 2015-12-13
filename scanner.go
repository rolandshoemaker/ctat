package main

import (
	// "bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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
	"golang.org/x/crypto/ocsp"
)

var suiteToString = map[uint16]string{
	0x0005: "RSA WITH RC4 128 SHA",
	0x000a: "RSA WITH 3DES EDE CBC SHA",
	0x002f: "RSA WITH AES 128 CBC SHA",
	0x0035: "RSA WITH AES 256 CBC SHA",
	0xc007: "ECDHE ECDSA WITH RC4 128 SHA",
	0xc009: "ECDHE ECDSA WITH AES 128 CBC SHA",
	0xc00a: "ECDHE ECDSA WITH AES 256 CBC SHA",
	0xc011: "ECDHE RSA WITH RC4 128 SHA",
	0xc012: "ECDHE RSA WITH 3DES EDE CBC SHA",
	0xc013: "ECDHE RSA WITH AES 128 CBC SHA",
	0xc014: "ECDHE RSA WITH AES 256 CBC SHA",
	0xc02f: "ECDHE RSA WITH AES 128 GCM SHA256",
	0xc02b: "ECDHE ECDSA WITH AES 128 GCM SHA256",
	0xc030: "ECDHE RSA WITH AES 256 GCM SHA384",
	0xc02c: "ECDHE ECDSA WITH AES 256 GCM SHA384",
}

type collectedResults struct {
	Started  time.Time
	Finished time.Time

	ProcessedCerts int64
	ProcessedNames int64

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

type workUnit struct {
	cert *x509.Certificate
	ocsp *ocsp.Response
}

type tester struct {
	// progress stuff
	totalCerts        int
	totalNames        int64
	progPrintInterval float64
	dontPrintProgress bool

	// important stuff
	results       collectedResults
	workers       int
	entries       chan *workUnit
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
			processedCerts := atomic.LoadInt64(&t.results.ProcessedCerts)
			processedNames := atomic.LoadInt64(&t.results.ProcessedNames)
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
	fmt.Printf("\t%d certificates checked (totalling %d DNS names)\n", t.results.ProcessedCerts, t.results.ProcessedNames)
	fmt.Println()
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 6, 4, 3, ' ', 0)

	fmt.Printf("\t# name problems\n\n")
	fmt.Fprintf(w, "\tinvalid DNS\t%d\t(%.2f%%)\n", t.results.NamesDontExist, percent(t.results.NamesDontExist, t.results.ProcessedNames))
	fmt.Fprintf(w, "\trefused/unavailable\t%d\t(%.2f%%)\n", t.results.NamesUnavailable, percent(t.results.NamesUnavailable, t.results.ProcessedNames))
	fmt.Fprintf(w, "\ttimed out\t%d\t(%.2f%%)\n", t.results.NamesSkipped, percent(t.results.NamesSkipped, t.results.ProcessedNames))
	fmt.Fprintf(w, "\tTLS error\t%d\t(%.2f%%)\n", t.results.NamesTLSError, percent(t.results.NamesTLSError, t.results.ProcessedNames))
	fmt.Fprintf(w, "\tsent incomplete chain\t%d\t(%.2f%%)\n", t.results.NamesUsingIncompleteChain, percent(t.results.NamesUsingIncompleteChain, t.results.ProcessedNames))
	fmt.Fprintf(w, "\texpired cert\t%d\t(%.2f%%)\n", t.results.NamesUsingExpiredCert, percent(t.results.NamesUsingExpiredCert, t.results.ProcessedNames))
	fmt.Fprintf(w, "\tself-signed cert\t%d\t(%.2f%%)\n", t.results.NamesUsingSelfSignedCert, percent(t.results.NamesUsingSelfSignedCert, t.results.ProcessedNames))
	fmt.Fprintf(w, "\tcert has wrong names\t%d\t(%.2f%%)\n", t.results.NamesUsingWrongCert, percent(t.results.NamesUsingWrongCert, t.results.ProcessedNames))
	fmt.Fprintf(w, "\tmisc. invalid cert\t%d\t(%.2f%%)\n", t.results.NamesUsingMiscInvalidCert, percent(t.results.NamesUsingMiscInvalidCert, t.results.ProcessedNames))
	fmt.Fprintln(w)
	w.Flush()

	fmt.Printf("\t# feature usage\n\n")
	fmt.Fprintf(w, "\tOCSP stapled\t%d\t(%.2f%%)\n", t.results.NamesWithOCSPStapled, percent(t.results.NamesWithOCSPStapled, t.results.ProcessedNames))
	fmt.Fprintf(w, "\tSCT included\t%d\t(%.2f%%)\n", t.results.NamesServingSCTs, percent(t.results.NamesServingSCTs, t.results.ProcessedNames))
	fmt.Fprintln(w)
	w.Flush()

	fmt.Printf("\t# adoption statistics\n\n")
	fmt.Fprintf(w, "\tnames using issued cert\t%d\t(%.2f%%)\n", t.results.ProcessedNames-t.results.NamesCertNotUsed, percent(t.results.ProcessedNames-t.results.NamesCertNotUsed, t.results.ProcessedNames))
	fmt.Fprintf(w, "\tcerts used by all names\t%d\t(%.2f%%)\n", t.results.CertsTotallyUsed, percent(t.results.CertsTotallyUsed, int64(t.results.ProcessedCerts)))
	fmt.Fprintf(w, "\tcerts used by some names\t%d\t(%.2f%%)\n", t.results.CertsPartiallyUsed, percent(t.results.CertsPartiallyUsed, int64(t.results.ProcessedCerts)))
	fmt.Fprintf(w, "\tcerts used by no names\t%d\t(%.2f%%)\n", t.results.CertsUnused, percent(t.results.CertsUnused, int64(t.results.ProcessedCerts)))
	fmt.Fprintln(w)
	w.Flush()

	fmt.Printf("\t# cipher suite breakdown\n\n")
	cipherNum := int64(0)
	for _, v := range t.results.CipherHist {
		cipherNum += v
	}
	for k, v := range t.results.CipherHist {
		fmt.Fprintf(w, "\t%s\t%d\t(%.2f%%)\n", k, v, percent(v, cipherNum))
	}
	fmt.Fprintln(w)
	w.Flush()
}

func (t *tester) saveStats(filename string) error {
	jsonBytes, err := json.Marshal(t.results)
	if err != nil {
		return err
	}
	content := string(jsonBytes)
	if !strings.HasSuffix("\n", content) {
		content = content + "\n"
	}
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(content)
	return err
}

func (t *tester) checkName(dnsName string, expectedFP [32]byte) (r result) {
	defer atomic.AddInt64(&t.results.ProcessedNames, 1)
	// XXX: dialer/TLS config should accept all cipher suites (possibly in some weird order?) so
	// we catch everything
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: t.dialerTimeout}, "tcp", fmt.Sprintf("%s:443", dnsName), &tls.Config{PreferServerCipherSuites: true})
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
	conn.Close()
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
	defer atomic.AddInt64(&t.results.ProcessedCerts, 1)
	fp := sha256.Sum256(cert.Raw)
	var results []result
	for _, name := range cert.DNSNames {
		results = append(results, t.checkName(name, fp))
	}
	t.processResults(results)
}

func (t *tester) run() {
	fmt.Printf("beginning scan of %d certificates (%d names)\n", t.totalCerts, t.totalNames)
	stopProg := make(chan bool, 1)
	if !t.debug && !t.dontPrintProgress {
		go t.printProgress(stopProg)
	}
	wg := new(sync.WaitGroup)
	t.results.Started = time.Now()
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
					t.checkCert(te.cert)
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
	t.results.Finished = time.Now()
	signal.Stop(sigChan)
	stopProg <- true
	fmt.Printf("\n\nscan finished, took %s\n", t.results.Finished.Sub(t.results.Started))
}

func basicFilter(issuerFilter string, checkOCSP bool, ent *ct.EntryAndPosition, err error) (*x509.Certificate, *ocsp.Response) {
	if err != nil {
		return nil, nil
	}
	cert, err := x509.ParseCertificate(ent.Entry.X509Cert)
	if err != nil {
		return nil, nil
	}
	if cert.Issuer.CommonName != issuerFilter {
		return nil, nil
	}
	if time.Now().After(cert.NotAfter) {
		return nil, nil
	}
	var ocspResp *ocsp.Response
	if checkOCSP {
		// do something
	}
	return cert, ocspResp
}

func (t *tester) filterOnIssuer(issuerFilter string) func(*ct.EntryAndPosition, error) {
	return func(ent *ct.EntryAndPosition, err error) {
		if cert, ocspResp := basicFilter(issuerFilter, false, ent, err); cert != nil {
			atomic.AddInt64(&t.totalNames, int64(len(cert.DNSNames)))
			t.entries <- &workUnit{cert: cert, ocsp: ocspResp}
		}
	}
}

func (t *tester) filterOnIssuerAndDedup(issuerFilter string) (func(*ct.EntryAndPosition, error), func()) {
	ddMap := make(map[string]*workUnit)
	ddMu := new(sync.Mutex)
	return func(ent *ct.EntryAndPosition, err error) {
			cert, ocspResp := basicFilter(issuerFilter, false, ent, err)
			if cert == nil {
				return
			}
			names := cert.DNSNames
			sort.Strings(names)
			sortedNames := strings.Join(names, ",")
			ddMu.Lock()
			if oldCert, present := ddMap[sortedNames]; present {
				if cert.NotAfter.After(oldCert.cert.NotAfter) {
					ddMap[sortedNames] = &workUnit{cert: cert, ocsp: ocspResp}
				}
			} else {
				ddMap[sortedNames] = &workUnit{cert: cert, ocsp: ocspResp}
			}
			ddMu.Unlock()
		}, func() {
			ddMu.Lock()
			defer ddMu.Unlock()
			for _, wu := range ddMap {
				atomic.AddInt64(&t.totalNames, int64(len(wu.cert.DNSNames)))
				t.entries <- wu
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

	// treeHash, err := entriesFile.HashTree(nil, sth.Size)
	// if err != nil {
	// 	return err
	// }
	// fmt.Printf("Do hashes match? %b\n", bytes.Compare(treeHash[:], sth.Hash) == 0)
	// fmt.Printf("STH: %#v\n", sth)
	// fmt.Printf("Local hash:\t%X\nRemote hash:\t%X\n", treeHash[:], sth.Hash)

	fmt.Println("filtering local cache")
	t.entries = make(chan *workUnit, sth.Size)
	entriesFile.Map(filterFunc)
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
	filter := flag.String("filter", "issuer", "how to filter the CT cache")
	statsFile := flag.String("statsFile", "", "file to save scan stats out to (subsequent runs will append to the end of the file)")
	flag.Parse()

	if *filter != "issuer" && *filter != "issuerDeduped" {
		fmt.Fprintf(os.Stderr, "incorrect filter type\n")
		os.Exit(1)
	}

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

	switch *filter {
	case "issuer":
		err := t.loadAndUpdate(*logURL, *logKey, *filename, *dontUpdateCache, t.filterOnIssuer(*issuerFilter))
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load, update, and filter the local CT cache file: %s\n", err)
			os.Exit(1)
		}
	case "issuerDeduped":
		filterFunc, dedup := t.filterOnIssuerAndDedup(*issuerFilter)
		err := t.loadAndUpdate(*logURL, *logKey, *filename, *dontUpdateCache, filterFunc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load, update, and filter the local CT cache file: %s\n", err)
			os.Exit(1)
		}
		dedup()
	}
	if len(t.entries) == 0 {
		fmt.Fprintf(os.Stderr, "filtered list contains no certificates!\n")
		os.Exit(1)
	}
	close(t.entries)
	t.totalCerts = len(t.entries)

	t.run()

	t.printStats()
	if *statsFile != "" {
		err := t.saveStats(*statsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot save stats out to disk: %s\n", err)
			os.Exit(1)
		}
	}
}
