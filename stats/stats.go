package stats

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"text/tabwriter"
	"time"

	"github.com/rolandshoemaker/ctat/common"
	"github.com/rolandshoemaker/ctat/filter"

	ct "github.com/jsha/certificatetransparency"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

type intBucket struct {
	Value     int
	Frequency int
}

type intDistribution []intBucket

func (d intDistribution) Len() int           { return len(d) }
func (d intDistribution) Swap(i, j int)      { d[i], d[j] = d[j], d[i] }
func (d intDistribution) Less(i, j int) bool { return d[i].Value < d[j].Value }

func (d intDistribution) print(valueLabel string, sum int) {
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintf(w, "Frequency\t\t%s\t \n", valueLabel)
	fmt.Fprintf(w, "-----\t\t%s\t \n", strings.Repeat("-", len(valueLabel)))
	maxWidth := 100.0
	for _, b := range d {
		percent := float64(b.Frequency) / float64(sum)
		fmt.Fprintf(w, "%d\t%.4f%%\t%d\t%s\n", b.Frequency, percent*100.0, b.Value, strings.Repeat("*", int(maxWidth*percent)))
	}
	w.Flush()
}

type strBucket struct {
	Value     string
	Frequency int
}

type strDistribution []strBucket

func (d strDistribution) Len() int           { return len(d) }
func (d strDistribution) Swap(i, j int)      { d[i], d[j] = d[j], d[i] }
func (d strDistribution) Less(i, j int) bool { return d[i].Frequency > d[j].Frequency }

func (d strDistribution) print(valueLabel string, sum int) {
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintf(w, "Frequency\t\t%s\t \n", valueLabel)
	fmt.Fprintf(w, "-----\t\t%s\t \n", strings.Repeat("-", len(valueLabel)))
	maxWidth := 100.0
	for _, b := range d {
		percent := float64(b.Frequency) / float64(sum)
		fmt.Fprintf(w, "%d\t%.4f%%\t%s\t%s\n", b.Frequency, percent*100.0, b.Value, strings.Repeat("*", int(maxWidth*percent)))
	}
	w.Flush()
}

type strMap map[string]int
type intMap map[int]int

func mapToStrDist(stuff strMap, cutoff int) (strDistribution, int) {
	dist := strDistribution{}
	sum := 0
	for k, v := range stuff {
		if cutoff > 0 && v < cutoff {
			continue
		}
		dist = append(dist, strBucket{Frequency: v, Value: k})
		sum += v
	}
	sort.Sort(dist)
	return dist, sum
}

func mapToIntDist(stuff intMap, cutoff int) (intDistribution, int) {
	dist := intDistribution{}
	sum := 0
	for k, v := range stuff {
		if cutoff > 0 && v < cutoff {
			continue
		}
		dist = append(dist, intBucket{Frequency: v, Value: k})
		sum += v
	}
	sort.Sort(dist)
	return dist, sum
}

type distHolder struct {
	Dist  interface{}
	Label string
}

type statHolder struct {
	Value int
	Label string
}

type datumType string

var (
	singleStat = datumType("single-stat")
	multiStat  = datumType("multi-stat")
	singleDist = datumType("single-dist")
	multiDist  = datumType("multi-dist")
)

type jsonDatum struct {
	Name string
	Type datumType
	Data interface{}
}

type jsonHolder struct {
	Timestamp time.Time
	Stats     []jsonDatum
}

type metricGenerator interface {
	process(*x509.Certificate)
	print()
	// json() jsonDatum
}

var dnsTimeout = time.Second * 5

var metricsLookup = map[string]metricGenerator{
	"validityDist":      &validityDistribution{periods: make(intMap)},
	"certSizeDist":      &certSizeDistribution{sizes: make(intMap)},
	"nameMetrics":       &nameMetrics{names: make(strMap), nameSets: make(strMap)},
	"sanSizeDist":       &sanSizeDistribution{sizes: make(intMap)},
	"pkTypeDist":        &pkAlgDistribution{algs: make(strMap)},
	"sigTypeDist":       &sigAlgDistribution{algs: make(strMap)},
	"popularSuffixes":   &popularSuffixes{suffixes: make(strMap)},
	"leafIssuers":       &leafIssuanceDist{issuances: make(strMap)},
	"serialLengthDist":  &serialLengthDistribution{lengths: make(intMap)},
	"keyUsageDist":      &keyUsageDist{usage: make(strMap)},
	"featureMetrics":    &featureMetrics{features: make(strMap)},
	"numExtensionsDist": &numExtensionsDistribution{extensions: make(intMap)},
	"keySizeDist":       &keySizeDistribution{rsaSizes: make(intMap), dsaSizes: make(intMap), ellipticSizes: make(intMap)},
	"keyTypeDist":       &keyTypeDistribution{keyTypes: make(strMap)},
	"maxPathLengthDist": &maxPathLenDistribution{lengths: make(intMap)},
	"keyReuseMetrics":   &keyReuseMetrics{hashes: make(map[[20]byte]int)},
	"badASNMetrics":     &badASNMetrics{negativeSerialIssuers: make(map[string]int)},
	"torDNSTest": &torDNSTest{
		client:         &dns.Client{DialTimeout: dnsTimeout, ReadTimeout: dnsTimeout, Net: "tcp"},
		normalResolver: "127.0.0.1:53",
		torResolver:    "127.0.0.1:9053",
	},
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

var cutoffLookup = map[string]*int{
	"popularSuffixes": &popularSuffixesCutoff,
	"leafIssuers":     &leafIssuanceCutoff,
	"reusedKeys":      &keyReuseCutoff,
}

func StringToCutoffs(cutoffs string) error {
	sections := strings.Split(cutoffs, ",")
	if len(sections) == 0 {
		return fmt.Errorf("At least one properly formatted cutoff must be specified")
	}
	for i, f := range sections {
		fields := strings.Split(f, ":")
		if len(fields) != 2 {
			return fmt.Errorf("Cutoff definition [%d] had invalid format", i+1)
		}
		if cutoff, present := cutoffLookup[fields[0]]; !present {
			return fmt.Errorf("Cutoff '%s' does not exist", fields[0])
		} else if present {
			value, err := strconv.Atoi(fields[1])
			if err != nil {
				return fmt.Errorf("Cutoff count for '%s' is not an int: %s", fields[0], err)
			}
			*cutoff = value
		}
	}
	return nil
}

type certSizeDistribution struct {
	sizes intMap
	mu    sync.Mutex
	dist  intDistribution
}

func (csd *certSizeDistribution) process(cert *x509.Certificate) {
	certSize := int(math.Ceil(float64(len(cert.Raw))/100)) * int(100)
	csd.mu.Lock()
	defer csd.mu.Unlock()
	csd.sizes[certSize]++
}

func (csd *certSizeDistribution) print() {
	dist, sum := mapToIntDist(csd.sizes, 0)
	fmt.Println("# Certificate size distribution")
	dist.print("Size (bytes)", sum)
	jd := jsonDatum{Data: distHolder{Dist: dist, Label: "Size (bytes)"}}
	d, e := json.Marshal(jd)
	fmt.Println(string(d), e)
}

func (csd *certSizeDistribution) json() jsonDatum {
	return jsonDatum{Name: "", Data: csd.dist}
}

type validityDistribution struct {
	periods intMap
	mu      sync.Mutex
}

func (vd *validityDistribution) process(cert *x509.Certificate) {
	period := int((cert.NotAfter.Sub(cert.NotBefore)).Hours() / 24 / 30)

	vd.mu.Lock()
	defer vd.mu.Unlock()
	vd.periods[period]++
}

func (vd *validityDistribution) print() {
	dist, sum := mapToIntDist(vd.periods, 0)
	fmt.Println("# Validity period distribution")
	dist.print("Validity period (months)", sum)
}

type sanSizeDistribution struct {
	sizes intMap
	mu    sync.Mutex
}

func (ssd *sanSizeDistribution) process(cert *x509.Certificate) {
	size := len(cert.DNSNames)
	ssd.mu.Lock()
	defer ssd.mu.Unlock()
	ssd.sizes[size]++
}

func (ssd *sanSizeDistribution) print() {
	dist, sum := mapToIntDist(ssd.sizes, 0)
	fmt.Println("# SAN num distribution")
	dist.print("Number of SANs", sum)
}

type serialLengthDistribution struct {
	lengths intMap
	mu      sync.Mutex
}

func (sld *serialLengthDistribution) process(cert *x509.Certificate) {
	sld.mu.Lock()
	defer sld.mu.Unlock()
	sld.lengths[cert.SerialNumber.BitLen()]++
}

func (sld *serialLengthDistribution) print() {
	dist, sum := mapToIntDist(sld.lengths, 0)
	fmt.Println("# Serial number length distribution")
	dist.print("Serial bit length", sum)
}

type numExtensionsDistribution struct {
	extensions intMap
	mu         sync.Mutex
}

func (ned *numExtensionsDistribution) process(cert *x509.Certificate) {
	ned.mu.Lock()
	defer ned.mu.Unlock()
	ned.extensions[len(cert.Extensions)]++
}

func (ned *numExtensionsDistribution) print() {
	dist, sum := mapToIntDist(ned.extensions, 0)
	fmt.Println("# TLS extension number distribution")
	dist.print("Num TLS extensions", sum)
}

var pkAlgToString = map[x509.PublicKeyAlgorithm]string{
	0: "Unknown",
	1: "RSA",
	2: "DSA",
	3: "ECDSA",
}

type pkAlgDistribution struct {
	algs strMap
	mu   sync.Mutex
}

func (pad *pkAlgDistribution) process(cert *x509.Certificate) {
	alg, ok := pkAlgToString[cert.PublicKeyAlgorithm]
	if !ok {
		return
	}
	pad.mu.Lock()
	defer pad.mu.Unlock()
	pad.algs[alg]++
}

func (pad *pkAlgDistribution) print() {
	dist, sum := mapToStrDist(pad.algs, 0)
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
	algs strMap
	mu   sync.Mutex
}

func (sad *sigAlgDistribution) process(cert *x509.Certificate) {
	alg, ok := sigAlgToString[cert.SignatureAlgorithm]
	if !ok {
		return
	}
	sad.mu.Lock()
	defer sad.mu.Unlock()
	sad.algs[alg]++
}

func (sad *sigAlgDistribution) print() {
	dist, sum := mapToStrDist(sad.algs, 0)
	fmt.Println("# Signature type distribution")
	dist.print("Type", sum)
}

type popularSuffixes struct {
	suffixes strMap
	mu       sync.Mutex
}

func (ps *popularSuffixes) process(cert *x509.Certificate) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	for _, n := range cert.DNSNames {
		suffix, err := publicsuffix.EffectiveTLDPlusOne(n)
		if err != nil || suffix == n {
			continue
		}
		ps.suffixes[suffix]++
	}
}

var popularSuffixesCutoff = 500

func (ps *popularSuffixes) print() {
	dist, sum := mapToStrDist(ps.suffixes, popularSuffixesCutoff)
	fmt.Println("# Popular DNS name suffixes")
	dist.print("eTLD+1", sum)
}

type leafIssuanceDist struct {
	issuances strMap
	mu        sync.Mutex
}

func (lid *leafIssuanceDist) process(cert *x509.Certificate) {
	lid.mu.Lock()
	defer lid.mu.Unlock()
	lid.issuances[common.SubjectToString(cert.Issuer)]++
}

var leafIssuanceCutoff = 500

func (lid *leafIssuanceDist) print() {
	dist, sum := mapToStrDist(lid.issuances, leafIssuanceCutoff)
	fmt.Println("# Leaf issuers")
	dist.print("Issuer distinguished name", sum)
}

var keyUsageLookup = map[x509.ExtKeyUsage]string{
	0:  "Any",
	1:  "Server Auth",
	2:  "Client Auth",
	3:  "Code Signing",
	4:  "Email Protection",
	5:  "IPSEC End System",
	6:  "IPSEC Tunnel",
	7:  "IPSEC User",
	8:  "Time Stamping",
	9:  "OCSP Signing",
	10: "Microsoft Server Gated Crypto",
	11: "Netscape Server Gated Crypto",
}

type keyUsageDist struct {
	usage strMap
	mu    sync.Mutex
}

func (kud *keyUsageDist) process(cert *x509.Certificate) {
	usages := []string{}
	for _, u := range cert.ExtKeyUsage {
		if name, present := keyUsageLookup[u]; present {
			usages = append(usages, name)
		}
	}
	sort.Strings(usages)
	kud.mu.Lock()
	defer kud.mu.Unlock()
	kud.usage[strings.Join(usages, ", ")]++
}

func (kud *keyUsageDist) print() {
	dist, sum := mapToStrDist(kud.usage, 0)
	fmt.Println("# Key usage distribution")
	dist.print("Usage sets", sum)
}

type keyTypeDistribution struct {
	keyTypes strMap
	mu       sync.Mutex
}

func (ktd *keyTypeDistribution) process(cert *x509.Certificate) {
	ktd.mu.Lock()
	defer ktd.mu.Unlock()
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		ktd.keyTypes["RSA"]++
	case *dsa.PublicKey:
		ktd.keyTypes["DSA"]++
	case *ecdsa.PublicKey:
		ktd.keyTypes["ECDSA"]++
	}
}

func (ktd *keyTypeDistribution) print() {
	dist, sum := mapToStrDist(ktd.keyTypes, 0)
	fmt.Println("# Key type distribution")
	dist.print("Type", sum)
}

type nameMetrics struct {
	nMu        sync.Mutex
	names      strMap
	totalNames int64

	nsMu          sync.Mutex
	nameSets      strMap
	totalNameSets int64
}

func (nm *nameMetrics) process(cert *x509.Certificate) {
	atomic.AddInt64(&nm.totalNameSets, 1)
	atomic.AddInt64(&nm.totalNames, int64(len(cert.DNSNames)))
	sort.Strings(cert.DNSNames)
	nameSet := strings.Join(cert.DNSNames, ",")
	nm.nsMu.Lock()
	nm.nameSets[nameSet]++
	nm.nsMu.Unlock()
	for _, name := range cert.DNSNames {
		nm.nMu.Lock()
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

var featureLookup = map[string]string{
	"1.3.6.1.4.1.11129.2.4.2": "Embedded SCT",
	"1.3.6.1.5.5.7.1.24":      "OCSP must staple",
}

type featureMetrics struct {
	features strMap
	mu       sync.Mutex
}

func (fm *featureMetrics) process(cert *x509.Certificate) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	for _, e := range cert.Extensions {
		if name, present := featureLookup[e.Id.String()]; present {
			fm.features[name]++
		}
	}
}

func (fm *featureMetrics) print() {
	dist, sum := mapToStrDist(fm.features, 0)
	fmt.Println("# TLS feature extension usage")
	dist.print("Extension name", sum)
}

type keySizeDistribution struct {
	rsaSizes      intMap
	rMu           sync.Mutex
	dsaSizes      intMap
	dMu           sync.Mutex
	ellipticSizes intMap
	eMu           sync.Mutex
}

func (ksd *keySizeDistribution) process(cert *x509.Certificate) {
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		ksd.rMu.Lock()
		defer ksd.rMu.Unlock()
		ksd.rsaSizes[k.N.BitLen()]++
	case *dsa.PublicKey:
		ksd.dMu.Lock()
		defer ksd.dMu.Unlock()
		ksd.dsaSizes[k.Y.BitLen()]++
	case *ecdsa.PublicKey:
		ksd.eMu.Lock()
		defer ksd.eMu.Unlock()
		ksd.ellipticSizes[k.Params().BitSize]++
	}
}

func (ksd *keySizeDistribution) print() {
	dsaDist, dsaSum := mapToIntDist(ksd.dsaSizes, 0)
	rsaDist, rsaSum := mapToIntDist(ksd.rsaSizes, 0)
	ecDist, ecSum := mapToIntDist(ksd.ellipticSizes, 0)
	fmt.Println("# DSA key size distribution")
	dsaDist.print("Bit length", dsaSum)
	fmt.Println("# RSA key size distribution")
	rsaDist.print("Bit length", rsaSum)
	fmt.Println("# ECDSA key size distribution")
	ecDist.print("Bit length", ecSum)
}

type maxPathLenDistribution struct {
	lengths intMap
	mu      sync.Mutex
}

func (mpld *maxPathLenDistribution) process(cert *x509.Certificate) {
	mpld.mu.Lock()
	defer mpld.mu.Unlock()
	if cert.BasicConstraintsValid && (cert.MaxPathLenZero || cert.MaxPathLen > 0) {
		mpld.lengths[cert.MaxPathLen]++
	}
}

func (mpld *maxPathLenDistribution) print() {
	dist, sum := mapToIntDist(mpld.lengths, 0)
	fmt.Println("# Max path length distribution")
	dist.print("Path length", sum)
}

var keyReuseCutoff = 100

type keyReuseMetrics struct {
	hashes map[[20]byte]int
	mu     sync.Mutex
}

func (krm *keyReuseMetrics) process(cert *x509.Certificate) {
	hash := sha1.Sum(cert.RawSubjectPublicKeyInfo)
	krm.mu.Lock()
	defer krm.mu.Unlock()
	krm.hashes[hash]++
}

func (krm *keyReuseMetrics) print() {
	reuseDistMap := make(map[int]int)
	hashMap := make(map[string]int)
	for k, v := range krm.hashes {
		reuseDistMap[v]++
		if v > keyReuseCutoff {
			hashMap[fmt.Sprintf("%X", k)] = v
		}
	}

	reuseDist, reuseSum := mapToIntDist(reuseDistMap, 1)
	fmt.Println("# Reused key frequency distribution")
	reuseDist.print("Frequency", reuseSum)

	hashDist, hashSum := mapToStrDist(hashMap, keyReuseCutoff)
	fmt.Printf("# Keys reused more than %d times\n", keyReuseCutoff)
	hashDist.print("Public key SHA1 hash", hashSum)
}

type badASNMetrics struct {
	negativeSerialIssuers map[string]int
	mu                    sync.Mutex
}

func (bam *badASNMetrics) process(cert *x509.Certificate) {
	if cert.SerialNumber.Sign() >= 0 {
		return
	}
	issuer := common.SubjectToString(cert.Issuer)
	bam.mu.Lock()
	defer bam.mu.Unlock()
	bam.negativeSerialIssuers[issuer]++
}

func (bam *badASNMetrics) print() {
	dist, sum := mapToStrDist(bam.negativeSerialIssuers, 0)
	fmt.Println("# Issuers creating certificates with negative serial numbers")
	dist.print("Issuer DN", sum)
}

type torDNSTest struct {
	torFailures    int64
	normalFailures int64
	bothFailures   int64
	totalChecked   int64

	torResolver    string
	normalResolver string
	client         *dns.Client
	torClient      *dns.Client
}

func (tdt *torDNSTest) process(cert *x509.Certificate) {
	for _, n := range cert.DNSNames {
		atomic.AddInt64(&tdt.totalChecked, 1)
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(n), dns.TypeA)
		r, _, err := tdt.client.Exchange(msg, tdt.normalResolver)
		normalFailed := err != nil || r.Rcode == dns.RcodeServerFailure
		if normalFailed {
			atomic.AddInt64(&tdt.normalFailures, 1)
		}
		r, _, err = tdt.client.Exchange(msg, tdt.torResolver)
		torFailed := err != nil || r.Rcode == dns.RcodeServerFailure
		if !normalFailed && torFailed {
			atomic.AddInt64(&tdt.torFailures, 1)
		} else if normalFailed && torFailed {
			atomic.AddInt64(&tdt.bothFailures, 1)
		}
	}
}

func (tdt *torDNSTest) print() {
	fmt.Println("# Tor DNS lookup test")
	fmt.Printf(
		"%d names checked, %.2f failed both tests, %.2f failed over Tor, %.2f failed with normal resolver",
		tdt.totalChecked,
		(float64(tdt.bothFailures)/float64(tdt.totalChecked))*100.0,
		(float64(tdt.torFailures)/float64(tdt.totalChecked))*100.0,
		(float64(tdt.normalFailures)/float64(tdt.totalChecked))*100.0,
	)
}

func Analyse(cacheFile string, filters []filter.Filter, generators []metricGenerator, measureErrors bool) error {
	entries, err := common.LoadCacheFile(cacheFile)
	if err != nil {
		return err
	}

	cMu := new(sync.Mutex)
	ctErrors := make(map[string]int)
	xMu := new(sync.Mutex)
	x509Errors := make(map[string]int)
	entries.Map(func(ent *ct.EntryAndPosition, err error) {
		if err != nil {
			if measureErrors {
				cMu.Lock()
				ctErrors[err.Error()]++
				cMu.Unlock()
			}
			return
		}
		// execute CT entry metric stuff (TODO!)
		cert, skip, err := common.ParseAndFilter(ent.Entry.X509Cert, filters)
		if !skip && err != nil {
			if measureErrors {
				xMu.Lock()
				x509Errors[err.Error()]++
				xMu.Unlock()
			}
			return
		} else if skip {
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

	if measureErrors {
		ctErrorDist, ctSum := mapToStrDist(ctErrors, 0)
		x509ErrorsDist, x509Sum := mapToStrDist(x509Errors, 0)
		fmt.Printf("\n# CT parsing errors distribution\n")
		ctErrorDist.print("Error", ctSum)
		fmt.Println("# x509 parsing errors distribution")
		x509ErrorsDist.print("Error", x509Sum)
	}

	return nil
}
