package main

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strings"
	"sync"

	ct "github.com/jsha/certificatetransparency"
)

func subjectToString(subject pkix.Name) string {
	return fmt.Sprintf("%s;;%s;;%s", subject.CommonName, subject.SerialNumber, strings.Join(append(subject.Country, append(subject.Organization, subject.OrganizationalUnit...)...), " "))
}

type node struct {
	Name          string
	Issued        int
	SubCASubjects map[string]struct{}

	subCAs      []*node
	issuer      *node
	totalLeaves int
	totalSubCAs int
}

type holder struct {
	rootsFile string

	gMu       *sync.Mutex
	Graph     map[string]*node // ...loose definition
	pMu       *sync.RWMutex
	processed map[[32]byte]struct{}

	CacheFile       string
	CacheFileOffset int64
}

func (h *holder) addNode(rawCert []byte) {
	certFP := sha256.Sum256(rawCert)
	h.pMu.RLock()
	if _, alreadyDone := h.processed[certFP]; alreadyDone {
		h.pMu.RUnlock()
		return
	}
	h.pMu.RUnlock()
	cert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		// fmt.Println(err)
		return
	}
	issuer := subjectToString(cert.Issuer)
	h.gMu.Lock()
	defer h.gMu.Unlock()
	if issuer == ";;;;" {
		subject := subjectToString(cert.Subject)
		if _, present := h.Graph[subject]; !present && subject != ";;;;" {
			name := ""
			if cert.Issuer.CommonName != "" {
				name = cert.Issuer.CommonName
			} else if len(cert.Issuer.Organization) > 0 {
				name = strings.Join(cert.Issuer.Organization, " ")
			} else {
				name = "???"
			}
			h.Graph[subject] = &node{Name: name, SubCASubjects: make(map[string]struct{})}
		}
		return
	}
	if _, present := h.Graph[issuer]; !present {
		name := ""
		if cert.Issuer.CommonName != "" {
			name = cert.Issuer.CommonName
		} else if len(cert.Issuer.Organization) > 0 {
			name = strings.Join(cert.Issuer.Organization, " ")
		} else {
			name = "???"
		}
		h.Graph[issuer] = &node{Name: name, SubCASubjects: make(map[string]struct{})}
	}

	h.Graph[issuer].Issued++
	subject := subjectToString(cert.Subject)
	if cert.BasicConstraintsValid && cert.IsCA && issuer != subject {
		if _, present := h.Graph[issuer].SubCASubjects[subject]; !present {
			h.Graph[issuer].SubCASubjects[subject] = struct{}{}
		}
	}
	h.pMu.Lock()
	h.processed[certFP] = struct{}{}
	h.pMu.Unlock()
}

func (h *holder) addSystemRoots() {
	fmt.Println("adding system root nodes to graph...")
	startingCount := len(h.Graph)
	data, err := ioutil.ReadFile(h.rootsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read roots file: %s\n", err)
		return
	}
	for {
		b, r := pem.Decode(data)
		if b == nil || len(b.Bytes) == 0 {
			break
		}
		h.addNode(b.Bytes)
		data = r
	}
	fmt.Printf("[added %d nodes]\n", len(h.Graph)-startingCount)
}

func (h *holder) createNodesFromCT() {
	// pre-populate roots form system (...)
	startingCount := len(h.Graph)

	fmt.Println("adding nodes from CT cache...")
	ctFile, err := os.OpenFile(h.CacheFile, os.O_RDONLY, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open CT cache file: %s\n", err)
		os.Exit(1)
	}
	defer ctFile.Close()
	entries := ct.EntriesFile{ctFile}
	if h.CacheFileOffset > 0 {
		fmt.Printf("moving to offset %d in CT cache file\n", h.CacheFileOffset)
		_, err := entries.Seek(h.CacheFileOffset, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to move to offset in CT cache file: %s\n", err)
			os.Exit(1)
		}
	}
	entries.Map(func(ent *ct.EntryAndPosition, err error) {
		if err != nil {
			// fmt.Println(err)
			return
		}
		if ent.Entry.Type != ct.X509Entry {
			return
		}
		h.addNode(ent.Entry.X509Cert)
		for _, extraCert := range ent.Entry.ExtraCerts {
			h.addNode(extraCert)
		}
	})
	currentPos, err := entries.Seek(0, 1) // seek to where we are now to get current position
	if err != nil {
		fmt.Printf("failed to get current position in CT cache file: %s\n", err)
	} else {
		h.CacheFileOffset = currentPos
	}
	fmt.Printf("[added %d nodes]\n", len(h.Graph)-startingCount)
}

func (n *node) setTotalLeaves(visited map[*node]struct{}) int {
	visited[n] = struct{}{}
	leaves := n.Issued
	for _, sub := range n.subCAs {
		if _, beenThere := visited[sub]; sub != n && !beenThere {
			leaves += sub.setTotalLeaves(visited)
		}
	}
	n.totalLeaves = leaves
	return leaves
}

func (n *node) setTotalSubs(visited map[*node]struct{}) int {
	visited[n] = struct{}{}
	subs := len(n.subCAs)
	for _, sub := range n.subCAs {
		if _, beenThere := visited[sub]; sub != n && !beenThere {
			subs += sub.setTotalSubs(visited)
		}
	}
	n.totalSubCAs = subs
	return subs
}

func (h *holder) createEdges() {
	fmt.Println("creating edges...")
	edges := 0
	for _, n := range h.Graph {
		// n.totalLeaves = n.issued
		for subSubject := range n.SubCASubjects {
			if subNode, present := h.Graph[subSubject]; present {
				if subNode.issuer == nil {
					subNode.issuer = n
				}
				if subNode != n {
					n.subCAs = append(n.subCAs, subNode)
					edges++
				}
			}
		}
	}
	fmt.Printf("[created %d edges]\n", edges)
	fmt.Println("calculating cumulative leaves and sub CAs...")
	for _, n := range h.Graph {
		if n.issuer == nil || n.issuer == n {
			n.setTotalLeaves(make(map[*node]struct{}))
			n.setTotalSubs(make(map[*node]struct{}))
		}
	}
}

func (n *node) print(indent int, visited map[*node]struct{}) {
	visited[n] = struct{}{}
	var info string
	if indent > 0 {
		info = strings.Repeat("  ", indent) + "∟"
	} else {
		info = "+"
	}
	info = fmt.Sprintf(
		"%s %s, Direct leaves: %d",
		info,
		n.Name,
		n.Issued,
	)
	if n.totalLeaves > n.Issued {
		info = fmt.Sprintf("%s, Total leaves: %d", info, n.totalLeaves)
	}
	if len(n.subCAs) > 0 {
		info = fmt.Sprintf("%s, Direct sub CAs: %d", info, len(n.subCAs))
	}
	if n.totalSubCAs > len(n.subCAs) {
		info = fmt.Sprintf("%s, Total sub CAs %d", info, n.totalSubCAs)
	}
	fmt.Println(info)
	for _, sub := range n.subCAs {
		if _, beenThere := visited[sub]; sub != n && !beenThere {
			sub.print(indent+1, visited)
		}
	}
}

type rootSet []*node

func (r rootSet) Len() int           { return len(r) }
func (r rootSet) Swap(i, j int)      { r[i], r[j] = r[j], r[i] }
func (r rootSet) Less(i, j int) bool { return r[i].totalLeaves > r[j].totalLeaves } // actually More but... you know :/

func main() {
	// filename := "google-pilot.log"
	// filename := "certly.log"
	ctCacheFile := flag.String("cacheFile", "google-pilot.log", "path to local CT cache file")
	rootsFile := flag.String("rootsFile", "/etc/ssl/certs/ca-certificates.crt", "path to file containg PEM encoded root certificates to prepopulate graph with")
	graphFile := flag.String("graphFile", "graph.json", "path to file to store aggregated graph data, CT cache file path, and curren cache offset")
	flag.Parse()

	h := holder{
		rootsFile: *rootsFile,
		gMu:       new(sync.Mutex),
		pMu:       new(sync.RWMutex),
		Graph:     make(map[string]*node),
		processed: make(map[[32]byte]struct{}),
		CacheFile: *ctCacheFile,
	}
	if *graphFile != "" {
		data, err := ioutil.ReadFile(*graphFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read graph file: %s\n", err)
			// fix me (fails on non-existent files, should match err)
			// os.Exit(1)
		}
		if len(data) > 0 {
			fmt.Println("importing data from graph file...")
			err = json.Unmarshal(data, &h)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to parse graph file: %s\n", err)
				os.Exit(1)
			}
			fmt.Printf("[added %d nodes]\n", len(h.Graph))
		}
	}
	h.addSystemRoots()
	h.createNodesFromCT()
	h.createEdges()
	if *graphFile != "" {
		data, err := json.Marshal(h)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to marshal graph: %s\n", err)
			os.Exit(1)
		}
		err = ioutil.WriteFile(*graphFile, data, 0666)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to write graph file: %s\n", err)
			os.Exit(1)
		}
	}

	// these should probably actually be chosen from a set of system root trusted certs...
	rs := rootSet{}
	for _, n := range h.Graph {
		if n.issuer == nil || n.issuer == n { // && n.totalLeaves > 0 {
			rs = append(rs, n)
		}
	}
	sort.Sort(rs)
	for i, r := range rs {
		fmt.Printf("# Size rank: %d\n", i+1)
		r.print(0, make(map[*node]struct{}))
		fmt.Printf("\n")
	}
}
