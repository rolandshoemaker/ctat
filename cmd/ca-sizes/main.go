package main

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	ct "github.com/jsha/certificatetransparency"
)

func escape(str string) string {
	return strings.Replace(str, ",", " -", -1)
}

func subjectToString(subject pkix.Name) string {
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
	return strings.Join(out, "; ")
	// return fmt.Sprintf("%s;;%s;;%s", subject.CommonName, subject.SerialNumber, strings.Join(append(subject.Country, append(subject.Organization, subject.OrganizationalUnit...)...), " "))
}

type rootSet []*node

func (r rootSet) Len() int           { return len(r) }
func (r rootSet) Swap(i, j int)      { r[i], r[j] = r[j], r[i] }
func (r rootSet) Less(i, j int) bool { return r[i].totalLeaves > r[j].totalLeaves } // actually More but... you know :/

type leafSet []*node

func (l leafSet) Len() int           { return len(l) }
func (l leafSet) Swap(i, j int)      { l[i], l[j] = l[j], l[i] }
func (l leafSet) Less(i, j int) bool { return l[i].Issued > l[j].Issued } // actually More but... you know :/

type node struct {
	Name          string
	Issued        int
	SubCASubjects map[string]struct{}

	subCAs      rootSet
	issuers     map[*node]struct{}
	totalLeaves int
	totalSubCAs int
}

type holder struct {
	rootsFile string

	rootNodes map[string]struct{}
	gMu       *sync.Mutex
	Graph     map[string]*node // ...loose definition
	pMu       *sync.Mutex
	processed map[[32]byte]struct{}

	CacheFile       string
	CacheFileOffset int64
	IgnoreExpiry    bool
}

func (h *holder) exportGDF() string {
	nodes, edgeMap := []string{}, make(map[string]struct{})

	i := 0
	nodeIDs := make(map[string]int)
	for _, n := range h.Graph {
		nodeIDs[n.Name] = i
		nodes = append(nodes, fmt.Sprintf("%d,%s,%d.0", i, n.Name, n.totalLeaves))
		i++
	}
	for _, n := range h.Graph {
		id := nodeIDs[n.Name]
		for _, s := range n.subCAs {
			edge := fmt.Sprintf("%d,%d", id, nodeIDs[s.Name])
			if _, present := edgeMap[edge]; !present {
				edgeMap[edge] = struct{}{}
			}
			for issuer := range n.issuers {
				otherEdge := fmt.Sprintf("%d,%d", nodeIDs[issuer.Name], id)
				if _, present := edgeMap[otherEdge]; !present {
					edgeMap[otherEdge] = struct{}{}
				}
			}
		}
	}
	edges := []string{}
	for e := range edgeMap {
		edges = append(edges, e)
	}
	return fmt.Sprintf(
		"nodedef>name VARCHAR,label VARCHAR,totalChildLeaves DOUBLE\n%s\nedgedef>node1 VARCHAR,node2 VARCHAR\n%s\n",
		strings.Join(nodes, "\n"),
		strings.Join(edges, "\n"),
	)
}

func (h *holder) addNode(rawCert []byte) *node {
	certFP := sha256.Sum256(rawCert)
	h.pMu.Lock()
	if _, alreadyDone := h.processed[certFP]; alreadyDone {
		h.pMu.Unlock()
		return nil
	}
	h.processed[certFP] = struct{}{}
	h.pMu.Unlock()

	cert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		// fmt.Println(err)
		return nil
	}
	if !h.IgnoreExpiry && time.Now().After(cert.NotAfter) {
		return nil
	}
	issuer := subjectToString(cert.Issuer)

	h.gMu.Lock()
	defer h.gMu.Unlock()
	subject := subjectToString(cert.Subject)
	n := &node{Name: issuer, SubCASubjects: make(map[string]struct{}), issuers: make(map[*node]struct{})}
	if issuer == "" && (cert.IsCA && cert.BasicConstraintsValid) {
		if _, present := h.Graph[subject]; !present && subject != "" {
			h.Graph[subject] = n
			return n
		}
		return nil
	}

	if _, present := h.Graph[issuer]; !present {
		h.Graph[issuer] = n
	}
	h.Graph[issuer].Issued++

	if cert.BasicConstraintsValid && cert.IsCA {
		if _, present := h.Graph[subject]; !present {
			n.Name = subject
			h.Graph[subject] = n
		}
		if _, present := h.Graph[issuer].SubCASubjects[subject]; !present && issuer != subject {
			h.Graph[issuer].SubCASubjects[subject] = struct{}{}
		}
	}
	return n
}

func (h *holder) addRootsFromFile() {
	fmt.Printf("adding roots to graph from %s...\n", h.rootsFile)
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

func (h *holder) addRootsFromLog(logURI string) {
	fmt.Println("adding roots from CT log")
	startingCount := len(h.Graph)
	resp, err := http.Get(fmt.Sprintf("%s/ct/v1/get-roots", logURI))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get CT log roots: %s\n", err)
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read CT log roots response: %s\n", err)
		return
	}
	var encodedRoots struct {
		Certificates []string `json:"certificates"`
	}
	err = json.Unmarshal(body, &encodedRoots)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse CT log roots response: %s\n", err)
		return
	}
	for _, encodedRoot := range encodedRoots.Certificates {
		rawCert, err := base64.StdEncoding.DecodeString(encodedRoot)
		if err != nil {
			continue
		}
		if n := h.addNode(rawCert); n != nil {
			h.rootNodes[n.Name] = struct{}{}
		}
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
				if subNode != n {
					if _, present := subNode.issuers[n]; !present {
						subNode.issuers[n] = struct{}{}
					}
					n.subCAs = append(n.subCAs, subNode)
					edges++
				}
			}
		}
	}
	fmt.Printf("[created %d edges]\n", edges)
	fmt.Println("calculating cumulative leaves and sub CAs...")
	leavesVisited, subsVisited := make(map[*node]struct{}), make(map[*node]struct{})
	for _, n := range h.Graph {
		if _, present := h.rootNodes[n.Name]; present {
			n.setTotalLeaves(leavesVisited)
			n.setTotalSubs(subsVisited)
		}
	}
}

func (n *node) print(indent int, visited map[*node]struct{}) {
	visited[n] = struct{}{}
	var info string
	padding := strings.Repeat("  ", indent)
	if indent > 0 {
		info = padding + "∟"
	} else {
		info = "+"
	}
	info = fmt.Sprintf(
		"%s %s\n%s  Direct leaves: %d",
		info,
		n.Name,
		padding,
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
	if len(n.issuers) > 1 {
		info = fmt.Sprintf("%s [Cross-signed by %d other parents]", info, len(n.issuers)-1)
	}
	fmt.Println(info)
	sort.Sort(n.subCAs)
	for _, sub := range n.subCAs {
		if _, beenThere := visited[sub]; sub != n && !beenThere {
			sub.print(indent+1, visited)
		}
	}
}

func main() {
	ctCacheFile := flag.String("cacheFile", "google-pilot.log", "path to local CT cache file")
	rootsFile := flag.String("rootsFile", "", "path to file containg PEM encoded root certificates to prepopulate graph with")
	logURI := flag.String("logURI", "", "URI for a CT log to pull roots from to prepopulate graph with")
	graphFile := flag.String("graphFile", "graph.json", "path to file to store aggregated graph data, CT cache file path, and curren cache offset")
	ignoreExpiry := flag.Bool("ignoreExpiry", false, "include expired certificates (both leaves, intermediates, and roots)")
	flag.Parse()

	h := holder{
		rootsFile:    *rootsFile,
		rootNodes:    make(map[string]struct{}),
		gMu:          new(sync.Mutex),
		pMu:          new(sync.Mutex),
		Graph:        make(map[string]*node),
		processed:    make(map[[32]byte]struct{}),
		CacheFile:    *ctCacheFile,
		IgnoreExpiry: *ignoreExpiry,
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
			for _, n := range h.Graph {
				n.issuers = make(map[*node]struct{})
			}
			fmt.Printf("[added %d nodes]\n", len(h.Graph))
		}
	}
	if *rootsFile != "" {
		h.addRootsFromFile()
	}
	if *logURI != "" {
		h.addRootsFromLog(*logURI)
	}
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

	// fmt.Println(h.exportGDF())
	// os.Exit(0)

	// these should probably actually be chosen from a set of system root trusted certs...
	rs := rootSet{}
	ls := leafSet{}
	for _, n := range h.Graph {
		if _, present := h.rootNodes[n.Name]; present {
			rs = append(rs, n)
		}
		if len(n.subCAs) == 0 && n.Issued > 1000 {
			ls = append(ls, n)
		}
	}
	sort.Sort(rs)
	sort.Sort(ls)
	fmt.Printf("## CA hierarchies sorted by total leaves below the root\n\n")
	visited := make(map[*node]struct{})
	i := 0
	for _, r := range rs {
		if _, beenThere := visited[r]; beenThere {
			continue
		}
		fmt.Printf("# Size rank: %d\n", i+1)
		r.print(0, visited)
		fmt.Printf("\n")
		i++
	}

	fmt.Printf("## Largest issuers with no sub CAs (with > 1000 leaves)\n\n")
	for i, l := range ls {
		fmt.Printf("  Rank %d:\t%d\t%s\n", i+1, l.Issued, l.Name)
	}
}
