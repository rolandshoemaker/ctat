package graph

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rolandshoemaker/ctat/common"
	"github.com/rolandshoemaker/ctat/filter"

	ct "github.com/rolandshoemaker/certificatetransparency"
)

type rootSet []*node

func (r rootSet) Len() int           { return len(r) }
func (r rootSet) Swap(i, j int)      { r[i], r[j] = r[j], r[i] }
func (r rootSet) Less(i, j int) bool { return r[i].totalLeaves > r[j].totalLeaves } // actually More but... you know :/

type node struct {
	Name            string
	Issued          int
	SubCASubjects   map[string]struct{}
	InitialRootNode bool
	NotAfter        time.Time
	OCSPStatus      string
	SeenCert        bool

	subCAs      rootSet
	issuers     map[*node]struct{}
	totalLeaves int
	totalSubCAs int
	certificate *x509.Certificate
}

func (n *node) setChainProperties(visited map[*node]struct{}) (int, int) {
	visited[n] = struct{}{}
	leaves := n.Issued
	subs := len(n.subCAs)
	for _, sub := range n.subCAs {
		if _, beenThere := visited[sub]; !beenThere {
			leavesBelow, subsBelow := sub.setChainProperties(visited)
			leaves += leavesBelow
			subs += subsBelow
		}
	}
	sort.Sort(n.subCAs)
	n.totalLeaves = leaves
	n.totalSubCAs = subs
	return leaves, subs
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
	// sort.Sort(n.subCAs)
	for _, sub := range n.subCAs {
		if _, beenThere := visited[sub]; !beenThere {
			sub.print(indent+1, visited)
		}
	}
}

func (n *node) remove(graph IssuerGraph) {
	for _, sub := range n.subCAs {
		delete(sub.issuers, n)
		if len(sub.issuers) == 0 && sub != n {
			sub.remove(graph)
		}
	}
	delete(graph, n.Name)
}

type IssuerGraph map[string]*node // ...loose definition

func LoadGraph(filename string) (IssuerGraph, error) {
	var graph IssuerGraph
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return graph, err
	}

	err = json.Unmarshal(data, &graph)
	if err != nil {
		return graph, err
	}
	for _, n := range graph {
		n.issuers = make(map[*node]struct{})
	}
	graph.createEdges()
	return graph, nil
}

func (g IssuerGraph) PrintLineages() {
	visited := make(map[*node]struct{})
	rs := rootSet{}
	impliedNodes := 0
	for _, n := range g {
		if n.InitialRootNode {
			rs = append(rs, n)
		}
		if !n.SeenCert {
			impliedNodes++
		}
	}
	fmt.Printf("!! There were %d nodes only implied by a issued leaf !!\n", impliedNodes)
	sort.Sort(rs)
	i := 1
	for _, r := range rs {
		if _, beenThere := visited[r]; !beenThere {
			fmt.Printf("# Size rank: %d\n", i)
			r.print(0, visited)
			fmt.Printf("\n")
			i++
		}
	}
}

func (g IssuerGraph) ExportGDF(filename string) error {
	nodes, edgeMap := []string{}, make(map[string]struct{})

	i := 0
	nodeIDs := make(map[string]int)
	for _, n := range g {
		nodeIDs[n.Name] = i
		nodes = append(nodes, fmt.Sprintf("%d,%s,%d.0", i, n.Name, n.totalLeaves))
		i++
	}
	for _, n := range g {
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
	output := fmt.Sprintf(
		"nodedef>name VARCHAR,label VARCHAR,totalChildLeaves DOUBLE\n%s\nedgedef>node1 VARCHAR,node2 VARCHAR\n%s\n",
		strings.Join(nodes, "\n"),
		strings.Join(edges, "\n"),
	)

	return ioutil.WriteFile(filename, []byte(output), os.ModePerm)
}

func (g IssuerGraph) createEdges() {
	fmt.Println("creating edges...")
	edges := 0
	for _, n := range g {
		for subSubject := range n.SubCASubjects {
			if subNode, present := g[subSubject]; present {
				if _, present := subNode.issuers[n]; !present {
					subNode.issuers[n] = struct{}{}
				}
				n.subCAs = append(n.subCAs, subNode)
				edges++
			}
		}
	}
	fmt.Printf("[created %d edges]\n", edges)
	fmt.Printf("calculating number of child leaves and sub CAs...\n\n")
	visited := make(map[*node]struct{})
	for _, n := range g {
		if _, beenThere := visited[n]; !beenThere && n.InitialRootNode {
			n.setChainProperties(visited)
		}
	}
}

func (g IssuerGraph) removeRevokedNodes() {
	// for _, n := range g {

	// }
}

type builder struct {
	filters []filter.Filter

	pMu       *sync.Mutex
	processed map[[32]byte]struct{}

	gMu   *sync.Mutex
	graph IssuerGraph

	verbose bool
}

func (b *builder) addAnchorsFromFile(anchorsFile string) {
	fmt.Printf("adding trust anchors to graph from %s...\n", anchorsFile)
	startingCount := len(b.graph)
	data, err := ioutil.ReadFile(anchorsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read trust anchors file: %s\n", err)
		return
	}
	for {
		block, r := pem.Decode(data)
		if block == nil || len(block.Bytes) == 0 {
			break
		}
		if n := b.addNode(block.Bytes); n != nil {
			n.InitialRootNode = true
		}
		data = r
	}
	fmt.Printf("[added %d nodes]\n", len(b.graph)-startingCount)
}

func (b *builder) addAnchorsFromLog(logURI string) {
	fmt.Println("adding roots from CT log")
	startingCount := len(b.graph)
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
		if n := b.addNode(rawCert); n != nil {
			n.InitialRootNode = true
		}
	}
	fmt.Printf("[added %d nodes]\n", len(b.graph)-startingCount)
}

func (b *builder) addNode(rawCert []byte) *node {
	certFP := sha256.Sum256(rawCert)
	b.pMu.Lock()
	if _, alreadyDone := b.processed[certFP]; alreadyDone {
		b.pMu.Unlock()
		return nil
	}
	b.processed[certFP] = struct{}{}
	b.pMu.Unlock()

	cert, skip, err := common.ParseAndFilter(rawCert, b.filters)
	if skip || err != nil {
		if err != nil {
			if b.verbose {
				fmt.Fprintf(os.Stderr, "error while filtering entries: %s\n", err)
			}
		}
		return nil
	}

	issuer := common.SubjectToString(cert.Issuer)
	if issuer == "???" {
		// idk when this would happen but... w/e
		if b.verbose {
			fmt.Fprintf(os.Stderr, "certificate had no issuer DN\n")
		}
		return nil
	}

	b.gMu.Lock()
	defer b.gMu.Unlock()
	if _, present := b.graph[issuer]; !present {
		b.graph[issuer] = &node{Name: issuer, SubCASubjects: make(map[string]struct{})}
	}
	i := b.graph[issuer]
	i.Issued++

	if cert.BasicConstraintsValid && cert.IsCA {
		subject := common.SubjectToString(cert.Subject)
		if subject == "???" {
			// idk when this would happen but... w/e
			fmt.Fprintf(os.Stderr, "certificate had no subject DN\n")
			return nil
		}
		if _, present := i.SubCASubjects[subject]; !present {
			i.SubCASubjects[subject] = struct{}{}
		}
		if existing, present := b.graph[subject]; !present {
			b.graph[subject] = &node{Name: subject, SubCASubjects: make(map[string]struct{}), SeenCert: true}
		} else if present && !existing.SeenCert {
			existing.SeenCert = true
		}
		return b.graph[subject]
	}
	return i
}

func (b *builder) createNodesFromCT(entries *ct.EntriesFile) {
	started := time.Now()
	startingCount := len(b.graph)
	fmt.Println("adding nodes from CT cache file...")
	entries.Map(func(ent *ct.EntryAndPosition, err error) {
		if err != nil {
			if b.verbose {
				fmt.Fprintf(os.Stderr, "error parsing ct entry: %s\n", err)
			}
			return
		}
		if ent.Entry.Type != ct.X509Entry {
			return
		}
		for _, extraCert := range ent.Entry.ExtraCerts {
			b.addNode(extraCert)
		}
		b.addNode(ent.Entry.X509Cert)
	})
	fmt.Printf("[added %d nodes]\ntook %s\n", len(b.graph)-startingCount, time.Since(started))
}

func Build(rootsFile, rootsURI, cacheFile, graphFile, filters string, verbose bool) error {
	b := builder{
		verbose:   verbose,
		gMu:       new(sync.Mutex),
		pMu:       new(sync.Mutex),
		graph:     make(map[string]*node),
		processed: make(map[[32]byte]struct{}),
	}
	if filters != "" {
		var err error
		b.filters, err = filter.StringToFilters(filters)
		if err != nil {
			return err
		}
	}
	if rootsFile != "" {
		b.addAnchorsFromFile(rootsFile)
	}
	if rootsURI != "" {
		b.addAnchorsFromLog(rootsURI)
	}

	entries, err := common.LoadCacheFile(cacheFile)
	if err != nil {
		return err
	}
	defer entries.Close()
	b.createNodesFromCT(entries)
	data, err := json.Marshal(b.graph)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(graphFile, data, 0666)
	if err != nil {
		return err
	}

	return nil
}
