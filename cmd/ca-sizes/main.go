package main

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strings"
	"sync"

	ct "github.com/jsha/certificatetransparency"
)

func subjectToString(subject pkix.Name) string {
	return fmt.Sprintf("%s;;%s;;%s;;%s", subject.CommonName, subject.SerialNumber, strings.Join(append(subject.Country, append(subject.Organization, subject.OrganizationalUnit...)...), " "), subject.SerialNumber)
}

type node struct {
	name string

	issued        int
	subCASubjects []string

	subCAs      map[string]*node
	issuer      *node
	totalLeaves int
	totalSubCAs int
}

type holder struct {
	gMu       *sync.Mutex
	graph     map[string]*node // ...loose definition
	pMu       *sync.RWMutex
	processed map[[32]byte]struct{}
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
	if issuer == ";;;;;;" {
		subject := subjectToString(cert.Subject)
		if _, present := h.graph[subject]; !present && subject != ";;;;;;" {
			name := ""
			if cert.Issuer.CommonName != "" {
				name = cert.Issuer.CommonName
			} else if len(cert.Issuer.Organization) > 0 {
				name = strings.Join(cert.Issuer.Organization, " ")
			} else {
				name = "???"
			}
			h.graph[subject] = &node{name: name, subCAs: make(map[string]*node)}
		}
		return
	}
	if _, present := h.graph[issuer]; !present {
		name := ""
		if cert.Issuer.CommonName != "" {
			name = cert.Issuer.CommonName
		} else if len(cert.Issuer.Organization) > 0 {
			name = strings.Join(cert.Issuer.Organization, " ")
		} else {
			name = "???"
		}
		h.graph[issuer] = &node{name: name, subCAs: make(map[string]*node)}
	}

	h.graph[issuer].issued++
	subject := subjectToString(cert.Subject)
	if cert.BasicConstraintsValid && cert.IsCA && issuer != subject {
		h.graph[issuer].subCASubjects = append(h.graph[issuer].subCASubjects, subject)
	}
	h.pMu.Lock()
	h.processed[certFP] = struct{}{}
	h.pMu.Unlock()
}

var certFiles = []string{"/etc/ssl/certs/ca-certificates.crt"}

func (h *holder) addSystemRoots() {
	for _, file := range certFiles {
		data, err := ioutil.ReadFile(file)
		if err == nil {
			certs, err := x509.ParseCertificates(data)
			if err != nil {
				continue
			}
			for _, c := range certs {
				h.addNode(c.Raw)
			}
			return
		}
	}
	return
}

func (h *holder) createNodes(entriesFile *os.File) {
	// pre-populate roots form system (...)
	h.addSystemRoots()

	entries := ct.EntriesFile{entriesFile}
	entries.Map(func(ent *ct.EntryAndPosition, err error) {
		if err != nil {
			// fmt.Println(err)
			return
		}
		// if ent.Entry.Type != ct.X509Entry {
		// 	return
		// }
		h.addNode(ent.Entry.X509Cert)
		for _, extraCert := range ent.Entry.ExtraCerts {
			h.addNode(extraCert)
		}
	})
}

func (n *node) setTotalLeaves() int {
	leaves := n.issued
	for _, sub := range n.subCAs {
		if sub != n {
			leaves += sub.setTotalLeaves()
		}
	}
	n.totalLeaves = leaves
	return leaves
}

func (n *node) setTotalSubs() int {
	subs := len(n.subCAs)
	for _, sub := range n.subCAs {
		if sub != n {
			subs += sub.setTotalSubs()
		}
	}
	n.totalSubCAs = subs
	return subs
}

func (h *holder) createEdges() int {
	edges := 0
	for _, n := range h.graph {
		// n.totalLeaves = n.issued
		for _, subSubject := range n.subCASubjects {
			if subNode, present := h.graph[subSubject]; present {
				if subNode.issuer == nil {
					subNode.issuer = n
				}
				if subNode != n {
					if _, present := n.subCAs[subSubject]; !present {
						n.subCAs[subSubject] = subNode
						edges++
					}
				}
			}
		}
	}
	for _, n := range h.graph {
		if n.issuer == nil || n.issuer == n {
			n.setTotalLeaves()
			n.setTotalSubs()
		}
	}
	return edges
}

func (n *node) print(indent int) {
	var info string
	if indent > 0 {
		info = strings.Repeat("  ", indent) + "∟"
	} else {
		info = "+"
	}
	info = fmt.Sprintf(
		"%s %s, Direct leaves: %d",
		info,
		n.name,
		n.issued,
	)
	if n.totalLeaves > n.issued {
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
		if sub != n {
			sub.print(indent + 1)
		}
	}
}

type rootSet []*node

func (r rootSet) Len() int           { return len(r) }
func (r rootSet) Swap(i, j int)      { r[i], r[j] = r[j], r[i] }
func (r rootSet) Less(i, j int) bool { return r[i].totalLeaves > r[j].totalLeaves } // actually More but... you know :/

func main() {
	filename := "google-pilot.log"
	// filename := "certly.log"

	file, err := os.OpenFile(filename, os.O_RDONLY, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open CT cache file: %s\n", err)
		os.Exit(1)
	}
	defer file.Close()

	h := holder{
		gMu:       new(sync.Mutex),
		pMu:       new(sync.RWMutex),
		graph:     make(map[string]*node),
		processed: make(map[[32]byte]struct{}),
	}
	fmt.Printf("Populating graph with nodes...")
	h.createNodes(file)
	fmt.Printf(" [created %d nodes]\n", len(h.graph))
	fmt.Printf("Creating Edges...")
	edges := h.createEdges()
	fmt.Printf(" [created %d edges]\n", edges)
	fmt.Printf("\nResults\n\n")

	// these should probably actually be chosen from a set of system root trusted certs...
	rs := rootSet{}
	for _, n := range h.graph {
		if n.issuer == nil || n.issuer == n { // && n.totalLeaves > 0 {
			rs = append(rs, n)
		}
	}
	sort.Sort(rs)
	for i, r := range rs {
		fmt.Printf("# Size rank: %d\n", i+1)
		r.print(0)
		fmt.Printf("\n")
	}
}
