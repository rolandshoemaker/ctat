package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
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
	commonName string

	issued        int
	subCASubjects []string

	subCAs      []*node
	issuer      *node
	totalLeaves int
}

type holder struct {
	mu    *sync.Mutex
	graph map[string]*node
}

func (h *holder) createNodes(entriesFile *os.File) {
	entries := ct.EntriesFile{entriesFile}
	entries.Map(func(ent *ct.EntryAndPosition, err error) {
		if err != nil {
			return
		}
		cert, err := x509.ParseCertificate(ent.Entry.X509Cert)
		if err != nil {
			return
		}
		issuer := subjectToString(cert.Issuer)
		h.mu.Lock()
		defer h.mu.Unlock()
		if _, present := h.graph[issuer]; !present {
			h.graph[issuer] = &node{commonName: cert.Issuer.CommonName}
		}
		h.graph[issuer].issued++
		if cert.BasicConstraintsValid && cert.IsCA {
			h.graph[issuer].subCASubjects = append(h.graph[issuer].subCASubjects, subjectToString(cert.Subject))
		}
	})
}

func (h *holder) createEdges() {
	for _, n := range h.graph {
		n.totalLeaves = n.issued
		for _, subSubject := range n.subCASubjects {
			if subNode, present := h.graph[subSubject]; present {
				n.subCAs = append(n.subCAs, subNode)
				subNode.issuer = n
				n.totalLeaves += subNode.issued
			} // else {
			//	h.graph[subSubject] = &node{commonName: strings.Split(subSubject, ";;")[0]}
			// }
		}
	}
}

func (n *node) print(indent int) {
	var info string
	if indent > 0 {
		info = strings.Repeat("  ", indent) + "∟"
	} else {
		info = "+"
	}
	info = fmt.Sprintf(
		"%s CN: %s, Direct leaves: %d, Total leaves: %d, Sub CAs: %d",
		info,
		n.commonName,
		n.issued,
		n.totalLeaves,
		len(n.subCASubjects),
	)
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
func (r rootSet) Less(i, j int) bool { return r[i].totalLeaves < r[j].totalLeaves }

func main() {
	// filename := "google-pilot.log"
	filename := "certly.log"

	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open CT cache file: %s\n", err)
		os.Exit(1)
	}
	defer file.Close()

	h := holder{
		mu:    new(sync.Mutex),
		graph: make(map[string]*node),
	}
	fmt.Println("Populating graph with nodes...")
	h.createNodes(file)
	fmt.Println("Creating Edges")
	h.createEdges()
	fmt.Printf("\nResults\n\n")

	rs := rootSet{}
	for _, n := range h.graph {
		if n.issuer == nil {
			rs = append(rs, n)
		}
	}
	sort.Sort(rs)
	for _, r := range rs {
		r.print(0)
	}
}
