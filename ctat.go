package main

import (
	"fmt"
	"os"

	"github.com/rolandshoemaker/ctat/downloader"
	"github.com/rolandshoemaker/ctat/graph"
	"github.com/rolandshoemaker/ctat/stats"

	"github.com/codegansta/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "ctat"
	app.Usage = "tools for analysing data from certificate transparency logs"

	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name: "verbose",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:  "download",
			Usage: "Download/update a local cache file for a remote ct log",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name: "logURI",
				},
				cli.StringFlag{
					Name: "logKey",
				},
				cli.StringFlag{
					Name: "cacheFile",
				},
			},
			Action: func(c *cli.Context) {
				if c.String("logURI") == "" || c.String("logKey") == "" || c.String("cacheFile") == "" {
					fmt.Fprintf(os.Stderr, "--logURI, --logKey, and --cacheFile are required\n")
					os.Exit(1)
				}
				err := downloader.Download(c.String("logURI"), c.String("logKey"), c.String("cacheFile"))
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s\n", err)
					os.Exit(1)
				}
			},
		},
		{
			Name:  "ca-graph",
			Usage: "Various CA graph tools",
			Subcommands: []cli.Command{
				{
					Name:  "build",
					Usage: "Build JSON representation of a cache file from which graph edges can be built/analyzed",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name: "cacheFile",
						},
						cli.StringFlag{
							Name: "graphFile",
						},
						cli.StringFlag{
							Name: "rootsFile",
						},
						cli.StringFlag{
							Name: "rootsURI",
						},
						cli.StringFlag{
							Name: "filters",
						},
					},
					Action: func(c *cli.Context) {
						if c.String("cacheFile") == "" || c.String("graphFile") == "" {
							fmt.Fprintf(os.Stderr, "--cacheFile and --graphFile are required\n")
							os.Exit(1)
						}
						err := graph.Build(c.String("rootsFile"), c.String("rootsURI"), c.String("cacheFile"), c.String("graphFile"), c.String("filters"), c.GlobalBool("verbose"))
						if err != nil {
							fmt.Fprintf(os.Stderr, "Failed to build CA graph: %s\n", err)
							os.Exit(1)
						}
					},
				},
				{
					Name:  "issuer-lineages",
					Usage: "Print root->sub-CA lineages",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name: "graphFile",
						},
					},
					Action: func(c *cli.Context) {
						if c.String("graphFile") == "" {
							fmt.Fprintf(os.Stderr, "--graphFile are required\n")
							os.Exit(1)
						}
						g, err := graph.LoadGraph(c.String("graphFile"))
						if err != nil {
							fmt.Fprintf(os.Stderr, "Failed to load graph from disk: %s\n", err)
							os.Exit(1)
						}
						g.PrintLineages()
					},
				},
				{
					Name:  "export",
					Usage: "Convert a JSON graph representation to a GDF graph file",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name: "graphFile",
						},
						cli.StringFlag{
							Name: "gdfFile",
						},
					},
					Action: func(c *cli.Context) {
						if c.String("graphFile") == "" || c.String("gdfFile") == "" {
							fmt.Fprintf(os.Stderr, "--graphFile and --gdfFile are required\n")
							os.Exit(1)
						}
						g, err := graph.LoadGraph(c.String("graphFile"))
						if err != nil {
							fmt.Fprintf(os.Stderr, "Failed to load graph from disk: %s\n", err)
							os.Exit(1)
						}
						if err = g.ExportGDF(c.String("gdfFile")); err != nil {
							fmt.Fprintf(os.Stderr, "Failed to save GDF to disk: %s\n", err)
							os.Exit(1)
						}
					},
				},
			},
		},
		{
			Name:  "stats",
			Usage: "Various cache file analysis tools",
			Subcommands: []cli.Command{
				{
					Name: "analyse",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name: "cacheFile",
						},
						cli.StringFlag{
							Name: "filters",
						},
					},
					Action: func(c *cli.Context) {
						err := stats.Analyse(c.String("cacheFile"), c.String("filters"))
						if err != nil {
							fmt.Fprintf(os.Stderr, "Failed to parse cache file: %s\n", err)
							os.Exit(1)
						}
					},
				},
			},
		},
		{
			Name:  "scanner",
			Usage: "Host extracter + TLS scanner (generates adoption/failure stats for HTTPS deployment)",
		},
	}

	app.Run(os.Args)
}
