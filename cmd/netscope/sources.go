package main

import (
	"fmt"
	"io"
	"net/http"
)

type passiveSourceAdapter interface {
	Name() string
	Category() string
	Fetch(client *http.Client, domain string, sourceLimit int) (passiveSourceResult, error)
}

type passiveSourceFunc struct {
	name     string
	category string
	fetch    func(*http.Client, string, int) (passiveSourceResult, error)
}

func (s passiveSourceFunc) Name() string {
	return s.name
}

func (s passiveSourceFunc) Category() string {
	return s.category
}

func (s passiveSourceFunc) Fetch(client *http.Client, domain string, sourceLimit int) (passiveSourceResult, error) {
	return s.fetch(client, domain, sourceLimit)
}

func builtInPassiveSources() []passiveSourceAdapter {
	return []passiveSourceAdapter{
		passiveSourceFunc{name: "crtsh", category: "certificate-transparency", fetch: func(client *http.Client, domain string, _ int) (passiveSourceResult, error) {
			names, err := fetchCRTSubdomains(client, domain)
			return passiveSourceResult{Subdomains: names}, err
		}},
		passiveSourceFunc{name: "certspotter", category: "certificate-transparency", fetch: fetchCertSpotterSubdomains},
		passiveSourceFunc{name: "hackertarget", category: "passive-dns-style", fetch: fetchHackerTargetSubdomains},
		passiveSourceFunc{name: "threatminer", category: "passive-dns-style", fetch: fetchThreatMinerSubdomains},
		passiveSourceFunc{name: "wayback", category: "archive-search", fetch: fetchWaybackSubdomains},
		passiveSourceFunc{name: "anubis", category: "archive-search", fetch: fetchAnubisSubdomains},
		passiveSourceFunc{name: "subdomain-center", category: "passive-dns-style", fetch: fetchSubdomainCenterSubdomains},
		passiveSourceFunc{name: "urlscan", category: "search-index", fetch: fetchURLScanSubdomains},
	}
}

func runSourcesCommand(args []string, stdout io.Writer) error {
	if len(args) == 0 || hasHelpFlag(args) {
		fmt.Fprint(stdout, `netscope sources

Usage:
  netscope sources list

Lists built-in passive source adapters. Enable/disable defaults through enabled_passive_sources in config.toml or per-run --sources.
`)
		return nil
	}
	switch args[0] {
	case "list":
		for _, source := range builtInPassiveSources() {
			fmt.Fprintf(stdout, "%s\t%s\n", source.Name(), source.Category())
		}
		fmt.Fprintln(stdout, "dns-google\tpublic-dns")
		fmt.Fprintln(stdout, "rdap\trdap")
		return nil
	default:
		return fmt.Errorf("unknown sources command %q", args[0])
	}
}
