package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
)

type diffOptions struct {
	Old       string
	New       string
	Format    string
	Out       string
	Workspace string
	OldRun    int64
	NewRun    int64
}

type diffResult struct {
	AssetsAdded      []string `json:"assets_added"`
	AssetsRemoved    []string `json:"assets_removed"`
	PortsOpened      []string `json:"ports_opened"`
	PortsClosed      []string `json:"ports_closed"`
	ServicesChanged  []string `json:"services_changed"`
	FindingsAdded    []string `json:"findings_added"`
	FindingsResolved []string `json:"findings_resolved"`
	TLSChanged       []string `json:"tls_changed"`
	DNSChanged       []string `json:"dns_changed"`
}

func runDiff(args []string, stdout io.Writer) error {
	opts, err := parseDiffOptions(args)
	if err != nil {
		return err
	}
	if opts.Workspace != "" {
		if opts.Old == "" && opts.OldRun > 0 {
			opts.Old, err = workspaceRunJSONLPath(opts.Workspace, opts.OldRun)
			if err != nil {
				return err
			}
		}
		if opts.New == "" && opts.NewRun > 0 {
			opts.New, err = workspaceRunJSONLPath(opts.Workspace, opts.NewRun)
			if err != nil {
				return err
			}
		}
	}
	oldEvents, err := readResultEvents(opts.Old)
	if err != nil {
		return err
	}
	newEvents, err := readResultEvents(opts.New)
	if err != nil {
		return err
	}
	diff := compareResults(summarizeEvents(oldEvents), summarizeEvents(newEvents))
	var content []byte
	switch opts.Format {
	case "text":
		content = []byte(renderTextDiff(diff))
	case "json":
		content, err = json.MarshalIndent(diff, "", "  ")
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("--format must be text or json")
	}
	if opts.Out != "" {
		return os.WriteFile(opts.Out, content, 0o600)
	}
	_, err = stdout.Write(content)
	return err
}

func parseDiffOptions(args []string) (diffOptions, error) {
	var opts diffOptions
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.StringVar(&opts.Old, "old", "", "old scan/recon JSONL file")
	fs.StringVar(&opts.New, "new", "", "new scan/recon JSONL file")
	fs.StringVar(&opts.Format, "format", "text", "diff format: text or json")
	fs.StringVar(&opts.Out, "out", "", "write diff to this file")
	fs.StringVar(&opts.Workspace, "workspace", "", "workspace name for --old-run/--new-run")
	fs.Int64Var(&opts.OldRun, "old-run", 0, "old workspace run id")
	fs.Int64Var(&opts.NewRun, "new-run", 0, "new workspace run id")
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	if (opts.Old == "" || opts.New == "") && (opts.Workspace == "" || opts.OldRun <= 0 || opts.NewRun <= 0) {
		return opts, fmt.Errorf("diff requires --old and --new, or --workspace with --old-run and --new-run")
	}
	if opts.Format != "text" && opts.Format != "json" {
		return opts, fmt.Errorf("--format must be text or json")
	}
	return opts, nil
}

func compareResults(oldSet, newSet resultSet) diffResult {
	oldServices := mapByServiceKey(oldSet.Services)
	newServices := mapByServiceKey(newSet.Services)
	oldFindings := mapByFindingKey(oldSet.Findings)
	newFindings := mapByFindingKey(newSet.Findings)
	return diffResult{
		AssetsAdded:      setAdded(oldSet.Assets, newSet.Assets),
		AssetsRemoved:    setRemoved(oldSet.Assets, newSet.Assets),
		PortsOpened:      setAdded(oldSet.Ports, newSet.Ports),
		PortsClosed:      setRemoved(oldSet.Ports, newSet.Ports),
		ServicesChanged:  changedServices(oldServices, newServices),
		FindingsAdded:    setAdded(keysOfFindings(oldFindings), keysOfFindings(newFindings)),
		FindingsResolved: setRemoved(keysOfFindings(oldFindings), keysOfFindings(newFindings)),
		TLSChanged:       symmetricChanged(oldSet.TLSItems, newSet.TLSItems),
		DNSChanged:       symmetricChanged(oldSet.DNSRecords, newSet.DNSRecords),
	}
}

func renderTextDiff(diff diffResult) string {
	var b strings.Builder
	b.WriteString("Netscope diff\n\n")
	writeDiffSection(&b, "assets_added", diff.AssetsAdded)
	writeDiffSection(&b, "assets_removed", diff.AssetsRemoved)
	writeDiffSection(&b, "ports_opened", diff.PortsOpened)
	writeDiffSection(&b, "ports_closed", diff.PortsClosed)
	writeDiffSection(&b, "services_changed", diff.ServicesChanged)
	writeDiffSection(&b, "findings_added", diff.FindingsAdded)
	writeDiffSection(&b, "findings_resolved", diff.FindingsResolved)
	writeDiffSection(&b, "tls_changed", diff.TLSChanged)
	writeDiffSection(&b, "dns_changed", diff.DNSChanged)
	return b.String()
}

func writeDiffSection(b *strings.Builder, title string, values []string) {
	fmt.Fprintf(b, "%s: %d\n", title, len(values))
	for _, value := range values {
		fmt.Fprintf(b, "  - %s\n", value)
	}
	b.WriteByte('\n')
}

func setAdded(oldValues, newValues []string) []string {
	oldSet := sliceSet(oldValues)
	var out []string
	for _, value := range newValues {
		if !oldSet[value] {
			out = append(out, value)
		}
	}
	return out
}

func setRemoved(oldValues, newValues []string) []string {
	newSet := sliceSet(newValues)
	var out []string
	for _, value := range oldValues {
		if !newSet[value] {
			out = append(out, value)
		}
	}
	return out
}

func symmetricChanged(oldValues, newValues []string) []string {
	out := append(setAdded(oldValues, newValues), setRemoved(oldValues, newValues)...)
	sort.Strings(out)
	return out
}

func sliceSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}

func mapByServiceKey(values []serviceSummary) map[string]serviceSummary {
	out := make(map[string]serviceSummary, len(values))
	for _, value := range values {
		out[value.Key] = value
	}
	return out
}

func changedServices(oldValues, newValues map[string]serviceSummary) []string {
	var out []string
	for key, newValue := range newValues {
		if oldValue, ok := oldValues[key]; ok && !reflect.DeepEqual(oldValue, newValue) {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

func mapByFindingKey(values []findingSummary) map[string]findingSummary {
	out := make(map[string]findingSummary, len(values))
	for _, value := range values {
		out[value.Key] = value
	}
	return out
}

func keysOfFindings(values map[string]findingSummary) []string {
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
