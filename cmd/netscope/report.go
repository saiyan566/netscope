package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"os"
	"strings"
)

type reportOptions struct {
	Input     string
	Format    string
	Out       string
	Workspace string
	RunID     int64
}

func runReport(args []string, stdout io.Writer) error {
	opts, err := parseReportOptions(args)
	if err != nil {
		return err
	}
	if opts.Input == "" && opts.Workspace != "" && opts.RunID > 0 {
		opts.Input, err = workspaceRunJSONLPath(opts.Workspace, opts.RunID)
		if err != nil {
			return err
		}
	}
	events, err := readResultEvents(opts.Input)
	if err != nil {
		return err
	}
	content, err := renderReport(summarizeEvents(events), opts.Format)
	if err != nil {
		return err
	}
	if opts.Out != "" {
		return os.WriteFile(opts.Out, content, 0o600)
	}
	_, err = stdout.Write(content)
	return err
}

func parseReportOptions(args []string) (reportOptions, error) {
	var opts reportOptions
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.StringVar(&opts.Input, "input", "", "scan or recon JSONL input")
	fs.StringVar(&opts.Format, "format", "markdown", "report format: text, json, jsonl, markdown, html, csv, or sarif")
	fs.StringVar(&opts.Out, "out", "", "write report to this file")
	fs.StringVar(&opts.Workspace, "workspace", "", "workspace name for --run")
	fs.Int64Var(&opts.RunID, "run", 0, "workspace run id to report")
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	if opts.Input == "" && (opts.Workspace == "" || opts.RunID <= 0) {
		return opts, fmt.Errorf("report requires --input or --workspace with --run")
	}
	switch opts.Format {
	case "text", "json", "jsonl", "markdown", "html", "csv", "sarif":
	default:
		return opts, fmt.Errorf("--format must be text, json, jsonl, markdown, html, csv, or sarif")
	}
	return opts, nil
}

func renderReport(results resultSet, format string) ([]byte, error) {
	switch format {
	case "text":
		return []byte(renderTextReport(results)), nil
	case "json":
		return json.MarshalIndent(results, "", "  ")
	case "jsonl":
		var buf bytes.Buffer
		for _, event := range results.Events {
			line, err := json.Marshal(event)
			if err != nil {
				return nil, err
			}
			buf.Write(line)
			buf.WriteByte('\n')
		}
		return buf.Bytes(), nil
	case "markdown":
		return []byte(renderMarkdownReport(results)), nil
	case "html":
		return []byte(renderHTMLReport(results)), nil
	case "csv":
		return renderCSVReport(results)
	case "sarif":
		return renderSARIFReport(results)
	default:
		return nil, fmt.Errorf("unsupported report format %q", format)
	}
}

func renderTextReport(results resultSet) string {
	var b strings.Builder
	b.WriteString("Netscope report\n\n")
	b.WriteString(reportSummaryLine(results))
	b.WriteString("\n\nAssets\n")
	writeStringList(&b, results.Assets)
	b.WriteString("\nExposed services\n")
	for _, service := range results.Services {
		fmt.Fprintf(&b, "- %s %s %s\n", service.Key, service.Service, service.Banner)
	}
	b.WriteString("\nFindings\n")
	writeFindingList(&b, results.Findings, false)
	return b.String()
}

func renderMarkdownReport(results resultSet) string {
	var b strings.Builder
	b.WriteString("# Netscope Report\n\n")
	b.WriteString("## Executive Summary\n\n")
	b.WriteString(reportSummaryLine(results))
	b.WriteString("\n\n## Assets\n\n")
	writeStringList(&b, results.Assets)
	b.WriteString("\n## Exposed Services\n\n")
	for _, service := range results.Services {
		fmt.Fprintf(&b, "- `%s` `%s` %s\n", service.Key, service.Service, service.Banner)
	}
	b.WriteString("\n## Findings\n\n")
	writeFindingList(&b, results.Findings, true)
	return b.String()
}

func renderHTMLReport(results resultSet) string {
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>Netscope Report</title>")
	b.WriteString("<style>body{font-family:system-ui,sans-serif;max-width:1100px;margin:32px auto;padding:0 16px;line-height:1.45}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:8px;text-align:left}code{background:#f4f4f4;padding:2px 4px}</style>")
	b.WriteString("</head><body><h1>Netscope Report</h1>")
	fmt.Fprintf(&b, "<p>%s</p>", html.EscapeString(reportSummaryLine(results)))
	b.WriteString("<h2>Assets</h2><ul>")
	for _, asset := range results.Assets {
		fmt.Fprintf(&b, "<li><code>%s</code></li>", html.EscapeString(asset))
	}
	b.WriteString("</ul><h2>Exposed Services</h2><table><tr><th>Endpoint</th><th>Service</th><th>Banner</th></tr>")
	for _, service := range results.Services {
		fmt.Fprintf(&b, "<tr><td><code>%s</code></td><td>%s</td><td>%s</td></tr>", html.EscapeString(service.Key), html.EscapeString(service.Service), html.EscapeString(service.Banner))
	}
	b.WriteString("</table><h2>Findings</h2><table><tr><th>Severity</th><th>Target</th><th>Title</th><th>Evidence</th><th>Remediation</th></tr>")
	for _, finding := range results.Findings {
		fmt.Fprintf(&b, "<tr><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td></tr>", html.EscapeString(finding.Severity), html.EscapeString(firstNonEmpty(finding.IP, finding.Target)), html.EscapeString(finding.Title), html.EscapeString(finding.Evidence), html.EscapeString(finding.Remediation))
	}
	b.WriteString("</table></body></html>\n")
	return b.String()
}

func renderCSVReport(results resultSet) ([]byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	_ = writer.Write([]string{"type", "key", "severity", "target", "port", "service", "title", "evidence", "remediation"})
	for _, asset := range results.Assets {
		_ = writer.Write([]string{"asset", asset, "", "", "", "", "", "", ""})
	}
	for _, service := range results.Services {
		_ = writer.Write([]string{"service", service.Key, "", firstNonEmpty(service.IP, service.Target), service.Port + "/" + service.Transport, service.Service, "", service.Banner, ""})
	}
	for _, finding := range results.Findings {
		_ = writer.Write([]string{"finding", finding.Key, finding.Severity, firstNonEmpty(finding.IP, finding.Target), finding.Port + "/" + finding.Transport, "", finding.Title, finding.Evidence, finding.Remediation})
	}
	writer.Flush()
	return buf.Bytes(), writer.Error()
}

func renderSARIFReport(results resultSet) ([]byte, error) {
	rules := map[string]map[string]any{}
	var sarifResults []map[string]any
	for _, finding := range results.Findings {
		ruleID := strings.NewReplacer(" ", "-", "/", "-").Replace(strings.ToLower(firstNonEmpty(finding.Title, "netscope-finding")))
		rules[ruleID] = map[string]any{
			"id":   ruleID,
			"name": finding.Title,
			"shortDescription": map[string]any{
				"text": finding.Title,
			},
			"help": map[string]any{
				"text": strings.TrimSpace(finding.Remediation + "\n\nSafe validation: " + finding.SafeValidate),
			},
		}
		sarifResults = append(sarifResults, map[string]any{
			"ruleId":  ruleID,
			"level":   sarifLevel(finding.Severity),
			"message": map[string]any{"text": finding.Evidence},
			"locations": []map[string]any{{
				"physicalLocation": map[string]any{
					"artifactLocation": map[string]any{
						"uri": firstNonEmpty(finding.IP, finding.Target, "netscope-target"),
					},
				},
			}},
		})
	}
	ruleList := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		ruleList = append(ruleList, rule)
	}
	doc := map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []map[string]any{{
			"tool": map[string]any{
				"driver": map[string]any{
					"name":           "Netscope",
					"informationUri": "https://github.com/saiyan566/netscope",
					"rules":          ruleList,
				},
			},
			"results": sarifResults,
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}

func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func reportSummaryLine(results resultSet) string {
	return fmt.Sprintf("%d events, %d assets, %d open ports, %d services, %d findings.", len(results.Events), len(results.Assets), len(results.Ports), len(results.Services), len(results.Findings))
}

func writeStringList(b *strings.Builder, values []string) {
	if len(values) == 0 {
		b.WriteString("- none\n")
		return
	}
	for _, value := range values {
		fmt.Fprintf(b, "- %s\n", value)
	}
}

func writeFindingList(b *strings.Builder, findings []findingSummary, markdown bool) {
	if len(findings) == 0 {
		b.WriteString("- none\n")
		return
	}
	for _, finding := range findings {
		target := firstNonEmpty(finding.IP, finding.Target)
		if markdown {
			fmt.Fprintf(b, "- **%s** `%s` %s\n  - Evidence: %s\n  - Remediation: %s\n", finding.Severity, target, finding.Title, finding.Evidence, finding.Remediation)
		} else {
			fmt.Fprintf(b, "- [%s] %s %s | evidence: %s | remediation: %s\n", finding.Severity, target, finding.Title, finding.Evidence, finding.Remediation)
		}
	}
}
