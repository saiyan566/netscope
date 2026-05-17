package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type dnsAuditOptions struct {
	Targets   stringList
	Records   string
	TimeoutMS int
	Format    string
	JSONLOut  string
	ReportOut string
	Workspace string
	Dedupe    bool
}

func runDNSAudit(args []string, stdout io.Writer) (err error) {
	opts, err := parseDNSAuditOptions(args)
	if err != nil {
		return err
	}
	cliOpts := cliOptions{
		request: engineRequest{
			Command: "dns-audit",
			Targets: []string(opts.Targets),
		},
		format:    opts.Format,
		jsonlOut:  opts.JSONLOut,
		reportOut: opts.ReportOut,
		workspace: opts.Workspace,
		dedupe:    opts.Dedupe,
	}
	workspaceRun, err := beginWorkspaceRun(cliOpts)
	if err != nil {
		return err
	}
	cliOpts.workspaceRun = workspaceRun
	writer, err := newCLIEventWriter(cliOpts, stdout)
	if err != nil {
		return err
	}
	defer writer.Close()
	defer func() {
		if workspaceRun != nil {
			err = errors.Join(err, finishWorkspaceRun(workspaceRun, writer, err))
		}
	}()
	if err := emitSafetyMode(writer, cliOpts.request); err != nil {
		return err
	}

	client := &http.Client{Timeout: time.Duration(positiveOrDefault(opts.TimeoutMS, 5000)) * time.Millisecond}
	recordTypes := reconRecordTypes(opts.Records)
	dnsSeen := map[string]bool{}
	for _, target := range opts.Targets {
		domain := normalizeAuditDomain(target)
		if domain == "" {
			_ = writer.Emit(map[string]any{"type": "warning", "message": fmt.Sprintf("skipping invalid DNS target %q", target)})
			continue
		}
		if err := auditDNSDomain(client, writer, domain, recordTypes, dnsSeen); err != nil {
			_ = writer.Emit(map[string]any{"type": "warning", "message": fmt.Sprintf("DNS audit failed for %s: %v", domain, err)})
		}
	}
	return writer.failOnError()
}

func parseDNSAuditOptions(args []string) (dnsAuditOptions, error) {
	opts := dnsAuditOptions{
		Records:   "A,AAAA,CNAME,MX,NS,TXT,CAA",
		TimeoutMS: 5000,
		Format:    "text",
		Dedupe:    true,
	}
	fs := flag.NewFlagSet("dns-audit", flag.ContinueOnError)
	fs.Var(&opts.Targets, "target", "domain to audit; repeatable or comma-separated")
	fs.StringVar(&opts.Records, "records", opts.Records, "DNS record types to collect")
	fs.IntVar(&opts.TimeoutMS, "timeout-ms", opts.TimeoutMS, "public resolver timeout in milliseconds")
	fs.StringVar(&opts.Format, "format", opts.Format, "output format: text or jsonl")
	fs.StringVar(&opts.JSONLOut, "jsonl-out", "", "write raw JSONL events to this file")
	fs.StringVar(&opts.ReportOut, "report-out", "", "write readable output to this file")
	fs.StringVar(&opts.Workspace, "workspace", "", "persist this run in a local workspace")
	fs.BoolVar(&opts.Dedupe, "dedupe", true, "remove duplicate DNS posture events")
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	if len(opts.Targets) == 0 {
		return opts, fmt.Errorf("dns-audit requires --target")
	}
	if opts.Format != "text" && opts.Format != "jsonl" {
		return opts, fmt.Errorf("--format must be text or jsonl")
	}
	return opts, nil
}

func auditDNSDomain(client *http.Client, writer *cliEventWriter, domain string, recordTypes []string, dnsSeen map[string]bool) error {
	_ = writer.Emit(map[string]any{"type": "domain", "domain": domain, "resolver": "dns.google"})

	recordValues := map[string][]string{}
	for _, recordType := range recordTypes {
		answers, err := fetchDoH(client, domain, recordType)
		if err != nil {
			return err
		}
		for _, answer := range answers {
			value := strings.TrimSuffix(answer.Data, ".")
			rrType := dnsTypeName(answer.Type)
			recordName := strings.TrimSuffix(answer.Name, ".")
			recordValues[rrType] = append(recordValues[rrType], value)
			dedupeKey := strings.Join([]string{recordName, rrType, value}, "\x00")
			if !dnsSeen[dedupeKey] {
				dnsSeen[dedupeKey] = true
				_ = writer.Emit(map[string]any{
					"type":        "dns_record",
					"domain":      domain,
					"name":        recordName,
					"record_type": rrType,
					"value":       value,
					"ttl":         answer.TTL,
					"source":      "dns.google",
				})
			}
		}
	}

	dmarcValues, _ := fetchDoH(client, "_dmarc."+domain, "TXT")
	var dmarcPolicy string
	for _, answer := range dmarcValues {
		value := strings.Trim(answer.Data, `"`)
		if strings.Contains(strings.ToLower(value), "v=dmarc1") {
			dmarcPolicy = extractDMARCPolicy(value)
			_ = writer.Emit(map[string]any{"type": "dns_record", "domain": domain, "name": "_dmarc." + domain, "record_type": "TXT", "value": value, "source": "dns.google"})
		}
	}

	spfPresent := false
	for _, value := range recordValues["TXT"] {
		if strings.Contains(strings.ToLower(value), "v=spf1") {
			spfPresent = true
			break
		}
	}
	caaPresent := len(recordValues["CAA"]) > 0
	_ = writer.Emit(map[string]any{
		"type":         "dns_posture",
		"domain":       domain,
		"spf_present":  spfPresent,
		"dmarc_policy": dmarcPolicy,
		"caa_present":  caaPresent,
		"ns_count":     len(recordValues["NS"]),
		"mx_count":     len(recordValues["MX"]),
		"evidence":     "public DNS records inspected through dns.google DoH",
	})
	if !spfPresent {
		emitDNSFinding(writer, domain, "dns_missing_spf", "low", "SPF record not observed", "No v=spf1 TXT record was observed for the domain.", "Publish an SPF TXT record that describes authorized mail senders.")
	}
	if dmarcPolicy == "" {
		emitDNSFinding(writer, domain, "dns_missing_dmarc", "low", "DMARC record not observed", "No _dmarc TXT record was observed for the domain.", "Publish a DMARC record with an explicit policy after validating mail flow.")
	}
	if !caaPresent {
		emitDNSFinding(writer, domain, "dns_missing_caa", "info", "CAA record not observed", "No CAA record was observed for the domain.", "Consider publishing CAA records to restrict certificate issuance.")
	}
	return nil
}

func emitDNSFinding(writer *cliEventWriter, domain, code, severity, title, evidence, remediation string) {
	_ = writer.Emit(map[string]any{
		"type":            "finding",
		"finding_code":    code,
		"target":          domain,
		"severity":        severity,
		"title":           title,
		"evidence":        evidence,
		"remediation":     remediation,
		"safe_validation": "Re-run netscope dns-audit or query public DNS for the corresponding TXT/CAA records.",
	})
}

func extractDMARCPolicy(value string) string {
	for _, part := range strings.Split(value, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "p=") {
			return strings.TrimSpace(strings.TrimPrefix(part, "p="))
		}
	}
	return ""
}

func normalizeAuditDomain(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if parsed := netParseHost(raw); parsed != "" {
		raw = parsed
	}
	raw = strings.TrimSuffix(strings.ToLower(raw), ".")
	if !validDomain(raw) {
		return ""
	}
	return raw
}

func netParseHost(raw string) string {
	if strings.Contains(raw, "://") {
		if parsed, err := url.Parse(raw); err == nil {
			return parsed.Hostname()
		}
	}
	return raw
}
