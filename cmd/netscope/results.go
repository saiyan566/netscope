package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

type resultSet struct {
	Events     []map[string]any `json:"events"`
	Counts     map[string]int   `json:"counts"`
	Assets     []string         `json:"assets"`
	Ports      []string         `json:"ports"`
	Services   []serviceSummary `json:"services"`
	Findings   []findingSummary `json:"findings"`
	DNSRecords []string         `json:"dns_records"`
	TLSItems   []string         `json:"tls_items"`
}

type serviceSummary struct {
	Key       string `json:"key"`
	Target    string `json:"target,omitempty"`
	IP        string `json:"ip,omitempty"`
	Port      string `json:"port,omitempty"`
	Transport string `json:"transport,omitempty"`
	Service   string `json:"service,omitempty"`
	Banner    string `json:"banner,omitempty"`
}

type findingSummary struct {
	Key          string `json:"key"`
	Severity     string `json:"severity,omitempty"`
	Target       string `json:"target,omitempty"`
	IP           string `json:"ip,omitempty"`
	Port         string `json:"port,omitempty"`
	Transport    string `json:"transport,omitempty"`
	Title        string `json:"title,omitempty"`
	Evidence     string `json:"evidence,omitempty"`
	Remediation  string `json:"remediation,omitempty"`
	SafeValidate string `json:"safe_validation,omitempty"`
}

func readResultEvents(path string) ([]map[string]any, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var events []map[string]any
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return nil, fmt.Errorf("%s:%d: invalid JSONL event: %w", path, lineNo, err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func summarizeEvents(events []map[string]any) resultSet {
	set := resultSet{
		Events: events,
		Counts: map[string]int{},
	}
	assets := map[string]bool{}
	ports := map[string]bool{}
	dnsRecords := map[string]bool{}
	tlsItems := map[string]bool{}
	services := map[string]serviceSummary{}
	findings := map[string]findingSummary{}

	for _, event := range events {
		eventType := text(event, "type")
		set.Counts[eventType]++
		switch eventType {
		case "domain":
			addSet(assets, "domain:"+text(event, "domain"))
		case "subdomain":
			addSet(assets, "subdomain:"+text(event, "name"))
		case "ip_asset":
			addSet(assets, "ip:"+text(event, "ip"))
		case "cidr":
			addSet(assets, "cidr:"+text(event, "cidr"))
		case "host":
			addSet(assets, "host:"+firstNonEmpty(text(event, "resolved_ip"), text(event, "target")))
		case "dns_record":
			addSet(dnsRecords, strings.Join([]string{text(event, "name"), text(event, "record_type"), text(event, "value")}, "|"))
		case "open_port":
			addSet(ports, portIdentity(event))
		case "service":
			key := portIdentity(event)
			if key == "" {
				key = strings.Join([]string{text(event, "target"), text(event, "resolved_ip"), number(event, "port"), text(event, "transport"), text(event, "service")}, "|")
			}
			services[key] = serviceSummary{
				Key:       key,
				Target:    text(event, "target"),
				IP:        text(event, "resolved_ip"),
				Port:      number(event, "port"),
				Transport: text(event, "transport"),
				Service:   firstNonEmpty(text(event, "service_name"), text(event, "service")),
				Banner:    text(event, "banner"),
			}
		case "finding":
			finding := findingFromEvent(event)
			findings[finding.Key] = finding
		case "tls":
			addSet(tlsItems, strings.Join([]string{
				text(event, "target"),
				text(event, "resolved_ip"),
				text(event, "subject"),
				text(event, "issuer"),
				firstNonEmpty(text(event, "not_after"), text(event, "expires_at")),
				text(event, "negotiated_tls_version"),
				text(event, "cipher_suite"),
				valueString(event, "trust_valid"),
				valueString(event, "hostname_mismatch"),
			}, "|"))
		}
	}

	set.Assets = sortedKeys(assets)
	set.Ports = sortedKeys(ports)
	set.DNSRecords = sortedKeys(dnsRecords)
	set.TLSItems = sortedKeys(tlsItems)
	set.Services = sortedServices(services)
	set.Findings = sortedFindings(findings)
	return set
}

func addSet(values map[string]bool, value string) {
	value = strings.TrimSpace(value)
	if value != "" {
		values[value] = true
	}
}

func portIdentity(event map[string]any) string {
	ip := firstNonEmpty(text(event, "resolved_ip"), text(event, "target"))
	port := number(event, "port")
	transport := text(event, "transport")
	if ip == "" || port == "" || transport == "" {
		return ""
	}
	return fmt.Sprintf("%s:%s/%s", ip, port, transport)
}

func findingFromEvent(event map[string]any) findingSummary {
	finding := findingSummary{
		Severity:     text(event, "severity"),
		Target:       text(event, "target"),
		IP:           text(event, "resolved_ip"),
		Port:         number(event, "port"),
		Transport:    text(event, "transport"),
		Title:        text(event, "title"),
		Evidence:     text(event, "evidence"),
		Remediation:  text(event, "remediation"),
		SafeValidate: text(event, "safe_validation"),
	}
	finding.Key = strings.Join([]string{
		firstNonEmpty(finding.IP, finding.Target),
		finding.Port,
		finding.Transport,
		strings.ToLower(finding.Severity),
		strings.ToLower(finding.Title),
	}, "|")
	return finding
}

func sortedKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func sortedServices(values map[string]serviceSummary) []serviceSummary {
	out := make([]serviceSummary, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func sortedFindings(values map[string]findingSummary) []findingSummary {
	out := make([]findingSummary, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		if severityRank(out[i].Severity) != severityRank(out[j].Severity) {
			return severityRank(out[i].Severity) > severityRank(out[j].Severity)
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func severityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
