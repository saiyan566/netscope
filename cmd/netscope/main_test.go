package main

import (
	"bytes"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseRequiresAuthorization(t *testing.T) {
	_, err := parseEngineCommand("scan", []string{"--target", "192.0.2.1"})
	if err == nil {
		t.Fatal("expected active scan without --ack-authorized to fail")
	}
}

func TestParsePassiveReconDoesNotRequireAuthorization(t *testing.T) {
	opts, err := parseEngineCommand("recon", []string{"--target", "example.com"})
	if err != nil {
		t.Fatalf("passive recon should not require --ack-authorized: %v", err)
	}
	decision := evaluateSafety(opts.request)
	if decision.Mode != safetyPassive || decision.RequiresAck {
		t.Fatalf("expected passive no-ack decision, got %#v", decision)
	}
}

func TestParseCIDRReconDoesNotRequireAuthorization(t *testing.T) {
	opts, err := parseEngineCommand("recon", []string{"--target", "example.com", "--cidr-ranges"})
	if err != nil {
		t.Fatalf("passive CIDR recon should not require --ack-authorized: %v", err)
	}
	decision := evaluateSafety(opts.request)
	if decision.Mode != safetyPassive || decision.RequiresAck {
		t.Fatalf("expected passive CIDR decision, got %#v", decision)
	}
}

func TestParseLiveIPsRequiresAuthorization(t *testing.T) {
	_, err := parseEngineCommand("recon", []string{"--target", "example.com", "--live-ips"})
	if err == nil || !strings.Contains(err.Error(), "--ack-authorized") {
		t.Fatalf("expected active live IP recon to require --ack-authorized, got %v", err)
	}
}

func TestParseDiscoverRequiresAuthorization(t *testing.T) {
	_, err := parseEngineCommand("discover", []string{"--target", "192.0.2.0/24"})
	if err == nil || !strings.Contains(err.Error(), "--ack-authorized") {
		t.Fatalf("expected discovery to require --ack-authorized, got %v", err)
	}
}

func TestParseLocalVulnInputDoesNotRequireAuthorization(t *testing.T) {
	opts, err := parseEngineCommand("vuln", []string{"--input", "scan.jsonl"})
	if err != nil {
		t.Fatalf("local vuln input should not require --ack-authorized: %v", err)
	}
	decision := evaluateSafety(opts.request)
	if decision.Mode != safetyLocal || decision.RequiresAck {
		t.Fatalf("expected local vuln decision, got %#v", decision)
	}
}

func TestParseLiveVulnRequiresAuthorization(t *testing.T) {
	_, err := parseEngineCommand("vuln", []string{"--target", "example.com", "--ports", "80"})
	if err == nil || !strings.Contains(err.Error(), "--ack-authorized") {
		t.Fatalf("expected live vuln mode to require --ack-authorized, got %v", err)
	}
}

func TestSafetyAcceptanceCommandMatrix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake engine script uses POSIX shell")
	}
	fakeEngine := filepath.Join(t.TempDir(), "netscope-engine")
	if err := os.WriteFile(fakeEngine, []byte("#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '{\"type\":\"summary\",\"message\":\"fake engine ok\"}'\n"), 0o700); err != nil {
		t.Fatalf("write fake engine failed: %v", err)
	}
	t.Setenv("NETSCOPE_ENGINE", fakeEngine)
	t.Setenv("NETSCOPE_CONFIG", filepath.Join(t.TempDir(), "missing.toml"))

	cases := []struct {
		name      string
		args      []string
		wantError bool
		contains  string
	}{
		{
			name:     "passive recon without ack succeeds",
			args:     []string{"recon", "--target", "192.0.2.1", "--no-resolve", "--no-rdap", "--timeout-ms", "100"},
			contains: "[mode] PASSIVE",
		},
		{
			name:     "dns audit without ack succeeds",
			args:     []string{"dns-audit", "--target", "not_a_valid_domain", "--timeout-ms", "100"},
			contains: "[mode] PASSIVE",
		},
		{
			name:     "doctor without ack succeeds",
			args:     []string{"doctor"},
			contains: "netscope=",
		},
		{
			name:     "egress without ack succeeds",
			args:     []string{"egress"},
			contains: "os=",
		},
		{
			name:      "active recon without ack fails",
			args:      []string{"recon", "--target", "127.0.0.1/32", "--live-ips", "--no-resolve", "--no-rdap"},
			wantError: true,
			contains:  "--ack-authorized",
		},
		{
			name:      "active scan without ack fails",
			args:      []string{"scan", "--target", "127.0.0.1", "--ports", "1", "--timeout-ms", "100"},
			wantError: true,
			contains:  "--ack-authorized",
		},
		{
			name:     "active recon with ack succeeds",
			args:     []string{"recon", "--target", "127.0.0.1/32", "--live-ips", "--no-resolve", "--no-rdap", "--timeout-ms", "100", "--concurrency", "1", "--ack-authorized"},
			contains: "[mode] ACTIVE",
		},
		{
			name:     "active scan with ack succeeds",
			args:     []string{"scan", "--target", "127.0.0.1", "--ports", "1", "--timeout-ms", "100", "--ack-authorized"},
			contains: "[mode] ACTIVE",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := run(tc.args, &stdout, &stderr)
			combined := stdout.String() + stderr.String()
			if tc.wantError {
				if err == nil {
					t.Fatalf("expected error, output: %s", combined)
				}
				combined += err.Error()
			} else if err != nil {
				t.Fatalf("unexpected error: %v output=%s", err, combined)
			}
			if !strings.Contains(combined, tc.contains) {
				t.Fatalf("expected %q in output/error, got: %s", tc.contains, combined)
			}
		})
	}
}

func TestParseRepeatedTargetsAndExcludes(t *testing.T) {
	opts, err := parseEngineCommand("scan", []string{
		"--target", "192.0.2.1",
		"--target", "192.0.2.2,192.0.2.3",
		"--exclude", "192.0.2.3",
		"--ports", "22,80",
		"--ack-authorized",
	})
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(opts.request.Targets) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(opts.request.Targets))
	}
	if len(opts.request.Excludes) != 1 {
		t.Fatalf("expected 1 exclude, got %d", len(opts.request.Excludes))
	}
}

func TestScanProfileAppliesDefaults(t *testing.T) {
	t.Setenv("NETSCOPE_CONFIG", filepath.Join(t.TempDir(), "missing.toml"))
	opts, err := parseEngineCommand("scan", []string{
		"--target", "192.0.2.1",
		"--profile", "quick",
		"--ack-authorized",
	})
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if opts.profile != "quick" {
		t.Fatalf("expected quick profile, got %q", opts.profile)
	}
	if !opts.request.TCP || opts.request.UDP {
		t.Fatalf("expected quick profile to enable TCP only, got tcp=%v udp=%v", opts.request.TCP, opts.request.UDP)
	}
	if opts.request.TopPorts != 25 || opts.request.TimeoutMS != 700 || opts.request.Concurrency != 128 {
		t.Fatalf("unexpected quick profile defaults: top=%d timeout=%d concurrency=%d", opts.request.TopPorts, opts.request.TimeoutMS, opts.request.Concurrency)
	}
}

func TestConfigDefaultsAndCLIOverride(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(configPath, []byte(`
default_profile = "standard"
timeout_ms = 2500
concurrency = 64
enabled_passive_sources = ["dns-google", "rdap"]
`), 0o600); err != nil {
		t.Fatalf("write config failed: %v", err)
	}
	t.Setenv("NETSCOPE_CONFIG", configPath)

	scanOpts, err := parseEngineCommand("scan", []string{
		"--target", "192.0.2.1",
		"--timeout-ms", "1000",
		"--ack-authorized",
	})
	if err != nil {
		t.Fatalf("scan parse failed: %v", err)
	}
	if scanOpts.profile != "standard" {
		t.Fatalf("expected config default profile, got %q", scanOpts.profile)
	}
	if scanOpts.request.TimeoutMS != 1000 {
		t.Fatalf("expected CLI timeout override, got %d", scanOpts.request.TimeoutMS)
	}
	if scanOpts.request.Concurrency != 64 {
		t.Fatalf("expected config concurrency, got %d", scanOpts.request.Concurrency)
	}
	if !scanOpts.request.TCP || !scanOpts.request.UDP || !scanOpts.request.SSHAudit {
		t.Fatalf("expected standard profile defaults, got tcp=%v udp=%v ssh=%v", scanOpts.request.TCP, scanOpts.request.UDP, scanOpts.request.SSHAudit)
	}

	reconOpts, err := parseEngineCommand("recon", []string{"--target", "example.com"})
	if err != nil {
		t.Fatalf("recon parse failed: %v", err)
	}
	if reconOpts.request.Sources != "dns-google,rdap" {
		t.Fatalf("expected config passive sources, got %q", reconOpts.request.Sources)
	}
}

func TestSplitCSV(t *testing.T) {
	values := splitCSV("arp, icmp,,tcp")
	if len(values) != 3 {
		t.Fatalf("expected 3 values, got %d", len(values))
	}
	if values[1] != "icmp" {
		t.Fatalf("expected trimmed value, got %q", values[1])
	}
}

func TestDNSAuditHelpers(t *testing.T) {
	if got := extractDMARCPolicy("v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"); got != "quarantine" {
		t.Fatalf("unexpected DMARC policy: %q", got)
	}
	if got := normalizeAuditDomain("https://WWW.Example.COM/login"); got != "www.example.com" {
		t.Fatalf("unexpected normalized domain: %q", got)
	}
}

func TestPassiveSourceAdaptersBackDefaultSources(t *testing.T) {
	adapters := builtInPassiveSources()
	if len(adapters) < 5 {
		t.Fatalf("expected built-in passive adapters, got %d", len(adapters))
	}
	defaults := strings.Join(defaultReconSources(), ",")
	for _, source := range adapters {
		if source.Name() == "" || source.Category() == "" {
			t.Fatalf("source metadata is incomplete: %#v", source)
		}
		if !strings.Contains(defaults, source.Name()) {
			t.Fatalf("default sources do not include adapter %q in %q", source.Name(), defaults)
		}
	}
}

func TestPassiveSourceFailureIsolation(t *testing.T) {
	var out bytes.Buffer
	writer, err := newCLIEventWriter(cliOptions{format: "text", dedupe: true}, &out)
	if err != nil {
		t.Fatalf("writer setup failed: %v", err)
	}
	defer writer.Close()

	sources := map[string]bool{"ok": true, "bad": true}
	subdomains := map[string]map[string]bool{}
	hints := map[string]map[string]bool{}
	adapters := []passiveSourceAdapter{
		passiveSourceFunc{name: "ok", category: "test", fetch: func(*http.Client, string, int) (passiveSourceResult, error) {
			return passiveSourceResult{Subdomains: []string{"api.example.com"}}, nil
		}},
		passiveSourceFunc{name: "bad", category: "test", fetch: func(*http.Client, string, int) (passiveSourceResult, error) {
			return passiveSourceResult{}, errors.New("source down")
		}},
	}
	collectPassiveSubdomainsWithAdapters(&http.Client{}, writer, "example.com", sources, subdomains, hints, 10, adapters)
	if !subdomains["api.example.com"]["ok"] {
		t.Fatalf("expected successful source result, got %#v", subdomains)
	}
	if !strings.Contains(out.String(), "passive source failures") {
		t.Fatalf("expected isolated failure warning, got %s", out.String())
	}
}

func TestParseReconFlags(t *testing.T) {
	opts, err := parseEngineCommand("recon", []string{
		"--target", "example.com",
		"--records", "A,MX,TXT",
		"--wordlist", "subs.txt",
		"--source-limit", "2000",
		"--max-subdomains", "1000",
		"--cidr_ranges",
		"--live-ips",
		"--live-ip-ports", "80,443",
		"--max-live-ips", "25",
		"--expand-cidrs",
		"--max-cidr-ips", "10",
		"--report-out", "recon.doc",
		"--dedupe=false",
		"--subdomains=false",
		"--ack-authorized",
	})
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if opts.request.Records != "A,MX,TXT" {
		t.Fatalf("unexpected records: %q", opts.request.Records)
	}
	if opts.request.Wordlist != "subs.txt" {
		t.Fatalf("unexpected wordlist: %q", opts.request.Wordlist)
	}
	if opts.request.SourceLimit != 2000 {
		t.Fatalf("unexpected source limit: %d", opts.request.SourceLimit)
	}
	if opts.request.MaxSubdomains != 1000 {
		t.Fatalf("unexpected max subdomains: %d", opts.request.MaxSubdomains)
	}
	if !opts.request.CIDRRanges {
		t.Fatal("expected --cidr_ranges to be honored")
	}
	if !opts.request.LiveIPs {
		t.Fatal("expected --live-ips to be honored")
	}
	if opts.request.LiveIPPorts != "80,443" {
		t.Fatalf("unexpected live IP ports: %q", opts.request.LiveIPPorts)
	}
	if opts.request.MaxLiveIPs != 25 {
		t.Fatalf("unexpected max live IPs: %d", opts.request.MaxLiveIPs)
	}
	if !opts.request.ExpandCIDRs {
		t.Fatal("expected --expand-cidrs to be honored")
	}
	if opts.request.MaxCIDRIPs != 10 {
		t.Fatalf("unexpected max CIDR IPs: %d", opts.request.MaxCIDRIPs)
	}
	if opts.reportOut != "recon.doc" {
		t.Fatalf("unexpected report path: %q", opts.reportOut)
	}
	if opts.dedupe {
		t.Fatal("expected --dedupe=false to be honored")
	}
	if opts.request.Subdomains {
		t.Fatal("expected --subdomains=false to be honored")
	}
}

func TestParseLiveIPsEnablesCIDRRangeMode(t *testing.T) {
	opts, err := parseEngineCommand("recon", []string{
		"--target", "example.com",
		"--live-ips",
		"--ack-authorized",
	})
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if !opts.request.LiveIPs || !opts.request.CIDRRanges {
		t.Fatalf("expected live IPs to enable CIDR mode, got live=%v cidr=%v", opts.request.LiveIPs, opts.request.CIDRRanges)
	}
	if !strings.Contains(opts.request.Sources, "dns-google") || !strings.Contains(opts.request.Sources, "rdap") {
		t.Fatalf("expected required sources, got %q", opts.request.Sources)
	}
}

func TestParseCIDRRangesAliasAddsRequiredSources(t *testing.T) {
	opts, err := parseEngineCommand("recon", []string{
		"--target", "example.com",
		"--sources", "anubis",
		"--cidr_ranges",
		"--ack-authorized",
	})
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if !opts.request.CIDRRanges {
		t.Fatal("expected cidr range mode")
	}
	for _, source := range []string{"anubis", "dns-google", "rdap"} {
		if !strings.Contains(opts.request.Sources, source) {
			t.Fatalf("expected source %q in %q", source, opts.request.Sources)
		}
	}
	if opts.request.Records != "A,AAAA" {
		t.Fatalf("expected CIDR mode to default records to A,AAAA, got %q", opts.request.Records)
	}
	if opts.request.Subdomains {
		t.Fatal("expected CIDR mode to disable passive subdomain collection")
	}
}

func TestParseCIDRRangesDefaultsToOnlyDNSAndRDAP(t *testing.T) {
	opts, err := parseEngineCommand("recon", []string{
		"--target", "www.example.com",
		"--cidr-ranges",
	})
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if opts.request.Sources != "dns-google,rdap" {
		t.Fatalf("expected focused CIDR sources, got %q", opts.request.Sources)
	}
	if opts.request.Subdomains {
		t.Fatal("expected focused CIDR mode to disable passive subdomain collection")
	}
}

func TestParseDefaultReconKeepsBroadSourcesAndSubdomains(t *testing.T) {
	opts, err := parseEngineCommand("recon", []string{
		"--target", "example.com",
	})
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if !opts.request.Subdomains {
		t.Fatal("expected default recon to keep passive subdomain collection enabled")
	}
	for _, source := range []string{"crtsh", "wayback", "anubis", "dns-google", "rdap"} {
		if !strings.Contains(opts.request.Sources, source) {
			t.Fatalf("expected default source %q in %q", source, opts.request.Sources)
		}
	}
}

func TestCollectReconInputsUsesApexScopeForHost(t *testing.T) {
	scopes, _, err := collectReconInputs(engineRequest{
		Targets: []string{"https://www.arkoselabs.com/login"},
	})
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if len(scopes) != 1 {
		t.Fatalf("expected 1 scope, got %d", len(scopes))
	}
	if scopes[0].Domain != "arkoselabs.com" {
		t.Fatalf("expected apex scope arkoselabs.com, got %q", scopes[0].Domain)
	}
	if len(scopes[0].Seeds) != 1 || scopes[0].Seeds[0] != "www.arkoselabs.com" {
		t.Fatalf("expected original host seed, got %#v", scopes[0].Seeds)
	}
}

func TestPassiveReconRootHandlesCommonSecondLevelSuffix(t *testing.T) {
	if got := passiveReconRoot("www.example.co.uk"); got != "example.co.uk" {
		t.Fatalf("expected example.co.uk, got %q", got)
	}
}

func TestGeneralHelpIncludesCommands(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"help"}, &out, &out); err != nil {
		t.Fatalf("help failed: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "Commands:") || !strings.Contains(text, "recon") || !strings.Contains(text, "help [command]") {
		t.Fatalf("unexpected help output: %s", text)
	}
}

func TestCommandHelpIncludesFlags(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"recon", "--help"}, &out, &out); err != nil {
		t.Fatalf("recon --help failed: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "--sources") || !strings.Contains(text, "--source-limit") || !strings.Contains(text, "--max-subdomains") || !strings.Contains(text, "--cidr_ranges") || !strings.Contains(text, "--live-ips") || !strings.Contains(text, "--live-ip-ports") || !strings.Contains(text, "--expand-cidrs") || !strings.Contains(text, "--max-cidr-ips") || !strings.Contains(text, "--report-out") || !strings.Contains(text, "--dedupe") || !strings.Contains(text, "netscope recon") {
		t.Fatalf("unexpected recon help output: %s", text)
	}
}

func TestCLIEventWriterWritesReportAndDedupes(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "recon.txt")
	var out bytes.Buffer
	writer, err := newCLIEventWriter(cliOptions{
		format:    "text",
		reportOut: reportPath,
		dedupe:    true,
	}, &out)
	if err != nil {
		t.Fatalf("writer setup failed: %v", err)
	}

	events := []map[string]any{
		{"type": "subdomain", "name": "api.example.com", "ipv4": "192.0.2.10", "ipv6": "", "sources": "crtsh"},
		{"type": "subdomain", "name": "api.example.com", "ipv4": "192.0.2.10", "ipv6": "", "sources": "urlscan"},
		{"type": "ip_asset", "ip": "192.0.2.10", "name": "api.example.com", "source": "dns-google"},
		{"type": "ip_asset", "ip": "192.0.2.10", "name": "other.example.com", "source": "rdap"},
	}
	for _, event := range events {
		if err := writer.Emit(event); err != nil {
			t.Fatalf("emit failed: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	stdoutText := out.String()
	if got := strings.Count(stdoutText, "[subdomain]"); got != 1 {
		t.Fatalf("expected 1 subdomain on stdout, got %d: %s", got, stdoutText)
	}
	if got := strings.Count(stdoutText, "[ip]"); got != 1 {
		t.Fatalf("expected 1 ip on stdout, got %d: %s", got, stdoutText)
	}

	report, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report failed: %v", err)
	}
	reportText := string(report)
	if !strings.Contains(reportText, "Netscope report") {
		t.Fatalf("missing report header: %s", reportText)
	}
	if got := strings.Count(reportText, "[subdomain]"); got != 1 {
		t.Fatalf("expected 1 subdomain in report, got %d: %s", got, reportText)
	}
	if got := strings.Count(reportText, "[ip]"); got != 1 {
		t.Fatalf("expected 1 ip in report, got %d: %s", got, reportText)
	}
}

func TestCLIEventWriterFailOnThreshold(t *testing.T) {
	var out bytes.Buffer
	writer, err := newCLIEventWriter(cliOptions{
		format: "text",
		failOn: "high",
	}, &out)
	if err != nil {
		t.Fatalf("writer setup failed: %v", err)
	}
	if err := writer.Emit(map[string]any{"type": "finding", "severity": "medium", "title": "medium risk"}); err != nil {
		t.Fatalf("emit failed: %v", err)
	}
	if err := writer.failOnError(); err != nil {
		t.Fatalf("medium finding should not fail high threshold: %v", err)
	}
	if err := writer.Emit(map[string]any{"type": "finding", "severity": "high", "title": "high risk"}); err != nil {
		t.Fatalf("emit failed: %v", err)
	}
	err = writer.failOnError()
	if err == nil {
		t.Fatal("expected high finding to fail high threshold")
	}
	var exitErr exitError
	if !errors.As(err, &exitErr) || exitErr.Code != 3 {
		t.Fatalf("expected policy exit code 3, got %v", err)
	}
}

func TestCIDRRangeModeWriterFiltersNonCIDREvents(t *testing.T) {
	var out bytes.Buffer
	writer, err := newCLIEventWriter(cliOptions{
		request: engineRequest{CIDRRanges: true},
		format:  "text",
		dedupe:  true,
	}, &out)
	if err != nil {
		t.Fatalf("writer setup failed: %v", err)
	}

	events := []map[string]any{
		{"type": "mode", "mode": "PASSIVE", "message": "passive recon uses public sources"},
		{"type": "domain", "domain": "example.com", "resolver": "public-sources"},
		{"type": "dns_record", "name": "example.com", "record_type": "A", "value": "192.0.2.1"},
		{"type": "ip_asset", "ip": "192.0.2.1", "name": "example.com", "source": "dns-google"},
		{"type": "cidr", "cidr": "192.0.2.0/24", "name": "TEST-NET", "source": "rdap.org"},
		{"type": "live_ip", "ip": "192.0.2.1", "cidr": "192.0.2.0/24", "port": 443, "rtt_ms": 5, "reason": "tcp/443 accepted connection"},
		{"type": "summary", "message": "cidr range recon complete: 1 ranges"},
	}
	for _, event := range events {
		if err := writer.Emit(event); err != nil {
			t.Fatalf("emit failed: %v", err)
		}
	}

	text := out.String()
	if strings.Contains(text, "[domain]") || strings.Contains(text, "[dns]") || strings.Contains(text, "[ip]") {
		t.Fatalf("expected CIDR mode to hide non-CIDR assets, got: %s", text)
	}
	if !strings.Contains(text, "[mode]") || !strings.Contains(text, "[cidr]") || !strings.Contains(text, "[live-ip]") || !strings.Contains(text, "[summary]") {
		t.Fatalf("expected mode, CIDR, live IP, and summary output, got: %s", text)
	}
}

func TestExpandDiscoveredCIDRsEmitsIPsWithCap(t *testing.T) {
	var out bytes.Buffer
	writer, err := newCLIEventWriter(cliOptions{
		format: "text",
		dedupe: true,
	}, &out)
	if err != nil {
		t.Fatalf("writer setup failed: %v", err)
	}

	expandDiscoveredCIDRs(writer, []discoveredCIDR{{
		CIDR:   "192.0.2.0/30",
		Name:   "TEST-NET",
		Source: "input",
	}}, 3)

	text := out.String()
	if got := strings.Count(text, "[cidr-ip]"); got != 3 {
		t.Fatalf("expected 3 expanded IPs, got %d: %s", got, text)
	}
	if !strings.Contains(text, "192.0.2.0") || !strings.Contains(text, "192.0.2.2") {
		t.Fatalf("expected first three IPs from CIDR, got: %s", text)
	}
	if !strings.Contains(text, "contains 4 IPs; emitted first 3 only") {
		t.Fatalf("expected cap warning, got: %s", text)
	}
}

func TestInputCIDRsExtractsDirectTargets(t *testing.T) {
	cidrs := inputCIDRs([]string{"192.0.2.0/30", "192.0.2.1", "2001:db8::/126"})
	if len(cidrs) != 2 {
		t.Fatalf("expected 2 CIDRs, got %#v", cidrs)
	}
	if cidrs[0].CIDR != "192.0.2.0/30" || cidrs[1].CIDR != "2001:db8::/126" {
		t.Fatalf("unexpected CIDRs: %#v", cidrs)
	}
}

func TestParsePortListSupportsRangesAndDedupes(t *testing.T) {
	ports, err := parsePortList("443,80,80,1000-1002", nil, 10)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	want := []int{443, 80, 1000, 1001, 1002}
	if len(ports) != len(want) {
		t.Fatalf("expected %v, got %v", want, ports)
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, ports)
		}
	}
}

func TestProbeLiveIPDetectsListeningPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer listener.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port failed: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("port parse failed: %v", err)
	}

	result := probeLiveIP("127.0.0.1", []int{port}, time.Second)
	if !result.Alive || result.Port != port {
		t.Fatalf("expected live result on port %d, got %#v", port, result)
	}
	<-done
}
