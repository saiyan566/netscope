package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReportGeneratesMarkdownHTMLCSVAndSARIF(t *testing.T) {
	input := writeJSONLFixture(t, []string{
		`{"type":"subdomain","name":"api.example.com","ipv4":"192.0.2.10","sources":"crtsh"}`,
		`{"type":"open_port","resolved_ip":"192.0.2.10","port":443,"transport":"tcp","state":"open"}`,
		`{"type":"service","resolved_ip":"192.0.2.10","port":443,"transport":"tcp","service":"https","banner":"nginx"}`,
		`{"type":"finding","resolved_ip":"192.0.2.10","port":443,"transport":"tcp","severity":"medium","title":"Missing HSTS","evidence":"HSTS header was not observed.","remediation":"Enable Strict-Transport-Security."}`,
	})

	for _, format := range []string{"markdown", "html", "csv", "sarif"} {
		var out bytes.Buffer
		if err := runReport([]string{"--input", input, "--format", format}, &out); err != nil {
			t.Fatalf("report %s failed: %v", format, err)
		}
		text := out.String()
		if !strings.Contains(text, "Netscope") && !strings.Contains(text, "Missing HSTS") {
			t.Fatalf("unexpected %s report: %s", format, text)
		}
	}
}

func TestDiffDetectsChanges(t *testing.T) {
	oldPath := writeJSONLFixture(t, []string{
		`{"type":"ip_asset","ip":"192.0.2.10","name":"old.example.com"}`,
		`{"type":"open_port","resolved_ip":"192.0.2.10","port":80,"transport":"tcp","state":"open"}`,
		`{"type":"finding","resolved_ip":"192.0.2.10","port":80,"transport":"tcp","severity":"low","title":"Old finding"}`,
	})
	newPath := writeJSONLFixture(t, []string{
		`{"type":"ip_asset","ip":"192.0.2.20","name":"new.example.com"}`,
		`{"type":"open_port","resolved_ip":"192.0.2.20","port":443,"transport":"tcp","state":"open"}`,
		`{"type":"finding","resolved_ip":"192.0.2.20","port":443,"transport":"tcp","severity":"high","title":"New finding"}`,
	})

	var out bytes.Buffer
	if err := runDiff([]string{"--old", oldPath, "--new", newPath, "--format", "json"}, &out); err != nil {
		t.Fatalf("diff failed: %v", err)
	}
	var diff diffResult
	if err := json.Unmarshal(out.Bytes(), &diff); err != nil {
		t.Fatalf("invalid diff json: %v", err)
	}
	if len(diff.AssetsAdded) != 1 || len(diff.AssetsRemoved) != 1 {
		t.Fatalf("unexpected asset diff: %#v", diff)
	}
	if len(diff.PortsOpened) != 1 || len(diff.PortsClosed) != 1 {
		t.Fatalf("unexpected port diff: %#v", diff)
	}
	if len(diff.FindingsAdded) != 1 || len(diff.FindingsResolved) != 1 {
		t.Fatalf("unexpected finding diff: %#v", diff)
	}
}

func TestWorkspacePersistsRunAndReportsByID(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake engine script uses POSIX shell")
	}
	root := t.TempDir()
	t.Setenv("NETSCOPE_WORKSPACE_DIR", root)
	t.Setenv("NETSCOPE_CONFIG", filepath.Join(t.TempDir(), "missing.toml"))
	fakeEngine := filepath.Join(t.TempDir(), "netscope-engine")
	t.Setenv("NETSCOPE_ENGINE", fakeEngine)
	writeFakeWorkspaceEngine(t, fakeEngine, []string{
		`{"type":"ip_asset","ip":"192.0.2.10","name":"first.example.test","source":"fixture"}`,
		`{"type":"open_port","target":"127.0.0.1","resolved_ip":"192.0.2.10","port":443,"transport":"tcp","state":"open","reason":"fake","service":"https"}`,
		`{"type":"service","target":"127.0.0.1","resolved_ip":"192.0.2.10","port":443,"transport":"tcp","service":"https","banner":"fixture/1"}`,
		`{"type":"finding","target":"127.0.0.1","resolved_ip":"192.0.2.10","port":443,"transport":"tcp","severity":"high","title":"Fake finding","evidence":"fixture","remediation":"fix"}`,
		`{"type":"summary","message":"fake complete one"}`,
	})

	var out bytes.Buffer
	if err := run([]string{"workspace", "init", "acme"}, &out, &out); err != nil {
		t.Fatalf("workspace init failed: %v", err)
	}
	out.Reset()
	if err := run([]string{"scan", "--target", "127.0.0.1", "--profile", "quick", "--ports", "443", "--workspace", "acme", "--ack-authorized"}, &out, &out); err != nil {
		t.Fatalf("workspace scan failed: %v output=%s", err, out.String())
	}
	writeFakeWorkspaceEngine(t, fakeEngine, []string{
		`{"type":"ip_asset","ip":"192.0.2.20","name":"second.example.test","source":"fixture"}`,
		`{"type":"open_port","target":"127.0.0.1","resolved_ip":"192.0.2.20","port":8443,"transport":"tcp","state":"open","reason":"fake","service":"https"}`,
		`{"type":"service","target":"127.0.0.1","resolved_ip":"192.0.2.20","port":8443,"transport":"tcp","service":"https","banner":"fixture/2"}`,
		`{"type":"finding","target":"127.0.0.1","resolved_ip":"192.0.2.20","port":8443,"transport":"tcp","severity":"medium","title":"Second fake finding","evidence":"fixture","remediation":"fix"}`,
		`{"type":"summary","message":"fake complete two"}`,
	})
	out.Reset()
	if err := run([]string{"scan", "--target", "127.0.0.1", "--profile", "quick", "--ports", "8443", "--workspace", "acme", "--ack-authorized"}, &out, &out); err != nil {
		t.Fatalf("second workspace scan failed: %v output=%s", err, out.String())
	}
	out.Reset()
	if err := run([]string{"workspace", "status", "acme"}, &out, &out); err != nil {
		t.Fatalf("workspace status failed: %v", err)
	}
	if !strings.Contains(out.String(), "runs=2") {
		t.Fatalf("workspace status missing run count: %s", out.String())
	}
	out.Reset()
	if err := run([]string{"workspace", "list-runs", "acme", "--target", "127.0.0.1", "--mode", "ACTIVE", "--profile", "quick"}, &out, &out); err != nil {
		t.Fatalf("workspace list-runs failed: %v", err)
	}
	if !strings.Contains(out.String(), "fake complete one") || !strings.Contains(out.String(), "fake complete two") {
		t.Fatalf("missing persisted run summary: %s", out.String())
	}
	out.Reset()
	if err := run([]string{"workspace", "list-runs", "acme", "--severity", "high"}, &out, &out); err != nil {
		t.Fatalf("workspace severity filter failed: %v", err)
	}
	if !strings.Contains(out.String(), "fake complete one") || strings.Contains(out.String(), "fake complete two") {
		t.Fatalf("severity filter returned unexpected runs: %s", out.String())
	}
	out.Reset()
	if err := run([]string{"workspace", "show-run", "acme", "1", "--format", "text"}, &out, &out); err != nil {
		t.Fatalf("workspace show-run text failed: %v", err)
	}
	if !strings.Contains(out.String(), "run=1") || !strings.Contains(out.String(), "summary=fake complete one") {
		t.Fatalf("unexpected show-run text: %s", out.String())
	}
	out.Reset()
	if err := run([]string{"workspace", "show-run", "acme", "1", "--format", "json"}, &out, &out); err != nil {
		t.Fatalf("workspace show-run json failed: %v", err)
	}
	if !strings.Contains(out.String(), `"id": 1`) || !strings.Contains(out.String(), `"max_severity": "high"`) {
		t.Fatalf("unexpected show-run json: %s", out.String())
	}
	out.Reset()
	if err := run([]string{"workspace", "assets", "acme"}, &out, &out); err != nil {
		t.Fatalf("workspace assets failed: %v", err)
	}
	if !strings.Contains(out.String(), "ip:192.0.2.10") || !strings.Contains(out.String(), "ip:192.0.2.20") {
		t.Fatalf("workspace assets missing stored assets: %s", out.String())
	}
	out.Reset()
	if err := run([]string{"workspace", "findings", "acme"}, &out, &out); err != nil {
		t.Fatalf("workspace findings failed: %v", err)
	}
	if !strings.Contains(out.String(), "Fake finding") || !strings.Contains(out.String(), "Second fake finding") {
		t.Fatalf("workspace findings missing stored findings: %s", out.String())
	}
	out.Reset()
	if err := run([]string{"report", "--workspace", "acme", "--run", "1", "--format", "json"}, &out, &out); err != nil {
		t.Fatalf("workspace report failed: %v", err)
	}
	if !strings.Contains(out.String(), "Fake finding") {
		t.Fatalf("workspace report did not load JSONL artifact: %s", out.String())
	}
	out.Reset()
	if err := run([]string{"diff", "--workspace", "acme", "--old-run", "1", "--new-run", "2", "--format", "json"}, &out, &out); err != nil {
		t.Fatalf("workspace diff failed: %v", err)
	}
	if !strings.Contains(out.String(), "192.0.2.20:8443/tcp") || !strings.Contains(out.String(), "192.0.2.10:443/tcp") {
		t.Fatalf("workspace diff did not compare run ids: %s", out.String())
	}
}

func writeFakeWorkspaceEngine(t *testing.T, path string, lines []string) {
	t.Helper()
	var script strings.Builder
	script.WriteString("#!/bin/sh\ncat >/dev/null\n")
	for _, line := range lines {
		script.WriteString("printf '%s\\n' '")
		script.WriteString(line)
		script.WriteString("'\n")
	}
	if err := os.WriteFile(path, []byte(script.String()), 0o700); err != nil {
		t.Fatalf("write fake engine failed: %v", err)
	}
}

func writeJSONLFixture(t *testing.T, lines []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.jsonl")
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture failed: %v", err)
	}
	return path
}
