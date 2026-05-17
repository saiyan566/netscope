package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func TestFindingFingerprintStability(t *testing.T) {
	base := map[string]any{"type": "finding", "finding_code": "redis_exposed", "target": "203.0.113.10", "transport": "tcp", "port": float64(6379), "severity": "medium", "title": "Redis service exposed"}
	first, ok := findingIdentityFromEvent(base)
	if !ok {
		t.Fatal("expected finding identity")
	}
	severityChanged := cloneFindingEvent(base)
	severityChanged["severity"] = "critical"
	second, _ := findingIdentityFromEvent(severityChanged)
	if first.Fingerprint != second.Fingerprint {
		t.Fatal("severity must not affect fingerprint")
	}
	titleChanged := cloneFindingEvent(base)
	titleChanged["title"] = "Different words"
	third, _ := findingIdentityFromEvent(titleChanged)
	if first.Fingerprint != third.Fingerprint {
		t.Fatal("title must not affect fingerprint when finding_code exists")
	}
	portChanged := cloneFindingEvent(base)
	portChanged["port"] = float64(6380)
	fourth, _ := findingIdentityFromEvent(portChanged)
	if first.Fingerprint == fourth.Fingerprint {
		t.Fatal("port must affect fingerprint")
	}
}

func TestFindingPersistenceUpsertAndAssetLinkage(t *testing.T) {
	db := openFindingTestWorkspace(t, "acme")
	defer db.Close()
	assetRun := insertInventoryRun(t, db, "recon", "PASSIVE", []string{"example.com"}, []string{
		`{"type":"domain","domain":"example.com"}`,
		`{"type":"subdomain","domain":"example.com","name":"api.example.com"}`,
	})
	if err := ingestWorkspaceRunAssets(db, assetRun); err != nil {
		t.Fatalf("asset ingest failed: %v", err)
	}
	run1 := insertInventoryRun(t, db, "dns-audit", "PASSIVE", []string{"example.com"}, []string{
		`{"type":"finding","finding_code":"dns_missing_dmarc","target":"example.com","severity":"low","title":"DMARC missing","evidence":"one","remediation":"publish DMARC"}`,
		`{"type":"finding","finding_code":"dns_missing_dmarc","target":"example.com","severity":"low","title":"DMARC missing duplicate","evidence":"dupe","remediation":"publish DMARC"}`,
	})
	if err := ingestWorkspaceRunFindings(db, run1); err != nil {
		t.Fatalf("finding ingest run1 failed: %v", err)
	}
	finding := mustLookupPersistentFinding(t, db, "dns_missing_dmarc")
	if finding.Status != findingStatusOpen || finding.OccurrenceCount != 1 || finding.AssetID == nil {
		t.Fatalf("unexpected first finding state: %#v", finding)
	}
	run2 := insertInventoryRun(t, db, "dns-audit", "PASSIVE", []string{"example.com"}, []string{
		`{"type":"finding","finding_code":"dns_missing_dmarc","target":"example.com","severity":"high","title":"DMARC wording changed","evidence":"two","remediation":"publish DMARC"}`,
	})
	if err := ingestWorkspaceRunFindings(db, run2); err != nil {
		t.Fatalf("finding ingest run2 failed: %v", err)
	}
	finding = mustLookupPersistentFinding(t, db, "dns_missing_dmarc")
	if finding.OccurrenceCount != 2 || finding.CurrentSeverity != "high" || finding.FirstSeenRunID == nil || *finding.FirstSeenRunID != run1 || finding.LastSeenRunID == nil || *finding.LastSeenRunID != run2 {
		t.Fatalf("unexpected repeated finding state: %#v", finding)
	}
	occurrences, err := findingOccurrences(db, finding.ID, 0)
	if err != nil {
		t.Fatalf("occurrence query failed: %v", err)
	}
	if len(occurrences) != 2 || occurrences[0].SeveritySnapshot != "high" || occurrences[1].SeveritySnapshot != "low" {
		t.Fatalf("unexpected severity snapshots: %#v", occurrences)
	}

	run3 := insertInventoryRun(t, db, "scan", "ACTIVE", []string{"orphan.example.net"}, []string{
		`{"type":"finding","finding_code":"plain_http_detected","target":"orphan.example.net","port":80,"transport":"tcp","severity":"low","title":"Plain HTTP"}`,
	})
	if err := ingestWorkspaceRunFindings(db, run3); err != nil {
		t.Fatalf("orphan ingest failed: %v", err)
	}
	orphan := mustLookupPersistentFinding(t, db, "plain_http_detected")
	if orphan.AssetID != nil || orphan.TargetValue != "orphan.example.net" {
		t.Fatalf("finding without existing asset should remain nullable: %#v", orphan)
	}
}

func TestFindingTriageTransitions(t *testing.T) {
	for _, status := range []string{findingStatusAcknowledged, findingStatusAcceptedRisk, findingStatusFalsePositive} {
		t.Run(status, func(t *testing.T) {
			db := openFindingTestWorkspace(t, "acme")
			defer db.Close()
			run1 := insertInventoryRun(t, db, "scan", "ACTIVE", []string{"203.0.113.10"}, []string{
				`{"type":"finding","finding_code":"redis_exposed","target":"203.0.113.10","port":6379,"transport":"tcp","severity":"medium","title":"Redis exposed"}`,
			})
			if err := ingestWorkspaceRunFindings(db, run1); err != nil {
				t.Fatalf("ingest failed: %v", err)
			}
			finding := mustLookupPersistentFinding(t, db, "redis_exposed")
			if err := setFindingStatusForTest(db, finding.ID, status, "Reviewed"); err != nil {
				t.Fatalf("triage failed: %v", err)
			}
			run2 := insertInventoryRun(t, db, "scan", "ACTIVE", []string{"203.0.113.10"}, []string{
				`{"type":"finding","finding_code":"redis_exposed","target":"203.0.113.10","port":6379,"transport":"tcp","severity":"medium","title":"Redis exposed again"}`,
			})
			if err := ingestWorkspaceRunFindings(db, run2); err != nil {
				t.Fatalf("reingest failed: %v", err)
			}
			finding = mustLookupPersistentFinding(t, db, "redis_exposed")
			if finding.Status != status || finding.TriageNote != "Reviewed" {
				t.Fatalf("triaged status/note should persist: %#v", finding)
			}
		})
	}

	db := openFindingTestWorkspace(t, "acme")
	defer db.Close()
	run1 := insertInventoryRun(t, db, "scan", "ACTIVE", []string{"203.0.113.10"}, []string{
		`{"type":"finding","finding_code":"redis_exposed","target":"203.0.113.10","port":6379,"transport":"tcp","severity":"medium","title":"Redis exposed"}`,
	})
	if err := ingestWorkspaceRunFindings(db, run1); err != nil {
		t.Fatalf("ingest failed: %v", err)
	}
	finding := mustLookupPersistentFinding(t, db, "redis_exposed")
	if err := setFindingStatusForTest(db, finding.ID, findingStatusResolved, "Fixed"); err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	run2 := insertInventoryRun(t, db, "scan", "ACTIVE", []string{"203.0.113.10"}, []string{
		`{"type":"finding","finding_code":"redis_exposed","target":"203.0.113.10","port":6379,"transport":"tcp","severity":"medium","title":"Redis returned"}`,
	})
	if err := ingestWorkspaceRunFindings(db, run2); err != nil {
		t.Fatalf("regression ingest failed: %v", err)
	}
	finding = mustLookupPersistentFinding(t, db, "redis_exposed")
	if finding.Status != findingStatusRegressed || finding.TriageNote != "Fixed" {
		t.Fatalf("resolved finding should regress and preserve note: %#v", finding)
	}
}

func TestFindingsCLI(t *testing.T) {
	root := t.TempDir()
	t.Setenv("NETSCOPE_WORKSPACE_DIR", root)
	db, _, err := openWorkspace("acme")
	if err != nil {
		t.Fatalf("open workspace failed: %v", err)
	}
	runID := insertInventoryRun(t, db, "scan", "ACTIVE", []string{"203.0.113.10"}, []string{
		`{"type":"host","target":"203.0.113.10","resolved_ip":"203.0.113.10","state":"up"}`,
		`{"type":"finding","finding_code":"redis_exposed","target":"203.0.113.10","port":6379,"transport":"tcp","severity":"medium","title":"Redis exposed"}`,
	})
	if err := ingestWorkspaceRunAssets(db, runID); err != nil {
		t.Fatalf("asset ingest failed: %v", err)
	}
	if err := ingestWorkspaceRunFindings(db, runID); err != nil {
		t.Fatalf("finding ingest failed: %v", err)
	}
	db.Close()

	var out bytes.Buffer
	if err := run([]string{"findings", "list", "--workspace", "acme"}, &out, &out); err != nil {
		t.Fatalf("findings list failed: %v", err)
	}
	if !strings.Contains(out.String(), "Redis exposed") {
		t.Fatalf("list missing finding: %s", out.String())
	}
	out.Reset()
	if err := run([]string{"findings", "list", "--workspace", "acme", "--severity", "medium", "--status", "open", "--target", "203.0.113.10", "--asset", "203.0.113.10", "--format", "json"}, &out, &out); err != nil {
		t.Fatalf("filtered json list failed: %v", err)
	}
	if !json.Valid(out.Bytes()) || !strings.Contains(out.String(), `"finding_code": "redis_exposed"`) {
		t.Fatalf("unexpected json list: %s", out.String())
	}
	finding := decodeFirstFinding(t, out.Bytes())
	out.Reset()
	if err := run([]string{"findings", "show", "--workspace", "acme", strconv.FormatInt(finding.ID, 10)}, &out, &out); err != nil {
		t.Fatalf("show by id failed: %v", err)
	}
	if !strings.Contains(out.String(), "fingerprint=") {
		t.Fatalf("show output missing fingerprint: %s", out.String())
	}
	out.Reset()
	if err := run([]string{"findings", "history", "--workspace", "acme", finding.Fingerprint}, &out, &out); err != nil {
		t.Fatalf("history by fingerprint failed: %v", err)
	}
	if !strings.Contains(out.String(), "active_scan") {
		t.Fatalf("history missing stage: %s", out.String())
	}
	out.Reset()
	if err := run([]string{"findings", "triage", "--workspace", "acme", finding.Fingerprint, "--status", "resolved", "--note", "fixed"}, &out, &out); err != nil {
		t.Fatalf("triage failed: %v", err)
	}
	if !strings.Contains(out.String(), "status=resolved") {
		t.Fatalf("triage output unexpected: %s", out.String())
	}
	out.Reset()
	if err := run([]string{"findings", "triage", "--workspace", "acme", finding.Fingerprint, "--status", "open", "--note", "reopened"}, &out, &out); err != nil {
		t.Fatalf("manual reopen failed: %v", err)
	}
	if !strings.Contains(out.String(), "status=open") {
		t.Fatalf("manual reopen output unexpected: %s", out.String())
	}
	if err := run([]string{"findings", "list", "--workspace", "acme", "--severity", "bad"}, &out, &out); err == nil {
		t.Fatal("expected invalid severity error")
	}
	if err := run([]string{"findings", "list", "--workspace", "acme", "--status", "bad"}, &out, &out); err == nil {
		t.Fatal("expected invalid status error")
	}
	out.Reset()
	if err := run([]string{"findings", "list"}, &out, &out); err != nil {
		t.Fatalf("single workspace auto-selection failed: %v", err)
	}
	if _, _, err := openWorkspace("other"); err != nil {
		t.Fatalf("second workspace failed: %v", err)
	}
	if err := run([]string{"findings", "list"}, &out, &out); err == nil {
		t.Fatal("expected multiple workspace selection error")
	}
}

func openFindingTestWorkspace(t *testing.T, name string) *sql.DB {
	t.Helper()
	t.Setenv("NETSCOPE_WORKSPACE_DIR", t.TempDir())
	db, _, err := openWorkspace(name)
	if err != nil {
		t.Fatalf("open workspace failed: %v", err)
	}
	return db
}

func mustLookupPersistentFinding(t *testing.T, db *sql.DB, code string) persistentFinding {
	t.Helper()
	findings, err := queryFindings(db, findingListFilters{})
	if err != nil {
		t.Fatalf("query findings failed: %v", err)
	}
	for _, finding := range findings {
		if finding.FindingCode == code {
			return finding
		}
	}
	t.Fatalf("finding code %q not found in %#v", code, findings)
	return persistentFinding{}
}

func setFindingStatusForTest(db *sql.DB, id int64, status, note string) error {
	_, err := db.Exec(`UPDATE findings SET status = ?, triage_note = ?, status_updated_at = ? WHERE id = ?`, status, note, "2026-01-01T00:00:00Z", id)
	return err
}

func cloneFindingEvent(in map[string]any) map[string]any {
	out := map[string]any{}
	for key, value := range in {
		out[key] = value
	}
	return out
}

func decodeFirstFinding(t *testing.T, raw []byte) persistentFinding {
	t.Helper()
	var findings []persistentFinding
	if err := json.Unmarshal(raw, &findings); err != nil {
		t.Fatalf("decode findings failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %#v", findings)
	}
	return findings[0]
}
