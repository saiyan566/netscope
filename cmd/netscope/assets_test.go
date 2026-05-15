package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestNormalizeInventoryAsset(t *testing.T) {
	cases := []struct {
		raw   string
		key   string
		value string
		ok    bool
	}{
		{raw: " API.Example.COM. ", key: "hostname:api.example.com", value: "api.example.com", ok: true},
		{raw: "203.000.113.010", ok: false},
		{raw: "999.1.2.3", ok: false},
		{raw: "203.0.113.10", key: "ipv4:203.0.113.10", value: "203.0.113.10", ok: true},
		{raw: "123.example.com", key: "hostname:123.example.com", value: "123.example.com", ok: true},
		{raw: "2001:0db8:0000:0000:0000:0000:0000:0001", key: "ipv6:2001:db8::1", value: "2001:db8::1", ok: true},
		{raw: "::ffff:203.0.113.10", key: "ipv4:203.0.113.10", value: "203.0.113.10", ok: true},
		{raw: "192.0.2.0/24", ok: false},
		{raw: "https://API.Example.COM/path?q=1", key: "hostname:api.example.com", value: "api.example.com", ok: true},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			got, ok := normalizeInventoryAsset(tc.raw)
			if ok != tc.ok {
				t.Fatalf("expected ok=%v, got %v (%#v)", tc.ok, ok, got)
			}
			if !ok {
				return
			}
			if got.Key != tc.key || got.Value != tc.value {
				t.Fatalf("unexpected candidate: %#v", got)
			}
		})
	}

	first, ok := normalizeInventoryAsset("2001:db8::1")
	if !ok {
		t.Fatal("expected first IPv6 form to normalize")
	}
	second, ok := normalizeInventoryAsset("2001:0db8::0001")
	if !ok {
		t.Fatal("expected second IPv6 form to normalize")
	}
	if first.Key != second.Key {
		t.Fatalf("equivalent IPv6 spellings should dedupe, got %q and %q", first.Key, second.Key)
	}
}

func TestWorkspaceMigrationV2CreatesInventoryTables(t *testing.T) {
	root := t.TempDir()
	t.Setenv("NETSCOPE_WORKSPACE_DIR", root)
	db, _, err := openWorkspace("acme")
	if err != nil {
		t.Fatalf("open workspace failed: %v", err)
	}
	defer db.Close()

	var version int
	if err := db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatalf("schema version query failed: %v", err)
	}
	if version != workspaceSchemaVersion {
		t.Fatalf("expected schema version %d, got %d", workspaceSchemaVersion, version)
	}
	for _, table := range []string{"assets", "asset_run_observations", "asset_service_observations"} {
		var name string
		if err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name); err != nil {
			t.Fatalf("missing table %s: %v", table, err)
		}
	}
}

func TestWorkspaceMigrationV1StartupRemainsSafe(t *testing.T) {
	root := t.TempDir()
	t.Setenv("NETSCOPE_WORKSPACE_DIR", root)
	dir := filepath.Join(root, "legacy")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "workspace.db"))
	if err != nil {
		t.Fatalf("open sqlite failed: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatalf("create legacy migrations failed: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE runs(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		command TEXT NOT NULL,
		mode TEXT NOT NULL,
		profile TEXT,
		targets TEXT,
		started_at TEXT NOT NULL,
		finished_at TEXT,
		status TEXT NOT NULL,
		summary TEXT,
		findings_count INTEGER DEFAULT 0,
		max_severity TEXT,
		jsonl_path TEXT,
		report_path TEXT
	)`); err != nil {
		t.Fatalf("create legacy runs failed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(1, ?)`, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("insert legacy version failed: %v", err)
	}
	db.Close()

	reopened, _, err := openWorkspace("legacy")
	if err != nil {
		t.Fatalf("reopen legacy workspace failed: %v", err)
	}
	defer reopened.Close()
	var version int
	if err := reopened.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatalf("schema version query failed: %v", err)
	}
	if version != 2 {
		t.Fatalf("expected migrated schema v2, got %d", version)
	}
}

func TestAssetUpsertDedupeAndServiceSummary(t *testing.T) {
	root := t.TempDir()
	t.Setenv("NETSCOPE_WORKSPACE_DIR", root)
	db, _, err := openWorkspace("acme")
	if err != nil {
		t.Fatalf("open workspace failed: %v", err)
	}
	defer db.Close()

	run1 := insertInventoryRun(t, db, "scan", "ACTIVE", []string{"api.example.com"}, []string{
		`{"type":"service","target":"api.example.com","resolved_ip":"203.0.113.10","port":443,"transport":"tcp","service":"https","banner":"fixture/1"}`,
		`{"type":"service","target":"api.example.com","resolved_ip":"203.0.113.10","port":443,"transport":"tcp","service":"https","banner":"fixture/1-duplicate"}`,
	})
	if err := ingestWorkspaceRunAssets(db, run1); err != nil {
		t.Fatalf("ingest run1 failed: %v", err)
	}
	asset := mustLookupAsset(t, db, "203.0.113.10")
	if asset.ObservationCount != 1 {
		t.Fatalf("duplicate raw events inflated observation count: %#v", asset)
	}
	firstSeen := asset.FirstSeenAt

	run2 := insertInventoryRun(t, db, "scan", "ACTIVE", []string{"api.example.com"}, []string{
		`{"type":"host","target":"api.example.com","resolved_ip":"203.0.113.10","state":"up","method":"tcp"}`,
	})
	if err := ingestWorkspaceRunAssets(db, run2); err != nil {
		t.Fatalf("ingest run2 failed: %v", err)
	}
	asset = mustLookupAsset(t, db, "203.0.113.10")
	if asset.FirstSeenAt != firstSeen {
		t.Fatalf("first_seen changed: before=%s after=%s", firstSeen, asset.FirstSeenAt)
	}
	if asset.LastSeenRunID == nil || *asset.LastSeenRunID != run2 {
		t.Fatalf("last seen run not updated: %#v", asset)
	}
	if asset.ObservationCount != 2 {
		t.Fatalf("expected later run to increment observation count, got %#v", asset)
	}

	services, err := latestObservedServices(db, asset.ID)
	if err != nil {
		t.Fatalf("service query failed: %v", err)
	}
	if len(services) != 1 || services[0].Service != "https" || services[0].Port != 443 {
		t.Fatalf("unexpected latest observed services: %#v", services)
	}
}

func TestDNSAuditInventoryGuard(t *testing.T) {
	root := t.TempDir()
	t.Setenv("NETSCOPE_WORKSPACE_DIR", root)
	db, _, err := openWorkspace("acme")
	if err != nil {
		t.Fatalf("open workspace failed: %v", err)
	}
	defer db.Close()
	runID := insertInventoryRun(t, db, "dns-audit", "PASSIVE", []string{"example.com"}, []string{
		`{"type":"domain","domain":"example.com","resolver":"dns.google"}`,
		`{"type":"dns_record","domain":"example.com","name":"example.com","record_type":"MX","value":"aspmx.l.google.com","source":"dns.google"}`,
		`{"type":"dns_record","domain":"example.com","name":"example.com","record_type":"NS","value":"ns1.cloudflare.com","source":"dns.google"}`,
		`{"type":"dns_record","domain":"example.com","name":"www.example.com","record_type":"CNAME","value":"example.cdn.test","source":"dns.google"}`,
		`{"type":"dns_record","domain":"example.com","name":"example.com","record_type":"A","value":"93.184.216.34","source":"dns.google"}`,
		`{"type":"dns_posture","domain":"example.com","spf_present":true,"dmarc_policy":"reject","caa_present":true,"ns_count":2,"mx_count":1}`,
	})
	if err := ingestWorkspaceRunAssets(db, runID); err != nil {
		t.Fatalf("ingest failed: %v", err)
	}
	assets, err := queryAssets(db, assetListFilters{Workspace: "acme"})
	if err != nil {
		t.Fatalf("query assets failed: %v", err)
	}
	if len(assets) != 1 || assets[0].AssetValue != "example.com" {
		t.Fatalf("dns-audit should only persist root domain, got %#v", assets)
	}
}

func TestAssetsCLIListShowHistoryAndWorkspaceSelection(t *testing.T) {
	root := t.TempDir()
	t.Setenv("NETSCOPE_WORKSPACE_DIR", root)
	db, _, err := openWorkspace("acme")
	if err != nil {
		t.Fatalf("open workspace failed: %v", err)
	}
	runID := insertInventoryRun(t, db, "scan", "ACTIVE", []string{"api.example.com"}, []string{
		`{"type":"service","target":"api.example.com","resolved_ip":"203.0.113.10","port":443,"transport":"tcp","service":"https"}`,
		`{"type":"subdomain","name":"api.example.com","ipv4":"203.0.113.10","sources":"fixture"}`,
	})
	if err := ingestWorkspaceRunAssets(db, runID); err != nil {
		t.Fatalf("ingest failed: %v", err)
	}
	db.Close()

	var out bytes.Buffer
	if err := run([]string{"assets", "list", "--workspace", "acme"}, &out, &out); err != nil {
		t.Fatalf("assets list failed: %v", err)
	}
	if !strings.Contains(out.String(), "203.0.113.10") || !strings.Contains(out.String(), "api.example.com") {
		t.Fatalf("assets list missing assets: %s", out.String())
	}
	out.Reset()
	if err := run([]string{"assets", "list", "--workspace", "acme", "--target", "api.example.com", "--type", "ipv4"}, &out, &out); err != nil {
		t.Fatalf("assets filtered list failed: %v", err)
	}
	if !strings.Contains(out.String(), "203.0.113.10") || strings.Contains(out.String(), "api.example.com\t") {
		t.Fatalf("assets filters returned unexpected output: %s", out.String())
	}
	out.Reset()
	if err := run([]string{"assets", "list", "--workspace", "acme", "--format", "json"}, &out, &out); err != nil {
		t.Fatalf("assets json list failed: %v", err)
	}
	if !json.Valid(out.Bytes()) || !strings.Contains(out.String(), `"asset_type": "ipv4"`) {
		t.Fatalf("unexpected assets json: %s", out.String())
	}
	out.Reset()
	if err := run([]string{"assets", "show", "--workspace", "acme", "--format", "json", "203.0.113.10"}, &out, &out); err != nil {
		t.Fatalf("assets show by value failed: %v", err)
	}
	if !strings.Contains(out.String(), `"latest_observed_services"`) {
		t.Fatalf("show json missing latest_observed_services: %s", out.String())
	}
	out.Reset()
	if err := run([]string{"assets", "show", "--workspace", "acme", "1"}, &out, &out); err != nil {
		t.Fatalf("assets show by id failed: %v", err)
	}
	if !strings.Contains(out.String(), "latest_observed_services:") {
		t.Fatalf("show text missing latest_observed_services: %s", out.String())
	}
	out.Reset()
	if err := run([]string{"assets", "history", "--workspace", "acme", "203.0.113.10"}, &out, &out); err != nil {
		t.Fatalf("assets history failed: %v", err)
	}
	if !strings.Contains(out.String(), "active_scan") {
		t.Fatalf("history missing observation stage: %s", out.String())
	}

	out.Reset()
	if err := run([]string{"assets", "list"}, &out, &out); err != nil {
		t.Fatalf("single workspace auto-selection failed: %v", err)
	}
	if !strings.Contains(out.String(), "203.0.113.10") {
		t.Fatalf("auto-selected workspace output missing asset: %s", out.String())
	}
	if _, _, err := openWorkspace("other"); err != nil {
		t.Fatalf("open second workspace failed: %v", err)
	}
	out.Reset()
	err = run([]string{"assets", "list"}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "multiple workspaces") {
		t.Fatalf("expected multiple workspace error, got err=%v output=%s", err, out.String())
	}
	t.Setenv("NETSCOPE_WORKSPACE", "acme")
	out.Reset()
	if err := run([]string{"assets", "list"}, &out, &out); err != nil {
		t.Fatalf("NETSCOPE_WORKSPACE selection failed: %v", err)
	}
}

func insertInventoryRun(t *testing.T, db *sql.DB, command, mode string, targets []string, lines []string) int64 {
	t.Helper()
	started := time.Now().UTC().Format(time.RFC3339)
	targetJSON, _ := json.Marshal(targets)
	result, err := db.Exec(`INSERT INTO runs(command, mode, profile, targets, started_at, status) VALUES(?, ?, ?, ?, ?, ?)`, command, mode, "", string(targetJSON), started, "success")
	if err != nil {
		t.Fatalf("insert run failed: %v", err)
	}
	runID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("last insert id failed: %v", err)
	}
	dbPath := sqliteDBPath(t, db)
	runDir := filepath.Join(filepath.Dir(dbPath), "runs")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatalf("mkdir runs failed: %v", err)
	}
	jsonlPath := filepath.Join(runDir, "fixture.jsonl")
	if err := os.WriteFile(jsonlPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write jsonl failed: %v", err)
	}
	if _, err := db.Exec(`UPDATE runs SET jsonl_path = ? WHERE id = ?`, jsonlPath, runID); err != nil {
		t.Fatalf("update run jsonl failed: %v", err)
	}
	return runID
}

func sqliteDBPath(t *testing.T, db *sql.DB) string {
	t.Helper()
	var row struct {
		Seq  int
		Name string
		File string
	}
	if err := db.QueryRow(`PRAGMA database_list`).Scan(&row.Seq, &row.Name, &row.File); err != nil {
		t.Fatalf("database_list failed: %v", err)
	}
	return row.File
}

func mustLookupAsset(t *testing.T, db *sql.DB, identity string) inventoryAsset {
	t.Helper()
	asset, err := lookupAsset(db, identity)
	if err != nil {
		t.Fatalf("lookup asset %q failed: %v", identity, err)
	}
	return asset
}
