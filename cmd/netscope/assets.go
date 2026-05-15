package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	assetTypeHostname = "hostname"
	assetTypeIPv4     = "ipv4"
	assetTypeIPv6     = "ipv6"
)

type inventoryAsset struct {
	ID               int64  `json:"id"`
	AssetKey         string `json:"asset_key"`
	AssetType        string `json:"asset_type"`
	AssetValue       string `json:"asset_value"`
	NormalizedValue  string `json:"normalized_value"`
	FirstSeenAt      string `json:"first_seen_at"`
	LastSeenAt       string `json:"last_seen_at"`
	FirstSeenRunID   *int64 `json:"first_seen_run_id,omitempty"`
	LastSeenRunID    *int64 `json:"last_seen_run_id,omitempty"`
	ObservationCount int    `json:"observation_count"`
	CreatedAt        string `json:"created_at,omitempty"`
	UpdatedAt        string `json:"updated_at,omitempty"`
}

type assetObservation struct {
	ID          int64           `json:"id"`
	AssetID     int64           `json:"asset_id,omitempty"`
	RunID       int64           `json:"run_id"`
	RootTarget  string          `json:"root_target,omitempty"`
	SourceStage string          `json:"source_stage"`
	ObservedAt  string          `json:"observed_at"`
	Evidence    json.RawMessage `json:"evidence_json,omitempty"`
}

type assetServiceObservation struct {
	ID         int64  `json:"id,omitempty"`
	AssetID    int64  `json:"asset_id,omitempty"`
	RunID      int64  `json:"run_id"`
	Transport  string `json:"transport,omitempty"`
	Port       int    `json:"port,omitempty"`
	Service    string `json:"service,omitempty"`
	ObservedAt string `json:"observed_at"`
	Banner     string `json:"banner,omitempty"`
}

type assetCandidate struct {
	Type  string
	Value string
	Key   string
}

type assetRunMetadata struct {
	Command   string
	Mode      string
	Targets   []string
	StartedAt string
}

type assetListFilters struct {
	Workspace string
	Target    string
	Type      string
	Format    string
}

type assetDetail struct {
	Asset                  inventoryAsset            `json:"asset"`
	RootTargets            []string                  `json:"root_targets"`
	RecentObservations     []assetObservation        `json:"recent_observations"`
	LatestObservedServices []assetServiceObservation `json:"latest_observed_services"`
}

func runAssetsCommand(args []string, stdout io.Writer) error {
	if len(args) == 0 || hasHelpFlag(args) {
		printAssetsHelp(stdout)
		return nil
	}
	switch args[0] {
	case "list":
		filters, err := parseAssetsListArgs(args[1:])
		if err != nil {
			return err
		}
		return listAssets(stdout, filters)
	case "show":
		workspace, identity, format, err := parseAssetsIdentityArgs("assets show", args[1:], true)
		if err != nil {
			return err
		}
		return showAsset(stdout, workspace, identity, format)
	case "history":
		workspace, identity, _, err := parseAssetsIdentityArgs("assets history", args[1:], false)
		if err != nil {
			return err
		}
		return showAssetHistory(stdout, workspace, identity)
	default:
		return fmt.Errorf("unknown assets command %q", args[0])
	}
}

func printAssetsHelp(stdout io.Writer) {
	fmt.Fprint(stdout, `netscope assets

Usage:
  netscope assets list [--workspace name] [--target value] [--type hostname|ipv4|ipv6] [--format text|json]
  netscope assets show [--workspace name] [--format text|json] <asset-id-or-value>
  netscope assets history [--workspace name] <asset-id-or-value>

Workspace selection:
  --workspace wins, then NETSCOPE_WORKSPACE, then the only local workspace if exactly one exists.
`)
}

func parseAssetsListArgs(args []string) (assetListFilters, error) {
	filters := assetListFilters{Format: "text"}
	fs := flag.NewFlagSet("assets list", flag.ContinueOnError)
	fs.StringVar(&filters.Workspace, "workspace", "", "workspace name")
	fs.StringVar(&filters.Target, "target", "", "filter by observed root target")
	fs.StringVar(&filters.Type, "type", "", "filter by asset type: hostname, ipv4, or ipv6")
	fs.StringVar(&filters.Format, "format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return filters, err
	}
	if fs.NArg() != 0 {
		return filters, fmt.Errorf("unexpected assets list argument %q", fs.Arg(0))
	}
	if filters.Type != "" && filters.Type != assetTypeHostname && filters.Type != assetTypeIPv4 && filters.Type != assetTypeIPv6 {
		return filters, errors.New("--type must be hostname, ipv4, or ipv6")
	}
	if filters.Format != "text" && filters.Format != "json" {
		return filters, errors.New("--format must be text or json")
	}
	workspace, err := resolveWorkspaceSelection(filters.Workspace)
	if err != nil {
		return filters, err
	}
	filters.Workspace = workspace
	return filters, nil
}

func parseAssetsIdentityArgs(command string, args []string, allowFormat bool) (string, string, string, error) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	workspace := fs.String("workspace", "", "workspace name")
	format := "text"
	if allowFormat {
		fs.StringVar(&format, "format", "text", "output format: text or json")
	}
	if err := fs.Parse(args); err != nil {
		return "", "", "", err
	}
	if fs.NArg() != 1 {
		return "", "", "", fmt.Errorf("%s requires an asset id or value", command)
	}
	if format != "text" && format != "json" {
		return "", "", "", errors.New("--format must be text or json")
	}
	resolved, err := resolveWorkspaceSelection(*workspace)
	if err != nil {
		return "", "", "", err
	}
	return resolved, fs.Arg(0), format, nil
}

func resolveWorkspaceSelection(explicit string) (string, error) {
	if strings.TrimSpace(explicit) != "" {
		return strings.TrimSpace(explicit), nil
	}
	if env := strings.TrimSpace(os.Getenv("NETSCOPE_WORKSPACE")); env != "" {
		return env, nil
	}
	names, err := workspaceNames()
	if err != nil {
		return "", err
	}
	if len(names) == 1 {
		return names[0], nil
	}
	if len(names) == 0 {
		return "", errors.New("no workspace selected and no workspaces exist; pass --workspace or set NETSCOPE_WORKSPACE")
	}
	return "", errors.New("multiple workspaces exist; pass --workspace or set NETSCOPE_WORKSPACE")
}

func workspaceNames() ([]string, error) {
	root, err := workspaceRootDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func workspaceRootDir() (string, error) {
	root := strings.TrimSpace(os.Getenv("NETSCOPE_WORKSPACE_DIR"))
	if root != "" {
		return root, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "netscope", "workspaces"), nil
}

func listAssets(stdout io.Writer, filters assetListFilters) error {
	db, _, err := openWorkspace(filters.Workspace)
	if err != nil {
		return err
	}
	defer db.Close()
	assets, err := queryAssets(db, filters)
	if err != nil {
		return err
	}
	if filters.Format == "json" {
		encoded, err := json.MarshalIndent(assets, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, string(encoded))
		return nil
	}
	fmt.Fprintln(stdout, "ID\tTYPE\tASSET\tFIRST SEEN\tLAST SEEN\tOBSERVATIONS")
	for _, asset := range assets {
		fmt.Fprintf(stdout, "%d\t%s\t%s\t%s\t%s\t%d\n", asset.ID, asset.AssetType, asset.AssetValue, asset.FirstSeenAt, asset.LastSeenAt, asset.ObservationCount)
	}
	return nil
}

func queryAssets(db *sql.DB, filters assetListFilters) ([]inventoryAsset, error) {
	query := `SELECT DISTINCT a.id, a.asset_key, a.asset_type, a.asset_value, a.normalized_value, a.first_seen_at, a.last_seen_at, a.first_seen_run_id, a.last_seen_run_id, a.observation_count, a.created_at, a.updated_at
FROM assets a`
	var args []any
	var where []string
	if filters.Target != "" {
		query += ` JOIN asset_run_observations aro ON aro.asset_id = a.id`
		where = append(where, `aro.root_target = ?`)
		args = append(args, filters.Target)
	}
	if filters.Type != "" {
		where = append(where, `a.asset_type = ?`)
		args = append(args, filters.Type)
	}
	if len(where) > 0 {
		query += ` WHERE ` + strings.Join(where, ` AND `)
	}
	query += ` ORDER BY a.asset_type, a.normalized_value`
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAssets(rows)
}

func scanAssets(rows *sql.Rows) ([]inventoryAsset, error) {
	var assets []inventoryAsset
	for rows.Next() {
		var asset inventoryAsset
		var firstRun, lastRun sql.NullInt64
		if err := rows.Scan(&asset.ID, &asset.AssetKey, &asset.AssetType, &asset.AssetValue, &asset.NormalizedValue, &asset.FirstSeenAt, &asset.LastSeenAt, &firstRun, &lastRun, &asset.ObservationCount, &asset.CreatedAt, &asset.UpdatedAt); err != nil {
			return nil, err
		}
		if firstRun.Valid {
			asset.FirstSeenRunID = &firstRun.Int64
		}
		if lastRun.Valid {
			asset.LastSeenRunID = &lastRun.Int64
		}
		assets = append(assets, asset)
	}
	return assets, rows.Err()
}

func showAsset(stdout io.Writer, workspace, identity, format string) error {
	db, _, err := openWorkspace(workspace)
	if err != nil {
		return err
	}
	defer db.Close()
	asset, err := lookupAsset(db, identity)
	if err != nil {
		return err
	}
	roots, err := assetRootTargets(db, asset.ID)
	if err != nil {
		return err
	}
	observations, err := assetObservations(db, asset.ID, 10)
	if err != nil {
		return err
	}
	services, err := latestObservedServices(db, asset.ID)
	if err != nil {
		return err
	}
	detail := assetDetail{
		Asset:                  asset,
		RootTargets:            roots,
		RecentObservations:     observations,
		LatestObservedServices: services,
	}
	if format == "json" {
		encoded, err := json.MarshalIndent(detail, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, string(encoded))
		return nil
	}
	fmt.Fprintf(stdout, "id=%d\n", asset.ID)
	fmt.Fprintf(stdout, "type=%s\n", asset.AssetType)
	fmt.Fprintf(stdout, "asset=%s\n", asset.AssetValue)
	fmt.Fprintf(stdout, "normalized_value=%s\n", asset.NormalizedValue)
	fmt.Fprintf(stdout, "first_seen_at=%s first_seen_run_id=%s\n", asset.FirstSeenAt, int64PtrString(asset.FirstSeenRunID))
	fmt.Fprintf(stdout, "last_seen_at=%s last_seen_run_id=%s\n", asset.LastSeenAt, int64PtrString(asset.LastSeenRunID))
	fmt.Fprintf(stdout, "observation_count=%d\n", asset.ObservationCount)
	fmt.Fprintf(stdout, "root_targets=%s\n", strings.Join(roots, ","))
	fmt.Fprintln(stdout, "recent_observations:")
	for _, observation := range observations {
		fmt.Fprintf(stdout, "  run_id=%d source_stage=%s root_target=%s observed_at=%s\n", observation.RunID, observation.SourceStage, observation.RootTarget, observation.ObservedAt)
	}
	fmt.Fprintln(stdout, "latest_observed_services:")
	for _, service := range services {
		fmt.Fprintf(stdout, "  run_id=%d %s/%d service=%s observed_at=%s\n", service.RunID, service.Transport, service.Port, service.Service, service.ObservedAt)
	}
	return nil
}

func showAssetHistory(stdout io.Writer, workspace, identity string) error {
	db, _, err := openWorkspace(workspace)
	if err != nil {
		return err
	}
	defer db.Close()
	asset, err := lookupAsset(db, identity)
	if err != nil {
		return err
	}
	observations, err := assetObservations(db, asset.ID, 0)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, "RUN ID\tSOURCE STAGE\tROOT TARGET\tOBSERVED AT")
	for _, observation := range observations {
		fmt.Fprintf(stdout, "%d\t%s\t%s\t%s\n", observation.RunID, observation.SourceStage, observation.RootTarget, observation.ObservedAt)
	}
	return nil
}

func lookupAsset(db *sql.DB, identity string) (inventoryAsset, error) {
	if id, err := strconv.ParseInt(identity, 10, 64); err == nil {
		return assetByQuery(db, `SELECT id, asset_key, asset_type, asset_value, normalized_value, first_seen_at, last_seen_at, first_seen_run_id, last_seen_run_id, observation_count, created_at, updated_at FROM assets WHERE id = ?`, id)
	}
	candidate, ok := normalizeInventoryAsset(identity)
	if !ok {
		return inventoryAsset{}, fmt.Errorf("asset %q not found", identity)
	}
	return assetByQuery(db, `SELECT id, asset_key, asset_type, asset_value, normalized_value, first_seen_at, last_seen_at, first_seen_run_id, last_seen_run_id, observation_count, created_at, updated_at FROM assets WHERE asset_key = ?`, candidate.Key)
}

func assetByQuery(db *sql.DB, query string, args ...any) (inventoryAsset, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return inventoryAsset{}, err
	}
	defer rows.Close()
	assets, err := scanAssets(rows)
	if err != nil {
		return inventoryAsset{}, err
	}
	if len(assets) == 0 {
		return inventoryAsset{}, errors.New("asset not found")
	}
	return assets[0], nil
}

func assetRootTargets(db *sql.DB, assetID int64) ([]string, error) {
	rows, err := db.Query(`SELECT DISTINCT COALESCE(root_target, '') FROM asset_run_observations WHERE asset_id = ? AND COALESCE(root_target, '') <> '' ORDER BY root_target`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roots []string
	for rows.Next() {
		var root string
		if err := rows.Scan(&root); err != nil {
			return nil, err
		}
		roots = append(roots, root)
	}
	return roots, rows.Err()
}

func assetObservations(db *sql.DB, assetID int64, limit int) ([]assetObservation, error) {
	query := `SELECT id, asset_id, run_id, COALESCE(root_target, ''), source_stage, observed_at, COALESCE(evidence_json, '') FROM asset_run_observations WHERE asset_id = ? ORDER BY observed_at DESC, id DESC`
	var args []any
	args = append(args, assetID)
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var observations []assetObservation
	for rows.Next() {
		var observation assetObservation
		var evidence string
		if err := rows.Scan(&observation.ID, &observation.AssetID, &observation.RunID, &observation.RootTarget, &observation.SourceStage, &observation.ObservedAt, &evidence); err != nil {
			return nil, err
		}
		if evidence != "" {
			observation.Evidence = json.RawMessage(evidence)
		}
		observations = append(observations, observation)
	}
	return observations, rows.Err()
}

func latestObservedServices(db *sql.DB, assetID int64) ([]assetServiceObservation, error) {
	rows, err := db.Query(`SELECT aso.id, aso.asset_id, aso.run_id, COALESCE(aso.transport, ''), COALESCE(aso.port, 0), COALESCE(aso.service, ''), aso.observed_at, COALESCE(aso.banner, '')
FROM asset_service_observations aso
JOIN (
	SELECT transport, port, service, MAX(observed_at) AS observed_at
	FROM asset_service_observations
	WHERE asset_id = ?
	GROUP BY transport, port, service
) latest ON latest.transport IS aso.transport AND latest.port IS aso.port AND latest.service IS aso.service AND latest.observed_at = aso.observed_at
WHERE aso.asset_id = ?
ORDER BY aso.transport, aso.port, aso.service`, assetID, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var services []assetServiceObservation
	for rows.Next() {
		var service assetServiceObservation
		if err := rows.Scan(&service.ID, &service.AssetID, &service.RunID, &service.Transport, &service.Port, &service.Service, &service.ObservedAt, &service.Banner); err != nil {
			return nil, err
		}
		services = append(services, service)
	}
	return services, rows.Err()
}

func ingestWorkspaceRunAssets(db *sql.DB, runID int64) error {
	meta, err := workspaceRunMetadataByID(db, runID)
	if err != nil {
		return err
	}
	if meta.Command == "" {
		return nil
	}
	run, err := workspaceRunByIDFromDB(db, runID)
	if err != nil {
		return err
	}
	path, _ := run["jsonl_path"].(string)
	if path == "" {
		return nil
	}
	events, err := readResultEvents(path)
	if err != nil {
		return err
	}
	stage := sourceStageForRun(meta.Command, meta.Mode)
	now := time.Now().UTC().Format(time.RFC3339)
	for _, event := range events {
		for _, candidate := range inventoryAssetsFromEvent(meta.Command, event) {
			if err := upsertAssetObservation(db, candidate, runID, rootTargetForEvent(meta.Targets, event), stage, meta.StartedAt, now, event); err != nil {
				return err
			}
		}
		if err := ingestServiceObservation(db, runID, meta.StartedAt, event); err != nil {
			return err
		}
	}
	return nil
}

func workspaceRunMetadataByID(db *sql.DB, runID int64) (assetRunMetadata, error) {
	var meta assetRunMetadata
	var targetsText sql.NullString
	err := db.QueryRow(`SELECT command, mode, COALESCE(targets, ''), started_at FROM runs WHERE id = ?`, runID).Scan(&meta.Command, &meta.Mode, &targetsText, &meta.StartedAt)
	if err != nil {
		return meta, err
	}
	if targetsText.Valid && targetsText.String != "" {
		_ = json.Unmarshal([]byte(targetsText.String), &meta.Targets)
	}
	return meta, nil
}

func workspaceRunByIDFromDB(db *sql.DB, runID int64) (map[string]any, error) {
	var path sql.NullString
	if err := db.QueryRow(`SELECT jsonl_path FROM runs WHERE id = ?`, runID).Scan(&path); err != nil {
		return nil, err
	}
	return map[string]any{"jsonl_path": path.String}, nil
}

func upsertAssetObservation(db *sql.DB, candidate assetCandidate, runID int64, rootTarget, sourceStage, observedAt, now string, event map[string]any) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	assetID, assetCreated, err := ensureAsset(tx, candidate, runID, observedAt, now)
	if err != nil {
		return err
	}
	evidence, _ := json.Marshal(event)
	result, err := tx.Exec(`INSERT OR IGNORE INTO asset_run_observations(asset_id, run_id, root_target, source_stage, observed_at, evidence_json)
VALUES(?, ?, ?, ?, ?, ?)`, assetID, runID, strings.TrimSpace(rootTarget), sourceStage, observedAt, string(evidence))
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted > 0 {
		if assetCreated {
			if _, err := tx.Exec(`UPDATE assets SET last_seen_at = ?, last_seen_run_id = ?, updated_at = ? WHERE id = ?`, observedAt, runID, now, assetID); err != nil {
				return err
			}
		} else if _, err := tx.Exec(`UPDATE assets SET last_seen_at = ?, last_seen_run_id = ?, observation_count = observation_count + 1, updated_at = ? WHERE id = ?`, observedAt, runID, now, assetID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func ensureAsset(tx *sql.Tx, candidate assetCandidate, runID int64, observedAt, now string) (int64, bool, error) {
	result, err := tx.Exec(`INSERT OR IGNORE INTO assets(asset_key, asset_type, asset_value, normalized_value, first_seen_at, last_seen_at, first_seen_run_id, last_seen_run_id, observation_count, created_at, updated_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`, candidate.Key, candidate.Type, candidate.Value, candidate.Value, observedAt, observedAt, runID, runID, now, now)
	if err != nil {
		return 0, false, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return 0, false, err
	}
	var assetID int64
	if err := tx.QueryRow(`SELECT id FROM assets WHERE asset_key = ?`, candidate.Key).Scan(&assetID); err != nil {
		return 0, false, err
	}
	if inserted == 0 {
		if _, err := tx.Exec(`UPDATE assets SET updated_at = ? WHERE id = ?`, now, assetID); err != nil {
			return 0, false, err
		}
	}
	return assetID, inserted > 0, nil
}

func ingestServiceObservation(db *sql.DB, runID int64, observedAt string, event map[string]any) error {
	if text(event, "type") != "service" {
		return nil
	}
	candidate, ok := normalizeInventoryAsset(firstNonEmpty(text(event, "resolved_ip"), text(event, "target")))
	if !ok {
		return nil
	}
	assetID, err := assetIDByKey(db, candidate.Key)
	if err != nil {
		return nil
	}
	port, _ := strconv.Atoi(number(event, "port"))
	if port <= 0 {
		return nil
	}
	_, err = db.Exec(`INSERT OR IGNORE INTO asset_service_observations(asset_id, run_id, transport, port, service, observed_at, banner)
VALUES(?, ?, ?, ?, ?, ?, ?)`, assetID, runID, strings.TrimSpace(text(event, "transport")), port, strings.TrimSpace(firstNonEmpty(text(event, "service_name"), text(event, "service"))), observedAt, strings.TrimSpace(text(event, "banner")))
	return err
}

func assetIDByKey(db *sql.DB, key string) (int64, error) {
	var id int64
	err := db.QueryRow(`SELECT id FROM assets WHERE asset_key = ?`, key).Scan(&id)
	return id, err
}

func inventoryAssetsFromEvent(command string, event map[string]any) []assetCandidate {
	eventType := text(event, "type")
	var raw []string
	switch eventType {
	case "domain":
		raw = append(raw, text(event, "domain"))
	case "subdomain":
		raw = append(raw, text(event, "name"))
	case "ip_asset":
		raw = append(raw, text(event, "ip"))
		for _, name := range splitCSV(text(event, "name")) {
			raw = append(raw, name)
		}
	case "cidr_ip", "live_ip":
		raw = append(raw, text(event, "ip"))
	case "host", "open_port", "service", "http_audit", "tls":
		raw = append(raw, firstNonEmpty(text(event, "resolved_ip"), text(event, "target")))
	case "finding":
		raw = append(raw, firstNonEmpty(text(event, "resolved_ip"), text(event, "target")))
	case "dns_posture":
		if command == "dns-audit" {
			raw = append(raw, text(event, "domain"))
		}
	case "dns_record":
		if command != "dns-audit" {
			raw = append(raw, text(event, "name"))
		}
	}
	candidates := make([]assetCandidate, 0, len(raw))
	seen := map[string]bool{}
	for _, value := range raw {
		candidate, ok := normalizeInventoryAsset(value)
		if !ok || seen[candidate.Key] {
			continue
		}
		seen[candidate.Key] = true
		candidates = append(candidates, candidate)
	}
	return candidates
}

func normalizeInventoryAsset(raw string) (assetCandidate, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return assetCandidate{}, false
	}
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil {
			return assetCandidate{}, false
		}
		value = parsed.Hostname()
	}
	value = strings.Trim(value, "[]")
	if strings.Contains(value, "/") {
		return assetCandidate{}, false
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		if addr.Is4In6() {
			addr = netip.AddrFrom4(addr.As4())
		}
		canonical := addr.String()
		if addr.Is4() {
			return assetCandidate{Type: assetTypeIPv4, Value: canonical, Key: assetTypeIPv4 + ":" + canonical}, true
		}
		return assetCandidate{Type: assetTypeIPv6, Value: canonical, Key: assetTypeIPv6 + ":" + canonical}, true
	}
	if numericDottedIPv4Like(value) {
		return assetCandidate{}, false
	}
	host := strings.TrimSuffix(strings.ToLower(value), ".")
	if !validDomain(host) {
		return assetCandidate{}, false
	}
	return assetCandidate{Type: assetTypeHostname, Value: host, Key: assetTypeHostname + ":" + host}, true
}

func numericDottedIPv4Like(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func rootTargetForEvent(targets []string, event map[string]any) string {
	if root := normalizeRootTarget(firstNonEmpty(text(event, "root_target"), text(event, "domain"))); root != "" {
		return root
	}
	if target := normalizeRootTarget(text(event, "target")); target != "" {
		return target
	}
	if len(targets) == 1 {
		return normalizeRootTarget(targets[0])
	}
	return ""
}

func normalizeRootTarget(raw string) string {
	candidate, ok := normalizeInventoryAsset(raw)
	if !ok {
		return ""
	}
	return candidate.Value
}

func sourceStageForRun(command, mode string) string {
	switch command {
	case "recon":
		if mode == string(safetyActive) {
			return "active_recon"
		}
		return "passive_recon"
	case "dns-audit":
		return "dns_audit"
	case "discover":
		return "active_recon"
	case "scan", "vuln":
		return "active_scan"
	default:
		return "other"
	}
}

func int64PtrString(value *int64) string {
	if value == nil {
		return ""
	}
	return strconv.FormatInt(*value, 10)
}
