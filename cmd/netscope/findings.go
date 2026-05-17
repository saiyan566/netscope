package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	findingStatusOpen          = "open"
	findingStatusAcknowledged  = "acknowledged"
	findingStatusAcceptedRisk  = "accepted-risk"
	findingStatusFalsePositive = "false-positive"
	findingStatusResolved      = "resolved"
	findingStatusRegressed     = "regressed"
)

var fallbackCodePattern = regexp.MustCompile(`[^a-z0-9]+`)

type persistentFinding struct {
	ID              int64  `json:"id"`
	Fingerprint     string `json:"fingerprint"`
	FindingCode     string `json:"finding_code"`
	Title           string `json:"title"`
	Category        string `json:"category,omitempty"`
	CurrentSeverity string `json:"current_severity"`
	Status          string `json:"status"`
	AssetID         *int64 `json:"asset_id,omitempty"`
	TargetValue     string `json:"target_value,omitempty"`
	TargetType      string `json:"target_type,omitempty"`
	Transport       string `json:"transport,omitempty"`
	Port            int    `json:"port,omitempty"`
	FirstSeenAt     string `json:"first_seen_at"`
	LastSeenAt      string `json:"last_seen_at"`
	FirstSeenRunID  *int64 `json:"first_seen_run_id,omitempty"`
	LastSeenRunID   *int64 `json:"last_seen_run_id,omitempty"`
	OccurrenceCount int    `json:"occurrence_count"`
	TriageNote      string `json:"triage_note,omitempty"`
	StatusUpdatedAt string `json:"status_updated_at,omitempty"`
	CreatedAt       string `json:"created_at,omitempty"`
	UpdatedAt       string `json:"updated_at,omitempty"`
}

type findingOccurrence struct {
	ID                  int64           `json:"id"`
	FindingID           int64           `json:"finding_id,omitempty"`
	RunID               int64           `json:"run_id"`
	RootTarget          string          `json:"root_target,omitempty"`
	SourceStage         string          `json:"source_stage"`
	ObservedAt          string          `json:"observed_at"`
	SeveritySnapshot    string          `json:"severity_snapshot"`
	TitleSnapshot       string          `json:"title_snapshot,omitempty"`
	Evidence            json.RawMessage `json:"evidence_json,omitempty"`
	RemediationSnapshot string          `json:"remediation_snapshot,omitempty"`
}

type findingListFilters struct {
	Workspace string
	Severity  string
	Status    string
	Target    string
	Asset     string
	Format    string
}

type findingDetail struct {
	Finding           persistentFinding   `json:"finding"`
	LinkedAsset       *inventoryAsset     `json:"linked_asset,omitempty"`
	LatestOccurrence  *findingOccurrence  `json:"latest_occurrence,omitempty"`
	RecentOccurrences []findingOccurrence `json:"recent_occurrences"`
}

type findingIdentity struct {
	Code        string
	Target      assetCandidate
	Transport   string
	Port        int
	Fingerprint string
}

func runFindingsCommand(args []string, stdout io.Writer) error {
	if len(args) == 0 || hasHelpFlag(args) {
		printFindingsHelp(stdout)
		return nil
	}
	switch args[0] {
	case "list":
		filters, err := parseFindingsListArgs(args[1:])
		if err != nil {
			return err
		}
		return listFindings(stdout, filters)
	case "show":
		workspace, identity, err := parseFindingIdentityArgs("findings show", args[1:])
		if err != nil {
			return err
		}
		return showFinding(stdout, workspace, identity)
	case "history":
		workspace, identity, err := parseFindingIdentityArgs("findings history", args[1:])
		if err != nil {
			return err
		}
		return showFindingHistory(stdout, workspace, identity)
	case "triage":
		return triageFindingCommand(stdout, args[1:])
	default:
		return fmt.Errorf("unknown findings command %q", args[0])
	}
}

func printFindingsHelp(stdout io.Writer) {
	fmt.Fprint(stdout, `netscope findings

Usage:
  netscope findings list [--workspace name] [--severity info|low|medium|high|critical] [--status open|acknowledged|accepted-risk|false-positive|resolved|regressed] [--target value] [--asset value] [--format text|json]
  netscope findings show [--workspace name] <id-or-fingerprint>
  netscope findings history [--workspace name] <id-or-fingerprint>
  netscope findings triage [--workspace name] <id-or-fingerprint> --status status [--note text]
`)
}

func parseFindingsListArgs(args []string) (findingListFilters, error) {
	filters := findingListFilters{Format: "text"}
	fs := flag.NewFlagSet("findings list", flag.ContinueOnError)
	fs.StringVar(&filters.Workspace, "workspace", "", "workspace name")
	fs.StringVar(&filters.Severity, "severity", "", "filter by severity")
	fs.StringVar(&filters.Status, "status", "", "filter by status")
	fs.StringVar(&filters.Target, "target", "", "filter by target value")
	fs.StringVar(&filters.Asset, "asset", "", "filter by linked asset id or value")
	fs.StringVar(&filters.Format, "format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return filters, err
	}
	if fs.NArg() != 0 {
		return filters, fmt.Errorf("unexpected findings list argument %q", fs.Arg(0))
	}
	var err error
	if filters.Severity, err = normalizeSeverityFilter(filters.Severity); err != nil {
		return filters, err
	}
	if filters.Status, err = normalizeFindingStatus(filters.Status); err != nil {
		return filters, err
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

func parseFindingIdentityArgs(command string, args []string) (string, string, error) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	workspace := fs.String("workspace", "", "workspace name")
	if err := fs.Parse(args); err != nil {
		return "", "", err
	}
	if fs.NArg() != 1 {
		return "", "", fmt.Errorf("%s requires a finding id or fingerprint", command)
	}
	resolved, err := resolveWorkspaceSelection(*workspace)
	if err != nil {
		return "", "", err
	}
	return resolved, fs.Arg(0), nil
}

func triageFindingCommand(stdout io.Writer, args []string) error {
	identity := ""
	var flagArgs []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if identity == "" && !strings.HasPrefix(arg, "-") {
			identity = arg
			continue
		}
		flagArgs = append(flagArgs, arg)
		if arg == "--workspace" || arg == "--status" || arg == "--note" {
			if i+1 < len(args) {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		}
	}
	fs := flag.NewFlagSet("findings triage", flag.ContinueOnError)
	workspace := fs.String("workspace", "", "workspace name")
	status := fs.String("status", "", "new status")
	note := fs.String("note", "", "triage note")
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if identity == "" || fs.NArg() != 0 {
		return errors.New("findings triage requires a finding id or fingerprint")
	}
	normalized, err := normalizeFindingStatus(*status)
	if err != nil {
		return err
	}
	if normalized == "" {
		return errors.New("--status is required")
	}
	resolved, err := resolveWorkspaceSelection(*workspace)
	if err != nil {
		return err
	}
	db, _, err := openWorkspace(resolved)
	if err != nil {
		return err
	}
	defer db.Close()
	finding, err := lookupFinding(db, identity)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.Exec(`UPDATE findings SET status = ?, triage_note = ?, status_updated_at = ?, updated_at = ? WHERE id = ?`, normalized, *note, now, now, finding.ID); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "finding=%d status=%s\n", finding.ID, normalized)
	return nil
}

func listFindings(stdout io.Writer, filters findingListFilters) error {
	db, _, err := openWorkspace(filters.Workspace)
	if err != nil {
		return err
	}
	defer db.Close()
	findings, err := queryFindings(db, filters)
	if err != nil {
		return err
	}
	if filters.Format == "json" {
		encoded, err := json.MarshalIndent(findings, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, string(encoded))
		return nil
	}
	fmt.Fprintln(stdout, "ID\tSEVERITY\tSTATUS\tTARGET\tTITLE\tLAST SEEN")
	for _, finding := range findings {
		fmt.Fprintf(stdout, "%d\t%s\t%s\t%s\t%s\t%s\n", finding.ID, finding.CurrentSeverity, finding.Status, firstNonEmpty(finding.TargetValue, int64PtrString(finding.AssetID)), finding.Title, finding.LastSeenAt)
	}
	return nil
}

func queryFindings(db *sql.DB, filters findingListFilters) ([]persistentFinding, error) {
	query := `SELECT f.id, f.fingerprint, f.finding_code, f.title, COALESCE(f.category, ''), f.current_severity, f.status, f.asset_id, COALESCE(f.target_value, ''), COALESCE(f.target_type, ''), COALESCE(f.transport, ''), COALESCE(f.port, 0), f.first_seen_at, f.last_seen_at, f.first_seen_run_id, f.last_seen_run_id, f.occurrence_count, COALESCE(f.triage_note, ''), COALESCE(f.status_updated_at, ''), f.created_at, f.updated_at FROM findings f`
	var args []any
	var where []string
	if filters.Severity != "" {
		where = append(where, `f.current_severity = ?`)
		args = append(args, filters.Severity)
	}
	if filters.Status != "" {
		where = append(where, `f.status = ?`)
		args = append(args, filters.Status)
	}
	if filters.Target != "" {
		where = append(where, `f.target_value = ?`)
		args = append(args, strings.TrimSpace(filters.Target))
	}
	if filters.Asset != "" {
		asset, err := lookupAsset(db, filters.Asset)
		if err != nil {
			return nil, err
		}
		where = append(where, `f.asset_id = ?`)
		args = append(args, asset.ID)
	}
	if len(where) > 0 {
		query += ` WHERE ` + strings.Join(where, ` AND `)
	}
	query += ` ORDER BY f.last_seen_at DESC, f.id DESC`
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFindings(rows)
}

func scanFindings(rows *sql.Rows) ([]persistentFinding, error) {
	var findings []persistentFinding
	for rows.Next() {
		var finding persistentFinding
		var assetID, firstRun, lastRun sql.NullInt64
		if err := rows.Scan(&finding.ID, &finding.Fingerprint, &finding.FindingCode, &finding.Title, &finding.Category, &finding.CurrentSeverity, &finding.Status, &assetID, &finding.TargetValue, &finding.TargetType, &finding.Transport, &finding.Port, &finding.FirstSeenAt, &finding.LastSeenAt, &firstRun, &lastRun, &finding.OccurrenceCount, &finding.TriageNote, &finding.StatusUpdatedAt, &finding.CreatedAt, &finding.UpdatedAt); err != nil {
			return nil, err
		}
		if assetID.Valid {
			finding.AssetID = &assetID.Int64
		}
		if firstRun.Valid {
			finding.FirstSeenRunID = &firstRun.Int64
		}
		if lastRun.Valid {
			finding.LastSeenRunID = &lastRun.Int64
		}
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}

func showFinding(stdout io.Writer, workspace, identity string) error {
	db, _, err := openWorkspace(workspace)
	if err != nil {
		return err
	}
	defer db.Close()
	finding, err := lookupFinding(db, identity)
	if err != nil {
		return err
	}
	occurrences, err := findingOccurrences(db, finding.ID, 10)
	if err != nil {
		return err
	}
	var asset *inventoryAsset
	if finding.AssetID != nil {
		row, err := assetByQuery(db, `SELECT id, asset_key, asset_type, asset_value, normalized_value, first_seen_at, last_seen_at, first_seen_run_id, last_seen_run_id, observation_count, created_at, updated_at FROM assets WHERE id = ?`, *finding.AssetID)
		if err == nil {
			asset = &row
		}
	}
	fmt.Fprintf(stdout, "id=%d\nfingerprint=%s\nfinding_code=%s\n", finding.ID, finding.Fingerprint, finding.FindingCode)
	fmt.Fprintf(stdout, "title=%s\ncurrent_severity=%s\nstatus=%s\n", finding.Title, finding.CurrentSeverity, finding.Status)
	if asset != nil {
		fmt.Fprintf(stdout, "asset=%s\n", asset.AssetValue)
	} else {
		fmt.Fprintf(stdout, "target=%s\n", finding.TargetValue)
	}
	if finding.Transport != "" || finding.Port > 0 {
		fmt.Fprintf(stdout, "service=%s/%d\n", finding.Transport, finding.Port)
	}
	fmt.Fprintf(stdout, "first_seen_at=%s first_seen_run_id=%s\n", finding.FirstSeenAt, int64PtrString(finding.FirstSeenRunID))
	fmt.Fprintf(stdout, "last_seen_at=%s last_seen_run_id=%s\n", finding.LastSeenAt, int64PtrString(finding.LastSeenRunID))
	fmt.Fprintf(stdout, "occurrence_count=%d\ntriage_note=%s\n", finding.OccurrenceCount, finding.TriageNote)
	if len(occurrences) > 0 {
		fmt.Fprintf(stdout, "latest_observed_evidence=%s\n", string(occurrences[0].Evidence))
	}
	return nil
}

func showFindingHistory(stdout io.Writer, workspace, identity string) error {
	db, _, err := openWorkspace(workspace)
	if err != nil {
		return err
	}
	defer db.Close()
	finding, err := lookupFinding(db, identity)
	if err != nil {
		return err
	}
	occurrences, err := findingOccurrences(db, finding.ID, 0)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, "RUN ID\tSOURCE STAGE\tROOT TARGET\tSEVERITY\tOBSERVED AT")
	for _, occurrence := range occurrences {
		fmt.Fprintf(stdout, "%d\t%s\t%s\t%s\t%s\n", occurrence.RunID, occurrence.SourceStage, occurrence.RootTarget, occurrence.SeveritySnapshot, occurrence.ObservedAt)
	}
	return nil
}

func lookupFinding(db *sql.DB, identity string) (persistentFinding, error) {
	if id, err := strconv.ParseInt(identity, 10, 64); err == nil {
		return findingByQuery(db, `SELECT id, fingerprint, finding_code, title, COALESCE(category, ''), current_severity, status, asset_id, COALESCE(target_value, ''), COALESCE(target_type, ''), COALESCE(transport, ''), COALESCE(port, 0), first_seen_at, last_seen_at, first_seen_run_id, last_seen_run_id, occurrence_count, COALESCE(triage_note, ''), COALESCE(status_updated_at, ''), created_at, updated_at FROM findings WHERE id = ?`, id)
	}
	return findingByQuery(db, `SELECT id, fingerprint, finding_code, title, COALESCE(category, ''), current_severity, status, asset_id, COALESCE(target_value, ''), COALESCE(target_type, ''), COALESCE(transport, ''), COALESCE(port, 0), first_seen_at, last_seen_at, first_seen_run_id, last_seen_run_id, occurrence_count, COALESCE(triage_note, ''), COALESCE(status_updated_at, ''), created_at, updated_at FROM findings WHERE fingerprint = ?`, identity)
}

func findingByQuery(db *sql.DB, query string, args ...any) (persistentFinding, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return persistentFinding{}, err
	}
	defer rows.Close()
	findings, err := scanFindings(rows)
	if err != nil {
		return persistentFinding{}, err
	}
	if len(findings) == 0 {
		return persistentFinding{}, errors.New("finding not found")
	}
	return findings[0], nil
}

func findingOccurrences(db *sql.DB, findingID int64, limit int) ([]findingOccurrence, error) {
	query := `SELECT id, finding_id, run_id, COALESCE(root_target, ''), source_stage, observed_at, severity_snapshot, COALESCE(title_snapshot, ''), COALESCE(evidence_json, ''), COALESCE(remediation_snapshot, '') FROM finding_run_occurrences WHERE finding_id = ? ORDER BY observed_at DESC, id DESC`
	args := []any{findingID}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var occurrences []findingOccurrence
	for rows.Next() {
		var occurrence findingOccurrence
		var evidence string
		if err := rows.Scan(&occurrence.ID, &occurrence.FindingID, &occurrence.RunID, &occurrence.RootTarget, &occurrence.SourceStage, &occurrence.ObservedAt, &occurrence.SeveritySnapshot, &occurrence.TitleSnapshot, &evidence, &occurrence.RemediationSnapshot); err != nil {
			return nil, err
		}
		if evidence != "" {
			occurrence.Evidence = json.RawMessage(evidence)
		}
		occurrences = append(occurrences, occurrence)
	}
	return occurrences, rows.Err()
}

func ingestWorkspaceRunFindings(db *sql.DB, runID int64) error {
	meta, err := workspaceRunMetadataByID(db, runID)
	if err != nil {
		return err
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
		if text(event, "type") != "finding" {
			continue
		}
		identity, ok := findingIdentityFromEvent(event)
		if !ok {
			continue
		}
		if err := upsertFindingOccurrence(db, identity, event, runID, rootTargetForEvent(meta.Targets, event), stage, meta.StartedAt, now); err != nil {
			return err
		}
	}
	return nil
}

func findingIdentityFromEvent(event map[string]any) (findingIdentity, bool) {
	code := findingCode(event)
	targetRaw := firstNonEmpty(text(event, "target"), text(event, "resolved_ip"))
	target, ok := normalizeInventoryAsset(targetRaw)
	if !ok {
		return findingIdentity{}, false
	}
	transport := strings.ToLower(strings.TrimSpace(text(event, "transport")))
	port, _ := strconv.Atoi(number(event, "port"))
	parts := []string{code, target.Key}
	if transport != "" && port > 0 {
		parts = append(parts, fmt.Sprintf("%s:%d", transport, port))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return findingIdentity{Code: code, Target: target, Transport: transport, Port: port, Fingerprint: hex.EncodeToString(sum[:])}, true
}

func findingCode(event map[string]any) string {
	for _, key := range []string{"rule_id", "finding_code", "code", "kind"} {
		if value := strings.TrimSpace(text(event, key)); value != "" {
			return normalizeFindingCode(value)
		}
	}
	return normalizeFindingCode(firstNonEmpty(text(event, "title"), "unknown_finding"))
}

func normalizeFindingCode(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = fallbackCodePattern.ReplaceAllString(value, "_")
	value = strings.Trim(value, "_")
	if value == "" {
		return "unknown_finding"
	}
	return value
}

func upsertFindingOccurrence(db *sql.DB, identity findingIdentity, event map[string]any, runID int64, rootTarget, sourceStage, observedAt, now string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	assetID := linkedAssetID(tx, identity.Target)
	severity := normalizeSeverityValue(text(event, "severity"))
	if severity == "" {
		severity = "info"
	}
	title := text(event, "title")
	if title == "" {
		title = identity.Code
	}
	findingID, created, previousStatus, err := ensureFinding(tx, identity, event, assetID, severity, title, runID, observedAt, now)
	if err != nil {
		return err
	}
	evidence, _ := json.Marshal(event)
	result, err := tx.Exec(`INSERT OR IGNORE INTO finding_run_occurrences(finding_id, run_id, root_target, source_stage, observed_at, severity_snapshot, title_snapshot, evidence_json, remediation_snapshot)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`, findingID, runID, strings.TrimSpace(rootTarget), sourceStage, observedAt, severity, title, string(evidence), strings.TrimSpace(text(event, "remediation")))
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted > 0 && !created {
		status := previousStatus
		statusUpdatedAt := any(nil)
		if previousStatus == findingStatusResolved {
			status = findingStatusRegressed
			statusUpdatedAt = now
		}
		if _, err := tx.Exec(`UPDATE findings SET title = ?, current_severity = ?, status = ?, asset_id = COALESCE(asset_id, ?), last_seen_at = ?, last_seen_run_id = ?, occurrence_count = occurrence_count + 1, status_updated_at = COALESCE(?, status_updated_at), updated_at = ? WHERE id = ?`, title, severity, status, assetID, observedAt, runID, statusUpdatedAt, now, findingID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func ensureFinding(tx *sql.Tx, identity findingIdentity, event map[string]any, assetID any, severity, title string, runID int64, observedAt, now string) (int64, bool, string, error) {
	result, err := tx.Exec(`INSERT OR IGNORE INTO findings(fingerprint, finding_code, title, category, current_severity, status, asset_id, target_value, target_type, transport, port, first_seen_at, last_seen_at, first_seen_run_id, last_seen_run_id, occurrence_count, created_at, updated_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`, identity.Fingerprint, identity.Code, title, strings.TrimSpace(text(event, "category")), severity, findingStatusOpen, assetID, identity.Target.Value, identity.Target.Type, nullEmpty(identity.Transport), nullZero(identity.Port), observedAt, observedAt, runID, runID, now, now)
	if err != nil {
		return 0, false, "", err
	}
	createdRows, err := result.RowsAffected()
	if err != nil {
		return 0, false, "", err
	}
	var id int64
	var status string
	if err := tx.QueryRow(`SELECT id, status FROM findings WHERE fingerprint = ?`, identity.Fingerprint).Scan(&id, &status); err != nil {
		return 0, false, "", err
	}
	return id, createdRows > 0, status, nil
}

func linkedAssetID(tx *sql.Tx, target assetCandidate) any {
	var id int64
	if err := tx.QueryRow(`SELECT id FROM assets WHERE asset_key = ?`, target.Key).Scan(&id); err != nil {
		return nil
	}
	return id
}

func normalizeSeverityFilter(value string) (string, error) {
	value = normalizeSeverityValue(value)
	if value == "" {
		return "", nil
	}
	if severityRank(value) == 0 && value != "info" {
		return "", errors.New("--severity must be info, low, medium, high, or critical")
	}
	return value, nil
}

func normalizeSeverityValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeFindingStatus(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "", nil
	}
	switch value {
	case findingStatusOpen, findingStatusAcknowledged, findingStatusAcceptedRisk, findingStatusFalsePositive, findingStatusResolved, findingStatusRegressed:
		return value, nil
	default:
		return "", errors.New("--status must be open, acknowledged, accepted-risk, false-positive, resolved, or regressed")
	}
}

func nullEmpty(value string) any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return value
}

func nullZero(value int) any {
	if value == 0 {
		return nil
	}
	return value
}
