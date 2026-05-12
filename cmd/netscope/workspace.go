package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type workspaceRunContext struct {
	Name      string
	DBPath    string
	RunID     int64
	JSONLPath string
	StartedAt time.Time
}

var workspaceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

const workspaceSchemaVersion = 1

func runWorkspaceCommand(args []string, stdout io.Writer) error {
	if len(args) == 0 || hasHelpFlag(args) {
		printWorkspaceHelp(stdout)
		return nil
	}
	switch args[0] {
	case "init":
		fs := flag.NewFlagSet("workspace init", flag.ContinueOnError)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return errors.New("workspace init requires a workspace name")
		}
		db, path, err := openWorkspace(fs.Arg(0))
		if err != nil {
			return err
		}
		defer db.Close()
		fmt.Fprintf(stdout, "workspace=%s path=%s\n", fs.Arg(0), path)
		return nil
	case "status":
		name, err := workspaceNameArg(args[1:])
		if err != nil {
			return err
		}
		return printWorkspaceStatus(stdout, name)
	case "list":
		return listWorkspaces(stdout)
	case "list-runs":
		name, filters, err := parseWorkspaceListRunsArgs(args[1:])
		if err != nil {
			return err
		}
		return listWorkspaceRuns(stdout, name, filters)
	case "show-run":
		name, runID, format, err := parseWorkspaceShowRunArgs(args[1:])
		if err != nil {
			return err
		}
		return showWorkspaceRun(stdout, name, runID, format)
	case "assets":
		name, err := workspaceNameArg(args[1:])
		if err != nil {
			return err
		}
		return listWorkspaceAssets(stdout, name)
	case "findings":
		name, err := workspaceNameArg(args[1:])
		if err != nil {
			return err
		}
		return listWorkspaceFindings(stdout, name)
	default:
		return fmt.Errorf("unknown workspace command %q", args[0])
	}
}

func printWorkspaceHelp(stdout io.Writer) {
	fmt.Fprint(stdout, `netscope workspace

Usage:
  netscope workspace init <name>
  netscope workspace status <name>
  netscope workspace list
  netscope workspace list-runs <name> [--target value] [--mode PASSIVE|ACTIVE|LOCAL] [--profile name] [--severity sev] [--since RFC3339] [--until RFC3339]
  netscope workspace show-run <name> <id> [--format text|json]
  netscope workspace assets <name>
  netscope workspace findings <name>

Use --workspace <name> on scan/recon/vuln/dns-audit commands to persist run metadata and JSONL artifacts.
`)
}

type workspaceRunFilters struct {
	Target   string
	Mode     string
	Profile  string
	Severity string
	Since    string
	Until    string
}

func parseWorkspaceListRunsArgs(args []string) (string, workspaceRunFilters, error) {
	var filters workspaceRunFilters
	if len(args) == 0 {
		return "", filters, errors.New("workspace list-runs requires a workspace name")
	}
	name := args[0]
	fs := flag.NewFlagSet("workspace list-runs", flag.ContinueOnError)
	fs.StringVar(&filters.Target, "target", "", "filter runs by target substring")
	fs.StringVar(&filters.Mode, "mode", "", "filter by mode: PASSIVE, ACTIVE, or LOCAL")
	fs.StringVar(&filters.Profile, "profile", "", "filter by scan profile")
	fs.StringVar(&filters.Severity, "severity", "", "filter by maximum finding severity")
	fs.StringVar(&filters.Since, "since", "", "filter started_at >= RFC3339 timestamp or date prefix")
	fs.StringVar(&filters.Until, "until", "", "filter started_at <= RFC3339 timestamp or date prefix")
	if err := fs.Parse(args[1:]); err != nil {
		return "", filters, err
	}
	if fs.NArg() != 0 {
		return "", filters, fmt.Errorf("unexpected workspace list-runs argument %q", fs.Arg(0))
	}
	return name, filters, nil
}

func parseWorkspaceShowRunArgs(args []string) (string, int64, string, error) {
	if len(args) < 2 {
		return "", 0, "", errors.New("workspace show-run requires a workspace name and run id")
	}
	name := args[0]
	runIDValue := args[1]
	fs := flag.NewFlagSet("workspace show-run", flag.ContinueOnError)
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args[2:]); err != nil {
		return "", 0, "", err
	}
	if fs.NArg() != 0 {
		return "", 0, "", fmt.Errorf("unexpected workspace show-run argument %q", fs.Arg(0))
	}
	if *format != "text" && *format != "json" {
		return "", 0, "", errors.New("--format must be text or json")
	}
	runID, err := strconv.ParseInt(runIDValue, 10, 64)
	if err != nil {
		return "", 0, "", fmt.Errorf("invalid run id %q", runIDValue)
	}
	return name, runID, *format, nil
}

func workspaceNameArg(args []string) (string, error) {
	if len(args) != 1 {
		return "", errors.New("workspace command requires exactly one workspace name")
	}
	return args[0], nil
}

func beginWorkspaceRun(opts cliOptions) (*workspaceRunContext, error) {
	if opts.workspace == "" {
		return nil, nil
	}
	db, dbPath, err := openWorkspace(opts.workspace)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	started := time.Now().UTC()
	mode := string(evaluateSafety(opts.request).Mode)
	targets, _ := json.Marshal(opts.request.Targets)
	artifactDir := filepath.Join(filepath.Dir(dbPath), "runs")
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		return nil, err
	}
	result, err := db.Exec(`INSERT INTO runs(command, mode, profile, targets, started_at, status, report_path) VALUES(?, ?, ?, ?, ?, ?, ?)`,
		opts.request.Command, mode, opts.profile, string(targets), started.Format(time.RFC3339), "running", opts.reportOut)
	if err != nil {
		return nil, err
	}
	runID, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}
	jsonlPath := filepath.Join(artifactDir, fmt.Sprintf("run-%06d.jsonl", runID))
	if _, err := db.Exec(`UPDATE runs SET jsonl_path = ? WHERE id = ?`, jsonlPath, runID); err != nil {
		return nil, err
	}
	return &workspaceRunContext{Name: opts.workspace, DBPath: dbPath, RunID: runID, JSONLPath: jsonlPath, StartedAt: started}, nil
}

func finishWorkspaceRun(ctx *workspaceRunContext, writer *cliEventWriter, runErr error) error {
	if ctx == nil {
		return nil
	}
	db, _, err := openWorkspace(ctx.Name)
	if err != nil {
		return err
	}
	defer db.Close()
	status := "success"
	if runErr != nil {
		status = "error"
	}
	_, err = db.Exec(`UPDATE runs SET finished_at = ?, status = ?, summary = ?, findings_count = ?, max_severity = ? WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339), status, writer.summary, writer.findingCount(), writer.maxSeverityName(), ctx.RunID)
	return err
}

func openWorkspace(name string) (*sql.DB, string, error) {
	if !workspaceNamePattern.MatchString(name) {
		return nil, "", fmt.Errorf("invalid workspace name %q", name)
	}
	dir, err := workspaceDir(name)
	if err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, "", err
	}
	dbPath := filepath.Join(dir, "workspace.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, "", err
	}
	if err := applyWorkspaceMigrations(db); err != nil {
		_ = db.Close()
		return nil, "", err
	}
	return db, dbPath, nil
}

func workspaceDir(name string) (string, error) {
	root := strings.TrimSpace(os.Getenv("NETSCOPE_WORKSPACE_DIR"))
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		root = filepath.Join(home, ".local", "share", "netscope", "workspaces")
	}
	return filepath.Join(root, name), nil
}

func applyWorkspaceMigrations(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS runs(
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
		return err
	}
	_, err := db.Exec(`INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(?, ?)`, workspaceSchemaVersion, time.Now().UTC().Format(time.RFC3339))
	return err
}

func printWorkspaceStatus(stdout io.Writer, name string) error {
	db, path, err := openWorkspace(name)
	if err != nil {
		return err
	}
	defer db.Close()
	var runs int
	var last sql.NullString
	if err := db.QueryRow(`SELECT COUNT(*), MAX(started_at) FROM runs`).Scan(&runs, &last); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "workspace=%s path=%s runs=%d\n", name, path, runs)
	if last.Valid {
		fmt.Fprintf(stdout, "last_run=%s\n", last.String)
	}
	return nil
}

func listWorkspaces(stdout io.Writer) error {
	root := strings.TrimSpace(os.Getenv("NETSCOPE_WORKSPACE_DIR"))
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		root = filepath.Join(home, ".local", "share", "netscope", "workspaces")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			fmt.Fprintln(stdout, entry.Name())
		}
	}
	return nil
}

func listWorkspaceRuns(stdout io.Writer, name string, filters workspaceRunFilters) error {
	db, _, err := openWorkspace(name)
	if err != nil {
		return err
	}
	defer db.Close()
	query := `SELECT id, started_at, command, mode, status, COALESCE(summary, ''), COALESCE(profile, ''), COALESCE(max_severity, ''), COALESCE(targets, '') FROM runs WHERE 1=1`
	var args []any
	if filters.Target != "" {
		query += ` AND targets LIKE ?`
		args = append(args, "%"+filters.Target+"%")
	}
	if filters.Mode != "" {
		query += ` AND mode = ?`
		args = append(args, strings.ToUpper(filters.Mode))
	}
	if filters.Profile != "" {
		query += ` AND profile = ?`
		args = append(args, filters.Profile)
	}
	if filters.Severity != "" {
		query += ` AND max_severity = ?`
		args = append(args, strings.ToLower(filters.Severity))
	}
	if filters.Since != "" {
		query += ` AND started_at >= ?`
		args = append(args, filters.Since)
	}
	if filters.Until != "" {
		query += ` AND started_at <= ?`
		args = append(args, filters.Until)
	}
	query += ` ORDER BY id DESC`
	rows, err := db.Query(query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var started, command, mode, status, summary, profile, severity, targets string
		if err := rows.Scan(&id, &started, &command, &mode, &status, &summary, &profile, &severity, &targets); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%d\t%s\t%s\t%s\t%s\tprofile=%s\tseverity=%s\ttargets=%s\t%s\n", id, started, command, mode, status, profile, severity, targets, summary)
	}
	return rows.Err()
}

func showWorkspaceRun(stdout io.Writer, name string, runID int64, format string) error {
	run, err := workspaceRunByID(name, runID)
	if err != nil {
		return err
	}
	if format == "text" {
		fmt.Fprintf(stdout, "run=%v command=%s mode=%s status=%s profile=%s\n", run["id"], run["command"], run["mode"], run["status"], run["profile"])
		fmt.Fprintf(stdout, "started_at=%s finished_at=%s\n", run["started_at"], run["finished_at"])
		fmt.Fprintf(stdout, "targets=%s\n", run["targets"])
		fmt.Fprintf(stdout, "summary=%s findings=%v max_severity=%s\n", run["summary"], run["findings_count"], run["max_severity"])
		fmt.Fprintf(stdout, "jsonl_path=%s\n", run["jsonl_path"])
		if run["report_path"] != "" {
			fmt.Fprintf(stdout, "report_path=%s\n", run["report_path"])
		}
		return nil
	}
	encoded, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, string(encoded))
	return nil
}

func listWorkspaceAssets(stdout io.Writer, name string) error {
	sets, err := summarizeWorkspaceRuns(name)
	if err != nil {
		return err
	}
	for _, asset := range sets.Assets {
		fmt.Fprintln(stdout, asset)
	}
	return nil
}

func listWorkspaceFindings(stdout io.Writer, name string) error {
	sets, err := summarizeWorkspaceRuns(name)
	if err != nil {
		return err
	}
	for _, finding := range sets.Findings {
		fmt.Fprintf(stdout, "[%s]\t%s\t%s\t%s\n", finding.Severity, firstNonEmpty(finding.IP, finding.Target), finding.Title, finding.Remediation)
	}
	return nil
}

func summarizeWorkspaceRuns(name string) (resultSet, error) {
	db, _, err := openWorkspace(name)
	if err != nil {
		return resultSet{}, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT COALESCE(jsonl_path, '') FROM runs ORDER BY id ASC`)
	if err != nil {
		return resultSet{}, err
	}
	defer rows.Close()
	var events []map[string]any
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			return resultSet{}, err
		}
		if path == "" {
			continue
		}
		runEvents, err := readResultEvents(path)
		if err != nil {
			continue
		}
		events = append(events, runEvents...)
	}
	if err := rows.Err(); err != nil {
		return resultSet{}, err
	}
	return summarizeEvents(events), nil
}

func workspaceRunByID(name string, runID int64) (map[string]any, error) {
	db, _, err := openWorkspace(name)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var run struct {
		ID            int64
		Command       string
		Mode          string
		Profile       sql.NullString
		Targets       sql.NullString
		StartedAt     string
		FinishedAt    sql.NullString
		Status        string
		Summary       sql.NullString
		FindingsCount int
		MaxSeverity   sql.NullString
		JSONLPath     sql.NullString
		ReportPath    sql.NullString
	}
	err = db.QueryRow(`SELECT id, command, mode, profile, targets, started_at, finished_at, status, summary, findings_count, max_severity, jsonl_path, report_path FROM runs WHERE id = ?`, runID).Scan(
		&run.ID, &run.Command, &run.Mode, &run.Profile, &run.Targets, &run.StartedAt, &run.FinishedAt, &run.Status, &run.Summary, &run.FindingsCount, &run.MaxSeverity, &run.JSONLPath, &run.ReportPath)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("workspace run %d not found", runID)
		}
		return nil, err
	}
	return map[string]any{
		"id":             run.ID,
		"command":        run.Command,
		"mode":           run.Mode,
		"profile":        run.Profile.String,
		"targets":        run.Targets.String,
		"started_at":     run.StartedAt,
		"finished_at":    run.FinishedAt.String,
		"status":         run.Status,
		"summary":        run.Summary.String,
		"findings_count": run.FindingsCount,
		"max_severity":   run.MaxSeverity.String,
		"jsonl_path":     run.JSONLPath.String,
		"report_path":    run.ReportPath.String,
	}, nil
}

func workspaceRunJSONLPath(name string, runID int64) (string, error) {
	run, err := workspaceRunByID(name, runID)
	if err != nil {
		return "", err
	}
	path, _ := run["jsonl_path"].(string)
	if path == "" {
		return "", fmt.Errorf("workspace run %d does not have a JSONL artifact", runID)
	}
	return path, nil
}
