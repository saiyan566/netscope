package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type netscopeConfig struct {
	DefaultProfile        string
	TimeoutMS             int
	Concurrency           int
	MemoryBudgetMB        int
	EnabledPassiveSources []string
	DefaultFormat         string
	DefaultReportOut      string
}

func loadNetscopeConfig() (netscopeConfig, string, error) {
	path := strings.TrimSpace(os.Getenv("NETSCOPE_CONFIG"))
	if path == "" {
		configDir, err := os.UserConfigDir()
		if err != nil {
			return netscopeConfig{}, "", nil
		}
		path = filepath.Join(configDir, "netscope", "config.toml")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return netscopeConfig{}, path, nil
		}
		return netscopeConfig{}, path, err
	}
	cfg, err := parseNetscopeConfig(data)
	if err != nil {
		return netscopeConfig{}, path, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return cfg, path, nil
}

func parseNetscopeConfig(data []byte) (netscopeConfig, error) {
	var cfg netscopeConfig
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := stripConfigComment(strings.TrimSpace(scanner.Text()))
		if line == "" || strings.HasPrefix(line, "[") {
			continue
		}
		key, rawValue, ok := strings.Cut(line, "=")
		if !ok {
			return cfg, fmt.Errorf("line %d: expected key = value", lineNo)
		}
		key = strings.TrimSpace(key)
		rawValue = strings.TrimSpace(rawValue)
		switch key {
		case "default_profile":
			cfg.DefaultProfile = parseConfigString(rawValue)
		case "timeout_ms":
			value, err := parseConfigInt(rawValue)
			if err != nil {
				return cfg, fmt.Errorf("line %d: %w", lineNo, err)
			}
			cfg.TimeoutMS = value
		case "concurrency":
			value, err := parseConfigInt(rawValue)
			if err != nil {
				return cfg, fmt.Errorf("line %d: %w", lineNo, err)
			}
			cfg.Concurrency = value
		case "memory_budget_mb":
			value, err := parseConfigInt(rawValue)
			if err != nil {
				return cfg, fmt.Errorf("line %d: %w", lineNo, err)
			}
			cfg.MemoryBudgetMB = value
		case "enabled_passive_sources":
			cfg.EnabledPassiveSources = parseConfigStringList(rawValue)
		case "default_format":
			cfg.DefaultFormat = parseConfigString(rawValue)
		case "default_report_out":
			cfg.DefaultReportOut = parseConfigString(rawValue)
		default:
			return cfg, fmt.Errorf("line %d: unknown key %q", lineNo, key)
		}
	}
	if err := scanner.Err(); err != nil {
		return cfg, err
	}
	if cfg.DefaultProfile != "" && scanProfileByName(cfg.DefaultProfile) == nil {
		return cfg, fmt.Errorf("unknown default_profile %q", cfg.DefaultProfile)
	}
	if cfg.DefaultFormat != "" && cfg.DefaultFormat != "text" && cfg.DefaultFormat != "jsonl" {
		return cfg, fmt.Errorf("default_format must be text or jsonl")
	}
	return cfg, nil
}

func stripConfigComment(line string) string {
	inQuote := false
	for i, r := range line {
		switch r {
		case '"':
			inQuote = !inQuote
		case '#':
			if !inQuote {
				return strings.TrimSpace(line[:i])
			}
		}
	}
	return line
}

func parseConfigString(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"`)
	return strings.TrimSpace(value)
}

func parseConfigInt(value string) (int, error) {
	out, err := strconv.Atoi(parseConfigString(value))
	if err != nil {
		return 0, fmt.Errorf("expected integer, got %q", value)
	}
	if out < 0 {
		return 0, fmt.Errorf("expected non-negative integer, got %d", out)
	}
	return out, nil
}

func parseConfigStringList(value string) []string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
	}
	var out []string
	for _, part := range strings.Split(value, ",") {
		part = parseConfigString(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func applyConfigAndProfiles(parser *commandParser) error {
	cfg, _, err := loadNetscopeConfig()
	if err != nil {
		return err
	}

	if parser.opts.request.Command == "scan" {
		profileName := parser.opts.profile
		if profileName == "" {
			profileName = cfg.DefaultProfile
			parser.opts.profile = profileName
		}
		if profileName != "" {
			if err := applyScanProfile(&parser.opts, parser.fs, profileName); err != nil {
				return err
			}
		}
	}
	applyConfigDefaults(&parser.opts, parser.fs, cfg)
	return nil
}

func applyConfigDefaults(opts *cliOptions, fs *flag.FlagSet, cfg netscopeConfig) {
	if cfg.TimeoutMS > 0 && !flagWasSet(fs, "timeout-ms") {
		opts.request.TimeoutMS = cfg.TimeoutMS
	}
	if cfg.Concurrency > 0 && !flagWasSet(fs, "concurrency") {
		opts.request.Concurrency = cfg.Concurrency
	}
	if cfg.MemoryBudgetMB > 0 && !flagWasSet(fs, "memory-budget-mb") {
		opts.request.MemoryBudgetMB = cfg.MemoryBudgetMB
	}
	if cfg.DefaultFormat != "" && !flagWasSet(fs, "format") {
		opts.format = cfg.DefaultFormat
	}
	if cfg.DefaultReportOut != "" && !flagWasSet(fs, "report-out") {
		opts.reportOut = cfg.DefaultReportOut
	}
	if opts.request.Command == "recon" && len(cfg.EnabledPassiveSources) > 0 && !flagWasSet(fs, "sources") {
		opts.request.Sources = strings.Join(cfg.EnabledPassiveSources, ",")
	}
}
