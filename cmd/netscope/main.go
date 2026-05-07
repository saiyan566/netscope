package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const version = "0.1.0"

type stringList []string

func (s *stringList) String() string {
	return strings.Join([]string(*s), ",")
}

func (s *stringList) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			*s = append(*s, part)
		}
	}
	return nil
}

type engineRequest struct {
	Command          string   `json:"command"`
	Targets          []string `json:"targets,omitempty"`
	TargetFile       string   `json:"target_file,omitempty"`
	Excludes         []string `json:"excludes,omitempty"`
	TCP              bool     `json:"tcp"`
	UDP              bool     `json:"udp"`
	Ports            string   `json:"ports,omitempty"`
	UDPPorts         string   `json:"udp_ports,omitempty"`
	TopPorts         int      `json:"top_ports,omitempty"`
	TopUDP           int      `json:"top_udp,omitempty"`
	DiscoverHosts    bool     `json:"discover_hosts,omitempty"`
	SkipDiscovery    bool     `json:"skip_host_discovery,omitempty"`
	DiscoveryMethods []string `json:"discovery_methods,omitempty"`
	ICMPWaitMS       int      `json:"icmp_wait_ms,omitempty"`
	TCPPingPorts     string   `json:"tcp_ping_ports,omitempty"`
	ARPTimeoutMS     int      `json:"arp_timeout_ms,omitempty"`
	UDPRetries       int      `json:"udp_retries,omitempty"`
	Rate             int      `json:"rate,omitempty"`
	Concurrency      int      `json:"concurrency,omitempty"`
	TimeoutMS        int      `json:"timeout_ms,omitempty"`
	MemoryBudgetMB   int      `json:"memory_budget_mb,omitempty"`
	SSHAudit         bool     `json:"ssh_audit,omitempty"`
	InputFile        string   `json:"input_file,omitempty"`
	Subdomains       bool     `json:"subdomains,omitempty"`
	Wordlist         string   `json:"wordlist,omitempty"`
	Records          string   `json:"records,omitempty"`
	Sources          string   `json:"sources,omitempty"`
	MaxSubdomains    int      `json:"max_subdomains,omitempty"`
	SourceLimit      int      `json:"source_limit,omitempty"`
	MaxIPs           int      `json:"max_ips,omitempty"`
	CIDRRanges       bool     `json:"cidr_ranges,omitempty"`
	ExpandCIDRs      bool     `json:"expand_cidrs,omitempty"`
	MaxCIDRIPs       int      `json:"max_cidr_ips,omitempty"`
	LiveIPs          bool     `json:"live_ips,omitempty"`
	LiveIPPorts      string   `json:"live_ip_ports,omitempty"`
	MaxLiveIPs       int      `json:"max_live_ips,omitempty"`
	NoResolve        bool     `json:"no_resolve,omitempty"`
	NoRDAP           bool     `json:"no_rdap,omitempty"`
}

type cliOptions struct {
	request       engineRequest
	format        string
	jsonlOut      string
	reportOut     string
	dedupe        bool
	ackAuthorized bool
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stdout)
		return nil
	}

	switch args[0] {
	case "discover":
		if hasHelpFlag(args[1:]) {
			printCommandHelp(stdout, "discover")
			return nil
		}
		opts, err := parseEngineCommand("discover", args[1:])
		if err != nil {
			return err
		}
		opts.request.DiscoverHosts = true
		opts.request.TCP = false
		opts.request.UDP = false
		return runEngine(opts, stdout, stderr)
	case "scan":
		if hasHelpFlag(args[1:]) {
			printCommandHelp(stdout, "scan")
			return nil
		}
		opts, err := parseEngineCommand("scan", args[1:])
		if err != nil {
			return err
		}
		if !opts.request.TCP && !opts.request.UDP {
			opts.request.TCP = true
		}
		return runEngine(opts, stdout, stderr)
	case "vuln":
		if hasHelpFlag(args[1:]) {
			printCommandHelp(stdout, "vuln")
			return nil
		}
		opts, err := parseEngineCommand("vuln", args[1:])
		if err != nil {
			return err
		}
		return runEngine(opts, stdout, stderr)
	case "recon":
		if hasHelpFlag(args[1:]) {
			printCommandHelp(stdout, "recon")
			return nil
		}
		opts, err := parseEngineCommand("recon", args[1:])
		if err != nil {
			return err
		}
		if opts.request.Records == "" {
			opts.request.Records = "A,AAAA,CNAME,MX,NS,TXT"
		}
		if opts.request.Sources == "" {
			opts.request.Sources = strings.Join(defaultReconSources(), ",")
		}
		if opts.request.CIDRRanges || opts.request.LiveIPs {
			if opts.request.LiveIPs {
				opts.request.CIDRRanges = true
			}
			if opts.request.Sources == "" {
				opts.request.Sources = "dns-google,rdap"
			} else {
				opts.request.Sources = ensureSources(opts.request.Sources, "dns-google", "rdap")
			}
			if opts.request.Records == "A,AAAA,CNAME,MX,NS,TXT" {
				opts.request.Records = "A,AAAA"
			}
			opts.request.Subdomains = false
		}
		if opts.request.TimeoutMS == 900 {
			opts.request.TimeoutMS = 20000
		}
		return runPassiveRecon(opts, stdout, stderr)
	case "egress":
		return runEgress(stdout)
	case "doctor":
		return runDoctor(stdout)
	case "self-update":
		fmt.Fprintln(stdout, "self-update is wired into the CLI interface, but release hosting is not configured in this source build yet.")
		return nil
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "netscope %s\n", version)
		return nil
	case "help", "--help", "-h":
		if len(args) > 1 {
			return printCommandHelp(stdout, args[1])
		}
		printUsage(stdout)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func parseEngineCommand(command string, args []string) (cliOptions, error) {
	parser := newCommandParser(command)
	if err := parser.fs.Parse(args); err != nil {
		return parser.opts, err
	}
	if err := parser.finalize(); err != nil {
		return parser.opts, err
	}
	return parser.opts, nil
}

func splitCSV(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func flagWasSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func ensureSources(value string, required ...string) string {
	values := splitCSV(value)
	if len(values) == 0 {
		values = defaultReconSources()
	}
	enabled := sourceSet(values)
	for _, source := range required {
		if !enabled[source] {
			values = append(values, source)
			enabled[source] = true
		}
	}
	return strings.Join(values, ",")
}

func parsePortList(value string, fallback []int, maxPorts int) ([]int, error) {
	values := splitCSV(value)
	if len(values) == 0 {
		return append([]int{}, fallback...), nil
	}
	if maxPorts <= 0 {
		maxPorts = 64
	}
	seen := map[int]bool{}
	ports := make([]int, 0, len(values))
	for _, raw := range values {
		startText, endText, hasRange := strings.Cut(raw, "-")
		start, err := strconv.Atoi(strings.TrimSpace(startText))
		if err != nil || start < 1 || start > 65535 {
			return nil, fmt.Errorf("invalid port %q", raw)
		}
		end := start
		if hasRange {
			end, err = strconv.Atoi(strings.TrimSpace(endText))
			if err != nil || end < start || end > 65535 {
				return nil, fmt.Errorf("invalid port range %q", raw)
			}
		}
		for port := start; port <= end; port++ {
			if seen[port] {
				continue
			}
			if len(ports) >= maxPorts {
				return nil, fmt.Errorf("too many ports; limit is %d", maxPorts)
			}
			seen[port] = true
			ports = append(ports, port)
		}
	}
	return ports, nil
}

type commandParser struct {
	opts     cliOptions
	fs       *flag.FlagSet
	targets  stringList
	excludes stringList
	methods  string
}

func newCommandParser(command string) *commandParser {
	parser := &commandParser{}
	parser.opts.request.Command = command
	parser.fs = flag.NewFlagSet(command, flag.ContinueOnError)
	parser.fs.SetOutput(io.Discard)

	registerTargetFlags(parser.fs, &parser.targets, &parser.opts, &parser.excludes)
	registerOutputFlags(parser.fs, &parser.opts)

	switch command {
	case "discover":
		registerDiscoveryFlags(parser.fs, &parser.opts, &parser.methods)
		registerPerformanceFlags(parser.fs, &parser.opts)
	case "scan":
		registerScanFlags(parser.fs, &parser.opts)
		registerDiscoveryFlags(parser.fs, &parser.opts, &parser.methods)
	case "vuln":
		registerVulnFlags(parser.fs, &parser.opts)
	case "recon":
		registerReconFlags(parser.fs, &parser.opts)
	}

	return parser
}

func registerTargetFlags(fs *flag.FlagSet, targets *stringList, opts *cliOptions, excludes *stringList) {
	fs.Var(targets, "target", "target, CIDR, IP range, IP pool, or domain; repeatable or comma-separated")
	fs.StringVar(&opts.request.TargetFile, "target-file", "", "file containing targets, one per line")
	fs.Var(excludes, "exclude", "target exclusion; repeatable or comma-separated")
	fs.BoolVar(&opts.ackAuthorized, "ack-authorized", false, "confirm you are authorized to scan the requested scope")
}

func registerOutputFlags(fs *flag.FlagSet, opts *cliOptions) {
	fs.StringVar(&opts.format, "format", "text", "output format: text or jsonl")
	fs.StringVar(&opts.jsonlOut, "jsonl-out", "", "write raw JSONL events to this file")
	fs.StringVar(&opts.reportOut, "report-out", "", "write readable output to a text/doc file")
	fs.BoolVar(&opts.dedupe, "dedupe", true, "remove duplicate domains, subdomains, DNS records, IPs, CIDRs, ports, and findings")
}

func registerPerformanceFlags(fs *flag.FlagSet, opts *cliOptions) {
	fs.IntVar(&opts.request.Rate, "rate", 0, "approximate per-process probe rate limit; 0 means unlimited")
	fs.IntVar(&opts.request.Concurrency, "concurrency", 256, "maximum concurrent work items")
	fs.IntVar(&opts.request.TimeoutMS, "timeout-ms", 900, "probe or source timeout in milliseconds")
	fs.IntVar(&opts.request.MemoryBudgetMB, "memory-budget-mb", 150, "soft memory budget for scheduling")
}

func registerScanFlags(fs *flag.FlagSet, opts *cliOptions) {
	fs.BoolVar(&opts.request.TCP, "tcp", false, "enable TCP scanning")
	fs.BoolVar(&opts.request.UDP, "udp", false, "enable UDP scanning")
	fs.StringVar(&opts.request.Ports, "ports", "", "TCP ports, for example 22,80,443 or 1-1024")
	fs.StringVar(&opts.request.UDPPorts, "udp-ports", "", "UDP ports, for example 53,123,161 or 1-65535")
	fs.IntVar(&opts.request.TopPorts, "top-ports", 100, "number of common TCP ports to scan when --ports is omitted")
	fs.IntVar(&opts.request.TopUDP, "top-udp", 20, "number of common UDP ports to scan when --udp-ports is omitted")
	fs.BoolVar(&opts.request.SSHAudit, "ssh-audit", false, "perform safe SSH banner and posture checks")
	fs.IntVar(&opts.request.UDPRetries, "udp-retries", 1, "UDP retry count")
	registerPerformanceFlags(fs, opts)
}

func registerDiscoveryFlags(fs *flag.FlagSet, opts *cliOptions, methods *string) {
	fs.BoolVar(&opts.request.DiscoverHosts, "discover-hosts", false, "run live host discovery before scanning")
	fs.BoolVar(&opts.request.SkipDiscovery, "skip-host-discovery", false, "scan targets directly without host discovery")
	fs.StringVar(methods, "discovery-methods", "arp,icmp,tcp", "comma-separated host discovery methods")
	fs.IntVar(&opts.request.ICMPWaitMS, "icmp-wait-ms", 700, "ICMP wait time in milliseconds")
	fs.StringVar(&opts.request.TCPPingPorts, "tcp-ping-ports", "22,80,443,445,3389", "TCP ports used for liveness fallback")
	fs.IntVar(&opts.request.ARPTimeoutMS, "arp-timeout-ms", 700, "ARP wait time in milliseconds")
}

func registerVulnFlags(fs *flag.FlagSet, opts *cliOptions) {
	fs.StringVar(&opts.request.InputFile, "input", "", "prior scan JSONL input for vuln mode")
	fs.BoolVar(&opts.request.TCP, "tcp", false, "enable TCP checks for live vuln mode")
	fs.BoolVar(&opts.request.UDP, "udp", false, "enable UDP checks for live vuln mode")
	fs.StringVar(&opts.request.Ports, "ports", "", "ports to inspect in live vuln mode")
	fs.StringVar(&opts.request.UDPPorts, "udp-ports", "", "UDP ports to inspect in live vuln mode")
	fs.IntVar(&opts.request.TopPorts, "top-ports", 100, "number of common TCP ports to inspect when --ports is omitted")
	fs.IntVar(&opts.request.TopUDP, "top-udp", 20, "number of common UDP ports to inspect when --udp-ports is omitted")
	registerPerformanceFlags(fs, opts)
}

func registerReconFlags(fs *flag.FlagSet, opts *cliOptions) {
	fs.BoolVar(&opts.request.Subdomains, "subdomains", true, "collect passive subdomains from public sources")
	fs.StringVar(&opts.request.Wordlist, "wordlist", "", "reserved for imported passive subdomain seed files")
	fs.StringVar(&opts.request.Records, "records", "A,AAAA,CNAME,MX,NS,TXT", "DNS record types to enrich")
	fs.StringVar(&opts.request.Sources, "sources", strings.Join(defaultReconSources(), ","), "comma-separated passive sources")
	fs.IntVar(&opts.request.SourceLimit, "source-limit", 500, "requested minimum result window per passive source; sources may return fewer or more")
	fs.IntVar(&opts.request.MaxSubdomains, "max-subdomains", 0, "optional final cap after merging/deduping; 0 means no final cap")
	fs.IntVar(&opts.request.MaxIPs, "max-ips", 200, "maximum IPs to enrich with RDAP")
	fs.BoolVar(&opts.request.CIDRRanges, "cidr-ranges", false, "focused mode: list CIDR ranges related to target domains or IPs")
	fs.BoolVar(&opts.request.CIDRRanges, "cidr_ranges", false, "alias for --cidr-ranges")
	fs.BoolVar(&opts.request.ExpandCIDRs, "expand-cidrs", false, "emit individual IPs from discovered or input CIDR ranges")
	fs.IntVar(&opts.request.MaxCIDRIPs, "max-cidr-ips", 4096, "maximum IPs to emit per CIDR when --expand-cidrs is set")
	fs.BoolVar(&opts.request.LiveIPs, "live-ips", false, "actively check expanded CIDR candidates and emit responsive IPs")
	fs.StringVar(&opts.request.LiveIPPorts, "live-ip-ports", "80,443,22", "TCP ports used for --live-ips liveness checks")
	fs.IntVar(&opts.request.MaxLiveIPs, "max-live-ips", 256, "maximum CIDR candidate IPs to check per range when --live-ips is set")
	fs.BoolVar(&opts.request.NoResolve, "no-resolve", false, "skip public DNS resolver enrichment")
	fs.BoolVar(&opts.request.NoRDAP, "no-rdap", false, "skip RDAP IP/CIDR enrichment")
	registerPerformanceFlags(fs, opts)
}

func (p *commandParser) finalize() error {
	p.opts.request.Targets = []string(p.targets)
	p.opts.request.Excludes = []string(p.excludes)
	p.opts.request.DiscoveryMethods = splitCSV(p.methods)

	if !p.opts.ackAuthorized {
		return errors.New("active scan commands require --ack-authorized for owned or explicitly permitted assets")
	}
	if p.opts.request.TargetFile == "" && len(p.opts.request.Targets) == 0 && p.opts.request.InputFile == "" {
		return errors.New("provide --target, --target-file, or --input")
	}
	if p.opts.request.DiscoverHosts && p.opts.request.SkipDiscovery {
		return errors.New("--discover-hosts and --skip-host-discovery cannot both be set")
	}
	if p.opts.format != "text" && p.opts.format != "jsonl" {
		return errors.New("--format must be text or jsonl")
	}
	if p.opts.request.Command == "recon" {
		p.applyReconSpecificModes()
	}
	return nil
}

func (p *commandParser) applyReconSpecificModes() {
	if p.opts.request.LiveIPs {
		p.opts.request.CIDRRanges = true
	}
	if !p.opts.request.CIDRRanges {
		return
	}

	p.opts.request.Subdomains = false
	if flagWasSet(p.fs, "sources") {
		p.opts.request.Sources = ensureSources(p.opts.request.Sources, "dns-google", "rdap")
	} else {
		p.opts.request.Sources = "dns-google,rdap"
	}
	if !flagWasSet(p.fs, "records") {
		p.opts.request.Records = "A,AAAA"
	}
}

func hasHelpFlag(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			return true
		}
	}
	return false
}

type cliEventWriter struct {
	mu         sync.Mutex
	stdout     io.Writer
	rawFile    *os.File
	reportFile *os.File
	jsonl      bool
	dedupe     bool
	cidrOnly   bool
	seen       map[string]bool
}

type crtEntry struct {
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
}

type dohResponse struct {
	Status int         `json:"Status"`
	Answer []dohAnswer `json:"Answer"`
}

type dohAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

type rdapIPResponse struct {
	Name         string     `json:"name"`
	Handle       string     `json:"handle"`
	Country      string     `json:"country"`
	StartAddress string     `json:"startAddress"`
	EndAddress   string     `json:"endAddress"`
	CIDRs        []rdapCIDR `json:"cidr0_cidrs"`
}

type rdapCIDR struct {
	V4Prefix string `json:"v4prefix"`
	V6Prefix string `json:"v6prefix"`
	Length   int    `json:"length"`
}

type passiveSourceResult struct {
	Subdomains   []string
	AddressHints map[string][]string
}

type reconScope struct {
	Domain string
	Seeds  []string
}

type discoveredCIDR struct {
	CIDR         string
	Name         string
	Country      string
	StartAddress string
	EndAddress   string
	Source       string
}

type liveIPCandidate struct {
	IP   netip.Addr
	CIDR discoveredCIDR
}

type liveIPResult struct {
	Alive  bool
	Port   int
	RTT    time.Duration
	Reason string
}

type certSpotterEntry struct {
	DNSNames []string `json:"dns_names"`
}

type threatMinerResponse struct {
	StatusCode string   `json:"status_code"`
	Results    []string `json:"results"`
}

type urlscanResponse struct {
	Results []struct {
		Page struct {
			Domain string `json:"domain"`
			URL    string `json:"url"`
		} `json:"page"`
		Task struct {
			Domain string `json:"domain"`
		} `json:"task"`
	} `json:"results"`
}

func newCLIEventWriter(opts cliOptions, stdout io.Writer) (*cliEventWriter, error) {
	writer := &cliEventWriter{
		stdout:   stdout,
		jsonl:    opts.format == "jsonl",
		dedupe:   opts.dedupe,
		cidrOnly: opts.request.CIDRRanges,
		seen:     map[string]bool{},
	}
	if opts.jsonlOut != "" {
		file, err := os.Create(opts.jsonlOut)
		if err != nil {
			return nil, err
		}
		writer.rawFile = file
	}
	if opts.reportOut != "" {
		file, err := os.Create(opts.reportOut)
		if err != nil {
			_ = writer.Close()
			return nil, err
		}
		writer.reportFile = file
		if _, err := fmt.Fprintf(file, "Netscope report\nGenerated: %s\nFormat: text\n\n", time.Now().Format(time.RFC3339)); err != nil {
			_ = writer.Close()
			return nil, err
		}
	}
	return writer, nil
}

func (w *cliEventWriter) Close() error {
	var closeErr error
	if w.rawFile != nil {
		closeErr = errors.Join(closeErr, w.rawFile.Close())
	}
	if w.reportFile != nil {
		closeErr = errors.Join(closeErr, w.reportFile.Close())
	}
	return closeErr
}

func (w *cliEventWriter) Emit(event map[string]any) error {
	line, err := json.Marshal(event)
	if err != nil {
		return err
	}
	return w.EmitRaw(line)
}

func (w *cliEventWriter) EmitRaw(line []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.cidrOnly && !cidrRangeModeEvent(line) {
		return nil
	}
	if w.dedupe {
		if key := eventDedupeKey(line); key != "" {
			if w.seen[key] {
				return nil
			}
			w.seen[key] = true
		}
	}
	if w.rawFile != nil {
		if _, err := w.rawFile.Write(append(append([]byte{}, line...), '\n')); err != nil {
			return err
		}
	}
	if w.reportFile != nil {
		if _, err := fmt.Fprintln(w.reportFile, renderEventLine(line)); err != nil {
			return err
		}
	}
	if w.jsonl {
		fmt.Fprintln(w.stdout, string(line))
		return nil
	}
	renderEvent(w.stdout, line)
	return nil
}

func cidrRangeModeEvent(line []byte) bool {
	var event map[string]any
	if err := json.Unmarshal(line, &event); err != nil {
		return true
	}
	switch text(event, "type") {
	case "cidr", "cidr_ip", "live_ip", "warning", "summary", "error":
		return true
	default:
		return false
	}
}

func runPassiveRecon(opts cliOptions, stdout, stderr io.Writer) error {
	writer, err := newCLIEventWriter(opts, stdout)
	if err != nil {
		return err
	}
	defer writer.Close()

	scopes, ipObjects, err := collectReconInputs(opts.request)
	if err != nil {
		return err
	}
	if len(scopes) == 0 && len(ipObjects) == 0 {
		return errors.New("recon needs at least one domain, IP, CIDR, or IP range target")
	}

	sources := sourceSet(splitCSV(opts.request.Sources))
	client := &http.Client{Timeout: time.Duration(opts.request.TimeoutMS) * time.Millisecond}
	if opts.request.TimeoutMS <= 0 {
		client.Timeout = 10 * time.Second
	}
	sourceLimit := positiveOrDefault(opts.request.SourceLimit, 500)
	maxSubdomains := opts.request.MaxSubdomains
	maxIPs := positiveOrDefault(opts.request.MaxIPs, 200)
	maxCIDRIPs := positiveOrDefault(opts.request.MaxCIDRIPs, 4096)
	maxLiveIPs := positiveOrDefault(opts.request.MaxLiveIPs, 256)
	recordTypes := reconRecordTypes(opts.request.Records)

	cidrExpansion := "disabled"
	if opts.request.ExpandCIDRs {
		cidrExpansion = fmt.Sprintf("enabled limit=%d-per-cidr", maxCIDRIPs)
	}
	modeNote := "no target ports or web paths are probed"
	if opts.request.LiveIPs {
		modeNote = fmt.Sprintf("live-ip mode uses bounded TCP liveness checks on ports %s", opts.request.LiveIPPorts)
		_ = writer.Emit(map[string]any{
			"type":    "warning",
			"message": "live IP discovery is active traffic; only run it for CIDR ranges that are owned or explicitly in-scope",
		})
	}
	_ = writer.Emit(map[string]any{
		"type":    "progress",
		"message": fmt.Sprintf("recon mode: source-limit=%d final-cap=%s cidr-expansion=%s; %s", sourceLimit, finalCapLabel(maxSubdomains), cidrExpansion, modeNote),
	})

	ipToNames := map[string]map[string]bool{}
	for _, object := range ipObjects {
		addNameForIP(ipToNames, object, object)
	}

	dnsSeen := map[string]bool{}
	for _, scope := range scopes {
		domain := scope.Domain
		_ = writer.Emit(map[string]any{
			"type":     "domain",
			"domain":   domain,
			"resolver": "public-sources",
			"sources":  strings.Join(keysOfSourceSet(sources), ","),
		})
		if seedMessage := reconSeedMessage(scope); seedMessage != "" {
			_ = writer.Emit(map[string]any{
				"type":    "progress",
				"message": seedMessage,
			})
		}

		subdomainSources := map[string]map[string]bool{}
		subdomainAddressHints := map[string]map[string]bool{}
		for _, seed := range scope.Seeds {
			if seed == domain {
				continue
			}
			addSubdomainSource(subdomainSources, seed, "input")
		}
		if opts.request.Subdomains {
			collectPassiveSubdomains(client, writer, domain, sources, subdomainSources, subdomainAddressHints, sourceLimit)
		}
		subdomains := rankedSubdomains(subdomainSources, subdomainAddressHints)
		if maxSubdomains > 0 && len(subdomains) > maxSubdomains {
			_ = writer.Emit(map[string]any{
				"type":    "warning",
				"message": fmt.Sprintf("subdomain results for %s capped at %d; raise --max-subdomains to enrich more", domain, maxSubdomains),
			})
			subdomains = subdomains[:maxSubdomains]
		}

		if sources["dns-google"] && !opts.request.NoResolve {
			enrichDNSName(client, writer, domain, recordTypes, ipToNames, "dns-google", dnsSeen)
		}

		for _, subdomain := range subdomains {
			addresses := keysOfBoolMap(subdomainAddressHints[subdomain])
			cnames := []string{}
			if sources["dns-google"] && !opts.request.NoResolve {
				dnsAddresses, dnsCnames := enrichDNSName(client, writer, subdomain, []string{"A", "AAAA", "CNAME"}, ipToNames, strings.Join(keysOfBoolMap(subdomainSources[subdomain]), ",")+",dns-google", dnsSeen)
				addresses = append(addresses, dnsAddresses...)
				cnames = dnsCnames
			}
			addresses = uniqueSorted(addresses)
			for _, address := range addresses {
				addNameForIP(ipToNames, address, subdomain)
			}
			ipv4, ipv6 := splitIPVersions(addresses)
			_ = writer.Emit(map[string]any{
				"type":      "subdomain",
				"domain":    domain,
				"name":      subdomain,
				"addresses": strings.Join(addresses, ","),
				"ipv4":      strings.Join(ipv4, ","),
				"ipv6":      strings.Join(ipv6, ","),
				"cnames":    cnames,
				"sources":   strings.Join(keysOfBoolMap(subdomainSources[subdomain]), ","),
			})
		}
	}

	cidrs := inputCIDRs(ipObjects)
	emitDiscoveredCIDRs(writer, cidrs)
	if sources["rdap"] && !opts.request.NoRDAP {
		cidrs = append(cidrs, enrichRDAP(client, writer, ipToNames, maxIPs)...)
	}
	cidrs = mergeDiscoveredCIDRs(cidrs)
	if opts.request.CIDRRanges && len(cidrs) == 0 {
		_ = writer.Emit(map[string]any{
			"type":    "warning",
			"message": "no CIDR ranges found; include dns-google and rdap sources, raise --max-subdomains, or provide direct IP targets",
		})
	}
	if opts.request.ExpandCIDRs {
		expandDiscoveredCIDRs(writer, cidrs, maxCIDRIPs)
	}
	liveCount := 0
	if opts.request.LiveIPs {
		ports, err := parsePortList(opts.request.LiveIPPorts, []int{80, 443, 22}, 64)
		if err != nil {
			return err
		}
		liveCount = discoverLiveCIDRIPs(writer, cidrs, ports, maxLiveIPs, time.Duration(opts.request.TimeoutMS)*time.Millisecond, opts.request.Concurrency)
	}

	summary := "passive recon complete"
	if opts.request.CIDRRanges {
		summary = fmt.Sprintf("cidr range recon complete: %d ranges", len(cidrs))
	}
	if opts.request.LiveIPs {
		summary = fmt.Sprintf("cidr live-ip recon complete: %d ranges, %d live IPs", len(cidrs), liveCount)
	}
	_ = writer.Emit(map[string]any{
		"type":    "summary",
		"message": summary,
	})
	return nil
}

func collectReconInputs(request engineRequest) ([]reconScope, []string, error) {
	specs := append([]string{}, request.Targets...)
	if request.TargetFile != "" {
		content, err := os.ReadFile(request.TargetFile)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read target file %s: %w", request.TargetFile, err)
		}
		for _, line := range strings.Split(string(content), "\n") {
			item := strings.TrimSpace(strings.Split(line, "#")[0])
			if item != "" {
				specs = append(specs, item)
			}
		}
	}

	scopeSeeds := map[string]map[string]bool{}
	ipSeen := map[string]bool{}
	var ipObjects []string
	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		if ip := net.ParseIP(spec); ip != nil {
			value := ip.String()
			if !ipSeen[value] {
				ipSeen[value] = true
				ipObjects = append(ipObjects, value)
			}
			continue
		}
		if _, network, err := net.ParseCIDR(spec); err == nil {
			value := network.String()
			if !ipSeen[value] {
				ipSeen[value] = true
				ipObjects = append(ipObjects, value)
			}
			continue
		}
		if start, end, ok := parseIPRange(spec); ok {
			for _, value := range []string{start.String(), end.String()} {
				if !ipSeen[value] {
					ipSeen[value] = true
					ipObjects = append(ipObjects, value)
				}
			}
			continue
		}
		domain := normalizeDomainInput(spec)
		if domain != "" {
			root := passiveReconRoot(domain)
			if scopeSeeds[root] == nil {
				scopeSeeds[root] = map[string]bool{}
			}
			scopeSeeds[root][domain] = true
		}
	}
	domains := keysOfNestedSet(scopeSeeds)
	scopes := make([]reconScope, 0, len(domains))
	for _, domain := range domains {
		scopes = append(scopes, reconScope{
			Domain: domain,
			Seeds:  keysOfBoolMap(scopeSeeds[domain]),
		})
	}
	sort.Strings(ipObjects)
	return scopes, ipObjects, nil
}

func parseIPRange(spec string) (net.IP, net.IP, bool) {
	start, end, ok := strings.Cut(spec, "-")
	if !ok {
		return nil, nil, false
	}
	startIP := net.ParseIP(strings.TrimSpace(start))
	endIP := net.ParseIP(strings.TrimSpace(end))
	return startIP, endIP, startIP != nil && endIP != nil
}

func normalizeDomainInput(raw string) string {
	value := strings.TrimSpace(strings.ToLower(raw))
	if strings.Contains(value, "://") {
		if parsed, err := url.Parse(value); err == nil {
			value = parsed.Hostname()
		}
	}
	value = strings.Split(value, "/")[0]
	value = strings.TrimSuffix(value, ".")
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	if net.ParseIP(value) != nil || !validDomain(value) {
		return ""
	}
	return value
}

func passiveReconRoot(domain string) string {
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(domain), "."), ".")
	if len(labels) <= 2 {
		return domain
	}

	suffix2 := strings.Join(labels[len(labels)-2:], ".")
	suffix3 := strings.Join(labels[len(labels)-3:], ".")
	commonSecondLevel := map[string]bool{
		"co": true, "com": true, "net": true, "org": true, "gov": true, "ac": true, "edu": true,
	}
	if len(labels) >= 3 && commonSecondLevel[labels[len(labels)-2]] && len(labels[len(labels)-1]) == 2 {
		return suffix3
	}
	return suffix2
}

func validDomain(value string) bool {
	if len(value) == 0 || len(value) > 253 || !strings.Contains(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z') && !(ch >= '0' && ch <= '9') && ch != '-' {
				return false
			}
		}
	}
	return true
}

func fetchCRTSubdomains(client *http.Client, domain string) ([]string, error) {
	values := url.Values{}
	values.Set("q", "%."+domain)
	values.Set("output", "json")
	req, err := http.NewRequest(http.MethodGet, "https://crt.sh/?"+values.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "netscope/0.1 passive-recon")
	resp, err := doRequest(client, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}
	var entries []crtEntry
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16*1024*1024)).Decode(&entries); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, entry := range entries {
		for _, candidate := range append(strings.Split(entry.NameValue, "\n"), entry.CommonName) {
			name, ok := normalizeSubdomain(candidate, domain)
			if ok && !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func doRequest(client *http.Client, req *http.Request) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		resp, err := client.Do(req.Clone(req.Context()))
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(attempt+1) * 350 * time.Millisecond)
			continue
		}
		if retryableStatus(resp.StatusCode) {
			lastErr = fmt.Errorf("unexpected status %s", resp.Status)
			resp.Body.Close()
			time.Sleep(time.Duration(attempt+1) * 350 * time.Millisecond)
			continue
		}
		return resp, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("request failed")
}

func retryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusInternalServerError || status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout || status == 521 || status == 522 || status == 523 || status == 524
}

func collectPassiveSubdomains(client *http.Client, writer *cliEventWriter, domain string, sources map[string]bool, subdomainSources map[string]map[string]bool, addressHints map[string]map[string]bool, sourceLimit int) {
	collectors := []struct {
		name string
		run  func(*http.Client, string, int) (passiveSourceResult, error)
	}{
		{"crtsh", func(client *http.Client, domain string, _ int) (passiveSourceResult, error) {
			names, err := fetchCRTSubdomains(client, domain)
			return passiveSourceResult{Subdomains: names}, err
		}},
		{"certspotter", fetchCertSpotterSubdomains},
		{"hackertarget", fetchHackerTargetSubdomains},
		{"threatminer", fetchThreatMinerSubdomains},
		{"wayback", fetchWaybackSubdomains},
		{"anubis", fetchAnubisSubdomains},
		{"subdomain-center", fetchSubdomainCenterSubdomains},
		{"urlscan", fetchURLScanSubdomains},
	}

	type sourceOutcome struct {
		name   string
		result passiveSourceResult
		err    error
	}

	outcomes := make(chan sourceOutcome, len(collectors))
	var wg sync.WaitGroup
	for _, collector := range collectors {
		if !sources[collector.name] {
			continue
		}
		wg.Add(1)
		go func(name string, run func(*http.Client, string, int) (passiveSourceResult, error)) {
			defer wg.Done()
			result, err := run(client, domain, sourceLimit)
			outcomes <- sourceOutcome{name: name, result: result, err: err}
		}(collector.name, collector.run)
	}
	wg.Wait()
	close(outcomes)

	failures := []string{}
	for outcome := range outcomes {
		if outcome.err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", outcome.name, outcome.err))
			continue
		}
		for _, raw := range outcome.result.Subdomains {
			name, ok := normalizeSubdomain(raw, domain)
			if !ok {
				continue
			}
			addSubdomainSource(subdomainSources, name, outcome.name)
		}
		for rawName, addresses := range outcome.result.AddressHints {
			name, ok := normalizeSubdomain(rawName, domain)
			if !ok {
				continue
			}
			addSubdomainSource(subdomainSources, name, outcome.name)
			for _, address := range addresses {
				if ip := net.ParseIP(strings.TrimSpace(address)); ip != nil {
					addAddressHint(addressHints, name, ip.String())
				}
			}
		}
		_ = writer.Emit(map[string]any{
			"type":    "progress",
			"message": fmt.Sprintf("%s returned %d passive subdomain candidates for %s", outcome.name, len(outcome.result.Subdomains)+len(outcome.result.AddressHints), domain),
		})
	}
	if len(failures) > 0 {
		sort.Strings(failures)
		_ = writer.Emit(map[string]any{
			"type":    "warning",
			"message": fmt.Sprintf("passive source failures for %s: %s", domain, strings.Join(failures, " | ")),
		})
	}
}

func fetchCertSpotterSubdomains(client *http.Client, domain string, _ int) (passiveSourceResult, error) {
	values := url.Values{}
	values.Set("domain", domain)
	values.Set("include_subdomains", "true")
	values.Set("expand", "dns_names")
	req, err := http.NewRequest(http.MethodGet, "https://api.certspotter.com/v1/issuances?"+values.Encode(), nil)
	if err != nil {
		return passiveSourceResult{}, err
	}
	req.Header.Set("User-Agent", "netscope/0.1 passive-recon")
	if token := os.Getenv("CERTSPOTTER_API_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := doRequest(client, req)
	if err != nil {
		return passiveSourceResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return passiveSourceResult{}, fmt.Errorf("unexpected status %s", resp.Status)
	}
	var entries []certSpotterEntry
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16*1024*1024)).Decode(&entries); err != nil {
		return passiveSourceResult{}, err
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.DNSNames...)
	}
	return passiveSourceResult{Subdomains: names}, nil
}

func fetchHackerTargetSubdomains(client *http.Client, domain string, _ int) (passiveSourceResult, error) {
	values := url.Values{}
	values.Set("q", domain)
	req, err := http.NewRequest(http.MethodGet, "https://api.hackertarget.com/hostsearch/?"+values.Encode(), nil)
	if err != nil {
		return passiveSourceResult{}, err
	}
	req.Header.Set("User-Agent", "netscope/0.1 passive-recon")
	resp, err := doRequest(client, req)
	if err != nil {
		return passiveSourceResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return passiveSourceResult{}, fmt.Errorf("unexpected status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return passiveSourceResult{}, err
	}
	result := passiveSourceResult{AddressHints: map[string][]string{}}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(strings.ToLower(line), "error") {
			continue
		}
		parts := strings.Split(line, ",")
		name := strings.TrimSpace(parts[0])
		result.Subdomains = append(result.Subdomains, name)
		if len(parts) > 1 {
			result.AddressHints[name] = append(result.AddressHints[name], strings.TrimSpace(parts[1]))
		}
	}
	return result, nil
}

func fetchThreatMinerSubdomains(client *http.Client, domain string, _ int) (passiveSourceResult, error) {
	values := url.Values{}
	values.Set("q", domain)
	values.Set("rt", "5")
	req, err := http.NewRequest(http.MethodGet, "https://api.threatminer.org/v2/domain.php?"+values.Encode(), nil)
	if err != nil {
		return passiveSourceResult{}, err
	}
	req.Header.Set("User-Agent", "netscope/0.1 passive-recon")
	resp, err := doRequest(client, req)
	if err != nil {
		return passiveSourceResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return passiveSourceResult{}, fmt.Errorf("unexpected status %s", resp.Status)
	}
	var decoded threatMinerResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8*1024*1024)).Decode(&decoded); err != nil {
		return passiveSourceResult{}, err
	}
	return passiveSourceResult{Subdomains: decoded.Results}, nil
}

func fetchWaybackSubdomains(client *http.Client, domain string, sourceLimit int) (passiveSourceResult, error) {
	limit := sourceLimit * 5
	if limit < 100 {
		limit = 100
	}
	if limit > 25000 {
		limit = 25000
	}
	values := url.Values{}
	values.Set("url", "*."+domain+"/*")
	values.Set("output", "json")
	values.Set("fl", "original")
	values.Set("collapse", "urlkey")
	values.Set("limit", fmt.Sprint(limit))
	req, err := http.NewRequest(http.MethodGet, "https://web.archive.org/cdx/search/cdx?"+values.Encode(), nil)
	if err != nil {
		return passiveSourceResult{}, err
	}
	req.Header.Set("User-Agent", "netscope/0.1 passive-recon")
	resp, err := doRequest(client, req)
	if err != nil {
		return passiveSourceResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return passiveSourceResult{}, fmt.Errorf("unexpected status %s", resp.Status)
	}
	var rows [][]string
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16*1024*1024)).Decode(&rows); err != nil {
		return passiveSourceResult{}, err
	}
	var names []string
	for index, row := range rows {
		if index == 0 || len(row) == 0 {
			continue
		}
		if parsed, err := url.Parse(row[0]); err == nil {
			if host := parsed.Hostname(); host != "" {
				names = append(names, host)
			}
		}
	}
	return passiveSourceResult{Subdomains: names}, nil
}

func fetchAnubisSubdomains(client *http.Client, domain string, _ int) (passiveSourceResult, error) {
	req, err := http.NewRequest(http.MethodGet, "https://jldc.me/anubis/subdomains/"+url.PathEscape(domain), nil)
	if err != nil {
		return passiveSourceResult{}, err
	}
	req.Header.Set("User-Agent", "netscope/0.1 passive-recon")
	resp, err := doRequest(client, req)
	if err != nil {
		return passiveSourceResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return passiveSourceResult{}, fmt.Errorf("unexpected status %s", resp.Status)
	}
	var names []string
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8*1024*1024)).Decode(&names); err != nil {
		return passiveSourceResult{}, err
	}
	return passiveSourceResult{Subdomains: names}, nil
}

func fetchSubdomainCenterSubdomains(client *http.Client, domain string, _ int) (passiveSourceResult, error) {
	values := url.Values{}
	values.Set("domain", domain)
	req, err := http.NewRequest(http.MethodGet, "https://api.subdomain.center/?"+values.Encode(), nil)
	if err != nil {
		return passiveSourceResult{}, err
	}
	req.Header.Set("User-Agent", "netscope/0.1 passive-recon")
	resp, err := doRequest(client, req)
	if err != nil {
		return passiveSourceResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return passiveSourceResult{}, fmt.Errorf("unexpected status %s", resp.Status)
	}
	var names []string
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8*1024*1024)).Decode(&names); err != nil {
		return passiveSourceResult{}, err
	}
	return passiveSourceResult{Subdomains: names}, nil
}

func fetchURLScanSubdomains(client *http.Client, domain string, sourceLimit int) (passiveSourceResult, error) {
	size := sourceLimit * 2
	if size < 100 {
		size = 100
	}
	if size > 10000 {
		size = 10000
	}
	values := url.Values{}
	values.Set("q", "domain:"+domain)
	values.Set("size", fmt.Sprint(size))
	req, err := http.NewRequest(http.MethodGet, "https://urlscan.io/api/v1/search/?"+values.Encode(), nil)
	if err != nil {
		return passiveSourceResult{}, err
	}
	req.Header.Set("User-Agent", "netscope/0.1 passive-recon")
	if token := os.Getenv("URLSCAN_API_KEY"); token != "" {
		req.Header.Set("API-Key", token)
	}
	resp, err := doRequest(client, req)
	if err != nil {
		return passiveSourceResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return passiveSourceResult{}, fmt.Errorf("unexpected status %s", resp.Status)
	}
	var decoded urlscanResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16*1024*1024)).Decode(&decoded); err != nil {
		return passiveSourceResult{}, err
	}
	var names []string
	for _, result := range decoded.Results {
		names = append(names, result.Page.Domain, result.Task.Domain)
		if parsed, err := url.Parse(result.Page.URL); err == nil {
			names = append(names, parsed.Hostname())
		}
	}
	return passiveSourceResult{Subdomains: names}, nil
}

func normalizeSubdomain(raw, domain string) (string, bool) {
	name := strings.TrimSpace(strings.ToLower(raw))
	name = strings.TrimPrefix(name, "*.")
	name = strings.TrimSuffix(name, ".")
	if strings.Contains(name, "*") || name == domain || !strings.HasSuffix(name, "."+domain) || !validDomain(name) {
		return "", false
	}
	return name, true
}

func enrichDNSName(client *http.Client, writer *cliEventWriter, name string, recordTypes []string, ipToNames map[string]map[string]bool, source string, dnsSeen map[string]bool) ([]string, []string) {
	addressSeen := map[string]bool{}
	cnameSeen := map[string]bool{}
	var addresses []string
	var cnames []string
	for _, recordType := range recordTypes {
		answers, err := fetchDoH(client, name, recordType)
		if err != nil {
			_ = writer.Emit(map[string]any{"type": "warning", "message": fmt.Sprintf("public DNS lookup failed for %s %s: %v", name, recordType, err)})
			continue
		}
		for _, answer := range answers {
			value := strings.TrimSuffix(answer.Data, ".")
			rrType := dnsTypeName(answer.Type)
			recordName := strings.TrimSuffix(answer.Name, ".")
			dedupeKey := strings.Join([]string{recordName, rrType, value}, "\x00")
			if !dnsSeen[dedupeKey] {
				dnsSeen[dedupeKey] = true
				_ = writer.Emit(map[string]any{
					"type":        "dns_record",
					"domain":      rootDomain(name),
					"name":        recordName,
					"record_type": rrType,
					"value":       value,
					"ttl":         answer.TTL,
					"source":      source,
				})
			}
			if rrType == "A" || rrType == "AAAA" {
				if ip := net.ParseIP(value); ip != nil && !addressSeen[ip.String()] {
					addressSeen[ip.String()] = true
					addresses = append(addresses, ip.String())
					addNameForIP(ipToNames, ip.String(), name)
				}
			}
			if rrType == "CNAME" && !cnameSeen[value] {
				cnameSeen[value] = true
				cnames = append(cnames, value)
			}
		}
	}
	sort.Strings(addresses)
	sort.Strings(cnames)
	return addresses, cnames
}

func fetchDoH(client *http.Client, name, recordType string) ([]dohAnswer, error) {
	values := url.Values{}
	values.Set("name", name)
	values.Set("type", strings.ToUpper(recordType))
	req, err := http.NewRequest(http.MethodGet, "https://dns.google/resolve?"+values.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "netscope/0.1 passive-recon")
	resp, err := doRequest(client, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}
	var decoded dohResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2*1024*1024)).Decode(&decoded); err != nil {
		return nil, err
	}
	if decoded.Status != 0 {
		return nil, nil
	}
	return decoded.Answer, nil
}

func enrichRDAP(client *http.Client, writer *cliEventWriter, ipToNames map[string]map[string]bool, maxIPs int) []discoveredCIDR {
	ips := make([]string, 0, len(ipToNames))
	for ip := range ipToNames {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	if len(ips) > maxIPs {
		_ = writer.Emit(map[string]any{
			"type":    "warning",
			"message": fmt.Sprintf("RDAP enrichment capped at %d IP objects; raise --max-ips to enrich more", maxIPs),
		})
		ips = ips[:maxIPs]
	}

	var cidrs []discoveredCIDR
	cidrSeen := map[string]bool{}
	for _, ip := range ips {
		names := namesForIP(ipToNames[ip])
		_ = writer.Emit(map[string]any{
			"type":   "ip_asset",
			"ip":     ip,
			"name":   strings.Join(names, ","),
			"source": "dns-google",
		})
		info, err := fetchRDAPIP(client, ip)
		if err != nil {
			_ = writer.Emit(map[string]any{"type": "warning", "message": fmt.Sprintf("RDAP lookup failed for %s: %v", ip, err)})
			continue
		}
		for _, cidr := range info.CIDRs {
			prefix := cidr.V4Prefix
			if prefix == "" {
				prefix = cidr.V6Prefix
			}
			if prefix == "" || cidr.Length == 0 {
				continue
			}
			value := fmt.Sprintf("%s/%d", prefix, cidr.Length)
			if cidrSeen[value] {
				continue
			}
			cidrSeen[value] = true
			item := discoveredCIDR{
				CIDR:         value,
				Name:         firstNonEmpty(info.Name, info.Handle),
				Country:      info.Country,
				StartAddress: info.StartAddress,
				EndAddress:   info.EndAddress,
				Source:       "rdap.org",
			}
			cidrs = append(cidrs, item)
			_ = writer.Emit(map[string]any{
				"type":          "cidr",
				"cidr":          item.CIDR,
				"name":          item.Name,
				"country":       item.Country,
				"start_address": item.StartAddress,
				"end_address":   item.EndAddress,
				"source":        item.Source,
			})
		}
	}
	return cidrs
}

func inputCIDRs(ipObjects []string) []discoveredCIDR {
	var cidrs []discoveredCIDR
	for _, object := range ipObjects {
		prefix, err := netip.ParsePrefix(object)
		if err != nil {
			continue
		}
		prefix = prefix.Masked()
		cidrs = append(cidrs, discoveredCIDR{
			CIDR:   prefix.String(),
			Name:   "input",
			Source: "input",
		})
	}
	return mergeDiscoveredCIDRs(cidrs)
}

func emitDiscoveredCIDRs(writer *cliEventWriter, cidrs []discoveredCIDR) {
	for _, item := range mergeDiscoveredCIDRs(cidrs) {
		_ = writer.Emit(map[string]any{
			"type":          "cidr",
			"cidr":          item.CIDR,
			"name":          item.Name,
			"country":       item.Country,
			"start_address": item.StartAddress,
			"end_address":   item.EndAddress,
			"source":        item.Source,
		})
	}
}

func mergeDiscoveredCIDRs(cidrs []discoveredCIDR) []discoveredCIDR {
	byCIDR := map[string]discoveredCIDR{}
	for _, item := range cidrs {
		prefix, err := netip.ParsePrefix(item.CIDR)
		if err != nil {
			continue
		}
		item.CIDR = prefix.Masked().String()
		if item.Source == "" {
			item.Source = "unknown"
		}
		existing, ok := byCIDR[item.CIDR]
		if !ok || (existing.Source == "input" && item.Source != "input") {
			byCIDR[item.CIDR] = item
		}
	}
	keys := make([]string, 0, len(byCIDR))
	for key := range byCIDR {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]discoveredCIDR, 0, len(keys))
	for _, key := range keys {
		out = append(out, byCIDR[key])
	}
	return out
}

func expandDiscoveredCIDRs(writer *cliEventWriter, cidrs []discoveredCIDR, maxPerCIDR int) {
	cidrs = mergeDiscoveredCIDRs(cidrs)
	if len(cidrs) == 0 {
		_ = writer.Emit(map[string]any{
			"type":    "warning",
			"message": "no CIDR ranges available to expand; include dns-google and rdap sources or provide a CIDR target",
		})
		return
	}
	if maxPerCIDR <= 0 {
		maxPerCIDR = 4096
	}

	for _, item := range cidrs {
		prefix, err := netip.ParsePrefix(item.CIDR)
		if err != nil {
			_ = writer.Emit(map[string]any{"type": "warning", "message": fmt.Sprintf("cannot expand invalid CIDR %s", item.CIDR)})
			continue
		}
		prefix = prefix.Masked()
		total := prefixAddressCount(prefix)
		limit := maxPerCIDR
		limitBig := big.NewInt(int64(limit))
		if total.Cmp(limitBig) < 0 {
			limit = int(total.Int64())
		}

		emitted := 0
		for addr := prefix.Addr(); addr.IsValid() && prefix.Contains(addr) && emitted < limit; addr = addr.Next() {
			_ = writer.Emit(map[string]any{
				"type":   "cidr_ip",
				"ip":     addr.String(),
				"cidr":   prefix.String(),
				"name":   item.Name,
				"source": firstNonEmpty(item.Source, "cidr-expansion"),
			})
			emitted++
		}

		_ = writer.Emit(map[string]any{
			"type":    "progress",
			"message": fmt.Sprintf("expanded %d IPs from %s", emitted, prefix.String()),
		})
		if total.Cmp(limitBig) > 0 {
			_ = writer.Emit(map[string]any{
				"type":    "warning",
				"message": fmt.Sprintf("CIDR %s contains %s IPs; emitted first %d only; raise --max-cidr-ips to include more", prefix.String(), total.String(), maxPerCIDR),
			})
		}
	}
}

func discoverLiveCIDRIPs(writer *cliEventWriter, cidrs []discoveredCIDR, ports []int, maxPerCIDR int, timeout time.Duration, concurrency int) int {
	cidrs = mergeDiscoveredCIDRs(cidrs)
	if len(cidrs) == 0 {
		_ = writer.Emit(map[string]any{
			"type":    "warning",
			"message": "no CIDR ranges available for live IP discovery; include dns-google and rdap sources or provide a CIDR target",
		})
		return 0
	}
	if maxPerCIDR <= 0 {
		maxPerCIDR = 256
	}
	if timeout <= 0 {
		timeout = 900 * time.Millisecond
	}
	if timeout < 100*time.Millisecond {
		timeout = 100 * time.Millisecond
	}
	workerCount := concurrency
	if workerCount <= 0 {
		workerCount = 64
	}
	if workerCount > 512 {
		workerCount = 512
	}

	jobs := make(chan liveIPCandidate, workerCount*2)
	results := make(chan liveIPCandidate, workerCount)
	var workers sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range jobs {
				result := probeLiveIP(job.IP.String(), ports, timeout)
				if !result.Alive {
					continue
				}
				_ = writer.Emit(map[string]any{
					"type":    "live_ip",
					"ip":      job.IP.String(),
					"cidr":    job.CIDR.CIDR,
					"name":    job.CIDR.Name,
					"port":    result.Port,
					"method":  "tcp",
					"rtt_ms":  result.RTT.Milliseconds(),
					"reason":  result.Reason,
					"source":  firstNonEmpty(job.CIDR.Source, "cidr-live"),
					"country": job.CIDR.Country,
				})
				results <- job
			}
		}()
	}

	go func() {
		workers.Wait()
		close(results)
	}()

	go func() {
		defer close(jobs)
		for _, item := range cidrs {
			prefix, err := netip.ParsePrefix(item.CIDR)
			if err != nil {
				_ = writer.Emit(map[string]any{"type": "warning", "message": fmt.Sprintf("cannot expand invalid CIDR %s for live discovery", item.CIDR)})
				continue
			}
			prefix = prefix.Masked()
			total := prefixAddressCount(prefix)
			limit := maxPerCIDR
			limitBig := big.NewInt(int64(limit))
			if total.Cmp(limitBig) < 0 {
				limit = int(total.Int64())
			}
			queued := 0
			for addr := prefix.Addr(); addr.IsValid() && prefix.Contains(addr) && queued < limit; addr = addr.Next() {
				jobs <- liveIPCandidate{IP: addr, CIDR: item}
				queued++
			}
			if total.Cmp(limitBig) > 0 {
				_ = writer.Emit(map[string]any{
					"type":    "warning",
					"message": fmt.Sprintf("live IP discovery for %s checks first %d of %s IPs; raise --max-live-ips only for authorized small ranges", prefix.String(), maxPerCIDR, total.String()),
				})
			}
		}
	}()

	liveCount := 0
	for range results {
		liveCount++
	}
	return liveCount
}

func probeLiveIP(ip string, ports []int, timeout time.Duration) liveIPResult {
	for _, port := range ports {
		started := time.Now()
		address := net.JoinHostPort(ip, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", address, timeout)
		rtt := time.Since(started)
		if err == nil {
			_ = conn.Close()
			return liveIPResult{
				Alive:  true,
				Port:   port,
				RTT:    rtt,
				Reason: fmt.Sprintf("tcp/%d accepted connection", port),
			}
		}
		reason := strings.ToLower(err.Error())
		if strings.Contains(reason, "connection refused") || strings.Contains(reason, "actively refused") {
			return liveIPResult{
				Alive:  true,
				Port:   port,
				RTT:    rtt,
				Reason: fmt.Sprintf("tcp/%d refused connection", port),
			}
		}
	}
	return liveIPResult{Reason: "no tcp liveness response"}
}

func prefixAddressCount(prefix netip.Prefix) *big.Int {
	totalBits := 128
	if prefix.Addr().Is4() {
		totalBits = 32
	}
	hostBits := totalBits - prefix.Bits()
	if hostBits < 0 {
		hostBits = 0
	}
	return new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
}

func fetchRDAPIP(client *http.Client, object string) (rdapIPResponse, error) {
	endpoints := []string{
		"https://rdap.org/ip/" + url.PathEscape(object),
		"https://rdap.arin.net/registry/ip/" + url.PathEscape(object),
		"https://rdap.db.ripe.net/ip/" + url.PathEscape(object),
		"https://rdap.apnic.net/ip/" + url.PathEscape(object),
		"https://rdap.lacnic.net/rdap/ip/" + url.PathEscape(object),
		"https://rdap.afrinic.net/rdap/ip/" + url.PathEscape(object),
	}
	var lastErr error
	for _, endpoint := range endpoints {
		decoded, err := fetchRDAPURL(client, endpoint)
		if err == nil {
			return decoded, nil
		}
		lastErr = err
	}
	return rdapIPResponse{}, lastErr
}

func fetchRDAPURL(client *http.Client, endpoint string) (rdapIPResponse, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return rdapIPResponse{}, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", "netscope/0.1 passive-recon")
	resp, err := doRequest(client, req)
	if err != nil {
		return rdapIPResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return rdapIPResponse{}, fmt.Errorf("unexpected status %s", resp.Status)
	}
	var decoded rdapIPResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4*1024*1024)).Decode(&decoded); err != nil {
		return rdapIPResponse{}, err
	}
	return decoded, nil
}

func addNameForIP(ipToNames map[string]map[string]bool, ip, name string) {
	if ipToNames[ip] == nil {
		ipToNames[ip] = map[string]bool{}
	}
	ipToNames[ip][name] = true
}

func addSubdomainSource(values map[string]map[string]bool, name, source string) {
	if values[name] == nil {
		values[name] = map[string]bool{}
	}
	values[name][source] = true
}

func addAddressHint(values map[string]map[string]bool, name, address string) {
	if values[name] == nil {
		values[name] = map[string]bool{}
	}
	values[name][address] = true
}

func namesForIP(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func keysOfNestedSet(values map[string]map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func rankedSubdomains(sources map[string]map[string]bool, hints map[string]map[string]bool) []string {
	names := keysOfNestedSet(sources)
	sort.SliceStable(names, func(i, j int) bool {
		left := subdomainScore(names[i], sources[names[i]], hints[names[i]])
		right := subdomainScore(names[j], sources[names[j]], hints[names[j]])
		if left == right {
			return names[i] < names[j]
		}
		return left > right
	})
	return names
}

func subdomainScore(name string, sources map[string]bool, hints map[string]bool) int {
	label := strings.Split(name, ".")[0]
	score := len(sources) * 20
	score += len(hints) * 30
	switch label {
	case "www", "api", "app", "admin", "portal", "login", "auth", "sso", "mail", "smtp", "vpn", "remote", "dev", "stage", "staging", "cdn", "static", "assets", "docs", "status", "blog", "shop", "dashboard", "git", "gitlab", "jira", "wiki":
		score += 100
	}
	if len(label) > 0 && label[0] >= '0' && label[0] <= '9' {
		score -= 30
	}
	if sources["urlscan"] {
		score += 15
	}
	if sources["hackertarget"] {
		score += 10
	}
	return score
}

func keysOfBoolMap(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value, ok := range values {
		if ok {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func splitIPVersions(addresses []string) ([]string, []string) {
	var ipv4 []string
	var ipv6 []string
	for _, address := range addresses {
		ip := net.ParseIP(address)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			ipv4 = append(ipv4, ip.String())
		} else {
			ipv6 = append(ipv6, ip.String())
		}
	}
	return uniqueSorted(ipv4), uniqueSorted(ipv6)
}

func sourceSet(values []string) map[string]bool {
	if len(values) == 0 {
		values = defaultReconSources()
	}
	out := map[string]bool{}
	for _, value := range values {
		key := strings.ToLower(strings.TrimSpace(value))
		switch key {
		case "crt.sh", "crt":
			key = "crtsh"
		case "cert-spotter", "certspotter.com":
			key = "certspotter"
		case "hacker-target", "hostsearch":
			key = "hackertarget"
		case "threat-miner":
			key = "threatminer"
		case "webarchive", "archive", "wayback-cdx":
			key = "wayback"
		case "subdomaincenter", "subdomain.center":
			key = "subdomain-center"
		case "dns", "doh", "google-dns":
			key = "dns-google"
		}
		if key != "" {
			out[key] = true
		}
	}
	return out
}

func defaultReconSources() []string {
	return []string{
		"crtsh",
		"certspotter",
		"hackertarget",
		"threatminer",
		"wayback",
		"anubis",
		"subdomain-center",
		"urlscan",
		"dns-google",
		"rdap",
	}
}

func keysOfSourceSet(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for key, enabled := range values {
		if enabled {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func reconRecordTypes(records string) []string {
	values := splitCSV(records)
	if len(values) == 0 {
		values = []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT"}
	}
	allowed := map[string]bool{"A": true, "AAAA": true, "CNAME": true, "MX": true, "NS": true, "TXT": true}
	out := make([]string, 0, len(values))
	for _, value := range values {
		key := strings.ToUpper(value)
		if allowed[key] {
			out = append(out, key)
		}
	}
	if len(out) == 0 {
		out = []string{"A", "AAAA"}
	}
	return out
}

func dnsTypeName(value int) string {
	switch value {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	default:
		return fmt.Sprintf("TYPE%d", value)
	}
}

func rootDomain(name string) string {
	parts := strings.Split(strings.TrimSuffix(name, "."), ".")
	if len(parts) < 2 {
		return name
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func positiveOrDefault(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func finalCapLabel(value int) string {
	if value <= 0 {
		return "none"
	}
	return fmt.Sprint(value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func reconSeedMessage(scope reconScope) string {
	seeds := make([]string, 0, len(scope.Seeds))
	for _, seed := range scope.Seeds {
		if seed != scope.Domain {
			seeds = append(seeds, seed)
		}
	}
	if len(seeds) == 0 {
		return ""
	}
	return fmt.Sprintf("using %s as passive recon root; seed hosts: %s", scope.Domain, strings.Join(seeds, ","))
}

func runEngine(opts cliOptions, stdout, stderr io.Writer) error {
	enginePath, err := findEngine()
	if err != nil {
		return err
	}

	payload, err := json.Marshal(opts.request)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.CommandContext(ctx, enginePath)
	cmd.Stdin = bytes.NewReader(append(payload, '\n'))
	cmd.Stderr = stderr

	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	writer, err := newCLIEventWriter(opts, stdout)
	if err != nil {
		_ = cmd.Process.Kill()
		return err
	}
	defer writer.Close()

	scanner := bufio.NewScanner(pipe)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		if err := writer.EmitRaw(scanner.Bytes()); err != nil {
			_ = cmd.Process.Kill()
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		_ = cmd.Process.Kill()
		return err
	}
	return cmd.Wait()
}

func renderEvent(stdout io.Writer, line []byte) {
	var event map[string]any
	if err := json.Unmarshal(line, &event); err != nil {
		fmt.Fprintln(stdout, string(line))
		return
	}
	fmt.Fprintln(stdout, renderEventLineFromMap(event, line))
}

func renderEventLine(line []byte) string {
	var event map[string]any
	if err := json.Unmarshal(line, &event); err != nil {
		return string(line)
	}
	return renderEventLineFromMap(event, line)
}

func renderEventLineFromMap(event map[string]any, line []byte) string {
	eventType, _ := event["type"].(string)
	switch eventType {
	case "progress":
		return fmt.Sprintf("[progress] %s", text(event, "message"))
	case "host":
		return fmt.Sprintf("[host] %-7s %-15s via %-4s %s", text(event, "state"), text(event, "resolved_ip"), text(event, "method"), text(event, "reason"))
	case "open_port":
		return fmt.Sprintf("[port] %-3s %-13s %-5s/%s %s", text(event, "state"), text(event, "resolved_ip"), number(event, "port"), text(event, "transport"), text(event, "reason"))
	case "service":
		return fmt.Sprintf("[service] %-15s %-5s/%s %-10s %s", text(event, "resolved_ip"), number(event, "port"), text(event, "transport"), text(event, "service"), text(event, "banner"))
	case "domain":
		return fmt.Sprintf("[domain] %s resolver=%s", text(event, "domain"), text(event, "resolver"))
	case "dns_record":
		return fmt.Sprintf("[dns] %-5s %-35s %s", text(event, "record_type"), text(event, "name"), text(event, "value"))
	case "subdomain":
		return fmt.Sprintf("[subdomain] %-35s v4=%s v6=%s sources=%s", text(event, "name"), text(event, "ipv4"), text(event, "ipv6"), text(event, "sources"))
	case "ip_asset":
		return fmt.Sprintf("[ip] %-39s %-35s %s", text(event, "ip"), text(event, "name"), text(event, "source"))
	case "cidr":
		return fmt.Sprintf("[cidr] %-22s %-15s %-15s %s", text(event, "cidr"), text(event, "start_address"), text(event, "end_address"), text(event, "name"))
	case "cidr_ip":
		return fmt.Sprintf("[cidr-ip] %-39s %-22s %s", text(event, "ip"), text(event, "cidr"), text(event, "source"))
	case "live_ip":
		return fmt.Sprintf("[live-ip] %-39s %-22s tcp/%-5s rtt=%sms %s", text(event, "ip"), text(event, "cidr"), number(event, "port"), number(event, "rtt_ms"), text(event, "reason"))
	case "finding":
		return fmt.Sprintf("[finding] %-8s %-15s %-5s/%s %s | fix: %s", text(event, "severity"), text(event, "resolved_ip"), number(event, "port"), text(event, "transport"), text(event, "title"), text(event, "remediation"))
	case "warning":
		return fmt.Sprintf("[warning] %s", text(event, "message"))
	case "summary":
		return fmt.Sprintf("[summary] %s", text(event, "message"))
	case "error":
		return fmt.Sprintf("[error] %s", text(event, "message"))
	default:
		return string(line)
	}
}

func eventDedupeKey(line []byte) string {
	var event map[string]any
	if err := json.Unmarshal(line, &event); err != nil {
		return ""
	}

	eventType := strings.ToLower(text(event, "type"))
	switch eventType {
	case "domain":
		return dedupeKey("domain", text(event, "domain"))
	case "subdomain":
		return dedupeKey("subdomain", text(event, "name"))
	case "dns_record":
		return dedupeKey("dns", text(event, "name"), text(event, "record_type"), text(event, "value"))
	case "ip_asset":
		return dedupeKey("ip", text(event, "ip"))
	case "cidr":
		return dedupeKey("cidr", text(event, "cidr"))
	case "cidr_ip":
		return dedupeKey("cidr-ip", text(event, "ip"))
	case "live_ip":
		return dedupeKey("live-ip", text(event, "ip"))
	case "host":
		return dedupeKey("host", firstNonEmpty(text(event, "resolved_ip"), text(event, "target")), text(event, "state"), text(event, "method"))
	case "open_port":
		return dedupeKey("port", firstNonEmpty(text(event, "resolved_ip"), text(event, "target")), number(event, "port"), text(event, "transport"), text(event, "state"))
	case "service":
		return dedupeKey("service", firstNonEmpty(text(event, "resolved_ip"), text(event, "target")), number(event, "port"), text(event, "transport"), text(event, "service"), text(event, "banner"))
	case "finding":
		return dedupeKey("finding", firstNonEmpty(text(event, "resolved_ip"), text(event, "target")), number(event, "port"), text(event, "transport"), text(event, "title"))
	default:
		return ""
	}
}

func dedupeKey(parts ...string) string {
	cleaned := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(part)), ".")
		if part != "" {
			cleaned = append(cleaned, part)
		}
	}
	if len(cleaned) <= 1 {
		return ""
	}
	return strings.Join(cleaned, "|")
}

func text(event map[string]any, key string) string {
	value, _ := event[key].(string)
	return value
}

func number(event map[string]any, key string) string {
	switch value := event[key].(type) {
	case float64:
		return fmt.Sprintf("%.0f", value)
	case string:
		return value
	default:
		return ""
	}
}

func findEngine() (string, error) {
	if value := os.Getenv("NETSCOPE_ENGINE"); value != "" {
		return value, nil
	}

	name := binaryName("netscope-engine")
	searchRoots := make([]string, 0, 12)
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exe)
		candidate := filepath.Join(dir, name)
		if fileExists(candidate) {
			return candidate, nil
		}
		searchRoots = append(searchRoots, parentDirs(dir, 4)...)
	}
	if cwd, err := os.Getwd(); err == nil {
		searchRoots = append(searchRoots, parentDirs(cwd, 4)...)
	}

	for _, root := range dedupeStrings(searchRoots) {
		devCandidates := []string{
			filepath.Join(root, "build", name),
			filepath.Join(root, "engine", "target", "release", name),
			filepath.Join(root, "engine", "target", "debug", name),
			filepath.Join(root, "target", "release", name),
			filepath.Join(root, "target", "debug", name),
		}
		for _, candidate := range devCandidates {
			if fileExists(candidate) {
				return candidate, nil
			}
		}
	}

	return "", errors.New("netscope-engine not found; set NETSCOPE_ENGINE, run from the project root, or place it beside the netscope CLI")
}

func parentDirs(start string, depth int) []string {
	var dirs []string
	current := filepath.Clean(start)
	for i := 0; i <= depth; i++ {
		dirs = append(dirs, current)
		next := filepath.Dir(current)
		if next == current {
			break
		}
		current = next
	}
	return dirs
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func binaryName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func runEgress(stdout io.Writer) error {
	fmt.Fprintf(stdout, "os=%s arch=%s\n", runtime.GOOS, runtime.GOARCH)
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		fmt.Fprintf(stdout, "public_ip=unknown reason=%s\n", err)
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
	fmt.Fprintf(stdout, "public_ip=%s\n", strings.TrimSpace(string(body)))
	return nil
}

func runDoctor(stdout io.Writer) error {
	fmt.Fprintf(stdout, "netscope=%s os=%s arch=%s\n", version, runtime.GOOS, runtime.GOARCH)
	if path, err := findEngine(); err == nil {
		fmt.Fprintf(stdout, "engine=found path=%s\n", path)
	} else {
		fmt.Fprintf(stdout, "engine=missing hint=%s\n", err)
	}
	if runtime.GOOS != "linux" {
		fmt.Fprintln(stdout, "linux=warning this project targets Linux releases; local development can still use connect scans")
	}
	if _, err := exec.LookPath("setcap"); err == nil {
		fmt.Fprintln(stdout, "setcap=available optional raw-socket capabilities can be configured on Linux")
	} else {
		fmt.Fprintln(stdout, "setcap=missing optional privileged scan setup is not available from PATH")
	}
	fmt.Fprintln(stdout, "safety=active scan commands require --ack-authorized")
	return nil
}

func printUsage(stdout io.Writer) {
	fmt.Fprintf(stdout, `netscope %s

Defensive Linux CLI scanner with passive recon.

Usage:
  netscope <command> [flags]
  netscope help [command]

Commands:
  discover    Live host discovery for owned or authorized scope
  scan        TCP/UDP scan with optional host discovery and SSH audit
  recon       Passive domain, subdomain, IP, and CIDR recon from public sources
  vuln        Remediation-first checks from live targets or prior JSONL
  egress      Show current public egress IP and runtime context
  doctor      Verify install, engine path, and optional capabilities
  self-update Placeholder command for future release updates
  version     Print version

Examples:
  netscope discover --target 192.0.2.0/24 --ack-authorized
  netscope scan --target example.com --tcp --ports 22,80,443 --ssh-audit --ack-authorized
  netscope recon --target www.arkoselabs.com --max-subdomains 100 --ack-authorized
  netscope recon --cidr_ranges --target example.com --ack-authorized
  netscope recon --cidr_ranges --live-ips --target example.com --max-live-ips 256 --ack-authorized
  netscope recon --target example.com --sources dns-google,rdap --expand-cidrs --max-cidr-ips 1024 --ack-authorized
  netscope recon --target example.com --report-out recon.txt --ack-authorized
  netscope vuln --input scan.jsonl --ack-authorized

Use "netscope help scan" or "netscope recon --help" for command-specific flags.
Active scanning is for owned or explicitly authorized assets only.
`, version)
}

func printCommandHelp(stdout io.Writer, command string) error {
	parser := newCommandParser(command)
	if parser.fs == nil {
		return fmt.Errorf("unknown help topic %q", command)
	}
	parser.fs.SetOutput(stdout)

	switch command {
	case "discover":
		fmt.Fprintf(stdout, `netscope discover

Usage:
  netscope discover --target 192.0.2.0/24 --ack-authorized [flags]

Examples:
  netscope discover --target 192.0.2.0/24 --ack-authorized
  netscope discover --target-file targets.txt --discovery-methods tcp --ack-authorized

Flags:
`)
	case "scan":
		fmt.Fprintf(stdout, `netscope scan

Usage:
  netscope scan --target example.com --ack-authorized [flags]

Examples:
  netscope scan --target example.com --tcp --ports 22,80,443 --ack-authorized
  netscope scan --target 10.0.0.5 --udp --udp-ports 53,123,161 --ack-authorized
  netscope scan --target-file targets.txt --discover-hosts --top-ports 100 --ack-authorized

Flags:
`)
	case "recon":
		fmt.Fprintf(stdout, `netscope recon

Usage:
  netscope recon --target example.com --ack-authorized [flags]

Examples:
  netscope recon --target www.arkoselabs.com --ack-authorized
  netscope recon --cidr_ranges --target example.com --ack-authorized
  netscope recon --cidr_ranges --live-ips --target example.com --live-ip-ports 80,443,22 --max-live-ips 256 --ack-authorized
  netscope recon --target example.com --sources anubis,urlscan,dns-google,rdap --max-subdomains 200 --ack-authorized
  netscope recon --target example.com --sources dns-google,rdap --records A,AAAA --expand-cidrs --max-cidr-ips 1024 --ack-authorized
  netscope recon --target example.com --report-out recon.txt --ack-authorized
  netscope recon --target example.com --report-out recon.doc --jsonl-out recon.jsonl --ack-authorized
  netscope recon --target 8.8.8.8 --max-ips 20 --ack-authorized

Flags:
`)
	case "vuln":
		fmt.Fprintf(stdout, `netscope vuln

Usage:
  netscope vuln --input scan.jsonl --ack-authorized [flags]
  netscope vuln --target example.com --ack-authorized [flags]

Examples:
  netscope vuln --input scan.jsonl --ack-authorized
  netscope vuln --target example.com --ports 22,80,443 --ack-authorized

Flags:
`)
	default:
		return fmt.Errorf("unknown help topic %q", command)
	}

	printFlagDefaults(stdout, parser.fs)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "Active scanning is for owned or explicitly authorized assets only.")
	return nil
}

func printFlagDefaults(stdout io.Writer, fs *flag.FlagSet) {
	fs.VisitAll(func(f *flag.Flag) {
		valueName, usage := flag.UnquoteUsage(f)
		if valueName != "" {
			fmt.Fprintf(stdout, "  --%s %s\n", f.Name, valueName)
		} else {
			fmt.Fprintf(stdout, "  --%s\n", f.Name)
		}
		if defaultText := flagDefaultText(f); defaultText != "" {
			fmt.Fprintf(stdout, "      %s %s\n", usage, defaultText)
		} else {
			fmt.Fprintf(stdout, "      %s\n", usage)
		}
	})
}

func flagDefaultText(f *flag.Flag) string {
	if f.DefValue == "" || f.DefValue == "false" {
		return ""
	}
	return fmt.Sprintf("(default %q)", f.DefValue)
}
