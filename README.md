# Netscope

Netscope is a Linux-first defensive scanner with a Go CLI front-end and a Rust scan engine.

This source tree is currently around `v0.3.0-beta`: a practical defensive beta for owned or explicitly authorized assets:

- live host discovery with TCP fallback probes
- passive domain/subdomain recon from public sources, with IP pool and CIDR enrichment
- target expansion for domains, IPs, IPv4/guarded IPv6 CIDRs, IPv4 ranges, and target files
- TCP connect port scanning
- UDP probe scanning for curated ports or explicit ranges
- SSH banner and safe posture reporting
- remediation-first vulnerability findings
- NDJSON IPC between the Go CLI and Rust engine

Netscope intentionally does not include IP hiding, exploit delivery, credential attacks, or live-target payload injection.

## Feature Matrix

| Capability | Status |
| --- | --- |
| Passive recon and source adapters | Complete |
| TCP/UDP scanning and live host discovery | Complete |
| Service detection | Complete |
| HTTP audit | Complete |
| TLS audit | Beta-complete, with trust/hostname checks and non-exhaustive cipher posture |
| DNS posture | Complete |
| Reports and SARIF | Complete |
| Diffing and workspace history | Complete |
| Workspace asset inventory | Complete |
| Findings lifecycle | Complete |
| IPv6 direct targets and guarded CIDRs | Complete |
| CI fail-on behavior | Complete |

## Build

Install Go 1.22+ and Rust 1.75+.

Workspace mode uses a pure-Go SQLite driver, so no system SQLite package or CGO setup is required.

```sh
mkdir -p build
cargo build --manifest-path engine/Cargo.toml --release
go build -o build/netscope ./cmd/netscope
cp engine/target/release/netscope-engine build/
```

Install it so `netscope` works from any directory:

```sh
make install
. ~/.bashrc
netscope doctor
```

Native package builds are available too:

```sh
make package-deb
sudo apt install ./dist/netscope_0.3.0-beta_amd64.deb
```

After the project is published on GitHub, users can install the release build with:

```sh
curl -fsSL https://raw.githubusercontent.com/saiyan566/netscope/main/scripts/install-release.sh | sh
```

See `docs/packaging.md` for Debian/Ubuntu and Arch local-repo setup that enables `sudo apt install netscope` or `sudo pacman -S netscope`.

See `docs/releasing.md` for the public release flow.

For development, either place `netscope-engine` next to `netscope` or set `NETSCOPE_ENGINE`:

```sh
export NETSCOPE_ENGINE="$PWD/engine/target/release/netscope-engine"
```

## Examples

```sh
netscope discover --target 192.0.2.0/24 --ack-authorized
netscope recon --target example.com
netscope recon --cidr_ranges --target example.com
netscope recon --cidr_ranges --live-ips --target example.com --live-ip-ports 80,443,22 --max-live-ips 256 --ack-authorized
netscope recon --target example.com --sources crtsh,certspotter,hackertarget,threatminer,wayback,anubis,subdomain-center,urlscan,dns-google,rdap --records A,AAAA,MX,NS,TXT
netscope recon --target example.com --source-limit 2000 --jsonl-out recon.jsonl
netscope recon --target example.com --report-out recon.txt
netscope recon --target example.com --report-out recon.doc --jsonl-out recon.jsonl
netscope recon --target example.com --source-limit 5000 --max-subdomains 1000
netscope recon --target example.com --sources dns-google,rdap --records A,AAAA --expand-cidrs --max-cidr-ips 1024
netscope recon --target 192.0.2.0/30 --expand-cidrs
netscope recon --target example.com --dedupe=false
netscope recon --target 8.8.8.8
netscope scan --target example.com --profile standard --ack-authorized
netscope scan --target example.com --tcp --ports 21,22,25,53,80,443,3306,5432,6379 --service-detect --http-audit --tls-audit --ack-authorized
netscope scan --target example.com --tcp --ports 22,80,443 --ssh-audit --ack-authorized
netscope scan --target 10.0.0.5 --udp --udp-ports 53,123,161 --ack-authorized
netscope scan --target-file targets.txt --tcp --udp --top-ports 100 --top-udp 20 --jsonl-out scan.jsonl --ack-authorized
netscope vuln --input scan.jsonl
netscope diff --old old.jsonl --new new.jsonl
netscope report --input scan.jsonl --format markdown --out report.md
netscope report --input scan.jsonl --format html --out report.html
netscope report --input scan.jsonl --format sarif --out report.sarif
netscope dns-audit --target example.com
netscope workspace init acme
netscope scan --workspace acme --target example.com --profile standard --ack-authorized
netscope workspace status acme
netscope workspace list-runs acme --target example.com --mode ACTIVE --profile standard
netscope workspace show-run acme 1 --format json
netscope workspace assets acme
netscope assets list --workspace acme
netscope assets show --workspace acme api.example.com
netscope assets history --workspace acme api.example.com
netscope workspace findings acme
netscope report --workspace acme --run 1 --format html --out report.html
netscope diff --workspace acme --old-run 1 --new-run 2 --format json
netscope sources list
netscope version
netscope doctor
netscope egress
```

## Safety Model

Netscope classifies each run as `PASSIVE`, `ACTIVE`, or `LOCAL` and prints that mode in CLI output. Passive and local-only commands do not require `--ack-authorized`; active target probes do.

`--ack-authorized` is required for `discover`, `scan`, live target vulnerability checks, and active recon such as `recon --live-ips`. It is not required for passive recon, CIDR range lookup from public DNS/RDAP, `doctor`, `egress`, or `vuln --input scan.jsonl`.

The scanner is designed for asset owners, internal security teams, and permitted assessments.

The vulnerability layer emits evidence, remediation, safe validation steps, and references. It does not provide exploit payloads or injection helpers.

`netscope recon` is passive by default. It uses public data sources such as certificate transparency, archive/search indexes, passive DNS-style APIs, public DNS resolver answers, and RDAP registration data; it does not probe target ports or web paths.

When a host such as `www.example.com` is supplied, passive recon uses the likely apex domain, for example `example.com`, as the source-query root while keeping the original host as a seed. This usually produces better subdomain coverage from public sources.

See `docs/safety-model.md` for the full passive/local/active authorization policy.

## Profiles and Config

Scan profiles provide practical defaults:

- `quick`: fast TCP scan of the most common ports
- `standard`: balanced TCP, curated UDP, and SSH posture reporting
- `deep`: broader authorized coverage
- `external`: common internet-facing services
- `internal`: private-network-friendly defaults with host discovery

Example:

```sh
netscope scan --target example.com --profile standard --ack-authorized
```

User defaults can live in `~/.config/netscope/config.toml`; CLI flags override config values. See `docs/configuration.md`.

## Reports and Diffing

JSONL remains the canonical raw event stream. Generate human and automation-friendly outputs from any scan or recon JSONL:

```sh
netscope report --input scan.jsonl --format markdown --out report.md
netscope report --input scan.jsonl --format html --out report.html
netscope report --input scan.jsonl --format csv --out report.csv
netscope report --input scan.jsonl --format sarif --out report.sarif
```

Compare two result files:

```sh
netscope diff --old old.jsonl --new new.jsonl
netscope diff --old old.jsonl --new new.jsonl --format json --out changes.json
```

`report` and `diff` are local-only commands and do not require `--ack-authorized`.

## CI Mode

Use `--quiet`, `--no-color`, machine-readable outputs, and `--fail-on` in pipelines:

```sh
netscope scan --target example.com --profile standard --jsonl-out scan.jsonl --quiet --no-color --ack-authorized
netscope vuln --input scan.jsonl --fail-on high --quiet --no-color
netscope report --input scan.jsonl --format sarif --out netscope.sarif
```

Exit code `3` means findings met the configured threshold. See `docs/ci.md`.

## Service Detection and HTTP/TLS Audits

`scan` can collect safe service metadata after an open TCP port is found:

```sh
netscope scan --target example.com --tcp --ports 21,22,25,53,80,443,3306,5432,6379 --service-detect --http-audit --tls-audit --ack-authorized
```

Current safe probes include HTTP, SSH, FTP/SMTP-style banners, DNS over TCP, Redis PING, MySQL banners, and conservative port-based identification for PostgreSQL and RDP. HTTP audit performs one normal `GET /` and extracts status, server/content headers, title, and common security headers. TLS audit performs standard client handshakes and records certificate subject, issuer, SANs, chain metadata, validity dates, expiry posture, hostname mismatch status, trust validation status, negotiated TLS version, and cipher suite. See `docs/service-detection.md` and `docs/tls-audit.md`.

## Workspaces and History

Workspace mode stores run history in a local SQLite database while preserving JSONL artifacts:

```sh
netscope workspace init acme
netscope scan --workspace acme --target example.com --profile standard --ack-authorized
netscope workspace list-runs acme --target example.com --severity high
netscope workspace show-run acme 1 --format text
netscope workspace assets acme
netscope assets list --workspace acme --type hostname
netscope assets list --workspace acme --target example.com --format json
netscope assets show --workspace acme api.example.com
netscope assets history --workspace acme api.example.com
netscope findings list --workspace acme --status open
netscope findings triage --workspace acme 1 --status acknowledged --note "Reviewed"
netscope workspace findings acme
netscope workspace list-runs acme
netscope report --workspace acme --run 1 --format html --out report.html
netscope diff --workspace acme --old-run 1 --new-run 2
```

Asset inventory is populated from successful workspace runs and tracks concrete hostnames, IPv4 addresses, and IPv6 addresses with first/last seen timestamps, root-target observations, and lightweight `latest_observed_services` summaries when structured service events are available. DNS CNAME/provider relationship hostnames remain in recon output and artifacts, but are not stored as first-class inventory assets unless independently discovered as scoped assets. DNS audit inventory deliberately stores only the audited root domain, not MX/NS/CNAME providers or DNS-referenced A/AAAA output. Old runs are not backfilled automatically.

Persistent findings track logical findings across successful workspace runs, support manual triage statuses, and mark a manually resolved finding as `regressed` if the same fingerprint appears again. Netscope does not auto-resolve findings just because they are absent from a later run. Old runs are not backfilled automatically.

See `docs/workspaces.md`, `docs/asset-inventory.md`, and `docs/findings-lifecycle.md`.

## Passive Source Adapters

Passive recon sources are modular adapters and can be listed with:

```sh
netscope sources list
```

Use `--sources` per run or `enabled_passive_sources` in config. See `docs/recon-sources.md`.

## DNS Posture

Passive DNS posture uses public resolver data and does not require `--ack-authorized`:

```sh
netscope dns-audit --target example.com
```

It collects common DNS records, summarizes SPF/DMARC/CAA/mail/name-server posture, and emits remediation-first findings for missing defensive records.

## Current Limits

The v1 engine uses portable TCP-based host discovery fallback. The CLI exposes ARP and ICMP discovery controls, but privileged Linux raw-packet probes should be added as a dedicated backend before claiming full ARP/ICMP coverage.

UDP scanning is best effort. A response means `open`; no response may mean open, filtered, dropped, or rate-limited, so quiet UDP ports are not emitted by default.

Full UDP port ranges are streamed through worker indexes instead of pre-building all target-port jobs, which keeps scheduler memory stable. Very large host expansions are still guarded and should be split into smaller authorized scopes.

Passive recon depends on third-party public services and may be rate-limited or return partial historical data.

Subdomain recon emits IPv4 and IPv6 separately in text output and as `ipv4`/`ipv6` fields in JSONL.

IPv6 addresses and small IPv6 CIDRs are supported for target expansion and TCP/UDP scans where the host network supports IPv6. Huge IPv6 CIDRs are rejected by guardrails; provide explicit IPv6 targets or small authorized ranges.

TLS audit performs browser-inspired trust checks with bundled Mozilla roots, but it is not a full browser validation engine. Cipher posture is based on the negotiated cipher from one safe handshake and does not exhaustively enumerate every protocol/cipher combination.

`--source-limit` controls how many results Netscope asks each passive source for when that source supports sizing. It defaults to `500`, and Netscope keeps extra results if a source returns more. `--max-subdomains` is a separate final cap after all sources are merged and deduped; `0` means no final cap.

Domain-to-CIDR recon works by resolving discovered hostnames to IPv4/IPv6 with public DNS and then querying RDAP for the owning ranges. `--expand-cidrs` streams individual IPs from those discovered ranges or from direct CIDR targets. Expansion is capped per range by `--max-cidr-ips` to avoid accidentally dumping enormous cloud or IPv6 allocations; raise it when the authorized range is small enough for your report.

For a cleaner bug-bounty style CIDR-only view, use `netscope recon --cidr_ranges --target example.com`. This focused passive mode runs only the work needed for CIDR range discovery: public DNS `A,AAAA` resolution for the target/seed host and RDAP range lookup. It does not run the broad passive subdomain collectors unless you use default recon.

To actively identify responsive IPs from those ranges, add `--live-ips`. Netscope expands each discovered CIDR up to `--max-live-ips` candidates per range and checks TCP liveness on `--live-ip-ports` only. This is active traffic, so keep it to owned or explicitly in-scope ranges.

Readable reports can be saved with `--report-out recon.txt` or `--report-out recon.doc`. The `.doc` output is plain text with a Word-friendly extension, while `--jsonl-out` keeps raw machine-readable events.

Duplicate domains, subdomains, DNS records, IPs, CIDRs, ports, services, and findings are removed by default across merged sources and streamed events. Use `--dedupe=false` when you need to inspect repeated evidence from different sources.

## Contributing

Contributions are welcome when they preserve Netscope's defensive scope. Read `CONTRIBUTING.md` and `SECURITY.md` before opening issues or pull requests.

## License

Netscope is licensed under the Apache License 2.0. See `LICENSE` and `NOTICE`.
