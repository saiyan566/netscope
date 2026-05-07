# Netscope

Netscope is a Linux-first defensive scanner with a Go CLI front-end and a Rust scan engine.

This source tree implements a practical v1 MVP for owned or explicitly authorized assets:

- live host discovery with TCP fallback probes
- passive domain/subdomain recon from public sources, with IP pool and CIDR enrichment
- target expansion for domains, IPs, IPv4 CIDRs, IPv4 ranges, and target files
- TCP connect port scanning
- UDP probe scanning for curated ports or explicit ranges
- SSH banner and safe posture reporting
- remediation-first vulnerability findings
- NDJSON IPC between the Go CLI and Rust engine

Netscope intentionally does not include IP hiding, exploit delivery, credential attacks, or live-target payload injection.

## Build

Install Go 1.22+ and Rust 1.76+.

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
sudo apt install ./dist/netscope_0.1.0_amd64.deb
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
netscope recon --target example.com --ack-authorized
netscope recon --cidr_ranges --target example.com --ack-authorized
netscope recon --cidr_ranges --live-ips --target example.com --live-ip-ports 80,443,22 --max-live-ips 256 --ack-authorized
netscope recon --target example.com --sources crtsh,certspotter,hackertarget,threatminer,wayback,anubis,subdomain-center,urlscan,dns-google,rdap --records A,AAAA,MX,NS,TXT --ack-authorized
netscope recon --target example.com --source-limit 2000 --jsonl-out recon.jsonl --ack-authorized
netscope recon --target example.com --report-out recon.txt --ack-authorized
netscope recon --target example.com --report-out recon.doc --jsonl-out recon.jsonl --ack-authorized
netscope recon --target example.com --source-limit 5000 --max-subdomains 1000 --ack-authorized
netscope recon --target example.com --sources dns-google,rdap --records A,AAAA --expand-cidrs --max-cidr-ips 1024 --ack-authorized
netscope recon --target 192.0.2.0/30 --expand-cidrs --ack-authorized
netscope recon --target example.com --dedupe=false --ack-authorized
netscope recon --target 8.8.8.8 --ack-authorized
netscope scan --target example.com --tcp --ports 22,80,443 --ssh-audit --ack-authorized
netscope scan --target 10.0.0.5 --udp --udp-ports 53,123,161 --ack-authorized
netscope scan --target-file targets.txt --tcp --udp --top-ports 100 --top-udp 20 --jsonl-out scan.jsonl --ack-authorized
netscope vuln --input scan.jsonl --ack-authorized
netscope doctor
netscope egress
```

## Safety Model

Active commands require `--ack-authorized`. The scanner is designed for asset owners, internal security teams, and permitted assessments.

The vulnerability layer emits evidence, remediation, safe validation steps, and references. It does not provide exploit payloads or injection helpers.

`netscope recon` is passive by default. It uses public data sources such as certificate transparency, archive/search indexes, passive DNS-style APIs, public DNS resolver answers, and RDAP registration data; it does not probe target ports or web paths.

When a host such as `www.example.com` is supplied, passive recon uses the likely apex domain, for example `example.com`, as the source-query root while keeping the original host as a seed. This usually produces better subdomain coverage from public sources.

## Current Limits

The v1 engine uses portable TCP-based host discovery fallback. The CLI exposes ARP and ICMP discovery controls, but privileged Linux raw-packet probes should be added as a dedicated backend before claiming full ARP/ICMP coverage.

UDP scanning is best effort. A response means `open`; no response may mean open, filtered, dropped, or rate-limited, so quiet UDP ports are not emitted by default.

Full UDP port ranges are streamed through worker indexes instead of pre-building all target-port jobs, which keeps scheduler memory stable. Very large host expansions are still guarded and should be split into smaller authorized scopes.

Passive recon depends on third-party public services and may be rate-limited or return partial historical data.

Subdomain recon emits IPv4 and IPv6 separately in text output and as `ipv4`/`ipv6` fields in JSONL.

`--source-limit` controls how many results Netscope asks each passive source for when that source supports sizing. It defaults to `500`, and Netscope keeps extra results if a source returns more. `--max-subdomains` is a separate final cap after all sources are merged and deduped; `0` means no final cap.

Domain-to-CIDR recon works by resolving discovered hostnames to IPv4/IPv6 with public DNS and then querying RDAP for the owning ranges. `--expand-cidrs` streams individual IPs from those discovered ranges or from direct CIDR targets. Expansion is capped per range by `--max-cidr-ips` to avoid accidentally dumping enormous cloud or IPv6 allocations; raise it when the authorized range is small enough for your report.

For a cleaner bug-bounty style CIDR-only view, use `netscope recon --cidr_ranges --target example.com --ack-authorized`. This focused mode runs only the work needed for CIDR range discovery: public DNS `A,AAAA` resolution for the target/seed host and RDAP range lookup. It does not run the broad passive subdomain collectors unless you use default recon.

To actively identify responsive IPs from those ranges, add `--live-ips`. Netscope expands each discovered CIDR up to `--max-live-ips` candidates per range and checks TCP liveness on `--live-ip-ports` only. This is active traffic, so keep it to owned or explicitly in-scope ranges.

Readable reports can be saved with `--report-out recon.txt` or `--report-out recon.doc`. The `.doc` output is plain text with a Word-friendly extension, while `--jsonl-out` keeps raw machine-readable events.

Duplicate domains, subdomains, DNS records, IPs, CIDRs, ports, services, and findings are removed by default across merged sources and streamed events. Use `--dedupe=false` when you need to inspect repeated evidence from different sources.

## Contributing

Contributions are welcome when they preserve Netscope's defensive scope. Read `CONTRIBUTING.md` and `SECURITY.md` before opening issues or pull requests.

## License

Netscope is licensed under the Apache License 2.0. See `LICENSE` and `NOTICE`.
