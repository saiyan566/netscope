# Netscope Safety Model

Netscope is a defensive scanner for owned assets, internal security programs, and explicitly authorized assessments. The CLI classifies each run before it starts:

- `PASSIVE`: reads public data sources such as certificate transparency, archive/search indexes, public DNS, and RDAP.
- `LOCAL`: reads local files or inspects the local environment only.
- `ACTIVE`: sends packets or protocol requests to target-owned infrastructure.

Only `ACTIVE` runs require `--ack-authorized`.

## No Authorization Acknowledgment Required

These commands are passive or local-only:

```sh
netscope recon --target example.com
netscope recon --cidr-ranges --target example.com
netscope vuln --input scan.jsonl
netscope doctor
netscope egress
netscope workspace status acme
netscope report --workspace acme --run 1 --format html --out report.html
netscope diff --workspace acme --old-run 1 --new-run 2
```

Passive recon may query third-party public services and public resolvers, but it does not probe target ports, crawl target websites, fuzz paths, authenticate, or send exploit payloads.

## Authorization Acknowledgment Required

These commands actively touch target infrastructure:

```sh
netscope discover --target 192.0.2.0/24 --ack-authorized
netscope scan --target 10.0.0.5 --tcp --ports 22,80,443 --ack-authorized
netscope recon --cidr-ranges --live-ips --target example.com --ack-authorized
netscope vuln --target example.com --ports 80,443 --ack-authorized
```

The same rule applies to future active modules, including service detection, HTTP/TLS audits, DNS active validation, and any feature that connects directly to target systems.

## Implementation Notes

The Go CLI owns the safety gate in `cmd/netscope/safety.go`. New commands should add a policy branch there instead of scattering ad hoc `--ack-authorized` checks throughout command handlers.

Every run emits a `mode` event. Text output shows it as:

```text
[mode] PASSIVE passive recon uses public sources, public DNS, archive indexes, certificate transparency, and RDAP
```

JSONL output preserves the same event for automation:

```json
{"type":"mode","mode":"PASSIVE","message":"passive recon uses public sources, public DNS, archive indexes, certificate transparency, and RDAP"}
```
