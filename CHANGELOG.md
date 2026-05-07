# Changelog

All notable changes to Netscope will be documented in this file.

This project uses pre-1.0 semantic versioning. Breaking changes may occur in minor releases until `1.0.0`.

## [0.1.0] - 2026-05-07

### Added

- Go CLI front-end and Rust scan engine.
- Linux-first install flow with local user PATH support.
- `discover`, `scan`, `recon`, `vuln`, `egress`, `doctor`, `self-update`, `help`, and `version` commands.
- Authorized-use gate with `--ack-authorized`.
- TCP connect scanning, UDP probe scanning, and SSH banner/posture audit.
- Passive recon from public sources.
- DNS enrichment with IPv4 and IPv6 output.
- RDAP IP/CIDR enrichment.
- Focused `--cidr-ranges` / `--cidr_ranges` recon mode.
- CIDR expansion with `--expand-cidrs` and `--max-cidr-ips`.
- Live IP discovery from CIDR candidates with `--live-ips`.
- Readable report output with `--report-out`.
- Raw JSONL output with `--jsonl-out`.
- Default deduplication across merged recon and scan events.
- Debian package generation and local apt repo helper.
- Arch package helper and local pacman repo helper.

### Security

- No exploit delivery, payload injection, credential attacks, post-auth actions, or IP hiding/evasion features.
- Active behaviors are scoped behind explicit authorization acknowledgement.
