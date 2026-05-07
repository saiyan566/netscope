# Contributing to Netscope

Thanks for helping make Netscope useful and safe.

## Project Goals

Netscope is a Linux-first defensive CLI for authorized scanning and passive recon. Contributions should preserve these boundaries:

- Defensive and authorized-use workflows only
- No IP hiding, evasion, exploit delivery, payload injection, credential attacks, or post-auth actions
- Clear output, safe defaults, low memory use, and bounded concurrency
- Useful evidence, remediation, and validation guidance for findings

## Development Setup

Install:

- Go 1.22 or newer
- Rust 1.76 or newer
- `make`

Build and test:

```sh
make build
make test
```

Install locally:

```sh
make install
netscope doctor
```

## Pull Request Checklist

Before opening a pull request:

- Run `gofmt` on Go files.
- Run `cargo fmt --manifest-path engine/Cargo.toml` on Rust files.
- Run `make test`.
- Add or update tests for changed behavior.
- Update `README.md`, `docs/`, or `CHANGELOG.md` when CLI behavior changes.
- Keep safety wording accurate when adding active behavior.

## Code Style

- Keep changes small and scoped.
- Prefer existing patterns over new abstractions.
- Stream large target sets instead of materializing them in memory.
- Make output machine-readable first, then render readable CLI text from events.
- Keep text output stable enough for users to read and copy into reports.

## Security-Sensitive Contributions

Do not add exploit strings, weaponized payloads, stealth, evasion, credential attacks, or instructions that enable unauthorized access.

Safe probe templates are welcome when they:

- Are non-destructive
- Do not bypass authentication
- Include evidence and remediation
- Explain false positives and safe validation steps

## Issue Triage

Useful bug reports include:

- Command run
- Expected behavior
- Actual output
- OS/distro and architecture
- Whether WSL, container, VM, or bare metal
- `netscope doctor` output

Please remove sensitive domains, tokens, internal IPs, and customer data before posting logs.
