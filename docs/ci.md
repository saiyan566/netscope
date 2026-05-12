# CI Usage

Netscope supports deterministic output and policy-oriented exit behavior for automation.

## Exit Codes

- `0`: command completed successfully and no `--fail-on` threshold was met
- `1`: operational error, invalid input, missing engine, or scan failure
- `3`: findings met or exceeded the configured `--fail-on` threshold

## Examples

```sh
netscope scan --target example.com --profile standard --jsonl-out scan.jsonl --quiet --no-color --ack-authorized
netscope vuln --input scan.jsonl --fail-on high --quiet --no-color
netscope report --input scan.jsonl --format sarif --out netscope.sarif
```

`--fail-on` accepts:

- `low`
- `medium`
- `high`
- `critical`

## GitHub Actions Sketch

```yaml
name: netscope

on:
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Netscope
        run: curl -fsSL https://raw.githubusercontent.com/saiyan566/netscope/main/scripts/install-release.sh | sh
      - name: Scan authorized target
        run: netscope scan --target example.com --profile standard --jsonl-out scan.jsonl --quiet --no-color --ack-authorized
      - name: Evaluate findings
        run: netscope vuln --input scan.jsonl --fail-on high --quiet --no-color
      - name: SARIF report
        if: always()
        run: netscope report --input scan.jsonl --format sarif --out netscope.sarif
```

Only run active scans in CI against assets your organization owns or has explicit permission to test.

## Local Formatting Tools

Repository CI installs the stable Rust toolchain with the `rustfmt` component and runs:

```sh
cargo fmt --manifest-path engine/Cargo.toml -- --check
```

If local `cargo fmt` is unavailable, install Rust through `rustup` and add the formatter:

```sh
rustup component add rustfmt
```
