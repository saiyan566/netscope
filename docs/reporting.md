# Reporting and Diffing

Netscope keeps JSONL as the canonical raw event stream. Reports and diffs are local-only commands, so they do not require `--ack-authorized`.

## Reports

```sh
netscope report --input scan.jsonl --format text --out report.txt
netscope report --input scan.jsonl --format markdown --out report.md
netscope report --input scan.jsonl --format html --out report.html
netscope report --input scan.jsonl --format csv --out report.csv
netscope report --input scan.jsonl --format sarif --out report.sarif
```

Supported formats:

- `text`: compact readable report
- `json`: structured summary with raw events
- `jsonl`: canonical event stream copy
- `markdown`: GitHub/internal documentation friendly
- `html`: simple client/demo friendly HTML
- `csv`: spreadsheet-friendly assets, services, and findings
- `sarif`: CI/security tooling ingestion for findings

Reports include an executive summary, discovered assets, exposed services, findings, evidence, and remediation where those fields are present in the input events.

## Diff

```sh
netscope diff --old old.jsonl --new new.jsonl
netscope diff --old old.jsonl --new new.jsonl --format json --out changes.json
```

Diff categories:

- `assets_added`
- `assets_removed`
- `ports_opened`
- `ports_closed`
- `services_changed`
- `findings_added`
- `findings_resolved`
- `tls_changed`
- `dns_changed`

The diff engine is deterministic: it normalizes scan/recon events into stable keys before comparing result files.
