# Workspaces

Netscope workspaces persist local scan/recon history in SQLite. They are additive: JSONL files and one-off commands still work exactly as before.

Default storage:

```text
~/.local/share/netscope/workspaces/<name>/workspace.db
~/.local/share/netscope/workspaces/<name>/runs/run-000001.jsonl
```

Override the root with:

```sh
export NETSCOPE_WORKSPACE_DIR=/path/to/workspaces
```

## Commands

```sh
netscope workspace init acme
netscope workspace status acme
netscope workspace list
netscope workspace list-runs acme
netscope workspace list-runs acme --target example.com --mode ACTIVE --profile standard
netscope workspace list-runs acme --severity high --since 2026-05-01 --until 2026-05-31
netscope workspace show-run acme 1
netscope workspace show-run acme 1 --format json
netscope workspace assets acme
netscope workspace findings acme
```

Persist a run:

```sh
netscope scan --workspace acme --target example.com --profile standard --ack-authorized
netscope recon --workspace acme --target example.com
netscope dns-audit --workspace acme --target example.com
```

Generate a report from a stored run:

```sh
netscope report --workspace acme --run 1 --format html --out report.html
```

Compare stored runs:

```sh
netscope diff --workspace acme --old-run 1 --new-run 2
```

## SQLite Schema

Migration version `1` creates:

- `schema_migrations`
- `runs`

The `runs` table stores:

- run id
- command
- safety mode
- scan profile
- target input
- start and finish timestamps
- status
- summary
- finding count
- maximum finding severity
- JSONL artifact path
- report artifact path

The raw JSONL artifact remains the source of truth for detailed reports and diffs.

`workspace assets` and `workspace findings` read the JSONL artifacts from stored runs, dedupe them, and print the current local inventory. If a JSONL artifact has been moved or deleted, Netscope skips that artifact instead of failing the whole workspace summary.
