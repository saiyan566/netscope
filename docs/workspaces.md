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
netscope assets list --workspace acme
netscope assets show --workspace acme api.example.com
netscope assets history --workspace acme api.example.com
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

Migration version `2` adds Asset Inventory v1:

- `assets`
- `asset_run_observations`
- `asset_service_observations`

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

Successful workspace runs populate the persistent asset inventory from structured JSONL events. The inventory tracks concrete hostnames, IPv4 addresses, and IPv6 addresses with first/last seen metadata and distinct run observations. Service observations are exposed as `latest_observed_services` when structured service events are available.

`workspace assets` is a compatibility alias for the persistent inventory list. `workspace findings` still reads JSONL artifacts from stored runs and dedupes findings. If a JSONL artifact has been moved or deleted, Netscope skips that artifact instead of failing the whole workspace summary.

DNS audit inventory stores only the audited root domain, not external MX/NS/CNAME providers or DNS-referenced A/AAAA answers. Old runs are not backfilled automatically. See `asset-inventory.md`.
