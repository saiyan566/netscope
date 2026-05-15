# Asset Inventory v1

Netscope workspaces maintain a persistent inventory of concrete assets observed across successful runs. The inventory is separate from raw JSONL artifacts and run history, so users can answer when an asset was first seen, when it was last seen, which runs observed it, which root target it appeared under, and which recent observations or service summaries are available.

## Scope

Tracked assets:

- hostnames and domains observed through passive recon, active recon, active scan, or safe DNS root-target handling
- IPv4 addresses observed or scanned
- IPv6 addresses observed or scanned

Not tracked as inventory assets:

- CIDR or range inputs themselves
- target files
- URLs with paths
- raw banners
- report strings
- file paths
- arbitrary metadata strings
- external DNS provider references such as MX, NS, or CNAME targets
- DNS-referenced A/AAAA addresses from DNS posture output unless they are independently discovered or scanned through recon or scan events

## Commands

```sh
netscope assets list --workspace acme
netscope assets list --workspace acme --target example.com
netscope assets list --workspace acme --type hostname
netscope assets list --workspace acme --type ipv4
netscope assets list --workspace acme --type ipv6
netscope assets list --workspace acme --format json

netscope assets show --workspace acme api.example.com
netscope assets show --workspace acme 1
netscope assets show --workspace acme --format json api.example.com

netscope assets history --workspace acme api.example.com
netscope assets history --workspace acme 1
```

The legacy `netscope workspace assets acme` command lists the same persistent inventory in text form.

## Workspace Selection

For the top-level `assets` command, workspace selection is deterministic:

- explicit `--workspace` wins
- otherwise `NETSCOPE_WORKSPACE` is used
- otherwise Netscope uses the only local workspace if exactly one exists
- if multiple workspaces exist and none is selected, Netscope returns an actionable error asking for `--workspace` or `NETSCOPE_WORKSPACE`

## Normalization

Hostnames are trimmed, lowercased, and stripped of a trailing dot. IPv4 and IPv6 addresses are canonicalized with Go's `net/netip`; equivalent IPv6 spellings dedupe to the same key, and IPv4-mapped IPv6 addresses dedupe to their IPv4 key.

Stable keys are type-aware:

```text
hostname:api.example.com
ipv4:203.0.113.10
ipv6:2001:db8::1
```

## Observation Counts

Inventory ingestion happens when a workspace run finishes successfully. Duplicate raw events inside one run, root target, and source stage do not inflate `observation_count`. A later successful run creates a new distinct observation and advances `last_seen_at`, `last_seen_run_id`, and `observation_count`.

## Service Summaries

When structured `service` events are available, Netscope records lightweight historical service observations for the corresponding asset. Output uses the name `latest_observed_services` to avoid implying a fresh live scan or current-state guarantee.

## DNS Audit Guard

`dns-audit` has intentionally narrow inventory semantics. A command such as:

```sh
netscope dns-audit --workspace acme --target example.com
```

may store `example.com` as the audited root domain. It must not store MX provider domains, NS hosts, CNAME provider targets, CDN references, or A/AAAA addresses that appear only in DNS posture records.

## Backfill

Asset Inventory v1 does not automatically backfill old workspace runs. New successful workspace runs populate the inventory going forward.
