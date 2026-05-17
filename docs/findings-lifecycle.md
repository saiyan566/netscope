# Findings Lifecycle v1

Netscope workspaces maintain persistent logical findings across successful runs. A finding is identified by a stable fingerprint built from a machine finding code, normalized target identity, and transport/port when relevant. Severity, title wording, evidence, timestamps, and run IDs do not define identity.

## Statuses

- `open`: newly observed and not triaged
- `acknowledged`: reviewed but not otherwise classified
- `accepted-risk`: intentionally accepted for now
- `false-positive`: reviewed and considered not actionable
- `resolved`: manually marked remediated
- `regressed`: previously resolved, then observed again

Netscope does not auto-resolve findings that are absent from later runs. A later run may be partial, timed out, or have different target coverage, so absence is left for a future Security Diff Intelligence Layer.

## Commands

```sh
netscope findings list --workspace acme
netscope findings list --workspace acme --severity high
netscope findings list --workspace acme --status open
netscope findings list --workspace acme --status regressed
netscope findings list --workspace acme --target example.com
netscope findings list --workspace acme --asset api.example.com
netscope findings list --workspace acme --format json

netscope findings show --workspace acme 1
netscope findings show --workspace acme <fingerprint>
netscope findings history --workspace acme 1

netscope findings triage --workspace acme 1 --status acknowledged --note "Reviewed"
netscope findings triage --workspace acme 1 --status accepted-risk --note "Accepted for now"
netscope findings triage --workspace acme 1 --status false-positive --note "Expected behavior"
netscope findings triage --workspace acme 1 --status resolved --note "Remediated"
netscope findings triage --workspace acme 1 --status open --note "Reopened manually"
```

Workspace selection follows the asset inventory behavior: `--workspace`, then `NETSCOPE_WORKSPACE`, then the only local workspace if exactly one exists.

## Asset Linkage

Findings link to Asset Inventory records when a matching asset already exists. Netscope does not create synthetic assets only to force a finding link. DNS posture findings link to the audited root-domain asset when present, and DNS provider or CNAME relationship hosts are not created as assets.

## Backfill

Findings Lifecycle v1 does not backfill old workspace runs. New successful workspace runs populate persistent findings going forward.
