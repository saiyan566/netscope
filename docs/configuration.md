# Configuration

Netscope reads an optional user config from:

```text
~/.config/netscope/config.toml
```

Set `NETSCOPE_CONFIG=/path/to/config.toml` to use a different file.

Supported keys:

```toml
default_profile = "standard"
timeout_ms = 1200
concurrency = 128
memory_budget_mb = 150
enabled_passive_sources = ["crtsh", "certspotter", "anubis", "urlscan", "dns-google", "rdap"]
default_format = "text"
default_report_out = "netscope-report.txt"
```

CLI flags override config values. Scan profiles fill in sensible defaults, then config values can tune resource limits such as timeout, concurrency, and memory budget.

## Scan Profiles

Use profiles to select practical defaults:

```sh
netscope scan --target example.com --profile quick --ack-authorized
netscope scan --target example.com --profile standard --ack-authorized
netscope scan --target example.com --profile deep --ack-authorized
netscope scan --target example.com --profile external --ack-authorized
netscope scan --target 10.0.0.0/24 --profile internal --ack-authorized
```

- `quick`: fast TCP scan of the most common ports with lower memory/concurrency defaults.
- `standard`: balanced TCP plus curated UDP and SSH posture reporting.
- `deep`: broader authorized TCP/UDP coverage; slower and noisier.
- `external`: common internet-facing services.
- `internal`: private-network-friendly defaults with host discovery.

Profiles do not remove the safety model. `scan` is active traffic and still requires `--ack-authorized`.
