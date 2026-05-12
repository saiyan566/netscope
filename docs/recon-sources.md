# Passive Source Adapters

Passive recon sources are represented as adapters in the Go CLI.

Adapter contract:

```go
type passiveSourceAdapter interface {
    Name() string
    Category() string
    Fetch(client *http.Client, domain string, sourceLimit int) (passiveSourceResult, error)
}
```

Built-in adapters currently include:

- `crtsh`
- `certspotter`
- `hackertarget`
- `threatminer`
- `wayback`
- `anubis`
- `subdomain-center`
- `urlscan`

Public DNS (`dns-google`) and RDAP (`rdap`) are enrichment sources handled separately because they produce DNS/IP/CIDR events, not only subdomain candidates.

List adapters:

```sh
netscope sources list
```

Use selected sources for a run:

```sh
netscope recon --target example.com --sources crtsh,certspotter,urlscan,dns-google,rdap
```

Configure defaults:

```toml
enabled_passive_sources = ["crtsh", "certspotter", "anubis", "urlscan", "dns-google", "rdap"]
```

## Adding a Source

1. Implement a function that returns `passiveSourceResult`.
2. Register it in `builtInPassiveSources()`.
3. Give it a stable name and category.
4. Add a small unit test that verifies it appears in `defaultReconSources()`.

Individual source failures are isolated. Netscope reports warnings for failing sources and continues with data returned by other adapters.
