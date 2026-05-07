# Netscope Engine IPC

The Go CLI starts `netscope-engine`, writes one JSON request to stdin, and reads newline-delimited JSON events from stdout.

## Request

```json
{
  "command": "scan",
  "targets": ["192.0.2.10", "example.com", "198.51.100.0/30"],
  "target_file": "",
  "excludes": ["198.51.100.2"],
  "tcp": true,
  "udp": false,
  "ports": "22,80,443",
  "udp_ports": "53,123,161",
  "top_ports": 100,
  "top_udp": 20,
  "discover_hosts": false,
  "skip_host_discovery": false,
  "discovery_methods": ["arp", "icmp", "tcp"],
  "tcp_ping_ports": "22,80,443,445,3389",
  "rate": 0,
  "concurrency": 256,
  "timeout_ms": 900,
  "memory_budget_mb": 150,
  "ssh_audit": true,
  "input_file": ""
}
```

## Events

Common event types are `progress`, `domain`, `dns_record`, `subdomain`, `ip_asset`, `cidr`, `host`, `open_port`, `service`, `finding`, `warning`, `summary`, and `error`.

Passive recon is handled in the Go CLI because it uses public HTTPS sources instead of the Rust scan engine.

Recon command shape:

```json
{
  "command": "recon",
  "targets": ["example.com"],
  "subdomains": true,
  "sources": "crtsh,certspotter,hackertarget,threatminer,wayback,anubis,subdomain-center,urlscan,dns-google,rdap",
  "records": "A,AAAA,CNAME,MX,NS,TXT",
  "source_limit": 500,
  "max_subdomains": 0,
  "max_ips": 200,
  "timeout_ms": 900
}
```

DNS record event:

```json
{
  "type": "dns_record",
  "domain": "example.com",
  "name": "example.com",
  "record_type": "MX",
  "value": "10 mail.example.com",
  "ttl": 3600
}
```

Subdomain event:

```json
{
  "type": "subdomain",
  "domain": "example.com",
  "name": "www.example.com",
  "addresses": "93.184.216.34",
  "ipv4": "93.184.216.34",
  "ipv6": "2606:2800:220:1:248:1893:25c8:1946",
  "cnames": [],
  "sources": "crtsh,wayback,dns-google"
}
```

IP asset event:

```json
{
  "type": "ip_asset",
  "ip": "93.184.216.34",
  "name": "www.example.com",
  "source": "dns-google"
}
```

CIDR event:

```json
{
  "type": "cidr",
  "cidr": "93.184.216.0/24",
  "name": "EXAMPLE-NET",
  "country": "US",
  "start_address": "93.184.216.0",
  "end_address": "93.184.216.255",
  "source": "rdap.org"
}
```

Host event:

```json
{
  "type": "host",
  "target": "192.0.2.10",
  "resolved_ip": "192.0.2.10",
  "state": "up",
  "method": "tcp",
  "rtt_ms": 12,
  "reason": "tcp/22 accepted connection"
}
```

Open port event:

```json
{
  "type": "open_port",
  "target": "example.com",
  "resolved_ip": "93.184.216.34",
  "port": 443,
  "transport": "tcp",
  "state": "open",
  "reason": "connect accepted",
  "service": "https",
  "banner": ""
}
```

Finding event:

```json
{
  "type": "finding",
  "target": "192.0.2.10",
  "resolved_ip": "192.0.2.10",
  "port": 22,
  "transport": "tcp",
  "severity": "info",
  "title": "SSH administration surface detected",
  "evidence": "SSH is reachable on this target.",
  "remediation": "Limit SSH exposure with firewall rules.",
  "safe_validation": "Confirm SSH is reachable only from approved administration networks.",
  "references": ["https://www.cisa.gov/resources-tools/resources/securing-remote-access"]
}
```
