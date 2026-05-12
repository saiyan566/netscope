# DNS Posture

`dns-audit` is passive. It queries public DNS resolver data and does not require `--ack-authorized`.

```sh
netscope dns-audit --target example.com
netscope dns-audit --target example.com --records A,AAAA,MX,NS,TXT,CAA --jsonl-out dns.jsonl
```

The module collects:

- A / AAAA
- CNAME
- MX
- NS
- TXT
- CAA
- `_dmarc.<domain>` TXT

It summarizes:

- SPF presence
- DMARC policy
- CAA presence
- name-server count
- mail-exchanger count

It emits remediation-first findings for missing SPF, DMARC, and CAA records. These are posture indicators, not proof of compromise or takeover.

Current limits:

- DNSSEC and wildcard detection are not implemented yet.
- DKIM selector discovery is intentionally not brute-forced.
- Dangling CNAME/subdomain takeover checks are limited to safe DNS evidence in this version.
