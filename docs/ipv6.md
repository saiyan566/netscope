# IPv6

Netscope supports IPv6 as a first-class target where practical:

- direct IPv6 targets, for example `2001:db8::10`
- domain resolution to IPv4 and IPv6
- small IPv6 CIDRs, for example `2001:db8::/126`
- IPv6 scan result fields in JSONL and reports
- TCP and UDP scans over IPv6 when the host network supports IPv6

Guardrails intentionally reject huge IPv6 CIDRs:

```sh
netscope scan --target 2001:db8::/126 --tcp --ports 80,443 --ack-authorized
```

Avoid naive scanning of large IPv6 allocations. For internet-facing work, prefer passive recon, explicit IPv6 addresses discovered from DNS, or small authorized lab ranges.
