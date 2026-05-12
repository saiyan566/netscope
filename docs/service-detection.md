# Service Detection and Audits

Service detection is an active scan feature and requires `--ack-authorized`.

```sh
netscope scan --target example.com --tcp --ports 21,22,25,53,80,443,3306,5432,6379 --service-detect --http-audit --tls-audit --ack-authorized
```

Current safe probes:

- SSH banner parsing
- HTTP `HEAD /` for service detection
- HTTP `GET /` for posture audit when `--http-audit` is enabled
- FTP/SMTP/POP/IMAP-style banner reads
- DNS over TCP query for `example.com`
- MySQL/MariaDB initial handshake banner
- Redis `PING`
- conservative port-based PostgreSQL and RDP identification
- TLS handshake and X.509 metadata parsing for common TLS ports

HTTP audit extracts:

- status code
- server header
- content type
- page title from the first response body
- Strict-Transport-Security
- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

Limits:

- No crawling
- No fuzzing
- No authentication
- No credential attacks
- No exploit payloads
- TLS cipher posture is based on the negotiated cipher from one safe client handshake, not exhaustive cipher enumeration.
