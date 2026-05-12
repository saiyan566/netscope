# TLS Audit

TLS audit is an active scan feature and requires `--ack-authorized`.

```sh
netscope scan --target example.com --tcp --ports 443,8443 --tls-audit --ack-authorized
```

The Rust engine performs a standard TLS client handshake and records defensive metadata:

- certificate subject
- issuer
- subject alternative names
- not-before and not-after validity dates
- days until expiry
- expired / expiring-soon status
- self-signed indicator
- hostname checked and hostname mismatch indicator
- trust validation status using bundled Mozilla roots through rustls
- certificate chain length
- certificate chain subjects and issuers
- negotiated TLS version
- negotiated cipher suite

Findings are remediation-first and currently include:

- expired certificate
- certificate expiring within 30 days
- self-signed certificate indicator
- hostname mismatch
- trust validation failure
- legacy TLS protocol negotiated, where detectable

Safety boundaries:

- no exploit payloads
- no credential attempts
- no brute force
- no crawling
- no post-authentication actions

Limitations:

- Netscope performs one permissive handshake to collect certificate metadata, then a second verifying handshake against bundled Mozilla roots to report basic trust status.
- Trust validation is browser-inspired, not a full browser validation engine. It does not model every platform trust store, enterprise root, revocation policy, or browser-specific rule.
- Cipher posture is based on the negotiated cipher suite from one safe handshake, not exhaustive cipher enumeration.
- Protocol posture is based on the negotiated version from the standard handshake. Exhaustive protocol/cipher enumeration is intentionally deferred for safety and noise control.
