# Security Policy

Netscope is a defensive scanner for owned assets, internal security work, and explicitly authorized assessments.

## Supported Versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

Pre-1.0 releases may change CLI flags, output schema, and packaging details. Security fixes should be applied from the newest release.

## Reporting Vulnerabilities

Please do not open public issues for exploitable vulnerabilities in Netscope itself.

Until a project security contact is configured, send reports privately to:

- GitHub Security Advisories after the repository is published
- Or the maintainer email listed in the repository profile

Include:

- Netscope version and commit, if known
- Operating system and architecture
- A clear reproduction path
- Impact
- Whether the issue affects local use, package installation, update flow, or scanner output

We aim to acknowledge reports within 7 days after the project has a public maintainer channel.

## Authorized Use Boundary

Netscope intentionally does not include:

- IP hiding or evasion features
- Exploit delivery
- Payload injection helpers
- Credential attacks
- Post-authentication actions

Active modes such as port scanning, live host discovery, UDP probing, SSH audit, and `--live-ips` must only be used against assets you own or are explicitly authorized to assess.

## Safe Research

If you are testing Netscope behavior:

- Prefer loopback, lab networks, RFC 5737 example ranges, or your own infrastructure.
- Keep rates and CIDR expansion caps conservative.
- Do not run broad scans against public third-party ranges unless they are explicitly in scope.
