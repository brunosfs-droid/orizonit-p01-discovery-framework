# Network Discovery v0.4a — Home/LAB Validation R1

Date: 2026-09-29

## Scope

Authorized first-pass validation of the non-credentialed Network Discovery scanner on a single IPv4 /24.

## Result

- Effective IPs: 254
- Discovered assets: 9
- Duration: 20.48 s
- Execution errors: 0
- Documented limitations: 3
- Warnings: 0
- High-confidence classifications: 3
- Low-confidence classifications: 6
- SSDP responses: 0
- Credential attempts: 0

A negative run against a non-local /24 completed with zero discovered assets and no execution error.

## Functional evidence

The scanner successfully identified:
- the local gateway as a Router/Gateway with High confidence;
- two Windows hosts based on Windows-associated service combinations;
- one Network/Embedded Candidate from a management-web + SSH combination;
- HTTP/HTTPS fingerprints including TLS metadata;
- additional low-confidence assets through ICMP/ARP evidence.

JSON outputs were parseable and SHA-256 sidecars matched the generated artifacts.

## Engineering observations

1. Add a scope sanity warning when no local IPv4/default gateway falls inside the selected scope.
2. Add hostname provenance/confidence because reverse DNS may return synthetic virtualization names.
3. Surface duplicate-MAC/multi-IP identity correlations without automatically deduplicating.
4. Investigate SSDP source-interface behavior on multi-homed Windows systems.
5. Add optional vendor/OUI enrichment and identify locally administered/randomized MACs.
6. Validate discovery coverage against an independent router/AP client inventory before promotion.

Raw home-network evidence is intentionally stored outside Git because discovery artifacts are confidential.
