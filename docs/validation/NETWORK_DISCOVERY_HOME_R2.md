# Network Discovery v0.4.1 — Home/LAB Validation R2

Date: 2026-09-29

## Result

The same authorized IPv4 /24 used in R1 was scanned after the v0.4.1 corrections.

Sanitized metrics:
- 254 effective IPs
- 9 discovered endpoints
- 0 execution errors
- 3 documented limitations
- 20.44 s duration
- 3 High-confidence classifications
- 6 Low-confidence classifications
- 7 unique MACs observed
- 1 same-MAC/multiple-IP correlation
- 0 SSDP responders
- 0 credential attempts

## Improvements confirmed

v0.4.1 correctly:
- recognized the local IPv4 and default gateway inside the selected scope;
- used local execution-host identity instead of a synthetic reverse-DNS name;
- labeled locally administered MAC addresses;
- surfaced same-MAC/multiple-IP identity hints;
- retained the R1 discovery/classification coverage with no regression.

## Identity model

The scan still reports IP endpoints. One logical device can appear on more than one IP. v0.4.1 surfaces this as an identity correlation but deliberately does not auto-merge the records. Definitive deduplication remains the responsibility of Asset Resolver v0.4c.

## SSDP

The run returned zero SSDP responders. This does not establish a scanner defect because the ground-truth inventory does not guarantee that a known device should answer M-SEARCH. SSDP remains best-effort and should later be validated against a known responder.

## Decision

**Network Discovery v0.4.1 core non-credentialed discovery is LAB VALIDATED for the current home/LAB scenario.**

This is not equivalent to production certification. Routed networks, VLANs, corporate devices and credentialed protocols still require their own validation matrix.

Raw residential network data remains in protected private legacy storage evidence storage and is intentionally not committed to Git.
