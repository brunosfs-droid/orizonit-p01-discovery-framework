# Multi-target Executor P01LAB AUTH R1 — v0.4b.5

Date: 2026-09-30

## Result

Multi-target AUTH-only completed successfully across the five currently planned P01LAB assets.

- actions total: 5
- ready: 5
- completed: 5
- skipped: 0
- authentication successes: 5
- authentication failures: 0
- open credential circuits: 0
- concurrency: 1

Targets:

1. P01-DC01 — WinRM / domain profile
2. P01-MGMT01 — WinRM / local profile
3. P01-W11-01 — WinRM / domain workstation profile
4. Ubuntu — SSH
5. Rocky — SSH

## Shared credential identity

P01-DC01 and P01-W11-01 used the same hashed credential identity and accumulated two successes while the circuit remained closed.

## Integrity

- job SHA256 passed;
- each target result matched its own SHA256 sidecar;
- each target result matched the SHA256 recorded in the job;
- every target result carried the reviewed Credential Plan digest.

## Secret hygiene

No password, raw secret reference or credential locator was persisted in target evidence.

## Decision

v0.4b.5 is LAB VALIDATED for multi-target AUTH-only.

Next gate: sequential multi-target full enrichment using the same reviewed plan and unchanged profiles.
