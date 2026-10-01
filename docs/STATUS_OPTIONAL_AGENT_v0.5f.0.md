# Cancã v0.5f.0 — Optional Agent foundation

Date: 2026-10-01. Status: CANDIDATE; partial Windows P01LAB evidence reviewed.
Baseline main: c35b3c27364dba4fb5c1e95ce3d5e29fbcd12d11, portable v0.5e.6 LAB VALIDATED.
Foundation merged in PR #84: b85746a38295def054a3822fb152086fae9ef3b2.
Tracking: Issue #83. Runtime engine version/schema remain v0.5e.6 / v0.5e.

## Implemented

- Cross-platform agent doctor/status/run-once/validate-policy.
- Strict versioned policy bound to assessment/run/node identity.
- Independent grants, default-deny; one checkpoint per invocation.
- Canonical runtime functions reused, including scopes, profile drift checks,
  sequential execution, credential budgets, strict SSH and mTLS.
- Shared OS lock with portable mutation functions; process/thread exclusion and
  release on crash, without deleting/replacing the retained lock inode.
- State/config/artifact/target/journal integrity gates.
- Sanitized JSON/SHA256 journal and persisted dispatch intent, blocking replay
  after interruption even before an upload checkpoint.
- No prompt providers for unattended AUTH/FULL; upload transport invocation-only.
- Windows/Linux CI workflow and real LAB procedure.

## Automated validation

Local Linux / Python 3.12: **170 tests passed**, including 25 agent tests and
145 existing regression tests. Python compilation, JSON syntax, default policy
validation and diff whitespace checks passed. Agent contract CI passed on
ubuntu-latest and windows-latest / Python 3.12 before PR #84 merged.
Live authentication/upload in agent integration tests use fixtures/mocks. They
prove runtime wiring, stage gates, integrity, journaling and resume; they do not
prove real connectivity or OS service lifecycle.

## Real LAB evidence and remaining acceptance

[23 Windows screenshots reviewed](validation/OPTIONAL_AGENT_P01LAB_R1_v0.5f.0.md):
offline doctor/status, completed-resume with unchanged state and two matching
journal hashes; default-deny; one-stage progression through discovery, planning,
dry-run, AUTH, FULL, resolver and export; separate AUTH/FULL/upload grants;
transport_required without mTLS inputs; agent/portable workspace_busy and release.
New run resolver: 5 network assets + 5 FULL observations -> 5 logical assets,
0 unresolved/ambiguous/conflicts. FULL: 5/5 completed/collected, 5 authentication
successes, 0 failures/circuits. Granted agent upload: HTTP 201/imported,
semantic_match=true, node P01-MGMT01, mTLS and TLS server verification true.
Repeat without transport inputs: already_complete; upload attempts=1. All eight
runtime artifact references, including receipt, exist and match their hashes;
next_action=complete. No service or schedule installed per doctor.

Invalid policy and identity mismatch failed closed with exit 2; all 17 new-run
journals shown match their SHA256 sidecars. Still pending: independent server
POST check; journal content/sanitization audit; tamper and interruption/review gates.
Security flags in runtime status do not replace review of agent journal content.
Follow the corrected
[LAB procedure](LAB_OPTIONAL_AGENT_v0.5f.0_R1.md); retain CANDIDATE until closure.

Service installation and automatic schedules remain outside v0.5f.0. Schedule
descriptor is metadata only. Workspaces require local filesystem lock semantics;
network filesystem qualification and journal rotation are pending. Protect policy,
manifest/profiles and workspace with OS permissions; SHA256 is not a signature.

Next: v0.5f.0 LAB VALIDATED -> v0.5f.1 Windows Service -> v0.5f.2 Linux/systemd ->
v0.5f.3 scheduling/recovery/soak. No v0.5f.1 service is installed by this change.
