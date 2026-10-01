# Cancã v0.5f.0 — Optional Agent foundation

Date: 2026-10-01. Status: CANDIDATE for real P01LAB acceptance.
Baseline main: c35b3c27364dba4fb5c1e95ce3d5e29fbcd12d11, portable v0.5e.6 LAB VALIDATED.
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
validation and diff whitespace checks passed. Agent contract CI is configured for
ubuntu-latest and windows-latest / Python 3.12; its results must pass before merge.
Live authentication/upload in agent integration tests use fixtures/mocks. They
prove runtime wiring, stage gates, integrity, journaling and resume; they do not
prove real connectivity or OS service lifecycle.

## Pending real acceptance

Run [LAB_OPTIONAL_AGENT_v0.5f.0_R1.md](LAB_OPTIONAL_AGENT_v0.5f.0_R1.md) on P01-MGMT01,
starting with the completed v0.5e.6 workspace. Preserve journals/sidecars and
verify no repeated POST on completed resume. Then use a separate run for policy
progression, AUTH/FULL, resolver/export and granted mTLS upload.

Service installation and automatic schedules remain outside v0.5f.0. Schedule
descriptor is metadata only. Workspaces require local filesystem lock semantics;
network filesystem qualification and journal rotation are pending. Protect policy,
manifest/profiles and workspace with OS permissions; SHA256 is not a signature.

Next: v0.5f.0 LAB VALIDATED -> v0.5f.1 Windows Service -> v0.5f.2 Linux/systemd ->
v0.5f.3 scheduling/recovery/soak. No v0.5f.1 service is installed by this change.
