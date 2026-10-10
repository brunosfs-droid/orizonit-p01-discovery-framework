# Cancã v0.6.80 — E0 / EVE-NG operational evidence gate

Status: **planned / human evidence required**. This document is a reproducible acceptance contract, NOT evidence that E0 was run.

## Preconditions
- Pin the exact tested `main` SHA, version, EVE-NG topology export and UTC timestamps.
- Record tester, target hosts (P01-DC01, P01-MGMT01, P01-W11-01, Linux), addresses, scope, authorized credential/profile identifiers **without passwords or tokens**.
- Identify isolated lab routes, DNS, time sync, and active firewall restrictions. Do not probe outside 192.168.100.0/24 without explicit authorization.
- Confirm backup/rollback snapshots; make sure approval is documented before any scanner invocation.

## Acceptance matrix
| Gate | Validation | Evidence | PASS condition |
| --- | --- | --- | --- |
| E0-01 | Offline collector packaging and import | archive digest, import logs, source commit | Signed/hashed artifact traced to tested commit and no import errors |
| E0-02 | Windows auth-only WinRM profiles for P01-DC01 / MGMT01 / W11-01 | profile IDs, redacted connection results, server timestamps | Correct target identity; no credential or raw token disclosure |
| E0-03 | Linux authenticated access | redacted SSH output, detected OS and host identity | Identity and privilege consistent with approved scope |
| E0-04 | Unauthorized/unreachable endpoints | sanitized timeout, denial, and retry logs | Fail closed; no credential leakage or cross-target fallback |
| E0-05 | Workspace A/B isolation and stale generation | sanitized API/SQL evidence | No history from A visible under B, no stale token accepted |
| E0-06 | Cancel/drain/lease and coordinator fence (R02) | timeline and request correlation IDs | In-flight cancellation respected; no execution after drain |
| E0-07 | Evidence import and source reconciliation (R05/R06) | sanitized before/after row counts, fingerprints | Deterministic reconciliation and no unauthorized overwrites |
| E0-08 | Evidence durability and same-cluster recovery (T13) | backup manifest and restore logs | Verified restore and correct lease reset; do not infer cross-cluster readiness |
| E0-09 | Audit trail and secret redaction | sanitized event logs and HTTP audit | Denial and admission events correlate; no secrets in logs |
| E0-10 | Rollback and repeatability | rollback log, second-run fingerprints | Environment restored, second pass reproducible without ghost jobs |

## Execution and adjudication
1. Capture repository SHA and 8 CI results. Record test operator and authorized scope.
2. Run baseline network, time, DNS and profile health checks from the lab **manually**.
3. Execute E0-01 through E0-10 with the existing project procedures; record command versions and redacted stdout/stderr. Do not invent outcomes.
4. For every gate record `PASS / FAIL / BLOCKED / NOT RUN`, environment version, UTC timestamp, evidence URI and issue/PR ID where applicable.
5. Stop on scope expansion, credential exposure, uncontrolled write, stale lease execution or missing rollback path. Record an incident before resuming.
6. Only declare **E0 passed** if all required gates have reviewed evidence and no critical failures or blockers remain. CI green alone is insufficient.

## Outstanding Alpha blockers
- R01–R06 are partially qualified. R02 adapters, drain and benchmarks remain open.
- E0 human-run lab evidence, T13/R20 cross-cluster restore, maker/checker separation and R06 full operational recovery remain open.
- No EVE-NG commands or real environment acceptance executed as part of v0.6.80.

## Evidence record template
| Field | Value |
| --- | --- |
| Gate ID / result | E0-XX / NOT RUN |
| Commit and workflow links | pending |
| Operator / execution UTC | pending |
| Target / scope | pending |
| Evidence URI / SHA-256 digest | pending |
| Redaction review | pending |
| Finding / follow-up PR | pending |
