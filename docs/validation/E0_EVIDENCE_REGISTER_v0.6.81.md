# E0 evidence register — Cancã v0.6.81

**Operational result: NOT RUN.** This register implements the [v0.6.80 acceptance matrix](E0_OPERATIONAL_ACCEPTANCE_v0.6.80.md); it does not assert EVE-NG execution.

## Identification
- Release / main commit: **to be pinned by test operator**
- Topology export / SHA-256: **NOT RECORDED**
- Lab operator / UTC execution date: **NOT RECORDED**
- Scope approval reference: **NOT RECORDED**
- Test evidence directory (restricted): **NOT RECORDED**
- Credential material: **never store passwords, tokens or private keys in this document**

## Operational gates
| Gate | Description | Result | Evidence URI | Evidence SHA-256 | Reviewer | Issue / remark |
| --- | --- | --- | --- | --- | --- | --- |
| E0-01 | Offline package and import | NOT RUN | — | — | — | — |
| E0-02 | Windows WinRM authorized profiles | NOT RUN | — | — | — | — |
| E0-03 | Linux authorized SSH collection | NOT RUN | — | — | — | — |
| E0-04 | Denied/unreachable endpoints fail closed | NOT RUN | — | — | — | — |
| E0-05 | Workspace scope and stale generation | NOT RUN | — | — | — | — |
| E0-06 | Coordinator cancel/drain/lease (R02) | NOT RUN | — | — | — | — |
| E0-07 | Import/reconciliation (R05/R06) | NOT RUN | — | — | — | — |
| E0-08 | Same-cluster recovery (T13) | NOT RUN | — | — | — | — |
| E0-09 | HTTP audit and secret redaction | NOT RUN | — | — | — | — |
| E0-10 | Rollback and reproducibility | NOT RUN | — | — | — | — |

## Review and exit criteria
Only mark a gate PASS after actual execution, immutable/redacted evidence, a digest and reviewer sign-off. Mark FAIL for a reproducible defect; BLOCKED for an unmet prerequisite; leave NOT RUN until attempted. Never infer successful EVE-NG execution from green CI.

**Stop immediately** for unexpected external probing, secret exposure, unexplained writes, lost cancellation fences or an invalid rollback path.

The Alpha remains blocked on E0, R02/R06, cross-cluster restoration T13/R20 and maker/checker operational evidence. Do not close these gaps by editing only the register.

## Sign-off
| Field | Value |
| --- | --- |
| Evidence reviewer / UTC | PENDING |
| Security review | PENDING |
| Go/no-go recommendation | NO-GO — evidence not collected |
