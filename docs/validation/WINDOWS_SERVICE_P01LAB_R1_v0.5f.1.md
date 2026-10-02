# Cancã — Windows Service v0.5f.1 / P01LAB R1 acceptance

Status: LAB VALIDATED for manual service lifecycle and preserved review gate.
Operator date: 2026-10-01 (-03); source filename uses 2026-10-02.
Node: P01-MGMT01, Windows Server 2022; Python 3.13 / pywin32 312.
Tested main: `3ddea991f80ed2a7380cd2e5765eecfebf9e1334` (PR #90).
Refs Issue #83; foundation v0.5f.0 Windows R1 remains a separate acceptance.

The operator supplied `image(20261002-002654).png` showing the fast-forward to
PR #90, successful pywin32 312 installation, and the real SCM helper invocation:
`python tests/windows_service_scm_smoke.py --lab-root "C:\Canca\service-lab" --node-id "P01-MGMT01"`.
Original capture SHA256:
`99ff6fcda20d3f6efbf7699f9a73540c86422ab99653588d03b741470a03476a`.

| Visible result | Value |
| --- | --- |
| status / service_version | WINDOWS SCM SMOKE PASS / 0.5f.1 |
| starts / one_invocation_per_start | 4 / true |
| policy_denied_starts / review_required_starts | 2 / 2 |
| idle_repeat / automatic_recovery_enabled | false / false |
| source_state_unchanged / intent_preserved | true / true |
| lock_reacquired / service_removed | true / true |
| journal_audit | JOURNAL AUDIT PASS; 7 journals |
| sha256_valid / contract_fields_valid | true / true |

This closes the R1 lifecycle gates: test-owned native registration, manual starts,
one policy-gated invocation per start, stop/restart, refusal to remove while
running, preserved pre-dispatch intent, no replay after an abrupt idle-host exit,
released native lock, sanitized hash-valid journals, removal preserving state.
The tested code checks LocalService, service SID, exact registration, manual start
and empty recovery actions before returning PASS. These are code-linked helper
assertions; the capture is a summary, not a separate SCM configuration export.

The bottom is cropped: fixture UUID/path, evidence_retained and final shell exit
are not visible. Do not report a captured exit 0 or invent the fixture path.
The explicit --lab-root mode retains a new fixture by implementation; the
operator can locate it locally. Raw journals/proof JSON were not independently
uploaded/reviewed in this acceptance. The screenshot and its hash are retained
in the separate v0.5f.1 evidence archive; the v0.5f.0 archive stays unchanged.

Limits: all-denied offline fixture; no service-account live AUTH/FULL/upload,
no mid-stage cancellation/POST recovery, no automatic scheduler, recovery or
long-duration soak. Idle observation windows belong to this helper run. Abrupt
SCM-host termination happens while idle; the intent comes from a separate real
pre-dispatch child process. Keep the running intent for review.

Next component: v0.5f.2 Linux/systemd candidate, with native CI and a separate
Rocky Linux P01-LNX-RKY01 LAB gate. Scheduling/recovery/soak remains v0.5f.3.
