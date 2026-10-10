# Cancã v0.6.82 — machine-checkable E0 evidence and GO/NO-GO gate

Extends [E0 acceptance requirements](E0_OPERATIONAL_ACCEPTANCE_v0.6.80.md) and the [human register](E0_EVIDENCE_REGISTER_v0.6.81.md) with:

- `E0_EVIDENCE_REGISTER_v0.6.82.json`: ten E0-01…E0-10 rows, initially `NOT RUN`; no fabricated lab results
- `E0_EVIDENCE_CHECK_v0.6.82.py`: standalone **offline** verifier; reads JSON, never probes lab hosts and never fetches evidence
- `tests/test_e0_evidence_gate.py`: fail-closed unit tests for empty evidence, duplicates, invalid timestamps/hashes, malformed structures and CLI exit codes
- Python CI structural validation of this checked-in register, explicitly permitting its genuine NO-GO operational status

## Run

From repository root:

```bash
python docs/validation/E0_EVIDENCE_CHECK_v0.6.82.py --check docs/validation/E0_EVIDENCE_REGISTER_v0.6.82.json
```

**Exit codes:** `0` = reviewed operational GO; `1` = structurally valid but NO-GO (current default); `2` = INVALID evidence/register. No secrets or raw evidence URI values are included in the JSON stdout summary.

To validate **structure only** in CI (not an operational sign-off):

```bash
python docs/validation/E0_EVIDENCE_CHECK_v0.6.82.py --check docs/validation/E0_EVIDENCE_REGISTER_v0.6.82.json --allow-no-go
```

The `--allow-no-go` flag returns exit 0 for a valid register that still has a NO-GO verdict; the verdict does **not** change to GO.

## Real EVE-NG evidence process

1. An authorized operator pins the tested 40-hex `release_commit`, approved scope, EVE-NG topology SHA-256, identity and UTC execution timestamp.
2. Execute E0 gates using the v0.6.80 procedure; store sanitized evidence in restricted storage with independently computed SHA-256, timestamp and reviewer for every PASS.
3. Record non-passing gates as FAIL, BLOCKED or NOT RUN. Missing PASS evidence, bad hash, non-UTC timestamps, duplicate/missing gate IDs and malformed structures are rejected.
4. A GO verdict requires **all ten PASS**, complete evidence metadata and both security and release reviewers. It is a machine-checked completeness decision, not a substitute for checking evidence authenticity or manually assessing R02/R06/T13/R20.
5. No implementation of this version executes WinRM/SSH/SNMP scans, restores infrastructure or approves Alpha.

Outstanding E0, R02/R06, cross-cluster recovery T13/R20 and maker/checker gates remain OPEN.
