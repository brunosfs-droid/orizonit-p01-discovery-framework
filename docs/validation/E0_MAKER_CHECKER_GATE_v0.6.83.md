# Cancã v0.6.83 — E0 maker/checker and validator output hardening

This increment hardens the offline E0 register machine-check introduced in v0.6.82. It **does not** run EVE-NG and does **not** certify the authenticity of evidence artifacts.

## Separation of duties

For a complete E0 acceptance candidate, three globally declared identities must be distinct after trimming whitespace and Unicode case-folding:
- `operator`: executes lab tasks and creates the original evidence;
- `security_reviewer`: reviews scope, controls, redaction and security;
- `release_reviewer`: approves the delivery gate independently.

Each E0 gate marked `PASS` must also name an `evidence reviewer` different from the `operator`. The same independent gate reviewer may sign multiple gates, but cannot sign their own execution.

Equality checks use `.strip().casefold()` to prevent evasion by letter case or surrounding whitespace. Duplicate actors produce `INVALID`, never `GO`. A register with all gates `NOT RUN` remains a structurally valid **NO_GO** when sign-offs are unfilled.

## Error-output hardening

- Well-formed IDs (`E0-01`…`E0-10`) are safe to include in diagnostics.
- Malformed IDs are replaced by positional markers such as `gate[1]`; the checker must not print arbitrary identifier values, which may contain secrets.
- No credential, evidence URI or reviewer name is included in the final JSON diagnostics.

## CI and operational state

- Existing `tests/test_e0_evidence_gate.py` expanded with reviewer independence/casefold, secret identifier redaction and valid independent sign-offs.
- Existing Python CI discovers and runs those tests. Remaining required workflows must pass before merge.
- The register `E0_EVIDENCE_REGISTER_v0.6.82.json` remains ten times `NOT RUN`; no lab result or sign-off was manufactured.
- E0 operational acceptance, R02/R06, cross-cluster T13/R20 and maker/checker **identity verification** against a trusted authorization source remain open. String equality checks are not identity attestation.

## Usage

```bash
python docs/validation/E0_EVIDENCE_CHECK_v0.6.82.py --check docs/validation/E0_EVIDENCE_REGISTER_v0.6.82.json
```

Expected result until actual lab evidence is reviewed: `NO_GO`, exit code `1`. The `--allow-no-go` flag may only be used by CI for structure checks and does not represent a human approval.
