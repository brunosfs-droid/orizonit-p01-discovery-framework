# Cancã v0.6.87 — strict, bounded E0 JSON intake

## Threat addressed

Python's default JSON parser silently keeps the **last** value of repeated object keys and accepts the non-standard numeric constants `NaN`, `Infinity` and `-Infinity`. An E0 register could therefore be interpreted differently by a reviewer, an import process and a verifier. A very large register can also waste memory before gate checks run.

## Implementation

- The common E0 verifier `E0_EVIDENCE_CHECK_v0.6.82.py` now exposes `load_register(path)`, with a 1 MiB byte limit and strict UTF-8 JSON parsing.
- Its `strict_json_loads(raw)` rejects duplicate keys in **any nested object**, as well as non-finite constants. Error messages do not repeat untrusted key names or values.
- All three supported command-line entrypoints use this shared loader: the evidence register checker (v0.6.82), local byte-integrity checker (v0.6.84) and verified/pinned snapshot checker (v0.6.85/v0.6.86).
- Invalid records fail as `INVALID`, exit code `2`, before local artifact reads or generation/comparison of fingerprints. Structural CI still accepts the genuine, checked-in `NOT RUN` register and never claims EVE-NG execution.
- Files greater than 1 MiB, invalid UTF-8 and excessive JSON nesting fail closed.

## Reproducible regression coverage

`tests/test_e0_evidence_gate.py` checks duplicate top-level and nested keys, `NaN`/`Infinity`, oversized input and redacted error output. `tests/test_e0_artifact_integrity.py` checks that all three CLI entrypoints reject duplicate keys, non-finite values, and oversized records with exit code `2` without showing private paths.

## Operational boundaries

Existing v0.6.82–v0.6.86 evidence fingerprints retain their canonicalization and all original CLI interfaces. This is input-security hardening, **not** proof of genuine lab execution, trusted approvals or completeness of E0. The ten checked-in E0 gates remain `NOT RUN`; EVE-NG, R02/R06, T13/R20 and Alpha homologation remain open.
