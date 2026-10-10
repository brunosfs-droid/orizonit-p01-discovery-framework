# Cancã v0.6.85 — deterministic verified E0 evidence snapshot

This release adds an **offline reproducible snapshot fingerprint** for an E0 evidence set that has already passed the structural, independent reviewer and local byte-verification gates introduced in v0.6.82–v0.6.84.

## Contract
- Run the new `E0_EVIDENCE_SNAPSHOT_v0.6.85.py` with a *private* JSON register and restricted local evidence directory.
- The utility invokes v0.6.84's actual SHA-256 byte verification for all ten `PASS` gates before emitting `snapshot_sha256`.
- The snapshot includes the **entire register**, especially exact release commit, topology digest, approved scope, operator, UTC execution date, independent security/release reviewers, gate evidence URI, file digest, review timestamp and reviewer.
- Canonical serialization is UTF-8 JSON with sorted keys, compact separators and gates sorted by gate ID. It is domain-separated as `canca-e0-verified-snapshot-v1` to avoid conflating hashes of unrelated objects.
- The printed result contains **only** the fingerprint and sanitized counts/errors, not credential values, private reviewer names, paths, URIs or file contents.
- The snapshot hash will change if any protected value, evidence byte digest or approval reference changes. A different JSON gate order produces the same digest.
- On missing, tampered, blocked or invalid evidence, the fingerprint is withheld and the process remains `NO_GO`/`INVALID`.

## Usage

```bash
python docs/validation/E0_EVIDENCE_SNAPSHOT_v0.6.85.py \
  --check /path/to/private/e0-register.json \
  --evidence-root /srv/canca-e0-evidence
```

Exit codes: `0` for `SNAPSHOT_READY`; `1` for `NO_GO`; `2` for `INVALID`. **All results include `operational_go: false`.** The exit 0 means only that synthetic or authentic bytes match the supplied register, not that the scanner was authorized, that E0 is operationally accepted or that signatories are trustworthy.

Store the printed digest in an independently approved, access-controlled release record along with the candidate commit and reviewer decision. A digest alone is neither a digital signature nor proof of origin; trusted identity attestation and external timestamping remain separate requirements.

## Test coverage
The existing `tests/test_e0_artifact_integrity.py` covers canonical ordering, repeatability, digest changes after release/topology/reviewer/scope modifications, matching changed evidence bytes, missing/tampered files and CLI output redaction. Standard Python CI runs the synthetic-file tests without touching EVE-NG.

## Remaining blockers
Checked-in register still contains ten `NOT RUN` entries. E0 evidence collection, R02/R06 operational closure, cross-cluster T13/R20 recovery and trusted maker/checker identity verification remain open. No Alpha sign-off is implied.
