# Cancã v0.6.86 — pinned reference comparison for E0 evidence snapshots

This increment extends the offline E0 snapshot generator introduced in v0.6.85 with a **second, independently approved SHA-256 fingerprint** against which the newly verified snapshot can be compared. It detects substituted evidence or changed release metadata between human review and release assessment.

## How it works

1. Independently review the E0 register and all ten actual laboratory evidence files. Obtain a complete v0.6.85 snapshot, then pin its `snapshot_sha256` in a separate access-controlled approval/release record, with provenance and reviewer sign-off.
2. During a later E0 recheck, supply that exact pinned 64-character lowercase hexadecimal value using `--expected-sha256` to the existing snapshot CLI.
3. The CLI re-verifies the ten local evidence files using the v0.6.84 read-only, symlink-safe byte checks, recomputes the full canonical register fingerprint, then compares it to the pinned value with `hmac.compare_digest`.
4. Any changes to the release SHA, topology, scope approval, reviewers, declared artifact hashes, evidence bytes or gate results cause mismatch, invalidity or NO-GO. The program does not silently re-pin a changed digest.

Example:

```bash
python docs/validation/E0_EVIDENCE_SNAPSHOT_v0.6.85.py \
  --check /path/to/restricted/e0-register.json \
  --evidence-root /srv/canca-e0-evidence \
  --expected-sha256 <64-hex-digest-from-separate-approved-record>
```

## Verdict contract

| Verdict | CLI exit | Meaning |
| --- | --- | --- |
| `SNAPSHOT_MATCH` | 0 | Locally verified evidence matches the independently supplied digest |
| `SNAPSHOT_MISMATCH` | 1 | Evidence/register verified, but the snapshot differs from the pinned digest |
| `NO_GO` | 1 | Gates incomplete, blocked or local evidence has missing/altered files |
| `INVALID` | 2 | Invalid pin syntax, malformed register or unsafe artifact reference |

The original no-pin behavior remains backward compatible: `SNAPSHOT_READY` is emitted only after the ten files match the register. An invalid pin is rejected before any artifact reading. On mismatch, the recalculated digest is withheld from output to reduce accidental replacement of the approved reference. The output **always contains `operational_go: false`**.

## Security boundaries and tests

- Store the pinned hash **outside** the evidence register and under an independently controlled approval process; supplying an untrusted digest derived from the same changed register provides no authenticity.
- A SHA-256 match detects modifications relative to the supplied pin, but does not establish who created the evidence, identity attestation, real EVE-NG execution or release authorization. A trusted signature or approved external record remains required for authenticity.
- Existing `tests/test_e0_artifact_integrity.py` now covers valid pin, changed metadata/approval, file tampering, invalid length/case/characters, incomplete gates and CLI exit/redaction behavior.
- This is local, offline and synthetic CI test coverage. E0 gates remain `NOT RUN`; R02/R06, T13/R20 and operational Alpha sign-off remain open.
