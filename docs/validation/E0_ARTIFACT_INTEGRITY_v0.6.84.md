# Cancã v0.6.84 — offline integrity verification for E0 artifacts

This gate complements the structured E0 register validator introduced in v0.6.82 and the independent reviewer checks in v0.6.83.

## Functional change

The new `E0_EVIDENCE_ARTIFACT_CHECK_v0.6.84.py` validates **actual local bytes** for every `PASS` E0 gate:
- Uses the existing structural/reviewer validator first; any incomplete, invalid, FAIL/BLOCKED/NOT RUN record prevents artifact verification and remains NO-GO.
- Accepts only references of the form `evidence://local/E0-01/report.txt`, stored relative to an explicitly supplied evidence root. Replace the gate ID for each individual gate and compute the SHA-256 from its file.
- Rejects remote URLs, embedded queries or percent escapes, dot-segments, path traversal, a reference under a different gate, duplicate paths and symlinks.
- Opens paths component-by-component using directory descriptors with `O_NOFOLLOW` to prevent following symbolic links; verifies regular files using a 64 MiB per-artifact limit.
- Streams SHA-256 using constant-time digest comparison, and outputs only sanitized gate IDs and error categories, never private evidence contents or paths.

## Usage

1. Keep the source artifact directory **outside the Git repository** and restrict filesystem permissions. E.g. `/srv/canca-e0-evidence/E0-01/report.txt`.
2. Pin the actual release SHA, topology digest and sign-offs, then set each gate to PASS only when a reviewer has signed verified lab evidence.
3. Run from the repository root:

```bash
python docs/validation/E0_EVIDENCE_ARTIFACT_CHECK_v0.6.84.py \
  --check /path/to/private/e0-register.json \
  --evidence-root /srv/canca-e0-evidence
```

Exit codes: `0` = `ARTIFACTS_VERIFIED` (all ten files matched); `1` = `NO_GO` (incomplete evidence, inaccessible or mismatching files); `2` = `INVALID` (invalid schema or unsafe artifact reference). The output always includes `operational_go: false` because hash matching does not establish that the lab was run safely or that a reviewer is trustworthy.

CI discovers `tests/test_e0_artifact_integrity.py` and exercises synthetic files in temporary directories, including tampering, missing/large files, path traversal, remote URI rejection and symlink denial. No CI task accesses the real laboratory.

## Boundaries

The checked-in E0 register remains ten times `NOT RUN`; do not fabricate approvals. This increment verifies local artifacts only. It does **not** attest evidence authenticity, establish a cryptographic identity of human signatories, validate the topology against the real EVE-NG environment, perform recovery or close E0/R02/R06/T13/R20/Alpha acceptance.
