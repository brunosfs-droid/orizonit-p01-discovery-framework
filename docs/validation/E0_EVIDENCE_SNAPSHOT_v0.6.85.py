#!/usr/bin/env python3
"""Create a reproducible digest of verified, offline E0 evidence and its metadata.

The snapshot fingerprint is for change detection, NOT a digital signature or
operational approval. No evidence bytes or private metadata are printed.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "e0_artifact_check_v084", BASE / "E0_EVIDENCE_ARTIFACT_CHECK_v0.6.84.py"
)
ARTIFACTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ARTIFACTS)

DOMAIN = b"canca-e0-verified-snapshot-v1\x00"


def snapshot(document, evidence_root):
    """Return (valid, verified, sanitized report). Never claim operational GO."""
    valid, verified, evidence = ARTIFACTS.verify(document, evidence_root)
    report = {
        "register_valid": valid,
        "artifacts_verified": verified,
        "verified_artifacts": evidence["verified_artifacts"],
        "artifact_errors": evidence["artifact_errors"],
        "operational_go": False,
    }
    if not verified:
        return valid, False, report
    # Canonicalize by gate ID so equivalent register row ordering does not
    # alter the fingerprint. Include all registration metadata; do not publish it.
    try:
        canonical = dict(document)
        canonical["gates"] = sorted(document["gates"], key=lambda x: x["gate_id"])
        payload = json.dumps(
            canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        report["artifact_errors"].append("register cannot be canonicalized")
        return False, False, report
    report["snapshot_sha256"] = hashlib.sha256(DOMAIN + payload).hexdigest()
    return True, True, report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Fingerprint reviewed E0 evidence offline")
    parser.add_argument("--check", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        document = json.loads(args.check.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        print(json.dumps({"verdict": "INVALID", "operational_go": False,
                          "error": type(exc).__name__}))
        return 2
    valid, verified, report = snapshot(document, args.evidence_root)
    print(json.dumps({"verdict": "SNAPSHOT_READY" if verified
                      else "NO_GO" if valid else "INVALID", **report},
                     sort_keys=True))
    return 0 if verified else 1 if valid else 2


if __name__ == "__main__":
    raise SystemExit(main())
