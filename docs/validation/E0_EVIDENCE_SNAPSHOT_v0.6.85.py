#!/usr/bin/env python3
"""Create a reproducible digest of verified, offline E0 evidence and its metadata.

The snapshot fingerprint is for change detection, NOT a digital signature or
operational approval. No evidence bytes or private metadata are printed.
"""
import argparse
import hashlib
import hmac
import importlib.util
import json
import re
from pathlib import Path

BASE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "e0_artifact_check_v084", BASE / "E0_EVIDENCE_ARTIFACT_CHECK_v0.6.84.py"
)
ARTIFACTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ARTIFACTS)

DOMAIN = b"canca-e0-verified-snapshot-v1\x00"
PIN = re.compile(r"^[0-9a-f]{64}$")


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



def compare_pinned_snapshot(document, evidence_root, expected_sha256):
    """Compare locally verified snapshot to independent pinned digest; no GO."""
    if not isinstance(expected_sha256, str) or not PIN.fullmatch(expected_sha256):
        return False, False, {
            "operational_go": False,
            "artifact_errors": ["expected snapshot must be exactly 64 lowercase hex chars"],
        }
    valid, ready, report = snapshot(document, evidence_root)
    if not ready:
        return valid, False, report
    matched = hmac.compare_digest(report["snapshot_sha256"], expected_sha256)
    report["matches_pinned_snapshot"] = matched
    if not matched:
        # Suppress the changed digest in mismatch output to avoid accidental re-pinning.
        report.pop("snapshot_sha256", None)
        report["artifact_errors"].append("snapshot differs from pinned reference")
    return valid, matched, report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Fingerprint reviewed E0 evidence offline")
    parser.add_argument("--check", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--expected-sha256",
                        help="Independently approved snapshot SHA-256 (64 lowercase hex)")
    args = parser.parse_args(argv)
    if args.expected_sha256 is not None and not PIN.fullmatch(args.expected_sha256):
        print(json.dumps({"verdict": "INVALID", "operational_go": False,
                          "error": "expected snapshot must be exactly 64 lowercase hex chars"}))
        return 2
    try:
        document = ARTIFACTS.CHECKER.load_register(args.check)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        print(json.dumps({"verdict": "INVALID", "operational_go": False,
                          "error": type(exc).__name__}))
        return 2
    if args.expected_sha256 is None:
        valid, verified, report = snapshot(document, args.evidence_root)
        verdict = "SNAPSHOT_READY" if verified else "NO_GO" if valid else "INVALID"
    else:
        valid, verified, report = compare_pinned_snapshot(
            document, args.evidence_root, args.expected_sha256)
        verdict = ("SNAPSHOT_MATCH" if verified else
                   "SNAPSHOT_MISMATCH" if valid and report.get("matches_pinned_snapshot") is False
                   else "NO_GO" if valid else "INVALID")
    print(json.dumps({"verdict": verdict, **report}, sort_keys=True))
    return 0 if verified else 1 if valid else 2


if __name__ == "__main__":
    raise SystemExit(main())
