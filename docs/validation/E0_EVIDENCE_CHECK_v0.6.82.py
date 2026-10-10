#!/usr/bin/env python3
"""Offline fail-closed E0 evidence register validator (no lab execution)."""
import argparse
from collections import Counter
from datetime import datetime, timedelta
import json
from pathlib import Path
import re

GATE_IDS = tuple(f"E0-{i:02d}" for i in range(1, 11))
STATES = frozenset({"PASS", "FAIL", "BLOCKED", "NOT RUN"})
DIGEST = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_METADATA = (
    "release_commit", "topology_sha256", "scope_approval_ref",
    "operator", "executed_at_utc", "security_reviewer", "release_reviewer",
)
REQUIRED_EVIDENCE = ("evidence_uri", "evidence_sha256", "reviewer", "executed_at_utc")


def nonempty(value):
    return isinstance(value, str) and bool(value.strip()) and value.strip().lower() not in {
        "pending", "not recorded", "not run", "none", "—", "-"
    }


def utc_timestamp(value):
    if not nonempty(value):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.utcoffset() == timedelta(0)
    except ValueError:
        return False


def assess(document):
    """Return (valid, go, summary); never reveal operator/evidence contents."""
    errors = []
    missing = []
    counts = Counter()
    if not isinstance(document, dict):
        return False, False, {"errors": ["register must be an object"], "missing": [], "counts": {}}
    if document.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    gates = document.get("gates")
    if not isinstance(gates, list):
        return False, False, {"errors": errors + ["gates must be an array"], "missing": [], "counts": {}}
    ids = [g.get("gate_id") if isinstance(g, dict) else None for g in gates]
    if len(gates) != len(GATE_IDS) or set(ids) != set(GATE_IDS) or len(set(ids)) != len(ids):
        errors.append("gate_id set must contain E0-01..E0-10 exactly once")
    for gate in gates:
        if not isinstance(gate, dict):
            errors.append("each gate must be an object")
            continue
        gid = gate.get("gate_id")
        state = gate.get("result")
        if state not in STATES:
            errors.append(f"{gid}: invalid result")
            continue
        counts[state] += 1
        if state != "PASS":
            missing.append(f"{gid}: {state}")
            continue
        for field in REQUIRED_EVIDENCE:
            if not nonempty(gate.get(field)):
                errors.append(f"{gid}: PASS requires {field}")
        if nonempty(gate.get("evidence_sha256")) and not DIGEST.fullmatch(gate["evidence_sha256"]):
            errors.append(f"{gid}: evidence_sha256 must be 64 lowercase hex chars")
        if nonempty(gate.get("executed_at_utc")) and not utc_timestamp(gate["executed_at_utc"]):
            errors.append(f"{gid}: executed_at_utc must be an ISO 8601 UTC timestamp")
        uri = gate.get("evidence_uri")
        if nonempty(uri) and (any(c.isspace() for c in uri) or "@" in uri):
            errors.append(f"{gid}: evidence_uri contains whitespace or embedded credentials")
    for field in REQUIRED_METADATA:
        val = document.get(field)
        if not nonempty(val):
            missing.append(f"metadata: {field}")
    if nonempty(document.get("release_commit")) and not COMMIT.fullmatch(document["release_commit"]):
        errors.append("release_commit must be 40 lowercase hex chars")
    if nonempty(document.get("topology_sha256")) and not DIGEST.fullmatch(document["topology_sha256"]):
        errors.append("topology_sha256 must be 64 lowercase hex chars")
    if nonempty(document.get("executed_at_utc")) and not utc_timestamp(document["executed_at_utc"]):
        errors.append("executed_at_utc must be an ISO 8601 UTC timestamp")
    valid = not errors
    go = valid and not missing and counts["PASS"] == 10
    return valid, go, {
        "errors": errors, "missing": missing,
        "counts": {s: counts[s] for s in ("PASS", "FAIL", "BLOCKED", "NOT RUN")},
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Validate E0 evidence; never run probes")
    parser.add_argument("--check", type=Path, required=True, help="JSON evidence register")
    parser.add_argument("--allow-no-go", action="store_true",
                        help="CI structure check only; NEVER implies operational approval")
    args = parser.parse_args(argv)
    try:
        data = json.loads(args.check.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(json.dumps({"verdict": "INVALID", "error": type(exc).__name__}))
        return 2
    valid, go, detail = assess(data)
    print(json.dumps({"verdict": "GO" if go else "NO_GO" if valid else "INVALID",
                      "structurally_valid": valid, **detail}, sort_keys=True))
    if not valid:
        return 2
    return 0 if go or args.allow_no_go else 1


if __name__ == "__main__":
    raise SystemExit(main())
