#!/usr/bin/env python3
"""Offline fail-closed E0 evidence register validator (no lab execution)."""
import argparse
from collections import Counter
from datetime import datetime, timedelta
import json
from pathlib import Path
import re

MAX_REGISTER_BYTES = 1024 * 1024


def strict_json_loads(raw):
    """Reject ambiguous JSON (duplicate keys and non-finite numbers) safely."""
    def unique_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                # Deliberately avoid printing untrusted key names.
                raise ValueError("duplicate JSON object member")
            result[key] = value
        return result

    def reject_constant(_value):
        raise ValueError("non-finite JSON numeric constant")

    return json.loads(raw, object_pairs_hook=unique_keys,
                      parse_constant=reject_constant)


def load_register(path):
    """Bound the input size before strict UTF-8 decoding and JSON parsing."""
    with Path(path).open("rb") as source:
        raw = source.read(MAX_REGISTER_BYTES + 1)
    if len(raw) > MAX_REGISTER_BYTES:
        raise ValueError("E0 register exceeds size limit")
    return strict_json_loads(raw.decode("utf-8"))


GATE_IDS = tuple(f"E0-{i:02d}" for i in range(1, 11))
GATE_DESCRIPTIONS = {
    "E0-01": "Offline package and import",
    "E0-02": "Windows WinRM authorized profiles",
    "E0-03": "Linux authorized SSH collection",
    "E0-04": "Denied/unreachable endpoints fail closed",
    "E0-05": "Workspace scope and stale generation",
    "E0-06": "Coordinator cancel/drain/lease (R02)",
    "E0-07": "Import/reconciliation (R05/R06)",
    "E0-08": "Same-cluster recovery (T13)",
    "E0-09": "HTTP audit and secret redaction",
    "E0-10": "Rollback and reproducibility",
}
REGISTER_FIELDS = frozenset({
    "schema_version", "release_commit", "topology_sha256",
    "scope_approval_ref", "operator", "executed_at_utc",
    "security_reviewer", "release_reviewer", "gates",
})
GATE_FIELDS = frozenset({
    "gate_id", "description", "result", "evidence_uri",
    "evidence_sha256", "reviewer", "executed_at_utc",
})
OPTIONAL_TEXT_FIELDS = ("evidence_uri", "evidence_sha256", "reviewer", "executed_at_utc")
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
    if type(document.get("schema_version")) is not int or document["schema_version"] != 1:
        errors.append("schema_version must be integer 1")
    if set(document) != REGISTER_FIELDS:
        errors.append("register fields differ from the schema contract")
    for field in REQUIRED_METADATA:
        value = document.get(field)
        if value is not None and not isinstance(value, str):
            errors.append(f"metadata: {field} must be a string or null")
    gates = document.get("gates")
    if not isinstance(gates, list):
        return False, False, {"errors": errors + ["gates must be an array"], "missing": [], "counts": {}}
    ids = [g.get("gate_id") if isinstance(g, dict) and isinstance(g.get("gate_id"), str) else None for g in gates]
    if len(gates) != len(GATE_IDS) or set(ids) != set(GATE_IDS) or len(set(ids)) != len(ids):
        errors.append("gate_id set must contain E0-01..E0-10 exactly once")
    for index, gate in enumerate(gates, 1):
        if not isinstance(gate, dict):
            errors.append("each gate must be an object")
            continue
        gid = gate.get("gate_id")
        # Never echo arbitrary identifier data in stdout (potential secret input).
        safe_id = gid if isinstance(gid, str) and gid in GATE_IDS else f"gate[{index}]"
        if set(gate) != GATE_FIELDS:
            errors.append(f"{safe_id}: gate fields differ from the schema contract")
        if isinstance(gid, str) and gid in GATE_DESCRIPTIONS:
            if gate.get("description") != GATE_DESCRIPTIONS[gid]:
                errors.append(f"{safe_id}: gate description differs from the pinned contract")
        for field in OPTIONAL_TEXT_FIELDS:
            value = gate.get(field)
            if value is not None and not isinstance(value, str):
                errors.append(f"{safe_id}: {field} must be a string or null")
        state = gate.get("result")
        if not isinstance(state, str) or state not in STATES:
            errors.append(f"{safe_id}: invalid result")
            continue
        counts[state] += 1
        if state != "PASS":
            missing.append(f"{safe_id}: {state}")
            continue
        for field in REQUIRED_EVIDENCE:
            if not nonempty(gate.get(field)):
                errors.append(f"{safe_id}: PASS requires {field}")
        if nonempty(gate.get("evidence_sha256")) and not DIGEST.fullmatch(gate["evidence_sha256"]):
            errors.append(f"{safe_id}: evidence_sha256 must be 64 lowercase hex chars")
        if nonempty(gate.get("executed_at_utc")) and not utc_timestamp(gate["executed_at_utc"]):
            errors.append(f"{safe_id}: executed_at_utc must be an ISO 8601 UTC timestamp")
        # Evidence must be reviewed by somebody other than its executor.
        # Compare normalized identities to prevent case/whitespace bypasses.
        operator = document.get("operator")
        reviewer = gate.get("reviewer")
        if nonempty(operator) and nonempty(reviewer) and operator.strip().casefold() == reviewer.strip().casefold():
            errors.append(f"{safe_id}: gate reviewer must differ from operator")
        uri = gate.get("evidence_uri")
        if nonempty(uri) and (any(c.isspace() for c in uri) or "@" in uri):
            errors.append(f"{safe_id}: evidence_uri contains whitespace or embedded credentials")
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
    # The lab executor, security reviewer and release approver are separate actors.
    actors = [document.get(field) for field in ("operator", "security_reviewer", "release_reviewer")]
    if all(nonempty(actor) for actor in actors):
        if len({actor.strip().casefold() for actor in actors}) != len(actors):
            errors.append("operator, security_reviewer and release_reviewer must be distinct")
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
        data = load_register(args.check)
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
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
