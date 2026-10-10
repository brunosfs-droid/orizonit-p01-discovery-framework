#!/usr/bin/env python3
"""Offline, non-executing SHA-256 verification of E0 evidence artifacts."""
import argparse
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import re
import stat

BASE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "e0_evidence_validator_v082", BASE / "E0_EVIDENCE_CHECK_v0.6.82.py"
)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
URI_PREFIX = "evidence://local/"


def relative_parts(uri, gate_id):
    """Accept only literal local references, bound to their own E0 gate."""
    if not isinstance(uri, str) or not uri.startswith(URI_PREFIX):
        return None
    path = uri[len(URI_PREFIX):]
    parts = path.split("/")
    if len(parts) < 2 or parts[0] != gate_id:
        return None
    if any(not COMPONENT.fullmatch(part) or part in (".", "..") for part in parts):
        return None
    return tuple(parts)


def digest_from_dir(root, parts):
    """Open each component relative to a directory fd, refusing symlinks."""
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise OSError("secure directory-descriptor operations unavailable")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(root, directory_flags)
    try:
        for part in parts[:-1]:
            child = os.open(part, directory_flags, dir_fd=fd)
            os.close(fd)
            fd = child
        file_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
        artifact = os.open(parts[-1], file_flags, dir_fd=fd)
        try:
            info = os.fstat(artifact)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ARTIFACT_BYTES:
                raise OSError("not a supported regular evidence file")
            size = 0
            digest = hashlib.sha256()
            while True:
                block = os.read(artifact, 1024 * 1024)
                if not block:
                    break
                size += len(block)
                if size > MAX_ARTIFACT_BYTES:
                    raise OSError("evidence size limit exceeded")
                digest.update(block)
            return digest.hexdigest()
        finally:
            os.close(artifact)
    finally:
        os.close(fd)


def verify(document, evidence_root):
    """Return (valid_structure, verified_bytes, sanitized summary)."""
    valid, complete, check = CHECKER.assess(document)
    report = {"register_valid": valid, "register_complete": complete,
              "artifact_errors": [], "verified_artifacts": 0}
    if not valid or not complete:
        return valid, False, report
    root = Path(evidence_root)
    seen = set()
    refs = []
    for gate in document["gates"]:
        gid = gate["gate_id"]
        parts = relative_parts(gate.get("evidence_uri"), gid)
        if parts is None:
            report["artifact_errors"].append(f"{gid}: invalid local artifact reference")
        elif parts in seen:
            report["artifact_errors"].append(f"{gid}: duplicate artifact reference")
        else:
            seen.add(parts)
            refs.append((gid, parts, gate["evidence_sha256"]))
    if report["artifact_errors"]:
        return False, False, report
    for gid, parts, expected in refs:
        try:
            actual = digest_from_dir(root, parts)
        except (OSError, ValueError, TypeError):
            report["artifact_errors"].append(f"{gid}: artifact unavailable or unsafe")
            continue
        if not hmac.compare_digest(actual, expected):
            report["artifact_errors"].append(f"{gid}: SHA-256 mismatch")
            continue
        report["verified_artifacts"] += 1
    return True, report["verified_artifacts"] == len(CHECKER.GATE_IDS), report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify local E0 evidence bytes only")
    parser.add_argument("--check", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        data = CHECKER.load_register(args.check)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        print(json.dumps({"verdict": "INVALID", "error": type(exc).__name__}))
        return 2
    valid, verified, details = verify(data, args.evidence_root)
    verdict = "ARTIFACTS_VERIFIED" if verified else "NO_GO" if valid else "INVALID"
    print(json.dumps({"verdict": verdict, "operational_go": False, **details},
                     sort_keys=True))
    return 0 if verified else 1 if valid else 2


if __name__ == "__main__":
    raise SystemExit(main())
