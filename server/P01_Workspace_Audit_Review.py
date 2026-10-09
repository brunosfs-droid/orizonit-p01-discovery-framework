#!/usr/bin/env python3
"""Read-only verification of the v0.6.29 private audit journal.

v0.6.44 foundation: validates structure and request pairing. This is NOT a
cryptographic integrity proof, operational approval, or scan authorization.
"""
from __future__ import annotations

import json
from pathlib import Path
import re

MAX_BYTES = 8 * 1024 * 1024
MAX_LINE = 1024
HEX = re.compile(r"[0-9a-f]{32}\Z")
EVENTS = {"listener_started", "listener_stopped", "request_started", "request_finished"}
OUTCOMES = {"response_written", "delivery_failed", "handler_failed"}


class JournalInvalid(ValueError):
    pass


def validate(data: bytes) -> dict:
    """Fail closed on malformed, truncated, reordered or unpaired events."""
    if type(data) is not bytes or not data or len(data) > MAX_BYTES or not data.endswith(b"\n"):
        raise JournalInvalid("audit_journal_invalid")
    active = {}
    count = 0
    started = stopped = False
    for line in data.splitlines():
        if not line or len(line) > MAX_LINE:
            raise JournalInvalid("audit_journal_invalid")
        try:
            doc = json.loads(line.decode("ascii"), object_pairs_hook=_unique)
        except (ValueError, UnicodeError):
            raise JournalInvalid("audit_journal_invalid") from None
        if type(doc) is not dict or doc.get("audit_version") != "1" or doc.get("listener") != "workspace":
            raise JournalInvalid("audit_journal_invalid")
        if type(doc.get("sequence")) is not int or doc["sequence"] != count + 1:
            raise JournalInvalid("audit_journal_invalid")
        if type(doc.get("at_utc")) is not str or not re.fullmatch(
            r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z", doc["at_utc"]
        ):
            raise JournalInvalid("audit_journal_invalid")
        event = doc.get("event")
        if event not in EVENTS or stopped:
            raise JournalInvalid("audit_journal_invalid")
        if event == "listener_started":
            if count != 0 or started:
                raise JournalInvalid("audit_journal_invalid")
            started = True
        elif not started:
            raise JournalInvalid("audit_journal_invalid")
        elif event == "listener_stopped":
            if active:
                raise JournalInvalid("audit_journal_invalid")
            stopped = True
        elif event == "request_started":
            key = doc.get("request_id")
            if type(key) is not str or not HEX.fullmatch(key) or key in active:
                raise JournalInvalid("audit_journal_invalid")
            if type(doc.get("operation")) is not str:
                raise JournalInvalid("audit_journal_invalid")
            active[key] = doc["operation"]
        else:
            key = doc.get("request_id")
            if type(key) is not str or key not in active or doc.get("operation") != active[key]:
                raise JournalInvalid("audit_journal_invalid")
            status = doc.get("http_status")
            if status is not None and (type(status) is not int or not 100 <= status <= 599):
                raise JournalInvalid("audit_journal_invalid")
            if doc.get("outcome") not in OUTCOMES:
                raise JournalInvalid("audit_journal_invalid")
            del active[key]
        count += 1
    return {"status": "valid_structure", "record_count": count,
            "pending_requests": len(active), "listener_closed": stopped,
            "execution_authorized": False, "integrity_proven": False}


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def validate_file(path: str | Path) -> dict:
    """Use only a trusted local journal path; refuse symbolic links."""
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        raise JournalInvalid("audit_journal_invalid")
    with p.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    return validate(data)
