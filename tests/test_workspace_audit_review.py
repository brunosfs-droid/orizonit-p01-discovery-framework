"""v0.6.44: read-only journal structure and replay detection."""
import json
from pathlib import Path
import sys
import unittest
import tempfile
import os
from unittest.mock import patch



sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "server"))
import P01_Workspace_Audit_Review as review


def entry(n, event, **fields):
    return dict(audit_version="1", sequence=n,
                at_utc="2026-10-08T20:00:00.000001Z",
                listener="workspace", event=event, **fields)


def encode(*rows):
    return b"".join((json.dumps(row, separators=(",", ":")) + "\n").encode()
                    for row in rows)


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.start = entry(1, "listener_started")
        self.begin = entry(2, "request_started", request_id="a" * 32,
                           operation="scan_intent_preview")
        self.end = entry(3, "request_finished", request_id="a" * 32,
                         operation="scan_intent_preview", http_status=200,
                         outcome="response_written", operator_id=None, workspace_id=None)
        self.stop = entry(4, "listener_stopped")

    def test_complete_journal_is_not_authorization(self):
        result = review.validate(encode(self.start, self.begin, self.end, self.stop))
        self.assertEqual(result["record_count"], 4)
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["integrity_proven"])
        self.assertTrue(result["listener_closed"])

    def test_unfinished_request_can_be_reported_for_recovery(self):
        result = review.validate(encode(self.start, self.begin))
        self.assertEqual(result["pending_requests"], 1)

    def test_rejects_sequence_gaps_and_replayed_ids(self):
        wrong = dict(self.end, sequence=8)
        cases = [
            encode(self.start, self.begin, wrong),
            encode(self.start, self.begin, self.begin),
            encode(self.start, self.end),
            encode(self.start, self.begin, self.stop),
            encode(self.start, self.begin, dict(self.end, operation="login")),
            encode(self.start, self.begin, dict(self.end, http_status=True)),
            encode(self.start, self.begin, self.end)[:-1],
            encode(self.start) + b'{"audit_version":"1","audit_version":"1"}\n',
        ]
        for content in cases:
            with self.subTest(content=content[:90]):
                with self.assertRaises(review.JournalInvalid):
                    review.validate(content)

    def test_completed_id_cannot_be_reused(self):
        with self.assertRaises(review.JournalInvalid):
            review.validate(encode(self.start, self.begin, self.end,
                                   dict(self.begin, sequence=4)))

    def test_strict_schema_and_types(self):
        mutations = [dict(self.start, secret="hidden"),
                     dict(self.start, at_utc="2026-02-30T20:00:00.000001Z"),
                     dict(self.start, event=[])]
        for row in mutations:
            with self.subTest(row=row), self.assertRaises(review.JournalInvalid):
                review.validate(encode(row))
        for fields in ({"operation": "unregistered"}, {"operation": []}):
            with self.assertRaises(review.JournalInvalid):
                review.validate(encode(self.start, dict(self.begin, **fields)))
        for fields in ({"outcome": []}, {"operator_id": True},
                       {"workspace_id": "w"}, {"operator_id": "secret/path"},
                       {"http_status": float("nan")}):
            with self.subTest(fields=fields), self.assertRaises(review.JournalInvalid):
                review.validate(encode(self.start, self.begin, dict(self.end, **fields)))
        missing = dict(self.end)
        del missing["operator_id"]
        with self.assertRaises(review.JournalInvalid):
            review.validate(encode(self.start, self.begin, missing))

    def test_capacity_and_line_format(self):
        rows = [self.start] + [dict(self.begin, sequence=n+2, request_id=f"{n:032x}")
                               for n in range(review.MAX_ACTIVE + 1)]
        for content in (encode(*rows), encode(self.start).replace(b"\n", b"\r\n"),
                        b"", b"x" * (review.MAX_BYTES + 1),
                        b"[" * 1000 + b"\n"):
            with self.assertRaises(review.JournalInvalid):
                review.validate(content)

    def test_real_producer_round_trip_and_no_write(self):
        from P01_Workspace_Audit import FileAudit, OPERATIONS
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            audit = FileAudit(path)
            for operation in sorted(OPERATIONS):
                key = audit.begin(operation)
                audit.finish(key, http_status=200, outcome="response_written",
                             operator_id="operator", workspace_id="workspace")
            audit.close()
            original = path.read_bytes()
            self.assertTrue(review.validate_file(path)["listener_closed"])
            self.assertEqual(original, path.read_bytes())
            link = Path(directory) / "alias.jsonl"
            link.symlink_to(path)
            with self.assertRaises(review.JournalInvalid):
                review.validate_file(link)
            with self.assertRaises(review.JournalInvalid):
                review.validate_file(Path(directory) / "missing")
            with patch("P01_Operator_Audit_Check._directory", side_effect=OSError("private path")):
                with self.assertRaisesRegex(review.JournalInvalid, "^audit_journal_invalid$"):
                    review.validate_file(path)
            if os.name == "posix":
                path.chmod(0o644)
                with self.assertRaises(review.JournalInvalid):
                    review.validate_file(path)


if __name__ == "__main__":
    unittest.main()
