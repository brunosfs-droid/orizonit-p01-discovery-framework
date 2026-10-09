"""v0.6.44: read-only journal structure and replay detection."""
import json
from pathlib import Path
import sys
import unittest

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
                         outcome="response_written")
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


if __name__ == "__main__":
    unittest.main()
