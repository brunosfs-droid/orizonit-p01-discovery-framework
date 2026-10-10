"""Deterministic offline R02 coordinator cancellation and timing qualification.

Never connects to PostgreSQL, EVE-NG or scanner endpoints.
"""
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import unittest

SCRIPT = (Path(__file__).resolve().parents[1] / "docs/validation"
          / "ALPHA_R02_COORDINATOR_LOAD_SMOKE_v0.6.89.py")
SPEC = importlib.util.spec_from_file_location("r02_offline_load_smoke", SCRIPT)
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


class R02OfflineLoadSmokeTests(unittest.TestCase):
    def test_coordinator_drains_and_fences_stale_tokens(self):
        result = smoke.qualify(cycles=3, workers=3)
        self.assertEqual(result["status"], "OFFLINE_QUALIFIED")
        self.assertEqual(result["scope"], "in_memory_coordinator_only")
        self.assertEqual(result["cancellations_fenced"], 9)
        self.assertEqual(result["stale_tokens_denied"], 3)
        self.assertFalse(result["operational_go"])
        self.assertFalse(result["lab_executed"])
        self.assertEqual(result["threshold_qualification"], "not_established")
        self.assertGreaterEqual(result["close_p95_ms"], 0)
        self.assertGreaterEqual(result["peak_python_allocations_kib"], 0)

    def test_alternating_workspace_load_rapidly(self):
        result = smoke.qualify(cycles=6, workers=4)
        self.assertEqual(result["cancellations_fenced"], 24)
        self.assertEqual(result["stale_tokens_denied"], 6)
        self.assertGreaterEqual(result["close_max_ms"], result["close_p95_ms"])
        self.assertGreaterEqual(result["close_p95_ms"], result["close_p50_ms"])

    def test_quantiles_are_nearest_rank_with_no_hidden_sla(self):
        self.assertEqual(smoke.percentile([10, 20, 30, 40], 50), 20)
        self.assertEqual(smoke.percentile([10, 20, 30, 40], 95), 40)
        with self.assertRaises(ValueError):
            smoke.percentile([], 95)
        with self.assertRaises(ValueError):
            smoke.percentile([1], 0)

    def test_unbounded_or_boolean_workload_is_rejected(self):
        for cycles, workers in ((0, 1), (51, 1), (1, 0),
                                (1, 17), (True, 1), (1, True),
                                ("1", 1), (1, 1.5)):
            with self.subTest(cycles=cycles, workers=workers):
                with self.assertRaises(ValueError):
                    smoke.qualify(cycles=cycles, workers=workers)

    def test_cli_reports_sanitized_offline_result_and_no_go(self):
        out = io.StringIO()
        with redirect_stdout(out):
            status = smoke.main(["--cycles", "1", "--workers", "2"])
        self.assertEqual(status, 0)
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["cancellations_fenced"], 2)
        self.assertFalse(payload["operational_go"])
        self.assertFalse(payload["lab_executed"])
        self.assertNotIn("credential", out.getvalue().lower())

    def test_cli_invalid_input_is_redacted_and_fails(self):
        out = io.StringIO()
        with redirect_stdout(out):
            status = smoke.main(["--cycles", "0", "--workers", "2"])
        self.assertEqual(status, 2)
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["error_code"], "r02_offline_qualification_failed")
        self.assertFalse(payload["operational_go"])


if __name__ == "__main__":
    unittest.main()
