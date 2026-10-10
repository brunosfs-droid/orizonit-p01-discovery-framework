"""Linux offline R02 multi-process cancellation integration regression.

Launches only short-lived synthetic local Python status scripts. No credentials,
database, EVE-NG hosts, scanners, or network probes.
"""
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import unittest

SCRIPT = (Path(__file__).resolve().parents[1] / "docs" / "validation" /
          "ALPHA_R02_LEGACY_MULTIPROCESS_SMOKE_v0.6.90.py")
SPEC = importlib.util.spec_from_file_location("r02_multiprocess_v090", SCRIPT)
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


@unittest.skipUnless(os.name == "posix" and sys.platform.startswith("linux"),
                     "controlled process-group smoke requires Linux/POSIX")
class R02MultiprocessSmokeTests(unittest.TestCase):
    def test_two_real_status_subprocesses_cancel_across_a_b(self):
        result = smoke.qualification(cycles=2, workers=2)
        self.assertEqual(result["status"], "OFFLINE_MULTIPROCESS_QUALIFIED")
        self.assertEqual(result["scope"], "synthetic_local_status_processes")
        self.assertEqual(result["cancellations_fenced"], 4)
        self.assertEqual(result["stale_tokens_denied"], 2)
        self.assertFalse(result["lab_executed"])
        self.assertFalse(result["operational_go"])
        self.assertEqual(result["threshold_qualification"], "not_established")
        self.assertGreaterEqual(result["close_p95_ms"], result["close_p50_ms"])
        self.assertGreaterEqual(result["close_max_ms"], result["close_p95_ms"])

    def test_three_simultaneous_local_processes_are_drained(self):
        result = smoke.qualification(cycles=1, workers=3)
        self.assertEqual(result["cancellations_fenced"], 3)
        self.assertEqual(result["stale_tokens_denied"], 1)
        self.assertFalse(result["operational_go"])

    def test_invalid_workload_sizes_rejected_before_spawning(self):
        for cycles, workers in ((0, 2), (9, 2), (1, 1), (1, 5),
                                (True, 2), (1, True), (1.5, 2), (1, "2")):
            with self.subTest(cycles=cycles, workers=workers):
                with self.assertRaises(ValueError):
                    smoke.qualification(cycles=cycles, workers=workers)

    def test_cli_is_machine_readable_and_explicitly_no_go(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = smoke.main(["--cycles", "1", "--workers", "2"])
        self.assertEqual(code, 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["status"], "OFFLINE_MULTIPROCESS_QUALIFIED")
        self.assertEqual(result["cancellations_fenced"], 2)
        self.assertFalse(result["operational_go"])
        self.assertFalse(result["lab_executed"])
        self.assertNotIn("synthetic-lease", output.getvalue())

    def test_cli_invalid_size_fails_closed(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = smoke.main(["--cycles", "0", "--workers", "3"])
        self.assertEqual(code, 2)
        result = json.loads(output.getvalue())
        self.assertEqual(result["error_code"], "r02_offline_multiprocess_failure")
        self.assertFalse(result["operational_go"])


if __name__ == "__main__":
    unittest.main()
