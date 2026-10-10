"""R02: real local subprocess cancellation on grant revocation and lease loss.

Synthetic Python status processes only. No SQL, scans, network, EVE-NG,
credentials, or privileged kill of unrelated processes is required.
"""
import os
from pathlib import Path
import signal
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "server"))
import P01_Workspace_Legacy_Jobs as jobs
import test_workspace_coordinator as coordinator
import test_workspace_legacy_jobs as legacy

pg = jobs.pg


@unittest.skipUnless(os.name == "posix" and sys.platform.startswith("linux"),
                     "real local process qualification requires Linux/POSIX")
class R02LiveRevocationTests(unittest.TestCase):
    setUp = coordinator.CoordinatorTests.setUp
    cleanup = coordinator.CoordinatorTests.cleanup
    opened = coordinator.CoordinatorTests.opened
    configured = legacy.LegacyJobsTests.configured

    @staticmethod
    def process_running(pid):
        """A zombie is not executing; prefer /proc for deterministic Linux checks."""
        try:
            content = (Path("/proc") / str(pid) / "stat").read_text()
            return content.split(") ", 1)[1][0] not in ("Z", "X")
        except (OSError, IndexError):
            return False

    @staticmethod
    def emergency_stop(pids):
        """Best effort fixture cleanup; only synthetic child PIDs tracked by marker."""
        for pid in pids:
            try:
                if R02LiveRevocationTests.process_running(pid):
                    os.kill(pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass

    def run_live_workers(self, failure_mode, workers):
        token = self.opened()
        script, source, adapter = self.configured()
        mark_dir = script.parent / "started"
        mark_dir.mkdir()
        script.write_text(
            "import os, time\nfrom pathlib import Path\n"
            + f"Path({str(mark_dir)!r}, str(os.getpid()) + '.pid').write_text('ready')\n"
            + "time.sleep(60)\n", encoding="utf-8",
        )
        failures = []
        outcomes = []
        threads = []
        pids = set()

        def work():
            try:
                outcomes.append(adapter.legacy_checkpoint("reader", token, timeout=12))
            except pg.PersistenceError as exc:
                failures.append(str(exc))
            except Exception:
                failures.append("unexpected_exception")

        try:
            with patch.object(jobs, "SCRIPT", script):
                for _ in range(workers):
                    thread = threading.Thread(target=work)
                    thread.start()
                    threads.append(thread)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    pids = {int(p.stem) for p in mark_dir.glob("*.pid")}
                    if len(pids) == workers and len(self.c._jobs) == workers:
                        break
                    time.sleep(0.02)
                self.assertEqual(len(pids), workers, "all synthetic children started")
                self.assertEqual(len(self.c._jobs), workers, "all jobs admitted")

                # Toggle permission or inject SQL lease loss only AFTER real
                # subprocesses were observed executing. Both must fail closed.
                if failure_mode == "revoke":
                    self.grants["reader"].clear()
                    expected = "workspace_access_denied"
                elif failure_mode == "lease_loss":
                    self.lease.lost = True
                    expected = "workspace_lease_lost"
                else:
                    self.fail("unknown injection mode")
                for thread in threads:
                    thread.join(timeout=5)
                self.assertFalse(any(t.is_alive() for t in threads),
                                 "revoked subprocess worker survived cleanup")
                self.assertEqual(outcomes, [], "unauthorized result was delivered")
                self.assertEqual(sorted(failures), [expected] * workers)
                self.assertFalse(self.c._jobs)
                self.assertFalse(self.c._cache)
                self.assertEqual(self.c._bytes, 0)
                for pid in pids:
                    deadline = time.monotonic() + 2
                    while self.process_running(pid) and time.monotonic() < deadline:
                        time.sleep(0.02)
                    self.assertFalse(self.process_running(pid),
                                     "synthetic child continued after permission failure")

                if failure_mode == "revoke":
                    self.c.close("writer", "A", token.generation, timeout=3)
                    reopened = self.opened("B")
                    self.assertEqual(reopened.workspace_id, "B")
                    with self.assertRaisesRegex(pg.PersistenceError,
                                                "workspace_generation_stale"):
                        adapter.legacy_checkpoint("writer", token, timeout=1)
                else:
                    self.assertEqual(self.c.state, "recovery_required")
                    with self.assertRaisesRegex(pg.PersistenceError,
                                                "workspace_lease_lost"):
                        self.opened("B")
                return {"injection": failure_mode,
                        "workers_fenced": len(failures), "child_count": len(pids),
                        "late_results": len(outcomes), "lab_executed": False,
                        "operational_go": False}
        finally:
            self.c._cancel.set()
            for thread in threads:
                if thread.is_alive():
                    thread.join(timeout=4)
            self.emergency_stop(pids)

    def test_two_live_children_die_after_read_grant_revocation(self):
        result = self.run_live_workers("revoke", 2)
        self.assertEqual(result["workers_fenced"], 2)
        self.assertEqual(result["child_count"], 2)
        self.assertEqual(result["late_results"], 0)
        self.assertFalse(result["operational_go"])

    def test_two_live_children_die_after_lease_loss(self):
        result = self.run_live_workers("lease_loss", 2)
        self.assertEqual(result["workers_fenced"], 2)
        self.assertEqual(result["child_count"], 2)
        self.assertEqual(result["late_results"], 0)
        self.assertFalse(result["operational_go"])


if __name__ == "__main__":
    unittest.main()
