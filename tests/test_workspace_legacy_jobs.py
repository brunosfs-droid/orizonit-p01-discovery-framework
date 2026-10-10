"""Read-only legacy process lifecycle and coordinator fencing tests."""
import os
import signal
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "server"))
import P01_Workspace_Legacy_Jobs as jobs
import P01_Workspace_Service as service
import test_workspace_coordinator as coordinator

pg = jobs.pg


class LegacyJobsTests(unittest.TestCase):
    setUp = coordinator.CoordinatorTests.setUp
    cleanup = coordinator.CoordinatorTests.cleanup
    opened = coordinator.CoordinatorTests.opened

    def configured(self, code="import sys; sys.exit(0)"):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        script = base / "check.py"
        script.write_text(code, encoding="utf-8")
        source = base / "workspace"
        source.mkdir()
        roots = jobs.LegacyRunRoots({"A": source})
        adapter = service.WorkspaceService(self.c, service.SourceRoots({}),
                                           legacy_runs=roots)
        return script, source, adapter

    def test_success_is_fenced_and_does_not_return_raw_runtime_stdout(self):
        token = self.opened()
        script, source, adapter = self.configured(
            "print('SECRET-DO-NOT-LEAK'); import sys; sys.exit(0)")
        with patch.object(jobs, "SCRIPT", script):
            result = adapter.legacy_checkpoint("reader", token, timeout=2)
        self.assertEqual(result["status"], "checkpoint_executed")
        self.assertEqual(result["workspace_id"], "A")
        self.assertFalse(result["network_activity_performed"])
        self.assertFalse(result["authentication_performed"])
        self.assertNotIn("SECRET", repr(result))
        self.assertFalse(self.c._jobs)

    def test_read_grant_and_private_roots_checked_before_spawn(self):
        token = self.opened()
        script, source, adapter = self.configured()
        with patch.object(jobs.subprocess, "Popen") as spawn:
            with self.assertRaisesRegex(pg.PersistenceError, "workspace_access_denied"):
                adapter.legacy_checkpoint("reader",
                    jobs.coordinator.Token("B", token.generation, token.lease_id))
            adapter.legacy_runs = jobs.LegacyRunRoots({})
            with self.assertRaisesRegex(pg.PersistenceError, "workspace_access_denied"):
                adapter.legacy_checkpoint("reader", token, timeout=2)
            spawn.assert_not_called()

    def test_invalid_roots_and_arguments_fail_without_child(self):
        token = self.opened()
        script, source, adapter = self.configured()
        alias = source.parent / "alias"
        try:
            alias.symlink_to(source, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(pg.PersistenceError):
            jobs.LegacyRunRoots({"A": alias})
        with self.assertRaises(pg.PersistenceError):
            jobs.LegacyRunRoots({"A": source, "B": source})
        with patch.object(jobs.subprocess, "Popen") as spawn:
            for bad in (0, 31, True, 1.1):
                with self.assertRaises(pg.PersistenceError):
                    adapter.legacy_checkpoint("reader", token, timeout=bad)
            spawn.assert_not_called()

    def test_nonzero_exits_fail_closed_without_showing_stderr(self):
        token = self.opened()
        script, source, adapter = self.configured(
            "import sys; print('PRIVATE-CONNECTION-STRING', file=sys.stderr); sys.exit(7)")
        with patch.object(jobs, "SCRIPT", script):
            with self.assertRaisesRegex(pg.PersistenceError, "workspace_legacy_job_failed"):
                adapter.legacy_checkpoint("reader", token, timeout=2)
        self.assertFalse(self.c._jobs)

    def test_timeout_terminates_child_and_releases_job(self):
        token = self.opened()
        script, source, adapter = self.configured("import time; time.sleep(60)")
        with patch.object(jobs, "SCRIPT", script):
            start = time.monotonic()
            with self.assertRaisesRegex(pg.PersistenceError, "workspace_legacy_job_timeout"):
                adapter.legacy_checkpoint("reader", token, timeout=1)
        self.assertLess(time.monotonic() - start, 4)
        self.assertFalse(self.c._jobs)

    def test_close_cancels_subprocess_before_opening_other_workspace(self):
        token = self.opened()
        script, source, adapter = self.configured("import time; time.sleep(60)")
        errors = []
        ready = threading.Event()
        with patch.object(jobs, "SCRIPT", script):
            def run():
                ready.set()
                try:
                    adapter.legacy_checkpoint("reader", token, timeout=15)
                except pg.PersistenceError as exc:
                    errors.append(str(exc))
            thread = threading.Thread(target=run)
            thread.start()
            self.assertTrue(ready.wait(2))
            deadline = time.monotonic() + 3
            while not self.c._jobs and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(self.c._jobs)
            self.c.close("writer", "A", token.generation, timeout=3)
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
        self.assertEqual(errors, ["workspace_generation_stale"])
        self.assertFalse(self.c._jobs)
        self.assertEqual(self.c.state, "closed")
        new = self.opened("B")
        with self.assertRaisesRegex(pg.PersistenceError, "workspace_generation_stale"):
            adapter.legacy_checkpoint("reader", token)
        self.assertEqual(new.workspace_id, "B")

    def test_failed_child_cleanup_quarantines_and_cancels_other_jobs(self):
        token = self.opened()
        script, source, adapter = self.configured()
        with self.c.borrow("reader", token) as other_operation:
            with (
                patch.object(jobs, "SCRIPT", script),
                patch.object(jobs.subprocess, "Popen") as spawned,
                patch.object(jobs, "_stop",
                             side_effect=OSError("PRIVATE child cleanup diagnostic")),
            ):
                spawned.return_value.poll.return_value = 0
                with self.assertRaisesRegex(
                    pg.PersistenceError, "workspace_legacy_job_failed"
                ) as caught:
                    adapter.legacy_checkpoint("reader", token, timeout=2)
                self.assertNotIn("PRIVATE", str(caught.exception))
                self.assertEqual(self.c.state, "recovery_required")
                self.assertTrue(other_operation.cancel.is_set())
                with self.assertRaisesRegex(pg.PersistenceError, "workspace_lease_lost"):
                    other_operation.check()
                with self.assertRaisesRegex(pg.PersistenceError, "workspace_lease_lost"):
                    self.opened("B")
                spawned.assert_called_once()
        self.assertFalse(self.c._jobs)
        self.assertEqual(self.c._cache, {})
        self.assertEqual(self.c._bytes, 0)

    def test_cleanup_failure_after_revocation_stays_quarantined(self):
        token = self.opened()
        script, source, adapter = self.configured()

        def revoke_on_exit(*args, **kwargs):
            self.grants["reader"].clear()
            return 0

        with (
            patch.object(jobs, "SCRIPT", script),
            patch.object(jobs.subprocess, "Popen") as spawned,
            patch.object(jobs, "_stop", side_effect=RuntimeError("private failure")),
        ):
            spawned.return_value.poll.side_effect = revoke_on_exit
            with self.assertRaisesRegex(
                pg.PersistenceError, "workspace_legacy_job_failed"
            ):
                adapter.legacy_checkpoint("reader", token, timeout=2)
        self.assertEqual(self.c.state, "recovery_required")
        self.assertFalse(self.c._jobs)
        with self.assertRaisesRegex(pg.PersistenceError, "workspace_lease_lost"):
            self.opened("B")

    def test_revoked_reader_cannot_receive_result(self):
        token = self.opened()
        script, source, adapter = self.configured()
        def revoke_and_succeed(*args, **kwargs):
            self.grants["reader"].clear()
            return 0
        with patch.object(jobs, "SCRIPT", script), patch.object(jobs.subprocess, "Popen") as spawned, patch.object(jobs, "_stop") as cleanup:
            proc = spawned.return_value
            proc.poll.side_effect = revoke_and_succeed
            proc.wait.return_value = 0
            with self.assertRaisesRegex(pg.PersistenceError, "workspace_access_denied"):
                adapter.legacy_checkpoint("reader", token, timeout=2)
            cleanup.assert_called_once_with(proc)
        self.assertFalse(self.c._jobs)



    @unittest.skipUnless(os.name == "posix" and sys.platform.startswith("linux"),
                         "POSIX Linux process-group qualification")
    def test_grandchild_cannot_survive_successful_parent_exit(self):
        token = self.opened()
        script, source, adapter = self.configured()
        marker = script.parent / "grandchild.pid"
        script.write_text(
            "import subprocess,sys\n"
            "from pathlib import Path\n"
            "child=subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(60)'],"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
            f"Path({str(marker)!r}).write_text(str(child.pid))\n"
            "sys.exit(0)\n", encoding="utf-8")
        with patch.object(jobs, "SCRIPT", script):
            result = adapter.legacy_checkpoint("reader", token, timeout=5)
        self.assertEqual(result["status"], "checkpoint_executed")
        self.assertTrue(marker.exists())
        pid = int(marker.read_text())
        self.addCleanup(self._kill_if_running, pid)
        self.assert_not_running(pid)
        self.assertFalse(self.c._jobs)

    @unittest.skipUnless(os.name == "posix" and sys.platform.startswith("linux"),
                         "POSIX Linux process-group qualification")
    def test_timeout_reaps_parent_and_descendant_before_job_release(self):
        token = self.opened()
        script, source, adapter = self.configured()
        marker = script.parent / "grandchild.pid"
        script.write_text(
            "import subprocess,sys,time\n"
            "from pathlib import Path\n"
            "child=subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(60)'],"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
            f"Path({str(marker)!r}).write_text(str(child.pid))\n"
            "time.sleep(60)\n", encoding="utf-8")
        with patch.object(jobs, "SCRIPT", script):
            with self.assertRaisesRegex(pg.PersistenceError, "workspace_legacy_job_timeout"):
                adapter.legacy_checkpoint("reader", token, timeout=2)
        self.assertTrue(marker.exists())
        pid = int(marker.read_text())
        self.addCleanup(self._kill_if_running, pid)
        self.assert_not_running(pid)
        self.assertFalse(self.c._jobs)

    @unittest.skipUnless(os.name == "posix" and sys.platform.startswith("linux"),
                         "POSIX Linux process-group qualification")
    def test_close_waits_until_child_process_group_is_terminated(self):
        token = self.opened()
        script, source, adapter = self.configured()
        marker = script.parent / "grandchild.pid"
        script.write_text(
            "import subprocess,sys,time\n"
            "from pathlib import Path\n"
            "child=subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(60)'],"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
            f"Path({str(marker)!r}).write_text(str(child.pid))\n"
            "time.sleep(60)\n", encoding="utf-8")
        errors = []
        with patch.object(jobs, "SCRIPT", script):
            def run():
                try:
                    adapter.legacy_checkpoint("reader", token, timeout=15)
                except pg.PersistenceError as exc:
                    errors.append(str(exc))
            worker = threading.Thread(target=run)
            worker.start()
            try:
                deadline = time.monotonic() + 3
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(marker.exists())
                pid = int(marker.read_text())
                self.addCleanup(self._kill_if_running, pid)
                self.c.close("writer", "A", token.generation, timeout=3)
                worker.join(3)
                self.assertFalse(worker.is_alive())
                self.assertEqual(errors, ["workspace_generation_stale"])
                self.assert_not_running(pid)
                self.assertFalse(self.c._jobs)
                self.assertEqual(self.c.state, "closed")
            finally:
                if worker.is_alive():
                    self.c._cancel.set()
                    worker.join(5)

    @staticmethod
    def _kill_if_running(pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def assert_not_running(self, pid):
        # A reparented child can briefly remain a zombie in a CI PID namespace.
        # Zombie state is not executing; Linux /proc avoids false failures.
        deadline = time.monotonic() + 2
        proc = Path("/proc") / str(pid) / "stat"
        while time.monotonic() < deadline:
            if not proc.exists():
                return
            try:
                status = proc.read_text().split(") ", 1)[1][0]
                if status in ("Z", "X"):
                    return
            except (OSError, IndexError):
                return
            time.sleep(0.03)
        self.fail("a detached legacy subprocess is still running")

if __name__ == "__main__":
    unittest.main()
