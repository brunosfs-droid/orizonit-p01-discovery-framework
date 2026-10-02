import json
import subprocess
import time
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
import P01_Linux_Service as service


@unittest.skipUnless(sys.platform == "linux", "Linux host path contracts")
class LinuxServiceContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.workspace = Path(service.agent.runtime.init_workspace(root, "S1", "R1", "NODE-01")["workspace"])
        self.policy = self.workspace / "config/agent-policy.json"
        self.policy.write_text(json.dumps({"schema_version": "0.5f", "identity": {
            "assessment_id": "S1", "run_id": "R1", "node_id": "NODE-01"}, "grants": {}}))
        self.config = root / "service.json"
        self.doc = {"schema_version": "0.5f.2", "workspace": str(self.workspace), "policy": str(self.policy)}
        self.config.write_text(json.dumps(self.doc))

    def test_strict_config_rejects_extra_duplicate_version_relative_external_and_unc(self):
        for doc in (dict(self.doc, password="SENTINEL"), dict(self.doc, schema_version="unknown"),
                    dict(self.doc, workspace="relative"), dict(self.doc, policy=str(self.config)),
                    dict(self.doc, workspace=r"\\server\share")):
            self.config.write_text(json.dumps(doc))
            with self.assertRaisesRegex(service.ServiceError, "^service_config_invalid$"):
                service.load_config(self.config)
        self.config.write_text('{"schema_version":"0.5f.2","schema_version":"0.5f.2"}')
        with self.assertRaises(service.ServiceError):
            service.load_config(self.config)

    def test_stop_before_invocation_never_reads_config_or_dispatches(self):
        stop = threading.Event()
        stop.set()
        with mock.patch.object(service, "load_config") as read, mock.patch.object(service.agent, "run_once") as run:
            result = service.invoke_once(self.config, stop)
        self.assertEqual(result["status"], "stopped_before_invocation")
        read.assert_not_called()
        run.assert_not_called()

    def test_worker_is_one_invocation_preserves_state_and_has_no_dispatch(self):
        rt = service.agent.runtime
        before = (self.workspace / rt.STATE_REL).read_bytes()
        done, stop, output = threading.Event(), threading.Event(), {}
        with mock.patch.object(service.agent, "_dispatch") as dispatch:
            service.worker(self.config, stop, done, output)
        self.assertTrue(done.is_set())
        self.assertEqual(output, {"status": "policy_denied", "stage": "discovery", "error_code": None})
        self.assertEqual(len(list((self.workspace / "logs/agent").glob("*.json"))), 1)
        self.assertEqual((self.workspace / rt.STATE_REL).read_bytes(), before)
        dispatch.assert_not_called()

    def test_running_intent_requires_review_in_service_and_remains_preserved(self):
        rt = service.agent.runtime
        intent = self.workspace / "logs/agent/intent.json"
        rt.write_json_with_sidecar(intent, {"schema_version": "0.5f", "status": "running"})
        with mock.patch.object(service.agent, "_dispatch") as dispatch:
            for _ in range(2):
                result = service.invoke_once(self.config, threading.Event())
                self.assertEqual(result["status"], "review_required")
        self.assertEqual(rt.load_json(intent)["status"], "running")
        dispatch.assert_not_called()

    def test_no_raw_errors_transport_paths_or_result_fields_escape_worker(self):
        for exc, code in ((RuntimeError("password=SENTINEL /private/SENTINEL.key"), "service_failed"),
                          (service.agent.AgentError("transport_required"), "transport_required"),
                          (service.agent.WorkspaceBusy("workspace_busy"), "workspace_busy")):
            with mock.patch.object(service.agent, "run_once", side_effect=exc):
                result = service.invoke_once(self.config, threading.Event())
            self.assertEqual(result["error_code"], code)
            self.assertNotIn("SENTINEL", json.dumps(result))
        with mock.patch.object(service.agent, "run_once", return_value={"status": "advanced", "stage": "full", "client_key": "SENTINEL"}) as run:
            result = service.invoke_once(self.config, threading.Event())
        run.assert_called_once_with(self.workspace, self.policy)
        self.assertEqual(set(result), {"status", "stage", "error_code"})
        self.assertNotIn("SENTINEL", json.dumps(result))

    def test_invalid_worker_result_is_fixed_failure_without_retry(self):
        with mock.patch.object(service.agent, "run_once", return_value={"status": "SENTINEL"}) as run:
            result = service.invoke_once(self.config, threading.Event())
        self.assertEqual(result["error_code"], "service_failed")
        self.assertEqual(run.call_count, 1)

    def test_unit_pins_paths_and_has_no_install_timer_recovery_or_transport(self):
        unit = service.unit_text(self.config)
        self.assertIn('ExecStart="' + str(Path(sys.executable).resolve()) + '"', unit)
        self.assertIn('"host" "--config" "' + str(self.config) + '"', unit)
        for text in ("Restart=no", "ProtectSystem=strict", "ProtectHome=yes", "TimeoutStopSec=infinity", "KillMode=mixed", "User=canca-agent"):
            self.assertIn(text, unit)
        self.assertNotIn("WantedBy=", unit)
        self.assertNotIn("server-url", unit)
        writable = next(line for line in unit.splitlines() if line.startswith("ReadWritePaths="))
        self.assertNotIn(str(self.workspace / "config"), writable)
        self.assertIn(str(self.workspace / ".canca-workspace.lock"), writable)
        for value in ("/path/%i", "/path/$VALUE", "/path/line\nnext"):
            with self.assertRaises(service.ServiceError):
                service.quote(value)
        self.assertEqual(service.quote('/path/with "quote"'), '\"/path/with \\"quote\\"\"')

    def test_dropins_enabled_or_foreign_fragment_block_controls(self):
        raw = "LoadState=loaded\nActiveState=inactive\nMainPID=0\nFragmentPath=" + str(service.UNIT_PATH) + "\nDropInPaths=\nUnitFileState=static\nUser=canca-agent\nGroup=canca-agent\nRestart=no\n"
        with mock.patch.object(service, "systemctl", return_value=raw), mock.patch.object(Path, "read_text", return_value=service.unit_text(self.config)):
            self.assertTrue(service.inspect_service(self.config)["configuration_matches"])
        for altered in (raw.replace("DropInPaths=", "DropInPaths=/override.conf"), raw.replace("static", "enabled"), raw.replace("Restart=no", "Restart=always"), raw.replace(str(service.UNIT_PATH), "/other/unit"), raw.replace("User=canca-agent", "User=root")):
            with mock.patch.object(service, "require_root"), mock.patch.object(service, "systemctl", return_value=altered) as call, mock.patch.object(Path, "read_text", return_value=service.unit_text(self.config)):
                for action in ("start", "stop", "remove"):
                    with self.assertRaisesRegex(service.ServiceError, "^service_configuration_mismatch$"):
                        service.control(action, self.config)
                self.assertTrue(all(args.args[0] == "show" for args in call.call_args_list))

    def test_systemd_failure_is_not_absent_unit(self):
        with mock.patch.object(service, "systemctl", return_value=""):
            with self.assertRaisesRegex(service.ServiceError, "^systemd_unavailable$"):
                service.inspect_service()

    def test_real_host_exits_on_sigterm_after_single_denied_invocation(self):
        process = subprocess.Popen([sys.executable, service.__file__, "host", "--config", str(self.config)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 10
            journals = self.workspace / "logs/agent"
            while not list(journals.glob("*.json")) and time.monotonic() < deadline:
                self.assertIsNone(process.poll())
                time.sleep(0.02)
            self.assertEqual(len(list(journals.glob("*.json"))), 1)
            process.terminate()
            output, error = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, error)
            self.assertIn('"status": "policy_denied"', output)
            self.assertEqual(len(list(journals.glob("*.json"))), 1)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()


if __name__ == "__main__":
    unittest.main()
