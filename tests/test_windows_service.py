import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
import P01_Windows_Service as service


class WindowsServiceContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.workspace = Path(service.agent.runtime.init_workspace(root, "S1", "R1", "NODE-01")["workspace"])
        self.policy = self.workspace / "config/agent-policy.json"
        self.policy.write_text(json.dumps({"schema_version": "0.5f", "identity": {
            "assessment_id": "S1", "run_id": "R1", "node_id": "NODE-01"}, "grants": {}}))
        self.config = root / "service.json"
        self.doc = {"schema_version": "0.5f.1", "workspace": str(self.workspace), "policy": str(self.policy)}
        self.config.write_text(json.dumps(self.doc))

    def test_strict_config_rejects_extra_duplicate_version_relative_external_and_unc(self):
        for doc in (dict(self.doc, password="SENTINEL"), dict(self.doc, schema_version="unknown"),
                    dict(self.doc, workspace="relative"), dict(self.doc, policy=str(self.config)),
                    dict(self.doc, workspace=r"\\server\share")):
            self.config.write_text(json.dumps(doc))
            with self.assertRaisesRegex(service.ServiceError, "^service_config_invalid$"):
                service.load_config(self.config)
        self.config.write_text('{"schema_version":"0.5f.1","schema_version":"0.5f.1"}')
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

    def test_binary_command_quotes_interpreter_script_and_config(self):
        path = Path(self.temp.name) / "config with spaces.json"
        command = service.binary_path(path)
        self.assertIn('"' + str(path.resolve()) + '"', command)
        self.assertIn(" host --config ", command)
        self.assertNotIn("server-url", command)


if __name__ == "__main__":
    unittest.main()
