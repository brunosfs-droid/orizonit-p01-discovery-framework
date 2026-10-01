import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock

import test_portable_discovery_node as fixtures

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("p01_agent_tests", ROOT / "agent/P01_Agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)
rt = agent.runtime


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.helpers = fixtures.PortableRuntimeTests()
        self.manifest = self.helpers._manifest_for_discovery(self.root)
        self.profiles = self.root / "profiles.json"
        profiles = json.loads((ROOT / "credential_manager/credentials.example.json").read_text())
        for profile in profiles["profiles"]:
            profile["secret_refs"] = {name: "env://P01_AGENT_TEST" for name in profile["secret_refs"]}
        self.profiles.write_text(json.dumps(profiles))
        self.workspace = Path(rt.init_workspace(self.root / "runs", "A1", "R1", "NODE-01",
                                               self.manifest, self.profiles)["workspace"])
        self.policy_path = self.root / "policy.json"
        self.policy = {"schema_version": "0.5f", "identity": {"assessment_id": "A1", "run_id": "R1", "node_id": "NODE-01"}}
        self.save_policy()

    def save_policy(self, grants=None):
        if grants is not None:
            self.policy["grants"] = grants
        self.policy_path.write_text(json.dumps(self.policy))

    def preview(self):
        self.helpers._seed_completed_network(self.workspace)
        self.helpers._seed_completed_plan(self.workspace, self.profiles)
        self.helpers._seed_preview_completed(self.workspace, self.profiles)

    def full(self):
        self.preview()
        self.auth()
        self.helpers._seed_full_completed(self.workspace)

    def auth(self):
        calls = {"runs": 0, "writes": 0}
        with mock.patch.object(rt, "_load_component", return_value=self.helpers._fake_auth_executor(calls)):
            rt.run_credentialed_execution_auth_only(self.workspace, ack_authorized_access=True)

    def journals(self):
        return sorted((self.workspace / "logs/agent").glob("*.json"))

    def test_missing_grants_deny_before_dispatch(self):
        with mock.patch.object(agent, "_dispatch") as dispatch:
            result = agent.run_once(self.workspace, self.policy_path)
        self.assertEqual(result["status"], "policy_denied")
        self.assertEqual(result["stage"], "discovery")
        dispatch.assert_not_called()
        self.assertTrue(rt.verify_sidecar(Path(result["journal_path"])))

    def test_policy_strict_types_versions_unknown_fields_and_secrets(self):
        for mutation in (
            {"schema_version": "unknown"}, {"grants": {"full": "false"}},
            {"grants": {"typo": True}}, {"password": "SENTINEL"},
            {"client_key": "/SENTINEL/key.pem"}, {"secret_refs": {"password": "env://SENTINEL"}},
            {"limits": {"max_actions": True}}, {"schedule": {"kind": "cron", "interval_seconds": 60}},
            {"discovery": {"targets": ["::1"]}}, {"grants": {"discovery": True}},
        ):
            with self.subTest(mutation=mutation):
                policy = dict(self.policy, **mutation)
                self.policy_path.write_text(json.dumps(policy))
                with mock.patch.object(agent, "_dispatch") as dispatch:
                    with self.assertRaisesRegex(agent.AgentError, "^invalid_policy$"):
                        agent.run_once(self.workspace, self.policy_path)
                dispatch.assert_not_called()
        self.assertNotIn("SENTINEL", "".join(p.read_text() for p in self.journals()))

    def test_duplicate_keys_nonfinite_and_missing_policy_rejected(self):
        for text in ('{"schema_version":"0.5f","schema_version":"0.5f"}', '{"limits":{"max_hosts":NaN}}', '[]'):
            self.policy_path.write_text(text)
            with self.assertRaises(agent.AgentError):
                agent.load_policy(self.policy_path)
        self.policy_path.unlink()
        with self.assertRaisesRegex(agent.AgentError, "invalid_policy"):
            agent.run_once(self.workspace, self.policy_path)

    def test_doctor_never_opens_network_or_resolves_credentials(self):
        with mock.patch("socket.socket", side_effect=AssertionError("network")), mock.patch.object(agent, "_dispatch") as dispatch:
            result = agent.doctor(self.workspace, self.policy_path)
        self.assertTrue(result["ready"])
        self.assertFalse(result["network_activity_performed"])
        self.assertFalse(result["secret_resolution_performed"])
        dispatch.assert_not_called()

    def test_identity_state_config_and_artifact_integrity_fail_closed(self):
        original = self.policy["identity"]["node_id"]
        self.policy["identity"]["node_id"] = "OTHER"
        self.save_policy()
        with self.assertRaisesRegex(agent.AgentError, "identity_mismatch"):
            agent.run_once(self.workspace, self.policy_path)
        self.policy["identity"]["node_id"] = original
        self.save_policy()
        self.helpers._seed_completed_network(self.workspace)
        state = rt._load_state(self.workspace)
        path = self.workspace / state["artifacts"]["network_discovery"]["path"]
        path.write_text("tampered")
        with mock.patch.object(agent, "_dispatch") as dispatch:
            with self.assertRaisesRegex(agent.AgentError, "integrity_failed"):
                agent.run_once(self.workspace, self.policy_path)
        dispatch.assert_not_called()

    def test_missing_config_sidecar_fails_closed(self):
        (self.workspace / rt.CONFIG_REL).with_suffix(".json.sha256").unlink()
        with self.assertRaisesRegex(agent.AgentError, "integrity_failed"):
            agent.run_once(self.workspace, self.policy_path)

    def test_inconsistent_completed_checkpoint_never_returns_complete(self):
        state = rt._load_state(self.workspace)
        state["steps"]["upload"]["status"] = "completed"
        rt._write_state(self.workspace, state)
        with self.assertRaisesRegex(agent.AgentError, "integrity_failed"):
            agent.run_once(self.workspace, self.policy_path)

    def test_auth_denied_independent_of_full_grant(self):
        self.preview()
        self.save_policy({"full": True, "dry_run": True})
        with mock.patch.object(rt, "run_credentialed_execution_auth_only") as live:
            result = agent.run_once(self.workspace, self.policy_path)
        self.assertEqual(result["stage"], "auth_only")
        self.assertEqual(result["status"], "policy_denied")
        live.assert_not_called()

    def test_full_denied_after_auth(self):
        self.preview()
        self.auth()
        self.save_policy({"auth_only": True})
        with mock.patch.object(rt, "run_credentialed_execution_full") as live:
            result = agent.run_once(self.workspace, self.policy_path)
        self.assertEqual(result["stage"], "full")
        live.assert_not_called()

    def test_failed_or_interrupted_execution_requires_review_even_when_granted(self):
        self.preview()
        self.save_policy(dict.fromkeys(agent.STAGES, True))
        self.policy["discovery"] = {"targets": ["192.0.2.10/32"]}
        self.save_policy()
        for checkpoint in ("failed", "running"):
            state = rt._load_state(self.workspace)
            state["steps"]["credentialed_execution"].update(status=checkpoint, mode="auth_only")
            rt._write_state(self.workspace, state)
            with mock.patch.object(agent, "_dispatch") as dispatch:
                self.assertEqual(agent.run_once(self.workspace, self.policy_path)["status"], "review_required")
            dispatch.assert_not_called()

    def test_interactive_provider_denied_before_live_executor(self):
        self.preview()
        self.save_policy({"auth_only": True})
        profiles = json.loads(self.profiles.read_text())
        profiles["profiles"][0]["secret_refs"]["password"] = "prompt://SENTINEL"
        self.profiles.write_text(json.dumps(profiles))
        with mock.patch.object(rt, "run_credentialed_execution_auth_only") as live:
            with self.assertRaisesRegex(agent.AgentError, "interactive_provider_denied"):
                agent.run_once(self.workspace, self.policy_path)
        live.assert_not_called()

    def test_exception_and_transport_never_enter_journal(self):
        self.preview()
        self.save_policy({"auth_only": True})
        with mock.patch.object(rt, "run_credentialed_execution_auth_only", side_effect=ValueError("password=SENTINEL /private/SENTINEL.pem")):
            with self.assertRaisesRegex(agent.AgentError, "^runtime_failed$"):
                agent.run_once(self.workspace, self.policy_path, {"client_key": "SENTINEL"})
        text = "".join(p.read_text() for p in self.journals())
        self.assertNotIn("SENTINEL", text)
        self.assertNotIn("client_key", text)

    def test_target_tamper_blocks_completed_resume(self):
        self.full()
        state = rt._load_state(self.workspace)
        job = rt.load_json(self.workspace / state["artifacts"]["credentialed_execution_full"]["path"])
        Path(job["actions"][0]["target_result_file"]).write_text("changed")
        with self.assertRaisesRegex(agent.AgentError, "integrity_failed"):
            agent.run_once(self.workspace, self.policy_path)

    def test_schedule_is_descriptor_only(self):
        self.policy["schedule"] = {"kind": "interval", "interval_seconds": 60}
        self.save_policy()
        result = agent.doctor(self.workspace, self.policy_path)
        self.assertFalse(result["schedule_installed"])
        self.assertFalse(result["os_service_installed"])

    def test_actual_runtime_progression_stops_before_auth(self):
        self.policy["discovery"] = {"targets": ["192.0.2.10/32"]}
        self.save_policy({"discovery": True, "planning": True, "dry_run": True})
        scanner_calls = {"runs": 0}
        planner_calls = {"builds": 0, "writes": 0}
        executor_calls = {"runs": 0, "writes": 0}
        components = {
            "network_discovery/P01_Network_Discovery_Scanner.py": self.helpers._fake_scanner(scanner_calls),
            "orchestrator/P01_Credentialed_Discovery_Planner.py": self.helpers._fake_planner(planner_calls),
            "orchestrator/P01_Credentialed_Discovery_Executor.py": self.helpers._fake_executor(executor_calls),
        }
        with mock.patch.object(rt, "_load_component", side_effect=lambda path, name: components[path]):
            for stage in ("discovery", "planning", "dry_run"):
                result = agent.run_once(self.workspace, self.policy_path)
                self.assertEqual((result["stage"], result["status"]), (stage, "advanced"))
            result = agent.run_once(self.workspace, self.policy_path)
            self.assertEqual((result["stage"], result["status"]), ("auth_only", "policy_denied"))
        self.assertEqual(scanner_calls["runs"], 1)
        self.assertEqual(planner_calls["builds"], 1)
        self.assertEqual(executor_calls["runs"], 1)

    def test_actual_auth_full_resolver_export_upload_gates_and_complete_resume(self):
        self.preview()
        self.save_policy({"auth_only": True, "full": True, "resolver": True, "export": True})
        auth_calls = {"runs": 0, "writes": 0}
        full_calls = {"runs": 0, "writes": 0}
        real_loader = rt._load_component
        def loader(path, name):
            if name == "p01_runtime_credentialed_executor_auth":
                return self.helpers._fake_auth_executor(auth_calls)
            if name == "p01_runtime_credentialed_executor_full":
                return self.helpers._fake_full_executor(full_calls)
            return real_loader(path, name)
        with mock.patch.object(rt, "_load_component", side_effect=loader):
            for stage in ("auth_only", "full", "resolver", "export"):
                result = agent.run_once(self.workspace, self.policy_path)
                self.assertEqual((result["stage"], result["status"]), (stage, "advanced"))
        # Export's exact external manifest binding is supported without a sidecar.
        self.assertEqual(agent.run_once(self.workspace, self.policy_path)["status"], "policy_denied")
        self.save_policy({"upload": True})
        with self.assertRaisesRegex(agent.AgentError, "transport_required"):
            agent.run_once(self.workspace, self.policy_path)
        transport = {"server_url": "https://server.example:8443"}
        for name in ("ca_cert", "client_cert", "client_key"):
            path = self.root / (name + "-SENTINEL.pem")
            path.write_text("test transport fixture")
            transport[name] = path
        upload = mock.Mock(return_value={"status": "success", "http_status": 201, "attempts": 1,
            "server_response": {"status": "imported", "semantic_match": True, "authenticated_node_id": "NODE-01"}})
        def write_receipt(outdir, *args):
            path = outdir / "fixture.json"
            rt.write_json_with_sidecar(path, {"status": "imported"})
            return path, path.with_suffix(".json.sha256")
        fake = types.SimpleNamespace(bundle_manifest=lambda bundle: {"node_id": "NODE-01"},
                                     upload_with_retries=upload, write_receipt=write_receipt)
        with mock.patch.object(rt, "_load_component", return_value=fake):
            result = agent.run_once(self.workspace, self.policy_path, transport)
            self.assertEqual((result["stage"], result["status"]), ("upload", "advanced"))
        upload.assert_called_once()
        self.assertNotIn("SENTINEL", "".join(p.read_text() for p in self.journals()))
        self.assertNotIn("client_key-SENTINEL", (self.workspace / rt.STATE_REL).read_text())
        self.save_policy({})
        with mock.patch.object(agent, "_dispatch") as dispatch:
            result = agent.run_once(self.workspace, self.policy_path)
        self.assertEqual(result["status"], "already_complete")
        dispatch.assert_not_called()
        self.assertEqual(auth_calls["runs"], 1)
        self.assertEqual(full_calls["runs"], 1)

    def test_policy_change_rechecked_at_each_invocation(self):
        self.preview()
        self.save_policy({"auth_only": True})
        self.assertEqual(agent.agent_status(self.workspace, self.policy_path)["status"], "ready")
        self.save_policy({"auth_only": False})
        with mock.patch.object(rt, "run_credentialed_execution_auth_only") as live:
            self.assertEqual(agent.run_once(self.workspace, self.policy_path)["status"], "policy_denied")
        live.assert_not_called()

    def test_external_evidence_path_rejected(self):
        self.helpers._seed_completed_network(self.workspace)
        state = rt._load_state(self.workspace)
        source = self.workspace / state["artifacts"]["network_discovery"]["path"]
        external = self.root / "outside.json"
        rt.write_json_with_sidecar(external, rt.load_json(source))
        state["artifacts"]["network_discovery"] = rt._artifact_ref(external)
        rt._write_state(self.workspace, state)
        with self.assertRaisesRegex(agent.AgentError, "integrity_failed"):
            agent.run_once(self.workspace, self.policy_path)

    def test_discovery_grant_cannot_expand_manifest_scope(self):
        self.policy["discovery"] = {"targets": ["198.51.100.10/32"]}
        self.save_policy({"discovery": True})
        calls = {"runs": 0}
        with mock.patch.object(rt, "_load_component", return_value=self.helpers._fake_scanner(calls)):
            with self.assertRaisesRegex(agent.AgentError, "runtime_failed"):
                agent.run_once(self.workspace, self.policy_path)
        self.assertEqual(calls["runs"], 0)

    def test_partial_auth_is_not_retried_on_next_invocation(self):
        self.preview()
        self.save_policy({"auth_only": True})
        def partial(workspace, **kwargs):
            state = rt._load_state(workspace)
            state["steps"]["credentialed_execution"].update(status="failed", mode="auth_only")
            rt._write_state(workspace, state)
            raise rt.RuntimeErrorSafe("partial")
        with mock.patch.object(rt, "run_credentialed_execution_auth_only", side_effect=partial) as live:
            with self.assertRaisesRegex(agent.AgentError, "runtime_failed"):
                agent.run_once(self.workspace, self.policy_path)
            self.assertEqual(agent.run_once(self.workspace, self.policy_path)["status"], "review_required")
        live.assert_called_once()

    def test_interrupted_dispatch_intent_blocks_replay_when_runtime_still_pending(self):
        self.preview()
        self.save_policy({"auth_only": True})
        with mock.patch.object(agent, "_dispatch", side_effect=KeyboardInterrupt) as dispatch:
            with self.assertRaises(KeyboardInterrupt):
                agent.run_once(self.workspace, self.policy_path)
            self.assertEqual(rt._load_state(self.workspace)["steps"]["credentialed_execution"]["status"], "preview_completed")
            self.assertEqual(agent.run_once(self.workspace, self.policy_path)["status"], "review_required")
            self.assertEqual(agent.agent_status(self.workspace, self.policy_path)["status"], "review_required")
        dispatch.assert_called_once()

    def test_journal_tamper_fails_closed(self):
        result = agent.run_once(self.workspace, self.policy_path)
        Path(result["journal_path"]).write_text("tampered")
        with self.assertRaisesRegex(agent.AgentError, "journal_integrity_failed"):
            agent.run_once(self.workspace, self.policy_path)

    def test_cross_process_lock_blocks_agent_and_portable_mutation(self):
        code = "import sys;sys.path.insert(0,sys.argv[1]);from P01_Workspace_Lock import workspace_lock;from pathlib import Path\nwith workspace_lock(Path(sys.argv[2])):\n print('locked',flush=True)\n sys.stdin.readline()\n"
        child = subprocess.Popen([sys.executable, "-c", code, str(ROOT / "runtime"), str(self.workspace)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), "locked")
            with self.assertRaises(agent.WorkspaceBusy):
                agent.run_once(self.workspace, self.policy_path)
            with self.assertRaises(agent.WorkspaceBusy):
                rt.run_credential_plan(self.workspace)
            self.assertFalse(self.journals())
        finally:
            child.communicate("release\n", timeout=10)
        self.assertEqual(agent.run_once(self.workspace, self.policy_path)["status"], "policy_denied")

    def test_process_crash_releases_lock_without_unlinking_inode(self):
        code = "import sys,os;sys.path.insert(0,sys.argv[1]);from P01_Workspace_Lock import workspace_lock\nwith workspace_lock(sys.argv[2]):os._exit(7)"
        result = subprocess.run([sys.executable, "-c", code, str(ROOT / "runtime"), str(self.workspace)], timeout=10)
        self.assertEqual(result.returncode, 7)
        self.assertTrue((self.workspace / ".canca-workspace.lock").exists())
        self.assertEqual(agent.run_once(self.workspace, self.policy_path)["status"], "policy_denied")

    def test_thread_exclusion_and_same_thread_reentrancy(self):
        errors = []
        with agent.workspace_lock(self.workspace):
            with agent.workspace_lock(self.workspace):
                self.assertEqual(agent.run_once(self.workspace, self.policy_path)["status"], "policy_denied")
            def attempt():
                try:
                    with agent.workspace_lock(self.workspace):
                        errors.append("unexpected")
                except agent.WorkspaceBusy:
                    errors.append("busy")
            thread = threading.Thread(target=attempt)
            thread.start()
            thread.join(timeout=5)
        self.assertEqual(errors, ["busy"])


if __name__ == "__main__":
    unittest.main()
