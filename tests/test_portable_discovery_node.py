import hashlib
import importlib.util
import json
import pathlib
import tempfile
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
path = ROOT / "runtime" / "P01_Discovery_Node.py"
spec = importlib.util.spec_from_file_location("p01_portable_runtime", path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def write_json(path, payload, sidecar=True):
    raw = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    if sidecar:
        sha = hashlib.sha256(raw).hexdigest()
        path.with_suffix(path.suffix + ".sha256").write_text(
            f"{sha}  {path.name}\n",
            encoding="utf-8",
        )
    return path


class PortableRuntimeTests(unittest.TestCase):
    def test_init_creates_isolated_workspace_and_integrity(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td) / "runs with spaces"
            result = mod.init_workspace(
                root,
                "ASSESS-001",
                "RUN-001",
                "NODE-01",
            )
            workspace = pathlib.Path(result["workspace"])
            self.assertEqual(result["status"], "initialized")
            for name in mod.WORKSPACE_DIRS:
                self.assertTrue((workspace / name).is_dir())
            self.assertTrue(mod.verify_sidecar(workspace / mod.STATE_REL))
            self.assertTrue(mod.verify_sidecar(workspace / mod.CONFIG_REL))
            state = mod._load_state(workspace)
            self.assertEqual(state["steps"]["network_discovery"]["status"], "pending")
            self.assertEqual(state["steps"]["credential_plan"]["status"], "pending")
            self.assertEqual(state["steps"]["credentialed_execution"]["status"], "pending")
            self.assertEqual(state["steps"]["asset_resolver"]["status"], "pending")
            self.assertEqual(state["steps"]["evidence_bundle"]["status"], "pending")
            self.assertEqual(state["steps"]["upload"]["status"], "pending")
            self.assertTrue(state["security"]["active_discovery_managed_in_this_version"])
            self.assertTrue(
                state["security"]["credentialed_execution_dry_run_managed_in_this_version"]
            )
            self.assertTrue(
                state["security"]["credentialed_execution_auth_only_managed_in_this_version"]
            )
            self.assertTrue(
                state["security"]["credentialed_execution_full_managed_in_this_version"]
            )
            self.assertTrue(
                state["security"]["asset_resolver_managed_in_this_version"]
            )
            self.assertFalse(state["security"]["plaintext_credentials_persisted"])

    def test_init_is_idempotent_for_same_identity(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            first = mod.init_workspace(root, "A1", "R1", "N1")
            second = mod.init_workspace(root, "A1", "R1", "N1")
            self.assertEqual(first["workspace"], second["workspace"])
            self.assertEqual(second["status"], "already_initialized")

    def test_secret_material_rejected_from_state_config(self):
        with self.assertRaises(mod.RuntimeErrorSafe):
            mod.assert_no_secret_material({"password": "example"})
        with self.assertRaises(mod.RuntimeErrorSafe):
            mod.assert_no_secret_material({"value": "wincred://EXAMPLE/secret"})
        with self.assertRaises(mod.RuntimeErrorSafe):
            mod.assert_no_secret_material({"value": "-----BEGIN PRIVATE KEY-----"})
        mod.assert_no_secret_material({"private_key_material_persisted": False})

    def test_state_sidecar_tamper_detected(self):
        with tempfile.TemporaryDirectory() as td:
            result = mod.init_workspace(pathlib.Path(td), "A1", "R1", "N1")
            workspace = pathlib.Path(result["workspace"])
            state_path = workspace / mod.STATE_REL
            state_path.write_text("{}\n", encoding="utf-8")
            with self.assertRaises(mod.RuntimeErrorSafe):
                mod._load_state(workspace)

    def test_status_next_action_starts_with_managed_discovery(self):
        with tempfile.TemporaryDirectory() as td:
            result = mod.init_workspace(pathlib.Path(td), "A1", "R1", "N1")
            workspace = pathlib.Path(result["workspace"])
            current = mod.status(workspace)
            self.assertEqual(current["next_action"], "run_network_discovery")

            state = mod._load_state(workspace)
            state["steps"]["network_discovery"] = {"status": "completed"}
            mod._write_state(workspace, state)
            current = mod.status(workspace)
            self.assertEqual(current["next_action"], "run_credential_plan")

    def _synthetic_inputs(self, td):
        td = pathlib.Path(td)
        network = write_json(
            td / "P01-Network-Discovery_TEST.json",
            {
                "metadata": {
                    "scanner_name": "P01-Network-Discovery-Scanner",
                    "scanner_version": "0.4.1",
                    "schema_version": "0.4",
                    "run_label": "LAB-NET",
                },
                "assets": [{"ip": "192.0.2.10"}],
            },
        )
        evidence_dir = td / "targets"
        cred = write_json(
            evidence_dir / "P01-Credentialed-Target_192.0.2.10_winrm_RUNTIME-FULL.json",
            {
                "metadata": {
                    "executor_name": "P01-Credentialed-Discovery-Executor",
                    "executor_version": "0.4b.5",
                    "schema_version": "0.4b.5",
                    "run_label": "RUNTIME-FULL",
                    "secret_values_persisted_to_output": False,
                },
                "action": {"target_ip": "192.0.2.10"},
                "authentication": {"success": True},
            },
        )
        resolver = write_json(
            td / "P01-Asset-Resolver_TEST.json",
            {
                "metadata": {
                    "resolver_name": "P01-Asset-Resolver",
                    "resolver_version": "0.4c.0",
                    "schema_version": "0.4c",
                    "run_label": "LAB-RES",
                    "secret_resolution": False,
                },
                "summary": {"logical_assets_resolved": 1},
                "assets": [],
            },
        )
        manifest = write_json(
            td / "assessment.json",
            {
                "schema_version": "0.4b.6",
                "assessment_id": "A1",
                "authorized_scopes": ["192.0.2.0/24"],
            },
            sidecar=False,
        )
        return network, evidence_dir, cred, resolver, manifest

    def _manifest_for_discovery(self, td, authorized=None, excludes=None):
        td = pathlib.Path(td)
        manifest = td / "assessment-discovery.json"
        return write_json(
            manifest,
            {
                "schema_version": "0.4b.6",
                "assessment_id": "A1",
                "authorized_scopes": authorized or ["192.0.2.0/24"],
                "exclude_scopes": excludes or [],
                "domains": [],
                "allowed_protocols": ["ssh", "winrm"],
                "safety_policy": {
                    "default_concurrency": 1,
                    "max_actions": 25,
                    "require_authorized_ack": True,
                    "auto_expand_scope": False,
                },
            },
            sidecar=False,
        )

    def _fake_scanner(self, calls):
        import ipaddress

        def resolve_scope(targets, excludes):
            target_ips = []
            for raw in targets:
                net = ipaddress.ip_network(raw, strict=False)
                target_ips.extend(str(ip) for ip in net.hosts())
                if net.prefixlen == 32:
                    target_ips.append(str(net.network_address))
            excluded = set()
            for raw in excludes:
                net = ipaddress.ip_network(raw, strict=False)
                excluded.update(str(ip) for ip in net.hosts())
                if net.prefixlen == 32:
                    excluded.add(str(net.network_address))
            values = sorted(set(target_ips) - excluded, key=ipaddress.ip_address)
            return values, sorted(excluded, key=ipaddress.ip_address)

        def main(argv):
            calls["runs"] += 1
            output_dir = pathlib.Path(argv[argv.index("--output-dir") + 1])
            run_label = argv[argv.index("--run-label") + 1]
            targets = [argv[i + 1] for i, value in enumerate(argv) if value == "--target"]
            effective, _ = resolve_scope(
                targets,
                [argv[i + 1] for i, value in enumerate(argv) if value == "--exclude"],
            )
            path = output_dir / f"P01-Network-Discovery_TEST_{run_label}.json"
            write_json(
                path,
                {
                    "metadata": {
                        "scanner_name": "P01-Network-Discovery-Scanner",
                        "scanner_version": "0.4.1",
                        "schema_version": "0.4",
                        "run_label": run_label,
                    },
                    "summary": {"hosts_discovered": len(effective)},
                    "assets": [{"ip": ip} for ip in effective],
                },
                sidecar=True,
            )
            return 0

        return types.SimpleNamespace(resolve_scope=resolve_scope, main=main)

    def test_managed_discovery_requires_ack_and_authorized_scope(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = self._manifest_for_discovery(td)
            init = mod.init_workspace(
                pathlib.Path(td) / "runs",
                "A1",
                "R1",
                "NODE-01",
                manifest=manifest,
            )
            workspace = pathlib.Path(init["workspace"])
            calls = {"runs": 0}
            fake = self._fake_scanner(calls)

            with mock.patch.object(mod, "_load_component", return_value=fake):
                with self.assertRaises(mod.RuntimeErrorSafe):
                    mod.run_network_discovery(
                        workspace,
                        ["192.0.2.0/30"],
                        [],
                        ack_authorized_scan=False,
                    )
                with self.assertRaises(mod.RuntimeErrorSafe):
                    mod.run_network_discovery(
                        workspace,
                        ["198.51.100.0/30"],
                        [],
                        ack_authorized_scan=True,
                    )
            self.assertEqual(calls["runs"], 0)

    def test_managed_discovery_is_resume_safe_and_honors_manifest_excludes(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = self._manifest_for_discovery(
                td,
                authorized=["192.0.2.0/29"],
                excludes=["192.0.2.2/32"],
            )
            init = mod.init_workspace(
                pathlib.Path(td) / "runs",
                "A1",
                "R1",
                "NODE-01",
                manifest=manifest,
            )
            workspace = pathlib.Path(init["workspace"])
            calls = {"runs": 0}
            fake = self._fake_scanner(calls)

            with mock.patch.object(mod, "_load_component", return_value=fake):
                first = mod.run_network_discovery(
                    workspace,
                    ["192.0.2.0/29"],
                    [],
                    ack_authorized_scan=True,
                )
                second = mod.run_network_discovery(
                    workspace,
                    ["192.0.2.0/29"],
                    [],
                    ack_authorized_scan=True,
                )

            self.assertEqual(first["status"], "completed")
            self.assertEqual(second["status"], "already_complete")
            self.assertTrue(first["network_activity_performed"])
            self.assertFalse(second["network_activity_performed"])
            self.assertEqual(calls["runs"], 1)

            state = mod._load_state(workspace)
            self.assertEqual(state["steps"]["network_discovery"]["status"], "completed")
            artifact = state["artifacts"]["network_discovery"]
            self.assertIn("192.0.2.2/32", artifact["excludes"])
            self.assertEqual(mod.status(workspace)["next_action"], "run_credential_plan")

    def _fake_planner(self, calls):
        def load_json(path):
            return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))

        def load_profiles(path):
            return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))

        def load_manifest(path):
            return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))

        def build_plan(discovery, profiles, realm_map=None, max_candidates=2, manifest=None):
            calls["builds"] += 1
            return {
                "metadata": {
                    "planner_name": "P01-Credentialed-Discovery-Planner",
                    "planner_version": "0.4b.3.2",
                    "secret_resolution": False,
                    "authentication_attempts": False,
                    "assessment_id": manifest.get("assessment_id") if manifest else None,
                },
                "source": {
                    "scanner_name": discovery.get("metadata", {}).get("scanner_name"),
                    "scanner_version": discovery.get("metadata", {}).get("scanner_version"),
                    "run_label": discovery.get("metadata", {}).get("run_label"),
                },
                "summary": {
                    "assets_seen": 1,
                    "assets_with_protocols": 1,
                    "adapter_candidates": 1,
                    "assets_with_adapter_candidates": 1,
                    "assets_skipped_no_protocol": 0,
                    "assets_skipped_no_profile": 0,
                    "protocols": ["ssh"],
                },
                "assets": [],
            }

        def write_output(output_dir, run_label, payload):
            calls["writes"] += 1
            output_dir = pathlib.Path(output_dir)
            path = output_dir / f"P01-Credential-Plan_TEST_{run_label}.json"
            write_json(path, payload, sidecar=True)
            return path, path.with_suffix(path.suffix + ".sha256")

        return types.SimpleNamespace(
            load_json=load_json,
            load_profiles=load_profiles,
            load_manifest=load_manifest,
            build_plan=build_plan,
            write_output=write_output,
        )

    def _seed_completed_network(self, workspace):
        network = write_json(
            pathlib.Path(workspace) / "evidence" / "network" / "P01-Network-Discovery_TEST.json",
            {
                "metadata": {
                    "scanner_name": "P01-Network-Discovery-Scanner",
                    "scanner_version": "0.4.1",
                    "schema_version": "0.4",
                    "run_label": "RUNTIME-NETWORK",
                },
                "summary": {"hosts_discovered": 1},
                "assets": [{"ip": "192.0.2.10"}],
            },
            sidecar=True,
        )
        state = mod._load_state(pathlib.Path(workspace))
        state["steps"]["network_discovery"] = {
            "status": "completed",
            "completed_at_utc": mod.utc_now_iso(),
            "managed_by": "0.5e.1",
        }
        state["artifacts"]["network_discovery"] = {
            "path": mod._relative_if_owned(pathlib.Path(workspace), network),
            "sha256_path": mod._relative_if_owned(
                pathlib.Path(workspace),
                network.with_suffix(network.suffix + ".sha256"),
            ),
            "sha256": mod.digest_file(network),
            "hosts_discovered": 1,
        }
        mod._write_state(pathlib.Path(workspace), state)
        return network

    def test_managed_credential_plan_is_resume_safe_and_migrates_external_state(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = self._manifest_for_discovery(td)
            profiles = write_json(
                pathlib.Path(td) / "profiles.json",
                {"schema_version": "0.4b.6", "profiles": []},
                sidecar=False,
            )
            init = mod.init_workspace(
                pathlib.Path(td) / "runs",
                "A1",
                "R1",
                "NODE-01",
                manifest=manifest,
                profiles=profiles,
            )
            workspace = pathlib.Path(init["workspace"])
            self._seed_completed_network(workspace)

            state = mod._load_state(workspace)
            state["steps"]["credential_plan"] = {
                "status": "external_required",
                "managed_from_version": "0.5e.1",
            }
            mod._write_state(workspace, state)

            calls = {"builds": 0, "writes": 0}
            fake = self._fake_planner(calls)
            with mock.patch.object(mod, "_load_component", return_value=fake):
                first = mod.run_credential_plan(workspace, max_candidates=2)
                second = mod.run_credential_plan(workspace, max_candidates=2)

            self.assertEqual(first["status"], "completed")
            self.assertEqual(second["status"], "already_complete")
            self.assertEqual(calls["builds"], 1)
            self.assertEqual(calls["writes"], 1)
            self.assertFalse(first["network_activity_performed"])
            self.assertFalse(first["secret_resolution_performed"])
            self.assertFalse(first["authentication_attempts_performed"])

            state = mod._load_state(workspace)
            self.assertEqual(state["steps"]["credential_plan"]["status"], "completed")
            self.assertEqual(
                mod.status(workspace)["next_action"],
                "run_credentialed_execution_dry_run",
            )
            artifact = state["artifacts"]["credential_plan"]
            plan_path = mod._workspace_owned_path(workspace, artifact["path"])
            self.assertTrue(plan_path.is_file())
            self.assertTrue(mod.verify_sidecar(plan_path))

    def test_managed_credential_plan_rejects_changed_network_artifact(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = self._manifest_for_discovery(td)
            profiles = write_json(
                pathlib.Path(td) / "profiles.json",
                {"schema_version": "0.4b.6", "profiles": []},
                sidecar=False,
            )
            init = mod.init_workspace(
                pathlib.Path(td) / "runs",
                "A1",
                "R1",
                "NODE-01",
                manifest=manifest,
                profiles=profiles,
            )
            workspace = pathlib.Path(init["workspace"])
            network = self._seed_completed_network(workspace)
            network.write_text("{}\n", encoding="utf-8")

            with self.assertRaises(mod.RuntimeErrorSafe) as ctx:
                mod.run_credential_plan(workspace)
            self.assertIn("SHA256", str(ctx.exception))

    def test_managed_credential_plan_requires_profiles_reference(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = self._manifest_for_discovery(td)
            init = mod.init_workspace(
                pathlib.Path(td) / "runs",
                "A1",
                "R1",
                "NODE-01",
                manifest=manifest,
            )
            workspace = pathlib.Path(init["workspace"])
            self._seed_completed_network(workspace)

            with self.assertRaises(mod.RuntimeErrorSafe) as ctx:
                mod.run_credential_plan(workspace)
            self.assertIn("Credential Profiles", str(ctx.exception))

    def _seed_completed_plan(self, workspace, profiles):
        plan = write_json(
            pathlib.Path(workspace) / "evidence" / "credential_plan" / "P01-Credential-Plan_TEST.json",
            {
                "metadata": {
                    "planner_name": "P01-Credentialed-Discovery-Planner",
                    "planner_version": "0.4b.3.2",
                    "secret_resolution": False,
                    "authentication_attempts": False,
                },
                "source": {"run_label": "RUNTIME-NETWORK"},
                "summary": {
                    "assets_seen": 1,
                    "adapter_candidates": 1,
                },
                "assets": [],
            },
            sidecar=True,
        )
        state = mod._load_state(pathlib.Path(workspace))
        state["steps"]["credential_plan"] = {
            "status": "completed",
            "completed_at_utc": mod.utc_now_iso(),
            "managed_by": "0.5e.2",
        }
        state["artifacts"]["credential_plan"] = {
            "path": mod._relative_if_owned(pathlib.Path(workspace), plan),
            "sha256_path": mod._relative_if_owned(
                pathlib.Path(workspace),
                plan.with_suffix(plan.suffix + ".sha256"),
            ),
            "sha256": mod.digest_file(plan),
            "credential_profiles_sha256": mod.digest_file(profiles),
            "assets_seen": 1,
            "adapter_candidates": 1,
        }
        mod._write_state(pathlib.Path(workspace), state)
        return plan

    def _fake_executor(self, calls):
        def load(path):
            return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))

        def load_profiles(path):
            return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))

        def run_job(
            plan,
            profiles,
            plan_hash,
            outdir,
            run_label,
            execute=False,
            auth_only=False,
            max_actions=25,
            known_hosts=None,
            hostkey="strict",
        ):
            calls["runs"] += 1
            self.assertFalse(execute)
            self.assertFalse(auth_only)
            return {
                "metadata": {
                    "executor_name": "P01-Credentialed-Discovery-Executor",
                    "executor_version": "0.4b.5",
                    "schema_version": "0.4b",
                    "execution_mode": "dry_run",
                    "auth_only": False,
                    "read_only_mode": True,
                    "secret_resolution": False,
                    "authentication_attempts": False,
                    "plan_sha256": plan_hash,
                    "concurrency": 1,
                },
                "summary": {
                    "actions_total": 1,
                    "actions_ready": 1,
                    "actions_blocked_preflight": 0,
                    "dry_run_ready": 1,
                    "completed": 0,
                    "skipped": 0,
                    "authentication_successes": 0,
                    "authentication_failures": 0,
                    "open_credential_circuits": 0,
                },
                "actions": [{"execution_status": "dry_run_ready"}],
                "credential_circuits": {},
                "limitations": [],
            }

        def write(path, payload):
            calls["writes"] += 1
            path = pathlib.Path(path)
            write_json(path, payload, sidecar=True)
            return (
                path,
                path.with_suffix(path.suffix + ".sha256"),
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )

        return types.SimpleNamespace(
            load=load,
            load_profiles=load_profiles,
            run_job=run_job,
            write=write,
        )

    def test_managed_executor_dry_run_is_resume_safe_and_migrates_external_state(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = self._manifest_for_discovery(td)
            profiles = write_json(
                pathlib.Path(td) / "profiles.json",
                {"schema_version": "0.4b.6", "profiles": []},
                sidecar=False,
            )
            init = mod.init_workspace(
                pathlib.Path(td) / "runs",
                "A1",
                "R1",
                "NODE-01",
                manifest=manifest,
                profiles=profiles,
            )
            workspace = pathlib.Path(init["workspace"])
            self._seed_completed_network(workspace)
            self._seed_completed_plan(workspace, profiles)

            state = mod._load_state(workspace)
            state["steps"]["credentialed_execution"] = {
                "status": "external_required",
                "managed_from_version": "0.5e.3",
            }
            mod._write_state(workspace, state)

            calls = {"runs": 0, "writes": 0}
            fake = self._fake_executor(calls)
            with mock.patch.object(mod, "_load_component", return_value=fake):
                first = mod.run_credentialed_execution_dry_run(workspace, max_actions=25)
                second = mod.run_credentialed_execution_dry_run(workspace, max_actions=25)

            self.assertEqual(first["status"], "preview_completed")
            self.assertEqual(second["status"], "already_complete")
            self.assertEqual(calls["runs"], 1)
            self.assertEqual(calls["writes"], 1)
            self.assertEqual(first["actions_total"], 1)
            self.assertEqual(first["actions_ready"], 1)
            self.assertFalse(first["network_activity_performed"])
            self.assertFalse(first["secret_resolution_performed"])
            self.assertFalse(first["authentication_attempts_performed"])

            state = mod._load_state(workspace)
            self.assertEqual(
                state["steps"]["credentialed_execution"]["status"],
                "preview_completed",
            )
            self.assertEqual(
                mod.status(workspace)["next_action"],
                "run_credentialed_execution_auth_only",
            )
            artifact = state["artifacts"]["credentialed_execution_preview"]
            job_path = mod._workspace_owned_path(workspace, artifact["path"])
            self.assertTrue(job_path.is_file())
            self.assertTrue(mod.verify_sidecar(job_path))

    def test_managed_executor_dry_run_rejects_changed_plan_artifact(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = self._manifest_for_discovery(td)
            profiles = write_json(
                pathlib.Path(td) / "profiles.json",
                {"schema_version": "0.4b.6", "profiles": []},
                sidecar=False,
            )
            init = mod.init_workspace(
                pathlib.Path(td) / "runs",
                "A1",
                "R1",
                "NODE-01",
                manifest=manifest,
                profiles=profiles,
            )
            workspace = pathlib.Path(init["workspace"])
            self._seed_completed_network(workspace)
            plan = self._seed_completed_plan(workspace, profiles)
            plan.write_text("{}\n", encoding="utf-8")

            with self.assertRaises(mod.RuntimeErrorSafe) as ctx:
                mod.run_credentialed_execution_dry_run(workspace)
            self.assertIn("SHA256", str(ctx.exception))

    def test_managed_executor_dry_run_requires_profiles_reference(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = self._manifest_for_discovery(td)
            init = mod.init_workspace(
                pathlib.Path(td) / "runs",
                "A1",
                "R1",
                "NODE-01",
                manifest=manifest,
            )
            workspace = pathlib.Path(init["workspace"])
            self._seed_completed_network(workspace)
            profiles = write_json(
                pathlib.Path(td) / "profiles-placeholder.json",
                {"schema_version": "0.4b.6", "profiles": []},
                sidecar=False,
            )
            self._seed_completed_plan(workspace, profiles)

            with self.assertRaises(mod.RuntimeErrorSafe) as ctx:
                mod.run_credentialed_execution_dry_run(workspace)
            self.assertIn("Credential Profiles", str(ctx.exception))

    def _seed_preview_completed(self, workspace, profiles):
        state = mod._load_state(pathlib.Path(workspace))
        plan_info = state["artifacts"]["credential_plan"]
        preview = write_json(
            pathlib.Path(workspace)
            / "evidence"
            / "credentialed_execution"
            / "P01-Credentialed-Job_PREVIEW.json",
            {
                "metadata": {
                    "executor_name": "P01-Credentialed-Discovery-Executor",
                    "executor_version": "0.4b.5",
                    "execution_mode": "dry_run",
                    "auth_only": False,
                    "secret_resolution": False,
                    "authentication_attempts": False,
                    "plan_sha256": plan_info["sha256"],
                    "concurrency": 1,
                },
                "summary": {
                    "actions_total": 1,
                    "actions_ready": 1,
                },
                "actions": [{"execution_status": "dry_run_ready"}],
            },
            sidecar=True,
        )
        state["steps"]["credentialed_execution"] = {
            "status": "preview_completed",
            "completed_at_utc": mod.utc_now_iso(),
            "managed_by": "0.5e.3",
            "mode": "dry_run",
            "secret_resolution": False,
            "authentication_attempts": False,
        }
        state["artifacts"]["credentialed_execution_preview"] = {
            "path": mod._relative_if_owned(pathlib.Path(workspace), preview),
            "sha256_path": mod._relative_if_owned(
                pathlib.Path(workspace),
                preview.with_suffix(preview.suffix + ".sha256"),
            ),
            "sha256": mod.digest_file(preview),
            "source_plan_sha256": plan_info["sha256"],
            "credential_profiles_sha256": mod.digest_file(profiles),
            "actions_total": 1,
            "actions_ready": 1,
            "mode": "dry_run",
        }
        mod._write_state(pathlib.Path(workspace), state)
        return preview

    def _fake_auth_executor(self, calls):
        def load(path):
            return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))

        def load_profiles(path):
            return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))

        def run_job(
            plan,
            profiles,
            plan_hash,
            outdir,
            run_label,
            execute=False,
            auth_only=False,
            max_actions=25,
            known_hosts=None,
            hostkey="strict",
        ):
            calls["runs"] += 1
            self.assertTrue(execute)
            self.assertTrue(auth_only)
            self.assertEqual(hostkey, "strict")
            target = pathlib.Path(outdir) / "targets" / "P01-Credentialed-Target_TEST.json"
            write_json(
                target,
                {
                    "metadata": {
                        "executor_name": "P01-Credentialed-Discovery-Executor",
                        "executor_version": "0.4b.5",
                        "secret_values_persisted_to_output": False,
                        "plan_sha256": plan_hash,
                    },
                    "action": {
                        "target_ip": "192.0.2.10",
                        "profile_id": "p-test",
                    },
                    "authentication": {
                        "success": True,
                        "failure_category": None,
                    },
                    "enrichment": None,
                },
                sidecar=True,
            )
            return {
                "metadata": {
                    "executor_name": "P01-Credentialed-Discovery-Executor",
                    "executor_version": "0.4b.5",
                    "schema_version": "0.4b",
                    "execution_mode": "execute",
                    "auth_only": True,
                    "read_only_mode": True,
                    "secret_resolution": True,
                    "authentication_attempts": True,
                    "plan_sha256": plan_hash,
                    "concurrency": 1,
                },
                "summary": {
                    "actions_total": 1,
                    "actions_ready": 1,
                    "actions_blocked_preflight": 0,
                    "dry_run_ready": 0,
                    "completed": 1,
                    "skipped": 0,
                    "authentication_successes": 1,
                    "authentication_failures": 0,
                    "open_credential_circuits": 0,
                },
                "actions": [
                    {
                        "execution_status": "completed",
                        "authentication_success": True,
                        "target_result_file": str(target),
                        "target_result_sha256": mod.digest_file(target),
                    }
                ],
                "credential_circuits": {},
                "limitations": [],
            }

        def write(path, payload):
            calls["writes"] += 1
            path = pathlib.Path(path)
            write_json(path, payload, sidecar=True)
            return (
                path,
                path.with_suffix(path.suffix + ".sha256"),
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )

        return types.SimpleNamespace(
            load=load,
            load_profiles=load_profiles,
            run_job=run_job,
            write=write,
        )

    def test_managed_auth_only_requires_explicit_ack(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = self._manifest_for_discovery(td)
            profiles = write_json(
                pathlib.Path(td) / "profiles.json",
                {"schema_version": "0.4b.6", "profiles": []},
                sidecar=False,
            )
            init = mod.init_workspace(
                pathlib.Path(td) / "runs",
                "A1",
                "R1",
                "NODE-01",
                manifest=manifest,
                profiles=profiles,
            )
            workspace = pathlib.Path(init["workspace"])
            self._seed_completed_network(workspace)
            self._seed_completed_plan(workspace, profiles)
            self._seed_preview_completed(workspace, profiles)

            calls = {"runs": 0, "writes": 0}
            fake = self._fake_auth_executor(calls)
            with mock.patch.object(mod, "_load_component", return_value=fake):
                with self.assertRaises(mod.RuntimeErrorSafe) as ctx:
                    mod.run_credentialed_execution_auth_only(
                        workspace,
                        ack_authorized_access=False,
                    )
            self.assertIn("--ack-authorized-access", str(ctx.exception))
            self.assertEqual(calls["runs"], 0)

    def test_managed_auth_only_is_resume_safe(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = self._manifest_for_discovery(td)
            profiles = write_json(
                pathlib.Path(td) / "profiles.json",
                {"schema_version": "0.4b.6", "profiles": []},
                sidecar=False,
            )
            init = mod.init_workspace(
                pathlib.Path(td) / "runs",
                "A1",
                "R1",
                "NODE-01",
                manifest=manifest,
                profiles=profiles,
            )
            workspace = pathlib.Path(init["workspace"])
            self._seed_completed_network(workspace)
            self._seed_completed_plan(workspace, profiles)
            self._seed_preview_completed(workspace, profiles)

            calls = {"runs": 0, "writes": 0}
            fake = self._fake_auth_executor(calls)
            with mock.patch.object(mod, "_load_component", return_value=fake):
                first = mod.run_credentialed_execution_auth_only(
                    workspace,
                    ack_authorized_access=True,
                    max_actions=25,
                )
                second = mod.run_credentialed_execution_auth_only(
                    workspace,
                    ack_authorized_access=True,
                    max_actions=25,
                )

            self.assertEqual(first["status"], "auth_validated")
            self.assertEqual(second["status"], "already_complete")
            self.assertEqual(calls["runs"], 1)
            self.assertEqual(calls["writes"], 1)
            self.assertEqual(first["authentication_successes"], 1)
            self.assertEqual(first["authentication_failures"], 0)
            self.assertTrue(first["network_activity_performed"])
            self.assertTrue(first["secret_resolution_performed"])
            self.assertTrue(first["authentication_attempts_performed"])
            self.assertFalse(second["network_activity_performed"])
            self.assertFalse(second["secret_resolution_performed"])
            self.assertFalse(second["authentication_attempts_performed"])

            state = mod._load_state(workspace)
            self.assertEqual(
                state["steps"]["credentialed_execution"]["status"],
                "auth_validated",
            )
            self.assertEqual(
                mod.status(workspace)["next_action"],
                "run_credentialed_execution_full",
            )
            artifact = state["artifacts"]["credentialed_execution_auth"]
            job_path = mod._workspace_owned_path(workspace, artifact["path"])
            self.assertTrue(job_path.is_file())
            self.assertTrue(mod.verify_sidecar(job_path))
            self.assertEqual(artifact["target_evidence_count"], 1)

    def test_managed_auth_only_rejects_changed_preview(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = self._manifest_for_discovery(td)
            profiles = write_json(
                pathlib.Path(td) / "profiles.json",
                {"schema_version": "0.4b.6", "profiles": []},
                sidecar=False,
            )
            init = mod.init_workspace(
                pathlib.Path(td) / "runs",
                "A1",
                "R1",
                "NODE-01",
                manifest=manifest,
                profiles=profiles,
            )
            workspace = pathlib.Path(init["workspace"])
            self._seed_completed_network(workspace)
            self._seed_completed_plan(workspace, profiles)
            preview = self._seed_preview_completed(workspace, profiles)
            preview.write_text("{}\n", encoding="utf-8")

            with self.assertRaises(mod.RuntimeErrorSafe) as ctx:
                mod.run_credentialed_execution_auth_only(
                    workspace,
                    ack_authorized_access=True,
                )
            self.assertIn("preview artifact", str(ctx.exception))

    def test_managed_auth_only_refuses_implicit_retry_after_failure(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = self._manifest_for_discovery(td)
            profiles = write_json(
                pathlib.Path(td) / "profiles.json",
                {"schema_version": "0.4b.6", "profiles": []},
                sidecar=False,
            )
            init = mod.init_workspace(
                pathlib.Path(td) / "runs",
                "A1",
                "R1",
                "NODE-01",
                manifest=manifest,
                profiles=profiles,
            )
            workspace = pathlib.Path(init["workspace"])
            self._seed_completed_network(workspace)
            self._seed_completed_plan(workspace, profiles)
            self._seed_preview_completed(workspace, profiles)
            state = mod._load_state(workspace)
            state["steps"]["credentialed_execution"] = {
                "status": "failed",
                "mode": "auth_only",
                "last_error": "synthetic partial failure",
            }
            mod._write_state(workspace, state)

            with self.assertRaises(mod.RuntimeErrorSafe) as ctx:
                mod.run_credentialed_execution_auth_only(
                    workspace,
                    ack_authorized_access=True,
                )
            self.assertIn("--force-auth-retry", str(ctx.exception))
            self.assertEqual(
                mod.status(workspace)["next_action"],
                "review_auth_failure_then_retry_explicitly",
            )

    def _seed_auth_validated(self, workspace, profiles):
        state = mod._load_state(pathlib.Path(workspace))
        plan_info = state["artifacts"]["credential_plan"]
        preview_info = state["artifacts"]["credentialed_execution_preview"]
        auth = write_json(
            pathlib.Path(workspace)
            / "evidence"
            / "credentialed_execution"
            / "P01-Credentialed-Job_AUTH.json",
            {
                "metadata": {
                    "executor_name": "P01-Credentialed-Discovery-Executor",
                    "executor_version": "0.4b.5",
                    "execution_mode": "execute",
                    "auth_only": True,
                    "secret_resolution": True,
                    "authentication_attempts": True,
                    "plan_sha256": plan_info["sha256"],
                    "concurrency": 1,
                },
                "summary": {
                    "actions_total": 1,
                    "actions_ready": 1,
                    "completed": 1,
                    "skipped": 0,
                    "authentication_successes": 1,
                    "authentication_failures": 0,
                    "open_credential_circuits": 0,
                },
                "actions": [],
            },
            sidecar=True,
        )
        state["steps"]["credentialed_execution"] = {
            "status": "auth_validated",
            "completed_at_utc": mod.utc_now_iso(),
            "managed_by": "0.5e.3.1",
            "mode": "auth_only",
            "secret_resolution": True,
            "authentication_attempts": True,
            "authentication_successes": 1,
            "authentication_failures": 0,
        }
        state["artifacts"]["credentialed_execution_auth"] = {
            "path": mod._relative_if_owned(pathlib.Path(workspace), auth),
            "sha256_path": mod._relative_if_owned(
                pathlib.Path(workspace),
                auth.with_suffix(auth.suffix + ".sha256"),
            ),
            "sha256": mod.digest_file(auth),
            "source_plan_sha256": plan_info["sha256"],
            "source_preview_sha256": preview_info["sha256"],
            "credential_profiles_sha256": mod.digest_file(profiles),
            "actions_total": 1,
            "actions_ready": 1,
            "completed": 1,
            "skipped": 0,
            "authentication_successes": 1,
            "authentication_failures": 0,
            "open_credential_circuits": 0,
            "target_evidence_count": 1,
            "mode": "auth_only",
        }
        mod._write_state(pathlib.Path(workspace), state)
        return auth

    def _fake_full_executor(self, calls, *, successful=True):
        def load(path):
            return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))

        def load_profiles(path):
            return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))

        def run_job(
            plan,
            profiles,
            plan_hash,
            outdir,
            run_label,
            execute=False,
            auth_only=False,
            max_actions=25,
            known_hosts=None,
            hostkey="strict",
        ):
            calls["runs"] += 1
            self.assertTrue(execute)
            self.assertFalse(auth_only)
            self.assertEqual(hostkey, "strict")
            target = pathlib.Path(outdir) / "targets" / "P01-Credentialed-Target_FULL_TEST.json"
            auth_ok = bool(successful)
            write_json(
                target,
                {
                    "metadata": {
                        "executor_name": "P01-Credentialed-Discovery-Executor",
                        "executor_version": "0.4b.5",
                        "secret_values_persisted_to_output": False,
                        "plan_sha256": plan_hash,
                    },
                    "action": {
                        "target_ip": "192.0.2.10",
                        "profile_id": "p-test",
                    },
                    "authentication": {
                        "success": auth_ok,
                        "failure_category": None if auth_ok else "authentication",
                    },
                    "enrichment": (
                        {
                            "collection_status": "collected",
                            "identity": {"hostname": "node-01"},
                        }
                        if auth_ok
                        else None
                    ),
                },
                sidecar=True,
            )
            return {
                "metadata": {
                    "executor_name": "P01-Credentialed-Discovery-Executor",
                    "executor_version": "0.4b.5",
                    "schema_version": "0.4b",
                    "execution_mode": "execute",
                    "auth_only": False,
                    "read_only_mode": True,
                    "secret_resolution": True,
                    "authentication_attempts": True,
                    "plan_sha256": plan_hash,
                    "concurrency": 1,
                },
                "summary": {
                    "actions_total": 1,
                    "actions_ready": 1,
                    "actions_blocked_preflight": 0,
                    "dry_run_ready": 0,
                    "completed": 1,
                    "skipped": 0,
                    "authentication_successes": 1 if auth_ok else 0,
                    "authentication_failures": 0 if auth_ok else 1,
                    "open_credential_circuits": 0 if auth_ok else 1,
                },
                "actions": [
                    {
                        "execution_status": "completed",
                        "authentication_success": auth_ok,
                        "collection_status": "collected" if auth_ok else None,
                        "target_result_file": str(target),
                        "target_result_sha256": mod.digest_file(target),
                    }
                ],
                "credential_circuits": {},
                "limitations": [],
            }

        def write(path, payload):
            calls["writes"] += 1
            path = pathlib.Path(path)
            write_json(path, payload, sidecar=True)
            return (
                path,
                path.with_suffix(path.suffix + ".sha256"),
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )

        return types.SimpleNamespace(
            load=load,
            load_profiles=load_profiles,
            run_job=run_job,
            write=write,
        )

    def test_managed_full_requires_explicit_ack(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = self._manifest_for_discovery(td)
            profiles = write_json(
                pathlib.Path(td) / "profiles.json",
                {"schema_version": "0.4b.6", "profiles": []},
                sidecar=False,
            )
            init = mod.init_workspace(
                pathlib.Path(td) / "runs",
                "A1",
                "R1",
                "NODE-01",
                manifest=manifest,
                profiles=profiles,
            )
            workspace = pathlib.Path(init["workspace"])
            self._seed_completed_network(workspace)
            self._seed_completed_plan(workspace, profiles)
            self._seed_preview_completed(workspace, profiles)
            self._seed_auth_validated(workspace, profiles)

            calls = {"runs": 0, "writes": 0}
            fake = self._fake_full_executor(calls)
            with mock.patch.object(mod, "_load_component", return_value=fake):
                with self.assertRaises(mod.RuntimeErrorSafe) as ctx:
                    mod.run_credentialed_execution_full(
                        workspace,
                        ack_authorized_access=False,
                    )
            self.assertIn("--ack-authorized-access", str(ctx.exception))
            self.assertEqual(calls["runs"], 0)

    def test_managed_full_is_resume_safe(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = self._manifest_for_discovery(td)
            profiles = write_json(
                pathlib.Path(td) / "profiles.json",
                {"schema_version": "0.4b.6", "profiles": []},
                sidecar=False,
            )
            init = mod.init_workspace(
                pathlib.Path(td) / "runs",
                "A1",
                "R1",
                "NODE-01",
                manifest=manifest,
                profiles=profiles,
            )
            workspace = pathlib.Path(init["workspace"])
            self._seed_completed_network(workspace)
            self._seed_completed_plan(workspace, profiles)
            self._seed_preview_completed(workspace, profiles)
            self._seed_auth_validated(workspace, profiles)

            calls = {"runs": 0, "writes": 0}
            fake = self._fake_full_executor(calls)
            with mock.patch.object(mod, "_load_component", return_value=fake):
                first = mod.run_credentialed_execution_full(
                    workspace,
                    ack_authorized_access=True,
                    max_actions=25,
                )
                second = mod.run_credentialed_execution_full(
                    workspace,
                    ack_authorized_access=True,
                    max_actions=25,
                )

            self.assertEqual(first["status"], "full_completed")
            self.assertEqual(second["status"], "already_complete")
            self.assertEqual(calls["runs"], 1)
            self.assertEqual(calls["writes"], 1)
            self.assertEqual(first["completed"], 1)
            self.assertEqual(first["collected"], 1)
            self.assertEqual(first["authentication_successes"], 1)
            self.assertTrue(first["network_activity_performed"])
            self.assertFalse(second["network_activity_performed"])
            self.assertFalse(second["secret_resolution_performed"])
            self.assertFalse(second["authentication_attempts_performed"])

            state = mod._load_state(workspace)
            self.assertEqual(
                state["steps"]["credentialed_execution"]["status"],
                "full_completed",
            )
            self.assertEqual(
                mod.status(workspace)["next_action"],
                "run_asset_resolver",
            )
            artifact = state["artifacts"]["credentialed_execution_full"]
            job_path = mod._workspace_owned_path(workspace, artifact["path"])
            self.assertTrue(job_path.is_file())
            self.assertTrue(mod.verify_sidecar(job_path))
            self.assertEqual(artifact["target_evidence_count"], 1)

    def test_managed_full_rejects_changed_auth_artifact(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = self._manifest_for_discovery(td)
            profiles = write_json(
                pathlib.Path(td) / "profiles.json",
                {"schema_version": "0.4b.6", "profiles": []},
                sidecar=False,
            )
            init = mod.init_workspace(
                pathlib.Path(td) / "runs",
                "A1",
                "R1",
                "NODE-01",
                manifest=manifest,
                profiles=profiles,
            )
            workspace = pathlib.Path(init["workspace"])
            self._seed_completed_network(workspace)
            self._seed_completed_plan(workspace, profiles)
            self._seed_preview_completed(workspace, profiles)
            auth = self._seed_auth_validated(workspace, profiles)
            auth.write_text("{}\n", encoding="utf-8")

            with self.assertRaises(mod.RuntimeErrorSafe) as ctx:
                mod.run_credentialed_execution_full(
                    workspace,
                    ack_authorized_access=True,
                )
            self.assertIn("AUTH-only job artifact", str(ctx.exception))

    def test_managed_full_partial_result_requires_explicit_retry(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = self._manifest_for_discovery(td)
            profiles = write_json(
                pathlib.Path(td) / "profiles.json",
                {"schema_version": "0.4b.6", "profiles": []},
                sidecar=False,
            )
            init = mod.init_workspace(
                pathlib.Path(td) / "runs",
                "A1",
                "R1",
                "NODE-01",
                manifest=manifest,
                profiles=profiles,
            )
            workspace = pathlib.Path(init["workspace"])
            self._seed_completed_network(workspace)
            self._seed_completed_plan(workspace, profiles)
            self._seed_preview_completed(workspace, profiles)
            self._seed_auth_validated(workspace, profiles)

            calls = {"runs": 0, "writes": 0}
            fake = self._fake_full_executor(calls, successful=False)
            with mock.patch.object(mod, "_load_component", return_value=fake):
                with self.assertRaises(mod.RuntimeErrorSafe) as ctx:
                    mod.run_credentialed_execution_full(
                        workspace,
                        ack_authorized_access=True,
                    )
            self.assertIn("partial/failed results", str(ctx.exception))
            self.assertEqual(
                mod.status(workspace)["next_action"],
                "review_full_failure_then_retry_explicitly",
            )

            with self.assertRaises(mod.RuntimeErrorSafe) as ctx2:
                mod.run_credentialed_execution_full(
                    workspace,
                    ack_authorized_access=True,
                )
            self.assertIn("--force-full-retry", str(ctx2.exception))
            self.assertEqual(calls["runs"], 1)

    def _seed_full_completed(self, workspace):
        workspace = pathlib.Path(workspace)
        target = write_json(
            workspace
            / "evidence"
            / "credentialed_execution"
            / "targets"
            / "P01-Credentialed-Target_192.0.2.10_ssh_R1-EXEC-FULL.json",
            {
                "metadata": {
                    "executor_name": "P01-Credentialed-Discovery-Executor",
                    "executor_version": "0.4b.5",
                    "secret_values_persisted_to_output": False,
                },
                "action": {
                    "target_ip": "192.0.2.10",
                    "hostname": "node-01.example.test",
                    "protocol": "ssh",
                    "port": 22,
                    "os_family": "Linux/Unix-like",
                    "device_type": "Linux/Unix Host",
                },
                "authentication": {"success": True},
                "enrichment": {
                    "identity": {
                        "hostname": "node-01",
                        "fqdn": "node-01.example.test",
                    },
                    "network": {
                        "interfaces": [
                            {"name": "eth0", "ipv4": ["192.0.2.10"]}
                        ]
                    },
                },
            },
            sidecar=True,
        )
        full = write_json(
            workspace
            / "evidence"
            / "credentialed_execution"
            / "P01-Credentialed-Job_FULL.json",
            {
                "metadata": {
                    "executor_name": "P01-Credentialed-Discovery-Executor",
                    "executor_version": "0.4b.5",
                    "execution_mode": "execute",
                    "auth_only": False,
                    "secret_resolution": True,
                    "authentication_attempts": True,
                    "concurrency": 1,
                },
                "summary": {
                    "actions_total": 1,
                    "actions_ready": 1,
                    "completed": 1,
                    "skipped": 0,
                    "authentication_successes": 1,
                    "authentication_failures": 0,
                    "open_credential_circuits": 0,
                },
                "actions": [
                    {
                        "execution_status": "completed",
                        "authentication_success": True,
                        "collection_status": "collected",
                        "target_result_file": str(target.resolve()),
                        "target_result_sha256": mod.digest_file(target),
                    }
                ],
            },
            sidecar=True,
        )
        state = mod._load_state(workspace)
        state["steps"]["credential_plan"] = {
            "status": "completed",
            "completed_at_utc": mod.utc_now_iso(),
            "managed_by": "0.5e.2",
        }
        state["steps"]["credentialed_execution"] = {
            "status": "full_completed",
            "completed_at_utc": mod.utc_now_iso(),
            "managed_by": "0.5e.3.2",
            "mode": "full",
        }
        state["artifacts"]["credentialed_execution_full"] = {
            "path": mod._relative_if_owned(workspace, full),
            "sha256_path": mod._relative_if_owned(
                workspace, full.with_suffix(full.suffix + ".sha256")
            ),
            "sha256": mod.digest_file(full),
            "target_evidence_count": 1,
            "mode": "full",
        }
        mod._write_state(workspace, state)
        return full, target

    def _fake_asset_resolver(self, calls):
        def resolve(
            network_path,
            evidence_paths,
            manifest_path=None,
            require_evidence_sidecars=False,
        ):
            calls["resolves"] += 1
            self.assertTrue(require_evidence_sidecars)
            self.assertEqual(len(evidence_paths), 1)
            self.assertIn("EXEC-FULL", evidence_paths[0].name)
            return {
                "metadata": {
                    "resolver_name": "P01-Asset-Resolver",
                    "resolver_version": "0.4c.0",
                    "schema_version": "0.4c",
                    "offline_only": True,
                    "read_only_mode": True,
                    "secret_resolution": False,
                    "authentication_attempts": False,
                    "network_access_performed": False,
                },
                "summary": {
                    "network_assets_seen": 1,
                    "credentialed_observations_seen": 1,
                    "logical_assets_resolved": 1,
                    "correlated_observations": 1,
                    "unresolved_observations": 0,
                    "ambiguous_correlations": 0,
                    "assets_with_conflicts": 0,
                    "assets_with_strong_identifiers": 1,
                },
                "assets": [{"asset_id": "ast-test"}],
                "unresolved_observations": [],
                "ambiguous_correlations": [],
                "limitations": [],
            }

        def write_output(output_dir, run_label, payload):
            calls["writes"] += 1
            path = pathlib.Path(output_dir) / f"P01-Asset-Resolver_TEST_{run_label}.json"
            write_json(path, payload, sidecar=True)
            return path, path.with_suffix(path.suffix + ".sha256")

        return types.SimpleNamespace(resolve=resolve, write_output=write_output)

    def test_managed_asset_resolver_is_resume_safe_and_adopts_external_state(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = self._manifest_for_discovery(td)
            init = mod.init_workspace(
                pathlib.Path(td) / "runs",
                "A1",
                "R1",
                "NODE-01",
                manifest=manifest,
            )
            workspace = pathlib.Path(init["workspace"])
            self._seed_completed_network(workspace)
            self._seed_full_completed(workspace)

            state = mod._load_state(workspace)
            state["steps"]["asset_resolver"] = {
                "status": "external_required",
                "managed_from_version": "0.5e.4",
            }
            mod._write_state(workspace, state)

            calls = {"resolves": 0, "writes": 0}
            fake = self._fake_asset_resolver(calls)
            with mock.patch.object(mod, "_load_component", return_value=fake):
                first = mod.run_asset_resolver(workspace)
                second = mod.run_asset_resolver(workspace)

            self.assertEqual(first["status"], "completed")
            self.assertEqual(second["status"], "already_complete")
            self.assertEqual(calls["resolves"], 1)
            self.assertEqual(calls["writes"], 1)
            self.assertEqual(first["logical_assets_resolved"], 1)
            self.assertFalse(first["network_activity_performed"])
            self.assertFalse(first["secret_resolution_performed"])
            self.assertFalse(first["authentication_attempts_performed"])

            state = mod._load_state(workspace)
            self.assertEqual(state["steps"]["asset_resolver"]["status"], "completed")
            self.assertEqual(mod.status(workspace)["next_action"], "export")
            artifact = state["artifacts"]["asset_resolver"]
            resolver_path = mod._workspace_owned_path(workspace, artifact["path"])
            self.assertTrue(resolver_path.is_file())
            self.assertTrue(mod.verify_sidecar(resolver_path))

    def test_managed_asset_resolver_rejects_changed_full_target(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = self._manifest_for_discovery(td)
            init = mod.init_workspace(
                pathlib.Path(td) / "runs",
                "A1",
                "R1",
                "NODE-01",
                manifest=manifest,
            )
            workspace = pathlib.Path(init["workspace"])
            self._seed_completed_network(workspace)
            _full, target = self._seed_full_completed(workspace)
            target.write_text("{}\n", encoding="utf-8")

            with self.assertRaises(mod.RuntimeErrorSafe) as ctx:
                mod.run_asset_resolver(workspace)
            self.assertIn("FULL target evidence", str(ctx.exception))

    def test_managed_asset_resolver_force_rejected_after_bundle_completion(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = self._manifest_for_discovery(td)
            init = mod.init_workspace(
                pathlib.Path(td) / "runs",
                "A1",
                "R1",
                "NODE-01",
                manifest=manifest,
            )
            workspace = pathlib.Path(init["workspace"])
            self._seed_completed_network(workspace)
            self._seed_full_completed(workspace)
            state = mod._load_state(workspace)
            state["steps"]["asset_resolver"] = {"status": "completed"}
            state["steps"]["evidence_bundle"] = {"status": "completed"}
            mod._write_state(workspace, state)

            with self.assertRaises(mod.RuntimeErrorSafe) as ctx:
                mod.run_asset_resolver(workspace, force_reresolve=True)
            self.assertIn("downstream completed steps", str(ctx.exception))

    def test_force_rescan_refused_after_downstream_bundle_completion(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = self._manifest_for_discovery(td)
            init = mod.init_workspace(
                pathlib.Path(td) / "runs",
                "A1",
                "R1",
                "NODE-01",
                manifest=manifest,
            )
            workspace = pathlib.Path(init["workspace"])
            state = mod._load_state(workspace)
            state["steps"]["network_discovery"] = {"status": "completed"}
            state["steps"]["evidence_bundle"] = {"status": "completed"}
            state["artifacts"]["network_discovery"] = {
                "path": "missing.json",
                "sha256": "0" * 64,
            }
            mod._write_state(workspace, state)

            with self.assertRaises(mod.RuntimeErrorSafe) as ctx:
                mod.run_network_discovery(
                    workspace,
                    ["192.0.2.0/30"],
                    [],
                    ack_authorized_scan=True,
                    force_rescan=True,
                )
            self.assertIn("downstream completed steps", str(ctx.exception))

    def test_export_wraps_existing_bundle_and_is_resume_safe(self):
        with tempfile.TemporaryDirectory() as td:
            network, evidence_dir, _cred, resolver, manifest = self._synthetic_inputs(td)
            init = mod.init_workspace(
                pathlib.Path(td) / "runs",
                "A1",
                "R1",
                "NODE-01",
                manifest=manifest,
            )
            workspace = pathlib.Path(init["workspace"])
            first = mod.export_bundle(
                workspace,
                network,
                evidence_dir,
                "RUNTIME-FULL",
                resolver,
                None,
                require_sidecars=True,
            )
            self.assertEqual(first["status"], "completed")
            bundle = pathlib.Path(first["bundle_path"])
            self.assertTrue(bundle.is_file())
            self.assertTrue(bundle.with_suffix(bundle.suffix + ".sha256").is_file())

            second = mod.export_bundle(
                workspace,
                network,
                evidence_dir,
                "RUNTIME-FULL",
                resolver,
                None,
                require_sidecars=True,
            )
            self.assertEqual(second["status"], "already_complete")
            state = mod._load_state(workspace)
            self.assertEqual(state["steps"]["evidence_bundle"]["status"], "completed")

    def test_upload_completed_step_is_not_repeated_silently(self):
        with tempfile.TemporaryDirectory() as td:
            network, evidence_dir, _cred, resolver, manifest = self._synthetic_inputs(td)
            init = mod.init_workspace(
                pathlib.Path(td) / "runs",
                "A1",
                "R1",
                "NODE-01",
                manifest=manifest,
            )
            workspace = pathlib.Path(init["workspace"])
            mod.export_bundle(
                workspace,
                network,
                evidence_dir,
                "RUNTIME-FULL",
                resolver,
                None,
                require_sidecars=True,
            )

            ca = pathlib.Path(td) / "ca.crt"
            cert = pathlib.Path(td) / "node.crt"
            key = pathlib.Path(td) / "node.key"
            for p in (ca, cert, key):
                p.write_text("test\n", encoding="utf-8")

            fake = types.SimpleNamespace()
            fake.bundle_manifest = lambda bundle: {
                "bundle_id": "bnd-test",
                "assessment_id": "A1",
                "node_id": "NODE-01",
            }
            calls = {"uploads": 0}

            def fake_upload(*args, **kwargs):
                calls["uploads"] += 1
                return {
                    "status": "success",
                    "http_status": 201,
                    "attempts": 1,
                    "server_response": {
                        "status": "imported",
                        "bundle_id": "bnd-test",
                        "assessment_id": "A1",
                        "semantic_match": True,
                        "authenticated_node_id": "NODE-01",
                    },
                }

            def fake_receipt(output_dir, node_id, bundle, server_url, result):
                output_dir.mkdir(parents=True, exist_ok=True)
                p = output_dir / "P01-Upload-Receipt_bnd-test.json"
                write_json(p, {"status": "success"}, sidecar=True)
                return p, p.with_suffix(p.suffix + ".sha256")

            fake.upload_with_retries = fake_upload
            fake.write_receipt = fake_receipt

            with mock.patch.object(mod, "_load_component", return_value=fake):
                first = mod.upload_bundle(
                    workspace,
                    "https://server.example:8443",
                    ca,
                    cert,
                    key,
                    max_retries=0,
                )
                second = mod.upload_bundle(
                    workspace,
                    "https://server.example:8443",
                    ca,
                    cert,
                    key,
                    max_retries=0,
                )

            self.assertEqual(first["status"], "completed")
            self.assertEqual(second["status"], "already_complete")
            self.assertEqual(calls["uploads"], 1)

    def test_doctor_performs_no_network_activity(self):
        with tempfile.TemporaryDirectory() as td:
            result = mod.doctor(pathlib.Path(td))
            self.assertFalse(result["network_activity_performed"])
            self.assertFalse(result["secret_resolution_performed"])
            self.assertFalse(result["authentication_attempts_performed"])

    def test_safe_labels_block_path_escape(self):
        with tempfile.TemporaryDirectory() as td:
            result = mod.init_workspace(
                pathlib.Path(td),
                "../../assessment",
                "..\\run",
                "NODE-01",
            )
            workspace = pathlib.Path(result["workspace"]).resolve()
            self.assertTrue(str(workspace).startswith(str(pathlib.Path(td).resolve())))
            self.assertNotIn("..", workspace.parts[-2:])


if __name__ == "__main__":
    unittest.main()
