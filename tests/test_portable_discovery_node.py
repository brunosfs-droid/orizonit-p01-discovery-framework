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
            self.assertEqual(state["steps"]["evidence_bundle"]["status"], "pending")
            self.assertEqual(state["steps"]["upload"]["status"], "pending")
            self.assertTrue(state["security"]["active_discovery_managed_in_this_version"])
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

    def test_status_next_action_export_then_upload(self):
        with tempfile.TemporaryDirectory() as td:
            result = mod.init_workspace(pathlib.Path(td), "A1", "R1", "N1")
            workspace = pathlib.Path(result["workspace"])
            current = mod.status(workspace)
            self.assertEqual(current["next_action"], "export")

            state = mod._load_state(workspace)
            state["steps"]["evidence_bundle"] = {"status": "completed"}
            mod._write_state(workspace, state)
            current = mod.status(workspace)
            self.assertEqual(current["next_action"], "upload_or_copy_bundle_offline")

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
            self.assertEqual(mod.status(workspace)["next_action"], "credential_plan_external")

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
