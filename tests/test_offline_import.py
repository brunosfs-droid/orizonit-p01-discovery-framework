import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

bundle_path = ROOT / "evidence_bundle" / "P01_Evidence_Bundle.py"
bundle_spec = importlib.util.spec_from_file_location("P01_Evidence_Bundle", bundle_path)
bundle_mod = importlib.util.module_from_spec(bundle_spec)
bundle_spec.loader.exec_module(bundle_mod)

resolver_path = ROOT / "asset_resolver" / "P01_Asset_Resolver.py"
resolver_spec = importlib.util.spec_from_file_location("P01_Asset_Resolver", resolver_path)
resolver_mod = importlib.util.module_from_spec(resolver_spec)
resolver_spec.loader.exec_module(resolver_mod)

import_path = ROOT / "ingestion" / "P01_Offline_Import.py"
import_spec = importlib.util.spec_from_file_location("p01_offline_import", import_path)
mod = importlib.util.module_from_spec(import_spec)
import_spec.loader.exec_module(mod)


def write_json(path, payload, sidecar=False):
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if sidecar:
        digest = bundle_mod.digest_file(path)
        path.with_suffix(path.suffix + ".sha256").write_text(
            f"{digest}  {path.name}\n", encoding="utf-8"
        )
    return path


def network_doc():
    return {
        "metadata": {
            "scanner_name": "P01-Network-Discovery-Scanner",
            "scanner_version": "0.4.1",
            "run_label": "LAB-NET-R1",
        },
        "assets": [{
            "ip": "192.0.2.10",
            "hostname": "HOST01.corp.example.test",
            "mac": "00:11:22:33:44:55",
            "device_type_guess": "Windows Host",
            "os_guess": "Windows",
            "confidence": "High",
            "open_ports": [{"port": 5985, "protocol": "tcp", "service": "winrm-http"}],
        }],
    }


def target_doc():
    return {
        "metadata": {
            "executor_name": "P01-Credentialed-Discovery-Executor",
            "executor_version": "0.4b.5",
            "run_label": "LAB-FULL-R1",
            "secret_values_persisted_to_output": False,
        },
        "action": {
            "target_ip": "192.0.2.10",
            "hostname": "HOST01.corp.example.test",
            "device_type": "Windows Host",
            "os_family": "Windows",
            "realm": "CORP",
            "protocol": "winrm",
            "port": 5985,
        },
        "authentication": {"success": True},
        "enrichment": {
            "collection_status": "collected",
            "identity": {
                "computer_name": "HOST01",
                "fqdn": "HOST01.corp.example.test",
                "serial_number": "SERIAL-001",
                "domain": "corp.example.test",
                "part_of_domain": True,
                "domain_role": 1,
            },
            "operating_system": {
                "caption": "Microsoft Windows 11 Enterprise",
                "build_number": "26000",
            },
            "network": {
                "interfaces": [{
                    "interface_alias": "Ethernet",
                    "ipv4": [{"address": "192.0.2.10", "prefix_length": 24}],
                }]
            },
        },
        "circuit_after_attempt": {"circuit_open": False},
    }


def manifest_doc():
    return {
        "schema_version": "0.4b.6",
        "assessment_id": "LAB-001",
        "environment_label": "LAB",
        "authorized_scopes": ["192.0.2.0/24"],
        "exclude_scopes": [],
        "domains": [{
            "dns_domain": "corp.example.test",
            "netbios_name": "CORP",
            "forest": "corp.example.test",
            "scopes": ["192.0.2.0/24"],
            "evidence_state": "declared",
        }],
        "allowed_protocols": ["winrm"],
        "discovery_nodes": [],
        "safety_policy": {
            "default_concurrency": 1,
            "max_actions": 25,
            "require_authorized_ack": True,
            "auto_expand_scope": False,
        },
    }


class OfflineImportTests(unittest.TestCase):
    def _bundle(self, td):
        td = pathlib.Path(td)
        network = write_json(td / "network.json", network_doc(), sidecar=True)
        target = write_json(
            td / "P01-Credentialed-Target_192.0.2.10_winrm_LAB-FULL-R1.json",
            target_doc(),
            sidecar=True,
        )
        manifest = write_json(td / "assessment.json", manifest_doc())

        resolved = resolver_mod.resolve(network, [target], manifest)
        resolved_path, _ = resolver_mod.write_output(td, "EDGE-R1", resolved)

        out = td / "LAB-BUNDLE-R1.p01bundle"
        bundle_mod.create_bundle(
            out,
            "LAB-001",
            "LAB-BUNDLE-R1",
            "NODE-01",
            network,
            [target],
            manifest,
            resolved_path,
            require_evidence_sidecars=True,
        )
        return out

    def test_import_process_and_semantic_match(self):
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            bundle = self._bundle(td)
            store = td / "server"
            result = mod.import_bundle(
                bundle,
                store,
                process=True,
                require_outer_sidecar=True,
                process_run_label="SERVER-R1",
            )
            self.assertEqual(result["status"], "imported")
            self.assertTrue(result["semantic_match"])

            receipt = mod.load_json(pathlib.Path(result["receipt_path"]))
            self.assertTrue(receipt["outer_sha256_verified"])
            self.assertTrue(receipt["processing"]["asset_resolver_executed"])
            self.assertTrue(receipt["processing"]["semantic_match"])
            self.assertEqual(
                receipt["processing"]["edge_semantic_sha256"],
                receipt["processing"]["server_semantic_sha256"],
            )
            self.assertFalse(receipt["security"]["secret_resolution"])
            self.assertFalse(receipt["security"]["authentication_attempts"])
            self.assertFalse(receipt["security"]["network_access_performed"])

    def test_second_import_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            bundle = self._bundle(td)
            store = td / "server"
            first = mod.import_bundle(bundle, store, process=True, require_outer_sidecar=True)
            second = mod.import_bundle(bundle, store, process=True, require_outer_sidecar=True)
            self.assertEqual(first["status"], "imported")
            self.assertEqual(second["status"], "already_imported")
            self.assertEqual(first["bundle_id"], second["bundle_id"])
            self.assertEqual(first["import_dir"], second["import_dir"])
            self.assertTrue(second["semantic_match"])

    def test_outer_sidecar_can_be_required(self):
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            bundle = self._bundle(td)
            bundle.with_suffix(bundle.suffix + ".sha256").unlink()
            with self.assertRaisesRegex(ValueError, "outer bundle SHA256"):
                mod.import_bundle(bundle, td / "server", require_outer_sidecar=True)

    def test_import_without_process_preserves_raw_bundle(self):
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            bundle = self._bundle(td)
            result = mod.import_bundle(bundle, td / "server", process=False, require_outer_sidecar=True)
            receipt = mod.load_json(pathlib.Path(result["receipt_path"]))
            raw = pathlib.Path(result["import_dir"]) / receipt["raw_bundle"]
            self.assertTrue(raw.exists())
            self.assertEqual(mod.digest_file(raw), mod.digest_file(bundle))
            self.assertFalse(receipt["processing"]["requested"])
            self.assertFalse(receipt["processing"]["asset_resolver_executed"])


if __name__ == "__main__":
    unittest.main()
