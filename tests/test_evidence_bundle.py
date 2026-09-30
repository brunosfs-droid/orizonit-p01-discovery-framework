import importlib.util
import json
import pathlib
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
path = ROOT / "evidence_bundle" / "P01_Evidence_Bundle.py"
spec = importlib.util.spec_from_file_location("p01_evidence_bundle", path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def write_json(path, payload, sidecar=False):
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if sidecar:
        digest = mod.digest_file(path)
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
        "assets": [{"ip": "192.0.2.10", "hostname": "host.example.test"}],
    }


def target_doc(ip="192.0.2.10"):
    return {
        "metadata": {
            "executor_name": "P01-Credentialed-Discovery-Executor",
            "executor_version": "0.4b.5",
            "run_label": "LAB-FULL-R1",
            "secret_values_persisted_to_output": False,
        },
        "action": {
            "target_ip": ip,
            "protocol": "winrm",
        },
        "authentication": {"success": True},
        "enrichment": {"collection_status": "collected"},
    }


def manifest_doc():
    return {
        "schema_version": "0.4b.6",
        "assessment_id": "LAB-001",
        "authorized_scopes": ["192.0.2.0/24"],
        "domains": [],
        "allowed_protocols": ["winrm"],
        "safety_policy": {
            "default_concurrency": 1,
            "max_actions": 25,
            "require_authorized_ack": True,
            "auto_expand_scope": False,
        },
    }


def resolver_doc():
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
        },
        "assets": [],
    }


class EvidenceBundleTests(unittest.TestCase):
    def _inputs(self, td):
        td = pathlib.Path(td)
        network = write_json(td / "network.json", network_doc(), sidecar=True)
        target = write_json(td / "P01-Credentialed-Target_192.0.2.10_winrm_LAB-FULL-R1.json", target_doc(), sidecar=True)
        manifest = write_json(td / "assessment.json", manifest_doc(), sidecar=False)
        resolver = write_json(td / "resolver.json", resolver_doc(), sidecar=True)
        return network, [target], manifest, resolver

    def test_create_and_validate_bundle(self):
        with tempfile.TemporaryDirectory() as td:
            network, targets, manifest, resolver = self._inputs(td)
            out = pathlib.Path(td) / "lab.p01bundle"
            created = mod.create_bundle(
                out, "LAB-001", "RUN-001", "NODE-01",
                network, targets, manifest, resolver,
                require_evidence_sidecars=True,
            )
            self.assertTrue(out.exists())
            self.assertTrue(out.with_suffix(".p01bundle.sha256").exists())
            self.assertEqual(created["artifact_count"], 4)

            result = mod.validate_bundle(out)
            self.assertTrue(result["valid"])
            self.assertEqual(result["assessment_id"], "LAB-001")
            self.assertEqual(result["artifact_count"], 4)
            self.assertEqual(result["credentialed_evidence_count"], 1)
            self.assertTrue(result["outer_sha256_verified"])
            self.assertEqual(result["integrity_mode"], "sha256_inventory")
            self.assertIsNone(result["digital_signature"])

    def test_bundle_contains_expected_layout(self):
        with tempfile.TemporaryDirectory() as td:
            network, targets, manifest, resolver = self._inputs(td)
            out = pathlib.Path(td) / "lab.p01bundle"
            mod.create_bundle(out, "LAB-001", "RUN-001", "NODE-01", network, targets, manifest, resolver)
            with zipfile.ZipFile(out) as z:
                names = set(z.namelist())
            self.assertIn("bundle-manifest.json", names)
            self.assertIn("integrity/sha256-manifest.json", names)
            self.assertIn("evidence/network/network.json", names)
            self.assertIn("context/assessment.json", names)
            self.assertIn("evidence/resolved/resolver.json", names)
            self.assertTrue(any(n.startswith("evidence/credentialed/") for n in names))

    def test_tampered_payload_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            network, targets, manifest, resolver = self._inputs(td)
            out = pathlib.Path(td) / "lab.p01bundle"
            mod.create_bundle(out, "LAB-001", "RUN-001", "NODE-01", network, targets, manifest, resolver)

            tampered = pathlib.Path(td) / "tampered.p01bundle"
            with zipfile.ZipFile(out, "r") as src, zipfile.ZipFile(tampered, "w") as dst:
                for info in src.infolist():
                    raw = src.read(info.filename)
                    if info.filename == "evidence/network/network.json":
                        raw = raw + b" "
                    dst.writestr(info.filename, raw)

            with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
                mod.validate_bundle(tampered)

    def test_secret_provider_reference_rejected_on_create(self):
        with tempfile.TemporaryDirectory() as td:
            network, targets, manifest, resolver = self._inputs(td)
            bad = target_doc()
            bad["profile"] = {"locator": "wincred://ORIZONIT/P01/example"}
            targets[0] = write_json(pathlib.Path(td) / "P01-Credentialed-Target_bad_LAB-FULL-R1.json", bad, sidecar=True)
            out = pathlib.Path(td) / "bad.p01bundle"
            with self.assertRaisesRegex(ValueError, "Secret Provider reference"):
                mod.create_bundle(out, "LAB-001", "RUN-001", "NODE-01", network, targets, manifest, resolver)

    def test_plaintext_password_key_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            network, targets, manifest, resolver = self._inputs(td)
            bad = target_doc()
            bad["authentication"]["password"] = "not-allowed"
            targets[0] = write_json(pathlib.Path(td) / "P01-Credentialed-Target_bad_LAB-FULL-R1.json", bad, sidecar=True)
            out = pathlib.Path(td) / "bad.p01bundle"
            with self.assertRaisesRegex(ValueError, "secret-like JSON key"):
                mod.create_bundle(out, "LAB-001", "RUN-001", "NODE-01", network, targets, manifest, resolver)

    def test_require_sidecars_rejects_missing(self):
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            network = write_json(td / "network.json", network_doc(), sidecar=True)
            target = write_json(td / "P01-Credentialed-Target_x_LAB-FULL-R1.json", target_doc(), sidecar=False)
            resolver = write_json(td / "resolver.json", resolver_doc(), sidecar=True)
            out = td / "lab.p01bundle"
            with self.assertRaisesRegex(ValueError, "missing or invalid source SHA256 sidecar"):
                mod.create_bundle(
                    out, "LAB-001", "RUN-001", "NODE-01",
                    network, [target], None, resolver,
                    require_evidence_sidecars=True,
                )

    def test_duplicate_zip_entry_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            out = pathlib.Path(td) / "dup.p01bundle"
            with zipfile.ZipFile(out, "w") as z:
                z.writestr("bundle-manifest.json", "{}")
                z.writestr("bundle-manifest.json", "{}")
                z.writestr("integrity/sha256-manifest.json", "{}")
            with self.assertRaisesRegex(ValueError, "duplicate ZIP entry"):
                mod.validate_bundle(out)

    def test_path_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            out = pathlib.Path(td) / "traversal.p01bundle"
            with zipfile.ZipFile(out, "w") as z:
                z.writestr("bundle-manifest.json", "{}")
                z.writestr("integrity/sha256-manifest.json", "{}")
                z.writestr("../evil.json", "{}")
            with self.assertRaisesRegex(ValueError, "unsafe bundle path"):
                mod.validate_bundle(out)

    def test_bundle_id_stable_for_same_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            network, targets, manifest, resolver = self._inputs(td)
            one = pathlib.Path(td) / "one.p01bundle"
            two = pathlib.Path(td) / "two.p01bundle"
            first = mod.create_bundle(one, "LAB-001", "RUN-001", "NODE-01", network, targets, manifest, resolver)
            second = mod.create_bundle(two, "LAB-001", "RUN-001", "NODE-01", network, targets, manifest, resolver)
            self.assertEqual(first["bundle_id"], second["bundle_id"])


if __name__ == "__main__":
    unittest.main()
