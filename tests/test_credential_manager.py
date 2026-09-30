import importlib.util
import pathlib
import unittest

MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "credential_manager" / "P01_Credential_Manager.py"
spec = importlib.util.spec_from_file_location("p01_credential_manager", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class ValidationTests(unittest.TestCase):
    def test_rejects_plaintext_password(self):
        doc = {
            "schema_version": "0.4b",
            "profiles": [{
                "id": "bad",
                "protocol": "ssh",
                "scopes": ["192.168.1.1/32"],
                "password": "do-not-store-this",
                "secret_refs": {"password": "prompt://bad"},
            }],
        }
        result = mod.validate_profile_document(doc)
        self.assertFalse(result["valid"])
        self.assertTrue(any("plaintext secret" in x for x in result["errors"]))

    def test_valid_document(self):
        doc = {
            "schema_version": "0.4b",
            "profiles": [{
                "id": "good",
                "protocol": "ssh",
                "scopes": ["192.168.1.0/24"],
                "priority": 10,
                "secret_refs": {"password": "env://P01_TEST_SECRET"},
            }],
        }
        result = mod.validate_profile_document(doc)
        self.assertTrue(result["valid"], result["errors"])


class MatchTests(unittest.TestCase):
    def test_scope_specificity_and_priority(self):
        doc = {
            "schema_version": "0.4b",
            "profiles": [
                {"id": "broad", "protocol": "ssh", "scopes": ["192.168.0.0/16"], "priority": 20, "secret_refs": {"password": "prompt://broad"}},
                {"id": "host", "protocol": "ssh", "scopes": ["192.168.15.7/32"], "priority": 10, "secret_refs": {"password": "prompt://host"}},
                {"id": "wrong-proto", "protocol": "winrm", "scopes": ["192.168.15.7/32"], "priority": 1, "secret_refs": {"password": "prompt://x"}},
            ],
        }
        matches = mod.match_profiles(doc, "192.168.15.7", "ssh", 2)
        self.assertEqual([m.profile["id"] for m in matches], ["host", "broad"])

    def test_disabled_profile_is_skipped(self):
        doc = {
            "schema_version": "0.4b",
            "profiles": [
                {"id": "off", "enabled": False, "protocol": "ssh", "scopes": ["192.168.15.7/32"], "secret_refs": {"password": "prompt://off"}},
            ],
        }
        self.assertEqual(mod.match_profiles(doc, "192.168.15.7", "ssh"), [])


class ContextAwareMatchTests(unittest.TestCase):
    def setUp(self):
        self.doc = {
            "schema_version": "0.4b",
            "profiles": [
                {
                    "id": "linux-subnet",
                    "enabled": True,
                    "protocol": "ssh",
                    "scopes": ["192.168.100.0/24"],
                    "priority": 20,
                    "username": "orizoncollector",
                    "selectors": {
                        "device_types": ["Linux/Unix Host"],
                        "os_families": ["Linux/Unix-like"],
                        "services": ["ssh"],
                        "min_confidence": "Medium",
                        "allow_unknown": False
                    },
                    "secret_refs": {"password": "prompt://linux"}
                },
                {
                    "id": "router-host",
                    "enabled": True,
                    "protocol": "ssh",
                    "scopes": ["192.168.100.1/32"],
                    "priority": 10,
                    "username": "admin",
                    "selectors": {
                        "device_types": ["Router/Gateway", "Network/Embedded Candidate"],
                        "services": ["ssh"],
                        "allow_unknown": False
                    },
                    "secret_refs": {"password": "prompt://router"}
                },
                {
                    "id": "unknown-explicit",
                    "enabled": True,
                    "protocol": "ssh",
                    "scopes": ["192.168.100.0/24"],
                    "priority": 100,
                    "selectors": {"services": ["ssh"], "allow_unknown": True},
                    "secret_refs": {"password": "prompt://unknown"}
                }
            ]
        }

    def test_linux_context_matches_linux_profile(self):
        ctx = {
            "device_type": "Linux/Unix Host",
            "os_family": "Linux/Unix-like",
            "services": ["ssh", "ftp"],
            "confidence": "Medium",
            "hostname": "p01-lnx-ubu01"
        }
        matches = mod.match_profiles(self.doc, "192.168.100.40", "ssh", 3, context=ctx)
        self.assertEqual([m.profile["id"] for m in matches], ["linux-subnet", "unknown-explicit"])
        self.assertGreater(matches[0].selector_score, matches[1].selector_score)

    def test_windows_context_does_not_receive_linux_profile(self):
        ctx = {
            "device_type": "Windows Host",
            "os_family": "Windows",
            "services": ["winrm-http", "rdp"],
            "confidence": "High",
        }
        matches = mod.match_profiles(self.doc, "192.168.100.20", "ssh", 3, context=ctx)
        self.assertEqual(matches, [])

    def test_unknown_requires_explicit_allow_unknown(self):
        ctx = {
            "device_type": "Unknown",
            "os_family": "Unknown",
            "services": ["ssh"],
            "confidence": "Low",
        }
        matches = mod.match_profiles(self.doc, "192.168.100.99", "ssh", 3, context=ctx)
        self.assertEqual([m.profile["id"] for m in matches], ["unknown-explicit"])

    def test_service_selector_is_hard_gate(self):
        ctx = {
            "device_type": "Linux/Unix Host",
            "os_family": "Linux/Unix-like",
            "services": ["http"],
            "confidence": "High",
        }
        matches = mod.match_profiles(self.doc, "192.168.100.40", "ssh", 3, context=ctx)
        self.assertEqual([m.profile["id"] for m in matches], ["unknown-explicit"])

    def test_context_from_network_asset(self):
        asset = {
            "hostname": "P01-LNX-UBU01.p01.lab.test",
            "device_type_guess": "Linux/Unix Host",
            "os_guess": "Linux/Unix-like",
            "confidence": "Medium",
            "open_ports": [
                {"port": 22, "service": "ssh"},
                {"port": 21, "service": "ftp"}
            ]
        }
        ctx = mod.context_from_network_asset(asset)
        self.assertEqual(ctx["device_type"], "Linux/Unix Host")
        self.assertEqual(ctx["os_family"], "Linux/Unix-like")
        self.assertEqual(ctx["services"], ["ftp", "ssh"])


class SelectorValidationTests(unittest.TestCase):
    def test_invalid_selector_key_is_rejected(self):
        doc = {
            "schema_version": "0.4b",
            "profiles": [{
                "id": "bad-selector",
                "protocol": "ssh",
                "scopes": ["192.168.100.0/24"],
                "selectors": {"device_magic": ["linux"]},
                "secret_refs": {"password": "prompt://x"}
            }]
        }
        result = mod.validate_profile_document(doc)
        self.assertFalse(result["valid"])
        self.assertTrue(any("unsupported key" in x for x in result["errors"]))

    def test_invalid_failure_budget_is_rejected(self):
        doc = {
            "schema_version": "0.4b",
            "profiles": [{
                "id": "bad-budget",
                "protocol": "ssh",
                "scopes": ["192.168.100.0/24"],
                "failure_budget_per_job": 0,
                "secret_refs": {"password": "prompt://x"}
            }]
        }
        result = mod.validate_profile_document(doc)
        self.assertFalse(result["valid"])
        self.assertTrue(any("failure_budget_per_job" in x for x in result["errors"]))


class SecretRefTests(unittest.TestCase):
    def test_prompt_status(self):
        status = mod.secret_ref_status("prompt://demo")
        self.assertTrue(status["available"])
        self.assertTrue(status["interactive"])

    def test_unsupported_scheme_rejected(self):
        with self.assertRaises(mod.CredentialConfigError):
            mod._parse_secret_ref("file://secret.txt")


if __name__ == "__main__":
    unittest.main()
