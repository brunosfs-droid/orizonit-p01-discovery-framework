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
