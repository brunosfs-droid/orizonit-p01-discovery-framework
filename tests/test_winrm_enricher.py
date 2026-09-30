import importlib.util
import pathlib
import unittest

MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "credentialed_enrichment" / "P01_WinRM_Enricher.py"
spec = importlib.util.spec_from_file_location("p01_winrm_enricher", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class ReadOnlyTests(unittest.TestCase):
    def test_collection_script_is_read_only(self):
        self.assertTrue(mod.powershell_is_read_only(mod.POWERSHELL_COLLECTION))
        self.assertTrue(mod.powershell_is_read_only(mod.POWERSHELL_AUTH_PROBE))
    def test_mutating_script_rejected(self):
        self.assertFalse(mod.powershell_is_read_only("Set-Service -Name WinRM -StartupType Automatic"))
        self.assertFalse(mod.powershell_is_read_only("Restart-Service WinRM"))

class ContextTests(unittest.TestCase):
    def test_http_context(self):
        c = mod.build_context("http", "Windows Host", "Windows", "PC01", None, "P01LAB", "High")
        self.assertEqual(c["services"], ["winrm-http"])
        self.assertEqual(c["realm"], "P01LAB")
    def test_https_context(self):
        c = mod.build_context("https", "Windows Host", "Windows", None, None, "local", "High")
        self.assertEqual(c["services"], ["winrm-https"])

class CandidateNetworkTests(unittest.TestCase):
    def test_build_candidate_networks(self):
        payload = {"network": {
            "interfaces": [
                {"interface_alias": "LAN", "ipv4": [{"address": "192.168.100.20", "prefix_length": 24}]},
                {"interface_alias": "NAT", "ipv4": [{"address": "172.31.250.5", "prefix_length": 16}]},
            ],
            "routes": [
                {"destination_prefix": "0.0.0.0/0", "next_hop": "172.31.250.2", "interface_index": 8},
                {"destination_prefix": "192.168.100.0/24", "next_hop": "0.0.0.0", "interface_index": 4},
            ],
        }}
        result = mod.build_candidate_networks(payload)
        self.assertEqual([x["network"] for x in result], ["172.31.0.0/16", "192.168.100.0/24"])
        self.assertTrue(all(x["auto_scan"] is False for x in result))

class JsonParsingTests(unittest.TestCase):
    def test_parse_collection(self):
        value = mod.parse_collection_json('{"identity":{"computer_name":"PC01"}}')
        self.assertEqual(value["identity"]["computer_name"], "PC01")
    def test_empty_collection_rejected(self):
        with self.assertRaises(ValueError):
            mod.parse_collection_json("")

class ErrorSafetyTests(unittest.TestCase):
    def test_secret_redaction(self):
        value = mod.safe_error(Exception("password=abc123 authentication failed"))
        self.assertNotIn("abc123", value)
        self.assertIn("<redacted>", value)

if __name__ == "__main__":
    unittest.main()
