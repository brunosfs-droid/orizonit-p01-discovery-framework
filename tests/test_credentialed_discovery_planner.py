import importlib.util
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

cred_path = ROOT / "credential_manager" / "P01_Credential_Manager.py"
cred_spec = importlib.util.spec_from_file_location("P01_Credential_Manager", cred_path)
cred = importlib.util.module_from_spec(cred_spec)
sys.modules[cred_spec.name] = cred
cred_spec.loader.exec_module(cred)

planner_path = ROOT / "orchestrator" / "P01_Credentialed_Discovery_Planner.py"
planner_spec = importlib.util.spec_from_file_location("p01_planner", planner_path)
planner = importlib.util.module_from_spec(planner_spec)
sys.modules[planner_spec.name] = planner
planner_spec.loader.exec_module(planner)


class PlannerTests(unittest.TestCase):
    def setUp(self):
        self.discovery = {
            "metadata": {
                "scanner_name": "P01-Network-Discovery-Scanner",
                "scanner_version": "0.4.1",
                "run_label": "test",
            },
            "assets": [
                {
                    "ip": "192.168.100.40",
                    "hostname": "p01-lnx-ubu01",
                    "device_type_guess": "Linux/Unix Host",
                    "os_guess": "Linux/Unix-like",
                    "confidence": "Medium",
                    "open_ports": [
                        {"port": 22, "service": "ssh"},
                        {"port": 21, "service": "ftp"},
                    ],
                },
                {
                    "ip": "192.168.100.10",
                    "hostname": "p01-dc01",
                    "device_type_guess": "Windows Host",
                    "os_guess": "Windows",
                    "confidence": "High",
                    "open_ports": [
                        {"port": 5985, "service": "winrm-http"},
                        {"port": 445, "service": "microsoft-ds"},
                    ],
                },
                {
                    "ip": "192.168.100.99",
                    "hostname": None,
                    "device_type_guess": "Unknown",
                    "os_guess": "Unknown",
                    "confidence": "Low",
                    "open_ports": [{"port": 22, "service": "ssh"}],
                },
            ],
        }
        self.profiles = {
            "schema_version": "0.4b",
            "profiles": [
                {
                    "id": "linux-ssh",
                    "protocol": "ssh",
                    "scopes": ["192.168.100.0/24"],
                    "priority": 10,
                    "selectors": {
                        "device_types": ["Linux/Unix Host"],
                        "os_families": ["Linux/Unix-like"],
                        "services": ["ssh"],
                        "min_confidence": "Medium",
                        "allow_unknown": False,
                    },
                    "secret_refs": {"password": "prompt://linux"},
                },
                {
                    "id": "domain-winrm",
                    "protocol": "winrm",
                    "scopes": ["192.168.100.0/24"],
                    "priority": 10,
                    "selectors": {
                        "device_types": ["Windows Host"],
                        "os_families": ["Windows"],
                        "services": ["winrm-http", "winrm-https"],
                        "realms": ["P01LAB"],
                        "min_confidence": "High",
                        "allow_unknown": False,
                    },
                    "secret_refs": {"password": "prompt://win"},
                },
            ],
        }

    def test_detect_protocols(self):
        self.assertEqual(planner.detect_protocols(self.discovery["assets"][0]), ["ssh"])
        self.assertEqual(planner.detect_protocols(self.discovery["assets"][1]), ["winrm"])

    def test_plan_matches_linux_and_domain_windows(self):
        plan = planner.build_plan(
            self.discovery,
            self.profiles,
            realm_map={"192.168.100.10": "P01LAB"},
            max_candidates=2,
        )
        linux = next(x for x in plan["assets"] if x["ip"] == "192.168.100.40")
        win = next(x for x in plan["assets"] if x["ip"] == "192.168.100.10")
        unknown = next(x for x in plan["assets"] if x["ip"] == "192.168.100.99")

        self.assertEqual(linux["protocol_plans"][0]["eligible_profiles"][0]["profile"]["id"], "linux-ssh")
        self.assertEqual(win["protocol_plans"][0]["eligible_profiles"][0]["profile"]["id"], "domain-winrm")
        self.assertEqual(unknown["protocol_plans"][0]["eligible_profile_count"], 0)

    def test_missing_realm_blocks_domain_profile(self):
        plan = planner.build_plan(self.discovery, self.profiles, realm_map={})
        win = next(x for x in plan["assets"] if x["ip"] == "192.168.100.10")
        self.assertEqual(win["protocol_plans"][0]["eligible_profile_count"], 0)


if __name__ == "__main__":
    unittest.main()
