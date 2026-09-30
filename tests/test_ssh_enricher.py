import importlib.util
import pathlib
import unittest

MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "credentialed_enrichment" / "P01_SSH_Enricher.py"
spec = importlib.util.spec_from_file_location("p01_ssh_enricher", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class CommandPolicyTests(unittest.TestCase):
    def test_catalog_is_read_only(self):
        mod.validate_command_catalog()

    def test_mutating_command_is_rejected(self):
        self.assertFalse(mod.command_is_read_only("rm -rf /tmp/foo"))
        self.assertFalse(mod.command_is_read_only("systemctl restart sshd"))
        self.assertTrue(mod.command_is_read_only("ip -j address"))
        self.assertTrue(mod.command_is_read_only(mod.EXEC_PROBE_COMMAND))


class ExecCapabilityTests(unittest.TestCase):
    def test_probe_requires_expected_output(self):
        self.assertTrue(mod.exec_probe_has_output({
            "success": True,
            "stdout": "P01_EXEC_PROBE"
        }))
        self.assertFalse(mod.exec_probe_has_output({
            "success": True,
            "stdout": ""
        }))
        self.assertFalse(mod.exec_probe_has_output({
            "success": False,
            "stdout": "P01_EXEC_PROBE"
        }))


class InterfaceParserTests(unittest.TestCase):
    def test_ip_json_and_candidates(self):
        text = """[
          {"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host"}]},
          {"ifname":"br-lan","address":"00:11:22:33:44:55",
           "addr_info":[{"family":"inet","local":"192.168.15.1","prefixlen":24,"scope":"global"}]},
          {"ifname":"guest","address":"00:11:22:33:44:66",
           "addr_info":[{"family":"inet","local":"192.168.50.1","prefixlen":24,"scope":"global"}]}
        ]"""
        interfaces = mod.parse_ip_json_interfaces(text)
        candidates = mod.build_candidate_networks(interfaces, [])
        nets = [x["network"] for x in candidates]
        self.assertEqual(nets, ["192.168.15.0/24", "192.168.50.0/24"])
        self.assertTrue(all(x["auto_scan"] is False for x in candidates))

    def test_ifconfig_busybox(self):
        text = """br0      Link encap:Ethernet  HWaddr 00:11:22:33:44:55
          inet addr:192.168.15.1  Bcast:192.168.15.255  Mask:255.255.255.0
eth1      Link encap:Ethernet  HWaddr 00:11:22:33:44:66
          inet addr:10.20.30.1  Bcast:10.20.30.255  Mask:255.255.255.0
"""
        interfaces = mod.parse_ifconfig_interfaces(text)
        candidates = mod.build_candidate_networks(interfaces, [])
        self.assertEqual([x["network"] for x in candidates], ["10.20.30.0/24", "192.168.15.0/24"])


class RouteParserTests(unittest.TestCase):
    def test_ip_route_text(self):
        rows = mod.parse_ip_route_text(
            "default via 192.168.15.1 dev eth0\n"
            "10.20.30.0/24 dev eth1 proto kernel src 10.20.30.1\n"
        )
        self.assertEqual(rows[0]["destination"], "default")
        self.assertEqual(rows[1]["destination"], "10.20.30.0/24")
        candidates = mod.build_candidate_networks([], rows)
        self.assertEqual([x["network"] for x in candidates], ["10.20.30.0/24"])


class SafetyTests(unittest.TestCase):
    def test_exception_redaction(self):
        value = mod._safe_exception_message(Exception("password=secret123 failed"))
        self.assertNotIn("secret123", value)
        self.assertIn("<redacted>", value)

    def test_public_network_never_auto_scans(self):
        interfaces = [{"ifname": "wan", "ipv4": [{"address": "203.0.113.10", "prefix_length": 24}]}]
        candidates = mod.build_candidate_networks(interfaces, [])
        self.assertEqual(len(candidates), 1)
        self.assertFalse(candidates[0]["auto_scan"])
        self.assertEqual(candidates[0]["authorization_status"], "unassessed")


if __name__ == "__main__":
    unittest.main()
