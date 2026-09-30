import importlib.util, pathlib, unittest
MODULE_PATH=pathlib.Path(__file__).resolve().parents[1]/"credentialed_enrichment"/"P01_WinRM_Enricher.py"
spec=importlib.util.spec_from_file_location("p01_winrm_enricher",MODULE_PATH);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)

class ReadOnlyTests(unittest.TestCase):
    def test_all_scripts_read_only(self):
        mod.validate_scripts()
    def test_mutating_rejected(self):
        self.assertFalse(mod.powershell_is_read_only("Set-Service -Name WinRM -StartupType Automatic"))

    def test_no_parenthesized_if_try_for_ps51(self):
        # Windows PowerShell 5.1 does not accept statement keywords wrapped
        # as parenthesized expressions inside hashtable values.
        for name, script in mod.POWERSHELL_SECTIONS.items():
            compact = script.replace(" ", "").lower()
            self.assertNotIn("=(if(", compact, name)
            self.assertNotIn("=(try{", compact, name)

class FailureClassificationTests(unittest.TestCase):
    def test_connect_timeout_does_not_burn_credential_budget(self):
        r=mod.classify_attempt_failure(
            "ConnectTimeout",
            "Connection to 192.0.2.10 timed out. (connect timeout=30)",
            None,
        )
        self.assertEqual(r["failure_category"],"transport")
        self.assertFalse(r["counts_against_credential_budget"])

    def test_http_401_counts_as_authentication_failure(self):
        r=mod.classify_attempt_failure(None,"HTTP 401 Unauthorized",401)
        self.assertEqual(r["failure_category"],"authentication")
        self.assertTrue(r["counts_against_credential_budget"])

    def test_unknown_remote_failure_is_conservative(self):
        r=mod.classify_attempt_failure(None,"remote script failed",500)
        self.assertEqual(r["failure_category"],"remote_execution_or_unknown")
        self.assertFalse(r["counts_against_credential_budget"])


class SizeRegressionTests(unittest.TestCase):
    def test_each_section_small(self):
        for name,script in mod.POWERSHELL_SECTIONS.items():
            self.assertLess(len(script),2400,name)

class AssembleTests(unittest.TestCase):
    def test_partial_failure_preserved(self):
        values={"identity":{"computer_name":"PC01"},"interfaces":[],"routes":[],"dns":[]}
        evidence=[{"section":"identity","success":True},{"section":"roles","success":False}]
        p=mod.assemble_collection(values,evidence)
        self.assertEqual(p["identity"]["computer_name"],"PC01")
        self.assertEqual(p["collection_status"],"collected_with_section_failures")
        self.assertEqual(p["failed_section_count"],1)

class NetworkTests(unittest.TestCase):
    def test_candidate_networks(self):
        payload={"network":{"interfaces":[{"interface_alias":"LAN","ipv4":[{"address":"192.168.100.20","prefix_length":24}]},{"interface_alias":"NAT","ipv4":[{"address":"172.31.250.5","prefix_length":16}]}],"routes":[{"destination_prefix":"0.0.0.0/0"},{"destination_prefix":"192.168.100.0/24","interface_index":4}]}}
        result=mod.build_candidate_networks(payload)
        self.assertEqual([x["network"] for x in result],["172.31.0.0/16","192.168.100.0/24"])
        self.assertTrue(all(x["auto_scan"] is False for x in result))

    def test_route_host_prefixes_not_candidates(self):
        payload = {"network": {
            "interfaces": [],
            "routes": [
                {"destination_prefix": "192.168.100.20/32", "next_hop": "0.0.0.0", "interface_index": 4},
                {"destination_prefix": "192.168.100.255/32", "next_hop": "0.0.0.0", "interface_index": 4},
                {"destination_prefix": "255.255.255.255/32", "next_hop": "0.0.0.0", "interface_index": 4},
                {"destination_prefix": "10.20.30.0/24", "next_hop": "10.0.0.1", "interface_index": 8},
            ],
        }}
        result = mod.build_candidate_networks(payload)
        self.assertEqual([x["network"] for x in result], ["10.20.30.0/24"])

if __name__=="__main__":unittest.main()
