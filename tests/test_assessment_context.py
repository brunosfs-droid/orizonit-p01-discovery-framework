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

assessment_path = ROOT / "assessment" / "P01_Assessment_Context.py"
assessment_spec = importlib.util.spec_from_file_location("P01_Assessment_Context", assessment_path)
assessment = importlib.util.module_from_spec(assessment_spec)
sys.modules[assessment_spec.name] = assessment
assessment_spec.loader.exec_module(assessment)

planner_path = ROOT / "orchestrator" / "P01_Credentialed_Discovery_Planner.py"
planner_spec = importlib.util.spec_from_file_location("p01_planner_v046", planner_path)
planner = importlib.util.module_from_spec(planner_spec)
sys.modules[planner_spec.name] = planner
planner_spec.loader.exec_module(planner)


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.manifest = assessment.build_manifest(
            assessment_id="P01LAB-CTX-R1",
            environment_label="P01LAB",
            authorized_scopes=["192.168.100.0/24"],
            exclude_scopes=[],
            domains=[{
                "dns_domain": "p01.lab.test",
                "netbios_name": "P01LAB",
                "forest": "p01.lab.test",
                "scopes": ["192.168.100.0/24"],
                "evidence_state": "declared",
            }],
            allowed_protocols=["ssh", "winrm"],
        )

    def test_manifest_valid(self):
        result = assessment.validate_manifest(self.manifest)
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["domain_count"], 1)

    def test_manifest_rejects_plaintext_secret(self):
        bad = dict(self.manifest)
        bad["password"] = "should-not-be-here"
        result = assessment.validate_manifest(bad)
        self.assertFalse(result["valid"])
        self.assertTrue(any("Assessment Manifest" in x for x in result["errors"]))

    def test_declared_domain_is_not_effective_without_observation(self):
        asset = {
            "ip": "192.168.100.30",
            "hostname": "P01-W11-01",
            "device_type_guess": "Windows Host",
        }
        ctx = assessment.manifest_context_for_asset(asset, self.manifest)
        self.assertEqual(len(ctx["declared_realm_candidates"]), 1)
        self.assertIsNone(ctx["realm"])
        self.assertIsNone(ctx["realm_evidence_state"])

    def test_hostname_suffix_promotes_realm_to_observed(self):
        asset = {
            "ip": "192.168.100.30",
            "hostname": "P01-W11-01.p01.lab.test",
            "device_type_guess": "Windows Host",
        }
        ctx = assessment.manifest_context_for_asset(asset, self.manifest)
        self.assertEqual(ctx["realm"], "P01LAB")
        self.assertEqual(ctx["realm_kind"], "ad_domain")
        self.assertEqual(ctx["realm_evidence_state"], "observed")
        self.assertIn("windows", ctx["target_classes"])


class CredentialTaxonomyTests(unittest.TestCase):
    def test_workstation_profile_adds_windows_family(self):
        profile = assessment.build_credential_profile(
            "w11", "winrm", ["192.168.100.30/32"], "P01LAB\\svc",
            "prompt://w11", "ad_domain", "P01LAB", ["windows_workstation"],
            "inventory", ["discovery", "inventory"], "winrm-http",
            ["P01-W11-*"], "observed", False,
        )
        self.assertIn("windows", profile["target_classes"])
        self.assertIn("windows_workstation", profile["target_classes"])
        doc = {"schema_version": "0.4b", "profiles": [profile]}
        result = cred.validate_profile_document(doc)
        self.assertTrue(result["valid"], result["errors"])

    def test_high_privilege_requires_ack(self):
        profile = assessment.build_credential_profile(
            "da", "winrm", ["192.168.100.10/32"], "P01LAB\\admin",
            "prompt://da", "ad_domain", "P01LAB", ["domain_controller"],
            "domain_admin", ["inventory"], "winrm-http",
            ["P01-DC01*"], "observed", False,
        )
        result = cred.validate_profile_document({"schema_version": "0.4b", "profiles": [profile]})
        self.assertFalse(result["valid"])
        self.assertTrue(any("high_privilege_acknowledged" in x for x in result["errors"]))

    def test_placeholder_username_warns(self):
        doc = {
            "schema_version": "0.4b",
            "profiles": [{
                "id": "placeholder",
                "protocol": "winrm",
                "scopes": ["192.168.100.10/32"],
                "username": "P01LAB\\SEU_USUARIO",
                "secret_refs": {"password": "prompt://x"},
            }],
        }
        result = cred.validate_profile_document(doc)
        self.assertTrue(result["valid"], result["errors"])
        self.assertTrue(any("placeholder" in x.lower() for x in result["warnings"]))


class PlannerManifestTests(unittest.TestCase):
    def setUp(self):
        self.manifest = assessment.build_manifest(
            "P01LAB-CTX-R1", "P01LAB", ["192.168.100.0/24"], [],
            [{
                "dns_domain": "p01.lab.test",
                "netbios_name": "P01LAB",
                "forest": "p01.lab.test",
                "scopes": ["192.168.100.0/24"],
                "evidence_state": "declared",
            }],
            ["winrm"],
        )
        self.profile = assessment.build_credential_profile(
            "w11", "winrm", ["192.168.100.30/32"], "P01LAB\\svc",
            "prompt://w11", "ad_domain", "P01LAB", ["windows_workstation"],
            "inventory", ["inventory"], "winrm-http", ["P01-W11-*"],
            "observed", False,
        )
        self.profiles = {"schema_version": "0.4b", "profiles": [self.profile]}

    def _discovery(self, hostname):
        return {
            "metadata": {"scanner_name": "P01-Network-Discovery-Scanner", "scanner_version": "0.4.1", "run_label": "ctx"},
            "assets": [{
                "ip": "192.168.100.30",
                "hostname": hostname,
                "device_type_guess": "Windows Host",
                "os_guess": "Windows",
                "confidence": "High",
                "open_ports": [{"port": 5985, "service": "winrm-http"}],
            }],
        }

    def test_declared_context_alone_does_not_create_candidate(self):
        plan = planner.build_plan(self._discovery("P01-W11-01"), self.profiles, manifest=self.manifest)
        asset = plan["assets"][0]
        self.assertEqual(asset["realm_evidence_state"], None)
        self.assertEqual(asset["credentialed_action_status"], "not_planned")
        self.assertEqual(asset["protocol_plans"][0]["eligible_profile_count"], 0)

    def test_observed_hostname_domain_allows_profile(self):
        plan = planner.build_plan(self._discovery("P01-W11-01.p01.lab.test"), self.profiles, manifest=self.manifest)
        asset = plan["assets"][0]
        self.assertEqual(asset["realm"], "P01LAB")
        self.assertEqual(asset["realm_kind"], "ad_domain")
        self.assertEqual(asset["realm_evidence_state"], "observed")
        self.assertEqual(asset["credentialed_action_status"], "adapter_candidate")
        self.assertEqual(asset["protocol_plans"][0]["eligible_profile_count"], 1)
        self.assertFalse(plan["metadata"]["secret_resolution"])
        self.assertFalse(plan["metadata"]["authentication_attempts"])

    def test_credentialed_confirmed_requirement_blocks_observed(self):
        profile = dict(self.profile)
        profile["realm_evidence_min"] = "credentialed_confirmed"
        plan = planner.build_plan(
            self._discovery("P01-W11-01.p01.lab.test"),
            {"schema_version": "0.4b", "profiles": [profile]},
            manifest=self.manifest,
        )
        self.assertEqual(plan["assets"][0]["credentialed_action_status"], "not_planned")

    def test_conflicting_realm_map_blocks_domain_candidate(self):
        plan = planner.build_plan(
            self._discovery("P01-W11-01.p01.lab.test"),
            self.profiles,
            realm_map={"192.168.100.30": "OTHER"},
            manifest=self.manifest,
        )
        asset = plan["assets"][0]
        self.assertIn("realm_map_conflicts_with_observed_manifest_domain", asset["context_conflicts"])
        self.assertEqual(asset["credentialed_action_status"], "not_planned")


if __name__ == "__main__":
    unittest.main()
