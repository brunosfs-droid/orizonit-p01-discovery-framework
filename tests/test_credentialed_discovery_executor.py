import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
cred_path=ROOT/"credential_manager"/"P01_Credential_Manager.py"
cred_spec=importlib.util.spec_from_file_location("P01_Credential_Manager",cred_path)
cred=importlib.util.module_from_spec(cred_spec);sys.modules[cred_spec.name]=cred;cred_spec.loader.exec_module(cred)
path=ROOT/"orchestrator"/"P01_Credentialed_Discovery_Executor.py"
spec=importlib.util.spec_from_file_location("p01_executor",path)
mod=importlib.util.module_from_spec(spec);sys.modules[spec.name]=mod;spec.loader.exec_module(mod)

class ExecutorTests(unittest.TestCase):
    def setUp(self):
        self.profile={
            "id":"domain-winrm","enabled":True,"protocol":"winrm","auth_type":"password",
            "scopes":["192.168.100.30/32"],"priority":10,"username":"P01LAB\\svc",
            "secret_refs":{"password":"wincred://ORIZONIT/P01/domain-winrm"},
            "max_attempts_per_target":1,"failure_budget_per_job":1,"tags":["domain"],
            "selectors":{"device_types":["Windows Host"],"os_families":["Windows"],"services":["winrm-http"],
                         "realms":["P01LAB"],"hostname_patterns":["P01-W11-01*"],"min_confidence":"High","allow_unknown":False}
        }
        safe=cred._safe_profile_view(self.profile)
        self.plan={"metadata":{"planner_name":"P01-Credentialed-Discovery-Planner","planner_version":"0.4b.3.1"},
                   "source":{"run_label":"lab"},
                   "assets":[
                    {"ip":"192.168.100.30","hostname":"P01-W11-01.p01.lab.test","device_type":"Windows Host",
                     "os_family":"Windows","confidence":"High","realm":"P01LAB","credentialed_action_status":"adapter_candidate",
                     "protocol_plans":[{"protocol":"winrm","action":"adapter_candidate","eligible_profiles":[{
                        "profile":safe,"matched_scope":"192.168.100.30/32","scope_prefix_length":32,"selector_score":90,
                        "matched_selectors":["device_types","os_families","realms","services","hostname_patterns","min_confidence"]}]}]},
                    {"ip":"192.168.100.99","hostname":"SKIP","credentialed_action_status":"not_planned","protocol_plans":[]}
                   ]}
        self.profiles={"schema_version":"0.4b","profiles":[self.profile]}

    def test_not_planned_is_never_action(self):
        actions=mod.build_actions(self.plan,self.profiles)
        self.assertEqual(len(actions),1)
        self.assertEqual(actions[0]["target_ip"],"192.168.100.30")
        self.assertEqual(actions[0]["execution_eligibility"],"ready")

    def test_profile_drift_blocks(self):
        profiles=json.loads(json.dumps(self.profiles))
        profiles["profiles"][0]["username"]="P01LAB\\changed"
        action=mod.build_actions(self.plan,profiles)[0]
        self.assertEqual(action["execution_eligibility"],"blocked")
        self.assertEqual(action["skip_reason"],"profile_drift_since_plan_generation")

    def test_same_secret_reference_same_identity(self):
        p2=json.loads(json.dumps(self.profile));p2["id"]="another";p2["scopes"]=["192.168.100.10/32"]
        self.assertEqual(mod.cred_id(self.profile),mod.cred_id(p2))

    def test_auth_failure_opens_budget_one(self):
        action=mod.build_actions(self.plan,self.profiles)[0]
        state=mod.circuits([action]);cid=action["credential_identity_id"]
        mod.update_circuit(state,cid,{"success":False,"failure_category":"authentication"})
        self.assertTrue(state[cid]["circuit_open"])
        self.assertEqual(state[cid]["authentication_failures"],1)

    def test_transport_does_not_open_circuit(self):
        action=mod.build_actions(self.plan,self.profiles)[0]
        state=mod.circuits([action]);cid=action["credential_identity_id"]
        mod.update_circuit(state,cid,{"success":False,"failure_category":"transport"})
        self.assertFalse(state[cid]["circuit_open"])
        self.assertEqual(state[cid]["authentication_failures"],0)
        self.assertEqual(state[cid]["transport_failures"],1)

    def test_ssh_failure_classifier(self):
        a=mod.classify_ssh({"success":False,"error_type":"AuthenticationException","error":"Authentication failed"})
        self.assertEqual(a["failure_category"],"authentication")
        self.assertTrue(a["counts_against_credential_budget"])
        t=mod.classify_ssh({"success":False,"error_type":"NoValidConnectionsError","error":"Unable to connect"})
        self.assertEqual(t["failure_category"],"transport")
        self.assertFalse(t["counts_against_credential_budget"])

    def test_plan_sha256(self):
        with tempfile.TemporaryDirectory() as td:
            td=pathlib.Path(td);p=td/"plan.json";p.write_text('{"a":1}\n',encoding="utf-8")
            h=mod.digest(p);s=td/"plan.json.sha256";s.write_text(f"{h}  plan.json\n",encoding="utf-8")
            self.assertEqual(mod.verify(p,s),h)

    def test_dry_run_resolves_no_secrets(self):
        with tempfile.TemporaryDirectory() as td:
            payload=mod.run_job(self.plan,self.profiles,"a"*64,pathlib.Path(td),"dry")
            self.assertEqual(payload["metadata"]["execution_mode"],"dry_run")
            self.assertFalse(payload["metadata"]["secret_resolution"])
            self.assertFalse(payload["metadata"]["authentication_attempts"])
            self.assertEqual(payload["summary"]["dry_run_ready"],1)
            self.assertEqual(payload["summary"]["completed"],0)

if __name__=="__main__":
    unittest.main()
