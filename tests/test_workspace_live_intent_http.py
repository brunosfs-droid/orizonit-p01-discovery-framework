"""v0.6.43: opt-in HTTP scan preview requires trusted scope and private audit."""
from contextlib import closing
import http.client
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"server"))
import P01_Workspace_API as api
import P01_Workspace_Audit as audit
import test_operator_auth as fixture
import test_workspace_api as api_fixture

URL = api.BASE + "/A/scan-intents/preview"
VALID = dict(generation=2,scope_id="lab",mode="auth_only",ack_authorized_access=True)


class BindingScanScopeTests(unittest.TestCase):
    def test_trusted_immutable_scope_binding(self):
        policy=api_fixture.bindings()
        policy["approved_scan_scopes"]={"A":{"lab":{
            "networks":["192.168.100.20/32"],"modes":["auth_only"]}}}
        parsed=api.BindingPolicy(json.dumps(policy).encode(),fixture.policy())
        scope=parsed.approved_scan_scopes._lookup("A","lab")
        self.assertEqual(scope["networks"],("192.168.100.20/32",))
        with self.assertRaises(AttributeError):
            parsed.approved_scan_scopes=None
        with self.assertRaises(TypeError):
            scope["networks"]=()
        self.assertIsNotNone(api_fixture.policy().approved_scan_scopes)

    def test_policy_rejects_public_or_credential_bearing_scope(self):
        doc=api_fixture.bindings()
        for spec in [
            {"networks":["8.8.8.8/32"],"modes":["auth_only"]},
            {"networks":["192.168.100.0/24"],"modes":["auth_only"],"credentials":"private"},
            {"networks":["192.168.1.1"],"modes":["auth_only"]},
        ]:
            doc["approved_scan_scopes"]={"A":{"lab":spec}}
            with self.assertRaisesRegex(ValueError,"invalid workspace binding policy"):
                api.BindingPolicy(json.dumps(doc).encode(),fixture.policy())


class HTTPScanPreviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.auth=api.authn.LocalAuth(fixture.policy())
        self.service=Mock()
        self.service.auth=self.auth
        self.service.execute.return_value=dict(
            status="preview_only",execution_authorized=False,
            network_activity_performed=False)
        self.server=api.WorkspaceServer(("127.0.0.1",0),self.service)
        self.worker=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.worker.start()
        self.addCleanup(self.stop)

    def stop(self):
        self.server.shutdown()
        self.worker.join(5)
        self.server.server_close()
        if self.server.audit is not None:
            self.server.audit.close()

    def request(self,method,path,doc=None,headers=None):
        data=None if doc is None else json.dumps(doc)
        with closing(http.client.HTTPConnection("127.0.0.1",self.server.server_port,timeout=5)) as conn:
            conn.request(method,path,data,headers or {})
            response=conn.getresponse()
            return response.status,json.loads(response.read())

    def login(self):
        status,result=self.request("POST","/api/v1/operator/session",
              {"username":"reader","password":fixture.PASSWORD},
              {"Content-Type":"application/json"})
        self.assertEqual(status,201)
        return {"Authorization":"Bearer "+result["access_token"],
                "Content-Type":"application/json"}

    def with_audit(self):
        path=Path(self.tmp.name)/"workspace-audit.jsonl"
        self.server.audit=audit.FileAudit(path)
        return path

    def test_no_audit_blocks_preview_before_service_call(self):
        h=self.login()
        code,doc=self.request("POST",URL,VALID,h)
        self.assertEqual(code,503,doc)
        self.assertEqual(doc["error_code"],"workspace_audit_unavailable")
        self.service.execute.assert_not_called()

    def test_authorized_audited_preview_never_exposes_scope_or_credentials(self):
        path=self.with_audit()
        h=self.login()
        status,doc=self.request("POST",URL,VALID,h)
        self.assertEqual(status,200,doc)
        self.assertFalse(doc["execution_authorized"])
        self.assertEqual(self.service.execute.call_args.args[1],"live_scan_intent")
        self.assertEqual(self.service.execute.call_args.kwargs,VALID)
        self.assertNotIn("192.168.",str(doc))
        self.service.execute.reset_mock()
        raw=path.read_text()
        self.assertIn('"operation":"scan_intent_preview"',raw)
        self.assertNotIn("scope_id",raw)
        self.assertNotIn('"lab"',raw)
        self.assertNotIn("auth_only",raw)
        self.assertNotIn("scope_digest_sha256",raw)
        self.assertNotIn("192.168.",raw)

    def test_disallow_request_supplied_targets_credentials_and_unknown_fields(self):
        self.with_audit()
        h=self.login()
        failures=[
            dict(VALID,targets=["192.168.100.10"]),
            dict(VALID,password="PRIVATE-TEST"),
            dict(VALID,command="run"),
            dict(VALID,ack_authorized_access=False),
            dict(VALID,ack_authorized_access=1),
            dict(VALID,mode="execute"),
            dict(VALID,scope_id="../B"),
            dict(VALID,generation="2"),
            dict(VALID,credentials={"password":"redact"})
        ]
        for payload in failures:
            with self.subTest(payload=list(payload)):
                status,result=self.request("POST",URL,payload,h)
                self.assertEqual(status,400,result)
        self.assertEqual(self.request("GET",URL+"?generation=2",headers=h)[0],404)
        self.assertEqual(self.request("POST",URL+"?x=1",VALID,h)[0],404)
        self.service.execute.assert_not_called()

    def test_invalid_or_revoked_session_denied_before_preview(self):
        self.with_audit()
        status,result=self.request("POST",URL,VALID,{"Content-Type":"application/json"})
        self.assertEqual(status,401,result)
        h=self.login()
        self.auth.logout(h["Authorization"].split(" ",1)[1])
        self.assertEqual(self.request("POST",URL,VALID,h)[0],401)
        self.service.execute.assert_not_called()

    def test_audit_operation_classifies_only_known_route_and_method(self):
        self.assertEqual(audit.operation("POST",URL),"scan_intent_preview")
        self.assertEqual(audit.operation("GET",URL),"other")
        self.assertEqual(audit.operation("POST",URL+"/run"),"other")
        self.assertEqual(audit.operation("POST",URL+"?scope_id=PRIVATE"),"scan_intent_preview")


if __name__=="__main__":
    unittest.main()
