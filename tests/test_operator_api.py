"""Real HTTP login/expiry/logout; denies before any PostgreSQL access."""
from contextlib import closing
import http.client
import json
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

import test_operator_auth as fixture
import P01_Operator_API as api


class OperatorAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name); self.path = self.base/'accounts.json'
        self.path.write_text(json.dumps(fixture.document())); self.path.chmod(0o600)
        self.server = api.create_server(self.path, port=0)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True); self.worker.start()
        self.addCleanup(self.stop)

    def stop(self):
        self.server.shutdown(); self.server.server_close(); self.worker.join(timeout=5)

    def request(self, method, path, payload=None, headers=None, context=None):
        cls = http.client.HTTPSConnection if context else http.client.HTTPConnection
        kwargs = {'context':context} if context else {}
        with closing(cls('127.0.0.1', self.server.server_port, timeout=10, **kwargs)) as conn:
            conn.request(method, path, json.dumps(payload) if payload is not None else None, headers or {})
            response = conn.getresponse(); raw = response.read()
            self.assertEqual(response.getheader('Cache-Control'), 'no-store')
            self.assertEqual(response.getheader('Connection'), 'close')
            self.assertIsNone(response.getheader('Set-Cookie'))
            self.assertIsNone(response.getheader('Access-Control-Allow-Origin'))
            return response.status, json.loads(raw)

    def login(self):
        status, doc = self.request('POST','/api/v1/operator/session',
            dict(username='reader',password=fixture.PASSWORD), {'Content-Type':'application/json'})
        self.assertEqual(status,201)
        return {'Authorization':'Bearer '+doc['access_token']}

    def test_health_and_full_http_login_report_logout(self):
        self.assertEqual(self.request('GET','/healthz')[1]['authentication_mode'],'local_operator')
        headers = self.login()
        with patch.object(api.report.pg,'open_connection') as connect, patch.object(api.report,'show_assessment',
                return_value=dict(status='found',assessment_id='LAB-001',source_bytes_revalidated=False)) as query:
            status, doc = self.request('GET','/api/v1/assessments/LAB-001/report?limit=1',headers=headers)
            self.assertEqual(status,200); self.assertFalse(doc['source_bytes_revalidated'])
            connect.assert_called_once(); self.assertEqual(query.call_args.args[1:5],('LAB-001','',-1,1))
        self.assertEqual(self.request('DELETE','/api/v1/operator/session',headers=headers)[0],200)
        with patch.object(api.report.pg,'open_connection') as connect:
            self.assertEqual(self.request('GET','/api/v1/assessments/LAB-001/report',headers=headers)[0],401)
        connect.assert_not_called()

    def test_missing_forged_node_query_token_and_cross_scope_never_connect(self):
        headers = self.login()
        cases = [('/api/v1/assessments/LAB-001/report',None,401),
                 ('/api/v1/assessments/LAB-001/report',{'X-P01-Node-ID':'OP-01'},401),
                 ('/api/v1/assessments/LAB-001/report?access_token=PRIVATE',None,401),
                 ('/api/v1/assessments/LAB-001/report',{'Authorization':'Bearer '+'x'*43},401),
                 ('/api/v1/assessments/LAB-002/report',headers,403),
                 ('/api/v1/assessments/lab-001/report',headers,403)]
        with patch.object(api.report.pg,'open_connection') as connect:
            for path, values, status in cases:
                self.assertEqual(self.request('GET',path,headers=values)[0],status)
        connect.assert_not_called()

    def test_bad_cursor_unknown_duplicate_query_never_connect(self):
        headers = self.login()
        with patch.object(api.report.pg,'open_connection') as connect:
            for suffix in ['limit=101','limit=1&limit=2','unknown=1','after_ordinal=0',
                           'after_analysis_id=ana-'+'0'*32, 'limit=true','limit=1&', 'expected_scope_sha256=bad']:
                with self.subTest(suffix=suffix):
                    self.assertEqual(self.request('GET','/api/v1/assessments/LAB-001/report?'+suffix,headers=headers)[0],400)
        connect.assert_not_called()

    def test_login_strict_json_body_and_no_password_error_disclosure(self):
        for payload, headers, status in [({'username':'reader','password':'PRIVATE'}, {'Content-Type':'application/json'},401),
            ({'username':'reader','password':fixture.PASSWORD},{'Content-Type':'text/plain'},400),
            ({'username':'reader','password':fixture.PASSWORD,'scope':'PRIVATE'},{'Content-Type':'application/json'},400),
            ({'username':'reader','password':'PRIVATE'*1000},{'Content-Type':'application/json'},400)]:
            code, doc = self.request('POST','/api/v1/operator/session',payload,headers)
            self.assertEqual(code,status); self.assertNotIn('PRIVATE',json.dumps(doc))
        self.assertEqual(self.request('POST','/api/v1/operator/session?password=PRIVATE',{}, {'Content-Type':'application/json'})[0],400)

    def test_framing_duplicates_and_transfer_encoding_rejected(self):
        cases = [b'Content-Length: 2\r\nContent-Length: 2\r\nContent-Type: application/json\r\n',
                 b'Transfer-Encoding: chunked\r\nContent-Type: application/json\r\n',
                 b'Content-Length: 2\r\nContent-Type: application/json\r\nExpect: 100-continue\r\n']
        for extra in cases:
            with closing(http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=10)) as conn:
                conn.connect(); conn.sock.sendall(b'POST /api/v1/operator/session HTTP/1.1\r\nHost: localhost\r\n'+extra+b'\r\n{}')
                response=http.client.HTTPResponse(conn.sock); response.begin()
                self.assertEqual(response.status,400); response.read()
        headers=self.login()
        token=headers['Authorization'].encode()
        with closing(http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=10)) as conn:
            conn.connect();conn.sock.sendall(b'GET /api/v1/assessments/LAB-001/report HTTP/1.1\r\nHost: localhost\r\nAuthorization: '+token+b'\r\nAuthorization: '+token+b'\r\n\r\n')
            response=http.client.HTTPResponse(conn.sock);response.begin();self.assertEqual(response.status,400);response.read()

    def test_backend_redaction_fence_conflict_and_not_found(self):
        headers=self.login()
        with patch.object(api.report.pg,'open_connection',side_effect=RuntimeError('password=PRIVATE')):
            status,doc=self.request('GET','/api/v1/assessments/LAB-001/report',headers=headers)
            self.assertEqual(status,503);self.assertNotIn('PRIVATE',json.dumps(doc))
        with patch.object(api.report.pg,'open_connection'),patch.object(api.report,'show_assessment',side_effect=api.report.pg.PersistenceError('report_scope_conflict')):
            self.assertEqual(self.request('GET','/api/v1/assessments/LAB-001/report',headers=headers)[0],409)
        with patch.object(api.report.pg,'open_connection'),patch.object(api.report,'show_assessment',return_value=dict(status='not_found')):
            self.assertEqual(self.request('GET','/api/v1/assessments/LAB-001/report',headers=headers)[0],404)

    def test_remote_plaintext_and_invalid_startup_never_listen(self):
        with patch.object(api,'OperatorServer') as server:
            for host in ['0.0.0.0','192.0.2.1','localhost','::1']:
                with self.assertRaises(ValueError):api.create_server(self.path,host,0)
            self.path.write_bytes(b'PRIVATE')
            with self.assertRaises(ValueError):api.create_server(self.path,port=0)
        server.assert_not_called()

    @unittest.skipUnless(shutil.which('openssl'),'openssl needed for real HTTPS')
    def test_real_https_certificate_and_no_plaintext_on_tls_listener(self):
        self.stop()
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-subj','/CN=Synthetic-Operator-LAB','-addext','subjectAltName=IP:127.0.0.1',
            '-keyout',str(self.base/'server.key'),'-out',str(self.base/'server.crt')],
            check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.server=api.create_server(self.path,port=0,tls_cert=self.base/'server.crt',tls_key=self.base/'server.key')
        self.worker=threading.Thread(target=self.server.serve_forever,daemon=True);self.worker.start()
        context=ssl.create_default_context(cafile=str(self.base/'server.crt'))
        status,doc=self.request('POST','/api/v1/operator/session',dict(username='reader',password=fixture.PASSWORD),
                               {'Content-Type':'application/json'},context)
        self.assertEqual(status,201)
        with self.assertRaises((OSError,http.client.HTTPException)):
            self.request('GET','/healthz')


if __name__=='__main__':unittest.main()
