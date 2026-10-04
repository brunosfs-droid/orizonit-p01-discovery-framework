"""Opt-in private audit alongside real SELECT-only PostgreSQL and unchanged store."""
from contextlib import closing
import hashlib
import http.client
import json
import os
import threading
import time
import unittest
from unittest.mock import patch

import test_postgres_operator_api as fixture
import P01_Operator_Web as web


@unittest.skipUnless(os.environ.get('CANCA_TEST_POSTGRES')=='1','real PostgreSQL CI opt-in required')
class PostgreSQLOperatorAuditTests(unittest.TestCase):
    setUp=fixture.fixture.PostgreSQLRecoveryTests.setUp

    def test_private_audit_records_real_reads_and_denies_unlogged_work_without_mutation(self):
        pg=web.api.report.pg; assessment=fixture.lab.ASSESSMENT
        before=fixture.lab.snapshot('canca_ci')
        files={str(p):pg.digest(p.read_bytes()) for p in self.store.rglob('*') if p.is_file()}
        canonical=web.exports.export.collect(self.conn,assessment,100); scope=canonical['report_scope_sha256']
        role='canca_audit_ci_reader'; self.conn.execute('DROP ROLE IF EXISTS '+role)
        self.conn.execute('CREATE ROLE '+role); self.conn.execute('GRANT USAGE ON SCHEMA canca TO '+role)
        self.conn.execute('GRANT SELECT ON ALL TABLES IN SCHEMA canca TO '+role)
        def remove():
            self.conn.execute('DROP OWNED BY '+role); self.conn.execute('DROP ROLE '+role)
        self.addCleanup(remove)
        original=pg.open_connection
        def reader():
            conn=original()
            try: conn.execute('SET ROLE '+role)
            except Exception: conn.close(); raise
            return conn
        from P01_Operator_Auth import create_policy
        policy=self.base/'audit-accounts.json'; password='Synthetic audit CI passphrase 01!'
        create_policy(policy,'OP-AUDIT-CI','audit-reader',[assessment],password)
        audit_path=self.base/'operator-audit.jsonl'; server=web.create_server(policy,port=0,audit_path=audit_path)
        worker=threading.Thread(target=server.serve_forever,daemon=True); worker.start()
        close_failed=False
        def request(method,path,payload=None,token=None):
            headers={'Content-Type':'application/json'} if payload else {}
            if token: headers['Authorization']='Bearer '+token
            with closing(http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=40)) as conn:
                conn.request(method,path,json.dumps(payload) if payload else None,headers)
                response=conn.getresponse(); return response.status,response.read()
        try:
            status,raw=request('POST','/api/v1/operator/session',dict(username='audit-reader',password=password))
            self.assertEqual(status,201); token=json.loads(raw)['access_token']
            with patch.object(pg,'open_connection',side_effect=reader) as calls:
                target='/api/v1/assessments/'+assessment+'/report'
                self.assertEqual(request('GET',target,token=token)[0],200)
                for suffix in ('/executive','/export','/executive/export'):
                    self.assertEqual(request('GET',target+suffix+'?expected_scope_sha256='+scope,token=token)[0],200)
                count=calls.call_count
                self.assertEqual(request('GET','/api/v1/assessments/OTHER/report',token=token)[0],403)
                self.assertEqual(calls.call_count,count)
                deadline=time.monotonic()+3
                while time.monotonic()<deadline:
                    with server.audit._lock: pending=bool(server.audit._pending)
                    if not pending: break
                    time.sleep(0.01)
                self.assertFalse(pending)
                with patch.object(web.api.audit.os,'fsync',side_effect=OSError('NEVER-SECRET-BACKEND')):
                    status,raw=request('GET',target,token=token)
                self.assertEqual(status,503); self.assertEqual(json.loads(raw)['error_code'],'operator_audit_unavailable')
                self.assertEqual(calls.call_count,count)
                self.assertEqual(request('DELETE','/api/v1/operator/session',token=token)[0],503)
                self.assertEqual(server.service.auth.require(token,assessment),'OP-AUDIT-CI')
            with reader() as conn:
                with self.assertRaises(Exception): conn.execute("UPDATE canca.findings SET status='Open'")
        finally:
            server.shutdown()
            try: server.server_close()
            except web.api.audit.AuditError: close_failed=True
            worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertTrue(close_failed)
        raw=audit_path.read_bytes(); rows=[json.loads(line) for line in raw.splitlines()]
        self.assertNotIn(password.encode(),raw); self.assertNotIn(token.encode(),raw)
        self.assertNotIn(hashlib.sha256(token.encode()).hexdigest().encode(),raw)
        self.assertNotIn(b'OTHER',raw); self.assertNotIn(b'NEVER-SECRET-BACKEND',raw)
        finished=[r for r in rows if r['event']=='request_finished']
        self.assertTrue(any(r['assessment_id']==assessment and r['http_status']==200 for r in finished))
        self.assertTrue(any(r['assessment_id'] is None and r['operator_id']=='OP-AUDIT-CI' and r['http_status']==403 for r in finished))
        self.assertEqual(before,fixture.lab.snapshot('canca_ci'))
        self.assertEqual(files,{str(p):pg.digest(p.read_bytes()) for p in self.store.rglob('*') if p.is_file()})


if __name__=='__main__': unittest.main()
