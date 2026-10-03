"""Real SELECT-only HTTP executive download with canonical/table/store agreement."""
from contextlib import closing
import http.client
import io
import json
import os
from pathlib import Path
import threading
import unittest
from unittest.mock import patch
import zipfile

import test_postgres_operator_api as fixture
from test_operator_web_executive import verify
import P01_Operator_Web as web


@unittest.skipUnless(os.environ.get('CANCA_TEST_POSTGRES')=='1', 'real PostgreSQL CI opt-in required')
class PostgreSQLOperatorExecutiveTests(unittest.TestCase):
    setUp=fixture.fixture.PostgreSQLRecoveryTests.setUp

    def test_reader_download_matches_qualified_synthesis_and_preserves_fourteen_tables_and_store(self):
        pg=web.api.report.pg; assessment=fixture.lab.ASSESSMENT
        before=fixture.lab.snapshot('canca_ci')
        files={str(p):pg.digest(p.read_bytes()) for p in self.store.rglob('*') if p.is_file()}
        canonical=web.exports.export.collect(self.conn,assessment,1)
        expected=web.exports.executive.summarize(canonical); scope=expected['report_scope_sha256']
        role='canca_executive_web_reader'
        self.conn.execute('DROP ROLE IF EXISTS '+role); self.conn.execute('CREATE ROLE '+role)
        self.conn.execute('GRANT USAGE ON SCHEMA canca TO '+role)
        self.conn.execute('GRANT SELECT ON canca.schema_migrations,canca.assessments,canca.imports,canca.artifacts,canca.assets,'
                          'canca.asset_imports,canca.asset_observations,canca.finding_analyses,canca.finding_evaluations,canca.findings TO '+role)
        def remove_role():
            self.conn.execute('DROP OWNED BY '+role); self.conn.execute('DROP ROLE '+role)
        self.addCleanup(remove_role)
        open_connection=pg.open_connection
        def reader():
            conn=open_connection()
            try: conn.execute('SET ROLE '+role)
            except Exception: conn.close(); raise
            return conn
        from P01_Operator_Auth import create_policy
        policy=self.base/'executive-web-accounts.json'; password='Synthetic executive CI passphrase 01!'
        create_policy(policy,'OP-EXECUTIVE-CI','executive-reader',[assessment],password)
        server=web.create_server(policy,port=0)
        worker=threading.Thread(target=server.serve_forever,daemon=True); worker.start()
        def request(method,path,payload=None,token=None):
            headers={'Content-Type':'application/json'} if payload else {}
            if token: headers['Authorization']='Bearer '+token
            with closing(http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=40)) as conn:
                conn.request(method,path,json.dumps(payload) if payload else None,headers)
                response=conn.getresponse(); return response.status,dict(response.getheaders()),response.read()
        try:
            status,_,raw=request('POST','/api/v1/operator/session',dict(username='executive-reader',password=password))
            self.assertEqual(status,201); token=json.loads(raw)['access_token']
            target='/api/v1/assessments/'+assessment+'/report/executive/export?expected_scope_sha256='
            with patch.object(pg,'open_connection',side_effect=reader):
                status,headers,raw=request('GET',target+scope+'&limit=1',token=token)
                self.assertEqual(status,200); self.assertEqual(headers['X-Canca-Export-SHA256'],pg.digest(raw))
                self.assertEqual(headers['Content-Disposition'],'attachment; filename="canca-'+assessment+'-executive.zip"')
                self.assertEqual(headers['X-Canca-Report-Scope-SHA256'],scope)
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    actual=json.loads(archive.read('executive.json'))
                    self.assertEqual(set(archive.namelist()),verify.NAMES)
                self.assertEqual(actual['consistency']['data_pages'],4)
                self.assertTrue(actual['consistency']['terminal_empty_page_verified'])
                actual.pop('consistency'); expected.pop('consistency'); self.assertEqual(actual,expected)
                self.assertEqual(actual['recorded_finding_occurrences'],2); self.assertEqual(actual['recommendation_group_count'],2)
                self.assertEqual(actual['coverage']['outcomes']['no_finding'],2)
                self.assertTrue(all(r['finding_status']=='Open' for g in actual['recommendation_groups'] for r in g['occurrences']))
                path=self.base/'downloaded-executive.zip'; path.write_bytes(raw)
                self.assertEqual(verify.verify(path,assessment,4,2,2)['files_verified'],4)
                self.assertEqual(request('GET',target+'0'*64,token=token)[0],409)
                self.assertEqual(request('GET','/api/v1/assessments/OTHER/report/executive/export?expected_scope_sha256='+scope,token=token)[0],403)
                self.assertEqual(request('DELETE','/api/v1/operator/session',token=token)[0],200)
                self.assertEqual(request('GET',target+scope,token=token)[0],401)
            with reader() as conn:
                for sql in ("UPDATE canca.findings SET status='Open'",'DELETE FROM canca.findings',
                            "INSERT INTO canca.assessments(assessment_id) VALUES('DENIED')",'CREATE TABLE canca.denied(id int)'):
                    with self.assertRaises(Exception): conn.execute(sql)
        finally:
            server.shutdown(); server.server_close(); worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(before,fixture.lab.snapshot('canca_ci'))
        self.assertEqual(files,{str(p):pg.digest(p.read_bytes()) for p in self.store.rglob('*') if p.is_file()})


if __name__=='__main__': unittest.main()
