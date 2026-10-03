"""Real reader-role HTTP export: canonical history, fences and 14-table invariants."""
from contextlib import closing
import http.client
import io
import json
import os
import threading
import unittest
from unittest.mock import patch
import zipfile

import test_postgres_operator_api as fixture
import P01_Operator_Web as web


@unittest.skipUnless(os.environ.get('CANCA_TEST_POSTGRES')=='1', 'real PostgreSQL CI opt-in required')
class PostgreSQLOperatorExportTests(unittest.TestCase):
    setUp = fixture.fixture.PostgreSQLRecoveryTests.setUp

    def test_reader_complete_export_matches_canonical_and_preserves_tables_and_store(self):
        pg=web.api.report.pg; assessment=fixture.lab.ASSESSMENT
        before=fixture.lab.snapshot('canca_ci')
        files={str(p):pg.digest(p.read_bytes()) for p in self.store.rglob('*') if p.is_file()}
        canonical=web.api.report.show_assessment(self.conn,assessment)
        scope=canonical['report_scope_sha256']
        self.conn.execute('DROP ROLE IF EXISTS canca_export_reader')
        self.conn.execute('CREATE ROLE canca_export_reader')
        self.conn.execute('GRANT USAGE ON SCHEMA canca TO canca_export_reader')
        self.conn.execute('GRANT SELECT ON ALL TABLES IN SCHEMA canca TO canca_export_reader')
        def remove_role():
            self.conn.execute('DROP OWNED BY canca_export_reader')
            self.conn.execute('DROP ROLE canca_export_reader')
        self.addCleanup(remove_role)
        original_connection=pg.open_connection
        def reader():
            conn=original_connection()
            try: conn.execute('SET ROLE canca_export_reader')
            except Exception: conn.close(); raise
            return conn
        policy=self.base/'web-export-accounts.json'
        from P01_Operator_Auth import create_policy
        password='Synthetic export CI passphrase 01!'
        create_policy(policy,'OP-EXPORT-CI','export-reader',[assessment],password)
        server=web.create_server(policy,port=0)
        worker=threading.Thread(target=server.serve_forever,daemon=True); worker.start()
        def request(method,path,payload=None,token=None):
            headers={'Content-Type':'application/json'} if payload else {}
            if token: headers['Authorization']='Bearer '+token
            with closing(http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=40)) as conn:
                conn.request(method,path,json.dumps(payload) if payload else None,headers)
                response=conn.getresponse()
                return response.status,dict(response.getheaders()),response.read()
        try:
            status,_,raw=request('POST','/api/v1/operator/session',dict(username='export-reader',password=password))
            self.assertEqual(status,201); token=json.loads(raw)['access_token']
            target='/api/v1/assessments/'+assessment+'/report/export?expected_scope_sha256='
            with patch.object(pg,'open_connection',side_effect=reader):
                status,headers,raw=request('GET',target+scope+'&limit=1',token=token)
                self.assertEqual(status,200)
                self.assertEqual(headers['X-Canca-Export-SHA256'],pg.digest(raw))
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    doc=json.loads(archive.read('report.json'))
                    manifest=json.loads(archive.read('manifest.json'))
                    for item in manifest['files']:
                        self.assertEqual(pg.digest(archive.read(item['name'])),item['sha256'])
                    self.assertEqual(len(archive.namelist()),4)
                self.assertEqual(doc['evaluations'],canonical['evaluations'])
                for key,value in canonical.items():
                    if key not in web.exports.export.PAGE_FIELDS: self.assertEqual(doc[key],value)
                self.assertEqual(doc['export_consistency']['data_pages'],4)
                self.assertTrue(doc['export_consistency']['terminal_empty_page_verified'])
                self.assertEqual(len(doc['evaluations']),4)
                self.assertEqual(sum(r['result']=='finding' for r in doc['evaluations']),2)
                self.assertEqual(request('GET',target+'0'*64,token=token)[0],409)
                self.assertEqual(request('GET','/api/v1/assessments/OTHER/report/export?expected_scope_sha256='+scope,token=token)[0],403)
                self.assertEqual(request('DELETE','/api/v1/operator/session',token=token)[0],200)
                self.assertEqual(request('GET',target+scope,token=token)[0],401)
        finally:
            server.shutdown(); server.server_close(); worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(before,fixture.lab.snapshot('canca_ci'))
        self.assertEqual(files,{str(p):pg.digest(p.read_bytes()) for p in self.store.rglob('*') if p.is_file()})


if __name__=='__main__': unittest.main()
