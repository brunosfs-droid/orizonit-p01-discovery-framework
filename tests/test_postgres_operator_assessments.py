"""Policy directory independent of SQL; exact report grants on real PostgreSQL."""
from contextlib import closing
from copy import deepcopy
import http.client
import json
import os
import threading
import unittest
from unittest.mock import patch

import test_postgres_operator_api as fixture
import P01_Operator_Auth as auth
import P01_Operator_Web as web


@unittest.skipUnless(os.environ.get('CANCA_TEST_POSTGRES') == '1', 'real PostgreSQL CI opt-in required')
class PostgreSQLOperatorAssessmentTests(unittest.TestCase):
    setUp = fixture.fixture.PostgreSQLRecoveryTests.setUp

    def test_directory_is_sql_free_and_reader_reports_preserve_fourteen_tables_and_store(self):
        pg = web.api.report.pg; assessment = fixture.lab.ASSESSMENT
        before = fixture.lab.snapshot('canca_ci')
        files = {str(p): pg.digest(p.read_bytes()) for p in self.store.rglob('*') if p.is_file()}
        role = 'canca_assessment_directory_reader'
        self.conn.execute('DROP ROLE IF EXISTS ' + role); self.conn.execute('CREATE ROLE ' + role)
        self.conn.execute('GRANT USAGE ON SCHEMA canca TO ' + role)
        self.conn.execute('GRANT SELECT ON ALL TABLES IN SCHEMA canca TO ' + role)
        def remove_role():
            self.conn.execute('DROP OWNED BY ' + role); self.conn.execute('DROP ROLE ' + role)
        self.addCleanup(remove_role)
        open_connection = pg.open_connection
        def reader():
            conn = open_connection()
            try: conn.execute('SET ROLE ' + role)
            except Exception: conn.close(); raise
            return conn
        policy = self.base / 'assessment-directory-accounts.json'
        password = 'Synthetic directory CI passphrase 01!'
        auth.create_policy(policy, 'OP-DIRECTORY', 'directory-reader', [assessment, 'MISSING'], password)
        doc = json.loads(policy.read_bytes()); other = deepcopy(doc['accounts'][0])
        other.update(operator_id='OP-OTHER', username='other-reader',
                     grants=[dict(assessment_id='OTHER', permissions=['assessment:read'])])
        doc['accounts'].append(other); policy.write_text(json.dumps(doc))
        server = web.create_server(policy, port=0)
        worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
        def request(method, path, payload=None, token=None):
            headers = {'Content-Type': 'application/json'} if payload else {}
            if token: headers['Authorization'] = 'Bearer ' + token
            with closing(http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=40)) as conn:
                conn.request(method, path, json.dumps(payload) if payload else None, headers)
                response = conn.getresponse(); return response.status, json.loads(response.read())
        try:
            status, session = request('POST', '/api/v1/operator/session', dict(username='directory-reader', password=password))
            self.assertEqual(status, 201); token = session['access_token']
            status, other = request('POST', '/api/v1/operator/session', dict(username='other-reader', password=password))
            self.assertEqual(status, 201)
            with patch.object(pg, 'open_connection', side_effect=AssertionError('Directory must not query SQL')) as connect:
                status, directory = request('GET', '/api/v1/operator/assessments', token=token)
                self.assertEqual(status, 200); self.assertFalse(directory['assessment_existence_checked'])
                self.assertEqual(directory['assessment_ids'], sorted([assessment, 'MISSING']))
                self.assertEqual(request('GET', '/api/v1/operator/assessments', token=other['access_token'])[1]['assessment_ids'], ['OTHER'])
                self.assertEqual(request('GET', '/api/v1/assessments/OTHER/report', token=token)[0], 403)
                self.assertEqual(request('GET', '/api/v1/assessments/' + assessment + '/report', token=other['access_token'])[0], 403)
            connect.assert_not_called()
            with patch.object(pg, 'open_connection', side_effect=reader) as connect:
                status, report = request('GET', '/api/v1/assessments/' + assessment + '/report?limit=1', token=token)
                self.assertEqual(status, 200); self.assertEqual(report['assessment_id'], assessment)
                self.assertEqual(report['coverage']['evaluation_count'], 4)
                self.assertEqual(report['recorded_finding_occurrences'], 2)
                self.assertFalse(report['source_bytes_revalidated'])
                self.assertEqual(request('GET', '/api/v1/assessments/MISSING/report', token=token)[0], 404)
                self.assertEqual(connect.call_count, 2)
            self.assertEqual(request('DELETE', '/api/v1/operator/session', token=token)[0], 200)
            with patch.object(pg, 'open_connection') as connect:
                self.assertEqual(request('GET', '/api/v1/operator/assessments', token=token)[0], 401)
            connect.assert_not_called()
            with reader() as conn:
                with self.assertRaises(Exception): conn.execute("UPDATE canca.findings SET status='Open'")
        finally:
            server.shutdown(); server.server_close(); worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(before, fixture.lab.snapshot('canca_ci'))
        self.assertEqual(files, {str(p): pg.digest(p.read_bytes()) for p in self.store.rglob('*') if p.is_file()})


if __name__ == '__main__': unittest.main()
