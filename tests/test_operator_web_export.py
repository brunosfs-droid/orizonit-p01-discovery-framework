"""Actual HTTP archive delivery, early denials and export resource boundaries."""
import io
import json
import unittest
from unittest.mock import patch
import zipfile

import test_operator_auth as auth_fixture
import test_operator_web as http_fixture
from test_postgres_export import sample
import P01_Operator_Web as web

export = web.exports.export


class OperatorWebExportTests(unittest.TestCase):
    setUp = http_fixture.OperatorWebTests.setUp
    stop = http_fixture.OperatorWebTests.stop
    request = http_fixture.OperatorWebTests.request

    def login(self):
        code, _, raw = self.request('POST', '/api/v1/operator/session',
            dict(username='reader', password=auth_fixture.PASSWORD), {'Content-Type':'application/json'})
        self.assertEqual(code, 201)
        return json.loads(raw)['access_token']

    def target(self, assessment='LAB-001', query=None):
        return '/api/v1/assessments/' + assessment + '/report/export?' + (
            query if query is not None else 'expected_scope_sha256='+'3'*64+'&limit=1')

    def test_complete_archive_members_hashes_headers_and_initial_terminal_fence(self):
        token = self.login()
        with patch.object(export.pg, 'open_connection'), \
                patch.object(export.report, 'show_assessment', side_effect=list(sample())) as query:
            code, headers, raw = self.request('GET', self.target(), headers={'Authorization':'Bearer '+token})
        self.assertEqual(code, 200)
        self.assertEqual(headers['Content-Type'], 'application/zip')
        self.assertEqual(headers['Content-Disposition'], 'attachment; filename="canca-LAB-001-report.zip"')
        self.assertEqual(headers['X-Canca-Export-SHA256'], export.pg.digest(raw))
        self.assertEqual(headers['X-Canca-Report-Scope-SHA256'], '3'*64)
        self.assertEqual(int(headers['Content-Length']), len(raw))
        self.assertEqual(headers['Cross-Origin-Resource-Policy'], 'same-origin')
        self.assertNotIn(token.encode(),raw); self.assertNotIn(auth_fixture.PASSWORD.encode(),raw)
        self.assertTrue(all(call.kwargs['expected_scope_sha256']=='3'*64 for call in query.call_args_list))
        self.assertEqual(query.call_count, 2)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            self.assertEqual(set(archive.namelist()), {'report.json','report.md','manifest.json','manifest.json.sha256'})
            doc = json.loads(archive.read('report.json')); manifest = json.loads(archive.read('manifest.json'))
            self.assertEqual(len(doc['evaluations']), 1)
            self.assertTrue(doc['export_consistency']['terminal_empty_page_verified'])
            self.assertEqual(manifest['delivery_version'], web.VERSION)
            for item in manifest['files']:
                data = archive.read(item['name'])
                self.assertEqual(len(data), item['size_bytes']); self.assertEqual(export.pg.digest(data), item['sha256'])
            self.assertEqual(archive.read('manifest.json.sha256').decode(),
                             export.pg.digest(archive.read('manifest.json'))+'  manifest.json\n')

    def test_auth_origin_and_malformed_queries_deny_before_database(self):
        token = self.login(); headers = {'Authorization':'Bearer '+token}
        with patch.object(export.pg, 'open_connection') as connect:
            self.assertEqual(self.request('GET', self.target())[0], 401)
            self.assertEqual(self.request('GET', self.target('OTHER'), headers=headers)[0], 403)
            self.assertEqual(self.request('GET', self.target(), headers={**headers,'Origin':'http://other.invalid'})[0], 403)
            for query in ['', 'expected_scope_sha256=', 'expected_scope_sha256=bad',
                          'expected_scope_sha256='+'3'*64+'&limit=101',
                          'expected_scope_sha256='+'3'*64+'&limit=1&limit=2',
                          'expected_scope_sha256='+'3'*64+'&password=PRIVATE']:
                self.assertEqual(self.request('GET', self.target(query=query), headers=headers)[0], 400)
            self.assertEqual(self.request('GET', self.target(), headers={**headers,'Content-Length':'1'})[0], 400)
        connect.assert_not_called()

    def test_scope_change_missing_assessment_and_backend_error_never_emit_archive(self):
        token = self.login()
        for failure, expected in [(export.pg.PersistenceError('report_scope_conflict'),409),
                                  (RuntimeError('password=NEVER-LOG'),503)]:
            with patch.object(export.pg, 'open_connection'), \
                    patch.object(export.report, 'show_assessment', side_effect=failure):
                code, headers, raw = self.request('GET', self.target(), headers={'Authorization':'Bearer '+token})
            self.assertEqual(code, expected); self.assertNotIn('Content-Disposition',headers)
            self.assertNotIn(b'NEVER-LOG',raw)
        with patch.object(export.pg, 'open_connection'), \
                patch.object(export.report, 'show_assessment', return_value={'status':'not_found'}):
            self.assertEqual(self.request('GET', self.target(), headers={'Authorization':'Bearer '+token})[0],404)

    def test_busy_byte_limit_and_deadline_release_slot(self):
        token = self.login(); headers = {'Authorization':'Bearer '+token}
        with patch.object(export.pg, 'open_connection'), \
                patch.object(export.report, 'show_assessment', side_effect=list(sample())):
            with self.server.report_exports.build(token, 'LAB-001', '3'*64, 1):
                with patch.object(export.pg, 'open_connection') as blocked:
                    code, _, raw = self.request('GET', self.target(), headers=headers)
                self.assertEqual(code,429); self.assertEqual(json.loads(raw)['error_code'],'export_busy')
                blocked.assert_not_called()
        with patch.object(web.exports, 'MAX_SECONDS', -1), patch.object(export.pg, 'open_connection') as connect:
            self.assertEqual(self.request('GET', self.target(), headers=headers)[0],503)
        connect.assert_not_called()
        with patch.object(web.exports, 'MAX_ARCHIVE_BYTES', 128), patch.object(export.pg, 'open_connection'), \
                patch.object(export.report, 'show_assessment', side_effect=list(sample())):
            self.assertEqual(self.request('GET', self.target(), headers=headers)[0],413)
        with patch.object(export.pg, 'open_connection'), \
                patch.object(export.report, 'show_assessment', side_effect=list(sample())):
            self.assertEqual(self.request('GET', self.target(), headers=headers)[0],200)

    def test_revoked_session_during_query_stops_before_archive_and_releases_slot(self):
        token = self.login()
        def revoke(*args, **kwargs):
            self.server.service.auth.logout(token)
            return sample()[0]
        with patch.object(export.pg, 'open_connection'), patch.object(export.report, 'show_assessment',side_effect=revoke):
            code, headers, _ = self.request('GET',self.target(),headers={'Authorization':'Bearer '+token})
        self.assertEqual(code,401); self.assertNotIn('Content-Disposition',headers)
        token=self.login()
        with patch.object(export.pg, 'open_connection'), \
                patch.object(export.report, 'show_assessment', side_effect=list(sample())):
            self.assertEqual(self.request('GET',self.target(),headers={'Authorization':'Bearer '+token})[0],200)


if __name__ == '__main__': unittest.main()
