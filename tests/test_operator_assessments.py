"""Own immutable policy grants; real HTTP boundary without database enumeration."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import test_operator_auth as fixture
import test_operator_web as boundary
import P01_Operator_Auth as auth
import P01_Operator_Web as web

ROUTE = '/api/v1/operator/assessments'
IDS = ['LAB-001', 'NOT-IN-DATABASE', 'lab-001']


def document():
    doc = fixture.document()
    doc['accounts'][0]['grants'] = [dict(assessment_id=a, permissions=['assessment:read']) for a in reversed(IDS)]
    for operator, username, ids in [('OP-PRIVATE', 'other', ['PRIVATE-OTHER']), ('OP-EMPTY', 'empty', [])]:
        row = deepcopy(doc['accounts'][0])
        row.update(operator_id=operator, username=username,
                   grants=[dict(assessment_id=a, permissions=['assessment:read']) for a in ids])
        doc['accounts'].append(row)
    return doc


class OperatorGrantAccessorTests(unittest.TestCase):
    def test_snapshot_is_immutable_case_sensitive_and_only_own_grants(self):
        service = auth.LocalAuth(fixture.policy(document()))
        token = service.login('reader', fixture.PASSWORD)['access_token']
        result = service.assessment_grants(token)
        self.assertEqual(result, tuple(IDS)); self.assertIsInstance(result, tuple)
        with self.assertRaises(TypeError): result[0] = 'OTHER'
        other = service.login('other', fixture.PASSWORD)['access_token']
        self.assertEqual(service.assessment_grants(other), ('PRIVATE-OTHER',))
        empty = service.login('empty', fixture.PASSWORD)['access_token']
        self.assertEqual(service.assessment_grants(empty), ())
        service.require(token, 'LAB-001'); service.require(token, 'lab-001')
        with self.assertRaises(auth.AccessError): service.require(token, 'Lab-001')

    def test_expiry_logout_and_restart_invalidate_accessor_without_renewal(self):
        now = [100.0]; service = auth.LocalAuth(fixture.policy(), clock=lambda: now[0])
        token = service.login('reader', fixture.PASSWORD)['access_token']
        now[0] += auth.SESSION_SECONDS - 1
        self.assertEqual(service.assessment_grants(token), ('LAB-001',))
        with self.assertRaises(auth.AccessError): auth.LocalAuth(fixture.policy()).assessment_grants(token)
        now[0] += 1
        with self.assertRaises(auth.AccessError): service.assessment_grants(token)
        token = service.login('reader', fixture.PASSWORD)['access_token']; service.logout(token)
        for invalid in [token, None, 'PRIVATE', 't' * 43]:
            with self.assertRaises(auth.AccessError): service.assessment_grants(invalid)


class OperatorAssessmentHTTPTests(unittest.TestCase):
    stop = boundary.OperatorWebTests.stop
    request = boundary.OperatorWebTests.request

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'accounts.json'
        self.path.write_text(json.dumps(document())); self.path.chmod(0o600)
        self.server = web.create_server(self.path, port=0)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True); self.worker.start()
        self.addCleanup(self.stop)

    def login(self, username='reader'):
        status, _, raw = self.request('POST', '/api/v1/operator/session',
            dict(username=username, password=fixture.PASSWORD), {'Content-Type': 'application/json'})
        self.assertEqual(status, 201)
        return {'Authorization': 'Bearer ' + json.loads(raw)['access_token']}

    def test_only_own_sorted_policy_ids_even_when_database_is_unavailable(self):
        headers = self.login()
        with patch.object(web.api.report.pg, 'open_connection', side_effect=AssertionError('SQL must not run')) as connect:
            status, response_headers, raw = self.request('GET', ROUTE, headers=headers)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(raw), dict(status='allowed', version=web.DIRECTORY_VERSION,
                source='local_operator_policy', assessment_existence_checked=False, assessment_ids=IDS))
            self.assertEqual(int(response_headers['Content-Length']), len(raw))
            self.assertLess(len(raw), web.MAX_DIRECTORY_BYTES)
            for secret in [b'PRIVATE-OTHER', b'OP-PRIVATE', fixture.RECORD['hash'].encode(), headers['Authorization'].encode()]:
                self.assertNotIn(secret, raw)
            other = self.login('other'); empty = self.login('empty')
            self.assertEqual(json.loads(self.request('GET', ROUTE, headers=other)[2])['assessment_ids'], ['PRIVATE-OTHER'])
            self.assertEqual(json.loads(self.request('GET', ROUTE, headers=empty)[2])['assessment_ids'], [])
        connect.assert_not_called()

    def test_authentication_is_required_before_query_and_revoked_session_cannot_list(self):
        headers = self.login(); token = headers['Authorization'][7:]
        with patch.object(web.api.report.pg, 'open_connection') as connect:
            self.assertEqual(self.request('GET', ROUTE)[0], 401)
            self.assertEqual(self.request('GET', ROUTE + '?token=PRIVATE')[0], 401)
            self.assertEqual(self.request('GET', ROUTE, headers={'Authorization': 'Bearer PRIVATE'})[0], 401)
            self.server.service.auth.logout(token)
            status, _, raw = self.request('GET', ROUTE, headers=headers)
            self.assertEqual(status, 401); self.assertNotIn(b'LAB-001', raw)
        connect.assert_not_called()

    def test_query_body_method_and_cross_origin_do_not_disclose_grants(self):
        headers = self.login()
        cases = [('GET', ROUTE + '?limit=1', None, {}, 400),
                 ('GET', ROUTE + '?username=PRIVATE', None, {}, 400),
                 ('GET', ROUTE, {'username': 'PRIVATE'}, {}, 400),
                 ('POST', ROUTE, None, {}, 404), ('DELETE', ROUTE, None, {}, 404),
                 ('GET', ROUTE, None, {'Origin': 'http://attacker.invalid'}, 403),
                 ('GET', ROUTE, None, {'Sec-Fetch-Site': 'same-site'}, 403),
                 ('GET', ROUTE, None, {'Host': 'attacker.invalid:' + str(self.server.server_port)}, 400)]
        with patch.object(web.api.report.pg, 'open_connection') as connect:
            for method, path, payload, extra, expected in cases:
                with self.subTest(method=method, path=path, extra=extra):
                    status, _, raw = self.request(method, path, payload, {**headers, **extra})
                    self.assertEqual(status, expected)
                    self.assertNotIn(b'LAB-001', raw); self.assertNotIn(b'PRIVATE', raw)
            with patch.object(self.server, 'RequestHandlerClass', web.api.OperatorHandler):
                self.assertEqual(self.request('GET', ROUTE, headers=headers)[0], 404)
        connect.assert_not_called()

    def test_listing_neither_bypasses_report_grants_nor_claims_existence(self):
        headers = self.login()
        with patch.object(web.api.report.pg, 'open_connection') as connect:
            self.assertEqual(self.request('GET', ROUTE, headers=headers)[0], 200)
            for assessment in ['PRIVATE-OTHER', 'Lab-001']:
                self.assertEqual(self.request('GET', '/api/v1/assessments/' + assessment + '/report', headers=headers)[0], 403)
        connect.assert_not_called()
        with patch.object(web.api.report.pg, 'open_connection') as connect, \
                patch.object(web.api.report, 'show_assessment', return_value=dict(status='not_found')):
            self.assertEqual(self.request('GET', '/api/v1/assessments/NOT-IN-DATABASE/report', headers=headers)[0], 404)
        connect.assert_called_once()

    def test_maximal_grants_stay_bounded_and_directory_budget_fails_closed(self):
        doc = fixture.document()
        ids = [str(n).zfill(3) + '-' + 'x' * 124 for n in range(auth.MAX_GRANTS)]
        self.assertTrue(all(len(a) == 128 for a in ids))
        doc['accounts'][0]['grants'] = [dict(assessment_id=a, permissions=['assessment:read']) for a in ids]
        service = auth.LocalAuth(fixture.policy(doc))
        headers = {'Authorization': 'Bearer ' + service.login('reader', fixture.PASSWORD)['access_token']}
        with patch.object(self.server.service, 'auth', service), patch.object(web.api.report.pg, 'open_connection') as connect:
            status, _, raw = self.request('GET', ROUTE, headers=headers)
            self.assertEqual(status, 200); self.assertEqual(json.loads(raw)['assessment_ids'], ids)
            self.assertLess(len(raw), web.MAX_DIRECTORY_BYTES)
            with patch.object(web, 'MAX_DIRECTORY_BYTES', 1):
                status, _, raw = self.request('GET', ROUTE, headers=headers)
                self.assertEqual(status, 503); self.assertNotIn(ids[0].encode(), raw)
        connect.assert_not_called()

    def test_revocation_between_snapshot_and_send_and_fixed_unexpected_error(self):
        headers = self.login(); token = headers['Authorization'][7:]
        accessor = self.server.service.auth.assessment_grants
        def revoke(value):
            ids = accessor(value); self.server.service.auth.logout(value); return ids
        with patch.object(self.server.service.auth, 'assessment_grants', side_effect=revoke):
            status, _, raw = self.request('GET', ROUTE, headers=headers)
            self.assertEqual(status, 401); self.assertNotIn(b'LAB-001', raw)
        headers = self.login()
        with patch.object(self.server.service.auth, 'assessment_grants', side_effect=ValueError('PRIVATE/path/password')):
            status, _, raw = self.request('GET', ROUTE, headers=headers)
            self.assertEqual(status, 503)
            self.assertEqual(json.loads(raw), dict(status='failed', error_code='operator_request_failed'))


if __name__ == '__main__': unittest.main()
