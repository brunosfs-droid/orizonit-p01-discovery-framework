"""Real Web HTTP boundary: fixed assets, same-origin login and scoped API."""
from contextlib import closing
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import test_operator_auth as fixture
import P01_Operator_Web as web


class OperatorWebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'accounts.json'
        self.path.write_text(json.dumps(fixture.document())); self.path.chmod(0o600)
        self.server = web.create_server(self.path, port=0)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True); self.worker.start()
        self.addCleanup(self.stop)

    def stop(self):
        self.server.shutdown(); self.server.server_close(); self.worker.join(timeout=5)

    def request(self, method, path, payload=None, headers=None):
        with closing(http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=10)) as conn:
            conn.request(method, path, json.dumps(payload) if payload is not None else None, headers or {})
            response = conn.getresponse(); raw = response.read()
            self.assertEqual(response.getheader('Cache-Control'), 'no-store')
            self.assertEqual(response.getheader('X-Content-Type-Options'), 'nosniff')
            self.assertIsNone(response.getheader('Set-Cookie'))
            return response.status, dict(response.getheaders()), raw

    def test_fixed_assets_csp_and_health_without_database(self):
        with patch.object(web.api.report.pg, 'open_connection') as connect:
            for path, content_type in [('/', 'text/html'), ('/assets/operator.js', 'text/javascript'), ('/assets/operator.css', 'text/css')]:
                status, headers, raw = self.request('GET', path)
                self.assertEqual(status, 200); self.assertTrue(headers['Content-Type'].startswith(content_type))
                self.assertEqual(headers['Content-Security-Policy'], web.CSP)
                self.assertNotIn('unsafe-inline', web.CSP); self.assertNotIn('unsafe-eval', web.CSP)
                self.assertEqual(headers['Referrer-Policy'], 'no-referrer'); self.assertTrue(raw)
            status, _, raw = self.request('GET', '/healthz')
            self.assertEqual(status, 200); self.assertEqual(json.loads(raw)['web_version'], web.VERSION)
        connect.assert_not_called()

    def test_private_paths_traversal_and_asset_queries_never_read_files_or_database(self):
        with patch.object(web.api.report.pg, 'open_connection') as connect:
            for path, expected in [('/accounts.json', 404), ('/server/P01_Operator_Auth.py', 404),
                    ('/assets/../accounts.json', 404), ('/%2e%2e/accounts.json', 404),
                    ('/assets/operator.js?token=PRIVATE', 400), ('/?password=PRIVATE', 400)]:
                status, _, raw = self.request('GET', path)
                self.assertEqual(status, expected); self.assertNotIn(b'PRIVATE', raw)
        connect.assert_not_called()

    def test_cross_origin_rebinding_and_duplicate_host_denied_before_login(self):
        payload = dict(username='reader', password=fixture.PASSWORD)
        with patch.object(self.server.service.auth, 'login') as login:
            for headers, expected in [({'Origin':'http://attacker.invalid'}, 403),
                    ({'Origin':'null'}, 403), ({'Sec-Fetch-Site':'cross-site'}, 403),
                    ({'Sec-Fetch-Site':'same-site'}, 403), ({'Host':'attacker.invalid:'+str(self.server.server_port)}, 400),
                    ({'Host':'127.0.0.1:1'}, 400)]:
                status, _, _ = self.request('POST', '/api/v1/operator/session', payload, {'Content-Type':'application/json', **headers})
                self.assertEqual(status, expected)
            with closing(http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=10)) as conn:
                conn.connect(); conn.sock.sendall(b'GET / HTTP/1.1\r\nHost: localhost\r\nHost: localhost\r\n\r\n')
                response = http.client.HTTPResponse(conn.sock); response.begin(); self.assertEqual(response.status, 400); response.read()
        login.assert_not_called()

    def test_same_origin_login_report_and_logout_keep_api_grants(self):
        origin = 'http://127.0.0.1:' + str(self.server.server_port)
        status, _, raw = self.request('POST', '/api/v1/operator/session', dict(username='reader', password=fixture.PASSWORD),
            {'Content-Type':'application/json', 'Origin':origin, 'Sec-Fetch-Site':'same-origin'})
        self.assertEqual(status, 201); headers = {'Authorization':'Bearer ' + json.loads(raw)['access_token'], 'Origin':origin}
        with patch.object(web.api.report.pg, 'open_connection') as connect:
            self.assertEqual(self.request('GET', '/api/v1/assessments/LAB-002/report', headers=headers)[0], 403)
        connect.assert_not_called()
        with patch.object(web.api.report.pg, 'open_connection'), patch.object(web.api.report, 'show_assessment',
                return_value=dict(status='found', source_bytes_revalidated=False)):
            self.assertEqual(self.request('GET', '/api/v1/assessments/LAB-001/report', headers=headers)[0], 200)
        self.assertEqual(self.request('DELETE', '/api/v1/operator/session', headers=headers)[0], 200)
        with patch.object(web.api.report.pg, 'open_connection') as connect:
            self.assertEqual(self.request('GET', '/api/v1/assessments/LAB-001/report', headers=headers)[0], 401)
        connect.assert_not_called()

    def test_localhost_tunnel_authority_and_no_plaintext_remote(self):
        self.assertEqual(self.request('GET', '/', headers={'Host':'localhost:'+str(self.server.server_port)})[0], 200)
        with patch.object(web.api, 'OperatorServer') as server:
            with self.assertRaises(ValueError): web.create_server(self.path, '0.0.0.0', 8878)
        server.assert_not_called()

    def test_missing_or_symlinked_assets_fail_before_listener(self):
        with patch.object(web, 'ASSETS', {'/':('../P01_Operator_Auth.py', 'text/plain')}):
            # Inventory is fixed in code; create_server must also confine a changed map.
            with patch.object(web.api, 'create_server') as server:
                with self.assertRaises(ValueError): web.create_server(self.path, port=0)
            server.assert_not_called()
        directory = self.path.parent / 'web'; directory.mkdir()
        try:
            (directory / 'index.html').symlink_to(self.path)
        except (OSError, NotImplementedError):
            return  # Windows symlink privilege is independent of route confinement.
        with patch.object(web, '__file__', str(self.path.parent / 'P01_Operator_Web.py')), \
                patch.object(web.api, 'create_server') as server:
            with self.assertRaises(ValueError): web.create_server(self.path, port=0)
        server.assert_not_called()


if __name__ == '__main__': unittest.main()
