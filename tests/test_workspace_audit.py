"""Private workspace HTTP audit: fixed metadata, redaction and fail-closed admission."""
from contextlib import closing
import http.client
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server'))
import P01_Workspace_Audit as audit
import P01_Workspace_API as api
import test_operator_auth as fixture

CORE = {'audit_version', 'sequence', 'at_utc', 'listener', 'event'}
START = CORE | {'request_id', 'operation'}
FINISH = START | {'http_status', 'outcome', 'operator_id', 'workspace_id'}
MARKER = 'NEVER-WORKSPACE-AUDIT-SECRET'
BUNDLE = 'bnd-' + 'a' * 20
SCOPE = 'b' * 64


def records(path, *, closed=True):
    raw = path.read_bytes()
    assert raw.endswith(b'\n')
    rows = [json.loads(line) for line in raw.splitlines()]
    lines = raw.splitlines(keepends=True)
    pending = {}
    for index, row in enumerate(rows, 1):
        assert row['audit_version'] == '1' and row['sequence'] == index
        assert row['listener'] == 'workspace' and row['at_utc'].endswith('Z')
        assert len(lines[index - 1]) <= audit.MAX_RECORD_BYTES
        if row['event'] == 'request_started':
            assert set(row) == START and row['request_id'] not in pending
            assert row['operation'] in audit.OPERATIONS
            pending[row['request_id']] = row['operation']
        elif row['event'] == 'request_finished':
            assert set(row) == FINISH
            assert pending.pop(row['request_id']) == row['operation']
            assert row['outcome'] in audit.OUTCOMES
        else:
            assert set(row) == CORE
            assert row['event'] in {'listener_started', 'listener_stopped'}
    assert rows[0]['event'] == 'listener_started'
    if closed:
        assert rows[-1]['event'] == 'listener_stopped' and not pending
    return rows


class FileAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.path = self.root / 'workspace-audit.jsonl'

    @staticmethod
    def _close(sink):
        try:
            sink.close()
        except audit.AuditError:
            pass

    def make(self, **kwargs):
        sink = audit.FileAudit(self.path, **kwargs)
        self.addCleanup(self._close, sink)
        return sink

    def test_private_exclusive_schema_and_ids(self):
        sink = self.make()
        request = sink.begin('workspace_open')
        sink.finish(
            request, http_status=200, outcome='response_written',
            operator_id='OP-01', workspace_id='LAB-A',
        )
        sink.close()
        rows = records(self.path)
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[2]['workspace_id'], 'LAB-A')
        self.assertEqual(self.path.stat().st_nlink, 1)
        if os.name == 'posix':
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_existing_file_capacity_and_reserved_completions(self):
        self.path.write_bytes(b'PRIVATE')
        with self.assertRaisesRegex(audit.AuditError, '^workspace_audit_unavailable$'):
            audit.FileAudit(self.path)
        self.path.unlink()
        sink = self.make(max_bytes=4096)
        pending = []
        while True:
            try:
                pending.append(sink.begin('object_list'))
            except audit.AuditError:
                break
        self.assertGreater(len(pending), 0)
        for request in pending:
            sink.finish(
                request, http_status=200, outcome='response_written',
                operator_id='O' * 128, workspace_id='W' * 128,
            )
        with self.assertRaises(audit.AuditError):
            sink.begin('health')
        sink.close()
        records(self.path)
        self.assertLessEqual(self.path.stat().st_size, 4096)

    def test_invalid_workspace_without_operator_latches_without_echo(self):
        sink = self.make()
        request = sink.begin('object_read')
        before = self.path.read_bytes()
        with self.assertRaises(audit.AuditError):
            sink.finish(
                request, http_status=403, outcome='response_written',
                workspace_id=MARKER,
            )
        self.assertEqual(before, self.path.read_bytes())
        with self.assertRaises(audit.AuditError):
            sink.begin('health')

    def test_route_classifier_is_fixed_and_never_returns_untrusted_values(self):
        cases = [
            ('POST', '/api/v1/operator/session?password=' + MARKER, 'login'),
            ('DELETE', '/api/v1/operator/session', 'logout'),
            ('GET', '/healthz', 'health'),
            ('GET', '/api/v1/workspaces', 'workspace_directory'),
            ('POST', '/api/v1/workspaces/A/open', 'workspace_open'),
            ('POST', '/api/v1/workspaces/A/close', 'workspace_close'),
            ('GET', '/api/v1/workspaces/A/objects?after=' + MARKER, 'object_list'),
            ('POST', '/api/v1/workspaces/A/objects', 'object_declare'),
            ('GET', '/api/v1/workspaces/A/objects/server', 'object_read'),
            ('GET', '/api/v1/workspaces/A/graph/server', 'graph_read'),
            ('POST', '/api/v1/workspaces/A/declarations', 'declaration_write'),
            ('POST', '/api/v1/workspaces/A/relationships', 'relationship_write'),
            ('POST', '/api/v1/workspaces/A/imports/preview', 'import_preview'),
            ('POST', '/api/v1/workspaces/A/imports/apply', 'import_apply'),
            ('POST', '/api/v1/workspaces/A/legacy/preview', 'legacy_preview'),
            ('POST', '/api/v1/workspaces/A/legacy/apply', 'legacy_apply'),
            (
                'GET',
                '/api/v1/workspaces/A/legacy/' + BUNDLE + '/report?token=' + MARKER,
                'historical_report',
            ),
            ('PATCH', '/api/v1/workspaces/A/open', 'other'),
            ('GET', 'http://[invalid', 'other'),
        ]
        for method, target, expected in cases:
            self.assertEqual(audit.operation(method, target), expected)

    def test_external_append_latches_and_is_never_repaired_live(self):
        sink = self.make()
        with self.path.open('ab') as stream:
            stream.write(b'EXTERNAL\n')
        before = self.path.read_bytes()
        with self.assertRaises(audit.AuditError):
            sink.begin('health')
        self.assertEqual(self.path.read_bytes(), before)
        with self.assertRaises(audit.AuditError):
            sink.close()


class HTTPAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name).resolve() / 'http.jsonl'
        self.auth = api.authn.LocalAuth(fixture.policy())
        self.service = Mock()
        self.service.auth = self.auth
        self.service.execute.return_value = {'status': 'ok'}
        self.server = api.WorkspaceServer(('127.0.0.1', 0), self.service)
        self.server.audit = audit.FileAudit(self.path)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.addCleanup(self.cleanup)

    def cleanup(self):
        if self.server is None:
            return
        server = self.server
        self.server = None
        try:
            server.shutdown()
            try:
                server.server_close()
            except audit.AuditError:
                pass
        finally:
            self.worker.join(5)

    def stop(self):
        server = self.server
        self.server = None
        server.shutdown()
        try:
            server.server_close()
        finally:
            self.worker.join(5)

    def request(self, method, path, payload=None, headers=None):
        with closing(
            http.client.HTTPConnection(
                '127.0.0.1', self.server.server_port, timeout=10,
            )
        ) as conn:
            conn.request(
                method, path,
                json.dumps(payload) if payload is not None else None,
                headers or {},
            )
            response = conn.getresponse()
            return response.status, json.loads(response.read())

    def login(self):
        code, doc = self.request(
            'POST', '/api/v1/operator/session',
            {'username': 'reader', 'password': fixture.PASSWORD},
            {'Content-Type': 'application/json'},
        )
        self.assertEqual(code, 201)
        return (
            doc['access_token'],
            {
                'Authorization': 'Bearer ' + doc['access_token'],
                'Content-Type': 'application/json',
            },
        )

    def drain(self):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            with self.server.audit._lock:
                if not self.server.audit._pending:
                    return
            time.sleep(0.01)
        self.fail('audit did not drain')

    def test_lifecycle_import_backfill_and_report_log_only_trusted_metadata(self):
        token, headers = self.login()
        calls = [
            ('GET', api.BASE, None),
            ('POST', api.BASE + '/A/open', {'generation': 1}),
            ('GET', api.BASE + '/A/objects?generation=2', None),
            (
                'POST', api.BASE + '/A/objects',
                {
                    'generation': 2, 'expected_revision': 0,
                    'request_id': 'r1', 'object_id': 'manual-' + MARKER,
                    'kind': 'host', 'label': 'Host', 'reason': MARKER,
                },
            ),
            (
                'POST', api.BASE + '/A/imports/preview',
                {
                    'generation': 2, 'assessment_id': 'LAB-001',
                    'bundle_id': BUNDLE,
                },
            ),
            (
                'POST', api.BASE + '/A/legacy/preview',
                {'generation': 2, 'bundle_id': BUNDLE},
            ),
            (
                'GET',
                api.BASE + '/A/legacy/' + BUNDLE
                + '/report?generation=2&expected_scope_sha256=' + SCOPE,
                None,
            ),
            ('POST', api.BASE + '/A/close', {'generation': 2, 'timeout': 0}),
        ]
        for method, path, payload in calls:
            self.assertEqual(self.request(method, path, payload, headers)[0], 200)
        self.assertEqual(
            self.request(
                'DELETE', '/api/v1/operator/session', headers=headers,
            )[0],
            200,
        )
        self.stop()
        rows = [
            row for row in records(self.path)
            if row['event'] == 'request_finished'
        ]
        self.assertEqual(
            [row['operation'] for row in rows],
            [
                'login', 'workspace_directory', 'workspace_open', 'object_list',
                'object_declare', 'import_preview', 'legacy_preview',
                'historical_report', 'workspace_close', 'logout',
            ],
        )
        self.assertEqual(
            [row['workspace_id'] for row in rows],
            [None, None, 'A', 'A', 'A', 'A', 'A', 'A', 'A', None],
        )
        self.assertTrue(all(row['operator_id'] == 'OP-01' for row in rows))
        raw = self.path.read_bytes()
        for value in (
            token, fixture.PASSWORD, MARKER, BUNDLE, SCOPE, 'LAB-001',
        ):
            self.assertNotIn(value.encode(), raw)

    def test_denied_workspace_id_is_not_copied(self):
        token, headers = self.login()
        self.service.execute.side_effect = api.pg.PersistenceError(
            'workspace_access_denied'
        )
        self.assertEqual(
            self.request(
                'GET',
                api.BASE + '/SECRET-WS/objects?generation=2',
                headers=headers,
            )[0],
            403,
        )
        self.stop()
        rows = [
            row for row in records(self.path)
            if row['event'] == 'request_finished'
        ]
        self.assertIsNone(rows[-1]['workspace_id'])
        self.assertEqual(rows[-1]['operator_id'], 'OP-01')
        self.assertNotIn(b'SECRET-WS', self.path.read_bytes())
        self.assertNotIn(token.encode(), self.path.read_bytes())

    def test_audit_drift_blocks_before_workspace_service(self):
        _, headers = self.login()
        self.drain()
        self.service.execute.reset_mock()
        with self.path.open('ab') as stream:
            stream.write(b'EXTERNAL\n')
        code, doc = self.request('GET', api.BASE, headers=headers)
        self.assertEqual(code, 503)
        self.assertEqual(doc['error_code'], 'workspace_audit_unavailable')
        self.service.execute.assert_not_called()
        with self.assertRaises(audit.AuditError):
            self.stop()


class WiringTests(unittest.TestCase):
    def test_create_server_installs_opt_in_audit_after_schema_gate(self):
        accounts = fixture.policy()
        bindings = api.BindingPolicy(
            json.dumps(
                dict(
                    binding_version='1',
                    coordinator_role='canca_ws_coordinator',
                    bindings=[
                        dict(operator_id='OP-01', db_role='canca_ws_writer')
                    ],
                    sources={},
                )
            ).encode(),
            accounts,
        )
        control = Mock()
        coordinator = Mock()
        server = Mock()
        server.audit = None
        sink = Mock()
        with patch.object(
            api.authn, 'load_policy', return_value=accounts
        ), patch.object(
            api, 'load_bindings', return_value=bindings
        ), patch.object(
            api.RoleConnections, 'open', return_value=control
        ), patch.object(
            api.pg, 'schema_check'
        ), patch.object(
            api.runtime, 'SessionLease'
        ), patch.object(
            api.runtime, 'Coordinator', return_value=coordinator
        ), patch.object(
            api, 'HumanWorkspaceService', return_value=Mock()
        ), patch.object(
            api, 'WorkspaceServer', return_value=server
        ), patch.object(
            api.workspace_audit, 'FileAudit', return_value=sink
        ) as factory:
            result = api.create_server(
                'accounts', 'bindings', port=0,
                audit_path='private-audit.jsonl',
            )
        self.assertIs(result, server)
        factory.assert_called_once_with('private-audit.jsonl')
        self.assertIs(server.audit, sink)
        coordinator.start.assert_called_once()


if __name__ == '__main__':
    unittest.main()
