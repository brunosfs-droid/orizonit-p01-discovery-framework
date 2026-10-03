"""Policy and real synthetic importer boundaries; no customer credentials."""
import copy
from contextlib import closing
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import test_ingestion_api as existing
import test_offline_import as source

api = existing.mod
auth = sys.modules['P01_Node_Authorization']
NODE = 'NODE-01'
ASSESSMENT = 'LAB-001'


def policy_doc(permissions=('bundle:ingest', 'bundle:read')):
    return {'policy_version': '1', 'nodes': [
        {'node_id': NODE, 'grants': [{'assessment_id': ASSESSMENT, 'permissions': list(permissions)}]}
    ]}


def policy(doc=None):
    return auth.NodePolicy(json.dumps(policy_doc() if doc is None else doc).encode())


class PolicyTests(unittest.TestCase):
    def test_exact_assessment_and_separate_permissions(self):
        p = policy(policy_doc(('bundle:ingest',)))
        p.require(NODE.lower(), ASSESSMENT, 'bundle:ingest')
        for node, assessment, permission, status in [
            (None, ASSESSMENT, 'bundle:read', 401),
            ('OTHER', ASSESSMENT, 'bundle:ingest', 403),
            (NODE, 'lab-001', 'bundle:ingest', 403),
            (NODE, 'LAB-002', 'bundle:ingest', 403),
            (NODE, ASSESSMENT, 'bundle:read', 403),
            (NODE, ASSESSMENT, '*', 403),
        ]:
            with self.subTest(node=node, assessment=assessment, permission=permission):
                with self.assertRaises(auth.AuthorizationError) as exc:
                    p.require(node, assessment, permission)
                self.assertEqual(exc.exception.status_code, status)

    def test_empty_policy_and_empty_grants_deny(self):
        with self.assertRaises(auth.AuthorizationError):
            policy({'policy_version': '1', 'nodes': []}).require_node(NODE)
        doc = policy_doc(); doc['nodes'][0]['grants'] = []
        with self.assertRaises(auth.AuthorizationError):
            policy(doc).require(NODE, ASSESSMENT, 'bundle:read')
        with self.assertRaises(auth.AuthorizationError):
            policy(policy_doc(())).require(NODE, ASSESSMENT, 'bundle:ingest')

    def test_invalid_documents_are_fixed_errors(self):
        docs = [None, [], {}, {'policy_version': True, 'nodes': []}]
        for key, value in [('policy_version', '2'), ('nodes', {}), ('extra', 'PRIVATE')]:
            d = policy_doc(); d[key] = value; docs.append(d)
        for key, value in [('node_id', '*'), ('node_id', '../PRIVATE'), ('grants', {}), ('secret', 'PRIVATE')]:
            d = policy_doc(); d['nodes'][0][key] = value; docs.append(d)
        for key, value in [('assessment_id', '*'), ('assessment_id', 'LAB/PRIVATE'),
                           ('permissions', ['admin']), ('permissions', ['bundle:read'] * 2),
                           ('permissions', [None]), ('permissions', 'bundle:read'), ('extra', 'PRIVATE')]:
            d = policy_doc(); d['nodes'][0]['grants'][0][key] = value; docs.append(d)
        duplicate_node = policy_doc()
        duplicate_node['nodes'].append(copy.deepcopy(duplicate_node['nodes'][0]))
        duplicate_node['nodes'][1]['node_id'] = NODE.lower(); docs.append(duplicate_node)
        duplicate_scope = policy_doc()
        duplicate_scope['nodes'][0]['grants'] *= 2; docs.append(duplicate_scope)
        d = policy_doc(); d['nodes'] *= auth.MAX_NODES + 1; docs.append(d)
        d = policy_doc(); d['nodes'][0]['grants'] *= auth.MAX_GRANTS_PER_NODE + 1; docs.append(d)
        for doc in docs:
            with self.subTest(doc=doc):
                with self.assertRaisesRegex(ValueError, '^invalid node authorization policy$'):
                    policy(doc) if doc is not None else auth.NodePolicy(b'null')
        for raw in [b'', b'PRIVATE', b'\xff', b' ' * (auth.MAX_POLICY_BYTES + 1),
                    b'{"policy_version":"1","nodes":[],"nodes":[]}',
                    b'{"policy_version":"1","nodes":[{"node_id":"a","node_id":"b","grants":[]}]}']:
            with self.assertRaisesRegex(ValueError, '^invalid node authorization policy$'):
                auth.NodePolicy(raw)

    def test_snapshot_and_nested_grants_are_immutable(self):
        raw = json.dumps(policy_doc()).encode(); p = auth.NodePolicy(raw)
        self.assertEqual(p.sha256, hashlib.sha256(raw).hexdigest())
        with self.assertRaises(AttributeError): p._grants = {}
        with self.assertRaises(AttributeError): del p._grants
        with self.assertRaises(TypeError): p.require_node(NODE)[ASSESSMENT] = frozenset()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'policy.json'; path.write_bytes(raw)
            loaded = auth.load_node_policy(path)
            path.write_text('{"policy_version":"1","nodes":[]}')
            loaded.require(NODE, ASSESSMENT, 'bundle:read')
            with self.assertRaises(auth.AuthorizationError): auth.load_node_policy(path).require_node(NODE)

    def test_bounded_regular_file_loader(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'policy.json'
            for candidate in [path, Path(td)]:
                with self.assertRaisesRegex(ValueError, '^invalid node authorization policy$'):
                    auth.load_node_policy(candidate)
            path.write_bytes(b' ' * (auth.MAX_POLICY_BYTES + 1))
            with self.assertRaises(ValueError): auth.load_node_policy(path)
            path.write_text(json.dumps(policy_doc()))
            if hasattr(os, 'O_NOFOLLOW'):
                alias = Path(td) / 'alias'; alias.symlink_to(path)
                with self.assertRaises(ValueError): auth.load_node_policy(alias)


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.raw = source.OfflineImportTests()._bundle(self.base).read_bytes()
        self.sha = hashlib.sha256(self.raw).hexdigest()
        self.store = self.base / 'store'

    def service(self, permissions=('bundle:ingest', 'bundle:read')):
        return api.IngestionService(self.store, transport_mode='mtls', node_policy=policy(policy_doc(permissions)))

    def ingest(self, service, node=NODE):
        return service.ingest_stream(io.BytesIO(self.raw), len(self.raw), self.sha, authenticated_node_id=node)

    def test_unauthorized_principal_never_reads_or_stages(self):
        service = self.service(); stream = Mock()
        with patch.object(service, '_stage_stream') as stage, patch.object(api, 'import_bundle') as importer:
            for node, status in [(None, 401), ('OTHER', 403)]:
                with self.assertRaises(api.IngestionError) as exc:
                    service.ingest_stream(stream, len(self.raw), self.sha, authenticated_node_id=node)
                self.assertEqual(exc.exception.status_code, status)
        stage.assert_not_called(); importer.assert_not_called(); stream.read.assert_not_called()
        self.assertEqual(list(service.staging_dir.iterdir()), [])

    def test_wrong_assessment_and_write_permission_never_import_or_index(self):
        doc = policy_doc(); doc['nodes'][0]['grants'][0]['assessment_id'] = 'OTHER'
        for p in [policy(doc), policy(policy_doc(('bundle:read',)))]:
            service = api.IngestionService(self.store, transport_mode='mtls', node_policy=p)
            service.metadata_indexer = Mock()
            with patch.object(api, 'import_bundle') as importer:
                with self.assertRaisesRegex(api.IngestionError, '^operation is not authorized$'):
                    self.ingest(service)
            importer.assert_not_called(); service.metadata_indexer.index.assert_not_called()
            self.assertEqual(list(service.staging_dir.iterdir()), [])
            self.assertFalse((self.store / 'assessments').exists())

    def test_real_import_replay_read_and_post_revocation_deny(self):
        service = self.service()
        first = self.ingest(service)
        before = {str(p): p.read_bytes() for p in self.store.rglob('*') if p.is_file()}
        self.assertEqual(self.ingest(service)['status'], 'already_imported')
        self.assertEqual(service.lookup(first['bundle_id'], NODE)['assessment_id'], ASSESSMENT)
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.store.rglob('*') if p.is_file()})
        reader = self.service(('bundle:read',))
        self.assertEqual(reader.lookup(first['bundle_id'], NODE)['bundle_id'], first['bundle_id'])
        writer = self.service(('bundle:ingest',)); writer.metadata_indexer = Mock()
        with self.assertRaisesRegex(api.IngestionError, '^operation is not authorized$'):
            writer.lookup(first['bundle_id'], NODE)
        writer.metadata_indexer.lookup.assert_not_called()
        changed = policy_doc(); changed['nodes'][0]['grants'][0]['assessment_id'] = 'LAB-002'
        other_scope = api.IngestionService(self.store, transport_mode='mtls', node_policy=policy(changed))
        other_scope.metadata_indexer = Mock()
        with self.assertRaisesRegex(api.IngestionError, '^operation is not authorized$'):
            other_scope.lookup(first['bundle_id'], NODE)
        other_scope.metadata_indexer.lookup.assert_not_called()
        revoked = api.IngestionService(self.store, transport_mode='mtls', node_policy=policy({'policy_version': '1', 'nodes': []}))
        with patch.object(api, 'load_json') as load:
            with self.assertRaisesRegex(api.IngestionError, '^node is not authorized$'):
                revoked.lookup(first['bundle_id'], NODE)
        load.assert_not_called()

    def test_grant_does_not_bypass_manifest_node_or_receipt_ownership(self):
        doc = policy_doc(); doc['nodes'][0]['node_id'] = 'OTHER'
        service = api.IngestionService(self.store, transport_mode='mtls', node_policy=policy(doc))
        with patch.object(api, 'import_bundle') as importer:
            with self.assertRaises(api.IngestionError): self.ingest(service, 'OTHER')
        importer.assert_not_called()
        first = self.ingest(self.service())
        with self.assertRaisesRegex(api.IngestionError, 'not owned'):
            service.lookup(first['bundle_id'], 'OTHER')

    def test_policy_cannot_use_unauthenticated_transport(self):
        with self.assertRaises(ValueError): api.IngestionService(self.store, node_policy=policy())
        with self.assertRaises(ValueError): api.IngestionService(self.store, transport_mode='mtls', node_policy={})

    def test_invalid_policy_startup_never_creates_store_or_server(self):
        paths = [self.base / x for x in ('cert', 'key', 'ca')]
        for path in paths: path.write_bytes(b'synthetic-placeholder')
        invalid = self.base / 'invalid-policy'; invalid.write_bytes(b'PRIVATE')
        with patch.object(api, 'IngestionService') as service, patch.object(api, 'P01HTTPServer') as server:
            with self.assertRaisesRegex(ValueError, '^invalid node authorization policy$'):
                api.serve(self.store, transport_mode='mtls', tls_cert=paths[0], tls_key=paths[1], client_ca=paths[2], node_policy_path=invalid)
        service.assert_not_called(); server.assert_not_called(); self.assertFalse(self.store.exists())


@unittest.skipUnless(shutil.which('openssl'), 'openssl required for synthetic mTLS fixture')
class HTTPMTLSTests(unittest.TestCase):
    setUp = ServiceTests.setUp
    service = ServiceTests.service
    def test_real_mtls_policy_and_http_connection_hygiene(self):
        def openssl(*args):
            subprocess.run(['openssl', *args], cwd=self.base, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=Synthetic-CI-CA', '-keyout', 'ca.key', '-out', 'ca.crt')
        for name, cn, ext in [('server', 'localhost', 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n'),
                              ('client', NODE, f'subjectAltName=DNS:{NODE}\nextendedKeyUsage=clientAuth\n')]:
            openssl('req', '-newkey', 'rsa:2048', '-nodes', '-subj', f'/CN={cn}', '-keyout', f'{name}.key', '-out', f'{name}.csr')
            (self.base / f'{name}.ext').write_text(ext)
            openssl('x509', '-req', '-in', f'{name}.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-days', '1', '-extfile', f'{name}.ext', '-out', f'{name}.crt')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(self.base / 'server.crt', self.base / 'server.key')
        context.load_verify_locations(self.base / 'ca.crt')
        client = ssl.create_default_context(cafile=str(self.base / 'ca.crt'))
        client.load_cert_chain(self.base / 'client.crt', self.base / 'client.key')
        service = self.service()
        server = api.P01HTTPServer(('127.0.0.1', 0), api.P01IngestionHandler, service)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
        def connection(tls=client):
            return closing(http.client.HTTPSConnection('localhost', server.server_address[1], context=tls, timeout=3))
        try:
            with connection() as conn:
                conn.request('GET', '/healthz'); response = conn.getresponse()
                self.assertEqual(json.loads(response.read())['authorization_mode'], 'node_policy')
            headers = {'X-P01-Node-ID': NODE, 'Content-Type': 'application/octet-stream', 'X-P01-Bundle-SHA256': self.sha}
            with connection() as conn:
                conn.request('POST', '/api/v1/bundles', self.raw, headers); response = conn.getresponse()
                self.assertEqual(response.status, 201); result = json.loads(response.read())
                conn.request('GET', '/api/v1/bundles/' + result['bundle_id'], headers={'X-P01-Node-ID': NODE})
                response = conn.getresponse(); self.assertEqual(response.status, 200); response.read()
            for node, expected in [('', 401), ('FORGED', 403)]:
                with connection() as conn:
                    conn.request('POST', '/api/v1/bundles', self.raw, {**headers, 'X-P01-Node-ID': node})
                    response = conn.getresponse(); self.assertEqual(response.status, expected)
                    self.assertEqual(response.getheader('Connection'), 'close'); response.read()
            # Controlled restart uses a fresh immutable snapshot to revoke the grant.
            server.shutdown(); worker.join(timeout=3); server.server_close()
            revoked = api.IngestionService(self.base / 'revoked-store', transport_mode='mtls', node_policy=policy({'policy_version': '1', 'nodes': []}))
            server = api.P01HTTPServer(('127.0.0.1', 0), api.P01IngestionHandler, revoked)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
            with patch.object(revoked, '_stage_stream') as stage, connection() as conn:
                conn.request('POST', '/api/v1/bundles', self.raw, headers); response = conn.getresponse()
                self.assertEqual(response.status, 403); self.assertEqual(response.getheader('Connection'), 'close')
                self.assertEqual(json.loads(response.read())['error']['message'], 'node is not authorized')
            stage.assert_not_called()
            no_cert = ssl.create_default_context(cafile=str(self.base / 'ca.crt'))
            with connection(no_cert) as conn, self.assertRaises((ssl.SSLError, OSError, http.client.HTTPException)):
                conn.request('GET', '/healthz'); conn.getresponse().read()
        finally:
            server.shutdown(); server.server_close(); worker.join(timeout=3)


if __name__ == '__main__':
    unittest.main()
