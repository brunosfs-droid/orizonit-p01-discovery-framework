"""Opt-in ingestion boundary; real PostgreSQL tests use the disposable CI service."""
import concurrent.futures
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch
from urllib import request

import test_offline_import as source
import test_postgresql as support

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('p01_indexed_api', ROOT/'ingestion/P01_Ingestion_API.py')
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)
sys.path.insert(0, str(ROOT/'persistence'))
import P01_Ingestion_Index as bridge
pg = bridge.pg


def ingest(service, raw, node=None):
    data = raw.read_bytes()
    return service.ingest_stream(io.BytesIO(data), len(data), pg.digest(data), authenticated_node_id=node)


def source_hashes(store):
    return {str(p.relative_to(store)): pg.digest(p.read_bytes()) for p in store.rglob('*') if p.is_file()}


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.raw = source.OfflineImportTests()._bundle(self.base)
        self.store = self.base/'store'

    def test_default_off_never_connects_and_preserves_response_contract(self):
        service = api.IngestionService(self.store)
        with patch.object(pg, 'open_connection') as connect:
            first = ingest(service, self.raw)
            before = source_hashes(self.store)
            repeat = ingest(service, self.raw)
            looked = service.lookup(first['bundle_id'])
        connect.assert_not_called()
        self.assertEqual(first['status'], 'imported')
        self.assertEqual(repeat['status'], 'already_imported')
        for doc in (first, repeat, looked):
            self.assertNotIn('metadata_index', doc)
        self.assertEqual(before, source_hashes(self.store))
        self.assertEqual(list(service.staging_dir.iterdir()), [])

    def test_unknown_mode_rejected(self):
        with self.assertRaisesRegex(ValueError, 'invalid metadata_index'):
            api.IngestionService(self.store, metadata_index='unknown')

    def test_db_failure_keeps_filesystem_acknowledgment_and_redacts_error(self):
        service = api.IngestionService(self.store, metadata_index='postgres')
        with patch.object(pg, 'open_connection', side_effect=RuntimeError('password=PRIVATE /secret/path')):
            result = ingest(service, self.raw)
            looked = service.lookup(result['bundle_id'])
        self.assertEqual(result['status'], 'imported')
        self.assertEqual(result['metadata_index']['status'], 'pending')
        self.assertEqual(looked['metadata_index']['error_code'], 'database_failed')
        self.assertNotIn('PRIVATE', json.dumps(result))
        self.assertNotIn('/secret/path', json.dumps(looked))
        directory = next(self.store.glob('assessments/*/imports/*'))
        self.assertEqual(pg.prepare_import(self.store, directory)['bundle_id'], result['bundle_id'])
        self.assertEqual(list(service.staging_dir.iterdir()), [])

    def test_identity_mismatch_prevents_connection(self):
        ingest(api.IngestionService(self.store), self.raw)
        directory = next(self.store.glob('assessments/*/imports/*'))
        expected = {k:v for k,v in pg.prepare_import(self.store, directory).items() if k in (*pg.IDENTITY,'bundle_id')}
        expected['node_id'] = 'OTHER'
        with patch.object(pg, 'open_connection') as connect:
            result = bridge.MetadataIndexer().index(self.store, directory, expected)
        connect.assert_not_called()
        self.assertEqual(result['status'], 'review_required')
        self.assertEqual(result['error_code'], 'identity_mismatch')

    def test_receipt_tamper_is_review_without_db_connection(self):
        first = ingest(api.IngestionService(self.store), self.raw)
        receipt = next(self.store.glob('assessments/*/imports/*/receipt/import-receipt.json'))
        receipt.write_bytes(receipt.read_bytes()+b' ')
        with patch.object(pg, 'open_connection') as connect:
            result = api.IngestionService(self.store, metadata_index='postgres').lookup(first['bundle_id'])
        connect.assert_not_called()
        self.assertEqual(result['metadata_index']['error_code'], 'receipt_integrity_failed')

    def test_wrong_node_post_is_rejected_before_import_and_index(self):
        service = api.IngestionService(self.store, metadata_index='postgres')
        with patch.object(pg, 'open_connection') as connect, self.assertRaises(api.IngestionError) as exc:
            ingest(service, self.raw, node='OTHER')
        connect.assert_not_called()
        self.assertEqual(exc.exception.status_code, 403)
        self.assertEqual(list(self.store.glob('assessments/*/imports/*')), [])

    def test_wrong_node_get_is_rejected_before_db_lookup(self):
        first = ingest(api.IngestionService(self.store), self.raw)
        service = api.IngestionService(self.store, metadata_index='postgres')
        with patch.object(pg, 'open_connection') as connect, self.assertRaises(api.IngestionError) as exc:
            service.lookup(first['bundle_id'], authenticated_node_id='OTHER')
        connect.assert_not_called()
        self.assertEqual(exc.exception.status_code, 403)

    def test_schema_failure_requires_review_and_never_runs_migration(self):
        service = api.IngestionService(self.store, metadata_index='postgres')
        with patch.object(pg, 'open_connection') as connect, patch.object(pg, 'migrate') as migrate:
            connect.return_value.__enter__.return_value = Mock()
            with patch.object(pg, 'index_import', side_effect=pg.PersistenceError('schema_mismatch')):
                result = ingest(service, self.raw)
        migrate.assert_not_called()
        self.assertEqual(result['metadata_index']['status'], 'review_required')
        self.assertEqual(result['metadata_index']['error_code'], 'schema_mismatch')

    def test_first_request_cleanup_cannot_delete_second_request_staging(self):
        service = api.IngestionService(self.store, metadata_index='postgres')
        first_index = threading.Event()
        second_inside = threading.Event()
        allow_second = threading.Event()
        original = api.import_bundle
        calls = 0
        guard = threading.Lock()
        def importer(path, *args, **kwargs):
            nonlocal calls
            with guard:
                calls += 1
                count = calls
            if count == 2:
                second_inside.set()
                self.assertTrue(allow_second.wait(5))
                self.assertTrue(path.is_file(), 'previous request deleted canonical staging')
            return original(path, *args, **kwargs)
        indexed = 0
        def index(*args):
            nonlocal indexed
            with guard:
                indexed += 1
                count = indexed
            if count == 1:
                first_index.set()
                self.assertTrue(second_inside.wait(5))
            return {'status': 'indexed' if count == 1 else 'already_indexed'}
        service.metadata_indexer.index = index
        with patch.object(api, 'import_bundle', side_effect=importer), concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            one = pool.submit(ingest, service, self.raw)
            self.assertTrue(first_index.wait(5))
            two = pool.submit(ingest, service, self.raw)
            try:
                self.assertEqual(one.result(timeout=10)['status'], 'imported')
            finally:
                allow_second.set()
            self.assertEqual(two.result(timeout=10)['status'], 'already_imported')
        self.assertEqual(list(service.staging_dir.iterdir()), [])


@unittest.skipUnless(os.environ.get('CANCA_TEST_POSTGRES') == '1', 'real PostgreSQL integration opt-in required')
class IndexedPostgreSQLTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.raw = source.OfflineImportTests()._bundle(self.base)
        self.store = self.base/'store'
        self.conn = pg.open_connection()
        self.addCleanup(self.conn.close)
        self.conn.execute('DROP SCHEMA IF EXISTS canca CASCADE')
        pg.migrate(self.conn)
        self.service = api.IngestionService(self.store, process=True, metadata_index='postgres')

    def directory(self):
        return next(self.store.glob('assessments/*/imports/*'))

    def counts(self):
        return tuple(self.conn.execute('SELECT count(*) FROM canca.'+table).fetchone()[0]
                     for table in ('assessments','nodes','runs','imports','artifacts'))

    def reconcile(self):
        projection = pg.prepare_import(self.store, self.directory())
        with pg.open_connection() as conn:
            return pg.index_import(conn, projection)

    def start_http(self):
        server = api.P01HTTPServer(('127.0.0.1',0), api.P01IngestionHandler, self.service)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def close():
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.addCleanup(close)
        return 'http://127.0.0.1:'+str(server.server_port)

    def post(self, url):
        data = self.raw.read_bytes()
        req = request.Request(url+'/api/v1/bundles', data=data, method='POST', headers={
            'Content-Type':'application/octet-stream','X-P01-Bundle-SHA256':pg.digest(data)})
        with request.urlopen(req, timeout=30) as response:
            return response.status, json.load(response)

    def test_http_first_repeat_get_and_read_only_store(self):
        url = self.start_http()
        code, first = self.post(url)
        self.assertEqual(code, 201)
        self.assertEqual(first['metadata_index']['status'], 'indexed')
        before = source_hashes(self.store)
        code, repeat = self.post(url)
        self.assertEqual(code, 200)
        self.assertEqual(repeat['metadata_index']['status'], 'already_indexed')
        with request.urlopen(url+'/api/v1/bundles/'+first['bundle_id']) as response:
            self.assertEqual(json.load(response)['metadata_index']['status'], 'indexed')
        self.assertEqual(before, source_hashes(self.store))
        self.assertEqual(self.counts(), (1,1,1,1,4))

    def test_unavailable_db_then_explicit_cli_reconciliation(self):
        url = self.start_http()
        with patch.dict(os.environ, {'PGPORT':'1'}):
            code, first = self.post(url)
        self.assertEqual(code, 201)
        self.assertEqual(first['metadata_index']['status'], 'pending')
        self.assertEqual(self.counts(), (0,0,0,0,0))
        before = source_hashes(self.store)
        output = io.StringIO()
        with redirect_stdout(output):
            status = pg.cli(['index-import','--store-dir',str(self.store),'--import-dir',str(self.directory())])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output.getvalue())['status'], 'indexed')
        self.assertEqual(before, source_hashes(self.store))
        self.assertEqual(self.service.lookup(first['bundle_id'])['metadata_index']['status'], 'indexed')

    def test_get_missing_index_reports_pending_without_writing(self):
        first = ingest(api.IngestionService(self.store), self.raw)
        before = source_hashes(self.store)
        result = self.service.lookup(first['bundle_id'])
        self.assertEqual(result['metadata_index']['reason'], 'not_indexed')
        self.assertEqual(self.counts(), (0,0,0,0,0))
        self.assertEqual(before, source_hashes(self.store))

    def test_schema_missing_does_not_auto_migrate(self):
        self.conn.execute('DROP SCHEMA canca CASCADE')
        first = ingest(self.service, self.raw)
        self.assertEqual(first['status'], 'imported')
        self.assertEqual(first['metadata_index']['error_code'], 'schema_required')
        self.assertIsNone(self.conn.execute("SELECT to_regclass('canca.schema_migrations')").fetchone()[0])
        pg.prepare_import(self.store, self.directory())

    def test_failed_db_transaction_preserves_import_for_reconciliation(self):
        self.conn.execute("""CREATE FUNCTION canca.fail_artifact() RETURNS trigger LANGUAGE plpgsql AS
            $$ BEGIN RAISE EXCEPTION 'synthetic rollback'; END $$""")
        self.conn.execute('CREATE TRIGGER reject_artifact BEFORE INSERT ON canca.artifacts FOR EACH ROW EXECUTE FUNCTION canca.fail_artifact()')
        first = ingest(self.service, self.raw)
        self.assertEqual(first['metadata_index']['status'], 'pending')
        self.assertEqual(self.counts(), (0,0,0,0,0))
        before = source_hashes(self.store)
        self.conn.execute('DROP TRIGGER reject_artifact ON canca.artifacts')
        self.assertEqual(self.reconcile()['status'], 'indexed')
        self.assertEqual(before, source_hashes(self.store))
        self.assertEqual(self.counts(), (1,1,1,1,4))

    def test_conflict_is_review_without_source_or_db_overwrite(self):
        first = ingest(api.IngestionService(self.store), self.raw)
        conflict = copy.deepcopy(pg.prepare_import(self.store, self.directory()))
        conflict['receipt_sha256'] = '0'*64
        pg.index_import(self.conn, conflict)
        before = source_hashes(self.store)
        repeat = ingest(self.service, self.raw)
        self.assertEqual(repeat['status'], 'already_imported')
        self.assertEqual(repeat['metadata_index']['error_code'], 'bundle_conflict')
        self.assertEqual(self.service.lookup(first['bundle_id'])['metadata_index']['error_code'], 'bundle_conflict')
        self.assertEqual(pg.show_import(self.conn, first['bundle_id'])['receipt_sha256'], '0'*64)
        self.assertEqual(before, source_hashes(self.store))

    def test_concurrent_duplicate_requests_converge(self):
        barrier = threading.Barrier(2)
        def worker():
            barrier.wait(timeout=5)
            return ingest(self.service, self.raw)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(worker) for _ in range(2)]
            docs = [f.result(timeout=40) for f in futures]
        self.assertCountEqual([d['status'] for d in docs], ['imported','already_imported'])
        self.assertCountEqual([d['metadata_index']['status'] for d in docs], ['indexed','already_indexed'])
        self.assertEqual(self.counts(), (1,1,1,1,4))
        self.assertEqual(list(self.service.staging_dir.iterdir()), [])

    def interrupted(self, phase):
        script = '''import io, os, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1])/'ingestion'))
from P01_Ingestion_API import IngestionService, digest_file
raw, store = Path(sys.argv[2]), Path(sys.argv[3])
service = IngestionService(store, process=True, metadata_index='postgres')
original = service.metadata_indexer.index
def cut(*args):
    if sys.argv[4]=='after-db':
        result = original(*args)
        if result['status']!='indexed': raise RuntimeError('expected real DB commit')
    os._exit(73)
service.metadata_indexer.index = cut
data = raw.read_bytes()
service.ingest_stream(io.BytesIO(data), len(data), digest_file(raw))
'''
        result = subprocess.run([sys.executable,'-c',script,str(ROOT),str(self.raw),str(self.store),phase],
                                capture_output=True, text=True, timeout=40)
        self.assertEqual(result.returncode, 73, result.stderr)
        pg.prepare_import(self.store, self.directory())
        return source_hashes(self.store)

    def test_process_exit_after_files_before_db_is_reconciled(self):
        before = self.interrupted('before-db')
        self.assertEqual(self.counts(), (0,0,0,0,0))
        self.assertEqual(self.reconcile()['status'], 'indexed')
        self.assertEqual(self.reconcile()['status'], 'already_indexed')
        self.assertEqual(before, source_hashes(self.store))

    def test_process_exit_after_db_before_ack_replays_safely(self):
        before = self.interrupted('after-db')
        self.assertEqual(self.counts(), (1,1,1,1,4))
        restarted = api.IngestionService(self.store, metadata_index='postgres')
        repeat = ingest(restarted, self.raw)
        self.assertEqual(repeat['status'], 'already_imported')
        self.assertEqual(repeat['metadata_index']['status'], 'already_indexed')
        self.assertEqual(before, source_hashes(self.store))
        self.assertEqual(self.counts(), (1,1,1,1,4))


if __name__ == '__main__':
    unittest.main()
