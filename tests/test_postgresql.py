"""Source checks everywhere; transaction tests require a real isolated PostgreSQL.

CANCA_TEST_POSTGRES=1 opts into destructive schema reset in PGDATABASE.
CI supplies an ephemeral service. Never enable it on a customer database.
"""
import concurrent.futures
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import test_offline_import as offline_tests

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('p01_postgresql', ROOT / 'persistence/P01_PostgreSQL.py')
pg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pg)


def fixture(base):
    raw = offline_tests.OfflineImportTests()._bundle(base)
    store = base / 'store'
    result = offline_tests.mod.import_bundle(raw, store, process=True, require_outer_sidecar=True)
    directory = Path(result['receipt_path']).parents[1]
    return store, directory


def rewrite_receipt(directory, mutate):
    path = directory / 'receipt/import-receipt.json'
    doc = json.loads(path.read_text())
    mutate(doc)
    path.write_bytes(pg.canonical(doc))
    path.with_suffix('.json.sha256').write_text(pg.digest(path.read_bytes()) + '  import-receipt.json\n')


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.store, self.directory = fixture(self.base)

    def test_validated_projection_is_read_only_and_repeatable(self):
        before = {str(p.relative_to(self.store)): pg.digest(p.read_bytes()) for p in self.store.rglob('*') if p.is_file()}
        one = pg.prepare_import(self.store, self.directory)
        self.assertEqual(one, pg.prepare_import(self.store, self.directory))
        self.assertEqual(one['assessment_id'], 'LAB-001')
        self.assertEqual(len(one['artifacts']), 4)
        pg.validate_projection(one)
        after = {str(p.relative_to(self.store)): pg.digest(p.read_bytes()) for p in self.store.rglob('*') if p.is_file()}
        self.assertEqual(before, after)

    def test_receipt_tamper_rejected_before_connect(self):
        path = self.directory / 'receipt/import-receipt.json'
        path.write_bytes(path.read_bytes() + b' ')
        out = io.StringIO()
        with patch.object(pg, 'open_connection') as connection, redirect_stdout(out):
            status = pg.cli(['index-import', '--store-dir', str(self.store), '--import-dir', str(self.directory)])
        connection.assert_not_called()
        self.assertEqual(status, 2)
        self.assertEqual(json.loads(out.getvalue())['error_code'], 'receipt_integrity_failed')

    def test_raw_bundle_tamper(self):
        projection = pg.prepare_import(self.store, self.directory)
        receipt = json.loads((self.directory / 'receipt/import-receipt.json').read_text())
        path = self.directory / receipt['raw_bundle']
        path.write_bytes(path.read_bytes() + b'changed')
        with self.assertRaisesRegex(pg.PersistenceError, 'bundle_integrity_failed'):
            pg.prepare_import(self.store, self.directory)
        self.assertEqual(len(projection['artifacts']), 4)

    def test_resigned_receipt_does_not_bypass_identity(self):
        rewrite_receipt(self.directory, lambda d: d.update(node_id='OTHER-NODE'))
        with self.assertRaisesRegex(pg.PersistenceError, 'identity_mismatch'):
            pg.prepare_import(self.store, self.directory)

    def test_resigned_receipt_count_mismatch(self):
        rewrite_receipt(self.directory, lambda d: d.update(artifact_count=99))
        with self.assertRaisesRegex(pg.PersistenceError, 'identity_mismatch'):
            pg.prepare_import(self.store, self.directory)

    def test_raw_traversal_and_symlink_rejected(self):
        rewrite_receipt(self.directory, lambda d: d.update(raw_bundle='../outside.p01bundle'))
        with self.assertRaisesRegex(pg.PersistenceError, 'input_invalid'):
            pg.prepare_import(self.store, self.directory)
        alias = self.store / 'alias'
        try:
            alias.symlink_to(self.directory, target_is_directory=True)
        except OSError:
            self.skipTest('symlink creation unavailable on this host')
        with self.assertRaisesRegex(pg.PersistenceError, 'input_invalid'):
            pg.prepare_import(self.store, alias)

    def test_noncanonical_import_directory(self):
        other = self.directory.with_name('renamed')
        self.directory.rename(other)
        with self.assertRaisesRegex(pg.PersistenceError, 'identity_mismatch'):
            pg.prepare_import(self.store, other)

    def test_json_duplicate_keys_and_nonfinite_rejected(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(pg.PersistenceError):
                pg.read_json(raw)

    def test_connection_error_is_redacted(self):
        out = io.StringIO()
        with patch.object(pg, 'open_connection', side_effect=RuntimeError('password=DO-NOT-PERSIST')), redirect_stdout(out):
            status = pg.cli(['migrate'])
        self.assertEqual(status, 2)
        self.assertNotIn('DO-NOT-PERSIST', out.getvalue())
        self.assertEqual(json.loads(out.getvalue())['error_code'], 'database_failed')

    def test_remote_tls_cannot_be_downgraded(self):
        class Driver:
            @staticmethod
            def connect(*args, **kwargs):
                return kwargs
        with patch.dict('sys.modules', {'psycopg': Driver}), patch.dict(os.environ, {
                'PGHOST': 'db.example.test', 'PGDATABASE': 'test', 'PGUSER': 'test',
                'PGSSLMODE': 'disable', 'PGSERVICE': '', 'PGHOSTADDR': ''}):
            self.assertEqual(pg.open_connection()['sslmode'], 'verify-full')
        with patch.dict('sys.modules', {'psycopg': Driver}), patch.dict(os.environ, {
                'PGHOST': 'localhost', 'PGDATABASE': 'test', 'PGUSER': 'test',
                'PGSERVICE': '', 'PGHOSTADDR': '192.0.2.1'}):
            self.assertEqual(pg.open_connection()['sslmode'], 'verify-full')


@unittest.skipUnless(os.environ.get('CANCA_TEST_POSTGRES') == '1', 'real PostgreSQL integration opt-in required')
class PostgreSQLTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store, self.directory = fixture(Path(self.temp.name))
        self.projection = pg.prepare_import(self.store, self.directory)
        self.conn = pg.open_connection()
        self.addCleanup(self.conn.close)
        self.assertGreaterEqual(self.conn.info.server_version, 160000)
        self.conn.execute('DROP SCHEMA IF EXISTS canca CASCADE')

    def counts(self):
        return tuple(self.conn.execute('SELECT count(*) FROM canca.' + table).fetchone()[0]
                     for table in ('assessments', 'nodes', 'runs', 'imports', 'artifacts'))

    def test_migration_replay_and_schema_drift(self):
        self.assertEqual(pg.migrate(self.conn)['status'], 'migrated')
        self.assertEqual(pg.migrate(self.conn)['status'], 'already_migrated')
        self.conn.execute("UPDATE canca.schema_migrations SET sha256='different'")
        with self.assertRaisesRegex(pg.PersistenceError, 'schema_mismatch'):
            pg.migrate(self.conn)
        with self.assertRaisesRegex(pg.PersistenceError, 'schema_mismatch'):
            pg.index_import(self.conn, self.projection)
        self.assertEqual(self.counts(), (0, 0, 0, 0, 0))

    def test_partial_migration_rolls_back(self):
        self.conn.execute('CREATE SCHEMA canca')
        self.conn.execute('CREATE TABLE canca.nodes (foreign_column integer)')
        with self.assertRaises(Exception):
            pg.migrate(self.conn)
        self.assertIsNone(self.conn.execute("SELECT to_regclass('canca.assessments')").fetchone()[0])
        self.assertIsNone(self.conn.execute("SELECT to_regclass('canca.schema_migrations')").fetchone()[0])
        self.assertIsNotNone(self.conn.execute("SELECT to_regclass('canca.nodes')").fetchone()[0])

    def test_missing_migration_blocks_index(self):
        with self.assertRaisesRegex(pg.PersistenceError, 'schema_required'):
            pg.index_import(self.conn, self.projection)

    def test_index_query_and_replay(self):
        pg.migrate(self.conn)
        self.assertEqual(pg.index_import(self.conn, self.projection)['status'], 'indexed')
        self.assertEqual(pg.index_import(self.conn, self.projection)['status'], 'already_indexed')
        result = pg.show_import(self.conn, self.projection['bundle_id'])
        self.assertEqual(result['artifacts'], self.projection['artifacts'])
        self.assertEqual(result['receipt_sha256'], self.projection['receipt_sha256'])
        self.assertEqual(self.counts(), (1, 1, 1, 1, 4))
        self.assertEqual(pg.show_import(self.conn, 'bnd-' + '0'*20)['status'], 'not_found')

    def test_conflicting_receipt_never_overwrites(self):
        pg.migrate(self.conn)
        pg.index_import(self.conn, self.projection)
        conflict = copy.deepcopy(self.projection)
        conflict['receipt_sha256'] = '0'*64
        with self.assertRaisesRegex(pg.PersistenceError, 'bundle_conflict'):
            pg.index_import(self.conn, conflict)
        self.assertEqual(pg.show_import(self.conn, conflict['bundle_id'])['receipt_sha256'], self.projection['receipt_sha256'])
        self.assertEqual(self.counts(), (1, 1, 1, 1, 4))

    def test_artifact_write_failure_rolls_back_entire_import(self):
        pg.migrate(self.conn)
        self.conn.execute("""CREATE FUNCTION canca.fail_artifact() RETURNS trigger LANGUAGE plpgsql AS
            $$ BEGIN RAISE EXCEPTION 'injected failure'; END $$""")
        self.conn.execute('CREATE TRIGGER reject_artifact BEFORE INSERT ON canca.artifacts FOR EACH ROW EXECUTE FUNCTION canca.fail_artifact()')
        with self.assertRaises(Exception):
            pg.index_import(self.conn, self.projection)
        self.assertEqual(self.counts(), (0, 0, 0, 0, 0))
        self.assertEqual(self.conn.info.transaction_status, 0)

    def test_concurrent_index_converges_to_one_import(self):
        pg.migrate(self.conn)
        barrier = threading.Barrier(2)
        def worker():
            with pg.open_connection() as conn:
                barrier.wait(timeout=10)
                return pg.index_import(conn, self.projection)['status']
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            jobs = [pool.submit(worker) for _ in range(2)]
            results = [job.result(timeout=40) for job in jobs]
        self.assertCountEqual(results, ['indexed', 'already_indexed'])
        self.assertEqual(self.counts(), (1, 1, 1, 1, 4))

    def test_concurrent_migration_converges(self):
        barrier = threading.Barrier(2)
        def worker():
            with pg.open_connection() as conn:
                barrier.wait(timeout=10)
                return pg.migrate(conn)['status']
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            jobs = [pool.submit(worker) for _ in range(2)]
            results = [job.result(timeout=40) for job in jobs]
        self.assertCountEqual(results, ['migrated', 'already_migrated'])
        self.assertEqual(self.counts(), (0, 0, 0, 0, 0))

    def test_caller_transaction_is_not_committed(self):
        self.conn.autocommit = False
        self.conn.execute('SELECT 1')
        with self.assertRaisesRegex(pg.PersistenceError, 'connection_not_idle'):
            pg.migrate(self.conn)
        self.assertNotEqual(self.conn.info.transaction_status, 0)
        self.conn.rollback()

    def test_indexer_role_can_index_and_read_without_schema_or_mutation_rights(self):
        pg.migrate(self.conn)
        if not self.conn.execute("SELECT 1 FROM pg_roles WHERE rolname='canca_test_indexer'").fetchone():
            self.conn.execute('CREATE ROLE canca_test_indexer NOLOGIN')
        self.conn.execute('GRANT USAGE ON SCHEMA canca TO canca_test_indexer')
        self.conn.execute('GRANT SELECT ON canca.schema_migrations TO canca_test_indexer')
        self.conn.execute('GRANT SELECT, INSERT ON canca.assessments,canca.nodes,canca.runs,canca.imports,canca.artifacts TO canca_test_indexer')
        self.conn.execute('SET ROLE canca_test_indexer')
        try:
            self.assertEqual(pg.index_import(self.conn, self.projection)['status'], 'indexed')
            self.assertEqual(pg.index_import(self.conn, self.projection)['status'], 'already_indexed')
            self.assertEqual(pg.show_import(self.conn, self.projection['bundle_id'])['status'], 'found')
            for sql in ('DELETE FROM canca.imports', "UPDATE canca.imports SET receipt_sha256='0'", 'CREATE TABLE canca.unauthorized (x int)'):
                with self.subTest(sql=sql), self.assertRaises(Exception):
                    self.conn.execute(sql)
        finally:
            self.conn.execute('RESET ROLE')


if __name__ == '__main__':
    unittest.main()
