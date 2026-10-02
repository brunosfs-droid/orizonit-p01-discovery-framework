import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


recovery = module('recovery_test', 'docs/validation/POSTGRESQL_LAB_RECOVERY_R1_v0.6.7.py')
fixture = module('recovery_fixture', 'docs/validation/POSTGRESQL_LAB_FIXTURE_R1_v0.6.5.py')
pg = recovery.pg


class RecoveryBoundaryTests(unittest.TestCase):
    def test_wrong_database_and_bad_reference_fail_before_connection(self):
        with tempfile.TemporaryDirectory() as temp:
            path = recovery.save_snapshot(dict(verification_version=recovery.VERSION,
                                              scope='isolated_synthetic_lab_r1'), temp)
            path.write_bytes(path.read_bytes() + b' ')
            with patch.dict(os.environ, {'PGDATABASE': 'canca_p01_restore_r1'}), \
                    patch.object(pg, 'open_connection') as conn, redirect_stdout(io.StringIO()):
                base = ['verify', '--store-dir', temp, '--reference', str(path)]
                for database in ('canca_p01_lab_r1', '../bad', 'canca_p01_restore_r1'):
                    self.assertEqual(recovery.cli(base + ['--expected-database', database]), 2)
                conn.assert_not_called()

    def test_inventory_refuses_symlinks_and_limit_without_truncation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / 'file').write_bytes(b'original')
            (root / 'alias').symlink_to(root / 'file')
            with self.assertRaisesRegex(recovery.RecoveryError, 'recovery_invalid'):
                recovery.inventory(root)
            (root / 'alias').unlink()
            with patch.object(recovery, 'MAX_FILE_BYTES', 3):
                with self.assertRaisesRegex(recovery.RecoveryError, 'recovery_limit'):
                    recovery.inventory(root)
            self.assertEqual((root / 'file').read_bytes(), b'original')

    def test_driver_error_is_redacted_and_capture_does_not_write_output(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {'PGDATABASE':'canca_p01_lab_r1'}), \
                patch.object(pg, 'open_connection', side_effect=RuntimeError('password=NEVER-LOG')):
            out = io.StringIO()
            with redirect_stdout(out):
                code = recovery.cli(['capture', '--store-dir', temp, '--expected-database',
                                     'canca_p01_lab_r1', '--evidence-root', temp])
            self.assertEqual(code, 2)
            self.assertNotIn('NEVER-LOG', out.getvalue())
            self.assertEqual(list(Path(temp).iterdir()), [])


@unittest.skipUnless(os.environ.get('CANCA_TEST_POSTGRES') == '1', 'real PostgreSQL integration opt-in required')
class PostgreSQLRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.conn = pg.open_connection(); self.addCleanup(self.conn.close)
        self.conn.execute('DROP SCHEMA IF EXISTS canca CASCADE'); pg.migrate(self.conn)
        self.prepared = fixture.prepare(self.base / 'fixture')
        self.store = Path(self.prepared['store_dir'])
        for item in self.prepared['imports']:
            directory = Path(item['import_dir'])
            pg.index_import(self.conn, pg.prepare_import(self.store, directory))
            recovery.assets.project_import(self.conn, recovery.assets.prepare_assets(self.store, directory))
            recovery.findings.project_import(self.conn, recovery.findings.prepare_findings(self.store, directory))

    def capture(self, store=None, database='canca_ci'):
        return recovery.capture(self.conn, store or self.store, database)

    def test_capture_same_bytes_in_new_path_verify_without_mutation(self):
        doc = self.capture()
        before = recovery.inventory(self.store)
        path = recovery.save_snapshot(doc, self.base / 'evidence')
        clone = self.base / 'restored-store'; shutil.copytree(self.store, clone)
        self.assertEqual(recovery.verify(self.conn, clone, 'canca_ci', path)['tables_compared'], 14)
        self.assertEqual(self.capture(), doc)
        self.assertEqual(recovery.inventory(self.store), before)
        self.assertEqual(recovery.inventory(clone), before)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)

    def test_wrong_database_extra_assessment_and_missing_projection_rejected(self):
        with self.assertRaisesRegex(recovery.RecoveryError, 'recovery_invalid'):
            self.capture(database='canca_p01_lab_r1')
        self.conn.execute("INSERT INTO canca.assessments (assessment_id) VALUES ('OTHER')")
        with self.assertRaisesRegex(recovery.RecoveryError, 'recovery_invalid'):
            self.capture()
        self.conn.execute("DELETE FROM canca.assessments WHERE assessment_id='OTHER'")
        self.conn.execute('TRUNCATE canca.finding_analyses CASCADE')
        with self.assertRaisesRegex(recovery.RecoveryError, 'recovery_invalid'):
            self.capture()

    def test_source_or_projection_drift_is_rejected(self):
        imported = Path(self.prepared['imports'][0]['import_dir'])
        receipt = imported / 'receipt/import-receipt.json'
        original = receipt.read_bytes(); receipt.write_bytes(original + b' ')
        with self.assertRaisesRegex(pg.PersistenceError, 'receipt_integrity_failed'):
            self.capture()
        receipt.write_bytes(original)
        self.conn.execute("UPDATE canca.asset_imports SET projection_sha256=%s", ('0' * 64,))
        with self.assertRaisesRegex(recovery.RecoveryError, 'recovery_mismatch'):
            self.capture()

    def test_bounds_and_logical_change_reject_entire_comparison(self):
        doc = self.capture(); path = recovery.save_snapshot(doc, self.base / 'evidence')
        with patch.object(recovery, 'MAX_ROWS', 1):
            with self.assertRaisesRegex(recovery.RecoveryError, 'recovery_limit'):
                self.capture()
        self.conn.execute("UPDATE canca.assessments SET lifecycle_state='active',lifecycle_revision=1")
        with self.assertRaisesRegex(recovery.RecoveryError, 'recovery_mismatch'):
            recovery.verify(self.conn, self.store, 'canca_ci', path)

    def test_full_select_only_role_can_capture_and_dml_still_denied(self):
        role = 'canca_recovery_ci_reader'
        self.conn.execute('DROP ROLE IF EXISTS ' + role)
        self.conn.execute('CREATE ROLE ' + role)
        self.addCleanup(lambda: self.conn.execute('DROP ROLE IF EXISTS ' + role))
        # DROP OWNED removes only this dedicated test role's grants, before role cleanup.
        self.addCleanup(lambda: self.conn.execute('DROP OWNED BY ' + role))
        self.conn.execute('GRANT USAGE ON SCHEMA canca TO ' + role)
        self.conn.execute('GRANT SELECT ON ALL TABLES IN SCHEMA canca TO ' + role)
        expected = self.capture()
        self.conn.execute('SET ROLE ' + role)
        try:
            self.assertEqual(self.capture(), expected)
            with self.assertRaises(Exception):
                self.conn.execute("UPDATE canca.findings SET status='Open'")
        finally:
            self.conn.execute('RESET ROLE')
