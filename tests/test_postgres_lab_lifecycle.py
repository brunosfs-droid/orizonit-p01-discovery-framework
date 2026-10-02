import io
import os
from pathlib import Path
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
import test_postgres_recovery as recovery_fixture

helper = recovery_fixture.module('lab_lifecycle_test', 'docs/validation/POSTGRESQL_LAB_LIFECYCLE_R1_v0.6.8.py')


class LifecycleLabBoundaryTests(unittest.TestCase):
    def test_source_database_missing_ack_and_reference_fail_before_connection(self):
        base = ['exercise', '--store-dir', '/not-used', '--reference', '/not-used', '--evidence-root', '/not-used-evidence']
        with patch.dict(os.environ, {'PGDATABASE': helper.DATABASE}), patch.object(helper.pg, 'open_connection') as connect:
            for database, extra in [('canca_p01_lab_r1', ['--ack-lifecycle-test']), (helper.DATABASE, []),
                                    (helper.DATABASE, ['--ack-lifecycle-test'])]:
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(helper.cli(base + ['--expected-database', database] + extra), 2)
            connect.assert_not_called()
            with patch.object(helper.recovery, 'load_snapshot'):
                for output in ('/not-used', '/not-used/nested'):
                    with redirect_stdout(io.StringIO()):
                        self.assertEqual(helper.cli(base + ['--expected-database', helper.DATABASE,
                                             '--ack-lifecycle-test', '--evidence-root', output]), 2)
                connect.assert_not_called()

    def test_driver_exception_is_redacted(self):
        with patch.dict(os.environ, {'PGDATABASE': helper.DATABASE}), patch.object(helper.recovery, 'load_snapshot'), \
                patch.object(helper.pg, 'open_connection', side_effect=RuntimeError('password=NEVER-LOG')):
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(helper.cli(['inspect', '--expected-database', helper.DATABASE, '--store-dir', '/unused',
                                             '--reference', '/unused', '--evidence-root', '/unused-evidence']), 2)
            self.assertNotIn('NEVER-LOG', out.getvalue())


@unittest.skipUnless(os.environ.get('CANCA_TEST_POSTGRES') == '1', 'real PostgreSQL integration opt-in required')
class PostgreSQLLabLifecycleTests(unittest.TestCase):
    # Reuse only fixture setup, not the other class's tests (which discover independently).
    setUp = recovery_fixture.PostgreSQLRecoveryTests.setUp

    def reference(self):
        doc = helper.recovery.capture(self.conn, self.store, 'canca_ci')
        return helper.recovery.save_snapshot(doc, self.base / 'reference')

    def run_helper(self, reference, exercise=False):
        return helper.run(self.conn, self.store, 'canca_ci', reference, exercise)

    def test_inspect_is_readonly_then_exercise_and_completed_replay(self):
        reference = self.reference()
        before = helper.recovery.capture(self.conn, self.store, 'canca_ci')
        read = self.run_helper(reference)
        self.assertEqual((read['report_pages'], read['revision'], read['transitions_applied']), (4, 0, 0))
        self.assertEqual(read['snapshot'], before)
        first = self.run_helper(reference, True)
        self.assertEqual((first['revision'], first['stale_cursor_rejections'], first['idempotent_replays']), (4, 4, 4))
        repeat = self.run_helper(reference, True)
        self.assertFalse(repeat['administrative_lifecycle_mutated'])
        self.assertEqual(repeat['transitions_applied'], 0)
        self.assertEqual(repeat['snapshot'], first['snapshot'])

    def test_committed_prefix_resumes_without_duplicate_events(self):
        reference = self.reference()
        for i in range(2):
            helper.life.transition(self.conn, helper.AID, i, helper.REQUESTS[i], helper.STATES[i + 1], helper.ACTOR)
        result = self.run_helper(reference, True)
        self.assertEqual((result['initial_revision'], result['transitions_applied'], result['stale_cursor_rejections']), (2, 2, 2))
        self.assertEqual(len(helper.history(self.conn)['events']), 4)

    def test_other_history_and_source_drift_fail_before_lifecycle_write(self):
        reference = self.reference()
        helper.life.transition(self.conn, helper.AID, 0, 'OTHER-request', 'active', 'OTHER')
        before = helper.recovery.capture(self.conn, self.store, 'canca_ci')
        with self.assertRaisesRegex(helper.recovery.RecoveryError, 'lifecycle_lab_mismatch'):
            self.run_helper(reference, True)
        self.assertEqual(helper.recovery.capture(self.conn, self.store, 'canca_ci'), before)
        imported = Path(self.prepared['imports'][0]['import_dir'])
        receipt = imported / 'receipt/import-receipt.json'
        receipt.write_bytes(receipt.read_bytes() + b' ')
        with self.assertRaisesRegex(helper.pg.PersistenceError, 'receipt_integrity_failed'):
            self.run_helper(reference, True)
        self.assertEqual(helper.life.show_assessment(self.conn, helper.AID)['revision'], 1)

    def test_page_duplicates_and_projection_drift_are_rejected(self):
        reference = self.reference()
        real = helper.report.show_assessment
        def bad_page(*args, **kwargs):
            doc = real(*args, **kwargs)
            if kwargs.get('after_analysis_id'):
                doc['evaluations'] = real(self.conn, helper.AID, limit=1)['evaluations']
            return doc
        with patch.object(helper.report, 'show_assessment', side_effect=bad_page):
            with self.assertRaisesRegex(helper.recovery.RecoveryError, 'lifecycle_lab_mismatch'):
                self.run_helper(reference, True)
        self.assertEqual(helper.history(self.conn)['revision'], 0)
        self.conn.execute("UPDATE canca.findings SET evidence='{}'")
        with self.assertRaisesRegex(helper.recovery.RecoveryError, 'lifecycle_lab_mismatch'):
            self.run_helper(reference, True)
        self.assertEqual(helper.history(self.conn)['revision'], 0)
