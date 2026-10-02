"""Lifecycle contracts and real PostgreSQL transactions in disposable CI only."""
import concurrent.futures
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import test_postgresql as support
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'persistence'))
import P01_Assessment_Lifecycle as life
pg = life.pg


class BoundaryTests(unittest.TestCase):
    def test_invalid_commands_rejected_before_connect(self):
        command = ['transition', '--assessment-id', 'LAB-001', '--expected-revision', '0',
                   '--request-id', 'req-1', '--target-state', 'active', '--actor-ref', 'operator-1']
        for flag, value in (('--assessment-id', '../escape'), ('--expected-revision', '-1'),
                            ('--expected-revision', str(2**63)), ('--request-id', 'x' * 129),
                            ('--target-state', 'unknown'), ('--actor-ref', 'password=secret')):
            args = list(command)
            args[args.index(flag) + 1] = value
            out = io.StringIO()
            with self.subTest(flag=flag), patch.object(pg, 'open_connection') as connect, redirect_stdout(out):
                self.assertEqual(life.cli(args), 2)
                connect.assert_not_called()
                self.assertEqual(json.loads(out.getvalue())['error_code'], 'input_invalid')
        with patch.object(pg, 'open_connection') as connect, redirect_stdout(io.StringIO()):
            self.assertEqual(life.cli(['show', '--assessment-id', 'LAB-001', '--limit', '101']), 2)
            connect.assert_not_called()

    def test_unknown_driver_errors_are_redacted(self):
        out = io.StringIO()
        with patch.object(pg, 'open_connection', side_effect=RuntimeError('password=DO-NOT-LOG')), redirect_stdout(out):
            self.assertEqual(life.cli(['register', '--assessment-id', 'LAB-001']), 2)
        self.assertEqual(json.loads(out.getvalue())['error_code'], 'database_failed')
        self.assertNotIn('DO-NOT-LOG', out.getvalue())

    def test_known_conflict_remains_fixed_public_code(self):
        out = io.StringIO()
        with patch.object(pg, 'open_connection', side_effect=pg.PersistenceError('revision_conflict')), redirect_stdout(out):
            self.assertEqual(life.cli(['show', '--assessment-id', 'LAB-001']), 2)
        self.assertEqual(json.loads(out.getvalue())['error_code'], 'revision_conflict')

    def test_internal_api_rejects_bool_and_unbounded_read(self):
        with self.assertRaisesRegex(pg.PersistenceError, 'input_invalid'):
            life.transition(None, 'LAB-001', True, 'req', 'active', 'operator')
        with self.assertRaisesRegex(pg.PersistenceError, 'input_invalid'):
            life.show_assessment(None, 'LAB-001', limit=0)


@unittest.skipUnless(os.environ.get('CANCA_TEST_POSTGRES') == '1', 'real PostgreSQL integration opt-in required')
class PostgreSQLLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store, self.directory = support.fixture(Path(self.temp.name))
        self.projection = pg.prepare_import(self.store, self.directory)
        self.conn = pg.open_connection()
        self.addCleanup(self.conn.close)
        self.conn.execute('DROP SCHEMA IF EXISTS canca CASCADE')
        pg.migrate(self.conn)

    def register(self, aid='LAB-001'):
        return life.register_assessment(self.conn, aid)

    def change(self, rev, target, request=None, aid='LAB-001', actor='operator-1'):
        return life.transition(self.conn, aid, rev, request or f'req-{rev}', target, actor)

    def state(self, aid='LAB-001'):
        return life.show_assessment(self.conn, aid)

    def legacy_schema(self):
        self.conn.execute('DROP SCHEMA canca CASCADE')
        self.conn.execute('CREATE SCHEMA canca')
        self.conn.execute('CREATE TABLE canca.schema_migrations (version integer PRIMARY KEY, sha256 text NOT NULL)')
        self.conn.execute(pg.SQL_PATH.read_text())
        self.conn.execute('INSERT INTO canca.schema_migrations VALUES (1,%s)', (pg.digest(pg.SQL_PATH.read_bytes()),))

    def test_upgrade_preserves_existing_import_and_neutral_backfill(self):
        self.legacy_schema()
        pg.index_import(self.conn, self.projection)
        before = pg.show_import(self.conn, self.projection['bundle_id'])
        files = {str(p): pg.digest(p.read_bytes()) for p in self.store.rglob('*') if p.is_file()}
        self.assertEqual(pg.migrate(self.conn)['migration'], len(pg.MIGRATIONS))
        self.assertEqual(pg.show_import(self.conn, self.projection['bundle_id']), before)
        self.assertEqual((self.state()['state'], self.state()['revision'], self.state()['events']), ('registered', 0, []))
        self.assertEqual(pg.index_import(self.conn, self.projection)['status'], 'already_indexed')
        self.assertEqual(files, {str(p): pg.digest(p.read_bytes()) for p in self.store.rglob('*') if p.is_file()})

    def test_legacy_index_works_but_lifecycle_requires_explicit_migration(self):
        self.legacy_schema()
        self.assertEqual(pg.index_import(self.conn, self.projection)['status'], 'indexed')
        with self.assertRaisesRegex(pg.PersistenceError, 'schema_required'):
            self.state()
        self.assertEqual(self.conn.execute('SELECT version FROM canca.schema_migrations').fetchall(), [(1,)])

    def test_failed_upgrade_is_atomic(self):
        self.legacy_schema()
        self.conn.execute('CREATE TABLE canca.assessment_events (foreign_column integer)')
        with self.assertRaises(Exception):
            pg.migrate(self.conn)
        self.assertEqual(self.conn.execute('SELECT version FROM canca.schema_migrations').fetchall(), [(1,)])
        self.assertEqual(self.conn.execute("SELECT column_name FROM information_schema.columns WHERE table_schema='canca' AND table_name='assessments'").fetchall(), [('assessment_id',)])

    def test_unknown_versions_gaps_and_checksum_drift_fail_closed(self):
        for mutate in ("UPDATE canca.schema_migrations SET sha256='bad' WHERE version=2",
                       "DELETE FROM canca.schema_migrations WHERE version=1",
                       "INSERT INTO canca.schema_migrations VALUES (5,'unknown')"):
            with self.subTest(mutate=mutate):
                self.conn.execute(mutate)
                with self.assertRaisesRegex(pg.PersistenceError, 'schema_mismatch'):
                    pg.migrate(self.conn)
                with self.assertRaisesRegex(pg.PersistenceError, 'schema_mismatch'):
                    self.register()
                self.conn.execute('DROP SCHEMA canca CASCADE')
                pg.migrate(self.conn)

    def test_allowed_paths_and_terminal_guards(self):
        for aid, path in (('A', ['active', 'review_required', 'active', 'completed']),
                          ('B', ['cancelled']), ('C', ['active', 'cancelled']),
                          ('D', ['active', 'review_required', 'cancelled'])):
            self.register(aid)
            for rev, target in enumerate(path):
                self.assertEqual(self.change(rev, target, aid=aid)['status'], 'applied')
            prior = self.state(aid)
            with self.assertRaisesRegex(pg.PersistenceError, 'transition_invalid'):
                self.change(len(path), 'active', aid=aid)
            self.assertEqual(self.state(aid), prior)
            self.assertEqual(self.register(aid)['status'], 'already_registered')
            self.assertEqual(self.state(aid), prior)

    def test_invalid_transition_stale_revision_and_missing_record_do_not_mutate(self):
        self.register()
        with self.assertRaisesRegex(pg.PersistenceError, 'transition_invalid'):
            self.change(0, 'completed')
        with self.assertRaisesRegex(pg.PersistenceError, 'revision_conflict'):
            self.change(1, 'active')
        with self.assertRaisesRegex(pg.PersistenceError, 'assessment_not_found'):
            self.change(0, 'active', aid='missing')
        self.assertEqual(self.state()['events'], [])

    def test_replay_returns_original_receipt_after_subsequent_change(self):
        self.register()
        original = self.change(0, 'active', 'start')
        self.change(1, 'completed', 'finish')
        replay = self.change(0, 'active', 'start')
        self.assertEqual(replay['status'], 'already_applied')
        self.assertEqual(replay['event'], original['event'])
        self.assertEqual(self.state()['state'], 'completed')
        for rev, target, actor in ((1, 'active', 'operator-1'), (0, 'cancelled', 'operator-1'), (0, 'active', 'operator-2')):
            with self.assertRaisesRegex(pg.PersistenceError, 'request_conflict'):
                self.change(rev, target, 'start', actor=actor)
        self.assertEqual(len(self.state()['events']), 2)

    def concurrent(self, requests, expected=0, target='active', aid='LAB-001'):
        barrier = threading.Barrier(len(requests))
        def invoke(request):
            with pg.open_connection() as conn:
                barrier.wait(timeout=10)
                try:
                    return life.transition(conn, aid, expected, request, target, 'operator-1')['status']
                except pg.PersistenceError as exc:
                    return str(exc)
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(requests)) as pool:
            return list(pool.map(invoke, requests))

    def test_concurrent_same_revision_has_one_winner(self):
        self.register()
        self.assertCountEqual(self.concurrent(['one', 'two']), ['applied', 'revision_conflict'])
        self.assertEqual(self.state()['revision'], 1)
        self.assertEqual(len(self.state()['events']), 1)

    def test_concurrent_identical_request_is_idempotent(self):
        self.register()
        self.assertCountEqual(self.concurrent(['same', 'same']), ['applied', 'already_applied'])
        self.assertEqual(len(self.state()['events']), 1)

    def test_event_failure_rolls_back_state_and_revision(self):
        self.register()
        self.conn.execute("CREATE FUNCTION canca.fail_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic failure'; END $$")
        self.conn.execute('CREATE TRIGGER fail_event BEFORE INSERT ON canca.assessment_events FOR EACH ROW EXECUTE FUNCTION canca.fail_event()')
        with self.assertRaises(Exception):
            self.change(0, 'active')
        self.assertEqual((self.state()['state'], self.state()['revision'], self.state()['events']), ('registered', 0, []))
        self.conn.execute('DROP TRIGGER fail_event ON canca.assessment_events')
        self.assertEqual(self.change(0, 'active')['status'], 'applied')

    def test_import_does_not_change_terminal_state_or_events(self):
        self.register()
        self.change(0, 'cancelled')
        before = self.state()
        self.assertEqual(pg.index_import(self.conn, self.projection)['status'], 'indexed')
        self.assertEqual(self.state(), before)

    def test_new_import_does_not_start_or_complete_assessment(self):
        pg.index_import(self.conn, self.projection)
        self.assertEqual((self.state()['state'], self.state()['revision'], self.state()['events']), ('registered', 0, []))

    def test_read_only_consistent_pagination_and_missing_record(self):
        self.register()
        self.change(0, 'active')
        self.change(1, 'review_required')
        self.change(2, 'active')
        first = life.show_assessment(self.conn, 'LAB-001', limit=2)
        second = life.show_assessment(self.conn, 'LAB-001', after_revision=first['next_after_revision'], limit=2)
        self.assertTrue(first['has_more'])
        self.assertFalse(second['has_more'])
        self.assertEqual([e['revision'] for e in first['events'] + second['events']], [1, 2, 3])
        self.assertEqual(first['revision'], 3)
        self.assertEqual(life.show_assessment(self.conn, 'missing')['status'], 'not_found')
        self.assertEqual(self.conn.execute('SELECT count(*) FROM canca.assessments').fetchone()[0], 1)

    def test_operator_role_can_transition_but_cannot_rewrite_history(self):
        self.register()
        self.conn.execute("DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='canca_test_lifecycle') THEN CREATE ROLE canca_test_lifecycle; END IF; END $$")
        self.conn.execute('GRANT USAGE ON SCHEMA canca TO canca_test_lifecycle')
        self.conn.execute('GRANT SELECT ON canca.schema_migrations,canca.assessments,canca.assessment_events TO canca_test_lifecycle')
        self.conn.execute('GRANT INSERT (assessment_id),UPDATE (lifecycle_state,lifecycle_revision) ON canca.assessments TO canca_test_lifecycle')
        self.conn.execute('GRANT INSERT ON canca.assessment_events TO canca_test_lifecycle')
        self.conn.execute('SET ROLE canca_test_lifecycle')
        try:
            self.assertEqual(self.change(0, 'active')['status'], 'applied')
            self.assertEqual(self.state()['revision'], 1)
            for sql in ("UPDATE canca.assessment_events SET actor_ref='tampered'", 'DELETE FROM canca.assessment_events',
                        'DELETE FROM canca.assessments', 'CREATE TABLE canca.unwanted (id integer)'):
                with self.assertRaises(Exception):
                    self.conn.execute(sql)
        finally:
            self.conn.execute('RESET ROLE')
        self.assertEqual(self.state()['events'][0]['actor_ref'], 'operator-1')

    def test_database_constraint_rejects_fabricated_transition(self):
        self.register()
        with self.assertRaises(Exception):
            self.conn.execute("INSERT INTO canca.assessment_events (assessment_id,revision,request_id,actor_ref,from_state,to_state,reason_code) VALUES ('LAB-001',1,'bad','operator','registered','completed','operator_complete')")
        self.assertEqual(self.state()['events'], [])

    def test_database_failure_returns_fixed_error_without_secrets(self):
        out = io.StringIO()
        with patch.dict(os.environ, {'PGPORT': '1'}), redirect_stdout(out):
            self.assertEqual(life.cli(['register', '--assessment-id', 'LAB-001']), 2)
        self.assertEqual(json.loads(out.getvalue())['error_code'], 'database_failed')
        self.assertNotIn(os.environ.get('PGPASSWORD', 'synthetic-ci-only'), out.getvalue())
