"""Opt-in schema8 fence and restore metadata; never invoke Docker from unit tests."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'persistence'))
import P01_Workspace_Recovery as recovery
import test_workspace_model as models
pg,ws,runtime,model=recovery.pg,recovery.ws,recovery.runtime,recovery.model

class RecoveryInputTests(unittest.TestCase):
    def test_prefixes_stay_explicit_and_previous_checksums_unchanged(self):
        self.assertEqual(len(pg.migration_prefix([],model=True)),7)
        self.assertEqual(len(pg.migration_prefix([],recovery=True)),8)
        old=pg.migration_prefix([],model=True)
        self.assertEqual(pg.migration_prefix(old,recovery=True)[:7],old)
        with self.assertRaisesRegex(pg.PersistenceError,'schema_mismatch'):
            pg.migration_prefix(pg.migration_prefix([],recovery=True),model=True)
    def test_invalid_generation_rejected_before_sql(self):
        conn=Mock()
        for generation in (True,-1,'1',None):
            with self.assertRaises(pg.PersistenceError):recovery.prepare_restored(conn,generation)
        conn.execute.assert_not_called()
    def test_cli_redacts_connection_failures_and_invalid_input(self):
        with patch.object(pg,'open_connection',side_effect=RuntimeError('password=PRIVATE')),redirect_stdout(io.StringIO()) as output:
            self.assertEqual(recovery.cli(['inspect']),2)
        self.assertNotIn('PRIVATE',output.getvalue())
        with patch.object(pg,'open_connection') as connect,redirect_stdout(io.StringIO()):
            self.assertEqual(recovery.cli(['prepare-restored','--expected-generation','-1']),2)
        connect.assert_not_called()

@unittest.skipUnless(os.environ.get('CANCA_TEST_WORKSPACE_POSTGRES')=='1','workspace SQL opt-in required')
class RecoveryPostgreSQLTests(unittest.TestCase):
    legacy_rows=models.ModelPostgreSQLTests.legacy_rows
    role=models.ModelPostgreSQLTests.role
    create=models.ModelPostgreSQLTests.create
    def setUp(self):
        models.ModelPostgreSQLTests.setUp(self)
        self.create('before',attributes={'description':'Before restore'})
        self.old_token=self.token
        self.c.shutdown(timeout=0)
        self.assertEqual(pg.migrate(self.conn,recovery=True)['migration'],8)
        self.generation=self.conn.execute('SELECT generation FROM canca.workspace_runtime').fetchone()[0]
    def restart(self):
        control=pg.open_connection();self.addCleanup(control.close);control.execute('SET ROLE canca_ws_coordinator')
        self.c=runtime.Coordinator(runtime.SessionLease(control),heartbeat_seconds=30);self.c.start()
        self.addCleanup(lambda:self.c.shutdown(timeout=0) if not self.c._terminated else None)
        with self.role('canca_ws_writer'):self.token=self.c.open(self.conn,'A',self.c.generation)
    def test_reset_preserves_content_and_next_write_increments_revision(self):
        before=self.conn.execute('SELECT to_jsonb(t)::text FROM canca.workspace_objects t').fetchall()
        revision=self.conn.execute("SELECT revision,last_txid FROM canca.workspace_revisions WHERE workspace_id='A'").fetchone()
        self.assertIsNotNone(revision[1])
        result=recovery.prepare_restored(self.conn,self.generation)
        self.assertEqual(result['generation'],self.generation+1)
        self.assertEqual(self.conn.execute('SELECT to_jsonb(t)::text FROM canca.workspace_objects t').fetchall(),before)
        self.assertEqual(self.conn.execute("SELECT revision,last_txid FROM canca.workspace_revisions WHERE workspace_id='A'").fetchone(),(revision[0],None))
        self.assertEqual(self.conn.execute('SELECT state,workspace_id,lease_id,lease_pid FROM canca.workspace_runtime').fetchone(),('closed',None,None,None))
        self.restart()
        self.create('after')
        self.assertEqual(self.revision,revision[0]+1)
    def test_stale_confirmation_and_live_coordinator_cannot_reset_metadata(self):
        before=self.conn.execute('SELECT to_jsonb(t)::text FROM canca.workspace_runtime t').fetchall()
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_restore_stale'):
            recovery.prepare_restored(self.conn,self.generation+1)
        self.assertEqual(self.conn.execute('SELECT to_jsonb(t)::text FROM canca.workspace_runtime t').fetchall(),before)
        self.restart()
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_restore_busy'):
            recovery.prepare_restored(self.conn,self.c.generation)
        with self.role('canca_ws_writer'):
            self.assertEqual(model.list_objects(self.conn,'A',self.token)['objects'][0]['object_id'],'before')
    def test_actor_cannot_inspect_or_reset_maintenance_metadata(self):
        with self.role('canca_ws_writer'):
            for call in (lambda:recovery.inspect(self.conn),lambda:recovery.prepare_restored(self.conn,self.generation)):
                with self.assertRaisesRegex(pg.PersistenceError,'workspace_admin_required'):call()
    def test_old_token_never_resumes_and_private_function_acl_is_preserved(self):
        from psycopg.errors import InsufficientPrivilege
        recovery.prepare_restored(self.conn,self.generation);self.restart()
        with self.role('canca_ws_writer'):
            with self.assertRaisesRegex(pg.PersistenceError,'model_context_denied'):
                model.list_objects(self.conn,'A',self.old_token)
            with self.assertRaises(InsufficientPrivilege):self.conn.execute('SELECT canca.workspace_active_fence()')
        with self.role('canca_ws_b'):
            with self.assertRaisesRegex(pg.PersistenceError,'model_context_denied'):
                model.list_objects(self.conn,'B',runtime.Token('B',self.token.generation,self.token.lease_id))
    def test_restored_runtime_cannot_borrow_other_database_session_lock(self):
        import psycopg
        foreign=psycopg.connect('',host=os.environ['PGHOST'],port=int(os.environ.get('PGPORT','5432')),
            user=os.environ['PGUSER'],dbname='postgres',connect_timeout=5,autocommit=True)
        self.addCleanup(foreign.close)
        self.assertTrue(foreign.execute('SELECT pg_try_advisory_lock(%s)',(runtime.LOCK_KEY,)).fetchone()[0])
        pid=foreign.execute('SELECT pg_backend_pid()').fetchone()[0]
        self.conn.execute("UPDATE canca.workspace_runtime SET state='open',workspace_id='A',generation=%s,lease_id=%s,lease_pid=%s",
                          (self.old_token.generation,self.old_token.lease_id,pid))
        with self.role('canca_ws_writer'):
            with self.assertRaisesRegex(pg.PersistenceError,'model_context_denied'):
                model.list_objects(self.conn,'A',self.old_token)
    def test_schema8_requires_explicit_migration_prefix(self):
        self.assertEqual(pg.migrate(self.conn,recovery=True)['status'],'already_migrated')
        with self.assertRaisesRegex(pg.PersistenceError,'schema_mismatch'):pg.migrate(self.conn,model=True)
        self.assertEqual(recovery.inspect(self.conn)['state'],'closed')

@unittest.skipUnless(os.environ.get('CANCA_TEST_WORKSPACE_POSTGRES')=='1','workspace SQL opt-in required')
class RecoveryUpgradePostgreSQLTests(unittest.TestCase):
    setUp=models.ModelPostgreSQLTests.setUp
    legacy_rows=models.ModelPostgreSQLTests.legacy_rows
    role=models.ModelPostgreSQLTests.role
    def test_upgrade8_refuses_live_coordinator_and_then_replays_safely(self):
        from psycopg.errors import ObjectInUse
        before=self.legacy_rows()
        with self.assertRaises(ObjectInUse):pg.migrate(self.conn,recovery=True)
        self.assertEqual(self.conn.execute('SELECT max(version) FROM canca.schema_migrations').fetchone()[0],7)
        with self.role('canca_ws_writer'):self.assertEqual(model.list_objects(self.conn,'A',self.token)['objects'],[])
        self.c.shutdown(timeout=0)
        self.assertEqual(pg.migrate(self.conn,recovery=True)['migration'],8)
        self.assertEqual(self.legacy_rows(),before)
        self.assertEqual(pg.migrate(self.conn,recovery=True)['status'],'already_migrated')
