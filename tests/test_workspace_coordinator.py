"""Lifecycle races and real PostgreSQL session lease fencing; no live network scan."""
from contextlib import contextmanager, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server'))
import P01_Workspace_Coordinator as runtime
import test_postgres_workspace as foundation

pg, ws = runtime.pg, runtime.ws


class MemoryLease:
    """Deterministic fault injection only; SQL semantics are tested separately."""
    def __init__(self):
        self.target = ('test',5432,'test')
        self.lease_id = 'test-epoch'; self.generation = 0; self.lost = False; self.stopped = False
    def start(self): self.generation += 1; return self.generation
    def check(self, generation):
        pg.require(not self.lost and generation == self.generation, 'workspace_lease_lost')
    def transition(self, generation, state, workspace_id):
        self.check(generation); self.generation += 1; return self.generation
    def stop(self, generation): self.stopped = True


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.grants = {'reader': {('A','workspace:read')},
                       'writer': {(x,p) for x in ('A','B') for p in ws.PERMISSIONS}}
        def authorize(actor, workspace_id, permission, target):
            pg.require((workspace_id,permission) in self.grants.get(actor,set()), 'workspace_access_denied')
        self.lease = MemoryLease()
        self.c = runtime.Coordinator(self.lease,authorizer=authorize,heartbeat_seconds=30,
                                     max_jobs=2,max_cache_entries=2,max_cache_bytes=8,max_entry_bytes=6)
        self.c.start(); self.addCleanup(self.cleanup)
    def cleanup(self):
        self.assertFalse(self.c._jobs, 'test leaked a job')
        self.c.shutdown(timeout=0)
    def opened(self, workspace_id='A'):
        return self.c.open('writer',workspace_id,self.c.generation)

    def test_second_workspace_is_busy_and_same_open_is_idempotent(self):
        a=self.opened()
        self.assertEqual(a,self.c.open('reader','A',a.generation))
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_runtime_busy'): self.opened('B')
        self.assertEqual(self.c.workspace_id,'A')

    def test_open_race_admits_exactly_one_generation(self):
        barrier=threading.Barrier(3); replies=[]; generation=self.c.generation
        def request(workspace_id):
            barrier.wait()
            try: replies.append(self.c.open('writer',workspace_id,generation))
            except pg.PersistenceError as exc: replies.append(str(exc))
        threads=[threading.Thread(target=request,args=(w,)) for w in ('A','B')]
        for t in threads:t.start()
        barrier.wait()
        for t in threads:t.join(2); self.assertFalse(t.is_alive())
        self.assertEqual(sum(type(x) is runtime.Token for x in replies),1)
        self.assertIn('workspace_generation_stale',replies)

    def test_closed_generation_and_forged_token_never_admit_jobs(self):
        a=self.opened(); fake=runtime.Token('B',a.generation,a.lease_id)
        for token in (fake,runtime.Token('A',a.generation,'other')):
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_generation_stale'):
                with self.c.borrow('writer',token):pass
        self.c.close('writer','A',a.generation)
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_generation_stale'):
            with self.c.borrow('writer',a):pass

    def test_denied_snapshot_does_not_reveal_workspace_metadata(self):
        self.opened('B')
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_access_denied'):self.c.snapshot('reader')
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_access_denied'):self.c.open('reader','B',self.c.generation)

    def test_read_grant_cannot_close_workspace(self):
        a=self.opened()
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_access_denied'):self.c.close('reader','A',a.generation)
        self.assertEqual(self.c.state,'open')

    def test_job_and_cache_limits_reject_without_losing_old_value(self):
        a=self.opened()
        with self.c.borrow('writer',a) as one, self.c.borrow('reader',a):
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_jobs_full'):
                with self.c.borrow('writer',a):pass
            one.cache_put('x',b'12345'); one.cache_put('y',b'123')
            for key,value in (('x',b'1234567'),('z',b''),('y',b'1234')):
                with self.assertRaisesRegex(pg.PersistenceError,'workspace_cache_full'):one.cache_put(key,value)
            self.assertEqual(one.cache_get('x'),b'12345');self.assertEqual(self.c._bytes,8)
            one.cache_put('x',b'1');self.assertEqual(self.c._bytes,4)

    def test_operation_cannot_be_reused_after_exit(self):
        a=self.opened()
        with self.c.borrow('writer',a) as job:job.check()
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_generation_stale'):job.check()
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_generation_stale'):job.cache_put('late',b'x')

    def test_revoked_grant_blocks_existing_job_and_cache_delivery(self):
        a=self.opened()
        with self.c.borrow('reader',a) as job:
            job.cache_put('x',b'data');self.grants['reader'].clear()
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_access_denied'):job.check()
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_access_denied'):job.cache_get('x')

    def test_close_timeout_keeps_closing_and_lease_until_jobs_exit(self):
        a=self.opened()
        with self.c.borrow('writer',a) as job:
            job.cache_put('x',b'data')
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_close_pending'):self.c.close('writer','A',a.generation,timeout=0)
            self.assertEqual(self.c.state,'closing');self.assertTrue(job.cancel.is_set())
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_generation_stale'):job.check()
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_runtime_busy'):self.opened('B')
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_close_pending'):self.c.shutdown(timeout=0)
            self.assertFalse(self.lease.stopped)
        self.c.close('writer','A',self.c.generation,timeout=0)
        self.assertEqual(self.c._cache,{})
        b=self.opened('B')
        with self.c.borrow('writer',b) as job:self.assertIsNone(job.cache_get('x'))

    def test_close_cooperatively_drains_and_suppresses_late_publish(self):
        a=self.opened(); ready=threading.Event(); finished=threading.Event(); errors=[]
        def work():
            with self.c.borrow('writer',a) as job:
                ready.set();self.assertTrue(job.cancel.wait(2))
                try:job.cache_put('late',b'x')
                except pg.PersistenceError as exc:errors.append(str(exc))
            finished.set()
        worker=threading.Thread(target=work);worker.start();self.assertTrue(ready.wait(2))
        self.c.close('writer','A',a.generation,timeout=2)
        worker.join(2);self.assertFalse(worker.is_alive());self.assertTrue(finished.is_set())
        self.assertEqual(errors,['workspace_generation_stale']);self.assertEqual(self.c.state,'closed')

    def test_concurrent_close_cannot_close_a_newly_opened_workspace(self):
        a=self.opened(); result=[]; entered=threading.Event()
        with self.c.borrow('writer',a) as job:
            def close():
                entered.set()
                try:result.append(self.c.close('writer','A',a.generation,timeout=2))
                except pg.PersistenceError as exc:result.append(str(exc))
            t=threading.Thread(target=close);t.start();self.assertTrue(job.cancel.wait(2))
            # Condition acquisition waits until close has released the lock for its drain.
            with self.c._condition:
                self.assertEqual(self.c.state,'closing')
                closing=self.c.generation
            def second():
                try:result.append(self.c.close('writer','A',closing,timeout=2))
                except pg.PersistenceError as exc:result.append(str(exc))
            u=threading.Thread(target=second);u.start()
        t.join(3);u.join(3);self.assertFalse(t.is_alive());self.assertFalse(u.is_alive())
        b=self.opened('B');self.assertEqual(self.c.workspace_id,b.workspace_id)
        self.assertGreaterEqual(sum(type(x) is int for x in result),1)
        self.assertTrue(all(type(x) is int or x=='workspace_generation_stale' for x in result))
        self.assertEqual(b.generation,a.generation+3)

    def test_lease_loss_cancels_jobs_clears_cache_and_never_reopens(self):
        a=self.opened()
        with self.c.borrow('writer',a) as job:
            job.cache_put('x',b'data');self.lease.lost=True
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_lease_lost'):job.check()
            self.assertTrue(job.cancel.is_set());self.assertEqual(self.c._cache,{})
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_lease_lost'):self.opened('B')
        self.assertEqual(self.c.state,'recovery_required')

    def test_twenty_switches_release_cache_and_preserve_monotonic_generation(self):
        previous=self.c.generation
        for i in range(20):
            workspace_id='A' if i%2==0 else 'B';token=self.opened(workspace_id)
            self.assertGreater(token.generation,previous)
            with self.c.borrow('writer',token) as job:job.cache_put('payload',b'1234')
            previous=self.c.close('writer',workspace_id,token.generation,timeout=0)
            snapshot=self.c.snapshot('writer');self.assertEqual(snapshot['cache_bytes'],0);self.assertEqual(snapshot['jobs'],0)

    def test_shutdown_discovers_session_loss_and_still_releases_its_resources(self):
        self.opened();self.lease.lost=True
        self.c.shutdown(timeout=0)
        self.assertTrue(self.c._terminated);self.assertTrue(self.lease.stopped)
        self.assertTrue(self.c._cancel.is_set());self.assertEqual(self.c.state,'recovery_required')

    def test_invalid_limits_and_generations_are_rejected(self):
        for kwargs in ({'max_jobs':True},{'max_jobs':0},{'max_cache_bytes':-1},{'heartbeat_seconds':float('nan')}):
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_input_invalid'):runtime.Coordinator(MemoryLease(),**kwargs)
        for value in (True,-1,2**63):
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_input_invalid'):self.c.open('writer','A',value)

    def test_invalid_cache_value_and_timeout_do_not_change_state(self):
        a=self.opened()
        with self.c.borrow('writer',a) as job:
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_input_invalid'):job.cache_put('../x',b'x')
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_input_invalid'):job.cache_put('x',bytearray(b'x'))
        for timeout in (True,-1,31,float('nan')):
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_input_invalid'):self.c.close('writer','A',a.generation,timeout=timeout)
        self.assertEqual(self.c.state,'open')

    def test_actor_target_mismatch_is_denied_before_reading_grants(self):
        conn=Mock();conn.info.host='other';conn.info.port=5432;conn.info.dbname='other'
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_connection_mismatch'):
            runtime.authorize(conn,'A','workspace:read',('expected',5432,'expected'))
        conn.execute.assert_not_called()

    def test_cli_redacts_database_errors_and_validates_before_connect(self):
        with patch.object(pg,'open_connection') as connect,redirect_stdout(io.StringIO()) as out:
            self.assertEqual(runtime.cli(['provision-runtime','--principal-role','../private']),2);connect.assert_not_called()
        with patch.object(pg,'open_connection',side_effect=RuntimeError('password=private')),redirect_stdout(io.StringIO()) as out:
            self.assertEqual(runtime.cli(['migrate']),2)
        self.assertEqual(json.loads(out.getvalue())['error_code'],'database_failed');self.assertNotIn('private',out.getvalue())


@unittest.skipUnless(os.environ.get('CANCA_TEST_WORKSPACE_POSTGRES')=='1','workspace PostgreSQL opt-in required')
class CoordinatorPostgreSQLTests(unittest.TestCase):
    legacy_rows=foundation.WorkspacePostgreSQLTests.legacy_rows
    role=foundation.WorkspacePostgreSQLTests.role
    def setUp(self):
        foundation.WorkspacePostgreSQLTests.setUp(self)
        self.assertEqual(pg.migrate(self.conn,runtime=True)['migration'],6)
        self.conn.execute('''DO $$ BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='canca_ws_coordinator') THEN
                CREATE ROLE canca_ws_coordinator NOLOGIN NOSUPERUSER NOBYPASSRLS;
            END IF;
        END $$''')
        self.conn.execute('GRANT USAGE ON SCHEMA canca TO canca_ws_coordinator')
        self.conn.execute('GRANT SELECT ON canca.schema_migrations TO canca_ws_coordinator')
        self.conn.execute('GRANT SELECT,UPDATE ON canca.workspace_runtime TO canca_ws_coordinator')
        runtime.provision(self.conn,'canca_ws_coordinator')
        ws.grant_workspace(self.conn,'B','canca_ws_writer','workspace:write')
    def lease(self):
        conn=pg.open_connection();self.addCleanup(conn.close)
        conn.execute('SET ROLE canca_ws_coordinator');return runtime.SessionLease(conn)
    def coordinator(self,heartbeat_seconds=30):
        c=runtime.Coordinator(self.lease(),heartbeat_seconds=heartbeat_seconds);c.start()
        self.addCleanup(lambda: c.shutdown(timeout=0) if not c._terminated else None)
        return c

    def test_runtime_migration_preserves_legacy_and_schema5_contracts(self):
        self.assertEqual(self.before,self.legacy_rows())
        self.assertEqual(pg.migrate(self.conn,runtime=True)['status'],'already_migrated')
        with self.role('canca_ws_a'):self.assertEqual(ws.list_workspaces(self.conn)['workspaces'][0]['workspace_id'],'A')
        with self.assertRaisesRegex(pg.PersistenceError,'schema_mismatch'):pg.migrate(self.conn,workspace=True)
        with self.assertRaisesRegex(pg.PersistenceError,'schema_mismatch'):pg.show_import(self.conn,pg.prepare_import(self.store,self.directory)['bundle_id'])

    def test_sql_lease_excludes_other_sessions_and_recovers_without_live_replay(self):
        one=self.lease();gen=one.start();opened=one.transition(gen,'open','A')
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_runtime_busy'):one.start()
        two=self.lease()
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_runtime_busy'):two.start()
        one.conn.close() # Simulate process/socket exit with persisted open state.
        recovered=self.lease();new=recovered.start();self.assertGreater(new,opened)
        self.assertEqual(self.conn.execute('SELECT state,workspace_id FROM canca.workspace_runtime').fetchone(),('closed',None))
        recovered.stop(new)

    def test_runtime_upgrade_failure_rolls_back_and_leaves_schema5_usable(self):
        from psycopg.errors import DuplicateTable
        self.conn.execute('DROP TABLE canca.workspace_runtime')
        self.conn.execute('DELETE FROM canca.schema_migrations WHERE version=6')
        self.conn.execute('CREATE TABLE canca.workspace_runtime (collision boolean)')
        with self.assertRaises(DuplicateTable):pg.migrate(self.conn,runtime=True)
        self.assertEqual(self.conn.execute('SELECT max(version) FROM canca.schema_migrations').fetchone()[0],5)
        self.assertEqual(self.before,self.legacy_rows())
        with self.role('canca_ws_a'):self.assertEqual(ws.list_workspaces(self.conn)['workspaces'][0]['workspace_id'],'A')

    def test_forced_rls_and_sql_privileges_keep_runtime_metadata_from_content_roles(self):
        from psycopg.errors import InsufficientPrivilege
        self.conn.execute('GRANT SELECT,UPDATE ON canca.workspace_runtime TO canca_ws_a')
        with self.role('canca_ws_a'):
            self.assertEqual(self.conn.execute('SELECT * FROM canca.workspace_runtime').fetchall(),[])
            self.assertEqual(self.conn.execute("UPDATE canca.workspace_runtime SET state='closed' RETURNING generation").fetchall(),[])
            with self.assertRaises(InsufficientPrivilege):self.conn.execute("INSERT INTO canca.workspace_runtime (principal_role) VALUES ('canca_ws_a')")
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_role_invalid'):runtime.SessionLease(self.conn).start()
        self.assertTrue(self.conn.closed)

    def test_real_coordinator_grants_and_revocation_fence_late_cache_results(self):
        c=self.coordinator()
        with self.role('canca_ws_writer'):a=c.open(self.conn,'A',c.generation)
        with self.role('canca_ws_a'):
            with c.borrow(self.conn,a) as job:
                job.cache_put('data',b'A')
                with self.assertRaisesRegex(pg.PersistenceError,'workspace_access_denied'):c.open(self.conn,'B',c.generation)
                with self.assertRaisesRegex(pg.PersistenceError,'workspace_access_denied'):c.close(self.conn,'A',c.generation)
                self.conn.execute('RESET ROLE');ws.revoke_workspace(self.conn,'A','canca_ws_a','workspace:read');self.conn.execute('SET ROLE canca_ws_a')
                with self.assertRaisesRegex(pg.PersistenceError,'workspace_access_denied'):job.cache_get('data')
        with self.role('canca_ws_writer'):c.close(self.conn,'A',c.generation)
        self.assertEqual(c.snapshot(self.conn)['cache_bytes'],0)

    def test_database_session_termination_is_detected_by_heartbeat(self):
        c=self.coordinator(heartbeat_seconds=0.05)
        pid=c.lease.conn.execute('SELECT pg_backend_pid()').fetchone()[0]
        with self.role('canca_ws_writer'):
            a=c.open(self.conn,'A',c.generation)
            with c.borrow(self.conn,a) as job:
                self.conn.execute('RESET ROLE');self.conn.execute('SELECT pg_terminate_backend(%s)',(pid,));self.conn.execute('SET ROLE canca_ws_writer')
                self.assertTrue(job.cancel.wait(3));self.assertEqual(c.state,'recovery_required')
                with self.assertRaisesRegex(pg.PersistenceError,'workspace_lease_lost'):job.check()
        # A lost physical connection cannot successfully persist a clean shutdown.
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_lease_lost'):c.shutdown(timeout=0)
        recovered=self.lease();gen=recovered.start();recovered.stop(gen)

    def test_raw_unlock_is_detected_and_old_generation_never_regains_ownership(self):
        one=self.lease();gen=one.start()
        one.conn.execute('SELECT pg_advisory_unlock_all()')
        two=self.lease();new=two.start();self.assertGreater(new,gen)
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_lease_lost'):one.check(gen)
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_lease_lost'):one.transition(gen,'open','A')
        one.conn.close();two.stop(new)

    def test_process_exit_releases_lease_and_preserves_monotonic_generation(self):
        code='''import os,sys
sys.path.insert(0,sys.argv[1])
import P01_Workspace_Coordinator as r
conn=r.pg.open_connection();conn.execute('SET ROLE canca_ws_coordinator')
lease=r.SessionLease(conn);gen=lease.start();gen=lease.transition(gen,'open','A')
print(gen,flush=True);sys.stdin.readline();os._exit(0)
'''
        process=subprocess.Popen([sys.executable,'-c',code,str(Path(runtime.__file__).parent)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        ready=threading.Event();lines=[]
        def read_ready():
            lines.append(process.stdout.readline());ready.set()
        reader=threading.Thread(target=read_ready,daemon=True);reader.start()
        self.assertTrue(ready.wait(10),'child lease did not become ready')
        line=lines[0];self.assertTrue(line.strip().isdigit(),line)
        previous=int(line)
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_runtime_busy'):self.lease().start()
        out,err=process.communicate('\n',timeout=10);self.assertEqual(process.returncode,0,err)
        lease=self.lease();gen=lease.start();self.assertGreater(gen,previous)
        self.assertEqual(self.conn.execute('SELECT state,workspace_id FROM canca.workspace_runtime').fetchone(),('closed',None))
        lease.stop(gen)

    def test_provisioning_cannot_reassign_coordinator_role_or_grant_content(self):
        self.assertEqual(runtime.provision(self.conn,'canca_ws_coordinator')['status'],'already_provisioned')
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_conflict'):runtime.provision(self.conn,'canca_ws_writer')
        with self.role('canca_ws_writer'):
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_admin_required'):runtime.provision(self.conn,'canca_ws_writer')
        lease=self.lease()
        from psycopg.errors import InsufficientPrivilege
        with self.assertRaises(InsufficientPrivilege):lease.conn.execute('SELECT * FROM canca.workspace_sites')
