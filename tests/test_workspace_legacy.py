"""Reviewed original stores/SQL, atomic migration and historical scoped reports."""
from contextlib import redirect_stdout
import copy
import http.client
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
import P01_Workspace_API as api
import test_workspace_model as models
import test_workspace_api as human_tests
import test_postgres_findings as findings_tests
legacy=api.backend.legacy
pg,ws,model,runtime=legacy.pg,legacy.ws,legacy.model,legacy.runtime

class LegacyInputTests(unittest.TestCase):
    def test_new_prefix_is_explicit_and_all_previous_hashes_retained(self):
        old=[(i,pg.digest(p.read_bytes())) for i,p in enumerate(pg.RECOVERY_MIGRATIONS,1)]
        new=old+[(9,pg.digest(pg.LEGACY_MIGRATIONS[-1].read_bytes()))]
        self.assertEqual(pg.migration_prefix(old,legacy=True)[:8],old)
        self.assertEqual(pg.migration_prefix(new,legacy=True),new)
        with self.assertRaisesRegex(pg.PersistenceError,'schema_mismatch'):pg.migration_prefix(new,recovery=True)
    def test_shared_legacy_store_is_read_only_and_handles_cannot_escape(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);store,directory=findings_tests.fixture(base/'fixture')
            sources=api.backend.LegacySources({'LAB-001':store,'OTHER':store})
            before={str(p):pg.digest(p.read_bytes()) for p in store.rglob('*') if p.is_file()}
            self.assertEqual(sources.prepare('LAB-001',directory.name),model.prepare_source(store,directory))
            self.assertEqual(before,{str(p):pg.digest(p.read_bytes()) for p in store.rglob('*') if p.is_file()})
            for args in (('../LAB-001',directory.name),('LAB-001','../'+directory.name),('OTHER',directory.name)):
                with self.assertRaises(pg.PersistenceError):sources.prepare(*args)
            alias=base/'alias';alias.symlink_to(store,target_is_directory=True)
            with self.assertRaises(pg.PersistenceError):api.backend.LegacySources({'LAB-001':alias})
    def test_invalid_report_cursor_never_accesses_sql(self):
        conn=Mock();token=runtime.Token('A',1,'a'*32)
        for fields in ({'after_ordinal':0},{'limit':101},{'after_ordinal':True},{'expected_scope_sha256':'bad'},
                       {'expected_revision':True},{'expected_revision':-1}):
            with self.assertRaises(pg.PersistenceError):legacy.report(conn,'A',token,'bnd-'+'a'*20,**fields)
        conn.execute.assert_not_called()
    def test_cli_redacts_errors(self):
        with patch.object(pg,'open_connection',side_effect=RuntimeError('password=PRIVATE')),redirect_stdout(io.StringIO()) as output:
            self.assertEqual(legacy.cli(['migrate']),2)
        self.assertNotIn('PRIVATE',output.getvalue())
    def test_new_http_routes_and_report_query_are_bounded(self):
        bid='bnd-'+'a'*20
        for route in ('legacy/preview','legacy/apply','legacy/'+bid+'/report'):
            self.assertIsNotNone(api.ROUTE.fullmatch(api.BASE+'/A/'+route))
        self.assertEqual(api.WorkspaceHandler._query('after_ordinal=-1&limit=1',{'after_ordinal','limit'}),{'after_ordinal':-1,'limit':1})
        for query in ('after_ordinal=-2','limit=+1','expected_scope_sha256=bad'):
            with self.assertRaises(api.authn.AccessError):api.WorkspaceHandler._query(query,{'after_ordinal','limit','expected_scope_sha256'})

@unittest.skipUnless(os.environ.get('CANCA_TEST_WORKSPACE_POSTGRES')=='1','workspace SQL opt-in required')
class LegacyPostgreSQLTests(unittest.TestCase):
    legacy_rows=models.ModelPostgreSQLTests.legacy_rows
    role=models.ModelPostgreSQLTests.role
    human=human_tests.APIPostgreSQLTests.human
    def seed_legacy(self):
        # Genuine schema4 producers execute before any opt-in workspace upgrade.
        self.rawstore,self.rawdir=findings_tests.fixture(Path(self.temp.name)/'historical',store=self.store,run='LEGACY')
        p=findings_tests.findings.prepare_findings(self.rawstore,self.rawdir)
        pg.index_import(self.conn,p['assets']['import'])
        model.registry.project_import(self.conn,p['assets'])
        findings_tests.findings.project_import(self.conn,p)
        self.projection=p['assets'];self.bid=self.rawdir.name
        model.registry.project_import(self.conn,model.prepare_source(self.store,self.directory))
    def setUp(self):
        models.ModelPostgreSQLTests.setUp(self)
        self.c.shutdown(timeout=0)
        self.assertEqual(pg.migrate(self.conn,legacy=True)['migration'],9)
        from psycopg import sql
        for role in ('canca_ws_a','canca_ws_b','canca_ws_writer'):
            self.conn.execute(sql.SQL('GRANT SELECT ON canca.workspace_legacy_plans,canca.workspace_legacy_imports TO {}').format(sql.Identifier(role)))
            self.conn.execute(sql.SQL('GRANT EXECUTE ON FUNCTION canca.workspace_legacy_snapshot(text) TO {}').format(sql.Identifier(role)))
        self.conn.execute('GRANT INSERT ON canca.workspace_legacy_plans,canca.workspace_legacy_imports TO canca_ws_writer')
        ws.bind_assessment(self.conn,'A','LAB-001')
        control=pg.open_connection();self.addCleanup(control.close);control.execute('SET ROLE canca_ws_coordinator')
        self.c=runtime.Coordinator(runtime.SessionLease(control),heartbeat_seconds=30);self.c.start()
        self.addCleanup(lambda:self.c.shutdown(timeout=0) if not self.c._terminated else None)
        with self.role('canca_ws_writer'):self.token=self.c.open(self.conn,'A',self.c.generation)
        self.adapter=api.backend.WorkspaceService(self.c,api.backend.SourceRoots({}),api.backend.LegacySources({'LAB-001':self.rawstore}))
    def preview(self,**kwargs):
        with self.role('canca_ws_writer'):return self.adapter.preview_legacy(self.conn,self.token,self.bid,**kwargs)
    def apply(self,plan,request='backfill'):
        with self.role('canca_ws_writer'):return self.adapter.apply_legacy(self.conn,self.token,plan['plan_id'],request)
    def report(self,**kwargs):
        with self.role('canca_ws_a'):return self.adapter.legacy_report(self.conn,self.token,self.bid,**kwargs)
    def test_preview_preserves_revision_legacy_rows_bytes_and_ids(self):
        plan=self.preview();self.assertEqual(plan['revision'],0);self.assertFalse(plan['review_required'])
        self.assertEqual(plan['finding_count'],2);self.assertTrue(plan['legacy_asset_ids'])
        self.assertEqual(self.before,self.legacy_rows())
        self.assertEqual(self.bytes_before,{str(p.relative_to(self.store)):pg.digest(p.read_bytes()) for p in self.store.rglob('*') if p.is_file()})
    def test_atomic_backfill_report_preserves_stored_evaluations_and_legacy_ids(self):
        with patch.object(findings_tests.findings,'evaluate',side_effect=AssertionError('historical engine must not rerun')):
            plan=self.preview();result=self.apply(plan);report=self.report()
        self.assertEqual(result['revision'],1);self.assertEqual(report['summary']['evaluation_count'],2)
        self.assertEqual(report['summary']['outcomes']['finding'],2)
        self.assertEqual(report['migrated_revision'],1)
        old=self.conn.execute('SELECT finding_id FROM canca.findings ORDER BY finding_id').fetchall()
        self.assertEqual(sorted(e['finding_id'] for e in report['evaluations']),[r[0] for r in old])
        self.assertTrue(all(e['legacy_asset_id'] in plan['legacy_asset_ids'] and e['workspace_object_id'] for e in report['evaluations']))
        self.assertEqual(self.before,self.legacy_rows())
        self.assertEqual(self.conn.execute('SELECT DISTINCT created_revision FROM canca.workspace_model_requests').fetchall(),[(1,)])
    def test_request_replay_survives_lost_source_and_changed_revision(self):
        plan=self.preview();first=self.apply(plan)
        with self.role('canca_ws_writer'):
            model.declare_object(self.conn,'A',self.token,1,'other','other','host','Other',reason='After migration')
        receipt=self.rawdir/'receipt/import-receipt.json';receipt.write_bytes(receipt.read_bytes()+b'corrupted')
        replay=self.apply(plan);self.assertTrue(replay['replayed']);self.assertEqual(replay['revision'],first['revision'])
    def test_drift_requires_new_preview_and_paged_report_is_fenced(self):
        plan=self.preview()
        with self.role('canca_ws_writer'):
            model.declare_object(self.conn,'A',self.token,0,'other','other','host','Other',reason='Drift')
        with self.assertRaisesRegex(pg.PersistenceError,'model_revision_stale'):self.apply(plan)
        plan=self.preview();self.apply(plan);page=self.report(limit=1)
        next_page=self.report(limit=1,after_ordinal=page['next_after_ordinal'],expected_revision=page['revision'],expected_scope_sha256=page['report_scope_sha256'])
        self.assertEqual(len(next_page['evaluations']),1);self.assertFalse(next_page['has_more'])
        with self.assertRaisesRegex(pg.PersistenceError,'legacy_scope_conflict'):
            self.report(after_ordinal=0,expected_revision=page['revision'],expected_scope_sha256='0'*64)
        with self.role('canca_ws_writer'):
            model.declare_attribute(self.conn,'A',self.token,page['revision'],'edit','other','description','Changed','Drift')
        with self.assertRaisesRegex(pg.PersistenceError,'model_revision_stale'):
            self.report(after_ordinal=0,expected_revision=page['revision'],expected_scope_sha256=page['report_scope_sha256'])
    def test_failed_copy_rolls_back_identity_receipts_and_revision(self):
        from psycopg.errors import CheckViolation
        plan=self.preview();self.conn.execute('ALTER TABLE canca.workspace_legacy_imports ADD CONSTRAINT fixture_failure CHECK (false)')
        try:
            with self.assertRaises(CheckViolation):self.apply(plan)
        finally:self.conn.execute('ALTER TABLE canca.workspace_legacy_imports DROP CONSTRAINT fixture_failure')
        for table in ('workspace_objects','workspace_collections','workspace_legacy_imports','workspace_model_requests'):
            self.assertEqual(self.conn.execute('SELECT count(*) FROM canca.'+table).fetchone()[0],0)
        self.assertEqual(self.conn.execute("SELECT revision FROM canca.workspace_revisions WHERE workspace_id='A'").fetchone()[0],0)
    def test_source_tamper_between_preview_and_apply_is_rejected(self):
        plan=self.preview();receipt=self.rawdir/'receipt/import-receipt.json';receipt.write_bytes(receipt.read_bytes()+b'changed')
        with self.assertRaises(pg.PersistenceError):self.apply(plan)
        self.assertEqual(self.conn.execute('SELECT count(*) FROM canca.workspace_collections').fetchone()[0],0)
    def test_session_lease_loss_before_commit_rolls_back_all_backfill_content(self):
        plan=self.preview();original=model.receipt
        killer=pg.open_connection();self.addCleanup(killer.close)
        pid=self.c.lease.conn.execute('SELECT pg_backend_pid()').fetchone()[0]
        def kill_after_receipt(conn,workspace_id,request_id,payload,result):
            value=original(conn,workspace_id,request_id,payload,result)
            if payload['op']=='apply_legacy':
                self.assertTrue(killer.execute('SELECT pg_terminate_backend(%s,5000)',(pid,)).fetchone()[0])
            return value
        with patch.object(model,'receipt',side_effect=kill_after_receipt):
            with self.assertRaisesRegex(pg.PersistenceError,'model_context_denied'):self.apply(plan)
        for table in ('workspace_objects','workspace_collections','workspace_legacy_imports','workspace_model_requests'):
            self.assertEqual(self.conn.execute('SELECT count(*) FROM canca.'+table).fetchone()[0],0)
        self.assertEqual(self.conn.execute("SELECT revision FROM canca.workspace_revisions WHERE workspace_id='A'").fetchone()[0],0)
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_lease_lost'):self.c.shutdown(timeout=0)
    def test_mapping_and_current_grants_precede_source_access(self):
        with patch.object(self.adapter.legacy_sources,'prepare') as prepare,self.role('canca_ws_a'):
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_access_denied'):
                self.adapter.preview_legacy(self.conn,self.token,self.bid)
            prepare.assert_not_called()
        with self.role('canca_ws_writer'):
            self.c.close(self.conn,'A',self.token.generation);token=self.c.open(self.conn,'B',self.c.generation)
            with patch.object(self.adapter.legacy_sources,'prepare') as prepare:
                with self.assertRaisesRegex(pg.PersistenceError,'legacy_source_unavailable'):self.adapter.preview_legacy(self.conn,token,self.bid)
                prepare.assert_not_called()
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_assignment_conflict'):ws.bind_assessment(self.conn,'B','LAB-001')
    def test_reader_never_gets_raw_legacy_select_and_rls_denies_forged_context(self):
        from psycopg.errors import InsufficientPrivilege
        with self.role('canca_ws_a'):
            with self.assertRaises(InsufficientPrivilege):self.conn.execute('SELECT * FROM canca.findings')
        plan=self.preview();self.apply(plan)
        with self.role('canca_ws_b'):
            self.conn.execute("SELECT set_config('canca.workspace_id','A',false)")
            try:self.assertEqual(self.conn.execute('SELECT * FROM canca.workspace_legacy_imports').fetchall(),[])
            finally:self.conn.execute("SELECT set_config('canca.workspace_id','',false)")
    def test_evidence_only_preserves_findings_without_attaching_objects(self):
        self.apply(self.preview(mode='evidence_only'));report=self.report()
        self.assertTrue(all(e['workspace_object_id'] is None and e['legacy_asset_id'] for e in report['evaluations']))
        self.assertEqual(self.conn.execute('SELECT count(*) FROM canca.workspace_objects').fetchone()[0],0)
    def test_missing_analysis_is_not_a_clean_report(self):
        bid=self.directory.name
        with self.role('canca_ws_writer'):
            plan=self.adapter.preview_legacy(self.conn,self.token,bid)
            self.assertEqual(plan['finding_coverage'],'not_analyzed')
            self.adapter.apply_legacy(self.conn,self.token,plan['plan_id'],'not-analyzed')
        with self.role('canca_ws_a'):report=self.adapter.legacy_report(self.conn,self.token,bid)
        self.assertEqual(report['coverage']['basis'],'not_analyzed');self.assertEqual(report['evaluations'],[])
    def test_snapshot_changes_between_preview_and_apply_are_detected(self):
        plan=self.preview();self.conn.execute("UPDATE canca.finding_analyses SET engine_sha256=%s",('f'*64,))
        with self.assertRaisesRegex(pg.PersistenceError,'legacy_source_conflict'):self.apply(plan)
        self.assertEqual(self.conn.execute('SELECT count(*) FROM canca.workspace_collections').fetchone()[0],0)
    def test_corrupt_historical_projection_is_rejected_before_preview(self):
        self.conn.execute("UPDATE canca.finding_analyses SET engine_sha256=%s",('f'*64,))
        with self.assertRaisesRegex(pg.PersistenceError,'legacy_source_conflict'):self.preview()
        self.assertEqual(self.conn.execute('SELECT count(*) FROM canca.workspace_import_plans').fetchone()[0],0)
    def test_close_during_original_source_preparation_suppresses_migration(self):
        ready=threading.Event();release=threading.Event();errors=[]
        actor=pg.open_connection();self.addCleanup(actor.close);actor.execute('SET ROLE canca_ws_writer')
        def prepare(*args):ready.set();self.assertTrue(release.wait(5));return self.projection
        def run():
            try:self.adapter.preview_legacy(actor,self.token,self.bid)
            except pg.PersistenceError as exc:errors.append(str(exc))
        with patch.object(self.adapter.legacy_sources,'prepare',side_effect=prepare):
            worker=threading.Thread(target=run);worker.start();self.assertTrue(ready.wait(5))
            try:
                with self.role('canca_ws_writer'),self.assertRaisesRegex(pg.PersistenceError,'workspace_close_pending'):
                    self.c.close(self.conn,'A',self.token.generation,timeout=0)
            finally:release.set();worker.join(5)
        self.assertFalse(worker.is_alive());self.assertEqual(errors,['workspace_generation_stale'])
        self.assertEqual(self.conn.execute('SELECT count(*) FROM canca.workspace_legacy_plans').fetchone()[0],0)
    def test_legacy_snapshot_and_history_are_immutable_to_actor(self):
        from psycopg.errors import InsufficientPrivilege
        plan=self.preview();self.apply(plan)
        self.conn.execute('GRANT UPDATE,DELETE ON canca.workspace_legacy_imports,canca.workspace_legacy_plans TO canca_ws_writer')
        with self.role('canca_ws_writer'):
            self.assertEqual(self.conn.execute('DELETE FROM canca.workspace_legacy_imports RETURNING collection_id').fetchall(),[])
            self.assertEqual(self.conn.execute("UPDATE canca.workspace_legacy_plans SET payload='{}'::jsonb RETURNING plan_id").fetchall(),[])
            with self.assertRaises(InsufficientPrivilege):self.conn.execute('UPDATE canca.findings SET evidence=\'{}\'::jsonb')
    def test_prefixes_remain_pinned(self):
        with self.assertRaisesRegex(pg.PersistenceError,'schema_mismatch'):pg.migrate(self.conn,recovery=True)
        self.assertEqual(self.conn.execute('SELECT version,sha256 FROM canca.schema_migrations ORDER BY version').fetchall(),
            [(i,pg.digest(p.read_bytes())) for i,p in enumerate(pg.LEGACY_MIGRATIONS,1)])
    def test_schema9_upgrade_is_refused_during_live_schema8_coordinator(self):
        from psycopg.errors import ObjectInUse
        self.c.shutdown(timeout=0)
        # Reset only schema9 in this disposable fixture, yielding the exact prefix8.
        self.conn.execute('DROP TABLE canca.workspace_legacy_imports,canca.workspace_legacy_plans')
        self.conn.execute('DROP FUNCTION canca.workspace_legacy_snapshot(text)')
        self.conn.execute('DELETE FROM canca.schema_migrations WHERE version=9')
        control=pg.open_connection();self.addCleanup(control.close);control.execute('SET ROLE canca_ws_coordinator')
        self.c=runtime.Coordinator(runtime.SessionLease(control),heartbeat_seconds=30);self.c.start()
        with self.assertRaises(ObjectInUse):pg.migrate(self.conn,legacy=True)
        self.assertEqual(self.conn.execute('SELECT max(version) FROM canca.schema_migrations').fetchone()[0],8)
        self.assertIsNone(self.conn.execute("SELECT to_regclass('canca.workspace_legacy_imports')").fetchone()[0])
        self.assertEqual(self.before,self.legacy_rows())
        self.c.shutdown(timeout=0)
        self.assertEqual(pg.migrate(self.conn,legacy=True)['migration'],9)
    def test_real_human_http_preview_apply_and_report(self):
        human,bearer=self.human();human.workspace.legacy_sources=self.adapter.legacy_sources
        server=api.WorkspaceServer(('127.0.0.1',0),human);worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
        def call(method,path,body=None):
            conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=10)
            headers={'Authorization':'Bearer '+bearer,'Content-Type':'application/json'}
            conn.request(method,path,None if body is None else json.dumps(body),headers);response=conn.getresponse();status=response.status;doc=json.loads(response.read());conn.close();return status,doc
        try:
            code,plan=call('POST',api.BASE+'/A/legacy/preview',dict(generation=self.token.generation,bundle_id=self.bid));self.assertEqual(code,200,plan)
            code,result=call('POST',api.BASE+'/A/legacy/apply',dict(generation=self.token.generation,plan_id=plan['plan_id'],request_id='http'));self.assertEqual(code,200,result)
            code,report=call('GET',api.BASE+'/A/legacy/'+self.bid+'/report?generation='+str(self.token.generation)+'&limit=1');self.assertEqual(code,200,report)
            self.assertEqual(report['summary']['evaluation_count'],2)
            self.assertEqual(call('GET',api.BASE+'/A/legacy/'+self.bid+'/report')[0],400)
        finally:server.shutdown();worker.join(5);server.server_close()
