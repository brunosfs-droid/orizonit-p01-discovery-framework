"""Verified history/manual graph/reconciliation and atomic close/commit fencing."""
from contextlib import redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'persistence'))
import P01_Workspace_Model as model
import test_postgres_workspace as foundation
import test_postgres_assets as assets

pg,ws,runtime=model.pg,model.ws,model.runtime


class ModelInputTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name)
        self.store,self.directory=assets.fixture(self.base/'source')
        self.p=model.prepare_source(self.store,self.directory)

    def test_verified_projection_is_repeatable_and_store_bytes_unchanged(self):
        before={str(p):pg.digest(p.read_bytes()) for p in self.store.rglob('*') if p.is_file()}
        self.assertEqual(self.p,model.prepare_source(self.store,self.directory))
        self.assertEqual(before,{str(p):pg.digest(p.read_bytes()) for p in self.store.rglob('*') if p.is_file()})
        self.assertTrue(any(s['qualified'] for s in self.p['observations'][0]['signals']))

    def test_embedded_forged_identity_is_ignored(self):
        store,directory=assets.fixture(self.base/'forged',forged=True)
        values=[s['value'] for s in model.prepare_source(store,directory)['observations'][0]['signals']]
        self.assertNotIn('FORGED',values);self.assertNotIn('forged.example.test',values)

    def test_tampered_source_fails_before_any_database_access(self):
        receipt=self.directory/'receipt/import-receipt.json';receipt.write_bytes(receipt.read_bytes()+b'changed')
        with patch.object(pg,'open_connection') as connect:
            with self.assertRaises(pg.PersistenceError):model.prepare_source(self.store,self.directory)
            connect.assert_not_called()

    def test_invalid_projection_references_are_rejected(self):
        p=copy.deepcopy(self.p);p['observations'][0]['signals'][0]['sources']=['other-workspace.json']
        with self.assertRaises(pg.PersistenceError):model.validate_source(p)

    def test_batch_limit_is_enforced_before_connection(self):
        p=copy.deepcopy(self.p)
        p['observations']=[dict(p['observations'][0],ordinal=i) for i in range(1001)]
        with self.assertRaisesRegex(pg.PersistenceError,'model_input_invalid'):model.validate_source(p)

    def test_invalid_manual_fields_tokens_and_graph_bounds_do_not_touch_sql(self):
        token=runtime.Token('A',1,'a'*32);conn=Mock()
        calls=[lambda:model.declare_attribute(conn,'A',token,0,'r','x','password','private','Reason'),
               lambda:model.declare_attribute(conn,'A',token,0,'r','x','capacity_bytes',True,'Reason'),
               lambda:model.declare_object(conn,'A',token,0,'r','x','vlan','VLAN',reason='Reason'),
               lambda:model.relationship(conn,'A',token,0,'r','edge','x','x','depends_on',reason='Reason'),
               lambda:model.graph(conn,'A',token,'x',node_limit=101),
               lambda:model.list_objects(conn,'A',runtime.Token('B',1,'a'*32))]
        for call in calls:
            with self.assertRaises(pg.PersistenceError):call()
        conn.execute.assert_not_called()

    def test_invalid_preview_policy_and_decisions_rejected_before_sql(self):
        conn=Mock();token=runtime.Token('A',1,'a'*32)
        for kwargs in ({'mode':'replace'},{'categories':['compute']},{'decisions':{True:{'action':'create','reason':'why'}}},
                       {'decisions':{0:{'action':'link','object_id':'../B','reason':'why'}}}):
            with self.assertRaises(pg.PersistenceError):model.preview_import(conn,'A',token,self.p,**kwargs)
        conn.execute.assert_not_called()

    def test_typed_attributes_reject_noncanonical_or_unbounded_values(self):
        for name,value in (('ip','192.168.01.1'),('cidr','192.0.2.1/24'),('vlan_id',4095),('description','x'*1025),('model','\ud800')):
            with self.assertRaises(pg.PersistenceError):model.attribute(name,value)
        for name,value in (('cidr','192.0.2.0/24'),('vlan_id',10),('description',None),('capacity_bytes',0)):
            model.attribute(name,value)

    def test_cli_redacts_driver_errors(self):
        with patch.object(pg,'open_connection',side_effect=RuntimeError('password=private')),redirect_stdout(io.StringIO()) as out:
            self.assertEqual(model.cli(['migrate']),2)
        self.assertNotIn('private',out.getvalue());self.assertEqual(json.loads(out.getvalue())['error_code'],'database_failed')


@unittest.skipUnless(os.environ.get('CANCA_TEST_WORKSPACE_POSTGRES')=='1','workspace SQL opt-in required')
class ModelPostgreSQLTests(unittest.TestCase):
    legacy_rows=foundation.WorkspacePostgreSQLTests.legacy_rows
    role=foundation.WorkspacePostgreSQLTests.role
    def setUp(self):
        foundation.WorkspacePostgreSQLTests.setUp(self)
        pg.migrate(self.conn,runtime=True)
        self.conn.execute('''DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='canca_ws_coordinator') THEN
            CREATE ROLE canca_ws_coordinator NOLOGIN NOSUPERUSER NOBYPASSRLS; END IF; END $$''')
        self.conn.execute('GRANT USAGE ON SCHEMA canca TO canca_ws_coordinator')
        self.conn.execute('GRANT SELECT ON canca.schema_migrations TO canca_ws_coordinator')
        self.conn.execute('GRANT SELECT,UPDATE ON canca.workspace_runtime TO canca_ws_coordinator')
        runtime.provision(self.conn,'canca_ws_coordinator')
        self.assertEqual(pg.migrate(self.conn,model=True)['migration'],7)
        for role in ('canca_ws_a','canca_ws_b','canca_ws_writer'):
            from psycopg import sql
            self.conn.execute(sql.SQL('GRANT SELECT ON canca.workspace_revisions,canca.workspace_objects,canca.workspace_collections,'
                'canca.workspace_observations,canca.workspace_identity_signals,canca.workspace_declarations,canca.workspace_relationships,'
                'canca.workspace_import_plans,canca.workspace_model_requests TO {}').format(sql.Identifier(role)))
            self.conn.execute(sql.SQL('GRANT EXECUTE ON FUNCTION canca.workspace_model_allowed(boolean),'
                'canca.workspace_revision_lock(boolean) TO {}').format(sql.Identifier(role)))
        self.conn.execute('GRANT INSERT ON canca.workspace_objects,canca.workspace_collections,canca.workspace_observations,'
            'canca.workspace_identity_signals,canca.workspace_declarations,canca.workspace_relationships,'
            'canca.workspace_import_plans,canca.workspace_model_requests TO canca_ws_writer')
        ws.grant_workspace(self.conn,'B','canca_ws_writer','workspace:write')
        control=pg.open_connection();self.addCleanup(control.close);control.execute('SET ROLE canca_ws_coordinator')
        self.c=runtime.Coordinator(runtime.SessionLease(control),heartbeat_seconds=30);self.c.start()
        self.addCleanup(lambda:self.c.shutdown(timeout=0) if not self.c._terminated else None)
        with self.role('canca_ws_writer'):self.token=self.c.open(self.conn,'A',self.c.generation)
        self.counter=0;self.revision=0
        self.assetbase=Path(self.temp.name)/'asset-sources';self.assetbase.mkdir()

    def source(self,**kwargs):
        self.counter+=1
        store,directory=assets.fixture(self.assetbase/str(self.counter),store=self.assetbase/'store',run=f'R{self.counter}',**kwargs)
        return model.prepare_source(store,directory)
    def create(self,object_id,kind='host',attributes=None,**kwargs):
        self.counter+=1
        with self.role('canca_ws_writer'):
            result=model.declare_object(self.conn,'A',self.token,self.revision,'manual-'+str(self.counter),object_id,kind,object_id,
                                       attributes=attributes,reason='LAB declaration',**kwargs)
        self.revision=result['revision'];return result
    def apply(self,p,**kwargs):
        self.counter+=1
        with self.role('canca_ws_writer'):
            plan=model.preview_import(self.conn,'A',self.token,p,**kwargs)
            result=model.apply_import(self.conn,'A',self.token,plan['plan_id'],'apply-'+str(self.counter))
        self.revision=result['revision'];return plan,result
    def state(self,object_id):
        with self.role('canca_ws_a'):return model.object_state(self.conn,'A',self.token,object_id)

    def test_schema_replay_preserves_legacy_and_default_prefixes(self):
        self.assertEqual(pg.migrate(self.conn,model=True)['status'],'already_migrated')
        self.assertEqual(self.before,self.legacy_rows())
        for flags in ({},{'workspace':True},{'runtime':True}):
            with self.assertRaisesRegex(pg.PersistenceError,'schema_mismatch'):pg.migrate(self.conn,**flags)
        with self.role('canca_ws_a'):self.assertEqual(ws.list_workspaces(self.conn)['workspaces'][0]['workspace_id'],'A')

    def test_manual_object_declarations_share_one_revision_and_are_immutable(self):
        self.create('server',attributes={'operating_system':'Linux','capacity_bytes':100,'description':'Manual'})
        self.assertEqual(self.revision,1)
        state=self.state('server');self.assertEqual(state['metadata']['origin'],'declared')
        self.assertEqual(len(state['declarations']),3)
        self.assertTrue(all(d['created_revision']==1 and d['author_role']=='canca_ws_writer' for d in state['declarations']))
        self.conn.execute('GRANT UPDATE,DELETE ON canca.workspace_declarations TO canca_ws_writer')
        with self.role('canca_ws_writer'),model.scope(self.conn,'A',self.token,writing=True):
            self.assertEqual(self.conn.execute("UPDATE canca.workspace_declarations SET reason='tampered' RETURNING declaration_id").fetchall(),[])
            self.assertEqual(self.conn.execute('DELETE FROM canca.workspace_declarations RETURNING declaration_id').fetchall(),[])

    def test_idempotent_manual_request_replays_but_changed_payload_conflicts(self):
        args=(self.conn,'A',self.token,0,'same-request','same-object','service','Service')
        with self.role('canca_ws_writer'):
            one=model.declare_object(*args,reason='Declared');two=model.declare_object(*args,reason='Declared')
            self.assertEqual(two['revision'],one['revision']);self.assertTrue(two['replayed'])
            with self.assertRaisesRegex(pg.PersistenceError,'model_request_conflict'):model.declare_object(*args,reason='Changed')
        self.revision=1

    def test_stale_revision_cannot_create_or_edit(self):
        self.create('server')
        with self.role('canca_ws_writer'):
            with self.assertRaisesRegex(pg.PersistenceError,'model_revision_stale'):
                model.declare_object(self.conn,'A',self.token,0,'stale','other','host','Other',reason='Reason')
        self.assertEqual(self.conn.execute('SELECT count(*) FROM canca.workspace_objects').fetchone()[0],1)

    def test_preview_does_not_change_revision_and_import_replays(self):
        p=self.source()
        with self.role('canca_ws_writer'):
            one=model.preview_import(self.conn,'A',self.token,p);two=model.preview_import(self.conn,'A',self.token,p)
            self.assertEqual(one,two);self.assertEqual(one['revision'],0)
            result=model.apply_import(self.conn,'A',self.token,one['plan_id'],'once')
            replay=model.apply_import(self.conn,'A',self.token,one['plan_id'],'once')
        self.assertEqual(result['revision'],1);self.assertEqual(replay['revision'],1);self.assertTrue(replay['replayed'])
        self.assertEqual(self.conn.execute('SELECT count(*) FROM canca.workspace_observations').fetchone()[0],1)
        self.assertEqual(self.before,self.legacy_rows())

    def test_two_runs_correlate_only_with_qualified_corroboration(self):
        first,result=self.apply(self.source());object_id=first['observations'][0]['object_id']
        second,_=self.apply(self.source(ip='192.0.2.20'))
        self.assertEqual(second['observations'][0]['object_id'],object_id)
        self.assertEqual(second['observations'][0]['decision'],'corroborated_identity')
        state=self.state(object_id);self.assertEqual(len(state['observations']),2)
        self.assertEqual(state['fields']['ip']['observed'],['192.0.2.20'])
        self.assertFalse(state['fields']['ip']['collection_time_known'])

    def test_weak_or_conflicting_identity_requires_explicit_decision(self):
        self.apply(self.source())
        conflicting=self.source(serial='DIFFERENT',credentialed=False)
        with self.role('canca_ws_writer'):
            plan=model.preview_import(self.conn,'A',self.token,conflicting)
            self.assertTrue(plan['review_required'])
            with self.assertRaisesRegex(pg.PersistenceError,'model_review_required'):
                model.apply_import(self.conn,'A',self.token,plan['plan_id'],'blocked')
        explicit,result=self.apply(conflicting,decisions={0:{'action':'create','reason':'Independent physical device'}})
        self.assertEqual(explicit['observations'][0]['decision'],'manual_create')
        self.assertEqual(self.conn.execute('SELECT count(*) FROM canca.workspace_objects').fetchone()[0],2)

    def test_evidence_only_keeps_observations_without_active_object(self):
        plan,result=self.apply(self.source(),mode='evidence_only')
        self.assertEqual(result['mode'],'evidence_only')
        self.assertEqual(self.conn.execute('SELECT count(*) FROM canca.workspace_objects').fetchone()[0],0)
        self.assertEqual(self.conn.execute('SELECT object_id,decision FROM canca.workspace_observations').fetchone(),(None,'evidence_only'))

    def test_manual_declared_and_observed_conflict_remain_visible(self):
        self.create('manual',attributes={'fqdn':'manual.example.test'})
        self.apply(self.source(),decisions={0:{'action':'link','object_id':'manual','reason':'Reviewed device identity'}})
        state=self.state('manual');self.assertEqual(state['fields']['fqdn']['declared'],'manual.example.test')
        self.assertEqual(state['fields']['fqdn']['resolution'],'conflicting')
        with self.role('canca_ws_writer'):
            result=model.declare_attribute(self.conn,'A',self.token,self.revision,'retract','manual','fqdn',None,'Retraction')
        self.revision=result['revision'];state=self.state('manual')
        self.assertIsNone(state['fields']['fqdn']['declared']);self.assertEqual(len(state['declarations']),2)

    def test_reviewed_manual_object_can_receive_later_corroborated_runs(self):
        self.create('manual',attributes={'operating_system':'Declared OS'})
        self.apply(self.source(),decisions={0:{'action':'link','object_id':'manual','reason':'Identity reviewed'}})
        plan,result=self.apply(self.source(ip='192.0.2.20'))
        self.assertEqual(plan['observations'][0]['object_id'],'manual')
        self.assertEqual(plan['observations'][0]['decision'],'corroborated_identity')
        self.assertEqual(self.state('manual')['fields']['operating_system']['declared'],'Declared OS')
        self.assertEqual(self.conn.execute('SELECT count(*) FROM canca.workspace_objects').fetchone()[0],1)

    def test_preview_becomes_stale_after_other_write_and_plan_cannot_be_overwritten(self):
        p=self.source()
        with self.role('canca_ws_writer'):plan=model.preview_import(self.conn,'A',self.token,p)
        self.create('manual')
        with self.role('canca_ws_writer'):
            with self.assertRaisesRegex(pg.PersistenceError,'model_revision_stale'):
                model.apply_import(self.conn,'A',self.token,plan['plan_id'],'stale-plan')
        self.conn.execute('GRANT UPDATE ON canca.workspace_import_plans TO canca_ws_writer')
        with self.role('canca_ws_writer'),model.scope(self.conn,'A',self.token,writing=True):
            self.assertEqual(self.conn.execute("UPDATE canca.workspace_import_plans SET payload='{}'::jsonb RETURNING plan_id").fetchall(),[])

    def test_same_ids_and_signals_in_other_workspace_never_correlate(self):
        p=self.source();plan,_=self.apply(p);self.create('same')
        with self.role('canca_ws_writer'):
            self.c.close(self.conn,'A',self.c.generation)
            b=self.c.open(self.conn,'B',self.c.generation)
            bp=model.preview_import(self.conn,'B',b,p)
            self.assertEqual(bp['observations'][0]['decision'],'new_identity')
            self.assertNotEqual(bp['observations'][0]['object_id'],plan['observations'][0]['object_id'])
            model.apply_import(self.conn,'B',b,bp['plan_id'],'same-bundle')
            model.declare_object(self.conn,'B',b,1,'same','same','host','B object',reason='B declaration')
            with self.assertRaisesRegex(pg.PersistenceError,'model_context_denied'):model.list_objects(self.conn,'A',self.token)
            self.c.close(self.conn,'B',self.c.generation);self.token=self.c.open(self.conn,'A',self.c.generation)
        self.assertEqual(self.state('same')['metadata']['label'],'same')

    def test_direct_sql_forged_context_and_missing_lease_cannot_write(self):
        from psycopg.errors import InsufficientPrivilege
        with self.role('canca_ws_writer'),self.conn.transaction():
            self.conn.execute("SELECT set_config('canca.workspace_id','B',true)")
            self.conn.execute("SELECT set_config('canca.workspace_generation',%s,true)",(str(self.token.generation),))
            self.conn.execute("SELECT set_config('canca.workspace_lease',%s,true)",(self.token.lease_id,))
            self.assertEqual(self.conn.execute('SELECT * FROM canca.workspace_objects').fetchall(),[])
        with self.role('canca_ws_writer'),self.assertRaises(InsufficientPrivilege),self.conn.transaction():
            self.conn.execute("SELECT set_config('canca.workspace_id','A',true)")
            self.conn.execute("INSERT INTO canca.workspace_objects (workspace_id,object_id,kind,label,origin,created_revision) VALUES ('A','hack','host','Hack','declared',0)")
        self.assertEqual(self.conn.execute("SELECT revision FROM canca.workspace_revisions WHERE workspace_id='A'").fetchone()[0],0)

    def test_authorship_spoof_and_cross_site_reference_roll_back_revision(self):
        from psycopg.errors import InsufficientPrivilege,ForeignKeyViolation
        with self.role('canca_ws_writer'),self.assertRaises(InsufficientPrivilege),model.scope(self.conn,'A',self.token,writing=True):
            self.conn.execute("INSERT INTO canca.workspace_objects (workspace_id,object_id,kind,label,origin,author_role,created_revision) VALUES ('A','hack','host','Hack','declared','other',0)")
        with self.role('canca_ws_writer'),self.assertRaises(ForeignKeyViolation):
            model.declare_object(self.conn,'A',self.token,0,'cross-site','host','host','Host',site_id='B-parent',reason='Reason')
        self.assertEqual(self.conn.execute("SELECT revision FROM canca.workspace_revisions WHERE workspace_id='A'").fetchone()[0],0)

    def test_graph_cycles_are_bounded_and_relationship_removal_is_historical(self):
        for name in ('a','b','c'):self.create(name,kind='service')
        for i,(source,target) in enumerate((('a','b'),('b','c'),('c','a'))):
            with self.role('canca_ws_writer'):
                result=model.relationship(self.conn,'A',self.token,self.revision,'edge-'+str(i),'rel-'+str(i),source,target,'depends_on',reason='Service dependency')
            self.revision=result['revision']
        with self.role('canca_ws_a'):
            result=model.graph(self.conn,'A',self.token,'a',depth=4)
            limited=model.graph(self.conn,'A',self.token,'a',node_limit=2)
        self.assertEqual(len(result['nodes']),3);self.assertEqual(len(result['edges']),3)
        self.assertTrue(limited['truncated']);self.assertLessEqual(len(limited['nodes']),2)
        with self.role('canca_ws_writer'):
            result=model.relationship(self.conn,'A',self.token,self.revision,'remove','rel-0','a','b','depends_on',active=False,reason='Removed declaration')
        self.revision=result['revision']
        with self.role('canca_ws_a'):self.assertEqual(len(model.graph(self.conn,'A',self.token,'a',depth=4)['edges']),2)
        self.assertEqual(self.conn.execute("SELECT count(*) FROM canca.workspace_relationships WHERE relationship_id='rel-0'").fetchone()[0],2)

    def test_relationship_identity_cannot_be_reassigned_and_wrong_endpoint_is_denied(self):
        for name in ('a','b','c'):self.create(name)
        with self.role('canca_ws_writer'):
            result=model.relationship(self.conn,'A',self.token,self.revision,'first-edge','r','a','b','connected_to',reason='Cable')
            self.revision=result['revision']
            with self.assertRaisesRegex(pg.PersistenceError,'model_relationship_conflict'):
                model.relationship(self.conn,'A',self.token,self.revision,'rebind','r','a','c','connected_to',reason='Changed')
            with self.assertRaisesRegex(pg.PersistenceError,'model_object_not_found'):
                model.relationship(self.conn,'A',self.token,self.revision,'wrong','r2','a','foreign','connected_to',reason='Wrong')

    def test_reader_cannot_preview_or_mutate_and_revocation_blocks_reads(self):
        self.create('server')
        with self.role('canca_ws_a'):
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_access_denied'):
                model.preview_import(self.conn,'A',self.token,self.source())
            self.assertEqual(model.object_state(self.conn,'A',self.token,'server')['object_id'],'server')
        ws.revoke_workspace(self.conn,'A','canca_ws_a','workspace:read')
        with self.role('canca_ws_a'),self.assertRaisesRegex(pg.PersistenceError,'workspace_access_denied'):
            model.object_state(self.conn,'A',self.token,'server')

    def test_cursor_revision_detects_drift_and_limits_are_enforced(self):
        self.create('a');self.create('b')
        with self.role('canca_ws_a'):first=model.list_objects(self.conn,'A',self.token,limit=1)
        self.assertTrue(first['has_more']);self.create('c')
        with self.role('canca_ws_a'),self.assertRaisesRegex(pg.PersistenceError,'model_revision_stale'):
            model.list_objects(self.conn,'A',self.token,after=first['next_after'],limit=1,expected_revision=first['revision'])

    def test_close_waits_for_atomic_model_commit_and_old_token_cannot_publish(self):
        ready=threading.Event();release=threading.Event();closed=threading.Event();errors=[]
        actor=pg.open_connection();self.addCleanup(actor.close);actor.execute('SET ROLE canca_ws_writer')
        closer=pg.open_connection();self.addCleanup(closer.close);closer.execute('SET ROLE canca_ws_writer')
        def mutate():
            try:
                with model.scope(actor,'A',self.token,writing=True):
                    actor.execute("INSERT INTO canca.workspace_objects (workspace_id,object_id,kind,label,origin,created_revision) VALUES ('A','committed','host','Committed','declared',0)")
                    ready.set()
                    if not release.wait(5):raise RuntimeError('test release timeout')
            except Exception as exc:errors.append(str(exc))
        def close():
            try:self.c.close(closer,'A',self.c.generation,timeout=5);closed.set()
            except Exception as exc:errors.append(str(exc))
        worker=threading.Thread(target=mutate);worker.start();self.assertTrue(ready.wait(5))
        closing=threading.Thread(target=close);closing.start()
        self.assertFalse(closed.wait(0.1));release.set();worker.join(5);closing.join(5)
        self.assertFalse(worker.is_alive());self.assertFalse(closing.is_alive());self.assertEqual(errors,[])
        self.assertTrue(closed.is_set());self.assertEqual(self.conn.execute("SELECT count(*) FROM canca.workspace_objects WHERE object_id='committed'").fetchone()[0],1)
        with self.role('canca_ws_a'),self.assertRaisesRegex(pg.PersistenceError,'model_context_denied'):model.list_objects(self.conn,'A',self.token)

    def test_runtime_loss_before_scope_exit_rolls_back_all_model_rows(self):
        actor=pg.open_connection();self.addCleanup(actor.close);actor.execute('SET ROLE canca_ws_writer')
        pid=self.c.lease.conn.info.backend_pid
        with self.assertRaisesRegex(pg.PersistenceError,'model_context_denied'),model.scope(actor,'A',self.token,writing=True):
            actor.execute("INSERT INTO canca.workspace_objects (workspace_id,object_id,kind,label,origin,created_revision) VALUES ('A','lost','host','Lost','declared',0)")
            self.conn.execute('SELECT pg_terminate_backend(%s)',(pid,))
        self.assertEqual(self.conn.execute("SELECT count(*) FROM canca.workspace_objects WHERE object_id='lost'").fetchone()[0],0)
        try:self.c.shutdown(timeout=0)
        except pg.PersistenceError:pass
        self.assertTrue(self.c._terminated)

    def test_upgrade_is_rejected_while_old_coordinator_session_holds_lease(self):
        # Qualified source SQL includes a nonblocking upgrade guard. Exercise it
        # against the live session even though schema7 has already been applied.
        from psycopg.errors import ObjectInUse
        sql=pg.MODEL_MIGRATIONS[-1].read_text().split('ALTER TABLE',1)[0]
        with self.assertRaises(ObjectInUse),self.conn.transaction():self.conn.execute(sql)
