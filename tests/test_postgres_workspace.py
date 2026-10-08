"""Workspace adversarial isolation; real SQL opt-in uses a disposable database only."""
from contextlib import contextmanager, redirect_stdout
import concurrent.futures
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'persistence'))
import P01_Workspace as ws
from test_postgresql import fixture

pg = ws.pg


class WorkspaceInputTests(unittest.TestCase):
    def test_invalid_requests_are_rejected_before_opening_database(self):
        commands = [
            ['create-workspace','--workspace-id','../B','--name','A'],
            ['create-workspace','--workspace-id','A','--name',' '],
            ['create-workspace','--workspace-id','A','--name','bad\nname'],
            ['create-workspace','--workspace-id','A','--name','\ud800'],
            ['create-site','--workspace-id','A','--site-id','x','--name','X','--kind','azure','--parent-site-id','x'],
            ['list-items','--workspace-id','A','--category','sites','--after','../B'],
            ['list-workspaces','--limit','101'],
            ['grant-workspace','--workspace-id','A','--principal-role',"role';DROP",'--permission','workspace:read'],
        ]
        for args in commands:
            with self.subTest(command=args[0]), patch.object(pg,'open_connection') as connect, redirect_stdout(io.StringIO()) as out:
                self.assertEqual(ws.cli(args),2)
                self.assertEqual(json.loads(out.getvalue())['error_code'],'workspace_input_invalid')
                connect.assert_not_called()

    def test_error_output_never_includes_database_details(self):
        with patch.object(pg,'open_connection',side_effect=RuntimeError('password=PRIVATE /path')), redirect_stdout(io.StringIO()) as out:
            self.assertEqual(ws.cli(['list-workspaces']),2)
        doc=json.loads(out.getvalue()); self.assertEqual(doc['error_code'],'database_failed')
        self.assertNotIn('PRIVATE',out.getvalue()); self.assertNotIn('/path',out.getvalue())

    def test_old_contract_rejects_workspace_schema_and_new_contract_verifies_all_hashes(self):
        rows=[(i,pg.digest(p.read_bytes())) for i,p in enumerate(pg.WORKSPACE_MIGRATIONS,1)]
        self.assertEqual(pg.migration_prefix(rows,workspace=True),rows)
        with self.assertRaisesRegex(pg.PersistenceError,'schema_mismatch'): pg.migration_prefix(rows)
        rows[-1]=(5,'0'*64)
        with self.assertRaisesRegex(pg.PersistenceError,'schema_mismatch'): pg.migration_prefix(rows,workspace=True)

    def test_invalid_direct_scope_does_not_touch_connection(self):
        conn=Mock()
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_input_invalid'):
            with ws.scope(conn,'../B'): pass
        conn.execute.assert_not_called()


@unittest.skipUnless(os.environ.get('CANCA_TEST_WORKSPACE_POSTGRES')=='1', 'workspace PostgreSQL opt-in required')
class WorkspacePostgreSQLTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.store,self.directory=fixture(Path(self.temp.name))
        self.conn=pg.open_connection(); self.addCleanup(self.conn.close)
        self.conn.execute('DROP SCHEMA IF EXISTS canca CASCADE')
        pg.migrate(self.conn)
        pg.index_import(self.conn,pg.prepare_import(self.store,self.directory))
        if hasattr(self,'seed_legacy'):self.seed_legacy()
        self.before=self.legacy_rows()
        self.bytes_before={str(p.relative_to(self.store)):pg.digest(p.read_bytes()) for p in self.store.rglob('*') if p.is_file()}
        self.assertEqual(pg.migrate(self.conn,workspace=True)['migration'],5)
        from psycopg import sql
        for role in ('canca_ws_a','canca_ws_b','canca_ws_writer'):
            if not self.conn.execute('SELECT 1 FROM pg_roles WHERE rolname=%s',(role,)).fetchone():
                self.conn.execute(sql.SQL('CREATE ROLE {} NOLOGIN NOSUPERUSER NOBYPASSRLS').format(sql.Identifier(role)))
            self.conn.execute(sql.SQL('GRANT USAGE ON SCHEMA canca TO {}').format(sql.Identifier(role)))
            self.conn.execute(sql.SQL('GRANT SELECT ON canca.schema_migrations,canca.workspace_grants,canca.workspaces,'
                'canca.workspace_sites,canca.workspace_environments,canca.workspace_assessments TO {}').format(sql.Identifier(role)))
        self.conn.execute('GRANT INSERT ON canca.workspace_sites,canca.workspace_environments TO canca_ws_writer')
        ws.create_workspace(self.conn,'A','Cliente A','Orizon LAB')
        ws.create_workspace(self.conn,'B','Cliente B')
        ws.grant_workspace(self.conn,'A','canca_ws_a','workspace:read')
        ws.grant_workspace(self.conn,'B','canca_ws_b','workspace:read')
        ws.grant_workspace(self.conn,'A','canca_ws_writer','workspace:write')
        # Setup data in B with trusted maintenance SQL; application roles cannot do so.
        self.conn.execute("INSERT INTO canca.workspace_sites VALUES ('B','same','B-private','azure',NULL)")
        self.conn.execute("INSERT INTO canca.workspace_sites VALUES ('B','B-parent','B-private-parent','on_premises',NULL)")
        self.conn.execute("INSERT INTO canca.workspace_environments VALUES ('B','same','B-private-env','production')")

    def legacy_rows(self):
        tables=('assessments','nodes','runs','imports','artifacts','assessment_events','assets',
                'asset_imports','asset_observations','asset_signals','finding_analyses','finding_evaluations','findings')
        return {t:self.conn.execute('SELECT to_jsonb(t)::text FROM canca.'+t+' t ORDER BY to_jsonb(t)::text').fetchall() for t in tables}

    @contextmanager
    def role(self, name):
        from psycopg import sql
        self.conn.execute(sql.SQL('SET ROLE {}').format(sql.Identifier(name)))
        try: yield
        finally: self.conn.execute('RESET ROLE')

    def test_migration_replay_preserves_legacy_rows_and_evidence_bytes(self):
        self.assertEqual(pg.migrate(self.conn,workspace=True)['status'],'already_migrated')
        self.assertEqual(self.before,self.legacy_rows())
        self.assertEqual(self.bytes_before,{str(p.relative_to(self.store)):pg.digest(p.read_bytes()) for p in self.store.rglob('*') if p.is_file()})
        with self.assertRaisesRegex(pg.PersistenceError,'schema_mismatch'): pg.show_import(self.conn,pg.prepare_import(self.store,self.directory)['bundle_id'])
        with self.assertRaisesRegex(pg.PersistenceError,'schema_mismatch'): pg.migrate(self.conn)

    def test_sql_rls_rejects_forged_workspace_context_and_cross_workspace_insert(self):
        from psycopg.errors import InsufficientPrivilege
        with self.role('canca_ws_writer'):
            with self.conn.transaction():
                self.conn.execute("SELECT set_config('canca.workspace_id','B',true)")
                self.assertEqual(self.conn.execute('SELECT * FROM canca.workspace_sites').fetchall(),[])
            with self.assertRaises(InsufficientPrivilege), self.conn.transaction():
                self.conn.execute("SELECT set_config('canca.workspace_id','B',true)")
                self.conn.execute("INSERT INTO canca.workspace_sites VALUES ('B','hack','hack','remote',NULL)")
            with self.assertRaises(InsufficientPrivilege):
                self.conn.execute("INSERT INTO canca.workspace_grants VALUES ('B','canca_ws_writer','workspace:write')")

    def test_registry_lists_only_owned_workspaces_and_admin_has_no_implicit_content_grant(self):
        self.assertEqual(ws.list_workspaces(self.conn)['workspaces'],[])
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_access_denied'): ws.list_items(self.conn,'A','sites')
        with self.role('canca_ws_a'):
            self.assertEqual([r['workspace_id'] for r in ws.list_workspaces(self.conn)['workspaces']],['A'])
            self.assertEqual(self.conn.execute('SELECT workspace_id FROM canca.workspaces').fetchall(),[('A',)])
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_access_denied'): ws.list_items(self.conn,'B','sites')
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_access_denied'): ws.list_items(self.conn,'missing','sites')

    def test_same_site_and_environment_ids_in_distinct_workspaces_are_independent(self):
        with self.role('canca_ws_writer'):
            ws.create_site(self.conn,'A','same','A-site','on_premises')
            ws.create_environment(self.conn,'A','same','A-env','lab')
            self.assertEqual(ws.list_items(self.conn,'A','sites')['items'][0]['name'],'A-site')
        with self.role('canca_ws_b'):
            self.assertEqual(ws.list_items(self.conn,'B','sites')['items'][-1]['name'],'B-private')
            self.assertEqual(ws.list_items(self.conn,'B','environments')['items'][0]['name'],'B-private-env')

    def test_parent_cannot_reference_other_workspace_and_context_resets_after_rollback(self):
        from psycopg.errors import ForeignKeyViolation
        with self.role('canca_ws_writer'):
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_parent_not_found'):
                ws.create_site(self.conn,'A','child','Child','remote','B-parent')
            with self.assertRaises(ForeignKeyViolation), ws.scope(self.conn,'A','workspace:write'):
                self.conn.execute("INSERT INTO canca.workspace_sites VALUES ('A','child','Child','remote','B-parent')")
            self.assertIn(self.conn.execute("SELECT current_setting('canca.workspace_id',true)").fetchone()[0],(None,''))
            self.assertEqual(ws.list_items(self.conn,'A','sites')['items'],[])

    def test_direct_multirow_cycle_is_rejected_and_valid_hierarchy_is_retained(self):
        from psycopg.errors import ForeignKeyViolation
        with self.role('canca_ws_writer'):
            with self.assertRaises(ForeignKeyViolation), ws.scope(self.conn,'A','workspace:write'):
                self.conn.execute("""INSERT INTO canca.workspace_sites VALUES
                    ('A','x','X','remote','y'),('A','y','Y','remote','x')""")
            ws.create_site(self.conn,'A','parent','Parent','on_premises')
            ws.create_site(self.conn,'A','child','Child','remote','parent')
            self.assertEqual(len(ws.list_items(self.conn,'A','sites')['items']),2)

    def test_reader_cannot_write_create_workspace_grant_or_bind_legacy(self):
        with self.role('canca_ws_a'):
            for call in (lambda:ws.create_workspace(self.conn,'C','C'),
                         lambda:ws.grant_workspace(self.conn,'B','canca_ws_a','workspace:read'),
                         lambda:ws.bind_assessment(self.conn,'A','LAB-001')):
                with self.assertRaisesRegex(pg.PersistenceError,'workspace_admin_required'): call()
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_access_denied'):
                ws.create_site(self.conn,'A','x','X','remote')

    def test_registration_replay_and_conflicts_preserve_original_values(self):
        self.assertEqual(ws.create_workspace(self.conn,'A','Cliente A','Orizon LAB')['status'],'already_registered')
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_conflict'): ws.create_workspace(self.conn,'A','Other')
        with self.role('canca_ws_writer'):
            for fun in (lambda name:ws.create_site(self.conn,'A','x',name,'remote'),
                        lambda name:ws.create_environment(self.conn,'A','x',name,'lab')):
                self.assertEqual(fun('X')['status'],'registered'); self.assertEqual(fun('X')['status'],'already_registered')
                with self.assertRaisesRegex(pg.PersistenceError,'workspace_conflict'): fun('Other')

    def test_explicit_legacy_mapping_does_not_grant_access_or_move_evidence(self):
        self.assertEqual(ws.bind_assessment(self.conn,'A','LAB-001')['status'],'assigned')
        self.assertEqual(ws.bind_assessment(self.conn,'A','LAB-001')['status'],'already_assigned')
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_assignment_conflict'): ws.bind_assessment(self.conn,'B','LAB-001')
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_assessment_not_found'): ws.bind_assessment(self.conn,'A','missing')
        with self.role('canca_ws_a'):
            self.assertEqual(ws.list_items(self.conn,'A','assessments')['items'],[{'assessment_id':'LAB-001'}])
        with self.role('canca_ws_b'):
            self.assertEqual(ws.list_items(self.conn,'B','assessments')['items'],[])
        self.assertEqual(self.before,self.legacy_rows())

    def test_revocation_is_idempotent_and_blocks_subsequent_reads(self):
        self.assertEqual(ws.revoke_workspace(self.conn,'A','canca_ws_a','workspace:read')['status'],'revoked')
        self.assertEqual(ws.revoke_workspace(self.conn,'A','canca_ws_a','workspace:read')['status'],'already_revoked')
        with self.role('canca_ws_a'):
            self.assertEqual(ws.list_workspaces(self.conn)['workspaces'],[])
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_access_denied'): ws.list_items(self.conn,'A','sites')
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_role_invalid'): ws.grant_workspace(self.conn,'A','no-such-role','workspace:read')
        current=self.conn.execute('SELECT current_user').fetchone()[0]
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_role_invalid'): ws.grant_workspace(self.conn,'A',current,'workspace:read')

    def test_pagination_and_context_reuse_never_include_other_workspace(self):
        with self.role('canca_ws_writer'):
            for x in ('a','b','c'): ws.create_site(self.conn,'A',x,x,'remote')
            one=ws.list_items(self.conn,'A','sites',limit=2)
            self.assertTrue(one['has_more']); self.assertEqual([r['site_id'] for r in one['items']],['a','b'])
            two=ws.list_items(self.conn,'A','sites',after=one['next_after'],limit=2)
            self.assertFalse(two['has_more']); self.assertEqual([r['site_id'] for r in two['items']],['c'])
            self.assertEqual(self.conn.execute('SELECT * FROM canca.workspace_sites').fetchall(),[])
        with self.role('canca_ws_b'):
            self.assertEqual(len(ws.list_items(self.conn,'B','sites')['items']),2)

    def test_partial_upgrade_rolls_back_and_keeps_legacy_usable(self):
        self.conn.execute('DROP SCHEMA canca CASCADE'); pg.migrate(self.conn)
        self.conn.execute('CREATE TABLE canca.workspace_environments (unexpected integer)')
        with self.assertRaises(Exception): pg.migrate(self.conn,workspace=True)
        self.assertIsNone(self.conn.execute("SELECT to_regclass('canca.workspaces')").fetchone()[0])
        self.assertEqual(self.conn.execute('SELECT version FROM canca.schema_migrations ORDER BY version').fetchall(),[(1,),(2,),(3,),(4,)])
        self.assertEqual(pg.migrate(self.conn)['status'],'already_migrated')

    def test_concurrent_registration_is_idempotent(self):
        barrier=threading.Barrier(2)
        def worker():
            with pg.open_connection() as conn:
                barrier.wait(timeout=10); return ws.create_workspace(conn,'C','C')['status']
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            jobs=[pool.submit(worker) for _ in range(2)]
            self.assertCountEqual([j.result(timeout=40) for j in jobs],['registered','already_registered'])

    def test_caller_transaction_is_not_committed(self):
        self.conn.autocommit=False; self.conn.execute('SELECT 1')
        with self.assertRaisesRegex(pg.PersistenceError,'connection_not_idle'): ws.list_workspaces(self.conn)
        self.assertNotEqual(self.conn.info.transaction_status,0); self.conn.rollback()


if __name__=='__main__': unittest.main()
