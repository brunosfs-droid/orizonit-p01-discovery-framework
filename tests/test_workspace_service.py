"""Bounded trusted source handles and coordinator-registered model operations."""
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
import P01_Workspace_Service as service
import test_workspace_coordinator as coordinator
import test_workspace_model as models
import test_postgres_assets as assets
pg,model,runtime=service.pg,service.model,service.runtime

class SourceRootTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name)
        self.store,self.directory=assets.fixture(self.base/'source')
        self.roots=service.SourceRoots({'A':self.store})
        self.bundle=self.directory.name
    def test_verified_handle_is_repeatable_and_binds_workspace_partition(self):
        self.assertEqual(self.roots.prepare('A','LAB-001',self.bundle),model.prepare_source(self.store,self.directory))
        with self.assertRaisesRegex(pg.PersistenceError,'workspace_access_denied'):
            self.roots.prepare('B','LAB-001',self.bundle)
    def test_invalid_handles_never_reach_source_reader(self):
        with patch.object(model,'prepare_source') as reader:
            for args in (('A','../LAB-001',self.bundle),('A','LAB-001','../'+self.bundle),
                         ('A','LAB-001','bnd-'+'a'*21),('A','LAB-001',None)):
                with self.assertRaises(pg.PersistenceError):self.roots.prepare(*args)
            reader.assert_not_called()
    def test_shared_nested_symlink_and_invalid_roots_rejected(self):
        child=self.store/'child';child.mkdir();alias=self.base/'alias';alias.symlink_to(self.store,target_is_directory=True)
        for roots in ({'A':self.store,'B':self.store},{'A':self.store,'B':child},{'A':alias},
                      {'A':self.base/'absent'},{'A':None},{'../A':self.store}):
            with self.assertRaises(pg.PersistenceError):service.SourceRoots(roots)
    def test_tampered_partition_fails_without_database_access(self):
        receipt=self.directory/'receipt/import-receipt.json';receipt.write_bytes(receipt.read_bytes()+b'tampered')
        with patch.object(pg,'open_connection') as connect:
            with self.assertRaises(pg.PersistenceError):self.roots.prepare('A','LAB-001',self.bundle)
            connect.assert_not_called()

class RegisteredOperationTests(unittest.TestCase):
    setUp=coordinator.CoordinatorTests.setUp
    cleanup=coordinator.CoordinatorTests.cleanup
    opened=coordinator.CoordinatorTests.opened
    def adapter(self):return service.WorkspaceService(self.c,service.SourceRoots({}))
    def test_read_is_registered_and_postcheck_suppresses_revoked_result(self):
        token=self.opened();adapter=self.adapter()
        def read(*args,**kwargs):
            self.assertEqual(len(self.c._jobs),1);self.grants['reader'].clear();return {'objects':['private']}
        with patch.object(model,'list_objects',side_effect=read):
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_access_denied'):adapter.objects('reader',token)
        self.assertFalse(self.c._jobs)
    def test_write_denied_before_model_and_source_access(self):
        token=self.opened();adapter=self.adapter()
        with patch.object(model,'declare_object') as write,patch.object(adapter.sources,'prepare') as prepare:
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_access_denied'):
                adapter.declare_object('reader',token)
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_access_denied'):
                adapter.preview_import('reader',token,'LAB-001','bnd-'+'a'*20)
            write.assert_not_called();prepare.assert_not_called()
    def test_close_tracks_source_preparation_and_blocks_late_preview(self):
        token=self.opened();adapter=self.adapter();ready=threading.Event();release=threading.Event();errors=[]
        def prepare(*args):ready.set();self.assertTrue(release.wait(3));return {}
        def work():
            try:adapter.preview_import('writer',token,'LAB-001','bnd-'+'a'*20)
            except pg.PersistenceError as exc:errors.append(str(exc))
        with patch.object(adapter.sources,'prepare',side_effect=prepare),patch.object(model,'preview_import') as preview:
            worker=threading.Thread(target=work);worker.start();self.assertTrue(ready.wait(3))
            try:
                with self.assertRaisesRegex(pg.PersistenceError,'workspace_close_pending'):
                    self.c.close('writer','A',token.generation,timeout=0)
            finally:release.set();worker.join(3)
            self.assertFalse(worker.is_alive());preview.assert_not_called()
        self.assertEqual(errors,['workspace_generation_stale']);self.assertFalse(self.c._jobs)
        self.c.close('writer','A',self.c.generation,timeout=0)
    def test_old_token_rejected_before_reader(self):
        token=self.opened();self.c.close('writer','A',token.generation);self.opened('B')
        with patch.object(model,'list_objects') as read:
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_generation_stale'):self.adapter().objects('writer',token)
            read.assert_not_called()

@unittest.skipUnless(os.environ.get('CANCA_TEST_WORKSPACE_POSTGRES')=='1','workspace SQL opt-in required')
class ServicePostgreSQLTests(unittest.TestCase):
    setUp=models.ModelPostgreSQLTests.setUp
    legacy_rows=models.ModelPostgreSQLTests.legacy_rows
    role=models.ModelPostgreSQLTests.role
    create=models.ModelPostgreSQLTests.create
    source=models.ModelPostgreSQLTests.source
    def adapter(self):return service.WorkspaceService(self.c,service.SourceRoots({}))
    def test_service_reads_and_writes_with_exact_generation(self):
        with self.role('canca_ws_writer'):
            adapter=self.adapter();token=adapter.active_token(self.conn,'A',self.token.generation)
            result=adapter.declare_object(self.conn,token,0,'request','server','host','Server',reason='LAB')
            self.assertEqual(result['generation'],token.generation);self.assertEqual(result['revision'],1)
            inventory=adapter.objects(self.conn,token)
            self.assertEqual(inventory['objects'][0]['object_id'],'server')
            self.assertEqual(adapter.object(self.conn,token,'server')['metadata']['origin'],'declared')
            self.assertFalse(self.c._jobs)
    def test_active_registry_hides_other_workspace_id_and_inventory(self):
        with self.role('canca_ws_writer'):
            self.c.close(self.conn,'A',self.token.generation)
            self.c.open(self.conn,'B',self.c.generation)
        with self.role('canca_ws_a'):
            result=self.adapter().registry(self.conn)
            self.assertIsNone(result['lifecycle']['workspace_id'])
            self.assertEqual([w['workspace_id'] for w in result['workspaces']],['A'])
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_access_denied'):
                self.adapter().active_token(self.conn,'B',self.c.generation)
    def test_stale_generation_and_revoked_grants_never_return_inventory(self):
        with self.role('canca_ws_writer'):
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_generation_stale'):
                self.adapter().active_token(self.conn,'A',self.token.generation-1)
        service.ws.revoke_workspace(self.conn,'A','canca_ws_a','workspace:read')
        with self.role('canca_ws_a'):
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_access_denied'):
                self.adapter().objects(self.conn,self.token)
    def test_verified_source_preview_and_apply_are_registered(self):
        store,directory=assets.fixture(self.assetbase/'service')
        adapter=service.WorkspaceService(self.c,service.SourceRoots({'A':store}))
        with self.role('canca_ws_writer'):
            plan=adapter.preview_import(self.conn,self.token,'LAB-001',directory.name)
            self.assertEqual(plan['generation'],self.token.generation)
            result=adapter.apply_import(self.conn,self.token,plan['plan_id'],'apply-service')
            self.assertEqual(result['revision'],1);self.assertFalse(self.c._jobs)
    def test_categories_real_sql_revision_and_role_isolation(self):
        adapter=self.adapter()
        self.create('server','host')
        self.create('switch','device')
        with self.role('canca_ws_a'):
            token=adapter.active_token(self.conn,'A',self.token.generation)
            compute=adapter.categories(self.conn,token,category='compute')
            self.assertEqual([x['object_id'] for x in compute['objects']],['server'])
            network=adapter.categories(self.conn,token,category='network',
                                       expected_revision=compute['revision'])
            self.assertEqual([x['object_id'] for x in network['objects']],['switch'])
            self.assertTrue(network['complete'])
            with self.assertRaisesRegex(pg.PersistenceError,'model_revision_stale'):
                adapter.categories(self.conn,token,category='network',
                                   expected_revision=compute['revision']-1)
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_generation_stale'):
                adapter.categories(self.conn,runtime.Token('B',token.generation,token.lease_id),
                                   category='compute')
        service.ws.revoke_workspace(self.conn,'A','canca_ws_a','workspace:read')
        with self.role('canca_ws_a'):
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_access_denied'):
                adapter.categories(self.conn,self.token,category='network')

    def test_categories_switching_workspace_never_leaks_records(self):
        adapter=self.adapter()
        self.create('a-only','host')
        with self.role('canca_ws_writer'):
            self.c.close(self.conn,'A',self.token.generation)
            other=self.c.open(self.conn,'B',self.c.generation)
            result=adapter.categories(self.conn,other,category='compute')
            self.assertEqual(result['workspace_id'],'B')
            self.assertEqual(result['objects'],[])
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_generation_stale'):
                adapter.categories(self.conn,self.token,category='compute')
        self.assertFalse(self.c._jobs)

    def test_connection_target_mismatch_rejected_before_sql(self):
        with patch.object(runtime,'connection_target',return_value=('other',5432,'other')):
            for call in (lambda:self.adapter().registry(self.conn),
                         lambda:self.adapter().active_token(self.conn,'A',self.token.generation)):
                with self.assertRaisesRegex(pg.PersistenceError,'workspace_connection_mismatch'):call()
