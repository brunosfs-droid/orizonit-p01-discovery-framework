"""Verified asset sources everywhere; database tests only on disposable PostgreSQL."""
import base64
import concurrent.futures
import copy
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

import test_offline_import as source
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'persistence'))
import P01_Asset_Registry as registry
import P01_Assessment_Lifecycle as life
pg = registry.pg


def fixture(base, store=None, run='R1', assessment='LAB-001', ip='192.0.2.10',
            fqdn='host01.corp.example.test', serial='SERIAL-001', key=None,
            credentialed=True, auth=True, extras=None, forged=False, mac=None):
    base.mkdir(parents=True, exist_ok=True)
    network = source.network_doc()
    network['assets'][0].update(ip=ip,hostname=fqdn,mac=mac or '00:11:22:33:44:'+format(int(ip.split('.')[-1]),'02x'))
    # Bundles require a target artifact. credentialed=False provides an auth-failed
    # target with no qualified identifier, preserving the existing bundle contract.
    target = source.target_doc()
    target['action'].update(target_ip=ip,hostname=fqdn)
    target['authentication']['success'] = auth and credentialed
    target['enrichment']['identity'].update(computer_name=fqdn.split('.')[0],fqdn=fqdn,
                                            serial_number=serial if credentialed else '')
    target['enrichment']['network']['interfaces'][0]['ipv4'][0]['address'] = ip
    if key:
        target['authentication']['server_host_key'] = {'fingerprint_sha256':key}
    targets=[source.write_json(base/'target.json',target,sidecar=True)]
    if extras:
        network['assets'].extend(extras)
    network_path=source.write_json(base/'network.json',network,sidecar=True)
    manifest=source.manifest_doc();manifest['assessment_id']=assessment
    manifest_path=source.write_json(base/'assessment.json',manifest)
    resolved=registry.resolver.resolve(network_path,targets,manifest_path)
    if forged:
        resolved['assets'][0]['identifiers']=[{'type':'serial_number','value':'FORGED'}]
        resolved['assets'][0]['identity']['fqdn']='forged.example.test'
    resolved_path=source.write_json(base/'resolved.json',resolved,sidecar=True)
    bundle=base/'bundle.p01bundle'
    source.bundle_mod.create_bundle(bundle,assessment,run,'NODE-01',network_path,targets,manifest_path,
                                    resolved_path,require_evidence_sidecars=True)
    store=store or base/'store'
    imported=source.mod.import_bundle(bundle,store,process=False,require_outer_sidecar=True)
    return store,Path(imported['import_dir'])


class AssetSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name)
        self.store,self.directory=fixture(self.base/'first')

    def test_source_is_repeatable_read_only_and_binds_provenance(self):
        before={str(p):pg.digest(p.read_bytes()) for p in self.store.rglob('*') if p.is_file()}
        one=registry.prepare_assets(self.store,self.directory)
        self.assertEqual(one,registry.prepare_assets(self.store,self.directory))
        registry.validate_projection(one)
        signal=next(s for s in one['observations'][0]['signals'] if s['kind']=='serial_number')
        self.assertEqual(signal['value'],'serial-001');self.assertTrue(signal['qualified'])
        refs=one['observations'][0]['source_refs']
        self.assertTrue(all(r in one['import']['artifacts'] for r in refs))
        self.assertEqual(before,{str(p):pg.digest(p.read_bytes()) for p in self.store.rglob('*') if p.is_file()})

    def test_tampered_receipt_and_raw_rejected_before_connect(self):
        receipt=self.directory/'receipt/import-receipt.json'
        receipt.write_bytes(receipt.read_bytes()+b' ')
        out=io.StringIO()
        with patch.object(pg,'open_connection') as connect,redirect_stdout(out):
            self.assertEqual(registry.cli(['project-import','--store-dir',str(self.store),'--import-dir',str(self.directory)]),2)
        connect.assert_not_called()
        self.assertEqual(json.loads(out.getvalue())['error_code'],'receipt_integrity_failed')

    def test_embedded_resolver_is_not_identity_authority(self):
        store,directory=fixture(self.base/'forged',forged=True)
        p=registry.prepare_assets(store,directory)
        signals=p['observations'][0]['signals']
        self.assertIn('serial-001',[s['value'] for s in signals])
        self.assertNotIn('FORGED',[s['value'] for s in signals])
        self.assertNotIn('forged.example.test',[s['value'] for s in signals])

    def test_failed_auth_and_generic_serial_do_not_qualify(self):
        store,directory=fixture(self.base/'auth',auth=False)
        self.assertFalse(any(s['qualified'] for s in registry.prepare_assets(store,directory)['observations'][0]['signals']))
        store,directory=fixture(self.base/'generic',serial='To Be Filled By O.E.M.')
        self.assertFalse(any(s['kind']=='serial_number' for s in registry.prepare_assets(store,directory)['observations'][0]['signals']))

    def test_ssh_base64_case_is_preserved_from_raw_source(self):
        key='SHA256:'+base64.b64encode(bytes(range(32))).decode().rstrip('=')
        store,directory=fixture(self.base/'key',key=key)
        signals=registry.prepare_assets(store,directory)['observations'][0]['signals']
        self.assertIn(key,[s['value'] for s in signals if s['kind']=='ssh_host_key_sha256'])
        self.assertIsNone(registry.fingerprint('SHA256:placeholder'))

    def test_duplicate_local_ids_are_preserved_by_ordinal_under_review(self):
        other=copy.deepcopy(source.network_doc()['assets'][0]);other['ip']='192.0.2.11'
        store,directory=fixture(self.base/'duplicate',credentialed=False,extras=[other])
        observations=registry.prepare_assets(store,directory)['observations']
        self.assertEqual(len(observations),2)
        self.assertEqual(observations[0]['source_asset_id'],observations[1]['source_asset_id'])
        self.assertTrue(all(o['local_review'] for o in observations))
        self.assertEqual([o['ordinal'] for o in observations],[0,1])

    def test_malformed_projection_invalid_queries_and_driver_errors_are_redacted(self):
        p=registry.prepare_assets(self.store,self.directory)
        p['observations'][0]['signals'][0]['sources']=['outside.json']
        with self.assertRaisesRegex(pg.PersistenceError,'asset_input_invalid'):
            registry.validate_projection(p)
        for args in (['show-import','--bundle-id','bad'],['show-import','--bundle-id','bnd-'+'0'*20,'--limit','101'],
                     ['show-asset','--assessment-id','../escape','--asset-id','cas-'+'0'*32]):
            with patch.object(pg,'open_connection') as connect,redirect_stdout(io.StringIO()):
                self.assertEqual(registry.cli(args),2);connect.assert_not_called()
        out=io.StringIO()
        with patch.object(pg,'open_connection',side_effect=RuntimeError('password=DO-NOT-LOG')),redirect_stdout(out):
            self.assertEqual(registry.cli(['show-import','--bundle-id','bnd-'+'0'*20]),2)
        self.assertNotIn('DO-NOT-LOG',out.getvalue())
        self.assertEqual(json.loads(out.getvalue())['error_code'],'database_failed')


@unittest.skipUnless(os.environ.get('CANCA_TEST_POSTGRES')=='1','real PostgreSQL integration opt-in required')
class PostgreSQLAssetTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.store=self.base/'store';self.counter=0
        self.conn=pg.open_connection();self.addCleanup(self.conn.close)
        self.conn.execute('DROP SCHEMA IF EXISTS canca CASCADE');pg.migrate(self.conn)

    def source(self,**kwargs):
        self.counter+=1
        _,directory=fixture(self.base/f'source-{self.counter}',store=self.store,run=f'R{self.counter}',**kwargs)
        return registry.prepare_assets(self.store,directory)

    def project(self,p):
        pg.index_import(self.conn,p['import'])
        return registry.project_import(self.conn,p)

    def observations(self,p,**kwargs):
        return registry.show_import(self.conn,p['import']['bundle_id'],**kwargs)['observations']

    def counts(self):
        return tuple(self.conn.execute('SELECT count(*) FROM canca.'+t).fetchone()[0]
                     for t in ('assets','asset_imports','asset_observations','asset_signals'))

    def test_upgrade_preserves_import_and_lifecycle_without_asset_backfill(self):
        self.conn.execute('DROP SCHEMA canca CASCADE');self.conn.execute('CREATE SCHEMA canca')
        self.conn.execute('CREATE TABLE canca.schema_migrations (version integer PRIMARY KEY,sha256 text NOT NULL)')
        for i,path in enumerate(pg.MIGRATIONS[:2],1):
            self.conn.execute(path.read_text());self.conn.execute('INSERT INTO canca.schema_migrations VALUES (%s,%s)',(i,pg.digest(path.read_bytes())))
        p=self.source();pg.index_import(self.conn,p['import'])
        life.transition(self.conn,'LAB-001',0,'start','active','operator')
        life.transition(self.conn,'LAB-001',1,'finish','completed','operator')
        before=life.show_assessment(self.conn,'LAB-001')
        with self.assertRaisesRegex(pg.PersistenceError,'schema_required'):
            registry.project_import(self.conn,p)
        self.assertEqual(pg.migrate(self.conn)['migration'],3)
        self.assertEqual(self.counts(),(0,0,0,0))
        self.project(p)
        self.assertEqual(life.show_assessment(self.conn,'LAB-001'),before)
        self.assertEqual(pg.show_import(self.conn,p['import']['bundle_id'])['status'],'found')

    def test_replay_preserves_central_id_and_rows(self):
        p=self.source();self.assertEqual(self.project(p)['status'],'projected')
        before=self.observations(p);counts=self.counts()
        self.assertRegex(before[0]['asset_id'],r'^cas-[0-9a-f]{32}$')
        self.assertEqual(self.project(p)['status'],'already_projected')
        self.assertEqual(self.observations(p),before);self.assertEqual(self.counts(),counts)

    def test_two_credentialed_categories_link_across_runs_despite_ip_change(self):
        first=self.source();self.project(first)
        second=self.source(ip='192.0.2.11');self.project(second)
        self.assertEqual(self.observations(second)[0]['decision'],'linked')
        self.assertEqual(self.observations(first)[0]['asset_id'],self.observations(second)[0]['asset_id'])
        self.assertEqual(registry.show_asset(self.conn,'LAB-001',self.observations(first)[0]['asset_id'])['observation_count'],2)

    def test_same_ip_hostname_without_strong_identity_never_links(self):
        first=self.source(credentialed=False);self.project(first)
        second=self.source(credentialed=False);self.project(second)
        self.assertEqual(self.observations(second)[0]['decision'],'review_required')
        self.assertNotEqual(self.observations(first)[0]['asset_id'],self.observations(second)[0]['asset_id'])

    def test_reused_ip_and_changed_serial_are_reviewed(self):
        first=self.source();self.project(first)
        second=self.source(fqdn='replacement.corp.example.test',serial='SERIAL-002');self.project(second)
        self.assertEqual(self.observations(second)[0]['decision'],'review_required')
        self.assertEqual(self.observations(second)[0]['reason_code'],'strong_conflict')

    def test_shared_serial_without_matching_fqdn_is_not_correlated(self):
        first=self.source();self.project(first)
        second=self.source(ip='192.0.2.11',fqdn='clone.corp.example.test');self.project(second)
        self.assertEqual(self.observations(second)[0]['reason_code'],'uncorroborated_candidate')
        self.assertNotEqual(self.observations(first)[0]['asset_id'],self.observations(second)[0]['asset_id'])

    def test_local_conflicts_duplicate_ids_preserved_without_global_link(self):
        other=copy.deepcopy(source.network_doc()['assets'][0]);other['ip']='192.0.2.11'
        p=self.source(credentialed=False,extras=[other]);self.project(p)
        rows=self.observations(p)
        self.assertEqual(len(rows),2)
        self.assertTrue(all(o['reason_code']=='local_conflict' and o['decision']=='review_required' for o in rows))
        self.assertNotEqual(rows[0]['asset_id'],rows[1]['asset_id'])

    def test_multiple_candidates_do_not_choose_a_winner(self):
        first=self.source(serial='SERIAL-001');self.project(first)
        second=self.source(serial='SERIAL-002');self.project(second)
        # Second is reviewed. Third has disjoint context. The next raw observation
        # corroborates the first identity but carries a MAC already seen on the third.
        third=self.source(ip='192.0.2.12',fqdn='third.other.test',serial='SERIAL-003');
        self.project(third)
        current=self.source(mac='00:11:22:33:44:0c')
        self.project(current)
        result=self.observations(current)[0]
        self.assertEqual(result['reason_code'],'multiple_candidates');self.assertEqual(len(result['candidates']),2)

    def test_assessment_scope_prevents_cross_assessment_association(self):
        first=self.source();self.project(first)
        other=self.source(assessment='OTHER-LAB');self.project(other)
        a=self.observations(first)[0]['asset_id'];b=self.observations(other)[0]['asset_id']
        self.assertNotEqual(a,b)
        self.assertEqual(registry.show_asset(self.conn,'OTHER-LAB',a)['status'],'not_found')

    def test_index_required_index_drift_and_projection_drift_preserve_rows(self):
        p=self.source()
        with self.assertRaisesRegex(pg.PersistenceError,'import_required'):
            registry.project_import(self.conn,p)
        self.assertEqual(self.counts(),(0,0,0,0))
        self.project(p);before=self.counts()
        changed=copy.deepcopy(p);changed['observations'][0]['local_review']=True
        with self.assertRaisesRegex(pg.PersistenceError,'asset_projection_conflict'):
            registry.project_import(self.conn,changed)
        self.conn.execute("UPDATE canca.imports SET projection_sha256=%s WHERE bundle_id=%s",('0'*64,p['import']['bundle_id']))
        with self.assertRaisesRegex(pg.PersistenceError,'import_conflict'):
            registry.project_import(self.conn,p)
        self.assertEqual(self.counts(),before)

    def test_failure_rolls_back_entire_projection_but_preserves_import(self):
        p=self.source();pg.index_import(self.conn,p['import'])
        self.conn.execute("CREATE FUNCTION canca.fail_observation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic'; END $$")
        self.conn.execute('CREATE TRIGGER fail_observation BEFORE INSERT ON canca.asset_observations FOR EACH ROW EXECUTE FUNCTION canca.fail_observation()')
        with self.assertRaises(Exception):registry.project_import(self.conn,p)
        self.assertEqual(self.counts(),(0,0,0,0))
        self.assertEqual(pg.show_import(self.conn,p['import']['bundle_id'])['status'],'found')
        self.conn.execute('DROP TRIGGER fail_observation ON canca.asset_observations')
        self.assertEqual(registry.project_import(self.conn,p)['status'],'projected')

    def concurrent(self,projections):
        barrier=threading.Barrier(2)
        def invoke(p):
            with pg.open_connection() as conn:
                barrier.wait(timeout=10);return registry.project_import(conn,p)['status']
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:return list(pool.map(invoke,projections))

    def test_concurrent_same_bundle_converges(self):
        p=self.source();pg.index_import(self.conn,p['import'])
        self.assertCountEqual(self.concurrent([p,p]),['projected','already_projected'])
        self.assertEqual(self.counts()[:3],(1,1,1))

    def test_concurrent_different_bundles_serialize_identity_decisions(self):
        a=self.source();b=self.source(ip='192.0.2.11')
        for p in (a,b):pg.index_import(self.conn,p['import'])
        self.assertEqual(self.concurrent([a,b]),['projected','projected'])
        self.assertEqual(self.observations(a)[0]['asset_id'],self.observations(b)[0]['asset_id'])
        self.assertEqual(self.counts()[:3],(1,2,2))

    def test_operator_insert_role_cannot_relink_or_delete_observations(self):
        p=self.source();pg.index_import(self.conn,p['import'])
        self.conn.execute("DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='canca_test_assets') THEN CREATE ROLE canca_test_assets; END IF; END $$")
        self.conn.execute('GRANT USAGE ON SCHEMA canca TO canca_test_assets')
        self.conn.execute('GRANT SELECT ON canca.schema_migrations,canca.imports TO canca_test_assets')
        self.conn.execute('GRANT SELECT,INSERT ON canca.assets,canca.asset_imports,canca.asset_observations,canca.asset_signals TO canca_test_assets')
        self.conn.execute('SET ROLE canca_test_assets')
        try:
            self.assertEqual(registry.project_import(self.conn,p)['status'],'projected')
            self.assertEqual(registry.show_import(self.conn,p['import']['bundle_id'])['status'],'found')
            for sql in ('DELETE FROM canca.assets',"UPDATE canca.asset_observations SET asset_id='cas-"+'0'*32+"'",'CREATE TABLE canca.unwanted (id integer)'):
                with self.assertRaises(Exception):self.conn.execute(sql)
        finally:self.conn.execute('RESET ROLE')

    def test_read_only_pagination_missing_lookup_and_source_provenance(self):
        other=copy.deepcopy(source.network_doc()['assets'][0]);other.update(ip='192.0.2.11',hostname='other.corp.example.test')
        p=self.source(credentialed=False,extras=[other]);self.project(p);before=self.counts()
        first=registry.show_import(self.conn,p['import']['bundle_id'],limit=1)
        second=registry.show_import(self.conn,p['import']['bundle_id'],after_ordinal=first['next_after_ordinal'],limit=1)
        self.assertTrue(first['has_more']);self.assertFalse(second['has_more'])
        self.assertEqual([o['ordinal'] for o in first['observations']+second['observations']],[0,1])
        refs=first['observations'][0]['source_refs'];self.assertTrue(all(r in p['import']['artifacts'] for r in refs))
        self.assertEqual(registry.show_import(self.conn,'bnd-'+'0'*20)['status'],'not_found')
        self.assertEqual(self.counts(),before)

    def test_migration_drift_is_rejected(self):
        self.conn.execute("UPDATE canca.schema_migrations SET sha256='bad' WHERE version=3")
        p=self.source()
        with self.assertRaisesRegex(pg.PersistenceError,'schema_mismatch'):registry.project_import(self.conn,p)
        self.assertEqual(self.counts(),(0,0,0,0))

    def test_conflicting_ssh_keys_with_case_difference_do_not_link(self):
        key='SHA256:'+base64.b64encode(bytes(32)).decode().rstrip('=')
        changed='SHA256:a'+key[8:]
        self.assertIsNotNone(registry.fingerprint(changed))
        first=self.source(key=key);self.project(first)
        second=self.source(key=changed);self.project(second)
        self.assertEqual(self.observations(second)[0]['reason_code'],'strong_conflict')
        self.assertNotEqual(self.observations(first)[0]['asset_id'],self.observations(second)[0]['asset_id'])

    def test_candidate_limit_never_hides_an_automatic_winner(self):
        p=self.source();self.project(p)
        # Simulate externally populated registry metadata to exercise the defensive
        # bound; direct SQL here is test setup in the disposable administrator DB.
        for i in range(101):
            asset='cas-'+format(i,'032x')
            self.conn.execute('INSERT INTO canca.assets (assessment_id,asset_id) VALUES (%s,%s)',('LAB-001',asset))
            self.conn.execute("INSERT INTO canca.asset_signals VALUES (%s,%s,'serial_number','serial-001',true,true)",('LAB-001',asset))
        next_source=self.source();self.project(next_source)
        row=self.observations(next_source)[0]
        self.assertEqual(row['decision'],'review_required')
        self.assertEqual(row['reason_code'],'candidate_bound_exceeded')
        self.assertTrue(row['candidates_truncated']);self.assertEqual(len(row['candidates']),100)

    def test_failed_third_migration_preserves_existing_data_and_versions(self):
        self.conn.execute('DROP SCHEMA canca CASCADE');self.conn.execute('CREATE SCHEMA canca')
        self.conn.execute('CREATE TABLE canca.schema_migrations (version integer PRIMARY KEY,sha256 text NOT NULL)')
        for i,path in enumerate(pg.MIGRATIONS[:2],1):
            self.conn.execute(path.read_text());self.conn.execute('INSERT INTO canca.schema_migrations VALUES (%s,%s)',(i,pg.digest(path.read_bytes())))
        p=self.source();pg.index_import(self.conn,p['import'])
        before=pg.show_import(self.conn,p['import']['bundle_id'])
        self.conn.execute('CREATE TABLE canca.assets (foreign_column integer)')
        with self.assertRaises(Exception):pg.migrate(self.conn)
        self.assertEqual(self.conn.execute('SELECT version FROM canca.schema_migrations ORDER BY version').fetchall(),[(1,),(2,)])
        self.assertIsNone(self.conn.execute("SELECT to_regclass('canca.asset_imports')").fetchone()[0])
        self.assertEqual(pg.show_import(self.conn,p['import']['bundle_id']),before)
