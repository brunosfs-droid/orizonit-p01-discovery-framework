"""Source coverage boundaries and real PostgreSQL immutable occurrence tests."""
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
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'persistence'))
import P01_Findings as findings
pg = findings.pg
assets = findings.assets


def target(disabled=True, broken=True):
    doc = source.target_doc()
    doc['enrichment']['security'] = {
        'firewall_profiles':[{'name':name,'enabled':not(disabled and name=='Public')} for name in ('Domain','Private','Public')],
        'secure_channel_checked':True,'secure_channel_healthy':not broken}
    doc['enrichment']['collection_sections'] = [dict(section=name,success=True,status_code=0) for name in ('identity','firewall','secure_channel')]
    return doc


def fixture(base,store=None,run='R1',doc=None,extras=None):
    base.mkdir(parents=True,exist_ok=True)
    network = source.network_doc()
    if extras:
        network['assets'].extend(extras)
    network_path = source.write_json(base/'network.json',network,sidecar=True)
    target_path = source.write_json(base/'target.json',doc or target(),sidecar=True)
    manifest_path = source.write_json(base/'assessment.json',source.manifest_doc())
    result = assets.resolver.resolve(network_path,[target_path],manifest_path)
    resolved_path = source.write_json(base/'resolved.json',result,sidecar=True)
    bundle = base/'bundle.p01bundle'
    source.bundle_mod.create_bundle(bundle,'LAB-001',run,'NODE-01',network_path,[target_path],manifest_path,
                                   resolved_path,require_evidence_sidecars=True)
    store = store or base/'store'
    imported = source.mod.import_bundle(bundle,store,process=False,require_outer_sidecar=True)
    return store,Path(imported['import_dir'])


class FindingSourceTests(unittest.TestCase):
    def test_positive_negative_and_partial_coverage(self):
        for disabled,broken in ((True,True),(False,False)):
            doc = target(disabled,broken)
            self.assertEqual(findings.evaluate(doc,'WIN-FW-001')[0],'finding' if disabled else 'no_finding')
            self.assertEqual(findings.evaluate(doc,'WIN-AD-001')[0],'finding' if broken else 'no_finding')
        doc = target(); doc['enrichment']['collection_status']='collected_with_section_failures'
        doc['enrichment']['collection_sections'].append(dict(section='hotfixes',success=False,status_code=1))
        self.assertEqual(findings.evaluate(doc,'WIN-FW-001')[0],'finding')

    def test_missing_false_auth_or_failed_section_is_not_a_clean_result(self):
        for mutate in (lambda d:d['authentication'].update(success=False),
                       lambda d:d['enrichment'].update(collection_status='auth_only'),
                       lambda d:d['enrichment'].pop('collection_sections'),
                       lambda d:d['enrichment']['collection_sections'][1].update(success=False),
                       lambda d:d['enrichment']['collection_sections'][1].update(status_code=True),
                       lambda d:d['enrichment']['collection_sections'].append(dict(section='firewall',success=True,status_code=0))):
            doc=target();mutate(doc)
            self.assertEqual(findings.evaluate(doc,'WIN-FW-001')[0],'insufficient_evidence')
        self.assertEqual(findings.evaluate(source.target_doc(),'WIN-FW-001')[0],'insufficient_evidence')

    def test_firewall_requires_complete_distinct_typed_profiles(self):
        for profiles in ([],[{'name':'Public','enabled':False}],
                         [{'name':n,'enabled':'False'} for n in ('Domain','Private','Public')],
                         [{'name':n,'enabled':True} for n in ('Public','Public','Private')],
                         [{'name':n,'enabled':True} for n in ('Domain','Private','Other')]):
            doc=target();doc['enrichment']['security']['firewall_profiles']=profiles
            self.assertEqual(findings.evaluate(doc,'WIN-FW-001')[0],'insufficient_evidence')

    def test_domain_membership_dc_and_unknown_are_distinct(self):
        for member,role,expected in ((False,0,'not_applicable'),(True,5,'not_applicable'),
                                     (True,1,'finding'),(True,0,'insufficient_evidence'),(True,True,'insufficient_evidence')):
            doc=target();doc['enrichment']['identity'].update(part_of_domain=member,domain_role=role)
            self.assertEqual(findings.evaluate(doc,'WIN-AD-001')[0],expected)
        for checked,healthy in ((False,False),(True,None),(True,'False')):
            doc=target();doc['enrichment']['security'].update(secure_channel_checked=checked,secure_channel_healthy=healthy)
            self.assertEqual(findings.evaluate(doc,'WIN-AD-001')[0],'insufficient_evidence')

    def test_ssh_is_not_supported_and_does_not_invoke_any_collector(self):
        doc=target();doc['action']['protocol']='ssh'
        for rule in findings.RULES:
            self.assertEqual(findings.evaluate(doc,rule),('not_supported',{},[]))

    def test_source_repeatable_read_only_with_exact_inventory_and_catalog(self):
        with tempfile.TemporaryDirectory() as td:
            store,directory=fixture(Path(td))
            before={str(p):pg.digest(p.read_bytes()) for p in store.rglob('*') if p.is_file()}
            one=findings.prepare_findings(store,directory)
            self.assertEqual(one,findings.prepare_findings(store,directory))
            self.assertEqual(len(one['evaluations']),2)
            self.assertTrue(all(r['source_ref'] in one['assets']['import']['artifacts'] for r in one['evaluations']))
            self.assertEqual(one['catalog_sha256'],pg.digest(findings.CATALOG_PATH.read_bytes()))
            self.assertEqual(before,{str(p):pg.digest(p.read_bytes()) for p in store.rglob('*') if p.is_file()})

    def test_tampering_is_rejected_before_connect(self):
        for mode in ('receipt','raw','alias'):
            with tempfile.TemporaryDirectory() as td:
                store,directory=fixture(Path(td))
                if mode=='receipt':
                    path=directory/'receipt/import-receipt.json';path.write_bytes(path.read_bytes()+b' ')
                elif mode=='raw':
                    receipt=pg.read_json((directory/'receipt/import-receipt.json').read_bytes())
                    path=directory/receipt['raw_bundle'];path.write_bytes(path.read_bytes()+b' ')
                else:
                    alias=store/'alias';alias.symlink_to(directory,target_is_directory=True);directory=alias
                with patch.object(pg,'open_connection') as connect,redirect_stdout(io.StringIO()):
                    self.assertEqual(findings.cli(['project-import','--store-dir',str(store),'--import-dir',str(directory)]),2)
                connect.assert_not_called()

    def test_projection_cannot_claim_external_source_catalog_or_asset(self):
        with tempfile.TemporaryDirectory() as td:
            store,directory=fixture(Path(td));p=findings.prepare_findings(store,directory)
            for mutate in (lambda d:d['evaluations'][0]['source_ref'].update(path='../outside'),
                           lambda d:d.update(catalog_sha256='0'*64),
                           lambda d:d['evaluations'][0].update(observation_ordinal=999),
                           lambda d:d['evaluations'][0].update(evidence_refs=['/password']),
                           lambda d:d['evaluations'].pop()):
                doc=copy.deepcopy(p);mutate(doc)
                with self.assertRaises(pg.PersistenceError):findings.validate_projection(doc)

    def test_invalid_query_and_driver_error_are_redacted(self):
        with patch.object(pg,'open_connection') as connect,redirect_stdout(io.StringIO()):
            self.assertEqual(findings.cli(['show-import','--bundle-id','bad']),2)
        connect.assert_not_called()
        out=io.StringIO()
        with patch.object(pg,'open_connection',side_effect=RuntimeError('password=NEVER-LOG')),redirect_stdout(out):
            self.assertEqual(findings.cli(['show-import','--bundle-id','bnd-'+'0'*20]),2)
        self.assertNotIn('NEVER-LOG',out.getvalue());self.assertEqual(json.loads(out.getvalue())['error_code'],'database_failed')


@unittest.skipUnless(os.environ.get('CANCA_TEST_POSTGRES')=='1','real PostgreSQL integration opt-in required')
class PostgreSQLFindingTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.store=self.base/'store';self.counter=0
        self.conn=pg.open_connection();self.addCleanup(self.conn.close)
        self.conn.execute('DROP SCHEMA IF EXISTS canca CASCADE');pg.migrate(self.conn)

    def source(self,**kwargs):
        self.counter+=1
        _,directory=fixture(self.base/f'source-{self.counter}',store=self.store,run=f'R{self.counter}',**kwargs)
        return findings.prepare_findings(self.store,directory)

    def prereqs(self,p):
        pg.index_import(self.conn,p['assets']['import']);assets.project_import(self.conn,p['assets'])

    def counts(self):
        return tuple(self.conn.execute('SELECT count(*) FROM canca.'+table).fetchone()[0]
                     for table in ('finding_analyses','finding_evaluations','findings'))

    def show(self,p,**kwargs):
        return findings.show_import(self.conn,p['assets']['import']['bundle_id'],**kwargs)

    def test_requires_matching_import_and_asset_projection_without_writes(self):
        p=self.source()
        with self.assertRaisesRegex(pg.PersistenceError,'import_required'):findings.project_import(self.conn,p)
        pg.index_import(self.conn,p['assets']['import'])
        with self.assertRaisesRegex(pg.PersistenceError,'assets_required'):findings.project_import(self.conn,p)
        assets.project_import(self.conn,p['assets'])
        self.conn.execute("UPDATE canca.asset_imports SET projection_sha256=%s",('0'*64,))
        with self.assertRaisesRegex(pg.PersistenceError,'asset_projection_conflict'):findings.project_import(self.conn,p)
        self.conn.execute('UPDATE canca.asset_imports SET projection_sha256=%s',(pg.digest(pg.canonical(p['assets'])),))
        self.conn.execute('UPDATE canca.imports SET projection_sha256=%s',('0'*64,))
        with self.assertRaisesRegex(pg.PersistenceError,'import_conflict'):findings.project_import(self.conn,p)
        self.assertEqual(self.counts(),(0,0,0))

    def test_replay_preserves_ids_rows_and_complete_source_link(self):
        p=self.source();self.prereqs(p);one=findings.project_import(self.conn,p)
        self.assertEqual(one['status'],'projected');self.assertEqual(one['finding_count'],2)
        before=self.show(p);self.assertEqual(self.counts(),(1,2,2))
        self.assertEqual(findings.project_import(self.conn,p)['status'],'already_projected')
        self.assertEqual(self.show(p),before);self.assertEqual(self.counts(),(1,2,2))
        for row in before['evaluations']:
            self.assertRegex(row['asset_id'],r'^cas-[0-9a-f]{32}$')
            self.assertEqual(row['finding_status'],'Open');self.assertEqual(row['link_state'],'unique_observation')
            self.assertTrue(row['evidence_refs']);self.assertRegex(row['finding_id'],r'^fnd-[0-9a-f]{32}$')

    def test_projection_drift_requires_review_and_preserves_old_findings(self):
        p=self.source();self.prereqs(p);findings.project_import(self.conn,p);before=self.show(p)
        changed=copy.deepcopy(p)
        row=next(r for r in changed['evaluations'] if r['rule_id']=='WIN-FW-001')
        row['evidence']['disabled_profiles']=['domain']
        with self.assertRaisesRegex(pg.PersistenceError,'finding_projection_conflict'):findings.project_import(self.conn,changed)
        self.assertEqual(self.show(p),before)

    def test_later_clean_collection_does_not_close_previous_occurrences(self):
        first=self.source();self.prereqs(first);findings.project_import(self.conn,first)
        second=self.source(doc=target(False,False));self.prereqs(second);findings.project_import(self.conn,second)
        self.assertEqual(self.counts(),(2,4,2))
        self.assertTrue(all(r['finding_status']=='Open' for r in self.show(first)['evaluations']))
        self.assertTrue(all(r['result']=='no_finding' and r['finding_id'] is None for r in self.show(second)['evaluations']))
        self.assertEqual(self.show(first)['evaluations'][0]['asset_id'],self.show(second)['evaluations'][0]['asset_id'])

    def test_failed_auth_and_unsupported_sources_persist_coverage_without_findings(self):
        for protocol,expected in (('winrm','insufficient_evidence'),('ssh','not_supported')):
            doc=target();doc['authentication']['success']=False;doc['action']['protocol']=protocol
            p=self.source(doc=doc);self.prereqs(p);findings.project_import(self.conn,p)
            self.assertTrue(all(r['result']==expected and r['finding_id'] is None for r in self.show(p)['evaluations']))
        self.assertEqual(self.counts(),(2,4,0))

    def test_ambiguous_source_does_not_choose_a_central_asset(self):
        doc=target();doc['authentication']['success']=False
        other=copy.deepcopy(source.network_doc()['assets'][0]);other['ip']='192.0.2.11'
        p=self.source(doc=doc,extras=[other])
        # Defensive trusted-API fixture: one inventoried artifact referenced by
        # two observations. The source adapter's usual resolver picks one seed.
        ref=next(r for r in p['assets']['import']['artifacts'] if r['role']=='credentialed_evidence')
        second=p['assets']['observations'][1]
        second['source_refs']=sorted(second['source_refs']+[ref],key=lambda r:r['path'])
        for row in p['evaluations']:
            row.update(observation_ordinal=None,link_state='ambiguous')
        self.prereqs(p);findings.project_import(self.conn,p)
        self.assertTrue(all(r['link_state']=='ambiguous' and r['asset_id'] is None for r in self.show(p)['evaluations']))

    def test_review_identity_is_retained_without_promotion(self):
        doc=target();doc['authentication']['success']=False
        other=copy.deepcopy(source.network_doc()['assets'][0]);other['ip']='192.0.2.11'
        p=self.source(doc=doc,extras=[other]);self.prereqs(p);findings.project_import(self.conn,p)
        self.assertTrue(all(r['asset_decision']=='review_required' for r in self.show(p)['evaluations']))
        self.assertTrue(all(r['result']=='insufficient_evidence' for r in self.show(p)['evaluations']))

    def test_rollback_after_evaluation_insert_preserves_dependencies(self):
        p=self.source();self.prereqs(p)
        self.conn.execute("CREATE FUNCTION canca.reject_finding() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic'; END $$")
        self.conn.execute('CREATE TRIGGER reject_finding BEFORE INSERT ON canca.findings FOR EACH ROW EXECUTE FUNCTION canca.reject_finding()')
        with self.assertRaises(Exception):findings.project_import(self.conn,p)
        self.assertEqual(self.counts(),(0,0,0))
        self.assertEqual(pg.show_import(self.conn,p['assets']['import']['bundle_id'])['status'],'found')
        self.assertEqual(assets.show_import(self.conn,p['assets']['import']['bundle_id'])['status'],'found')
        self.conn.execute('DROP TRIGGER reject_finding ON canca.findings')
        self.assertEqual(findings.project_import(self.conn,p)['status'],'projected')

    def test_concurrent_replay_commits_one_analysis(self):
        p=self.source();self.prereqs(p);barrier=threading.Barrier(2)
        def project():
            with pg.open_connection() as conn:
                barrier.wait(timeout=10);return findings.project_import(conn,p)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures=[pool.submit(project) for _ in range(2)];results=[f.result(timeout=30) for f in futures]
        self.assertEqual(sorted(r['status'] for r in results),['already_projected','projected'])
        self.assertEqual(results[0]['analysis_id'],results[1]['analysis_id']);self.assertEqual(self.counts(),(1,2,2))

    def test_upgrade_preserves_assets_and_has_no_analysis_backfill(self):
        self.conn.execute('DROP SCHEMA canca CASCADE');self.conn.execute('CREATE SCHEMA canca')
        self.conn.execute('CREATE TABLE canca.schema_migrations (version integer PRIMARY KEY,sha256 text NOT NULL)')
        for i,path in enumerate(pg.MIGRATIONS[:3],1):
            self.conn.execute(path.read_text());self.conn.execute('INSERT INTO canca.schema_migrations VALUES (%s,%s)',(i,pg.digest(path.read_bytes())))
        p=self.source();self.prereqs(p);before=assets.show_import(self.conn,p['assets']['import']['bundle_id'])
        with self.assertRaisesRegex(pg.PersistenceError,'schema_required'):findings.project_import(self.conn,p)
        self.assertEqual(pg.migrate(self.conn)['migration'],4)
        self.assertEqual(self.counts(),(0,0,0));self.assertEqual(assets.show_import(self.conn,p['assets']['import']['bundle_id']),before)
        findings.project_import(self.conn,p);self.assertEqual(self.counts(),(1,2,2))

    def test_pagination_read_only_and_unknown_import(self):
        p=self.source();self.prereqs(p);findings.project_import(self.conn,p);before=self.counts()
        one=self.show(p,limit=1);self.assertTrue(one['has_more'])
        two=self.show(p,after_ordinal=one['next_after_ordinal'],limit=1);self.assertFalse(two['has_more'])
        self.assertEqual([r['ordinal'] for r in one['evaluations']+two['evaluations']],[0,1])
        self.assertEqual(self.show(p,after_ordinal=1)['evaluations'],[])
        self.assertEqual(findings.show_import(self.conn,'bnd-'+'0'*20)['status'],'not_found');self.assertEqual(self.counts(),before)

    def test_failed_fourth_migration_rolls_back_and_preserves_prior_assets(self):
        self.conn.execute('DROP SCHEMA canca CASCADE');self.conn.execute('CREATE SCHEMA canca')
        self.conn.execute('CREATE TABLE canca.schema_migrations (version integer PRIMARY KEY,sha256 text NOT NULL)')
        for i,path in enumerate(pg.MIGRATIONS[:3],1):
            self.conn.execute(path.read_text());self.conn.execute('INSERT INTO canca.schema_migrations VALUES (%s,%s)',(i,pg.digest(path.read_bytes())))
        p=self.source();self.prereqs(p);before=assets.show_import(self.conn,p['assets']['import']['bundle_id'])
        self.conn.execute('CREATE TABLE canca.finding_evaluations (foreign_column integer)')
        with self.assertRaises(Exception):pg.migrate(self.conn)
        self.assertEqual(self.conn.execute('SELECT version FROM canca.schema_migrations ORDER BY version').fetchall(),[(1,),(2,),(3,)])
        self.assertIsNone(self.conn.execute("SELECT to_regclass('canca.finding_analyses')").fetchone()[0])
        self.assertEqual(assets.show_import(self.conn,p['assets']['import']['bundle_id']),before)

    def test_minimum_role_can_project_and_read_but_cannot_update_delete_or_create(self):
        p=self.source();self.prereqs(p)
        self.conn.execute('DROP ROLE IF EXISTS canca_findings_test');self.conn.execute('CREATE ROLE canca_findings_test')
        self.addCleanup(lambda:self.conn.execute('DROP ROLE IF EXISTS canca_findings_test'))
        self.addCleanup(lambda:self.conn.execute('DROP OWNED BY canca_findings_test'))
        self.conn.execute('GRANT USAGE ON SCHEMA canca TO canca_findings_test')
        self.conn.execute('GRANT SELECT ON canca.schema_migrations,canca.imports,canca.artifacts,canca.asset_imports,canca.asset_observations TO canca_findings_test')
        self.conn.execute('GRANT SELECT,INSERT ON canca.finding_analyses,canca.finding_evaluations,canca.findings TO canca_findings_test')
        self.conn.execute('SET ROLE canca_findings_test')
        try:
            findings.project_import(self.conn,p);self.assertEqual(self.show(p)['finding_count'],2)
            for sql in ('UPDATE canca.findings SET status=\'Open\'','DELETE FROM canca.findings','CREATE TABLE canca.denied(id integer)'):
                with self.assertRaises(Exception):self.conn.execute(sql)
        finally:self.conn.execute('RESET ROLE')
