"""Assessment scope, historical coverage and consistent read-only pages."""
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
import test_postgres_findings as fixture
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'persistence'))
import P01_Assessment_Report as report
import P01_Assessment_Lifecycle as life
pg=report.pg


class ReportBoundaryTests(unittest.TestCase):
    def test_invalid_scope_or_unfenced_cursor_rejected_before_connection(self):
        common=['show-assessment','--assessment-id','LAB-001']
        for args in (['show-assessment','--assessment-id','../escape'],common+['--limit','101'],
                     common+['--after-ordinal','0'],common+['--after-analysis-id','ana-'+'0'*32],
                     common+['--expected-scope-sha256','not-a-hash'],common+['--after-analysis-id','bad']):
            with patch.object(pg,'open_connection') as connect,redirect_stdout(io.StringIO()):
                self.assertEqual(report.cli(args),2)
            connect.assert_not_called()

    def test_driver_error_does_not_expose_connection_details(self):
        out=io.StringIO()
        with patch.object(pg,'open_connection',side_effect=RuntimeError('password=NEVER-LOG')),redirect_stdout(out):
            self.assertEqual(report.cli(['show-assessment','--assessment-id','LAB-001']),2)
        self.assertNotIn('NEVER-LOG',out.getvalue())
        self.assertEqual(json.loads(out.getvalue())['error_code'],'database_failed')


@unittest.skipUnless(os.environ.get('CANCA_TEST_POSTGRES')=='1','real PostgreSQL integration opt-in required')
class PostgreSQLReportTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.store=self.base/'store';self.counter=0
        self.conn=pg.open_connection();self.addCleanup(self.conn.close)
        self.conn.execute('DROP SCHEMA IF EXISTS canca CASCADE');pg.migrate(self.conn)

    def source(self,**kwargs):
        self.counter+=1
        _,directory=fixture.fixture(self.base/f'source-{self.counter}',store=self.store,run=f'R{self.counter}',**kwargs)
        return fixture.findings.prepare_findings(self.store,directory)

    def persist(self,p,stage='findings',conn=None):
        conn=conn or self.conn
        pg.index_import(conn,p['assets']['import'])
        if stage!='index':fixture.assets.project_import(conn,p['assets'])
        if stage=='findings':fixture.findings.project_import(conn,p)

    def read(self,**kwargs):return report.show_assessment(self.conn,'LAB-001',**kwargs)

    def test_empty_registered_assessment_and_unknown_are_not_clean_reports(self):
        self.assertEqual(report.show_assessment(self.conn,'MISSING')['status'],'not_found')
        life.register_assessment(self.conn,'LAB-001');doc=self.read()
        self.assertEqual(doc['coverage']['projection_status'],'no_imports')
        self.assertEqual(doc['lifecycle'],{'state':'registered','revision':0})
        self.assertEqual(doc['recorded_finding_occurrences'],0);self.assertEqual(doc['evaluations'],[])
        self.assertFalse(doc['source_bytes_revalidated']);self.assertNotIn('healthy',doc)

    def test_pending_imports_are_explicit_beside_analyzed_imports(self):
        full=self.source();self.persist(full)
        indexed=self.source();self.persist(indexed,'index')
        asset=self.source();self.persist(asset,'assets')
        doc=self.read();coverage=doc['coverage']
        self.assertEqual(coverage['import_count'],3)
        self.assertEqual(coverage['asset_projected_import_count'],2)
        self.assertEqual(coverage['analyzed_import_count'],1)
        self.assertEqual(coverage['imports_without_assets'],[indexed['assets']['import']['bundle_id']])
        self.assertEqual(set(coverage['imports_without_analysis']),{p['assets']['import']['bundle_id'] for p in (indexed,asset)})
        self.assertEqual(coverage['projection_status'],'missing_analyses')
        self.assertEqual(coverage['credentialed_sources_indexed'],3);self.assertEqual(coverage['credentialed_sources_evaluated'],1)
        self.assertEqual(doc['recorded_finding_occurrences'],2)

    def test_old_findings_survive_clean_run_without_unique_vulnerability_claim(self):
        first=self.source();self.persist(first)
        second=self.source(doc=fixture.target(False,False));self.persist(second)
        doc=self.read()
        self.assertEqual(doc['coverage']['outcomes']['finding'],2)
        self.assertEqual(doc['coverage']['outcomes']['no_finding'],2)
        self.assertEqual(doc['recorded_finding_occurrences'],2)
        self.assertEqual(doc['identity']['central_asset_count'],1)
        self.assertEqual(doc['identity']['decisions']['linked'],1)
        self.assertTrue(all(r['finding_status']=='Open' for r in doc['evaluations'] if r['finding_id']))
        self.assertEqual(doc['lifecycle']['state'],'registered')

    def test_insufficient_unsupported_and_not_applicable_outcomes_are_retained(self):
        failed=fixture.target();failed['authentication']['success']=False
        ssh=fixture.target();ssh['action']['protocol']='ssh'
        standalone=fixture.target(False,False);standalone['enrichment']['identity'].update(part_of_domain=False,domain_role=0)
        for target in (failed,ssh,standalone):self.persist(self.source(doc=target))
        doc=self.read();out=doc['coverage']['outcomes']
        self.assertEqual(out,{'finding':0,'no_finding':1,'insufficient_evidence':2,'not_applicable':1,'not_supported':2})
        self.assertEqual(doc['coverage']['projection_status'],'all_imports_analyzed')
        self.assertEqual(doc['recorded_finding_occurrences'],0)
        self.assertTrue(all(r['result'] in report.RESULTS for r in doc['evaluations']))

    def test_cursor_fence_and_limit_preserve_all_evaluations_without_duplicates(self):
        for _ in range(3):self.persist(self.source())
        first=self.read(limit=1);scope=first['report_scope_sha256'];seen=first['evaluations']
        while first['has_more']:
            first=self.read(**first['next_cursor'],limit=1,expected_scope_sha256=scope)
            self.assertEqual(first['report_scope_sha256'],scope);seen+=first['evaluations']
        self.assertEqual(len(seen),6);self.assertEqual(len({(r['analysis_id'],r['ordinal']) for r in seen}),6)
        self.assertEqual([(r['analysis_id'],r['ordinal']) for r in seen],sorted((r['analysis_id'],r['ordinal']) for r in seen))
        self.assertEqual(self.read(**first['next_cursor'],expected_scope_sha256=scope)['evaluations'],[])
        again=self.read();self.assertEqual(again['report_scope_sha256'],scope)
        self.assertEqual(again['recorded_finding_occurrences'],6)

    def test_new_import_invalidates_page_fence(self):
        self.persist(self.source());one=self.read(limit=1)
        self.persist(self.source(),'index')
        with self.assertRaisesRegex(pg.PersistenceError,'report_scope_conflict'):
            self.read(**one['next_cursor'],limit=1,expected_scope_sha256=one['report_scope_sha256'])
        self.assertNotEqual(self.read()['report_scope_sha256'],one['report_scope_sha256'])

    def test_lifecycle_change_invalidates_page_fence_without_changing_findings(self):
        self.persist(self.source());one=self.read(limit=1)
        life.transition(self.conn,'LAB-001',0,'activate','active','operator')
        with self.assertRaisesRegex(pg.PersistenceError,'report_scope_conflict'):
            self.read(**one['next_cursor'],expected_scope_sha256=one['report_scope_sha256'])
        new=self.read();self.assertEqual(new['lifecycle'],{'state':'active','revision':1})
        self.assertEqual(new['recorded_finding_occurrences'],2)

    def test_writer_during_read_does_not_mix_snapshot_counts_and_details(self):
        self.persist(self.source());later=self.source();actual=self.conn
        class HookConnection:
            fired=False
            @property
            def autocommit(self):return actual.autocommit
            @property
            def info(self):return actual.info
            def transaction(self):return actual.transaction()
            def execute(proxy,sql,params=None):
                result=actual.execute(sql,params)
                if 'FROM canca.imports i LEFT JOIN' in sql and not proxy.fired:
                    proxy.fired=True
                    with pg.open_connection() as writer:self.persist(later,conn=writer)
                return result
        hooked=HookConnection();doc=report.show_assessment(hooked,'LAB-001')
        self.assertTrue(hooked.fired)
        self.assertEqual(doc['coverage']['import_count'],1);self.assertEqual(doc['coverage']['evaluation_count'],2)
        self.assertEqual(len(doc['evaluations']),2)
        self.assertEqual(self.read()['coverage']['import_count'],2)

    def test_original_catalog_is_used_and_source_bytes_are_not_read(self):
        p=self.source();self.persist(p)
        # Reporting intentionally reads the persisted catalog, independent of the
        # current rules file or the continued availability of the raw store.
        with patch.object(fixture.findings,'catalog',side_effect=RuntimeError('must not load source')):
            doc=self.read()
        self.assertEqual(doc['catalogs'][0]['catalog'],p['catalog'])
        self.assertEqual(doc['catalogs'][0]['catalog_sha256'],p['catalog_sha256'])
        for row in doc['evaluations']:
            self.assertEqual(row['rule'],next(r for r in p['catalog']['rules'] if r['id']==row['rule_id']))
            self.assertTrue(row['source_path']);self.assertEqual(row['source_sha256'],p['evaluations'][0]['source_ref']['sha256'])
        self.assertFalse(doc['source_bytes_revalidated'])

    def test_assessment_scope_never_includes_another_assessment(self):
        p=self.source();self.persist(p)
        # Additional trusted metadata fixture for a different assessment.
        imported=copy.deepcopy(p['assets']['import']);imported['assessment_id']='OTHER'
        imported['bundle_id']=pg.bundle._bundle_id(*(imported[k] for k in pg.IDENTITY),imported['artifacts'])
        pg.index_import(self.conn,imported)
        doc=self.read();self.assertEqual(doc['coverage']['import_count'],1)
        other=report.show_assessment(self.conn,'OTHER')
        self.assertEqual(other['coverage']['import_count'],1);self.assertEqual(other['coverage']['evaluation_count'],0)
        self.assertEqual(other['recorded_finding_occurrences'],0)

    def test_import_limit_rejects_entire_report(self):
        p=self.source();self.persist(p,'index')
        # Defensive bound: synthetic trusted-API metadata in disposable CI DB.
        for i in range(1,101):
            imported=copy.deepcopy(p['assets']['import']);imported['run_id']=f'BOUND-{i}'
            imported['bundle_id']=pg.bundle._bundle_id(*(imported[k] for k in pg.IDENTITY),imported['artifacts'])
            pg.index_import(self.conn,imported)
        with self.assertRaisesRegex(pg.PersistenceError,'report_limit_exceeded'):self.read()

    def test_evaluation_and_observation_limits_reject_instead_of_truncating(self):
        self.persist(self.source())
        with patch.object(report,'MAX_EVALUATIONS',1):
            with self.assertRaisesRegex(pg.PersistenceError,'report_limit_exceeded'):self.read()
        with patch.object(report,'MAX_OBSERVATIONS',0):
            with self.assertRaisesRegex(pg.PersistenceError,'report_limit_exceeded'):self.read()

    def test_drift_or_missing_schema_is_not_a_partial_success(self):
        p=self.source();self.persist(p)
        self.conn.execute('UPDATE canca.finding_analyses SET evaluation_count=3')
        with self.assertRaisesRegex(pg.PersistenceError,'report_data_conflict'):self.read()
        self.conn.execute("UPDATE canca.schema_migrations SET sha256='bad' WHERE version=4")
        with self.assertRaisesRegex(pg.PersistenceError,'schema_mismatch'):self.read()
        self.conn.execute('DROP SCHEMA canca CASCADE')
        with self.assertRaisesRegex(pg.PersistenceError,'schema_required'):self.read()

    def test_reader_grants_allow_report_without_any_write_privileges(self):
        self.persist(self.source());before=self.read()
        self.conn.execute('DROP ROLE IF EXISTS canca_report_reader_test');self.conn.execute('CREATE ROLE canca_report_reader_test')
        self.addCleanup(lambda:self.conn.execute('DROP ROLE IF EXISTS canca_report_reader_test'))
        self.addCleanup(lambda:self.conn.execute('DROP OWNED BY canca_report_reader_test'))
        self.conn.execute('GRANT USAGE ON SCHEMA canca TO canca_report_reader_test')
        self.conn.execute('GRANT SELECT ON canca.schema_migrations,canca.assessments,canca.imports,canca.artifacts,canca.assets,'
                          'canca.asset_imports,canca.asset_observations,canca.finding_analyses,canca.finding_evaluations,canca.findings TO canca_report_reader_test')
        self.conn.execute('SET ROLE canca_report_reader_test')
        try:
            doc=self.read();self.assertEqual(doc['report_scope_sha256'],before['report_scope_sha256'])
            for sql in ("INSERT INTO canca.assessments (assessment_id) VALUES ('DENIED')",'UPDATE canca.findings SET status=\'Open\'',
                        'DELETE FROM canca.findings','CREATE TABLE canca.denied(id integer)'):
                with self.assertRaises(Exception):self.conn.execute(sql)
        finally:self.conn.execute('RESET ROLE')
        self.assertEqual(self.read()['report_scope_sha256'],before['report_scope_sha256'])
