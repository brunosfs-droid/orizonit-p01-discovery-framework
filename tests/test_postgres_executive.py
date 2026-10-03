"""Historical executive semantics, private publication and real read-only SQL."""
from collections import Counter
from copy import deepcopy
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_postgres_export as fixture
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'persistence'))
import P01_Executive_Report as executive

pg = executive.pg
report = executive.report


def history(results=None):
    """Two positive runs and one later negative run, with an identity ambiguity."""
    results = results if results is not None else [('finding', 'finding'), ('finding', 'finding'), ('no_finding', 'no_finding')]
    catalog = json.loads((Path(__file__).resolve().parents[1] / 'persistence/P01_Finding_Rules.json').read_bytes())
    catalogs = [dict(policy_version='0.6.4', catalog_sha256='a'*64, engine_sha256='b'*64, catalog=catalog)] if results else []
    imports = []; analyses = []; rows = []
    for n, outcomes in enumerate(results, 1):
        aid = 'ana-' + f'{n:032x}'; bundle = f'bnd-synthetic-{n}'
        imports.append(dict(bundle_id=bundle))
        analyses.append(dict(analysis_id=aid, bundle_id=bundle, policy_version='0.6.4',
                             engine_sha256='b'*64, catalog_sha256='a'*64,
                             evaluation_count=len(outcomes), finding_count=outcomes.count('finding')))
        for ordinal, (rule, outcome) in enumerate(zip(catalog['rules'], outcomes)):
            rows.append(dict(analysis_id=aid, ordinal=ordinal, bundle_id=bundle, rule_id=rule['id'], result=outcome,
                             finding_id='fnd-'+f'{n*2+ordinal:032x}' if outcome == 'finding' else None,
                             finding_status='Open' if outcome == 'finding' else None,
                             asset_id=None if n == 2 else 'cas-'+'c'*32,
                             asset_decision='review_required' if n == 2 else 'new_asset' if n == 1 else 'linked',
                             source_sha256=f'{n:064x}', source_path='evidence/NEVER-EXPORT-THIS-PATH.json',
                             evidence=dict(value='NEVER-EXPORT-EXTRACTED-EVIDENCE'),
                             evidence_refs=['NEVER-EXPORT-EVIDENCE-REFS'], rule=deepcopy(rule)))
    outcomes = Counter(r['result'] for r in rows)
    decisions = dict(new_asset=int(bool(results)), linked=max(len(results)-2, 0), review_required=int(len(results)>=2))
    return dict(status='found', export_version=executive.export.VERSION, report_version=report.VERSION,
                assessment_id='LAB-001', scope_mode='all_persisted_imports', report_scope_sha256='d'*64,
                source_bytes_revalidated=False, lifecycle=dict(state='completed', revision=4),
                coverage=dict(import_count=len(imports), asset_projected_import_count=len(imports), analyzed_import_count=len(analyses),
                              imports_without_assets=[], imports_without_analysis=[], credentialed_sources_indexed=len(imports),
                              credentialed_sources_evaluated=len(imports), evaluation_count=len(rows),
                              projection_status='all_imports_analyzed' if imports else 'no_imports',
                              outcomes={r: outcomes[r] for r in report.RESULTS},
                              by_rule={r: {s: sum(x['rule_id']==r and x['result']==s for x in rows) for s in report.RESULTS}
                                       for r in report.RULES}),
                identity=dict(central_asset_count=int(bool(imports)), observation_count=len(imports), decisions=decisions,
                              reasons={'synthetic_identity_reason':len(imports)} if imports else {}),
                recorded_finding_occurrences=outcomes['finding'], imports=imports, analyses=analyses, catalogs=catalogs, evaluations=rows,
                export_consistency=dict(mode='canonical_report_scope_fence', terminal_empty_page_verified=True,
                                        data_pages=len(rows), first_snapshot_at_utc='2026-10-03T16:00:00+00:00',
                                        last_snapshot_at_utc='2026-10-03T16:00:01+00:00'))


class ExecutiveBoundaryTests(unittest.TestCase):
    def test_history_groups_recommendations_without_resolving_prior_findings(self):
        original = history(); saved = deepcopy(original)
        doc = executive.summarize(original)
        self.assertEqual(original, saved)
        self.assertEqual(doc['recorded_finding_occurrences'], 4)
        self.assertEqual(doc['coverage']['outcomes']['no_finding'], 2)
        self.assertEqual(doc['recommendation_group_count'], 2)
        self.assertEqual(doc['findings_by_recorded_severity'], {'High':4})
        for group, rule in zip(doc['recommendation_groups'], original['catalogs'][0]['catalog']['rules']):
            self.assertEqual(group['rule']['recommendation'], rule['recommendation'])
            self.assertEqual(group['occurrence_count'], 2)
            self.assertEqual(group['linked_central_asset_count'], 1)
            self.assertEqual(group['occurrences_without_central_asset'], 1)
            self.assertEqual(group['occurrences_requiring_identity_review'], 1)
            self.assertEqual([r['finding_status'] for r in group['occurrences']], ['Open','Open'])
            self.assertEqual(len({r['finding_id'] for r in group['occurrences']}), 2)
        self.assertEqual(doc['lifecycle']['state'], 'completed')
        self.assertFalse(doc['semantics']['current_risk_assessed'])
        self.assertEqual(executive.summarize(original), doc)

    def test_distinct_historical_catalog_and_engine_variants_never_merge(self):
        original = history([('finding','finding')]*3)
        changed = deepcopy(original['catalogs'][0]); changed['catalog_sha256'] = 'e'*64
        changed['catalog']['rules'][0]['recommendation'] = 'Recommendation from a different stored catalog'
        other_engine = deepcopy(original['catalogs'][0]); other_engine['engine_sha256'] = 'f'*64
        original['catalogs'] += [changed, other_engine]
        original['analyses'][1]['catalog_sha256'] = 'e'*64
        original['analyses'][2]['engine_sha256'] = 'f'*64
        for row in original['evaluations'][2:4]:
            row['rule'] = deepcopy(changed['catalog']['rules'][row['ordinal']])
        doc = executive.summarize(original)
        self.assertEqual(doc['recommendation_group_count'], 6)
        self.assertEqual(len({g['group_id'] for g in doc['recommendation_groups']}), 6)
        self.assertEqual(sum(g['occurrence_count'] for g in doc['recommendation_groups']), 6)
        self.assertIn(changed['catalog']['rules'][0]['recommendation'], [g['rule']['recommendation'] for g in doc['recommendation_groups']])
        original['catalogs'].reverse()
        self.assertEqual(doc, executive.summarize(original))

    def test_saved_severities_keep_unknown_values_and_sort_known_values_first(self):
        for severities in (('Unrated locally','Medium'), ('Low','Critical')):
            original = history()
            for rule, severity in zip(original['catalogs'][0]['catalog']['rules'], severities):
                rule['severity'] = severity
            for row in original['evaluations']:
                row['rule']['severity'] = severities[row['ordinal']]
            doc = executive.summarize(original)
            self.assertEqual([g['rule']['severity'] for g in doc['recommendation_groups']], list(reversed(severities)))
            self.assertEqual(doc['findings_by_recorded_severity'], {s:2 for s in severities})

    def test_empty_pending_and_inconclusive_outcomes_are_explicit(self):
        empty = executive.summarize(history([]))
        self.assertEqual(empty['coverage']['projection_status'], 'no_imports')
        self.assertEqual(empty['recommendation_groups'], [])
        self.assertIn('Não há imports persistidos', executive.markdown(empty).decode())
        incomplete = history([('insufficient_evidence','not_supported'), ('not_applicable','no_finding')])
        incomplete['imports'].append(dict(bundle_id='bnd-pending'))
        incomplete['coverage'].update(import_count=3, imports_without_assets=['bnd-pending'],
                                      imports_without_analysis=['bnd-pending'], projection_status='missing_analyses')
        doc = executive.summarize(incomplete)
        self.assertEqual(doc['recommendation_groups'], [])
        self.assertEqual(doc['coverage']['outcomes'], dict(finding=0, no_finding=1, insufficient_evidence=1, not_applicable=1, not_supported=1))
        rendered = executive.markdown(doc).decode()
        self.assertIn('Análise ausente', rendered); self.assertIn('Revisão de identidade necessária', rendered)
        self.assertIn('não comprova segurança do ambiente', rendered)

    def test_only_whitelisted_metadata_and_occurrence_references_leave_the_synthesis(self):
        original = history(); original['secret_extra_field'] = 'NEVER-EXPORT-TOP-LEVEL'
        original['coverage']['secret_extra_field'] = 'NEVER-EXPORT-COVERAGE'
        original['catalogs'][0]['catalog']['rules'][0]['secret_extra_field'] = 'NEVER-EXPORT-RULE-EXTRA'
        for row in original['evaluations']:
            if row['ordinal'] == 0: row['rule']['secret_extra_field'] = 'NEVER-EXPORT-RULE-EXTRA'
        doc = executive.summarize(original)
        raw = executive.bounded_json(doc) + executive.markdown(doc)
        self.assertNotIn(b'NEVER-EXPORT', raw)
        refs = [r for g in doc['recommendation_groups'] for r in g['occurrences']]
        expected = [r for r in original['evaluations'] if r['result'] == 'finding']
        self.assertEqual({r['finding_id'] for r in refs}, {r['finding_id'] for r in expected})
        self.assertEqual({r['source_sha256'] for r in refs}, {r['source_sha256'] for r in expected})

    def test_partial_duplicate_and_conflicting_inputs_are_rejected(self):
        cases = []
        def broken():
            doc = history(); cases.append(doc); return doc
        broken()['export_consistency']['terminal_empty_page_verified'] = False
        broken()['evaluations'].pop()
        broken()['evaluations'][1]['ordinal'] = 0
        broken()['evaluations'][1]['finding_id'] = 'fnd-'+f'{2:032x}'
        broken()['evaluations'][0]['rule']['recommendation'] = 'wrong historical rule'
        broken()['analyses'][0]['catalog_sha256'] = 'f'*64
        broken()['coverage']['outcomes']['finding'] = 3
        broken()['coverage']['by_rule']['WIN-AD-001']['finding'] = 3
        broken()['identity']['decisions']['review_required'] = True
        broken()['identity']['reasons']['synthetic_identity_reason'] = 0
        broken()['analyses'][0]['finding_count'] = 1
        broken()['imports'].append(dict(bundle_id='bnd-extra'))
        broken()['source_bytes_revalidated'] = True
        broken()['export_consistency']['last_snapshot_at_utc'] = None
        for doc in cases:
            with self.subTest(case=cases.index(doc)):
                with self.assertRaisesRegex(pg.PersistenceError, 'executive_data_conflict'):
                    executive.summarize(doc)

    def test_markdown_preserves_inert_text_without_active_links_images_or_headings(self):
        original = history()
        malicious = '<img src=x> ![click](https://evil) |\n# injected @someone'
        original['catalogs'][0]['catalog']['rules'][0]['recommendation'] = malicious
        original['catalogs'][0]['catalog']['rules'][0]['title'] = malicious
        for row in original['evaluations']:
            if row['ordinal'] == 0:
                row['rule']['recommendation'] = malicious; row['rule']['title'] = malicious
        rendered = executive.markdown(executive.summarize(original)).decode()
        for active in ('<img', '![click]', 'https://evil', '\n# injected', '@someone'):
            self.assertNotIn(active, rendered)
        for escaped in ('&lt;img', 'https&#58;&#47;&#47;evil', '&#124;', '&#64;someone'):
            self.assertIn(escaped, rendered)

    def test_private_publication_hashes_repeat_and_limit_before_files(self):
        doc = executive.summarize(history())
        with tempfile.TemporaryDirectory() as td:
            one = executive.save(doc, td); two = executive.save(doc, td)
            self.assertNotEqual(one['export_dir'], two['export_dir'])
            self.assertEqual(one['manifest_sha256'], two['manifest_sha256'])
            run = Path(one['export_dir']); self.assertEqual(run.stat().st_mode & 0o777, 0o700)
            self.assertEqual(set(p.name for p in run.iterdir()), {'executive.json','executive.md','manifest.json','manifest.json.sha256'})
            self.assertEqual(json.loads((run/'executive.json').read_bytes()), doc)
            manifest = json.loads((run/'manifest.json').read_bytes())
            for item in manifest['files']:
                raw = (run/item['name']).read_bytes()
                self.assertEqual(item['sha256'], pg.digest(raw)); self.assertEqual(item['size_bytes'], len(raw))
            self.assertEqual((run/'manifest.json.sha256').read_text(), one['manifest_sha256']+'  manifest.json\n')
            self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in run.iterdir()))
            total = sum(p.stat().st_size for p in run.iterdir())
            before = set(Path(td).iterdir())
            with patch.object(executive, 'MAX_BYTES', total-1):
                with self.assertRaisesRegex(pg.PersistenceError, 'executive_limit_exceeded'):
                    executive.save(doc, td)
            self.assertEqual(set(Path(td).iterdir()), before)

    def test_failed_publication_cleans_only_its_stage_and_refuses_existing_target(self):
        doc = executive.summarize(history())
        with tempfile.TemporaryDirectory() as td:
            keep = Path(td)/'keep.txt'; keep.write_text('keep')
            for fail in ('fsync','rename'):
                target = os if fail == 'fsync' else Path
                with patch.object(target, fail, side_effect=OSError('NEVER-LOG-PRIVATE-PATH')):
                    with self.assertRaisesRegex(pg.PersistenceError, 'executive_write_failed'):
                        executive.save(doc, td)
                self.assertEqual(list(Path(td).iterdir()), [keep])
            existing = Path(td)/('P01-EXECUTIVE-'+'1'*32); existing.mkdir(); (existing/'keep').write_text('existing')
            with patch.object(executive.uuid, 'uuid4', return_value=type('UUID', (), {'hex':'1'*32})()):
                with self.assertRaisesRegex(pg.PersistenceError, 'executive_write_failed'):
                    executive.save(doc, td)
            self.assertEqual((existing/'keep').read_text(), 'existing')
            self.assertEqual(set(Path(td).iterdir()), {keep,existing})

    def test_bad_cli_inputs_fail_before_connection_and_driver_errors_are_redacted(self):
        with tempfile.TemporaryDirectory() as td:
            alias = Path(td)/'alias'; alias.symlink_to(td, target_is_directory=True)
            base = ['--assessment-id','LAB-001','--output-root',td]
            cases = [base+['--page-size','0'],base+['--expected-scope-sha256','bad'],
                     ['--assessment-id','../bad','--output-root',td],
                     ['--assessment-id','LAB-001','--output-root',str(alias)]]
            for args in cases:
                with patch.object(pg, 'open_connection') as connection, redirect_stdout(io.StringIO()):
                    self.assertEqual(executive.cli(args), 2)
                connection.assert_not_called()
            output = io.StringIO()
            with patch.object(pg, 'open_connection', side_effect=RuntimeError('password=NEVER-LOG')), redirect_stdout(output):
                self.assertEqual(executive.cli(base), 2)
            self.assertEqual(json.loads(output.getvalue())['error_code'], 'database_failed')
            self.assertNotIn('NEVER-LOG', output.getvalue())
            self.assertEqual(list(Path(td).iterdir()), [alias])

    def test_collection_fence_and_byte_limit_do_not_publish_partial_summary(self):
        with patch.object(executive.export, 'collect', return_value=history()) as collect:
            doc = executive.collect(object(), 'LAB-001', 1, expected_scope_sha256='d'*64)
        self.assertEqual(collect.call_args.kwargs['expected_scope_sha256'], 'd'*64)
        self.assertEqual(doc['consistency']['data_pages'], 6)
        with patch.object(executive.export, 'collect', side_effect=pg.PersistenceError('report_scope_conflict')):
            with self.assertRaisesRegex(pg.PersistenceError, 'report_scope_conflict'):
                executive.collect(object(), 'LAB-001')
        with patch.object(executive, 'MAX_BYTES', 16):
            with self.assertRaisesRegex(pg.PersistenceError, 'executive_limit_exceeded'):
                executive.summarize(history())


@unittest.skipUnless(os.environ.get('CANCA_TEST_POSTGRES') == '1', 'real PostgreSQL integration opt-in required')
class PostgreSQLExecutiveTests(unittest.TestCase):
    setUp = fixture.PostgreSQLExportTests.setUp
    source = fixture.PostgreSQLExportTests.source
    persist = fixture.PostgreSQLExportTests.persist
    snapshot = fixture.PostgreSQLExportTests.snapshot

    def test_select_only_cli_matches_complete_history_and_preserves_fourteen_tables_and_store(self):
        self.persist(self.source()); self.persist(self.source())
        self.persist(self.source(doc=fixture.fixture.fixture.target(False,False)))
        before = self.snapshot()
        files = {str(p):pg.digest(p.read_bytes()) for p in self.store.rglob('*') if p.is_file()}
        canonical = executive.export.collect(self.conn, 'LAB-001', 1)
        expected = executive.summarize(canonical)
        role = 'canca_executive_reader_test'
        self.conn.execute('DROP ROLE IF EXISTS '+role); self.conn.execute('CREATE ROLE '+role)
        self.addCleanup(lambda:self.conn.execute('DROP ROLE IF EXISTS '+role))
        self.addCleanup(lambda:self.conn.execute('DROP OWNED BY '+role))
        self.conn.execute('GRANT USAGE ON SCHEMA canca TO '+role)
        self.conn.execute('GRANT SELECT ON canca.schema_migrations,canca.assessments,canca.imports,canca.artifacts,canca.assets,'
                          'canca.asset_imports,canca.asset_observations,canca.finding_analyses,canca.finding_evaluations,canca.findings TO '+role)
        open_connection = pg.open_connection
        def reader():
            conn = open_connection()
            try: conn.execute('SET ROLE '+role)
            except Exception: conn.close(); raise
            return conn
        output = io.StringIO()
        with patch.object(pg, 'open_connection', side_effect=reader), redirect_stdout(output):
            self.assertEqual(executive.cli(['--assessment-id','LAB-001','--output-root',str(self.base),
                                           '--page-size','1','--expected-scope-sha256',canonical['report_scope_sha256']]), 0)
        result = json.loads(output.getvalue()); self.assertFalse(result['database_mutated'])
        run = Path(result['export_dir']); saved = json.loads((run/'executive.json').read_bytes())
        self.assertEqual(saved['consistency']['data_pages'], 6)
        self.assertTrue(saved['consistency']['terminal_empty_page_verified'])
        saved.pop('consistency'); expected.pop('consistency'); self.assertEqual(saved, expected)
        self.assertEqual(result['recorded_finding_occurrences'], 4); self.assertEqual(result['recommendation_group_count'], 2)
        self.assertEqual(saved['coverage']['outcomes']['no_finding'], 2)
        self.assertEqual([g['occurrence_count'] for g in saved['recommendation_groups']], [2,2])
        manifest = json.loads((run/'manifest.json').read_bytes())
        self.assertEqual(result['manifest_sha256'], pg.digest((run/'manifest.json').read_bytes()))
        for item in manifest['files']: self.assertEqual(item['sha256'], pg.digest((run/item['name']).read_bytes()))
        with reader() as conn:
            for sql in ("UPDATE canca.findings SET status='Open'", 'DELETE FROM canca.findings',
                        "INSERT INTO canca.assessments(assessment_id) VALUES('DENIED')", 'CREATE TABLE canca.denied(id int)'):
                with self.assertRaises(Exception): conn.execute(sql)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(files, {str(p):pg.digest(p.read_bytes()) for p in self.store.rglob('*') if p.is_file()})

    def test_empty_pending_unsupported_and_insufficient_results_remain_visible(self):
        fixture.fixture.life.register_assessment(self.conn, 'LAB-001')
        self.assertEqual(executive.collect(self.conn, 'LAB-001')['coverage']['projection_status'], 'no_imports')
        self.persist(self.source(), 'index')
        failed = fixture.fixture.fixture.target(); failed['authentication']['success'] = False
        unsupported = fixture.fixture.fixture.target(); unsupported['action']['protocol'] = 'ssh'
        self.persist(self.source(doc=failed)); self.persist(self.source(doc=unsupported))
        doc = executive.collect(self.conn, 'LAB-001', 1)
        self.assertEqual(doc['coverage']['outcomes']['insufficient_evidence'], 2)
        self.assertEqual(doc['coverage']['outcomes']['not_supported'], 2)
        self.assertEqual(doc['recommendation_groups'], [])
        self.assertEqual(len(doc['coverage']['imports_without_analysis']), 1)
        self.assertEqual(doc['coverage']['projection_status'], 'missing_analyses')

    def test_absent_store_and_current_catalog_do_not_change_recorded_recommendations(self):
        self.persist(self.source())
        original = executive.collect(self.conn, 'LAB-001', 1)
        shutil.rmtree(self.store)
        with patch.object(fixture.fixture.fixture.findings, 'catalog', side_effect=RuntimeError('must not load current rules')):
            doc = executive.collect(self.conn, 'LAB-001', 1)
        self.assertEqual(doc['recommendation_groups'], original['recommendation_groups'])
        self.assertEqual(doc['coverage'], original['coverage'])

    def test_scope_change_after_last_data_page_produces_no_files(self):
        self.persist(self.source())
        query = report.show_assessment; fired = False
        def changed(*args, **kwargs):
            nonlocal fired
            page = query(*args, **kwargs)
            if not fired:
                fired = True
                with pg.open_connection() as writer:
                    fixture.fixture.life.transition(writer, 'LAB-001', 0, 'activate', 'active', 'operator')
            return page
        output = io.StringIO()
        with patch.object(report, 'show_assessment', side_effect=changed), redirect_stdout(output):
            self.assertEqual(executive.cli(['--assessment-id','LAB-001','--output-root',str(self.base)]), 2)
        self.assertEqual(json.loads(output.getvalue())['error_code'], 'report_scope_conflict')
        self.assertEqual(list(self.base.glob('*P01-EXECUTIVE-*')), [])


if __name__ == '__main__': unittest.main()
