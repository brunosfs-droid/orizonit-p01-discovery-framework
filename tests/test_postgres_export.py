"""Export completeness, concurrency fence, filesystem failure and read role."""
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

import test_postgres_report as fixture
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'persistence'))
import P01_Report_Export as export

pg = export.pg
report = export.report


def sample():
    row = dict(analysis_id='ana-'+'1'*32, ordinal=0, bundle_id='bnd-synthetic',
               rule_id='WIN-AD-001', result='no_finding', finding_id=None,
               finding_status=None, source_path='evidence/source.json', source_sha256='2'*64,
               asset_id=None, asset_decision=None, rule=dict(title='Synthetic rule'))
    outcomes = {k: int(k == 'no_finding') for k in report.RESULTS}
    by_rule = {k: {r: int(k == 'WIN-AD-001' and r == 'no_finding') for r in report.RESULTS}
               for k in report.RULES}
    page = dict(status='found', report_version=report.VERSION, assessment_id='LAB-001',
                source_bytes_revalidated=False, report_scope_sha256='3'*64,
                snapshot_at_utc='2026-10-02T23:00:00+00:00', lifecycle=dict(state='registered', revision=0),
                coverage=dict(import_count=1, analyzed_import_count=1, projection_status='all_imports_analyzed',
                              evaluation_count=1, outcomes=outcomes, by_rule=by_rule,
                              imports_without_assets=[], imports_without_analysis=[]),
                identity=dict(central_asset_count=0, observation_count=0), recorded_finding_occurrences=0,
                analyses=[dict(analysis_id=row['analysis_id'], evaluation_count=1, finding_count=0)],
                evaluations=[row], has_more=False,
                next_cursor=dict(after_analysis_id=row['analysis_id'], after_ordinal=0))
    end = copy.deepcopy(page)
    end['evaluations'] = []
    return page, end


class ExportBoundaryTests(unittest.TestCase):
    def test_input_and_alias_rejected_before_connection(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            alias = root / 'alias'
            alias.symlink_to(root, target_is_directory=True)
            for aid, output, size in (('../escape', root, 1), ('LAB-001', root, 101),
                                      ('LAB-001', root/'missing', 1), ('LAB-001', alias, 1)):
                with patch.object(pg, 'open_connection') as connect, redirect_stdout(io.StringIO()):
                    self.assertEqual(export.cli(['--assessment-id', aid, '--output-root', str(output),
                                                 '--page-size', str(size)]), 2)
                connect.assert_not_called()

    def test_error_redaction(self):
        with tempfile.TemporaryDirectory() as td:
            out = io.StringIO()
            with patch.object(pg, 'open_connection', side_effect=RuntimeError('password=NEVER-LOG')), redirect_stdout(out):
                self.assertEqual(export.cli(['--assessment-id', 'LAB-001', '--output-root', td]), 2)
            self.assertNotIn('NEVER-LOG', out.getvalue())
            self.assertEqual(json.loads(out.getvalue())['error_code'], 'database_failed')

    def test_terminal_query_and_counts_reject_partial_export(self):
        page, end = sample()
        with patch.object(report, 'show_assessment', side_effect=[page, end]) as query:
            doc = export.collect(object(), 'LAB-001', 1)
        self.assertEqual(len(doc['evaluations']), 1)
        self.assertEqual(query.call_args.kwargs['expected_scope_sha256'], '3'*64)
        self.assertTrue(doc['export_consistency']['terminal_empty_page_verified'])
        broken = copy.deepcopy(page)
        broken['coverage']['evaluation_count'] = 2
        broken_end = copy.deepcopy(broken)
        broken_end['evaluations'] = []
        with patch.object(report, 'show_assessment', side_effect=[broken, broken_end]):
            with self.assertRaisesRegex(pg.PersistenceError, 'export_data_conflict'):
                export.collect(object(), 'LAB-001', 1)

    def test_duplicate_cursor_metadata_change_and_empty_has_more_are_rejected(self):
        page, end = sample()
        cases = ([page, page], [page, dict(end, lifecycle=dict(state='active', revision=1))],
                 [dict(page, next_cursor=dict(after_analysis_id='', after_ordinal=-1))],
                 [dict(end, has_more=True)])
        for pages in cases:
            with patch.object(report, 'show_assessment', side_effect=pages):
                with self.assertRaisesRegex(pg.PersistenceError, 'export_data_conflict'):
                    export.collect(object(), 'LAB-001', 1)

    def test_unknown_and_byte_limit_produce_no_files(self):
        for pages, expected, max_bytes in (([dict(status='not_found')], 'assessment_not_found', export.MAX_BYTES),
                                            ([sample()[0]], 'export_limit_exceeded', 10)):
            with tempfile.TemporaryDirectory() as td, patch.object(report, 'show_assessment', side_effect=pages), \
                    patch.object(export, 'MAX_BYTES', max_bytes):
                with self.assertRaisesRegex(pg.PersistenceError, expected):
                    export.collect(object(), 'LAB-001', 1)
                self.assertEqual(list(Path(td).iterdir()), [])

    def test_private_run_files_hashes_and_independent_repeat(self):
        with patch.object(report, 'show_assessment', side_effect=list(sample())):
            doc = export.collect(object(), 'LAB-001', 1)
        with tempfile.TemporaryDirectory() as td:
            one = export.save(doc, td)
            two = export.save(doc, td)
            self.assertNotEqual(one['export_dir'], two['export_dir'])
            self.assertEqual(one['manifest_sha256'], two['manifest_sha256'])
            run = Path(one['export_dir'])
            self.assertEqual(set(p.name for p in run.iterdir()), {'report.json', 'report.md', 'manifest.json', 'manifest.json.sha256'})
            manifest = json.loads((run/'manifest.json').read_bytes())
            for item in manifest['files']:
                raw = (run/item['name']).read_bytes()
                self.assertEqual(len(raw), item['size_bytes'])
                self.assertEqual(pg.digest(raw), item['sha256'])
                self.assertEqual((run/item['name']).stat().st_mode & 0o777, 0o600)
            self.assertEqual(run.stat().st_mode & 0o777, 0o700)
            self.assertEqual((run/'manifest.json.sha256').read_text(), one['manifest_sha256']+'  manifest.json\n')

    def test_failed_write_removes_only_its_staging_directory(self):
        with patch.object(report, 'show_assessment', side_effect=list(sample())):
            doc = export.collect(object(), 'LAB-001', 1)
        with tempfile.TemporaryDirectory() as td:
            unrelated = Path(td)/'keep.txt'
            unrelated.write_text('keep')
            with patch.object(os, 'fsync', side_effect=OSError('secret path')):
                with self.assertRaisesRegex(pg.PersistenceError, 'export_write_failed'):
                    export.save(doc, td)
            self.assertEqual(list(Path(td).iterdir()), [unrelated])
            self.assertEqual(unrelated.read_text(), 'keep')

    def test_markdown_persisted_text_is_inert(self):
        pages = list(sample())
        pages[0]['evaluations'][0]['rule']['title'] = '<img src=x> ![click](https://evil) |\n# injected'
        with patch.object(report, 'show_assessment', side_effect=pages):
            doc = export.collect(object(), 'LAB-001', 1)
        rendered = export.markdown(doc).decode('utf-8')
        self.assertNotIn('<img', rendered)
        self.assertNotIn('![click]', rendered)
        self.assertNotIn('\n# injected', rendered)
        self.assertIn('&lt;img', rendered)
        self.assertIn('&#124;', rendered)


@unittest.skipUnless(os.environ.get('CANCA_TEST_POSTGRES') == '1', 'real PostgreSQL integration opt-in required')
class PostgreSQLExportTests(unittest.TestCase):
    setUp = fixture.PostgreSQLReportTests.setUp
    source = fixture.PostgreSQLReportTests.source
    persist = fixture.PostgreSQLReportTests.persist

    def snapshot(self):
        tables = ('schema_migrations', 'assessments', 'nodes', 'runs', 'imports', 'artifacts', 'assessment_events',
                  'assets', 'asset_imports', 'asset_observations', 'asset_signals', 'finding_analyses',
                  'finding_evaluations', 'findings')
        return {t: self.conn.execute(f'SELECT row_to_json(t) FROM canca.{t} t ORDER BY row_to_json(t)::text').fetchall()
                for t in tables}

    def test_complete_history_export_preserves_all_tables_and_store(self):
        self.persist(self.source())
        self.persist(self.source(doc=fixture.fixture.target(False, False)))
        before = self.snapshot()
        files = {str(p): pg.digest(p.read_bytes()) for p in self.store.rglob('*') if p.is_file()}
        doc = export.collect(self.conn, 'LAB-001', 1)
        self.assertEqual(doc['export_consistency']['data_pages'], 4)
        self.assertEqual(doc['coverage']['outcomes']['finding'], 2)
        self.assertEqual(doc['coverage']['outcomes']['no_finding'], 2)
        self.assertTrue(all(r['finding_status'] == 'Open' for r in doc['evaluations'] if r['finding_id']))
        result = export.save(doc, self.base)
        saved = json.loads((Path(result['export_dir'])/'report.json').read_bytes())
        self.assertEqual(saved, doc)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(files, {str(p): pg.digest(p.read_bytes()) for p in self.store.rglob('*') if p.is_file()})

    def test_empty_and_pending_coverage_do_not_claim_clean_environment(self):
        fixture.life.register_assessment(self.conn, 'LAB-001')
        empty = export.collect(self.conn, 'LAB-001', 1)
        self.assertEqual(empty['coverage']['projection_status'], 'no_imports')
        self.assertEqual(empty['evaluations'], [])
        self.persist(self.source(), 'index')
        pending = export.collect(self.conn, 'LAB-001', 1)
        self.assertEqual(pending['coverage']['projection_status'], 'missing_analyses')
        self.assertEqual(len(pending['coverage']['imports_without_analysis']), 1)
        self.assertFalse(pending['source_bytes_revalidated'])
        self.assertNotIn('healthy', pending)

    def test_lifecycle_or_import_writer_blocks_export_even_after_last_data_page(self):
        for change in ('lifecycle', 'import'):
            self.conn.execute('DROP SCHEMA canca CASCADE')
            pg.migrate(self.conn)
            self.persist(self.source())
            later = self.source()
            actual = report.show_assessment
            fired = False
            def hooked(*args, **kwargs):
                nonlocal fired
                result = actual(*args, **kwargs)
                if not fired:
                    fired = True
                    with pg.open_connection() as writer:
                        if change == 'lifecycle':
                            fixture.life.transition(writer, 'LAB-001', 0, 'activate', 'active', 'operator')
                        else:
                            self.persist(later, 'index', writer)
                return result
            with patch.object(report, 'show_assessment', side_effect=hooked):
                with self.assertRaisesRegex(pg.PersistenceError, 'report_scope_conflict'):
                    export.collect(self.conn, 'LAB-001', 100)
            self.assertEqual(list(self.base.glob('P01-EXPORT-*')), [])

    def test_current_catalog_and_absent_source_store_do_not_rewrite_history(self):
        self.persist(self.source())
        expected = report.show_assessment(self.conn, 'LAB-001')
        import shutil
        shutil.rmtree(self.store)
        with patch.object(fixture.fixture.findings, 'catalog', side_effect=RuntimeError('must not load')):
            doc = export.collect(self.conn, 'LAB-001', 1)
        self.assertEqual(doc['catalogs'], expected['catalogs'])
        self.assertEqual(doc['evaluations'], expected['evaluations'])

    def test_unknown_schema_and_corrupt_counts_do_not_export(self):
        with self.assertRaisesRegex(pg.PersistenceError, 'assessment_not_found'):
            export.collect(self.conn, 'MISSING')
        self.persist(self.source())
        self.conn.execute('UPDATE canca.finding_analyses SET evaluation_count=3')
        with self.assertRaisesRegex(pg.PersistenceError, 'report_data_conflict'):
            export.collect(self.conn, 'LAB-001')
        self.conn.execute("UPDATE canca.schema_migrations SET sha256='bad' WHERE version=4")
        with self.assertRaisesRegex(pg.PersistenceError, 'schema_mismatch'):
            export.collect(self.conn, 'LAB-001')

    def test_select_only_reader_can_export_without_mutation_permissions(self):
        self.persist(self.source())
        before = self.snapshot()
        role = 'canca_export_reader_test'
        self.conn.execute('DROP ROLE IF EXISTS '+role)
        self.conn.execute('CREATE ROLE '+role)
        self.addCleanup(lambda: self.conn.execute('DROP ROLE IF EXISTS '+role))
        self.addCleanup(lambda: self.conn.execute('DROP OWNED BY '+role))
        self.conn.execute('GRANT USAGE ON SCHEMA canca TO '+role)
        self.conn.execute('GRANT SELECT ON canca.schema_migrations,canca.assessments,canca.imports,canca.artifacts,canca.assets,'
                          'canca.asset_imports,canca.asset_observations,canca.finding_analyses,canca.finding_evaluations,canca.findings TO '+role)
        self.conn.execute('SET ROLE '+role)
        try:
            result = export.save(export.collect(self.conn, 'LAB-001', 1), self.base)
            self.assertEqual(result['status'], 'exported')
            for sql in ('UPDATE canca.findings SET status=\'Open\'', 'DELETE FROM canca.findings',
                        "INSERT INTO canca.assessments(assessment_id) VALUES('DENIED')", 'CREATE TABLE canca.denied(id int)'):
                with self.assertRaises(Exception):
                    self.conn.execute(sql)
        finally:
            self.conn.execute('RESET ROLE')
        self.assertEqual(before, self.snapshot())
