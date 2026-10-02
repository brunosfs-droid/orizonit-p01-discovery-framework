"""Offline LAB fixtures never touch existing evidence or require PostgreSQL."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import test_postgres_findings as tools

PATH=Path(__file__).resolve().parents[1]/'docs/validation/POSTGRESQL_LAB_FIXTURE_R1_v0.6.5.py'
spec=importlib.util.spec_from_file_location('pg_lab_fixture',PATH)
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)


class PostgreSQLLabFixtureTests(unittest.TestCase):
    def test_prepare_valid_sources_with_positive_and_negative_rules_offline(self):
        with tempfile.TemporaryDirectory() as td,patch.object(tools.pg,'open_connection') as connect,patch('socket.socket',side_effect=AssertionError('network forbidden')):
            result=fixture.prepare(Path(td))
            self.assertEqual(result['assessment_id'],'P01-PG-LAB-R1');self.assertTrue(result['offline_synthetic'])
            projections=[tools.findings.prepare_findings(result['store_dir'],i['import_dir']) for i in result['imports']]
            self.assertEqual([r['result'] for p in projections for r in p['evaluations']],['finding','finding','no_finding','no_finding'])
            connect.assert_not_called()

    def test_repeated_preparation_creates_new_private_fixture_without_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);sentinel=root/'existing.txt';sentinel.write_text('preserve')
            first=fixture.prepare(root)
            files={str(p):p.read_bytes() for p in Path(first['fixture_directory']).rglob('*') if p.is_file()}
            second=fixture.prepare(root)
            self.assertNotEqual(first['fixture_directory'],second['fixture_directory'])
            self.assertEqual(sentinel.read_text(),'preserve')
            self.assertTrue(all(Path(p).read_bytes()==raw for p,raw in files.items()))

    def test_fixture_summary_and_original_bundles_have_valid_digests(self):
        with tempfile.TemporaryDirectory() as td:
            doc=fixture.prepare(td);base=Path(doc['fixture_directory'])
            summary=base/'fixture-summary.json'
            self.assertEqual(summary.with_suffix('.json.sha256').read_text().split()[0],tools.pg.digest(summary.read_bytes()))
            for package in base.glob('*/fixture.p01bundle'):
                self.assertEqual(tools.source.bundle_mod.validate_bundle(package)['credentialed_evidence_count'],1)
