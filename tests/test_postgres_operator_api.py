"""Canonical report equality and unchanged PostgreSQL behind real operator HTTP."""
import importlib.util
import io
import os
from pathlib import Path
from contextlib import redirect_stdout
import unittest
from unittest.mock import patch

import test_postgres_recovery as fixture
import test_operator_api as http_fixture

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('local_operator_lab',ROOT/'docs/validation/LOCAL_OPERATOR_LAB_R1_v0.6.11.py')
lab=importlib.util.module_from_spec(spec);spec.loader.exec_module(lab)


class OperatorLabBoundaryTests(unittest.TestCase):
    def test_wrong_lab_database_or_host_fails_before_connection(self):
        for database,host in [('canca_ci','127.0.0.1'),('canca_p01_restore_r1','192.0.2.1')]:
            with patch.dict(os.environ,{'PGDATABASE':database,'PGHOST':host}),patch.object(lab.api.report.pg,'open_connection') as connection,redirect_stdout(io.StringIO()):
                self.assertEqual(lab.cli([]),2)
            connection.assert_not_called()


@unittest.skipUnless(os.environ.get('CANCA_TEST_POSTGRES')=='1','real PostgreSQL CI opt-in required')
class PostgreSQLOperatorTests(unittest.TestCase):
    setUp=fixture.PostgreSQLRecoveryTests.setUp

    def test_real_operator_http_pages_equal_canonical_without_database_mutation(self):
        result=lab.exercise('canca_ci')
        self.assertEqual(result['status'],'LOCAL OPERATOR LAB PASS')
        self.assertEqual(result['tables_compared'],14)
        self.assertFalse(result['database_mutated'])
        self.assertTrue(result['terminal_empty_checked'])

    def test_reader_database_role_can_read_through_operator_boundary(self):
        role='canca_operator_reader_ci'
        self.conn.execute('DROP ROLE IF EXISTS '+role)
        self.conn.execute('CREATE ROLE '+role)
        self.conn.execute('GRANT USAGE ON SCHEMA canca TO '+role)
        self.conn.execute('GRANT SELECT ON ALL TABLES IN SCHEMA canca TO '+role)
        original=lab.api.report.pg.open_connection
        def reader():
            connection=original();connection.execute('SET ROLE '+role)
            return connection
        try:
            with patch.object(lab.api.report.pg,'open_connection',side_effect=reader):
                result=lab.exercise('canca_ci')
            self.assertEqual(result['status'],'LOCAL OPERATOR LAB PASS')
        finally:
            self.conn.execute('DROP OWNED BY '+role)
            self.conn.execute('DROP ROLE '+role)


if __name__=='__main__':unittest.main()
