"""Web listener real PostgreSQL report equality, fence and 14-table invariance."""
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_postgres_operator_api as fixture
import P01_Operator_Web as web


@unittest.skipUnless(os.environ.get('CANCA_TEST_POSTGRES') == '1', 'real PostgreSQL CI opt-in required')
class PostgreSQLOperatorWebTests(unittest.TestCase):
    setUp = fixture.fixture.PostgreSQLRecoveryTests.setUp

    def test_web_listener_matches_canonical_report_without_mutation(self):
        boundary = SimpleNamespace(report=web.api.report, VERSION=web.VERSION, create_server=web.create_server)
        with patch.object(fixture.lab, 'api', boundary):
            result = fixture.lab.exercise('canca_ci')
        self.assertEqual(result['operator_version'], '0.6.12')
        self.assertTrue(result['canonical_report_match'])
        self.assertTrue(result['fenced_pages_match'])
        self.assertEqual(result['tables_compared'], 14)
        self.assertFalse(result['database_mutated'])
        self.assertTrue(result['temporary_credentials_removed'])


if __name__ == '__main__': unittest.main()
