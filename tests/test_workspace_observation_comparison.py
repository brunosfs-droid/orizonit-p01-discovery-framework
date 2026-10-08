"""Contract tests for recorded-vs-recorded comparisons, without device inference."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server'))
import P01_Workspace_Observation_Comparison as comparison
from test_workspace_observed_signals import state


class ComparisonTests(unittest.TestCase):
    def test_two_distinct_epochs_and_provenance_are_preserved(self):
        s = state()
        s['observations'][1]['signals'] = [{'kind': 'hostname', 'value': 'older'}]
        result = comparison.compare(s)
        field = result['fields'][0]
        self.assertEqual(field['comparison'], 'different_recorded_values')
        self.assertEqual(field['latest']['values'][0]['value'], 'observed-value')
        self.assertEqual(field['previous']['values'][0]['value'], 'older')
        self.assertEqual(field['latest']['values'][0]['provenance'][0]['collection_id'], 'col-1')
        self.assertEqual(field['previous']['values'][0]['provenance'][0]['ordinal'], 1)
        self.assertFalse(result['drift_assessed'])
        self.assertFalse(result['absence_implies_missing'])
        self.assertNotIn('manual-value', str(result))
        self.assertNotIn('/private/secrets', str(result))

    def test_no_prior_epoch_is_insufficient_not_absent(self):
        result = comparison.compare(state())
        self.assertEqual(result['fields'][0]['comparison'], 'insufficient_history')
        self.assertIsNone(result['fields'][0]['previous'])
        self.assertEqual(result['compared_kind_count'], 0)
        self.assertEqual(result['uncompared_kind_count'], 1)

    def test_identical_values_from_distinct_receipts(self):
        s = state()
        s['observations'][1]['signals'] = [{'kind': 'hostname', 'value': 'observed-value'}]
        field = comparison.compare(s)['fields'][0]
        self.assertEqual(field['comparison'], 'same_recorded_values')
        self.assertFalse(field['latest_conflicting'])

    def test_same_receipt_epoch_multiple_conflicts_do_not_create_history(self):
        s = state()
        s['observations'][1]['received_at_utc'] = s['observations'][0]['received_at_utc']
        s['observations'][1]['signals'] = [{'kind': 'hostname', 'value': 'other'}]
        result = comparison.compare(s)
        self.assertEqual(result['fields'][0]['comparison'], 'insufficient_history')
        self.assertTrue(result['fields'][0]['latest_conflicting'])

    def test_empty_history_is_explicitly_unassessed(self):
        s = state()
        s['observations'] = []
        result = comparison.compare(s)
        self.assertEqual(result['fields'], [])
        self.assertEqual(result['compared_kind_count'], 0)
        self.assertFalse(result['drift_assessed'])

    def test_second_page_retains_provenance_and_older_epoch(self):
        s = state()
        s['observations'] = [
            {**s['observations'][0], 'ordinal': i}
            for i in range(50)
        ] + [{**s['observations'][1], 'signals': [{'kind': 'hostname', 'value': 'older'}]}]
        result = comparison.compare(s)
        self.assertEqual(result['fields'][0]['comparison'], 'different_recorded_values')
        self.assertEqual(len(result['fields'][0]['latest']['values'][0]['provenance']), 50)

    def test_too_many_kinds_and_invalid_observations_fail_closed(self):
        s = state()
        s['observations'][0]['signals'] = [
            {'kind': 'kind-' + str(i), 'value': 'v'} for i in range(101)
        ]
        with self.assertRaises(Exception):
            comparison.compare(s)
        bad = state()
        bad['observations'][0]['source_refs'] = ['/private/secret']
        bad['observations'][0]['signals'] = [{'kind': 'x', 'value': None}]
        with self.assertRaises(Exception):
            comparison.compare(bad)

    def test_scope_and_revision_are_enforced_by_model_reader(self):
        with patch.object(comparison.observed.model, 'object_state', return_value=state()) as read:
            result = comparison.object_comparison(None, 'ws-a', object(), 'host-1', expected_revision=7)
            self.assertEqual(result['revision'], 7)
            self.assertEqual(read.call_args.kwargs, {'expected_revision': 7})
        with patch.object(comparison.observed.model, 'object_state', return_value={**state(), 'workspace_id': 'ws-b'}):
            with self.assertRaises(Exception):
                comparison.object_comparison(None, 'ws-a', object(), 'host-1')


if __name__ == '__main__':
    unittest.main()
