#!/usr/bin/env python3
"""Contract tests for recorded observed signals; no database is required."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server'))
import P01_Workspace_Observed_Signals as reader


def state():
    return {
        'status': 'found', 'workspace_id': 'ws-a', 'object_id': 'host-1', 'revision': 7,
        'declarations': [{'attribute': 'hostname', 'value': 'manual-value'}],
        'observations': [
            {'collection_id': 'col-1', 'ordinal': 0, 'received_at_utc': '2026-10-08T00:00:00Z',
             'created_revision': 6, 'decision': 'new_identity', 'identity_eligible': True,
             'signals': [{'kind': 'hostname', 'value': 'observed-value'}],
             'source_refs': ['/private/secrets/file.json']},
            {'collection_id': 'col-2', 'ordinal': 1, 'received_at_utc': '2026-10-08T01:00:00Z',
             'created_revision': 7, 'decision': 'review_required', 'identity_eligible': False,
             'signals': [], 'source_refs': []},
        ]
    }


class ObservedSignalsTests(unittest.TestCase):
    def test_projection_never_promotes_declaration_or_discloses_path(self):
        result = reader.project(state())
        self.assertEqual(result['observations'][0]['signals'][0]['value'], 'observed-value')
        self.assertTrue(result['observations'][0]['source_reference_recorded'])
        self.assertNotIn('manual-value', str(result))
        self.assertNotIn('/private/secrets', str(result))
        self.assertFalse(result['collection_time_known'])
        self.assertTrue(result['complete'])

    def test_pagination_is_explicit_and_stable(self):
        first = reader.project(state(), limit=1)
        self.assertFalse(first['complete'])
        self.assertEqual(first['next_after'], 1)
        second = reader.project(state(), after=1, limit=1)
        self.assertTrue(second['complete'])
        self.assertEqual(second['observations'][0]['collection_id'], 'col-2')

    def test_continuation_requires_revision_fence_before_model_read(self):
        with patch.object(reader.model, 'object_state') as mocked:
            with self.assertRaises(Exception):
                reader.object_signals(None, 'ws-a', object(), 'host-1', after=1)
            mocked.assert_not_called()

    def test_model_is_called_with_revision_and_workspace_id_checked(self):
        with patch.object(reader.model, 'object_state', return_value=state()) as mocked:
            result = reader.object_signals(None, 'ws-a', object(), 'host-1', expected_revision=7)
            self.assertEqual(result['revision'], 7)
            self.assertEqual(mocked.call_args.kwargs, {'expected_revision': 7})
        with patch.object(reader.model, 'object_state', return_value={**state(), 'workspace_id': 'ws-b'}):
            with self.assertRaises(Exception):
                reader.object_signals(None, 'ws-a', object(), 'host-1')

    def test_malformed_data_fails_closed(self):
        cases = [
            {**state(), 'observations': 'not-list'},
            {**state(), 'observations': [{**state()['observations'][0], 'signals': [{'kind': 'x', 'value': None}]}]},
            {**state(), 'observations': [{**state()['observations'][0], 'identity_eligible': 'yes'}]},
            {**state(), 'observations': state()['observations'] * 51},
        ]
        for case in cases:
            with self.subTest(case=str(case)[:50]), self.assertRaises(Exception):
                reader.project(case)

    def test_rejects_boolean_cursor_and_limit(self):
        with self.assertRaises(Exception):
            reader.project(state(), after=True)
        with self.assertRaises(Exception):
            reader.project(state(), limit=False)


if __name__ == '__main__':
    unittest.main()
