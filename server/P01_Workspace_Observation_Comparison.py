#!/usr/bin/env python3
"""Bounded comparison of recorded signal values, never inferred configuration drift.

Reuses v0.6.32 authorization, revision fencing and observation validation. The
two cohorts are the latest and preceding *received-at times per signal kind*;
they are not proof of two distinct device scans or their collection times.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import P01_Workspace_Observed_Signals as observed

VERSION = '0.6.35'
MAX_KINDS = 100
MAX_DISTINCT_VALUES = 100


def compare(state):
    first = observed.project(state, after=0, limit=observed.PAGE_SIZE)
    rows = first['observations']
    if not first['complete']:
        second = observed.project(state, after=first['next_after'], limit=observed.PAGE_SIZE)
        observed.model.require(second['complete'] and second['revision'] == first['revision'])
        rows = rows + second['observations']
    grouped = {}
    for row in rows:
        for signal in row['signals']:
            kind, value = signal['kind'], signal['value']
            if kind not in grouped:
                observed.model.require(len(grouped) < MAX_KINDS)
                grouped[kind] = []
            epochs = grouped[kind]
            if not epochs or row['received_at_utc'] != epochs[-1]['received_at_utc']:
                if len(epochs) == 2:
                    continue
                epochs.append({'received_at_utc': row['received_at_utc'], 'values': {}})
            values = epochs[-1]['values']
            if value not in values:
                observed.model.require(len(values) < MAX_DISTINCT_VALUES)
                values[value] = []
            values[value].append({
                'collection_id': row['collection_id'],
                'ordinal': row['ordinal'],
                'created_revision': row['created_revision'],
                'source_reference_recorded': row['source_reference_recorded'],
            })
    fields = []
    for kind in sorted(grouped):
        epochs = grouped[kind]
        def projection(epoch):
            return {
                'received_at_utc': epoch['received_at_utc'],
                'values': [
                    {'value': value, 'provenance': epoch['values'][value]}
                    for value in sorted(epoch['values'])
                ],
            }
        latest = projection(epochs[0])
        earlier = projection(epochs[1]) if len(epochs) == 2 else None
        if earlier is None:
            comparison = 'insufficient_history'
        elif set(epochs[0]['values']) == set(epochs[1]['values']):
            comparison = 'same_recorded_values'
        else:
            comparison = 'different_recorded_values'
        fields.append({
            'kind': kind,
            'comparison': comparison,
            'latest': latest,
            'previous': earlier,
            'latest_conflicting': len(epochs[0]['values']) > 1,
            'previous_conflicting': len(epochs[1]['values']) > 1 if earlier else False,
        })
    return {
        'status': 'observed_comparison',
        'workspace_id': first['workspace_id'],
        'object_id': first['object_id'],
        'revision': first['revision'],
        'fields': fields,
        'compared_kind_count': sum(f['previous'] is not None for f in fields),
        'uncompared_kind_count': sum(f['previous'] is None for f in fields),
        'time_basis': 'import_received',
        'collection_time_known': False,
        'drift_assessed': False,
        'absence_implies_missing': False,
        'declarations_included': False,
        'source_refs_disclosed': False,
        'history_bound': observed.MAX_OBSERVATIONS,
    }


def object_comparison(conn, workspace_id, token, object_id, *, expected_revision=None):
    observed.model.ws.identifier(object_id)
    state = observed.model.object_state(
        conn, workspace_id, token, object_id, expected_revision=expected_revision
    )
    observed.model.require(
        state['workspace_id'] == workspace_id and state['object_id'] == object_id
    )
    return compare(state)
