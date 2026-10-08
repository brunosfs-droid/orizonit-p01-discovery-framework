#!/usr/bin/env python3
"""Revision-fenced bounded per-object observed signal summary (v0.6.33).

Only stored observations are eligible. Received timestamps describe ingestion,
not device collection time. No declarations or source paths enter this projection.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server'))
import P01_Workspace_Observed_Signals as observed

MAX_KINDS = 100
MAX_VALUES_PER_KIND = 100


def summarize(state):
    # Reuse the v0.6.32 full-history validation and provenance redaction.
    page = observed.project(state, after=0, limit=observed.PAGE_SIZE)
    rows = list(page['observations'])
    if not page['complete']:
        tail = observed.project(state, after=page['next_after'], limit=observed.PAGE_SIZE)
        rows.extend(tail['observations'])
        observed.model.require(tail['complete'])
    grouped = {}
    for row in rows:
        for signal in row['signals']:
            kind, value = signal['kind'], signal['value']
            if kind not in grouped:
                observed.model.require(len(grouped) < MAX_KINDS)
                grouped[kind] = {'timestamp': row['received_at_utc'], 'values': {}}
            group = grouped[kind]
            # The input order comes from model.object_state, which sorts latest
            # first. Do not infer the newest timestamp from lexical string sort.
            if row['received_at_utc'] != group['timestamp']:
                continue
            values = group['values']
            if value not in values:
                observed.model.require(len(values) < MAX_VALUES_PER_KIND)
                values[value] = []
            values[value].append({'collection_id': row['collection_id'], 'ordinal': row['ordinal'],
                                  'created_revision': row['created_revision']})
    fields = []
    for kind in sorted(grouped):
        group = grouped[kind]
        entries = [{'value': v, 'provenance': group['values'][v]} for v in sorted(group['values'])]
        fields.append({'kind': kind, 'received_at_utc': group['timestamp'], 'values': entries,
                       'status': 'conflicting' if len(entries) > 1 else 'observed'})
    return {'status': 'observed_summary', 'workspace_id': page['workspace_id'],
            'object_id': page['object_id'], 'revision': page['revision'],
            'fields': fields, 'time_basis': 'import_received',
            'collection_time_known': False, 'declared_values_included': False,
            'source_refs_disclosed': False, 'history_bound': observed.MAX_OBSERVATIONS}


def object_summary(conn, workspace_id, token, object_id, *, expected_revision=None):
    observed.model.ws.identifier(object_id)
    state = observed.model.object_state(conn, workspace_id, token, object_id,
                                        expected_revision=expected_revision)
    observed.model.require(state['workspace_id'] == workspace_id and state['object_id'] == object_id)
    return summarize(state)
