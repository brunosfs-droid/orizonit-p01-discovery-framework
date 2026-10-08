#!/usr/bin/env python3
"""Bounded read-only projection of *recorded* workspace observations (v0.6.32).

Values are returned only if a stored observation contains the signal. The
reader does not probe devices, infer missing signals or elevate declarations.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'persistence'))
import P01_Workspace_Model as model

VERSION = '0.6.32'
MAX_OBSERVATIONS = 100
MAX_SIGNALS = 1000
PAGE_SIZE = 50


def project(state, *, after=0, limit=PAGE_SIZE):
    """Validate an authorized object_state result, then project stable observations.

    Cursor is an ordinal within the same object_state snapshot, never a grant.
    All continuation calls MUST supply expected_revision to object_signals.
    Provenance points at collection_id and ordinal; original source_refs are
    intentionally excluded from this response to avoid disclosing file paths.
    """
    model.require(type(state) is dict and state.get('status') == 'found')
    model.require(type(state.get('revision')) is int and state['revision'] >= 0)
    model.ws.identifier(state.get('workspace_id'))
    model.ws.identifier(state.get('object_id'))
    model.require(type(after) is int and 0 <= after <= MAX_OBSERVATIONS)
    model.require(type(limit) is int and 1 <= limit <= PAGE_SIZE)
    history = state.get('observations')
    model.require(type(history) is list and len(history) <= MAX_OBSERVATIONS)
    model.require(after <= len(history))
    items = []
    count = 0
    for i, obs in enumerate(history):
        model.require(type(obs) is dict)
        model.require(type(obs.get('signals')) is list)
        model.ws.identifier(obs.get('collection_id'))
        model.require(type(obs.get('ordinal')) is int and obs['ordinal'] >= 0)
        model.require(type(obs.get('received_at_utc')) is str and bool(obs['received_at_utc']))
        model.require(type(obs.get('created_revision')) is int and obs['created_revision'] >= 0)
        model.require(type(obs.get('identity_eligible')) is bool)
        for signal in obs['signals']:
            count += 1
            model.require(count <= MAX_SIGNALS)
            model.require(type(signal) is dict and set(signal) >= {'kind', 'value'})
            model.require(type(signal['kind']) is str and bool(signal['kind']))
            model.require(type(signal['value']) is str and bool(signal['value']))
        if i < after or i >= after + limit:
            continue
        items.append({
            'collection_id': obs['collection_id'],
            'ordinal': obs['ordinal'],
            'received_at_utc': obs['received_at_utc'],
            'created_revision': obs['created_revision'],
            'decision': obs.get('decision'),
            'identity_eligible': obs['identity_eligible'],
            'signals': [{'kind': s['kind'], 'value': s['value']} for s in obs['signals']],
            'source_reference_recorded': bool(obs.get('source_refs')),
        })
    end = min(after + limit, len(history))
    return {
        'status': 'observed_signals', 'workspace_id': state['workspace_id'],
        'object_id': state['object_id'], 'revision': state['revision'],
        'observations': items, 'complete': end == len(history),
        'next_after': None if end == len(history) else end,
        'history_bound': MAX_OBSERVATIONS,
        'time_basis': 'import_received',
        'collection_time_known': False,
        'declarations_included': False,
        'source_refs_disclosed': False,
    }


def object_signals(conn, workspace_id, token, object_id, *, expected_revision=None,
                   after=0, limit=PAGE_SIZE):
    model.ws.identifier(object_id)
    model.require(type(after) is int and 0 <= after <= MAX_OBSERVATIONS)
    model.require(type(limit) is int and 1 <= limit <= PAGE_SIZE)
    model.require(after == 0 or expected_revision is not None)
    state = model.object_state(conn, workspace_id, token, object_id,
                               expected_revision=expected_revision)
    model.require(state['workspace_id'] == workspace_id and state['object_id'] == object_id)
    return project(state, after=after, limit=limit)
