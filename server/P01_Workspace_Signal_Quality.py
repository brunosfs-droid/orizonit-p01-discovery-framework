#!/usr/bin/env python3
"""Fail-closed quality diagnostics over the authorized v0.6.33 observed summary."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import P01_Workspace_Signal_Summary as summary

VERSION = '0.6.34'

def diagnose(result):
    require = summary.observed.model.require
    require(type(result) is dict and result.get('status') == 'observed_summary')
    summary.observed.model.ws.identifier(result.get('workspace_id'))
    summary.observed.model.ws.identifier(result.get('object_id'))
    require(type(result.get('revision')) is int and result['revision'] >= 0)
    require(result.get('time_basis') == 'import_received'
            and result.get('collection_time_known') is False
            and result.get('declared_values_included') is False
            and result.get('source_refs_disclosed') is False)
    fields = result.get('fields')
    require(type(fields) is list and len(fields) <= summary.MAX_KINDS)
    seen = set()
    entries = []
    for field in fields:
        require(type(field) is dict)
        kind = field.get('kind')
        require(type(kind) is str and kind and kind not in seen)
        seen.add(kind)
        values = field.get('values')
        require(type(values) is list and 1 <= len(values) <= summary.MAX_VALUES_PER_KIND)
        status = 'conflicting' if len(values) > 1 else 'observed'
        require(field.get('status') == status)
        require(type(field.get('received_at_utc')) is str and bool(field['received_at_utc']))
        provenance_count = 0
        for entry in values:
            require(type(entry) is dict and type(entry.get('value')) is str and bool(entry['value']))
            proof = entry.get('provenance')
            require(type(proof) is list and len(proof) >= 1)
            provenance_count += len(proof)
            require(provenance_count <= summary.observed.MAX_SIGNALS)
            for ref in proof:
                require(type(ref) is dict)
                summary.observed.model.ws.identifier(ref.get('collection_id'))
                require(type(ref.get('ordinal')) is int and ref['ordinal'] >= 0)
                require(type(ref.get('created_revision')) is int and ref['created_revision'] >= 0)
        entries.append({'kind': kind, 'status': status,
                        'distinct_observed_values': len(values),
                        'observation_references': provenance_count,
                        'time_basis': 'import_received'})
    return {'status': 'signal_quality', 'workspace_id': result['workspace_id'],
            'object_id': result['object_id'], 'revision': result['revision'],
            'fields': sorted(entries, key=lambda e: e['kind']),
            'observed_kind_count': len(entries),
            'conflicting_kind_count': sum(x['status']=='conflicting' for x in entries),
            'coverage': 'not_assessed', 'absence_implies_missing': False,
            'source_refs_disclosed': False, 'declarations_included': False}

def object_quality(conn, workspace_id, token, object_id, *, expected_revision=None):
    return diagnose(summary.object_summary(conn, workspace_id, token, object_id,
                                           expected_revision=expected_revision))
