#!/usr/bin/env python3
"""Bounded read-only category overview of recorded signal attributes.

Counts recorded attributes, not scanner or network discovery coverage.
All object reads are revision-fenced and workspace-scoped.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import P01_Workspace_Category_Reader as categories
import P01_Workspace_Signal_Summary as summary

VERSION = '0.6.36'
MAX_OBJECTS = 20


def overview(conn, workspace_id, token, *, category, expected_revision=None,
             after='', limit=MAX_OBJECTS, site_id=None, environment_id=None,
             kind=None, origin=None):
    model = categories.model
    model.require(type(limit) is int and 1 <= limit <= MAX_OBJECTS)
    page = categories.inventory(conn, workspace_id, token, category=category,
                                expected_revision=expected_revision, max_pages=1,
                                after=after, site_id=site_id, environment_id=environment_id,
                                kind=kind, origin=origin)
    model.require(page['workspace_id'] == workspace_id and page['category'] == category)
    model.require(type(page['revision']) is int and page['revision'] >= 0)
    model.require(type(page['complete']) is bool)
    objs = page['objects']
    model.require(type(objs) is list and len(objs) <= categories.PAGE_SIZE)
    selected = objs[:limit]
    rows = []
    for obj in selected:
        oid = model.ws.identifier(obj['object_id'])
        state = summary.object_summary(conn, workspace_id, token, oid,
                                       expected_revision=page['revision'])
        model.require(state['workspace_id'] == workspace_id and state['object_id'] == oid
                      and state['revision'] == page['revision']
                      and state['status'] == 'observed_summary')
        fields = state['fields']
        model.require(type(fields) is list and len(fields) <= summary.MAX_KINDS)
        model.require(all(type(f) is dict and f.get('status') in
                          ('observed','conflicting') for f in fields))
        rows.append({'object_id': oid, 'kind': obj['kind'], 'origin': obj['origin'],
                     'observed_kind_count': len(fields),
                     'conflicting_kind_count': sum(f['status']=='conflicting' for f in fields),
                     'observation_status': 'recorded' if fields else 'not_recorded_in_object_history'})
    if len(objs) > limit:
        cursor = selected[-1]['object_id']
        complete = False
    else:
        cursor = page['next_after']
        complete = page['complete']
    model.require(complete or type(cursor) is str and bool(cursor))
    if cursor is not None:
        model.ws.identifier(cursor)
        model.require(cursor > after)
    return {'status': 'category_signal_coverage', 'workspace_id': workspace_id,
            'revision': page['revision'], 'category': category, 'objects': rows,
            'complete': complete, 'next_after': None if complete else cursor,
            'scanned_registered_objects': page['scanned'],
            'evaluated_objects': len(rows), 'filters': page['filters'],
            'collection_coverage': 'not_assessed', 'absence_implies_missing': False,
            'declarations_included': False, 'source_refs_disclosed': False}
