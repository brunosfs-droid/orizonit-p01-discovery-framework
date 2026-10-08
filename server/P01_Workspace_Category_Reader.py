#!/usr/bin/env python3
"""Bounded, revision-pinned workspace inventory category reader (v0.6.30).

Uses the already-authorized model reader; never queries an unscoped database.
No inference from missing observations, no cross-workspace aggregation.
"""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'persistence'))
import P01_Workspace_Model as model

VERSION='0.6.30'
CATEGORY_KINDS={
    'compute':frozenset(('host',)),
    'network':frozenset(('device','interface','network','vlan')),
    'services':frozenset(('service','group')),
    'components':frozenset(('component','passive')),
}
MAX_PAGES=10
PAGE_SIZE=100


def inventory(conn, workspace_id, token, *, category, expected_revision=None, max_pages=MAX_PAGES):
    """Return stable category rows, or explicit incomplete pagination.

    Calls model.list_objects with revision fences on every page. The model owns
    SQL scope, workspace authorization, generation fencing and ordering.
    """
    model.token_args(workspace_id,token)
    model.require(type(category) is str and category in CATEGORY_KINDS)
    model.require(type(max_pages) is int and 1<=max_pages<=MAX_PAGES)
    if expected_revision is not None:
        model.runtime.require_generation(expected_revision)
    kinds=CATEGORY_KINDS[category]
    after='';seen=set();rows=[];revision=expected_revision
    for _ in range(max_pages):
        page=model.list_objects(conn,workspace_id,token,after=after,limit=PAGE_SIZE,
                                expected_revision=revision)
        model.require(page['workspace_id']==workspace_id and type(page['revision']) is int)
        if revision is None:revision=page['revision']
        model.require(page['revision']==revision)
        objects=page['objects']
        model.require(type(objects) is list and len(objects)<=PAGE_SIZE)
        for obj in objects:
            oid=obj['object_id']
            model.ws.identifier(oid)
            model.require(oid not in seen and oid>after)
            seen.add(oid)
            if obj['kind'] in kinds:
                rows.append({k:obj[k] for k in ('object_id','kind','label','site_id','environment_id','origin','created_revision')})
        more=page['has_more']
        model.require(type(more) is bool)
        if not more:
            return dict(status='listed',workspace_id=workspace_id,revision=revision,
                        category=category,objects=rows,complete=True,next_after=None)
        cursor=page['next_after']
        model.ws.identifier(cursor)
        model.require(objects and cursor==objects[-1]['object_id'] and cursor>after)
        after=cursor
    return dict(status='listed',workspace_id=workspace_id,revision=revision,
                category=category,objects=rows,complete=False,next_after=after)
