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


def inventory(conn, workspace_id, token, *, category, expected_revision=None, max_pages=MAX_PAGES, after='', site_id=None, environment_id=None, kind=None, origin=None):
    """Return stable category rows, or explicit incomplete pagination.

    Calls model.list_objects with revision fences on every page. The model owns
    SQL scope, workspace authorization, generation fencing and ordering.
    """
    model.token_args(workspace_id,token)
    model.require(type(category) is str and category in CATEGORY_KINDS)
    model.require(type(max_pages) is int and 1<=max_pages<=MAX_PAGES)
    model.require(type(after) is str)
    if after:
        model.ws.identifier(after)
        model.require(expected_revision is not None)
    if expected_revision is not None:
        model.runtime.require_generation(expected_revision)
    for location in (site_id,environment_id):
        if location is not None:model.ws.identifier(location)
    kinds=CATEGORY_KINDS[category]
    if kind is not None:model.require(type(kind) is str and kind in kinds)
    if origin is not None:model.require(type(origin) is str and origin in ('declared','observed'))
    seen=set();rows=[];revision=expected_revision;last_oid=after;scanned=0
    for _ in range(max_pages):
        page=model.list_objects(conn,workspace_id,token,after=after,limit=PAGE_SIZE,
                                expected_revision=revision)
        model.require(page['workspace_id']==workspace_id and type(page['revision']) is int)
        if revision is None:revision=page['revision']
        model.require(page['revision']==revision)
        objects=page['objects']
        model.require(type(objects) is list and len(objects)<=PAGE_SIZE)
        model.require(type(page['has_more']) is bool)
        model.require(not page['has_more'] or bool(objects))
        for obj in objects:
            model.require(type(obj) is dict and set(('object_id','kind','label','site_id','environment_id','origin','created_revision'))<=set(obj))
            model.require(type(obj['kind']) is str and obj['kind'] in model.KINDS)
            model.require(type(obj['origin']) is str and obj['origin'] in ('declared','observed'))
            for location in ('site_id','environment_id'):
                model.require(obj[location] is None or isinstance(obj[location],str))
                if obj[location] is not None:model.ws.identifier(obj[location])
            model.require(type(obj['created_revision']) is int and obj['created_revision']>=0)
            model.ws.label(obj['label'])
            oid=obj['object_id']
            model.ws.identifier(oid)
            model.require(oid not in seen and oid>after and oid>last_oid)
            last_oid=oid
            seen.add(oid);scanned+=1
            if obj['kind'] in kinds and (site_id is None or obj['site_id']==site_id) and (environment_id is None or obj['environment_id']==environment_id) and (kind is None or obj['kind']==kind) and (origin is None or obj['origin']==origin):
                rows.append({k:obj[k] for k in ('object_id','kind','label','site_id','environment_id','origin','created_revision')})
        more=page['has_more']
        model.require(type(more) is bool)
        if not more:
            return dict(status='listed',workspace_id=workspace_id,revision=revision,
                        category=category,objects=rows,complete=True,next_after=None,
                        scanned=scanned,matched=len(rows),filters=dict(site_id=site_id,environment_id=environment_id,kind=kind,origin=origin))
        cursor=page['next_after']
        model.ws.identifier(cursor)
        model.require(objects and cursor==objects[-1]['object_id'] and cursor>after)
        after=cursor
    return dict(status='listed',workspace_id=workspace_id,revision=revision,
                category=category,objects=rows,complete=False,next_after=after,
                scanned=scanned,matched=len(rows),filters=dict(site_id=site_id,environment_id=environment_id,kind=kind,origin=origin))
