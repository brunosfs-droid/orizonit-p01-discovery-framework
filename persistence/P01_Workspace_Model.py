#!/usr/bin/env python3
"""Opt-in workspace history, manual graph and revision-fenced reconciliation.

Observed import API is trusted: prepare_source verifies original bytes first.
No scanner, HTTP server, legacy backfill, secrets or network-side action.
"""
from contextlib import contextmanager
from datetime import datetime
import argparse
import ipaddress
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
import P01_Asset_Registry as registry
import P01_Workspace_Coordinator as runtime

ws, pg = runtime.ws, runtime.pg
VERSION='0.6.25'
POLICY='workspace-identity-1'
KINDS=('host','device','interface','component','network','vlan','service','group','passive')
RELATIONS=('connected_to','hosted_on','member_of','depends_on','available_on','located_in')
ATTRIBUTES=set(registry.KINDS)|{'display_name','manufacturer','model','description','operating_system',
    'os_build','capacity_bytes','free_bytes','vlan_id','vlan_namespace','cidr'}
ERRORS=runtime.ERRORS|registry.ERRORS|{'model_input_invalid','model_revision_stale','model_request_conflict',
    'model_object_not_found','model_plan_not_found','model_review_required','model_import_conflict',
    'model_relationship_conflict','model_history_bound','model_context_denied'}


def require(value):pg.require(value,'model_input_invalid')


def digest(value):return pg.digest(pg.canonical(value))


def text(value,maximum=1024):
    require(isinstance(value,str) and 1<=len(value)<=maximum and value.strip()==value
            and not any(ord(c)<32 or 127<=ord(c)<=159 for c in value))
    try:value.encode('utf-8')
    except UnicodeError:raise pg.PersistenceError('model_input_invalid') from None
    return value


def attribute(name,value):
    require(isinstance(name,str) and name in ATTRIBUTES)
    if value is None:return
    if name in ('capacity_bytes','free_bytes','vlan_id'):
        require(type(value) is int and 0<=value<2**63 and (name!='vlan_id' or 1<=value<=4094));return
    text(value)
    if name in registry.KINDS:require(registry.normalized(name,value)==value)
    if name=='cidr':
        try:require(str(ipaddress.ip_network(value,strict=False))==value)
        except ValueError:raise pg.PersistenceError('model_input_invalid') from None


def prepare_source(store,import_dir):
    """Private replay from verified receipt/bundle; copied resolver claims never trusted."""
    projection=registry.prepare_assets(store,import_dir)
    validate_source(projection)
    return projection


def validate_source(projection):
    registry.validate_projection(projection)
    require(len(projection['observations'])<=1000 and len(pg.canonical(projection))<=4*1024*1024)
    moment=datetime.fromisoformat(projection['import']['imported_at_utc'])
    require(moment.utcoffset() is not None and moment.utcoffset().total_seconds()==0)


def token_args(workspace_id,token):
    ws.identifier(workspace_id)
    require(type(token) is runtime.Token and token.workspace_id==workspace_id)
    runtime.require_generation(token.generation)
    require(isinstance(token.lease_id,str) and len(token.lease_id)==32 and all(c in '0123456789abcdef' for c in token.lease_id))


@contextmanager
def scope(conn,workspace_id,token,*,writing=False):
    token_args(workspace_id,token)
    with ws.scope(conn,workspace_id,'workspace:write' if writing else 'workspace:read'):
        pg.schema_check(conn,minimum=7,model=True)
        conn.execute("SELECT set_config('canca.workspace_generation',%s,true)",(str(token.generation),))
        conn.execute("SELECT set_config('canca.workspace_lease',%s,true)",(token.lease_id,))
        allowed=conn.execute('SELECT canca.workspace_model_allowed(%s)',(writing,)).fetchone()[0]
        pg.require(allowed,'model_context_denied')
        revision=conn.execute('SELECT canca.workspace_revision_lock(%s)',(writing,)).fetchone()[0]
        pg.require(revision is not None,'model_context_denied')
        yield revision
        # Revalidate before successful exit/commit; runtime row stays locked until
        # transaction end, so close/recovery cannot change workspace in between.
        pg.require(conn.execute('SELECT canca.workspace_model_allowed(%s)',(writing,)).fetchone()[0],'model_context_denied')


def check_revision(expected,revision):
    runtime.require_generation(expected)
    pg.require(expected==revision,'model_revision_stale')


def object_exists(conn,workspace_id,object_id):
    row=conn.execute('SELECT kind,label,site_id,environment_id,origin,created_revision FROM canca.workspace_objects '
        'WHERE workspace_id=%s AND object_id=%s',(workspace_id,object_id)).fetchone()
    pg.require(row,'model_object_not_found');return row


def replay(conn,workspace_id,request_id,payload):
    old=conn.execute('SELECT payload_sha256,result FROM canca.workspace_model_requests WHERE workspace_id=%s AND request_id=%s',
        (workspace_id,request_id)).fetchone()
    if old:
        pg.require(old[0]==digest(payload),'model_request_conflict')
        return dict(old[1],replayed=True)
    return None


def receipt(conn,workspace_id,request_id,payload,result):
    revision=conn.execute('SELECT revision FROM canca.workspace_revisions WHERE workspace_id=%s',(workspace_id,)).fetchone()[0]
    result=dict(result,revision=revision,replayed=False)
    conn.execute('INSERT INTO canca.workspace_model_requests (workspace_id,request_id,payload_sha256,result,created_revision) '
        'VALUES (%s,%s,%s,%s::jsonb,0)',(workspace_id,request_id,digest(payload),json.dumps(result)))
    return result


def declare_object(conn,workspace_id,token,expected_revision,request_id,object_id,kind,label,*,
                   attributes=None,site_id=None,environment_id=None,reason):
    ws.identifier(request_id);ws.identifier(object_id);ws.label(label);text(reason)
    require(kind in KINDS)
    for value in (site_id,environment_id):
        if value is not None:ws.identifier(value)
    attributes={} if attributes is None else attributes
    require(type(attributes) is dict and len(attributes)<=len(ATTRIBUTES))
    for name,value in attributes.items():attribute(name,value)
    if kind=='vlan':require(attributes.get('vlan_id') is not None and attributes.get('vlan_namespace') is not None)
    payload=dict(op='declare_object',expected_revision=expected_revision,object_id=object_id,kind=kind,label=label,
                 attributes=attributes,site_id=site_id,environment_id=environment_id,reason=reason)
    runtime.require_generation(expected_revision)
    with scope(conn,workspace_id,token,writing=True) as revision:
        old=replay(conn,workspace_id,request_id,payload)
        if old:return old
        check_revision(expected_revision,revision)
        exists=conn.execute('SELECT 1 FROM canca.workspace_objects WHERE workspace_id=%s AND object_id=%s',(workspace_id,object_id)).fetchone()
        pg.require(not exists,'model_request_conflict')
        conn.execute('INSERT INTO canca.workspace_objects (workspace_id,object_id,kind,label,site_id,environment_id,origin,created_revision) '
            "VALUES (%s,%s,%s,%s,%s,%s,'declared',0)",(workspace_id,object_id,kind,label,site_id,environment_id))
        for name,value in sorted(attributes.items()):
            declaration='dec-'+digest([request_id,name])[:32]
            conn.execute('INSERT INTO canca.workspace_declarations (workspace_id,declaration_id,object_id,attribute,value,reason,created_revision) '
                'VALUES (%s,%s,%s,%s,%s::jsonb,%s,0)',(workspace_id,declaration,object_id,name,json.dumps(value),reason))
        return receipt(conn,workspace_id,request_id,payload,{'status':'declared','object_id':object_id})


def declare_attribute(conn,workspace_id,token,expected_revision,request_id,object_id,name,value,reason):
    ws.identifier(request_id);ws.identifier(object_id);attribute(name,value);text(reason)
    runtime.require_generation(expected_revision)
    payload=dict(op='declare_attribute',expected_revision=expected_revision,object_id=object_id,name=name,value=value,reason=reason)
    with scope(conn,workspace_id,token,writing=True) as revision:
        old=replay(conn,workspace_id,request_id,payload)
        if old:return old
        check_revision(expected_revision,revision);object_exists(conn,workspace_id,object_id)
        conn.execute('INSERT INTO canca.workspace_declarations (workspace_id,declaration_id,object_id,attribute,value,reason,created_revision) '
            'VALUES (%s,%s,%s,%s,%s::jsonb,%s,0)',(workspace_id,'dec-'+digest(request_id)[:32],object_id,name,json.dumps(value),reason))
        return receipt(conn,workspace_id,request_id,payload,{'status':'declared','object_id':object_id,'attribute':name})


def relationship(conn,workspace_id,token,expected_revision,request_id,relationship_id,source_id,target_id,kind,*,active=True,reason):
    for value in (request_id,relationship_id,source_id,target_id):ws.identifier(value)
    require(kind in RELATIONS and type(active) is bool and source_id!=target_id);text(reason)
    runtime.require_generation(expected_revision)
    payload=dict(op='relationship',expected_revision=expected_revision,relationship_id=relationship_id,
                 source_id=source_id,target_id=target_id,kind=kind,active=active,reason=reason)
    with scope(conn,workspace_id,token,writing=True) as revision:
        old=replay(conn,workspace_id,request_id,payload)
        if old:return old
        check_revision(expected_revision,revision)
        object_exists(conn,workspace_id,source_id);object_exists(conn,workspace_id,target_id)
        row=conn.execute('SELECT source_id,target_id,kind FROM canca.workspace_relationships WHERE workspace_id=%s AND relationship_id=%s LIMIT 1',
            (workspace_id,relationship_id)).fetchone()
        pg.require(not row or row==(source_id,target_id,kind),'model_relationship_conflict')
        conn.execute('INSERT INTO canca.workspace_relationships (workspace_id,relationship_id,event_id,source_id,target_id,kind,active,reason,created_revision) '
            'VALUES (%s,%s,%s,%s,%s,%s,%s,%s,0)',(workspace_id,relationship_id,'evt-'+digest(request_id)[:32],source_id,target_id,kind,active,reason))
        return receipt(conn,workspace_id,request_id,payload,{'status':'declared','relationship_id':relationship_id,'active':active})


def choose(conn,workspace_id,obs):
    if obs['local_review']:return {'decision':'review_required','reason':'local_conflict','candidates':[],'object_id':None}
    signals=obs['signals'];current=registry.qualified(signals)
    if not signals:return {'decision':'review_required','reason':'insufficient_identity','candidates':[],'object_id':None}
    conditions=' OR '.join('(kind=%s AND value=%s)' for _ in signals);params=[workspace_id]
    for s in signals:params.extend((s['kind'],s['value']))
    rows=conn.execute('SELECT DISTINCT object_id FROM canca.workspace_identity_signals WHERE workspace_id=%s AND eligible AND ('+
        conditions+') ORDER BY object_id LIMIT 101',params).fetchall()
    candidates=[r[0] for r in rows[:100]]
    if len(rows)>100:return dict(decision='review_required',reason='candidate_bound',candidates=candidates,object_id=None)
    if not candidates:
        kinds={k for k,v in current}
        sufficient=bool(kinds&registry.STRONG) and len(kinds)>=2
        return dict(decision='new_identity' if sufficient else 'review_required',reason='new_identity' if sufficient else 'insufficient_identity',
                    candidates=[],object_id=None)
    eligible=[]
    for object_id in candidates:
        history=conn.execute('SELECT signals FROM canca.workspace_observations WHERE workspace_id=%s AND object_id=%s '
            'AND identity_eligible ORDER BY collection_id,ordinal LIMIT 101',(workspace_id,object_id)).fetchall()
        if len(history)>100:return dict(decision='review_required',reason='history_bound',candidates=candidates,object_id=None)
        old=set().union(*(registry.qualified(row[0]) for row in history)) if history else set()
        conflicting=any({v for k,v in current if k==kind} and {v for k,v in old if k==kind} and
            not ({v for k,v in current if k==kind}&{v for k,v in old if k==kind}) for kind in registry.STRONG)
        if not conflicting and any(({k for k,v in current&registry.qualified(row[0])}&registry.STRONG) and
            len({k for k,v in current&registry.qualified(row[0])})>=2 for row in history):eligible.append(object_id)
    if len(candidates)==len(eligible)==1:return dict(decision='corroborated_identity',reason='corroborated_identity',candidates=candidates,object_id=eligible[0])
    return dict(decision='review_required',reason='ambiguous_identity',candidates=candidates,object_id=None)


def identity_eligible(conn,workspace_id,object_id,obs,decision):
    if decision in ('new_identity','corroborated_identity'):return True
    if decision!='manual_link' or obs['local_review']:return False
    current=registry.qualified(obs['signals']);kinds={k for k,v in current}
    if not kinds&registry.STRONG or len(kinds)<2:return False
    old=conn.execute('SELECT DISTINCT kind,value FROM canca.workspace_identity_signals WHERE workspace_id=%s AND object_id=%s AND qualified LIMIT 129',
        (workspace_id,object_id)).fetchall()
    if len(old)>128:return False
    return not any({v for k,v in current if k==kind} and {v for k,v in old if k==kind} and
        not ({v for k,v in current if k==kind}&{v for k,v in old if k==kind}) for kind in registry.STRONG)


def claim_diff(conn,workspace_id,obs,item,received_at):
    previous={};declared={};old_time=None
    if item['object_id'] and item['decision'] not in ('new_identity','manual_create'):
        old=conn.execute('SELECT o.signals,c.received_at_utc FROM canca.workspace_observations o JOIN canca.workspace_collections c USING (workspace_id,collection_id) '
            'WHERE o.workspace_id=%s AND o.object_id=%s ORDER BY c.received_at_utc DESC,o.collection_id,o.ordinal LIMIT 1',
            (workspace_id,item['object_id'])).fetchone()
        if old:
            old_time=old[1]
            for s in old[0]:previous.setdefault(s['kind'],set()).add(s['value'])
        rows=conn.execute('SELECT DISTINCT ON (attribute) attribute,value FROM canca.workspace_declarations WHERE workspace_id=%s AND object_id=%s '
            'ORDER BY attribute,created_revision DESC',(workspace_id,item['object_id'])).fetchall()
        declared=dict(rows)
    changes=[];current={}
    for s in obs['signals']:current.setdefault(s['kind'],set()).add(s['value'])
    for name,values in sorted(current.items()):
        changes.append(dict(attribute=name,before=sorted(previous.get(name,set())),after=sorted(values),
            status='unchanged' if values==previous.get(name) else 'added' if name not in previous else 'changed',
            declared_conflict=declared.get(name) is not None and declared[name] not in values))
    historical=old_time is not None and datetime.fromisoformat(received_at)<old_time
    return dict(claims=changes,effect='history_only' if historical else item['decision'],
                absent_claims_preserved=sorted(set(previous)-set(current)),time_basis='import_received')


def preview_import(conn,workspace_id,token,projection,*,mode='merge',categories=('identity',),decisions=None,
                   site_id=None,environment_id=None):
    validate_source(projection)
    require(mode in ('merge','evidence_only') and list(categories)==['identity'])
    decisions={} if decisions is None else decisions
    require(type(decisions) is dict and all(type(k) is int and 0<=k<len(projection['observations']) for k in decisions))
    for value in (site_id,environment_id):
        if value is not None:ws.identifier(value)
    for decision in decisions.values():
        require(type(decision) is dict and set(decision) in ({'action','reason'},{'action','reason','object_id'}))
        require(decision['action'] in ('link','create'));text(decision['reason'])
        if decision['action']=='link':require('object_id' in decision);ws.identifier(decision['object_id'])
        else:require('object_id' not in decision)
    with scope(conn,workspace_id,token,writing=True) as revision:
        resolved=[]
        for obs in projection['observations']:
            if mode=='evidence_only':item=dict(decision='evidence_only',reason='evidence_only',candidates=[],object_id=None)
            else:
                item=choose(conn,workspace_id,obs)
                manual=decisions.get(obs['ordinal'])
                if manual:
                    if manual['action']=='link':object_exists(conn,workspace_id,manual['object_id'])
                    item=dict(decision='manual_link' if manual['action']=='link' else 'manual_create',
                              reason=manual['reason'],candidates=item['candidates'],object_id=manual.get('object_id'))
                if item['decision'] in ('new_identity','manual_create'):
                    item['object_id']='wobj-'+digest([workspace_id,projection['import']['bundle_id'],obs['ordinal']])[:32]
            resolved.append(dict(item,ordinal=obs['ordinal'],diff=claim_diff(conn,workspace_id,obs,item,projection['import']['imported_at_utc'])))
        payload=dict(policy=POLICY,projection=projection,mode=mode,categories=list(categories),site_id=site_id,
                     environment_id=environment_id,decisions={str(k):v for k,v in sorted(decisions.items())})
        plan_id='plan-'+digest([workspace_id,revision,payload,resolved])[:32]
        conn.execute('INSERT INTO canca.workspace_import_plans (workspace_id,plan_id,expected_revision,payload_sha256,payload,preview) '
            'VALUES (%s,%s,%s,%s,%s::jsonb,%s::jsonb) ON CONFLICT DO NOTHING',
            (workspace_id,plan_id,revision,digest(payload),json.dumps(payload),json.dumps(resolved)))
        return dict(status='preview',workspace_id=workspace_id,plan_id=plan_id,revision=revision,observations=resolved,
                    review_required=any(r['decision']=='review_required' for r in resolved),policy=POLICY,mode=mode)


def apply_import(conn,workspace_id,token,plan_id,request_id):
    ws.identifier(plan_id);ws.identifier(request_id)
    request=dict(op='apply_import',plan_id=plan_id)
    with scope(conn,workspace_id,token,writing=True) as revision:
        old=replay(conn,workspace_id,request_id,request)
        if old:return old
        row=conn.execute('SELECT expected_revision,payload_sha256,payload,preview FROM canca.workspace_import_plans '
            'WHERE workspace_id=%s AND plan_id=%s',(workspace_id,plan_id)).fetchone()
        pg.require(row,'model_plan_not_found');expected,sha,payload,preview=row
        require(payload['policy']==POLICY and sha==digest(payload));validate_source(payload['projection'])
        check_revision(expected,revision)
        pg.require(not any(r['decision']=='review_required' for r in preview),'model_review_required')
        projection=payload['projection'];imported=projection['import'];collection_id=imported['bundle_id']
        projection_sha=digest(projection)
        previous=conn.execute('SELECT projection_sha256,mode,categories FROM canca.workspace_collections WHERE workspace_id=%s AND collection_id=%s',
            (workspace_id,collection_id)).fetchone()
        if previous:
            pg.require(previous==(projection_sha,payload['mode'],payload['categories']),'model_import_conflict')
            return dict(status='already_imported',collection_id=collection_id,revision=revision,replayed=True)
        conn.execute('INSERT INTO canca.workspace_collections (workspace_id,collection_id,bundle_sha256,projection_sha256,assessment_id,run_id,node_id,'
            'received_at_utc,mode,categories,coverage,created_revision) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,0)',
            (workspace_id,collection_id,imported['bundle_sha256'],projection_sha,imported['assessment_id'],imported['run_id'],imported['node_id'],
             imported['imported_at_utc'],payload['mode'],json.dumps(payload['categories']),'identity_only'))
        for obs,item in zip(projection['observations'],preview):
            object_id=item['object_id']
            if item['decision'] in ('new_identity','manual_create'):
                label=next((s['value'] for s in obs['signals'] if s['kind']=='fqdn'),obs['source_asset_id'])
                conn.execute('INSERT INTO canca.workspace_objects (workspace_id,object_id,kind,label,site_id,environment_id,origin,created_revision) '
                    "VALUES (%s,%s,'device',%s,%s,%s,'observed',0)",(workspace_id,object_id,label,payload['site_id'],payload['environment_id']))
            eligible=identity_eligible(conn,workspace_id,object_id,obs,item['decision']) if object_id is not None else False
            conn.execute('INSERT INTO canca.workspace_observations (workspace_id,collection_id,ordinal,object_id,source_asset_id,decision,identity_eligible,reason,signals,source_refs,created_revision) '
                'VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb,0)',
                (workspace_id,collection_id,obs['ordinal'],object_id,obs['source_asset_id'],item['decision'],eligible,item['reason'],
                 json.dumps(obs['signals']),json.dumps(obs['source_refs'])))
            if object_id is not None:
                for signal in obs['signals']:
                    conn.execute('INSERT INTO canca.workspace_identity_signals (workspace_id,object_id,kind,value,qualified,eligible,created_revision) '
                        'VALUES (%s,%s,%s,%s,%s,%s,0) ON CONFLICT DO NOTHING',
                        (workspace_id,object_id,signal['kind'],signal['value'],signal['qualified'],eligible))
        return receipt(conn,workspace_id,request_id,request,dict(status='applied',collection_id=collection_id,
            observation_count=len(projection['observations']),mode=payload['mode']))


def list_objects(conn,workspace_id,token,*,after='',limit=100,expected_revision=None):
    ws.page_args(after,limit)
    with scope(conn,workspace_id,token) as revision:
        if expected_revision is not None:check_revision(expected_revision,revision)
        rows=conn.execute('SELECT object_id,kind,label,site_id,environment_id,origin,created_revision FROM canca.workspace_objects '
            'WHERE workspace_id=%s AND object_id>%s ORDER BY object_id LIMIT %s',(workspace_id,after,limit+1)).fetchall()
        columns=('object_id','kind','label','site_id','environment_id','origin','created_revision')
        return dict(status='listed',workspace_id=workspace_id,revision=revision,objects=[dict(zip(columns,r)) for r in rows[:limit]],
                    has_more=len(rows)>limit,next_after=rows[min(len(rows),limit)-1][0] if rows else after)


def object_state(conn,workspace_id,token,object_id,*,expected_revision=None):
    ws.identifier(object_id)
    with scope(conn,workspace_id,token) as revision:
        if expected_revision is not None:check_revision(expected_revision,revision)
        row=object_exists(conn,workspace_id,object_id)
        history=conn.execute('SELECT o.collection_id,o.ordinal,o.decision,o.reason,o.signals,o.source_refs,c.received_at_utc,o.created_revision,o.identity_eligible '
            'FROM canca.workspace_observations o JOIN canca.workspace_collections c USING (workspace_id,collection_id) '
            'WHERE o.workspace_id=%s AND o.object_id=%s ORDER BY c.received_at_utc DESC,o.collection_id,o.ordinal LIMIT 101',(workspace_id,object_id)).fetchall()
        declarations=conn.execute('SELECT declaration_id,attribute,value,reason,author_role,created_revision FROM canca.workspace_declarations '
            'WHERE workspace_id=%s AND object_id=%s ORDER BY created_revision DESC,declaration_id LIMIT 101',(workspace_id,object_id)).fetchall()
        pg.require(len(history)<=100 and len(declarations)<=100,'model_history_bound')
        fields={}
        latest_time={}
        for h in history:
            for s in h[4]:
                name=s['kind'];time=h[6]
                if name not in latest_time:latest_time[name]=time
                if time==latest_time[name]:fields.setdefault(name,{'observed':[],'declared':None})['observed'].append(s['value'])
        declared=set()
        for d in declarations:
            if d[1] not in declared:
                fields.setdefault(d[1],{'observed':[],'declared':None})['declared']=d[2];declared.add(d[1])
        for name,field in fields.items():
            field['observed']=sorted(set(field['observed']))
            values=set(field['observed'])
            if field['declared'] is not None:values.add(field['declared'])
            field['resolution']='unknown' if not values else 'conflicting' if len(values)>1 else 'known'
            field['time_basis']='import_received';field['collection_time_known']=False
        columns=('kind','label','site_id','environment_id','origin','created_revision')
        return dict(status='found',workspace_id=workspace_id,object_id=object_id,revision=revision,metadata=dict(zip(columns,row)),
                    fields=fields,observations=[dict(collection_id=h[0],ordinal=h[1],decision=h[2],reason=h[3],signals=h[4],source_refs=h[5],
                    received_at_utc=h[6].isoformat(),created_revision=h[7],identity_eligible=h[8]) for h in history],
                    declarations=[dict(zip(('declaration_id','attribute','value','reason','author_role','created_revision'),d)) for d in declarations])


def graph(conn,workspace_id,token,root_id,*,depth=2,node_limit=100,edge_limit=200,expected_revision=None):
    ws.identifier(root_id)
    require(type(depth) is int and 0<=depth<=4 and type(node_limit) is int and 1<=node_limit<=100
            and type(edge_limit) is int and 1<=edge_limit<=200)
    with scope(conn,workspace_id,token) as revision:
        if expected_revision is not None:check_revision(expected_revision,revision)
        object_exists(conn,workspace_id,root_id)
        seen={root_id};frontier={root_id};edges={};truncated=False
        for level in range(depth):
            if not frontier:break
            rows=conn.execute('WITH latest AS (SELECT DISTINCT ON (relationship_id) relationship_id,source_id,target_id,kind,active,author_role,reason,created_revision '
                'FROM canca.workspace_relationships WHERE workspace_id=%s ORDER BY relationship_id,created_revision DESC) '
                'SELECT relationship_id,source_id,target_id,kind,author_role,reason,created_revision FROM latest '
                'WHERE active AND (source_id=ANY(%s) OR target_id=ANY(%s)) ORDER BY relationship_id LIMIT %s',
                (workspace_id,sorted(frontier),sorted(frontier),edge_limit+1)).fetchall()
            if len(rows)>edge_limit:truncated=True
            next_frontier=set()
            for r in rows[:edge_limit]:
                if r[0] in edges:continue
                new={r[1],r[2]}-seen
                if len(seen|new)>node_limit or len(edges)>=edge_limit:truncated=True;continue
                edges[r[0]]=dict(zip(('relationship_id','source_id','target_id','kind','author_role','reason','created_revision'),r),origin='declared')
                seen|=new;next_frontier|=new
            frontier=next_frontier
        rows=conn.execute('SELECT object_id,kind,label,origin FROM canca.workspace_objects WHERE workspace_id=%s AND object_id=ANY(%s) ORDER BY object_id',
            (workspace_id,sorted(seen))).fetchall()
        return dict(status='graph',workspace_id=workspace_id,revision=revision,root_id=root_id,
                    nodes=[dict(zip(('object_id','kind','label','origin'),r)) for r in rows],
                    edges=sorted(edges.values(),key=lambda r:r['relationship_id']),truncated=truncated,depth=depth)


def cli(argv=None):
    parser=argparse.ArgumentParser(description='Cancã workspace model v'+VERSION)
    parser.add_argument('command',choices=('migrate',))
    args=parser.parse_args(argv)
    try:
        with pg.open_connection() as conn:
            ws.admin(conn);result=pg.migrate(conn,model=True)
        print(json.dumps(dict(result,model_version=VERSION)));return 0
    except Exception as exc:
        code=str(exc) if isinstance(exc,pg.PersistenceError) and str(exc) in ERRORS else 'database_failed'
        print(json.dumps({'status':'failed','error_code':code,'model_version':VERSION}));return 2


if __name__=='__main__':raise SystemExit(cli())
