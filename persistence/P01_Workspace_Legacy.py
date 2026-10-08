#!/usr/bin/env python3
"""Reviewed, bounded legacy bridge and revision-fenced historical report.

Original rows/bytes/IDs stay intact. Stored evaluations are copied, never rerun.
Trusted source preparation and the coordinator service are required at the boundary.
"""
from collections import Counter
from contextlib import contextmanager
import argparse
import json
from pathlib import Path
import re
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import P01_Workspace_Model as model
import P01_Assessment_Report as historical
pg,ws,runtime=model.pg,model.ws,model.runtime
VERSION='0.6.28'
ERRORS=model.ERRORS|historical.ERRORS|{'legacy_source_unavailable','legacy_source_conflict',
    'legacy_plan_not_found','legacy_report_not_found','legacy_scope_conflict'}
BUNDLE=re.compile(r'bnd-[0-9a-f]{20}')
SHA=re.compile(r'[0-9a-f]{64}')

def require(value):pg.require(value,'legacy_source_conflict')

@contextmanager
def scope(conn,workspace_id,token,*,writing=False):
    with model.scope(conn,workspace_id,token,writing=writing) as revision:
        pg.schema_check(conn,minimum=9,legacy=True)
        yield revision

def _snapshot(conn,bundle_id):
    value=conn.execute('SELECT canca.workspace_legacy_snapshot(%s)',(bundle_id,)).fetchone()[0]
    pg.require(value is not None,'legacy_source_unavailable')
    return value

def source_snapshot(conn,workspace_id,token,bundle_id):
    model.require(isinstance(bundle_id,str) and BUNDLE.fullmatch(bundle_id))
    with scope(conn,workspace_id,token):return _snapshot(conn,bundle_id)

def validate_snapshot(snapshot,projection):
    """Check source hashes/counts/links without using the current finding engine."""
    model.validate_source(projection)
    try:
        require(type(snapshot) is dict and set(snapshot)=={'import','assets','artifacts','observations','analysis','evaluations'})
        require(len(pg.canonical(snapshot))<=4*1024**2)
        imported=projection['import'];i=snapshot['import'];a=snapshot['assets']
        require(all(i[k]==imported[k] for k in ('bundle_id','assessment_id','run_id','node_id','bundle_sha256','receipt_sha256')))
        require(i['projection_sha256']==model.digest(imported) and snapshot['artifacts']==imported['artifacts'])
        require(a['bundle_id']==imported['bundle_id'] and a['assessment_id']==imported['assessment_id']
            and a['policy_version']==projection['policy_version'] and a['projection_sha256']==model.digest(projection))
        rows=snapshot['observations'];require(type(rows) is list and len(rows)==len(projection['observations'])==a['observation_count'])
        for old,new in zip(rows,projection['observations']):
            require(all(old[k]==new[k] for k in ('ordinal','source_asset_id','signals','source_refs')))
            require(re.fullmatch('cas-[0-9a-f]{32}',old['asset_id']) is not None)
        analysis=snapshot['analysis'];evaluations=snapshot['evaluations']
        require(type(evaluations) is list and len(evaluations)<=2000)
        if analysis is None:require(not evaluations);return
        require(analysis['bundle_id']==i['bundle_id'] and analysis['assessment_id']==i['assessment_id']
            and analysis['policy_version']=='0.6.4' and analysis['import_projection_sha256']==model.digest(imported)
            and analysis['asset_projection_sha256']==model.digest(projection))
        for name in ('projection_sha256','engine_sha256','catalog_sha256'):require(SHA.fullmatch(analysis[name]) is not None)
        require(analysis['analysis_id']=='ana-'+analysis['projection_sha256'][:32])
        rules=historical.stored_rules(analysis['catalog'])
        refs={r['path']:r for r in imported['artifacts'] if r['role']=='credentialed_evidence'}
        require(analysis['evaluation_count']==len(evaluations)==len(refs)*len(historical.RULES))
        require(analysis['finding_count']==sum(e['result']=='finding' for e in evaluations))
        pairs=set()
        for ordinal,e in enumerate(evaluations):
            require(type(e['ordinal']) is int and e['ordinal']==ordinal and e['rule_id'] in rules and e['result'] in historical.RESULTS)
            ref=refs.get(e['source_path']);require(ref is not None and e['source_sha256']==ref['sha256'])
            pair=(e['source_path'],e['rule_id']);require(pair not in pairs);pairs.add(pair)
            observation=e['observation_ordinal']
            require(e['link_state'] in ('unique_observation','ambiguous','unresolved')
                and (observation is not None)==(e['link_state']=='unique_observation'))
            if observation is not None:
                require(type(observation) is int and 0<=observation<len(rows)
                    and any(r['path']==e['source_path'] for r in rows[observation]['source_refs']))
            require(type(e['evidence_refs']) is list and len(e['evidence_refs'])<=6 and len(set(e['evidence_refs']))==len(e['evidence_refs'])
                and all(isinstance(r,str) and r in {'/authentication/success','/enrichment/collection_status',
                    '/enrichment/collection_sections','/enrichment/security/firewall_profiles','/enrichment/identity',
                    '/enrichment/security/secure_channel_checked','/enrichment/security/secure_channel_healthy'}
                    for r in e['evidence_refs']))
            if e['result']=='finding':
                expected='fnd-'+model.digest(dict(analysis_id=analysis['analysis_id'],ordinal=ordinal))[:32]
                require(e['finding_id']==expected and e['finding_status']=='Open' and type(e['evidence']) is dict)
                if e['rule_id']=='WIN-AD-001':require(e['evidence']=={'secure_channel_healthy':False})
                else:
                    values=e['evidence'].get('disabled_profiles')
                    require(set(e['evidence'])=={'disabled_profiles'} and type(values) is list and bool(values)
                        and values==sorted(set(values)) and set(values)<={'domain','private','public'})
            else:require(e['finding_id'] is None and e['finding_status'] is None and e['evidence'] is None)
        require(pairs=={(path,rule) for path in refs for rule in historical.RULES})
        # Rebuild the recorded projection with its saved engine/catalogue. This
        # verifies its digest without evaluating current rules or source content.
        recorded=dict(policy_version=analysis['policy_version'],engine_sha256=analysis['engine_sha256'],
            catalog_sha256=analysis['catalog_sha256'],catalog=analysis['catalog'],assets=projection,
            evaluations=[dict(ordinal=e['ordinal'],source_ref=refs[e['source_path']],rule_id=e['rule_id'],
                result=e['result'],observation_ordinal=e['observation_ordinal'],link_state=e['link_state'],
                evidence_refs=e['evidence_refs'],evidence=e['evidence'] if e['result']=='finding' else {}) for e in evaluations])
        require(model.digest(recorded)==analysis['projection_sha256'])
    except pg.PersistenceError:raise
    except Exception:raise pg.PersistenceError('legacy_source_conflict') from None

def preview(conn,workspace_id,token,projection,snapshot,**selection):
    validate_snapshot(snapshot,projection)
    # Staged plans do not publish inventory/history. A race leaves an unused
    # immutable plan; the second fence pins the same revision/source snapshot.
    plan=model.preview_import(conn,workspace_id,token,projection,**selection)
    with scope(conn,workspace_id,token,writing=True) as revision:
        model.check_revision(plan['revision'],revision)
        require(_snapshot(conn,projection['import']['bundle_id'])==snapshot)
        payload=dict(model_plan_id=plan['plan_id'],source=snapshot,projection_sha256=model.digest(projection))
        plan_id='legacy-'+model.digest([workspace_id,revision,payload])[:32]
        conn.execute('INSERT INTO canca.workspace_legacy_plans VALUES (%s,%s,%s,%s,%s::jsonb) ON CONFLICT DO NOTHING',
            (workspace_id,plan_id,plan['plan_id'],model.digest(payload),json.dumps(payload)))
        return dict(plan,plan_id=plan_id,legacy_version=VERSION,
            legacy_asset_ids=[r['asset_id'] for r in snapshot['observations']],
            evaluation_count=len(snapshot['evaluations']),finding_count=sum(r['result']=='finding' for r in snapshot['evaluations']),
            finding_coverage='recorded_historical' if snapshot['analysis'] else 'not_analyzed')

def _plan(conn,workspace_id,plan_id):
    row=conn.execute('SELECT payload_sha256,payload FROM canca.workspace_legacy_plans WHERE workspace_id=%s AND plan_id=%s',
        (workspace_id,plan_id)).fetchone()
    pg.require(row is not None,'legacy_plan_not_found');require(row[0]==model.digest(row[1]));return row[1]

def read_plan(conn,workspace_id,token,plan_id):
    ws.identifier(plan_id)
    with scope(conn,workspace_id,token,writing=True):return _plan(conn,workspace_id,plan_id)

def request(plan_id):return dict(op='apply_legacy',plan_id=plan_id)

def replay_request(conn,workspace_id,token,plan_id,request_id):
    ws.identifier(plan_id);ws.identifier(request_id)
    with scope(conn,workspace_id,token,writing=True):return model.replay(conn,workspace_id,request_id,request(plan_id))

def apply(conn,workspace_id,token,plan_id,request_id,projection):
    ws.identifier(plan_id);ws.identifier(request_id)
    with scope(conn,workspace_id,token,writing=True) as revision:
        replay=model.replay(conn,workspace_id,request_id,request(plan_id))
        if replay:return replay
        payload=_plan(conn,workspace_id,plan_id);snapshot=payload['source']
        validate_snapshot(snapshot,projection);require(model.digest(projection)==payload['projection_sha256'])
        require(_snapshot(conn,projection['import']['bundle_id'])==snapshot)
        result=model._apply_import_locked(conn,workspace_id,payload['model_plan_id'],'legacy-child-'+model.digest(request_id)[:32],revision)
        collection_id=projection['import']['bundle_id'];source_sha=model.digest(snapshot)
        previous=conn.execute('SELECT source_sha256 FROM canca.workspace_legacy_imports WHERE workspace_id=%s AND collection_id=%s',
            (workspace_id,collection_id)).fetchone()
        if previous:require(previous[0]==source_sha)
        else:
            links=conn.execute('SELECT ordinal,object_id FROM canca.workspace_observations WHERE workspace_id=%s AND collection_id=%s ORDER BY ordinal',
                (workspace_id,collection_id)).fetchall()
            conn.execute('INSERT INTO canca.workspace_legacy_imports (workspace_id,collection_id,assessment_id,source_sha256,source_snapshot,object_links,created_revision) '
                'VALUES (%s,%s,%s,%s,%s::jsonb,%s::jsonb,0)',(workspace_id,collection_id,projection['import']['assessment_id'],source_sha,
                    json.dumps(snapshot),json.dumps([dict(ordinal=r[0],object_id=r[1]) for r in links])))
        return model.receipt(conn,workspace_id,request_id,request(plan_id),dict(status='backfilled',collection_id=collection_id,
            observation_count=result.get('observation_count',len(projection['observations'])),evaluation_count=len(snapshot['evaluations']),source_sha256=source_sha))

def report(conn,workspace_id,token,collection_id,*,after_ordinal=-1,limit=100,expected_revision=None,expected_scope_sha256=None):
    model.require(isinstance(collection_id,str) and BUNDLE.fullmatch(collection_id)
        and type(after_ordinal) is int and -1<=after_ordinal<=1999 and type(limit) is int and 1<=limit<=100
        and (expected_scope_sha256 is None or isinstance(expected_scope_sha256,str) and SHA.fullmatch(expected_scope_sha256))
        and (after_ordinal==-1 or expected_revision is not None and expected_scope_sha256 is not None))
    if expected_revision is not None:runtime.require_generation(expected_revision)
    with scope(conn,workspace_id,token) as revision:
        if expected_revision is not None:model.check_revision(expected_revision,revision)
        row=conn.execute('SELECT source_sha256,source_snapshot,object_links,created_revision FROM canca.workspace_legacy_imports '
            'WHERE workspace_id=%s AND collection_id=%s',(workspace_id,collection_id)).fetchone()
        pg.require(row is not None,'legacy_report_not_found');sha,snapshot,links,migrated_revision=row
        require(sha==model.digest(snapshot));scope_sha=model.digest([VERSION,workspace_id,collection_id,revision,sha,migrated_revision,links])
        pg.require(expected_scope_sha256 is None or scope_sha==expected_scope_sha256,'legacy_scope_conflict')
        analysis=snapshot['analysis'];rules=historical.stored_rules(analysis['catalog']) if analysis else {}
        evaluations=snapshot['evaluations'];counts=Counter(e['result'] for e in evaluations)
        objects={r['ordinal']:r['object_id'] for r in links}
        selected=[e for e in evaluations if e['ordinal']>after_ordinal][:limit+1]
        details=[]
        for e in selected[:limit]:
            ordinal=e['observation_ordinal'];old=snapshot['observations'][ordinal] if ordinal is not None else None
            details.append(dict(e,rule=rules[e['rule_id']],legacy_asset_id=old['asset_id'] if old else None,
                workspace_object_id=objects.get(ordinal),analysis_id=analysis['analysis_id']))
        return dict(status='found',report_version=VERSION,workspace_id=workspace_id,collection_id=collection_id,
            assessment_id=snapshot['import']['assessment_id'],revision=revision,migrated_revision=migrated_revision,
            report_scope_sha256=scope_sha,source_sha256=sha,source_bundle_sha256=snapshot['import']['bundle_sha256'],
            summary=dict(evaluation_count=len(evaluations),outcomes={k:counts[k] for k in historical.RESULTS}),
            coverage=dict(basis='recorded_historical' if analysis else 'not_analyzed',identity_only_import=True,
                automatic_finding_closure=False,time_basis='import_received',collection_time_known=False),
            analysis=analysis,evaluations=details,has_more=len(selected)>limit,
            next_after_ordinal=details[-1]['ordinal'] if details else after_ordinal)

def cli(argv=None):
    parser=argparse.ArgumentParser(description='Cancã reviewed legacy bridge '+VERSION)
    parser.add_argument('command',choices=('migrate',));parser.parse_args(argv)
    try:
        with pg.open_connection() as conn:ws.admin(conn);result=pg.migrate(conn,legacy=True)
        print(json.dumps(dict(result,legacy_version=VERSION)));return 0
    except Exception as exc:
        code=str(exc) if isinstance(exc,pg.PersistenceError) and str(exc) in ERRORS else 'database_failed'
        print(json.dumps(dict(status='failed',error_code=code,legacy_version=VERSION)));return 2

if __name__=='__main__':raise SystemExit(cli())
