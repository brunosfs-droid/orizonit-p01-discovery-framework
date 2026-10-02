#!/usr/bin/env python3
"""Read-only assessment report; explicit historical coverage and fenced pages."""
from __future__ import annotations
from collections import Counter
from datetime import timezone
import argparse
import json
from pathlib import Path
import re
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
import P01_PostgreSQL as pg

VERSION = '0.6.5'
MAX_IMPORTS = 100
MAX_OBSERVATIONS = 10000
MAX_EVALUATIONS = 10000
RULES = ('WIN-AD-001','WIN-FW-001')
RESULTS = ('finding','no_finding','insufficient_evidence','not_applicable','not_supported')
ERRORS = pg.ERRORS | {'report_input_invalid','report_scope_conflict','report_limit_exceeded','report_data_conflict'}


def validate_query(assessment_id,after_analysis_id='',after_ordinal=-1,limit=100,expected_scope_sha256=None):
    pg.require(isinstance(assessment_id,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}',assessment_id)
               and isinstance(after_analysis_id,str) and (after_analysis_id=='' or re.fullmatch(r'ana-[0-9a-f]{32}',after_analysis_id))
               and type(after_ordinal) is int and -1 <= after_ordinal <= 1999
               and type(limit) is int and 1 <= limit <= 100
               and (after_analysis_id!='' or after_ordinal==-1)
               and (expected_scope_sha256 is None or isinstance(expected_scope_sha256,str)
                    and re.fullmatch(r'[0-9a-f]{64}',expected_scope_sha256))
               and (after_analysis_id=='' or expected_scope_sha256 is not None),'report_input_invalid')


def stored_rules(catalog):
    try:
        pg.require(isinstance(catalog,dict) and catalog.get('ruleset_version')=='0.6.4'
                   and isinstance(catalog.get('rules'),list)
                   and tuple(r['id'] for r in catalog['rules'])==RULES,'report_data_conflict')
        for rule in catalog['rules']:
            pg.require(rule['version']=='0.6.4' and rule['enabled'] is True
                       and all(isinstance(rule.get(k),str) and 0<len(rule[k])<=4096
                               for k in ('title','category','severity','recommendation')),'report_data_conflict')
        return {r['id']:r for r in catalog['rules']}
    except pg.PersistenceError:
        raise
    except Exception:
        raise pg.PersistenceError('report_data_conflict') from None


def show_assessment(conn,assessment_id,after_analysis_id='',after_ordinal=-1,limit=100,expected_scope_sha256=None):
    validate_query(assessment_id,after_analysis_id,after_ordinal,limit,expected_scope_sha256)
    pg.guard_connection(conn)
    with conn.transaction():
        conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        pg.timeout(conn); pg.schema_check(conn,minimum=4)
        state=conn.execute('SELECT lifecycle_state,lifecycle_revision FROM canca.assessments WHERE assessment_id=%s',
                           (assessment_id,)).fetchone()
        if state is None:
            return dict(status='not_found',report_version=VERSION,assessment_id=assessment_id)
        snapshot=conn.execute('SELECT transaction_timestamp()').fetchone()[0].astimezone(timezone.utc).isoformat()
        columns=('bundle_id','run_id','node_id','projection_sha256','asset_projection_sha256','asset_observation_count')
        imports=conn.execute('''SELECT i.bundle_id,i.run_id,i.node_id,i.projection_sha256,a.projection_sha256,a.observation_count
            FROM canca.imports i LEFT JOIN canca.asset_imports a ON a.bundle_id=i.bundle_id
            WHERE i.assessment_id=%s ORDER BY i.bundle_id LIMIT %s''',(assessment_id,MAX_IMPORTS+1)).fetchall()
        pg.require(len(imports)<=MAX_IMPORTS,'report_limit_exceeded')
        imported=[dict(zip(columns,row)) for row in imports]
        pg.require(sum(r['asset_observation_count'] or 0 for r in imported)<=MAX_OBSERVATIONS,'report_limit_exceeded')
        observations=conn.execute('''SELECT bundle_id,ordinal,asset_id,source_asset_id,decision,reason_code
            FROM canca.asset_observations WHERE assessment_id=%s ORDER BY bundle_id,ordinal LIMIT %s''',
            (assessment_id,MAX_OBSERVATIONS+1)).fetchall()
        pg.require(len(observations)<=MAX_OBSERVATIONS,'report_limit_exceeded')
        actual_observations=Counter(row[0] for row in observations)
        pg.require(all(actual_observations[r['bundle_id']]==(r['asset_observation_count'] or 0) for r in imported),'report_data_conflict')
        analysis_columns=('analysis_id','bundle_id','policy_version','projection_sha256','engine_sha256','catalog_sha256',
                          'catalog','evaluation_count','finding_count','actual_evaluation_count','actual_finding_count')
        rows=conn.execute('''SELECT a.analysis_id,a.bundle_id,a.policy_version,a.projection_sha256,a.engine_sha256,a.catalog_sha256,
            a.catalog,a.evaluation_count,a.finding_count,
            (SELECT count(*) FROM canca.finding_evaluations e WHERE e.analysis_id=a.analysis_id),
            (SELECT count(*) FROM canca.findings f WHERE f.analysis_id=a.analysis_id)
            FROM canca.finding_analyses a WHERE a.assessment_id=%s ORDER BY a.analysis_id LIMIT %s''',
            (assessment_id,MAX_IMPORTS+1)).fetchall()
        pg.require(len(rows)<=MAX_IMPORTS,'report_limit_exceeded')
        analyses=[dict(zip(analysis_columns,row)) for row in rows]
        pg.require(sum(a['evaluation_count'] for a in analyses)<=MAX_EVALUATIONS
                   and sum(a['actual_evaluation_count'] for a in analyses)<=MAX_EVALUATIONS,'report_limit_exceeded')
        catalog_by_analysis={}; catalogs={}
        for analysis in analyses:
            pg.require(analysis['policy_version']=='0.6.4'
                       and analysis['evaluation_count']==analysis['actual_evaluation_count']
                       and analysis['finding_count']==analysis['actual_finding_count'],'report_data_conflict')
            rules=stored_rules(analysis['catalog']);catalog_by_analysis[analysis['analysis_id']]=rules
            key=(analysis['catalog_sha256'],analysis['engine_sha256'])
            entry={k:analysis[k] for k in ('policy_version','engine_sha256','catalog_sha256','catalog')}
            pg.require(key not in catalogs or catalogs[key]==entry,'report_data_conflict');catalogs[key]=entry
        outcome_rows=conn.execute('''SELECT e.rule_id,e.result,count(*) FROM canca.finding_evaluations e
            JOIN canca.finding_analyses a ON a.analysis_id=e.analysis_id WHERE a.assessment_id=%s
            GROUP BY e.rule_id,e.result ORDER BY e.rule_id,e.result''',(assessment_id,)).fetchall()
        outcomes={r:{s:0 for s in RESULTS} for r in RULES}
        for rule,result,count in outcome_rows:
            pg.require(rule in RULES and result in RESULTS,'report_data_conflict');outcomes[rule][result]=count
        evaluation_count=sum(sum(v.values()) for v in outcomes.values())
        finding_count=sum(a['finding_count'] for a in analyses)
        pg.require(evaluation_count==sum(a['evaluation_count'] for a in analyses)
                   and finding_count==sum(v['finding'] for v in outcomes.values()),'report_data_conflict')
        source_count=conn.execute('''SELECT count(*) FROM canca.artifacts t JOIN canca.imports i ON i.bundle_id=t.bundle_id
            WHERE i.assessment_id=%s AND t.role='credentialed_evidence' ''',(assessment_id,)).fetchone()[0]
        evaluated_sources=conn.execute('''SELECT count(*) FROM (SELECT e.analysis_id,e.source_path
            FROM canca.finding_evaluations e JOIN canca.finding_analyses a ON a.analysis_id=e.analysis_id
            WHERE a.assessment_id=%s GROUP BY e.analysis_id,e.source_path) sources''',(assessment_id,)).fetchone()[0]
        asset_count=conn.execute('SELECT count(*) FROM canca.assets WHERE assessment_id=%s',(assessment_id,)).fetchone()[0]
        scope=pg.digest(pg.canonical(dict(report_version=VERSION,assessment_id=assessment_id,lifecycle=list(state),
                                        imports=imported,observations=observations,analyses=analyses,outcomes=outcomes,
                                        source_count=source_count,evaluated_sources=evaluated_sources,asset_count=asset_count)))
        pg.require(expected_scope_sha256 is None or expected_scope_sha256==scope,'report_scope_conflict')
        fields=('analysis_id','ordinal','bundle_id','source_path','source_sha256','rule_id','result','observation_ordinal',
                'link_state','evidence_refs','asset_id','asset_decision','asset_reason_code','finding_id','finding_status','evidence')
        details=conn.execute('''SELECT e.analysis_id,e.ordinal,e.bundle_id,e.source_path,e.source_sha256,e.rule_id,e.result,
            e.observation_ordinal,e.link_state,e.evidence_refs,o.asset_id,o.decision,o.reason_code,f.finding_id,f.status,f.evidence
            FROM canca.finding_evaluations e JOIN canca.finding_analyses a ON a.analysis_id=e.analysis_id
            LEFT JOIN canca.asset_observations o ON o.bundle_id=e.bundle_id AND o.ordinal=e.observation_ordinal
            LEFT JOIN canca.findings f ON f.analysis_id=e.analysis_id AND f.evaluation_ordinal=e.ordinal
            WHERE a.assessment_id=%s AND (e.analysis_id,e.ordinal)>(%s,%s)
            ORDER BY e.analysis_id,e.ordinal LIMIT %s''',(assessment_id,after_analysis_id,after_ordinal,limit+1)).fetchall()
        page=[]
        for row in details[:limit]:
            record=dict(zip(fields,row))
            pg.require((record['result']=='finding')==(record['finding_id'] is not None),'report_data_conflict')
            record['rule']=catalog_by_analysis[record['analysis_id']][record['rule_id']]
            page.append(record)
        asset_counts=Counter(row[4] for row in observations)
        asset_reasons=Counter(row[5] for row in observations)
        analyzed_bundles={a['bundle_id'] for a in analyses}
        missing_assets=[r['bundle_id'] for r in imported if r['asset_projection_sha256'] is None]
        missing_analyses=[r['bundle_id'] for r in imported if r['bundle_id'] not in analyzed_bundles]
        outcomes_total={s:sum(v[s] for v in outcomes.values()) for s in RESULTS}
        last=page[-1] if page else dict(analysis_id=after_analysis_id,ordinal=after_ordinal)
    return dict(status='found',report_version=VERSION,assessment_id=assessment_id,
                lifecycle=dict(state=state[0],revision=state[1]),snapshot_at_utc=snapshot,report_scope_sha256=scope,
                scope_mode='all_persisted_imports',source_bytes_revalidated=False,
                coverage=dict(import_count=len(imported),asset_projected_import_count=len(imported)-len(missing_assets),
                              analyzed_import_count=len(analyses),imports_without_assets=missing_assets,imports_without_analysis=missing_analyses,
                              credentialed_sources_indexed=source_count,credentialed_sources_evaluated=evaluated_sources,
                              projection_status='no_imports' if not imported else 'missing_analyses' if missing_analyses else 'all_imports_analyzed',
                              evaluation_count=evaluation_count,outcomes=outcomes_total,by_rule=outcomes),
                identity=dict(central_asset_count=asset_count,observation_count=len(observations),
                              decisions={s:asset_counts[s] for s in ('new_asset','linked','review_required')},reasons=dict(asset_reasons)),
                recorded_finding_occurrences=finding_count,catalogs=[catalogs[k] for k in sorted(catalogs)],
                imports=imported,analyses=[{k:a[k] for k in ('analysis_id','bundle_id','policy_version','engine_sha256','catalog_sha256','evaluation_count','finding_count')} for a in analyses],
                evaluations=page,has_more=len(details)>limit,next_cursor=dict(after_analysis_id=last['analysis_id'],after_ordinal=last['ordinal']))


def cli(argv=None):
    parser=argparse.ArgumentParser(description='Cancã read-only assessment report v'+VERSION)
    commands=parser.add_subparsers(dest='command',required=True)
    show=commands.add_parser('show-assessment');show.add_argument('--assessment-id',required=True)
    show.add_argument('--after-analysis-id',default='');show.add_argument('--after-ordinal',type=int,default=-1)
    show.add_argument('--limit',type=int,default=100);show.add_argument('--expected-scope-sha256')
    args=parser.parse_args(argv)
    try:
        params=(args.assessment_id,args.after_analysis_id,args.after_ordinal,args.limit,args.expected_scope_sha256)
        validate_query(*params)
        with pg.open_connection() as conn:result=show_assessment(conn,*params)
        print(json.dumps(result,ensure_ascii=False,allow_nan=False));return 0
    except Exception as exc:
        code=str(exc) if isinstance(exc,pg.PersistenceError) and str(exc) in ERRORS else 'database_failed'
        print(json.dumps(dict(status='failed',error_code=code,report_version=VERSION)));return 2


if __name__=='__main__':
    raise SystemExit(cli())
