#!/usr/bin/env python3
"""Short, isolated operator HTTP exercise against the existing synthetic R1.

No migrations, grants, store access or persistent account/server installation.
"""
from __future__ import annotations
import argparse
from contextlib import closing
import http.client
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'server'))
import P01_Operator_API as api
import P01_Operator_Auth as auth

ASSESSMENT = 'P01-PG-LAB-R1'
DATABASE = 'canca_p01_restore_r1'
TABLES = ('schema_migrations','assessments','nodes','runs','imports','artifacts',
          'assessment_events','assets','asset_imports','asset_observations','asset_signals',
          'finding_analyses','finding_evaluations','findings')


def require(ok):
    if not ok:
        raise ValueError('operator_lab_check_failed')


def snapshot(expected_database):
    with api.report.pg.open_connection() as conn:
        api.report.pg.guard_connection(conn)
        with conn.transaction():
            conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
            api.report.pg.timeout(conn)
            require(conn.execute('SELECT current_database()').fetchone()[0] == expected_database)
            api.report.pg.schema_check(conn, minimum=4)
            result = {}
            for table in TABLES:
                rows = conn.execute('SELECT CASE WHEN octet_length(to_jsonb(t)::text)>131072 THEN NULL '
                    'ELSE to_jsonb(t)::text END FROM canca.'+table+
                    ' t ORDER BY to_jsonb(t)::text LIMIT 201').fetchall()
                require(len(rows)<=200 and all(row[0] is not None for row in rows))
                texts=[row[0] for row in rows]
                require(sum(len(row.encode()) for row in texts)<=4*1024*1024)
                result[table]=dict(rows=len(rows),sha256=api.report.pg.digest(api.report.pg.canonical(texts)))
            require(result['schema_migrations']['rows']==4 and result['imports']['rows']==2
                    and result['assets']['rows']==1 and result['asset_observations']['rows']==2
                    and result['finding_evaluations']['rows']==4 and result['findings']['rows']==2)
            return result


def exercise(expected_database):
    before=snapshot(expected_database)
    with api.report.pg.open_connection() as conn:
        canonical=api.report.show_assessment(conn,ASSESSMENT)
    require(canonical['status']=='found' and len(canonical['evaluations'])==4)
    with tempfile.TemporaryDirectory(prefix='canca-operator-r1-') as temporary:
        path=Path(temporary)/'accounts.json'; password=secrets.token_urlsafe(32)
        auth.create_policy(path,'OP-R1','reader-r1',[ASSESSMENT],password)
        server=api.create_server(path,port=0)
        worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
        def request(method,target,payload=None,token=None):
            headers={'Content-Type':'application/json'} if payload is not None else {}
            if token is not None: headers['Authorization']='Bearer '+token
            with closing(http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=40)) as connection:
                connection.request(method,target,json.dumps(payload) if payload is not None else None,headers)
                response=connection.getresponse();raw=response.read()
                require(response.getheader('Cache-Control')=='no-store' and response.getheader('Set-Cookie') is None)
                return response.status,json.loads(raw)
        try:
            require(request('GET','/healthz')[1]['authentication_mode']=='local_operator')
            target='/api/v1/assessments/'+ASSESSMENT+'/report'
            require(request('GET',target)[0]==401)
            require(request('POST','/api/v1/operator/session',dict(username='reader-r1',password=password+'x'))[0]==401)
            status,login=request('POST','/api/v1/operator/session',dict(username='reader-r1',password=password))
            require(status==201 and login['operator_id']=='OP-R1')
            token=login['access_token']
            require(request('GET','/api/v1/assessments/OTHER/report',token=token)[0]==403)
            status,full=request('GET',target+'?limit=100',token=token)
            require(status==200)
            left=dict(canonical);right=dict(full)
            left.pop('snapshot_at_utc',None);right.pop('snapshot_at_utc',None)
            require(left==right)
            scope=full['report_scope_sha256'];evaluations=[];cursor=None
            for _ in range(5):
                query='?limit=1'
                if cursor:
                    query+='&after_analysis_id='+cursor['after_analysis_id']+'&after_ordinal='+str(cursor['after_ordinal'])+'&expected_scope_sha256='+scope
                code,page=request('GET',target+query,token=token)
                require(code==200 and page['report_scope_sha256']==scope)
                evaluations.extend(page['evaluations']);cursor=page['next_cursor']
                if not page['has_more']:break
            require(evaluations==full['evaluations'])
            code,terminal=request('GET',target+'?limit=1&after_analysis_id='+cursor['after_analysis_id']+
                '&after_ordinal='+str(cursor['after_ordinal'])+'&expected_scope_sha256='+scope,token=token)
            require(code==200 and terminal['evaluations']==[] and terminal['report_scope_sha256']==scope)
            require(request('GET',target+'?limit=1&expected_scope_sha256='+'0'*64,token=token)[0]==409)
            require(request('DELETE','/api/v1/operator/session',token=token)[0]==200)
            require(request('GET',target,token=token)[0]==401)
        finally:
            server.shutdown();server.server_close();worker.join(timeout=5)
            require(not worker.is_alive())
    require(snapshot(expected_database)==before)
    return dict(status='LOCAL OPERATOR LAB PASS',operator_version=api.VERSION,
        assessment_id=ASSESSMENT,evaluations=4,historical_findings=2,tables_compared=len(TABLES),
        login=True,unauthenticated_denied=True,cross_assessment_denied=True,logout_revoked=True,
        canonical_report_match=True,fenced_pages_match=True,terminal_empty_checked=True,
        database_mutated=False,store_accessed=False,temporary_server_stopped=True,
        temporary_credentials_removed=True,scope='same_host_loopback_synthetic_r1')


def cli(argv=None):
    parser=argparse.ArgumentParser(description='Read-only existing Rocky R1; no restore/migration')
    parser.parse_args(argv)
    try:
        host=os.environ.get('PGHOST','')
        require(os.environ.get('PGDATABASE')==DATABASE and host in {'127.0.0.1','localhost'}
                and os.environ.get('CANCA_TEST_POSTGRES')!='1')
        print(json.dumps(exercise(DATABASE)));return 0
    except Exception:
        print(json.dumps(dict(status='failed',error_code='operator_lab_check_failed',operator_version=api.VERSION)))
        return 2


if __name__=='__main__':raise SystemExit(cli())
