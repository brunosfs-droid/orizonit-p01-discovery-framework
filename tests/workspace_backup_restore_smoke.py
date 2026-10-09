#!/usr/bin/env python3
"""Destructive ONLY in the guarded disposable GitHub workspace CI service."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'persistence'));sys.path.insert(0,str(ROOT/'tests'))
import P01_Workspace_Recovery as recovery
import test_workspace_model as models
import postgres_backup_restore_smoke as legacy
pg,ws,runtime,model=recovery.pg,recovery.ws,recovery.runtime,recovery.model
VERSION='0.6.27'
RESTORE_DB='canca_workspace_restore'
TABLES=legacy.TABLES+('workspaces','workspace_grants','workspace_sites','workspace_environments','workspace_assessments',
    'workspace_runtime','workspace_revisions','workspace_objects','workspace_collections','workspace_observations',
    'workspace_identity_signals','workspace_declarations','workspace_relationships','workspace_import_plans','workspace_model_requests')

class SmokeError(Exception):pass

def require(condition):
    if not condition:raise SmokeError('workspace_backup_restore_failed')

def guard(container):
    require(os.environ.get('GITHUB_ACTIONS')=='true'
        and os.environ.get('CANCA_TEST_WORKSPACE_POSTGRES')=='1'
        and os.environ.get('PGDATABASE')=='canca_workspace_ci'
        and os.environ.get('PGUSER')=='canca_ci' and os.environ.get('PGHOST')=='127.0.0.1'
        and os.environ.get('PGPORT')=='5432' and not os.environ.get('PGSERVICE')
        and isinstance(container,str) and re.fullmatch('[0-9a-f]{12,64}',container))

def docker(container,args,*,source=None,target=None):
    command=['docker','exec']+(['-i'] if source is not None else [])+[container]+args
    result=subprocess.run(command,stdin=source,stdout=target or subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,check=False)
    require(result.returncode==0);return result.stdout

def open_restored():
    import psycopg
    # No process-wide environment mutation and no user-supplied DSN.
    return psycopg.connect('',host='127.0.0.1',port=5432,user='canca_ci',dbname=RESTORE_DB,autocommit=True,connect_timeout=5)

def snapshot(conn,tables=TABLES):
    result={}
    for table in tables:
        if table=='workspace_runtime':continue
        expression="to_jsonb(t)-'last_txid'" if table=='workspace_revisions' else 'to_jsonb(t)'
        result[table]=conn.execute('SELECT ('+expression+')::text FROM canca.'+table+' t ORDER BY ('+expression+')::text').fetchall()
    return result

def policies(conn):
    return conn.execute("SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='canca' AND c.relkind='r' ORDER BY c.relname").fetchall()

@contextmanager
def role(conn,name):
    from psycopg import sql
    conn.execute(sql.SQL('SET ROLE {}').format(sql.Identifier(name)))
    try:yield
    finally:conn.execute('RESET ROLE')

def run(container,*,reviewed_legacy=False,intent_ledger=False):
    guard(container)
    started=time.monotonic()
    tables=TABLES
    require(not (reviewed_legacy and intent_ledger))
    if intent_ledger:
        import test_workspace_intent_ledger as intents
        case=intents.LedgerTests('test_restart_preserves_history_but_never_rearms')
        tables+=('workspace_legacy_plans','workspace_legacy_imports','workspace_scan_intents','workspace_scan_decisions')
    elif reviewed_legacy:
        import test_workspace_legacy as reviewed
        case=reviewed.LegacyPostgreSQLTests('test_atomic_backfill_report_preserves_stored_evaluations_and_legacy_ids')
        tables+=('workspace_legacy_plans','workspace_legacy_imports')
    else:case=models.ModelPostgreSQLTests('test_schema_replay_preserves_legacy_and_default_prefixes')
    target=None;coordinator=None;created=False
    try:
        # Verify the container/connection identity before the fixture resets schema.
        with pg.open_connection() as preflight:
            require(preflight.execute('SELECT current_database(),current_user').fetchone()==('canca_workspace_ci','canca_ci'))
            cluster=str(preflight.execute('SELECT system_identifier FROM pg_control_system()').fetchone()[0])
            inside=docker(container,['psql','-U','canca_ci','-d','canca_workspace_ci','-X','-tA','-c','SELECT system_identifier FROM pg_control_system()'])
            require(inside.decode().strip()==cluster)
            require(not preflight.execute('SELECT 1 FROM pg_database WHERE datname=%s',(RESTORE_DB,)).fetchone())
        case.setUp();conn=case.conn
        initial_revision=0
        if intent_ledger:
            recorded=case.record(ttl_seconds=300)['intent_id']
            case.decide(recorded,'approved','restore-approved')
            pending=case.record('restore-pending',ttl_seconds=300)['intent_id']
            initial_revision=conn.execute("SELECT revision FROM canca.workspace_revisions WHERE workspace_id='A'").fetchone()[0]
        if reviewed_legacy:
            legacy_plan=case.preview();backfilled=case.apply(legacy_plan,'restore-legacy')
            initial_revision=backfilled['revision']
        projection=models.ModelPostgreSQLTests.source(case)
        with case.role('canca_ws_writer'):
            manual=model.declare_object(conn,'A',case.token,initial_revision,'restore-manual','manual','service','Manual',
                attributes={'description':'Restore fixture'},reason='CI restore')
            plan=model.preview_import(conn,'A',case.token,projection)
            applied=model.apply_import(conn,'A',case.token,plan['plan_id'],'restore-apply')
            observed=plan['observations'][0]['object_id']
            model.relationship(conn,'A',case.token,applied['revision'],'restore-relation','restore-edge','manual',observed,'depends_on',reason='CI restore')
            before_state=model.object_state(conn,'A',case.token,'manual')
            before_graph=model.graph(conn,'A',case.token,'manual')
        if reviewed_legacy:
            with case.role('canca_ws_writer'):
                before_report=reviewed.legacy.report(conn,'A',case.token,case.bid)
        old_token=case.token;case.c.shutdown(timeout=0)
        require(pg.migrate(conn,intents=intent_ledger,legacy=reviewed_legacy,recovery=True)['migration']==(10 if intent_ledger else 9 if reviewed_legacy else 8))
        before=snapshot(conn,tables);before_policies=policies(conn)
        current_revision=conn.execute("SELECT revision FROM canca.workspace_revisions WHERE workspace_id='A'").fetchone()[0]
        generation=conn.execute('SELECT generation FROM canca.workspace_runtime').fetchone()[0]
        original_store=case.assetbase/'store'
        relative=Path(next(original_store.glob('assessments/*/imports/*'))).relative_to(original_store)
        sources=(case.store,original_store)
        inventories=[legacy.store_inventory(root) for root in sources]
        with tempfile.TemporaryDirectory(prefix='canca-workspace-restore-') as temporary:
            base=Path(temporary);archive=base/'database.dump'
            with archive.open('xb') as output:
                docker(container,['pg_dump','-U','canca_ci','-d','canca_workspace_ci','--format=custom'],target=output)
            require(archive.stat().st_size>0)
            restored_stores=[]
            for index,root in enumerate(sources):
                destination=base/('store-'+str(index));shutil.copytree(root,destination)
                require(legacy.store_inventory(destination)==inventories[index]);restored_stores.append(destination)
            require(snapshot(conn,tables)==before)
            conn.execute('CREATE DATABASE canca_workspace_restore TEMPLATE template0');created=True
            with archive.open('rb') as input_file:
                # Existing synthetic roles are deliberately retained; preserve ACLs.
                docker(container,['pg_restore','-U','canca_ci','-d',RESTORE_DB,'--single-transaction','--exit-on-error','--no-owner'],source=input_file)
            target=open_restored()
            require(pg.migrate(target,intents=intent_ledger,legacy=reviewed_legacy,recovery=True)['status']=='already_migrated')
            require(snapshot(target,tables)==before and policies(target)==before_policies)
            require(model.prepare_source(restored_stores[1],restored_stores[1]/relative)==projection)
            prepared=recovery.prepare_restored(target,generation)
            require(prepared['state']=='closed' and prepared['generation']==generation+1)
            require(snapshot(target,tables)==before)
            require(target.execute('SELECT count(*) FROM canca.workspace_revisions WHERE last_txid IS NOT NULL').fetchone()[0]==0)
            control=open_restored();control.execute('SET ROLE canca_ws_coordinator')
            coordinator=runtime.Coordinator(runtime.SessionLease(control),heartbeat_seconds=30);coordinator.start()
            with role(target,'canca_ws_writer'):
                token=coordinator.open(target,'A',coordinator.generation)
                require(model.object_state(target,'A',token,'manual')==before_state)
                require(model.graph(target,'A',token,'manual')==before_graph)
                replay=model.declare_object(target,'A',token,initial_revision,'restore-manual','manual','service','Manual',
                    attributes={'description':'Restore fixture'},reason='CI restore')
                require(replay['replayed'] and replay['revision']==manual['revision'])
                replay=model.apply_import(target,'A',token,plan['plan_id'],'restore-apply')
                require(replay['replayed'] and replay['revision']==applied['revision'])
                if reviewed_legacy:
                    require(reviewed.legacy.report(target,'A',token,case.bid)==before_report)
                    restored_projection=reviewed.api.backend.LegacySources({'LAB-001':restored_stores[0]}).prepare('LAB-001',case.bid)
                    require(restored_projection==case.projection)
                    replay=reviewed.legacy.apply(target,'A',token,legacy_plan['plan_id'],'restore-legacy',restored_projection)
                    require(replay['replayed'] and replay['revision']==backfilled['revision'])
                if intent_ledger:
                    for intent_id in (recorded,pending):
                        history=intents.ledger.history(target,'A',token,intent_id)
                        require(not history['context_current'] and not history['execution_authorized'])
                    with coordinator.borrow(target,token,'workspace:write') as operation:
                        new_digest=intents.ledger.live.preview(operation,case.service.approved_scan_scopes,
                            'lab','auth_only',ack_authorized_access=True)['scope_digest_sha256']
                        try:intents.ledger.decide(operation,case.service.approved_scan_scopes,'lab','auth_only',
                            new_digest,recorded,'consumed','restore-no-resume',ack_authorized_access=True)
                        except pg.PersistenceError as exc:require(str(exc)=='intent_stale')
                        else:raise SmokeError('workspace_backup_restore_failed')
                try:model.list_objects(target,'A',old_token)
                except pg.PersistenceError as exc:require(str(exc)=='model_context_denied')
                else:raise SmokeError('workspace_backup_restore_failed')
                from psycopg.errors import InsufficientPrivilege
                try:target.execute('SELECT canca.workspace_active_fence()')
                except InsufficientPrivilege:pass
                else:raise SmokeError('workspace_backup_restore_failed')
            with role(target,'canca_ws_b'):
                try:model.list_objects(target,'B',runtime.Token('B',token.generation,token.lease_id))
                except pg.PersistenceError as exc:require(str(exc)=='model_context_denied')
                else:raise SmokeError('workspace_backup_restore_failed')
            require(snapshot(target,tables)==before)
            receipt=restored_stores[1]/relative/'receipt/import-receipt.json';raw=receipt.read_bytes()
            try:
                receipt.write_bytes(raw+b' ')
                try:model.prepare_source(restored_stores[1],restored_stores[1]/relative)
                except pg.PersistenceError as exc:require(str(exc)=='receipt_integrity_failed')
                else:raise SmokeError('workspace_backup_restore_failed')
            finally:receipt.write_bytes(raw)
            for root,inventory in zip(restored_stores,inventories):require(legacy.store_inventory(root)==inventory)
            with role(target,'canca_ws_writer'):
                changed=model.declare_attribute(target,'A',token,current_revision,'restore-after','manual','description','After restore','CI restore')
                require(changed['revision']==current_revision+1)
            require(snapshot(conn,tables)==before)
            return dict(status='WORKSPACE BACKUP RESTORE PASS',recovery_version='0.6.46' if intent_ledger else '0.6.28' if reviewed_legacy else VERSION,
                schema_migration=10 if intent_ledger else 9 if reviewed_legacy else 8,server_version_num=conn.info.server_version,
                tables_compared=len(tables)-1,model_revision_preserved=True,next_revision_incremented=True,
                runtime_reset_closed=True,transaction_markers_reset=True,old_token_rejected=True,
                graph_state_preserved=True,idempotent_receipts_preserved=True,force_rls_and_existing_role_acls_preserved=True,
                source_bytes_revalidated=True,receipt_corruption_rejected=True,exclusive_synthetic_fixture=True,
                legacy_report_and_receipt_preserved=reviewed_legacy,
                intent_ledger_preserved_without_reauthorization=intent_ledger,
                same_cluster_existing_roles=True,dump_sha256=legacy.digest_file(archive),
                logical_snapshot_sha256=pg.digest(pg.canonical(before)),elapsed_seconds=round(time.monotonic()-started,3),
                evidence_retained=False)
    finally:
        if coordinator is not None:
            try:coordinator.shutdown(timeout=0)
            finally:
                if target is not None:target.close()
        elif target is not None:target.close()
        if created:case.conn.execute('DROP DATABASE canca_workspace_restore')
        case.doCleanups()

def cli(argv=None):
    parser=argparse.ArgumentParser();parser.add_argument('--container-id',required=True)
    parser.add_argument('--reviewed-legacy',action='store_true');parser.add_argument('--intent-ledger',action='store_true');args=parser.parse_args(argv)
    try:print(json.dumps(run(args.container_id,reviewed_legacy=args.reviewed_legacy,intent_ledger=args.intent_ledger)));return 0
    except Exception:
        print(json.dumps(dict(status='failed',error_code='workspace_backup_restore_failed',
            recovery_version='0.6.46' if args.intent_ledger else '0.6.28' if args.reviewed_legacy else VERSION)));return 2

if __name__=='__main__':raise SystemExit(cli())
