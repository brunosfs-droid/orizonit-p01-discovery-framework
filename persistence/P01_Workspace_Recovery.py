#!/usr/bin/env python3
"""Maintenance-only metadata reset after verified isolated database/store restore."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import P01_Workspace_Model as model
pg,ws,runtime=model.pg,model.ws,model.runtime
VERSION='0.6.27'
ERRORS=model.ERRORS|{'workspace_restore_busy','workspace_restore_stale'}

def inspect(conn):
    pg.guard_connection(conn)
    with conn.transaction():
        pg.timeout(conn);pg.schema_check(conn,minimum=8,recovery=True);ws.admin(conn)
        row=conn.execute('SELECT generation,state FROM canca.workspace_runtime WHERE singleton').fetchone()
        pg.require(row,'workspace_runtime_not_provisioned')
        count=conn.execute('SELECT count(*) FROM canca.workspace_revisions').fetchone()[0]
        return dict(status='inspected',generation=row[0],state=row[1],workspaces=count)

def prepare_restored(conn,expected_generation):
    """No dump, copy, grants, source repair or automatic resume. Admin confirms pair."""
    runtime.require_generation(expected_generation);pg.guard_connection(conn)
    with conn.transaction():
        pg.timeout(conn);pg.schema_check(conn,minimum=8,recovery=True);ws.admin(conn)
        held=conn.execute('SELECT pg_try_advisory_xact_lock(%s)',(runtime.LOCK_KEY,)).fetchone()[0]
        pg.require(held,'workspace_restore_busy')
        row=conn.execute('SELECT generation FROM canca.workspace_runtime WHERE singleton FOR UPDATE').fetchone()
        pg.require(row,'workspace_runtime_not_provisioned')
        pg.require(row[0]==expected_generation,'workspace_restore_stale')
        conn.execute("UPDATE canca.workspace_runtime SET generation=generation+1,state='closed',workspace_id=NULL,lease_id=NULL,lease_pid=NULL WHERE singleton")
        # XIDs belong to a cluster timeline and are not durable content revisions.
        changed=conn.execute('UPDATE canca.workspace_revisions SET last_txid=NULL').rowcount
        return dict(status='prepared',generation=expected_generation+1,state='closed',workspaces=changed)

def cli(argv=None):
    parser=argparse.ArgumentParser(description='Cancã isolated workspace recovery '+VERSION)
    commands=parser.add_subparsers(dest='command',required=True)
    commands.add_parser('migrate');commands.add_parser('inspect')
    prepare=commands.add_parser('prepare-restored');prepare.add_argument('--expected-generation',type=int,required=True)
    args=parser.parse_args(argv)
    try:
        if args.command=='prepare-restored':runtime.require_generation(args.expected_generation)
        with pg.open_connection() as conn:
            if args.command=='migrate':ws.admin(conn);result=pg.migrate(conn,recovery=True)
            elif args.command=='inspect':result=inspect(conn)
            else:result=prepare_restored(conn,args.expected_generation)
        print(json.dumps(dict(result,recovery_version=VERSION)));return 0
    except Exception as exc:
        code=str(exc) if isinstance(exc,pg.PersistenceError) and str(exc) in ERRORS else 'database_failed'
        print(json.dumps(dict(status='failed',error_code=code,recovery_version=VERSION)));return 2

if __name__=='__main__':raise SystemExit(cli())
