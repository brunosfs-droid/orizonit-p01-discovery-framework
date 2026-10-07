#!/usr/bin/env python3
"""Opt-in workspace registry, SQL-role grants and immutable legacy ownership mapping.

No human-session adapter, workspace activation, inventory backfill or network access.
Administrative DB roles are trusted maintenance identities, never content grants.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import P01_PostgreSQL as pg

VERSION = '0.6.21'
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}')
SITE_KINDS = ('on_premises', 'remote', 'azure', 'aws', 'cloud', 'other')
ENVIRONMENT_KINDS = ('production', 'homologation', 'lab', 'other')
PERMISSIONS = ('workspace:read', 'workspace:write')
ERRORS = pg.ERRORS | {'workspace_input_invalid', 'workspace_access_denied', 'workspace_admin_required',
    'workspace_role_invalid', 'workspace_conflict', 'workspace_assignment_conflict',
    'workspace_not_found', 'workspace_parent_not_found', 'workspace_assessment_not_found'}


def identifier(value):
    pg.require(isinstance(value, str) and ID.fullmatch(value) is not None, 'workspace_input_invalid')
    return value


def label(value, *, empty=False):
    pg.require(isinstance(value, str) and (0 if empty else 1) <= len(value) <= 255
               and (empty and value == '' or value.strip() == value and bool(value))
               and not any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value), 'workspace_input_invalid')
    try:
        value.encode('utf-8')
    except UnicodeError:
        raise pg.PersistenceError('workspace_input_invalid') from None
    return value


def page_args(after, limit):
    pg.require(after == '' or isinstance(after, str) and ID.fullmatch(after), 'workspace_input_invalid')
    pg.require(type(limit) is int and 1 <= limit <= 100, 'workspace_input_invalid')


def schema(conn):
    pg.schema_check(conn, minimum=5, runtime=True)


def admin(conn):
    # SQL admin and human product admin are deliberately not interchangeable.
    row = conn.execute('SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user').fetchone()
    pg.require(row and row[0], 'workspace_admin_required')


@contextmanager
def transaction(conn):
    pg.guard_connection(conn)
    with conn.transaction():
        pg.timeout(conn)
        schema(conn)
        yield


@contextmanager
def scope(conn, workspace_id, permission='workspace:read'):
    identifier(workspace_id)
    pg.require(permission in PERMISSIONS, 'workspace_input_invalid')
    with transaction(conn):
        # No GUC can grant access. current_user is the authenticated PostgreSQL role.
        allowed = conn.execute('''SELECT 1 FROM canca.workspace_grants
            WHERE workspace_id=%s AND principal_role=current_user
              AND (permission=%s OR permission='workspace:write') LIMIT 1''',
            (workspace_id, permission)).fetchone()
        pg.require(allowed, 'workspace_access_denied')
        previous = conn.execute("SELECT current_setting('canca.workspace_id',true)").fetchone()[0]
        conn.execute("SELECT set_config('canca.workspace_id',%s,true)", (workspace_id,))
        try:
            yield
        finally:
            # On SQL error the transaction aborts and SET LOCAL is rolled back.
            if conn.info.transaction_status != 3:
                conn.execute("SELECT set_config('canca.workspace_id',%s,true)", (previous or '',))


def create_workspace(conn, workspace_id, name, organization=''):
    identifier(workspace_id); label(name); label(organization, empty=True)
    with transaction(conn):
        admin(conn)
        conn.execute('SELECT pg_advisory_xact_lock(%s)', (pg.lock_key('workspace:' + workspace_id),))
        old = conn.execute('SELECT name,organization FROM canca.workspaces WHERE workspace_id=%s', (workspace_id,)).fetchone()
        if old:
            pg.require(old == (name, organization), 'workspace_conflict')
            return {'status': 'already_registered', 'workspace_id': workspace_id}
        conn.execute('INSERT INTO canca.workspaces (workspace_id,name,organization) VALUES (%s,%s,%s)',
                     (workspace_id, name, organization))
    return {'status': 'registered', 'workspace_id': workspace_id}


def grant_workspace(conn, workspace_id, principal_role, permission):
    identifier(workspace_id); identifier(principal_role)
    pg.require(permission in PERMISSIONS, 'workspace_input_invalid')
    with transaction(conn):
        admin(conn)
        role = conn.execute('SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=%s', (principal_role,)).fetchone()
        pg.require(role and not any(role), 'workspace_role_invalid')
        pg.require(conn.execute('SELECT 1 FROM canca.workspaces WHERE workspace_id=%s', (workspace_id,)).fetchone(),
                   'workspace_not_found')
        row = conn.execute('''INSERT INTO canca.workspace_grants VALUES (%s,%s,%s)
            ON CONFLICT DO NOTHING RETURNING workspace_id''', (workspace_id, principal_role, permission)).fetchone()
    return {'status': 'granted' if row else 'already_granted', 'workspace_id': workspace_id}


def bind_assessment(conn, workspace_id, assessment_id):
    identifier(workspace_id); identifier(assessment_id)
    with transaction(conn):
        admin(conn)
        conn.execute('SELECT pg_advisory_xact_lock(%s)', (pg.lock_key('workspace-assessment:' + assessment_id),))
        old = conn.execute('SELECT workspace_id FROM canca.workspace_assessments WHERE assessment_id=%s',
                           (assessment_id,)).fetchone()
        if old:
            pg.require(old[0] == workspace_id, 'workspace_assignment_conflict')
            return {'status': 'already_assigned', 'workspace_id': workspace_id, 'assessment_id': assessment_id}
        pg.require(conn.execute('SELECT 1 FROM canca.workspaces WHERE workspace_id=%s', (workspace_id,)).fetchone(),
                   'workspace_not_found')
        pg.require(conn.execute('SELECT 1 FROM canca.assessments WHERE assessment_id=%s', (assessment_id,)).fetchone(),
                   'workspace_assessment_not_found')
        conn.execute('INSERT INTO canca.workspace_assessments VALUES (%s,%s)', (workspace_id, assessment_id))
    return {'status': 'assigned', 'workspace_id': workspace_id, 'assessment_id': assessment_id}


def revoke_workspace(conn, workspace_id, principal_role, permission):
    identifier(workspace_id); identifier(principal_role)
    pg.require(permission in PERMISSIONS, 'workspace_input_invalid')
    with transaction(conn):
        admin(conn)
        row = conn.execute('''DELETE FROM canca.workspace_grants
            WHERE workspace_id=%s AND principal_role=%s AND permission=%s RETURNING workspace_id''',
            (workspace_id, principal_role, permission)).fetchone()
    return {'status': 'revoked' if row else 'already_revoked', 'workspace_id': workspace_id}


def list_workspaces(conn, after='', limit=100):
    page_args(after, limit)
    with transaction(conn):
        # Explicit predicate also applies when a trusted maintenance role calls it.
        rows = conn.execute('''SELECT w.workspace_id,w.name,w.organization FROM canca.workspaces w
            WHERE w.workspace_id>%s AND EXISTS (SELECT 1 FROM canca.workspace_grants g
                WHERE g.workspace_id=w.workspace_id AND g.principal_role=current_user)
            ORDER BY w.workspace_id LIMIT %s''', (after, limit + 1)).fetchall()
    visible = rows[:limit]
    return {'status': 'listed', 'workspaces': [dict(zip(('workspace_id','name','organization'), r)) for r in visible],
            'has_more': len(rows) > limit, 'next_after': visible[-1][0] if visible else after}


def create_site(conn, workspace_id, site_id, name, kind, parent_site_id=None):
    identifier(workspace_id); identifier(site_id); label(name)
    pg.require(kind in SITE_KINDS, 'workspace_input_invalid')
    if parent_site_id is not None:
        identifier(parent_site_id)
        pg.require(parent_site_id != site_id, 'workspace_input_invalid')
    with scope(conn, workspace_id, 'workspace:write'):
        conn.execute('SELECT pg_advisory_xact_lock(%s)', (pg.lock_key('site:' + workspace_id + ':' + site_id),))
        old = conn.execute('SELECT name,kind,parent_site_id FROM canca.workspace_sites WHERE workspace_id=%s AND site_id=%s',
                           (workspace_id, site_id)).fetchone()
        if old:
            pg.require(old == (name, kind, parent_site_id), 'workspace_conflict')
            return {'status': 'already_registered', 'workspace_id': workspace_id, 'site_id': site_id}
        if parent_site_id:
            pg.require(conn.execute('SELECT 1 FROM canca.workspace_sites WHERE workspace_id=%s AND site_id=%s',
                       (workspace_id, parent_site_id)).fetchone(), 'workspace_parent_not_found')
        conn.execute('INSERT INTO canca.workspace_sites VALUES (%s,%s,%s,%s,%s)',
                     (workspace_id, site_id, name, kind, parent_site_id))
    return {'status': 'registered', 'workspace_id': workspace_id, 'site_id': site_id}


def create_environment(conn, workspace_id, environment_id, name, kind):
    identifier(workspace_id); identifier(environment_id); label(name)
    pg.require(kind in ENVIRONMENT_KINDS, 'workspace_input_invalid')
    with scope(conn, workspace_id, 'workspace:write'):
        conn.execute('SELECT pg_advisory_xact_lock(%s)', (pg.lock_key('environment:' + workspace_id + ':' + environment_id),))
        old = conn.execute('SELECT name,kind FROM canca.workspace_environments WHERE workspace_id=%s AND environment_id=%s',
                           (workspace_id, environment_id)).fetchone()
        if old:
            pg.require(old == (name, kind), 'workspace_conflict')
            return {'status': 'already_registered', 'workspace_id': workspace_id, 'environment_id': environment_id}
        conn.execute('INSERT INTO canca.workspace_environments VALUES (%s,%s,%s,%s)',
                     (workspace_id, environment_id, name, kind))
    return {'status': 'registered', 'workspace_id': workspace_id, 'environment_id': environment_id}


def list_items(conn, workspace_id, category, after='', limit=100):
    tables = {'sites': ('workspace_sites', ('site_id','name','kind','parent_site_id')),
              'environments': ('workspace_environments', ('environment_id','name','kind')),
              'assessments': ('workspace_assessments', ('assessment_id',))}
    pg.require(isinstance(category, str) and category in tables, 'workspace_input_invalid')
    identifier(workspace_id); page_args(after, limit)
    table, columns = tables[category]
    with scope(conn, workspace_id):
        # Identifiers are exclusively from this constant allowlist.
        rows = conn.execute('SELECT ' + ','.join(columns) + ' FROM canca.' + table +
            ' WHERE workspace_id=%s AND ' + columns[0] + '>%s ORDER BY ' + columns[0] + ' LIMIT %s',
            (workspace_id, after, limit + 1)).fetchall()
    visible = rows[:limit]
    return {'status': 'listed', 'workspace_id': workspace_id, 'category': category,
            'items': [dict(zip(columns, r)) for r in visible], 'has_more': len(rows) > limit,
            'next_after': visible[-1][0] if visible else after}


def cli(argv=None):
    parser = argparse.ArgumentParser(description='Cancã workspace foundation v' + VERSION)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('migrate')
    create = commands.add_parser('create-workspace')
    create.add_argument('--workspace-id', required=True); create.add_argument('--name', required=True)
    create.add_argument('--organization', default='')
    for command in ('grant-workspace', 'revoke-workspace'):
        grant = commands.add_parser(command)
        grant.add_argument('--workspace-id', required=True); grant.add_argument('--principal-role', required=True)
        grant.add_argument('--permission', choices=PERMISSIONS, required=True)
    bind = commands.add_parser('bind-assessment')
    bind.add_argument('--workspace-id', required=True); bind.add_argument('--assessment-id', required=True)
    site = commands.add_parser('create-site')
    site.add_argument('--workspace-id', required=True); site.add_argument('--site-id', required=True)
    site.add_argument('--name', required=True); site.add_argument('--kind', choices=SITE_KINDS, required=True)
    site.add_argument('--parent-site-id')
    environment = commands.add_parser('create-environment')
    environment.add_argument('--workspace-id', required=True); environment.add_argument('--environment-id', required=True)
    environment.add_argument('--name', required=True); environment.add_argument('--kind', choices=ENVIRONMENT_KINDS, required=True)
    for command in ('list-workspaces', 'list-items'):
        listing = commands.add_parser(command); listing.add_argument('--after', default=''); listing.add_argument('--limit', type=int, default=100)
        if command == 'list-items':
            listing.add_argument('--workspace-id', required=True); listing.add_argument('--category', choices=('sites','environments','assessments'), required=True)
    args = parser.parse_args(argv)
    try:
        # Validate all submitted identifiers/labels before opening the database.
        for key in ('workspace_id','site_id','environment_id','assessment_id','principal_role'):
            value = getattr(args, key, None)
            if value is not None: identifier(value)
        if getattr(args, 'parent_site_id', None) is not None: identifier(args.parent_site_id)
        if args.command == 'create-site':
            pg.require(args.parent_site_id != args.site_id, 'workspace_input_invalid')
        if hasattr(args, 'name'): label(args.name)
        if hasattr(args, 'organization'): label(args.organization, empty=True)
        if hasattr(args, 'limit'): page_args(args.after, args.limit)
        with pg.open_connection() as conn:
            if args.command == 'migrate': result = pg.migrate(conn, workspace=True)
            elif args.command == 'create-workspace': result = create_workspace(conn, args.workspace_id, args.name, args.organization)
            elif args.command == 'grant-workspace': result = grant_workspace(conn, args.workspace_id, args.principal_role, args.permission)
            elif args.command == 'revoke-workspace': result = revoke_workspace(conn, args.workspace_id, args.principal_role, args.permission)
            elif args.command == 'bind-assessment': result = bind_assessment(conn, args.workspace_id, args.assessment_id)
            elif args.command == 'create-site': result = create_site(conn, args.workspace_id, args.site_id, args.name, args.kind, args.parent_site_id)
            elif args.command == 'create-environment': result = create_environment(conn, args.workspace_id, args.environment_id, args.name, args.kind)
            elif args.command == 'list-workspaces': result = list_workspaces(conn, args.after, args.limit)
            else: result = list_items(conn, args.workspace_id, args.category, args.after, args.limit)
        print(json.dumps(dict(result, workspace_version=VERSION), ensure_ascii=False))
        return 0
    except Exception as exc:
        code = str(exc) if isinstance(exc, pg.PersistenceError) and str(exc) in ERRORS else 'database_failed'
        print(json.dumps({'status': 'failed', 'error_code': code, 'workspace_version': VERSION}))
        return 2


if __name__ == '__main__':
    raise SystemExit(cli())
