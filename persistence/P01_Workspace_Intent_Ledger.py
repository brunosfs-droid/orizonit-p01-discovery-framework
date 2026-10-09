#!/usr/bin/env python3
"""Durable review decisions only; never a scanner execution authorization."""
import argparse
import hmac
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import P01_Workspace_Model as model
import P01_Workspace_Live_Intent as live

pg, ws, runtime = model.pg, model.ws, model.runtime
VERSION = '0.6.45'
SHA = re.compile(r'[0-9a-f]{64}\Z')
INTENT = re.compile(r'intent-[0-9a-f]{32}\Z')
ERRORS = model.ERRORS | {'intent_conflict', 'intent_stale', 'intent_not_found', 'intent_transition_denied'}


def require(value, code='workspace_input_invalid'):
    pg.require(value, code)


def _id(value):
    require(type(value) is str and INTENT.fullmatch(value))


def _scope(operation, approved, scope_id, mode, expected_digest):
    require(type(expected_digest) is str and SHA.fullmatch(expected_digest))
    preview = live.preview(operation, approved, scope_id, mode, ack_authorized_access=True)
    require(hmac.compare_digest(preview['scope_digest_sha256'], expected_digest), 'intent_stale')
    return pg.digest(operation.token.lease_id.encode('ascii'))


def _result(intent_id, decision, *, replayed=False):
    return dict(version=VERSION, intent_id=intent_id, status=decision,
                replayed=replayed, execution_authorized=False,
                authentication_performed=False, network_activity_performed=False)


def _row(conn, workspace_id, intent_id):
    row = conn.execute('SELECT generation,lease_sha256,scope_id,mode,scope_sha256,expires_at>clock_timestamp() '
                       'FROM canca.workspace_scan_intents WHERE workspace_id=%s AND intent_id=%s',
                       (workspace_id, intent_id)).fetchone()
    require(row is not None, 'intent_not_found')
    return row


def _current(row, token, lease_sha, scope_id, mode, digest):
    require(row[:5] == (token.generation, lease_sha, scope_id, mode, digest) and row[5], 'intent_stale')


def record(operation, approved, scope_id, mode, expected_digest, request_id,
           *, ttl_seconds=60, ack_authorized_access=False):
    ws.identifier(request_id)
    require(type(ttl_seconds) is int and 1 <= ttl_seconds <= 300)
    require(type(ack_authorized_access) is bool and ack_authorized_access)
    lease_sha = _scope(operation, approved, scope_id, mode, expected_digest)
    conn, token = operation.actor, operation.token
    with model.scope(conn, token.workspace_id, token, writing=True):
        pg.schema_check(conn, minimum=10, intents=True)
        role = conn.execute('SELECT current_user').fetchone()[0]
        old = conn.execute('SELECT intent_id,ttl_seconds FROM canca.workspace_scan_intents '
                           'WHERE workspace_id=%s AND author_role=current_user AND request_id=%s',
                           (token.workspace_id, request_id)).fetchone()
        if old:
            _current(_row(conn, token.workspace_id, old[0]), token, lease_sha, scope_id, mode, expected_digest)
            require(old[1] == ttl_seconds, 'intent_conflict')
            return _result(old[0], 'intent_recorded_only', replayed=True)
        intent_id = 'intent-' + model.digest([token.workspace_id, role, request_id])[:32]
        conn.execute('INSERT INTO canca.workspace_scan_intents '
                     '(workspace_id,intent_id,request_id,generation,lease_sha256,scope_id,mode,scope_sha256,ttl_seconds,expires_at,created_revision) '
                     'VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,clock_timestamp(),0)',
                     (token.workspace_id, intent_id, request_id, token.generation, lease_sha,
                      scope_id, mode, expected_digest, ttl_seconds))
        return _result(intent_id, 'intent_recorded_only')


def decide(operation, approved, scope_id, mode, expected_digest, intent_id, decision, request_id,
           *, ack_authorized_access=False):
    _id(intent_id); ws.identifier(request_id)
    require(type(decision) is str and decision in {'approved', 'rejected', 'revoked', 'consumed'})
    require(type(ack_authorized_access) is bool and ack_authorized_access)
    lease_sha = _scope(operation, approved, scope_id, mode, expected_digest)
    conn, token = operation.actor, operation.token
    with model.scope(conn, token.workspace_id, token, writing=True):
        pg.schema_check(conn, minimum=10, intents=True)
        _current(_row(conn, token.workspace_id, intent_id), token, lease_sha, scope_id, mode, expected_digest)
        old = conn.execute('SELECT intent_id,decision FROM canca.workspace_scan_decisions '
                           'WHERE workspace_id=%s AND author_role=current_user AND request_id=%s',
                           (token.workspace_id, request_id)).fetchone()
        if old:
            require(old == (intent_id, decision), 'intent_conflict')
            return _result(intent_id, decision + '_recorded_only', replayed=True)
        previous = conn.execute('SELECT sequence,decision FROM canca.workspace_scan_decisions '
                                'WHERE workspace_id=%s AND intent_id=%s ORDER BY sequence DESC LIMIT 1',
                                (token.workspace_id, intent_id)).fetchone()
        state = previous[1] if previous else 'pending'
        require(decision in ({'approved', 'rejected', 'revoked'} if state == 'pending' else
                             {'revoked', 'consumed'} if state == 'approved' else set()), 'intent_transition_denied')
        conn.execute('INSERT INTO canca.workspace_scan_decisions '
                     '(workspace_id,intent_id,sequence,request_id,decision,created_revision) VALUES (%s,%s,%s,%s,%s,0)',
                     (token.workspace_id, intent_id, previous[0] + 1 if previous else 1, request_id, decision))
        return _result(intent_id, decision + '_recorded_only')


def history(conn, workspace_id, token, intent_id):
    """Read historical decisions after restart; never re-arm an old generation."""
    _id(intent_id)
    with model.scope(conn, workspace_id, token):
        pg.schema_check(conn, minimum=10, intents=True)
        row = _row(conn, workspace_id, intent_id)
        events = conn.execute('SELECT sequence,decision,author_role,created_at FROM canca.workspace_scan_decisions '
                              'WHERE workspace_id=%s AND intent_id=%s ORDER BY sequence LIMIT 2',
                              (workspace_id, intent_id)).fetchall()
        return dict(_result(intent_id, 'historical_review_only'),
                    context_current=row[0] == token.generation and row[1] == pg.digest(token.lease_id.encode('ascii')),
                    expired=not row[5], decisions=[dict(sequence=e[0], decision=e[1], author_role=e[2],
                                                      at_utc=e[3].isoformat()) for e in events])


def cli(argv=None):
    parser = argparse.ArgumentParser(description='Cancã opt-in review ledger migration')
    parser.add_argument('command', choices=('migrate',)); parser.parse_args(argv)
    try:
        with pg.open_connection() as conn:
            ws.admin(conn)
            result = pg.migrate(conn, intents=True)
        print(json.dumps(dict(result, version=VERSION))); return 0
    except Exception as error:
        code = str(error) if isinstance(error, pg.PersistenceError) and str(error) in ERRORS else 'database_failed'
        print(json.dumps(dict(status='failed', error_code=code, version=VERSION))); return 2


if __name__ == '__main__':
    raise SystemExit(cli())
