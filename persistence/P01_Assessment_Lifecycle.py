#!/usr/bin/env python3
"""Explicit operator decisions; never controls node execution or infers coverage."""
from __future__ import annotations
import argparse
from datetime import timezone
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import P01_PostgreSQL as pg

VERSION = '0.6.2'
TRANSITIONS = {
    ('registered', 'active'): 'operator_start',
    ('active', 'review_required'): 'operator_review',
    ('review_required', 'active'): 'operator_resume',
    ('active', 'completed'): 'operator_complete',
    **{(state, 'cancelled'): 'operator_cancel' for state in ('registered', 'active', 'review_required')},
}
STATES = {'registered', 'active', 'review_required', 'completed', 'cancelled'}
ERRORS = pg.ERRORS | {'assessment_not_found', 'revision_conflict', 'transition_invalid', 'request_conflict'}
EVENT_COLUMNS = ('revision', 'request_id', 'actor_ref', 'from_state', 'to_state', 'reason_code', 'occurred_at_utc')


def identifier(value):
    pg.require(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', value), 'input_invalid')


def revision(value):
    pg.require(type(value) is int and 0 <= value < 2**63 - 1, 'input_invalid')


def validate_transition(assessment_id, expected_revision, request_id, target_state, actor_ref):
    for value in (assessment_id, request_id, actor_ref):
        identifier(value)
    revision(expected_revision)
    pg.require(isinstance(target_state, str) and target_state in STATES, 'input_invalid')


def event_doc(row):
    result = dict(zip(EVENT_COLUMNS, row))
    result['occurred_at_utc'] = row[-1].astimezone(timezone.utc).isoformat()
    return result


def setup(conn, readonly=False):
    conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY' if readonly
                 else 'SET TRANSACTION ISOLATION LEVEL READ COMMITTED')
    pg.timeout(conn)
    pg.schema_check(conn, minimum=2)


def register_assessment(conn, assessment_id):
    identifier(assessment_id)
    pg.guard_connection(conn)
    with conn.transaction():
        setup(conn)
        inserted = conn.execute('INSERT INTO canca.assessments (assessment_id) VALUES (%s) '
                                'ON CONFLICT DO NOTHING RETURNING assessment_id', (assessment_id,)).fetchone()
        row = conn.execute('SELECT lifecycle_state,lifecycle_revision FROM canca.assessments '
                           'WHERE assessment_id=%s', (assessment_id,)).fetchone()
    return {'status': 'registered' if inserted else 'already_registered', 'assessment_id': assessment_id,
            'state': row[0], 'revision': row[1]}


def transition(conn, assessment_id, expected_revision, request_id, target_state, actor_ref):
    validate_transition(assessment_id, expected_revision, request_id, target_state, actor_ref)
    pg.guard_connection(conn)
    with conn.transaction():
        setup(conn)
        current = conn.execute('SELECT lifecycle_state,lifecycle_revision FROM canca.assessments '
                               'WHERE assessment_id=%s FOR UPDATE', (assessment_id,)).fetchone()
        pg.require(current is not None, 'assessment_not_found')
        previous = conn.execute('SELECT ' + ','.join(EVENT_COLUMNS) + ' FROM canca.assessment_events '
                                'WHERE assessment_id=%s AND request_id=%s', (assessment_id, request_id)).fetchone()
        if previous:
            pg.require(previous[0] - 1 == expected_revision and previous[2] == actor_ref
                       and previous[4] == target_state, 'request_conflict')
            return {'status': 'already_applied', 'assessment_id': assessment_id, 'event': event_doc(previous)}
        pg.require(current[1] == expected_revision, 'revision_conflict')
        reason = TRANSITIONS.get((current[0], target_state))
        pg.require(reason is not None, 'transition_invalid')
        updated = conn.execute('UPDATE canca.assessments SET lifecycle_state=%s,lifecycle_revision=%s '
                               'WHERE assessment_id=%s AND lifecycle_revision=%s RETURNING assessment_id',
                               (target_state, expected_revision + 1, assessment_id, expected_revision)).fetchone()
        pg.require(updated is not None, 'revision_conflict')
        event = conn.execute('INSERT INTO canca.assessment_events '
                             '(assessment_id,revision,request_id,actor_ref,from_state,to_state,reason_code) '
                             'VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING ' + ','.join(EVENT_COLUMNS),
                             (assessment_id, expected_revision + 1, request_id, actor_ref,
                              current[0], target_state, reason)).fetchone()
    return {'status': 'applied', 'assessment_id': assessment_id, 'event': event_doc(event)}


def show_assessment(conn, assessment_id, after_revision=0, limit=100):
    identifier(assessment_id)
    revision(after_revision)
    pg.require(type(limit) is int and 1 <= limit <= 100, 'input_invalid')
    pg.guard_connection(conn)
    with conn.transaction():
        setup(conn, readonly=True)
        row = conn.execute('SELECT lifecycle_state,lifecycle_revision FROM canca.assessments '
                           'WHERE assessment_id=%s', (assessment_id,)).fetchone()
        if row is None:
            return {'status': 'not_found', 'assessment_id': assessment_id}
        events = conn.execute('SELECT ' + ','.join(EVENT_COLUMNS) + ' FROM canca.assessment_events '
                              'WHERE assessment_id=%s AND revision>%s ORDER BY revision LIMIT %s',
                              (assessment_id, after_revision, limit + 1)).fetchall()
    page = events[:limit]
    return {'status': 'found', 'assessment_id': assessment_id, 'state': row[0], 'revision': row[1],
            'events': [event_doc(event) for event in page], 'has_more': len(events) > limit,
            'next_after_revision': page[-1][0] if page else after_revision}


def cli(argv=None):
    parser = argparse.ArgumentParser(description='Cancã assessment lifecycle v' + VERSION)
    commands = parser.add_subparsers(dest='command', required=True)
    register = commands.add_parser('register')
    register.add_argument('--assessment-id', required=True)
    show = commands.add_parser('show')
    show.add_argument('--assessment-id', required=True)
    show.add_argument('--after-revision', type=int, default=0)
    show.add_argument('--limit', type=int, default=100)
    change = commands.add_parser('transition')
    change.add_argument('--assessment-id', required=True)
    change.add_argument('--expected-revision', required=True, type=int)
    change.add_argument('--request-id', required=True)
    change.add_argument('--target-state', required=True)
    change.add_argument('--actor-ref', required=True)
    args = parser.parse_args(argv)
    try:
        identifier(args.assessment_id)
        if args.command == 'transition':
            validate_transition(args.assessment_id, args.expected_revision, args.request_id, args.target_state, args.actor_ref)
        if args.command == 'show':
            revision(args.after_revision)
            pg.require(1 <= args.limit <= 100, 'input_invalid')
        with pg.open_connection() as conn:
            if args.command == 'register':
                result = register_assessment(conn, args.assessment_id)
            elif args.command == 'show':
                result = show_assessment(conn, args.assessment_id, args.after_revision, args.limit)
            else:
                result = transition(conn, args.assessment_id, args.expected_revision, args.request_id, args.target_state, args.actor_ref)
        print(json.dumps(dict(result, lifecycle_version=VERSION)))
        return 0
    except Exception as exc:
        code = str(exc) if isinstance(exc, pg.PersistenceError) and str(exc) in ERRORS else 'database_failed'
        print(json.dumps({'status': 'failed', 'error_code': code, 'lifecycle_version': VERSION}))
        return 2


if __name__ == '__main__':
    raise SystemExit(cli())
