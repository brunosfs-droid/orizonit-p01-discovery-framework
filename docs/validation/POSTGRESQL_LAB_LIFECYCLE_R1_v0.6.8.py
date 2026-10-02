#!/usr/bin/env python3
"""Explicit lifecycle exercise restricted to the recovered synthetic R1 pair."""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'persistence'))
import P01_Assessment_Lifecycle as life
import P01_Assessment_Report as report

spec = importlib.util.spec_from_file_location('lab_recovery_r1', Path(__file__).with_name('POSTGRESQL_LAB_RECOVERY_R1_v0.6.7.py'))
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)
pg = recovery.pg
VERSION = '0.6.8'
DATABASE = 'canca_p01_restore_r1'
AID = recovery.ASSESSMENT_ID
ACTOR = 'P01-PG-LAB-R1-operator'
STATES = ('registered', 'active', 'review_required', 'active', 'completed')
REQUESTS = tuple('P01-PG-LIFE-R1-' + str(i) for i in range(1, 5))


def require(ok):
    recovery.require(ok, 'lifecycle_lab_mismatch')


def unchanged_projection(snapshot):
    # Only the administrative state and its four history rows may change.
    return {**snapshot, 'table_fingerprints': {k: v for k, v in snapshot['table_fingerprints'].items()
                                             if k not in ('assessments', 'assessment_events')}}


def history(conn):
    doc = life.show_assessment(conn, AID, limit=100)
    require(doc['status'] == 'found' and type(doc['revision']) is int and 0 <= doc['revision'] <= 4)
    n = doc['revision']
    require(doc['state'] == STATES[n] and not doc['has_more'] and len(doc['events']) == n)
    for i, event in enumerate(doc['events'], 1):
        require(event['revision'] == i and event['request_id'] == REQUESTS[i - 1]
                and event['actor_ref'] == ACTOR and event['from_state'] == STATES[i - 1]
                and event['to_state'] == STATES[i]
                and event['reason_code'] == life.TRANSITIONS[(STATES[i - 1], STATES[i])])
    return doc


def pages(conn):
    first = report.show_assessment(conn, AID, limit=1)
    require(first['status'] == 'found')
    scope = first['report_scope_sha256']
    seen = list(first['evaluations']); page = first; count = 1
    while page['has_more']:
        require(count < 4)
        page = report.show_assessment(conn, AID, limit=1, expected_scope_sha256=scope, **page['next_cursor'])
        require(page['report_scope_sha256'] == scope and len(page['evaluations']) == 1)
        seen.extend(page['evaluations']); count += 1
    keys = [(r['analysis_id'], r['ordinal']) for r in seen]
    require(count == 4 and len(keys) == len(set(keys)) == 4 and keys == sorted(keys))
    full = report.show_assessment(conn, AID, expected_scope_sha256=scope)
    require(seen == full['evaluations'] and full['coverage']['evaluation_count'] == 4
            and full['coverage']['outcomes'] == {'finding': 2, 'no_finding': 2, 'insufficient_evidence': 0,
                                               'not_applicable': 0, 'not_supported': 0}
            and full['identity']['central_asset_count'] == 1 and full['identity']['observation_count'] == 2
            and full['recorded_finding_occurrences'] == 2
            and all(r['finding_status'] == 'Open' for r in seen if r['finding_id']))
    end = report.show_assessment(conn, AID, expected_scope_sha256=scope, **page['next_cursor'])
    require(not end['has_more'] and end['evaluations'] == [])
    return dict(report_pages=count, evaluations=len(seen), report_scope_sha256=scope,
                recorded_open_findings=2, central_assets=1)


def expect_error(code, operation):
    try:
        operation()
    except pg.PersistenceError as exc:
        require(str(exc) == code)
    else:
        require(False)


def run(conn, store, database, reference, exercise=False):
    # Full original sources are checked before any lifecycle decision is written.
    expected = recovery.load_snapshot(reference)
    baseline = recovery.capture(conn, store, database)
    require(unchanged_projection(baseline) == unchanged_projection(expected))
    initial = history(conn)['revision']
    checks = pages(conn)
    invalidated = 0
    if exercise:
        for i in range(initial, 4):
            old = report.show_assessment(conn, AID, limit=1)
            result = life.transition(conn, AID, i, REQUESTS[i], STATES[i + 1], ACTOR)
            require(result['status'] == 'applied')
            expect_error('report_scope_conflict', lambda: report.show_assessment(
                conn, AID, limit=1, expected_scope_sha256=old['report_scope_sha256'], **old['next_cursor']))
            invalidated += 1
        final = history(conn)
        require(final['revision'] == 4)
        for i in range(4):
            repeat = life.transition(conn, AID, i, REQUESTS[i], STATES[i + 1], ACTOR)
            require(repeat['status'] == 'already_applied' and repeat['event'] == final['events'][i])
        expect_error('request_conflict', lambda: life.transition(conn, AID, 0, REQUESTS[0], 'active', 'OTHER'))
        expect_error('revision_conflict', lambda: life.transition(conn, AID, 3, 'P01-PG-LIFE-R1-stale', 'active', ACTOR))
        expect_error('transition_invalid', lambda: life.transition(conn, AID, 4, 'P01-PG-LIFE-R1-terminal', 'active', ACTOR))
        # Exercise lifecycle history pagination independently of report pagination.
        events = []; cursor = 0
        for _ in range(4):
            page = life.show_assessment(conn, AID, after_revision=cursor, limit=1)
            require(len(page['events']) == 1)
            events.extend(page['events']); cursor = page['next_after_revision']
        require(events == final['events'] and not page['has_more'])
        checks = pages(conn)
    after = recovery.capture(conn, store, database)
    require(unchanged_projection(after) == unchanged_projection(baseline))
    if not exercise or initial == 4:
        require(after == baseline)
    final = history(conn)
    return dict(status='POSTGRESQL LAB LIFECYCLE PASS' if exercise else 'POSTGRESQL LAB PAGES PASS',
                validation_version=VERSION, expected_database=database, assessment_id=AID,
                initial_revision=initial, state=final['state'], revision=final['revision'],
                transitions_applied=4 - initial if exercise else 0,
                stale_cursor_rejections=invalidated, idempotent_replays=4 if exercise else 0,
                negative_transition_gates=3 if exercise else 0, **checks,
                unchanged_tables_compared=12, source_bytes_revalidated=True,
                store_mutated=False, administrative_lifecycle_mutated=exercise and initial < 4,
                snapshot=after)


def cli(argv=None):
    parser = argparse.ArgumentParser(description='Recovered R1 lifecycle and report validation v' + VERSION)
    parser.add_argument('command', choices=('inspect', 'exercise'))
    parser.add_argument('--expected-database', required=True)
    parser.add_argument('--store-dir', required=True)
    parser.add_argument('--reference', required=True)
    parser.add_argument('--evidence-root', required=True)
    parser.add_argument('--ack-lifecycle-test', action='store_true')
    args = parser.parse_args(argv)
    try:
        # CLI never permits the source database or a caller-selected assessment.
        require(args.expected_database == DATABASE and os.environ.get('PGDATABASE') == DATABASE)
        require(args.command != 'exercise' or args.ack_lifecycle_test)
        # Proof output must never add files to the store whose integrity we report.
        require(not Path(args.evidence_root).expanduser().resolve().is_relative_to(
            Path(args.store_dir).expanduser().resolve()))
        recovery.load_snapshot(args.reference)
        with pg.open_connection() as conn:
            doc = run(conn, args.store_dir, DATABASE, args.reference, args.command == 'exercise')
        path = recovery.save_snapshot(doc, args.evidence_root)
        summary = {k: v for k, v in doc.items() if k != 'snapshot'}
        summary.update(proof_path=str(path), proof_sha256=pg.digest(pg.canonical(doc)))
        print(json.dumps(summary)); return 0
    except Exception as exc:
        allowed = pg.ERRORS | report.ERRORS | life.ERRORS | {'recovery_invalid', 'recovery_limit', 'recovery_mismatch', 'lifecycle_lab_mismatch'}
        code = str(exc) if isinstance(exc, (pg.PersistenceError, recovery.RecoveryError)) and str(exc) in allowed else 'database_failed'
        print(json.dumps(dict(status='failed', error_code=code, validation_version=VERSION))); return 2


if __name__ == '__main__':
    raise SystemExit(cli())
