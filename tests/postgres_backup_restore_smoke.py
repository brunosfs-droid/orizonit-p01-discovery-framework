#!/usr/bin/env python3
"""Destructive ONLY inside the guarded disposable GitHub PostgreSQL CI service."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'persistence'))
import P01_PostgreSQL as pg
import P01_Asset_Registry as assets
import P01_Findings as findings
import P01_Assessment_Lifecycle as lifecycle
import P01_Assessment_Report as report

VERSION = '0.6.6'
RESTORE_DB = 'canca_ci_restore'
TABLES = ('schema_migrations', 'assessments', 'nodes', 'runs', 'imports', 'artifacts',
          'assessment_events', 'assets', 'asset_imports', 'asset_observations',
          'asset_signals', 'finding_analyses', 'finding_evaluations', 'findings')


class SmokeError(Exception):
    pass


def require(condition):
    if not condition:
        raise SmokeError('backup_restore_failed')


def guard(container):
    require(os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('CANCA_TEST_POSTGRES') == '1'
            and os.environ.get('PGDATABASE') == 'canca_ci'
            and os.environ.get('PGUSER') == 'canca_ci'
            and os.environ.get('PGHOST') == '127.0.0.1'
            and os.environ.get('PGPORT') == '5432'
            and not os.environ.get('PGSERVICE')
            and re.fullmatch(r'[0-9a-f]{12,64}', container) is not None)


def docker(container, arguments, *, source=None, target=None):
    args = ['docker', 'exec'] + (['-i'] if source is not None else []) + [container] + arguments
    result = subprocess.run(args, stdin=source, stdout=target or subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=60, check=False)
    require(result.returncode == 0)
    return result.stdout


def digest_file(path):
    sha = hashlib.sha256()
    with path.open('rb') as source:
        while chunk := source.read(1024 * 1024):
            sha.update(chunk)
    return sha.hexdigest()


def store_inventory(root):
    entries = []
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink())
        if path.is_file():
            entries.append({'path': path.relative_to(root).as_posix(),
                            'size_bytes': path.stat().st_size, 'sha256': digest_file(path)})
        else:
            require(path.is_dir())
    require(entries)
    return entries


def table_snapshot(conn):
    # Names are a constant allowlist; rows contain source metadata, never logged.
    return {table: [row[0] for row in conn.execute(
        'SELECT to_jsonb(t)::text FROM canca.' + table + ' t ORDER BY to_jsonb(t)::text').fetchall()]
        for table in TABLES}


def report_snapshot(conn, assessment_id):
    result = report.show_assessment(conn, assessment_id)
    result.pop('snapshot_at_utc', None)
    require(result['status'] == 'found' and not result['has_more'])
    return result


def prepare_projections(store, directory):
    return (pg.prepare_import(store, directory), assets.prepare_assets(store, directory),
            findings.prepare_findings(store, directory))


def run(container):
    guard(container)  # Before driver loading, filesystem preparation or subprocess/DDL.
    start = time.monotonic()
    with pg.open_connection() as conn:
        require(conn.execute('SELECT current_database(),current_user').fetchone() == ('canca_ci', 'canca_ci'))
        cluster = str(conn.execute('SELECT system_identifier FROM pg_control_system()').fetchone()[0])
        inside = docker(container, ['psql', '-U', 'canca_ci', '-d', 'canca_ci', '-X', '-tA',
                                   '-c', 'SELECT system_identifier FROM pg_control_system()'])
        require(inside.decode().strip() == cluster)
        require(conn.execute('SELECT 1 FROM pg_database WHERE datname=%s', (RESTORE_DB,)).fetchone() is None)
        version = conn.info.server_version
        conn.execute('DROP SCHEMA IF EXISTS canca CASCADE')
        require(pg.migrate(conn)['status'] == 'migrated')
        with tempfile.TemporaryDirectory(prefix='canca-backup-restore-') as temp:
            base = Path(temp)
            spec = importlib.util.spec_from_file_location('backup_fixture',
                ROOT / 'docs/validation/POSTGRESQL_LAB_FIXTURE_R1_v0.6.5.py')
            fixture = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(fixture)
            prepared = fixture.prepare(base / 'fixture')
            store = Path(prepared['store_dir'])
            aid = prepared['assessment_id']
            projections = []
            directories = []
            for item in prepared['imports']:
                directory = Path(item['import_dir'])
                directories.append(directory.relative_to(store))
                projection = prepare_projections(store, directory)
                require(pg.index_import(conn, projection[0])['status'] == 'indexed')
                require(assets.project_import(conn, projection[1])['status'] == 'projected')
                require(findings.project_import(conn, projection[2])['status'] == 'projected')
                projections.append(projection)
            lifecycle.transition(conn, aid, 0, 'backup-start', 'active', 'CI-SYNTHETIC')
            event = lifecycle.transition(conn, aid, 1, 'backup-finish', 'completed', 'CI-SYNTHETIC')['event']
            before = table_snapshot(conn)
            before_report = report_snapshot(conn, aid)
            require(len(before['imports']) == 2 and len(before['assets']) == 1
                    and len(before['finding_evaluations']) == 4 and len(before['findings']) == 2
                    and len(before['assessment_events']) == 2)
            require(conn.execute('SELECT status FROM canca.findings').fetchall() == [('Open',), ('Open',)])
            inventory = store_inventory(store)
            archive = base / 'database.dump'
            with archive.open('xb') as target:
                docker(container, ['pg_dump', '-U', 'canca_ci', '-d', 'canca_ci', '--format=custom'], target=target)
            require(archive.stat().st_size > 0)
            restored_store = base / 'restored-store'
            shutil.copytree(store, restored_store)
            require(store_inventory(store) == inventory == store_inventory(restored_store))
            require(table_snapshot(conn) == before)  # Exclusive fixture is quiescent throughout the pair copy.
            conn.execute('CREATE DATABASE canca_ci_restore TEMPLATE template0')
            with archive.open('rb') as source:
                docker(container, ['pg_restore', '-U', 'canca_ci', '-d', RESTORE_DB,
                                   '--single-transaction', '--exit-on-error', '--no-owner', '--no-privileges'], source=source)
            original_database = os.environ['PGDATABASE']
            os.environ['PGDATABASE'] = RESTORE_DB
            try:
                with pg.open_connection() as restored:
                    require(pg.migrate(restored)['status'] == 'already_migrated')
                    require(table_snapshot(restored) == before)
                    require(report_snapshot(restored, aid) == before_report)
                    for relative, expected in zip(directories, projections):
                        actual = prepare_projections(restored_store, restored_store / relative)
                        require(actual == expected)
                        require(pg.index_import(restored, actual[0])['status'] == 'already_indexed')
                        require(assets.project_import(restored, actual[1])['status'] == 'already_projected')
                        require(findings.project_import(restored, actual[2])['status'] == 'already_projected')
                    replay = lifecycle.transition(restored, aid, 1, 'backup-finish', 'completed', 'CI-SYNTHETIC')
                    require(replay['status'] == 'already_applied' and replay['event'] == event)
                    require(table_snapshot(restored) == before)
                    require(report_snapshot(restored, aid) == before_report)
                    # Prove the restored receipt bytes are actually revalidated.
                    receipt = restored_store / directories[0] / 'receipt/import-receipt.json'
                    original = receipt.read_bytes()
                    try:
                        receipt.write_bytes(original + b' ')
                        try:
                            pg.prepare_import(restored_store, restored_store / directories[0])
                        except pg.PersistenceError as error:
                            require(str(error) == 'receipt_integrity_failed')
                        else:
                            raise SmokeError('backup_restore_failed')
                    finally:
                        receipt.write_bytes(original)
                    require(store_inventory(restored_store) == inventory)
                    require(table_snapshot(restored) == before)
            finally:
                os.environ['PGDATABASE'] = original_database
            logical_sha = hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest()
            return {'status': 'POSTGRESQL BACKUP RESTORE PASS', 'qualification_version': VERSION,
                    'server_version_num': version, 'tables_compared': len(TABLES),
                    'row_counts': {table: len(rows) for table, rows in before.items()},
                    'dump_sha256': digest_file(archive), 'store_file_count': len(inventory),
                    'store_inventory_sha256': hashlib.sha256(pg.canonical(inventory)).hexdigest(),
                    'logical_snapshot_sha256': logical_sha, 'source_bytes_revalidated': True,
                    'receipt_corruption_rejected': True, 'replay_preserved_snapshot': True,
                    'exclusive_synthetic_fixture': True, 'roles_and_grants_qualified': False,
                    'elapsed_seconds': round(time.monotonic() - start, 3), 'evidence_retained': False}


def cli(argv=None):
    parser = argparse.ArgumentParser(description='Disposable GitHub CI backup/restore qualification')
    parser.add_argument('--postgres-container', required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(run(args.postgres_container), sort_keys=True))
        return 0
    except Exception:
        print(json.dumps({'status': 'failed', 'error_code': 'backup_restore_failed',
                          'qualification_version': VERSION}))
        return 2


if __name__ == '__main__':
    raise SystemExit(cli())
