#!/usr/bin/env python3
"""Explicit PostgreSQL migrations and index of validated imported evidence metadata."""
from __future__ import annotations
import argparse
from datetime import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'evidence_bundle'))
import P01_Evidence_Bundle as bundle

VERSION = '0.6.4'
SQL_PATH = Path(__file__).resolve().parent / 'migrations/0001_metadata.sql'
MIGRATIONS = (SQL_PATH, SQL_PATH.with_name('0002_assessment_lifecycle.sql'),
              SQL_PATH.with_name('0003_asset_registry.sql'), SQL_PATH.with_name('0004_findings.sql'))
WORKSPACE_MIGRATIONS = MIGRATIONS + (SQL_PATH.with_name('0005_workspace_foundation.sql'),)
RUNTIME_MIGRATIONS = WORKSPACE_MIGRATIONS + (SQL_PATH.with_name('0006_workspace_runtime.sql'),)
MODEL_MIGRATIONS = RUNTIME_MIGRATIONS + (SQL_PATH.with_name('0007_workspace_model.sql'),)
RECOVERY_MIGRATIONS = MODEL_MIGRATIONS + (SQL_PATH.with_name('0008_workspace_recovery_fence.sql'),)
IDENTITY = ('assessment_id', 'run_id', 'node_id')
ROLES = {'network_discovery', 'credentialed_evidence', 'assessment_manifest', 'asset_resolver'}
ERRORS = {'input_invalid', 'receipt_integrity_failed', 'bundle_integrity_failed', 'identity_mismatch',
          'schema_mismatch', 'schema_required', 'database_failed', 'database_config_required',
          'database_driver_required', 'database_version_unsupported', 'connection_not_idle', 'bundle_conflict'}


class PersistenceError(RuntimeError):
    pass


def require(ok, code):
    if not ok:
        raise PersistenceError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(doc):
    return (json.dumps(doc, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False) + '\n').encode()


def unique(pairs):
    doc = {}
    for key, value in pairs:
        require(key not in doc, 'input_invalid')
        doc[key] = value
    return doc


def read_json(raw):
    try:
        doc = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=unique,
                         parse_constant=lambda _: (_ for _ in ()).throw(PersistenceError('input_invalid')))
        require(isinstance(doc, dict), 'input_invalid')
        return doc
    except PersistenceError:
        raise
    except Exception:
        raise PersistenceError('input_invalid') from None


def safe_relative(value):
    require(isinstance(value, str) and value and '\\' not in value and ':' not in value
            and not any(ord(c) < 32 for c in value), 'input_invalid')
    path = PurePosixPath(value)
    require(not path.is_absolute() and '..' not in path.parts and str(path) == value, 'input_invalid')
    return path


def owned(root, relative):
    rel = safe_relative(relative)
    path = root.joinpath(*rel.parts)
    cursor = root
    for part in rel.parts:
        cursor = cursor / part
        require(not cursor.is_symlink(), 'input_invalid')
    require(path.resolve().is_relative_to(root) and path.is_file(), 'input_invalid')
    return path


def prepare_import(store, import_dir):
    """Read-only source; validate one private snapshot before any DB operation."""
    try:
        store = Path(store).expanduser().resolve()
        supplied = Path(import_dir).expanduser().absolute()
        require(store.is_dir() and supplied.is_relative_to(store), 'input_invalid')
        # Refuse symlink aliases, even if their target is inside the store.
        relative = supplied.relative_to(store)
        cursor = store
        for part in relative.parts:
            require(part not in {'.', '..'}, 'input_invalid')
            cursor = cursor / part
            require(not cursor.is_symlink(), 'input_invalid')
        directory = supplied.resolve()
        require(directory.is_dir(), 'input_invalid')
        receipt_path = owned(directory, 'receipt/import-receipt.json')
        with receipt_path.open('rb') as source:
            raw_receipt = source.read(65537)
        require(len(raw_receipt) <= 65536, 'input_invalid')
        sidecar = owned(directory, 'receipt/import-receipt.json.sha256').read_text().strip().split()
        require(sidecar and sidecar[0] == digest(raw_receipt), 'receipt_integrity_failed')
        receipt = read_json(raw_receipt)
        require(receipt.get('schema_version') == '0.5b' and receipt.get('status') == 'imported', 'input_invalid')
        for field in IDENTITY:
            require(isinstance(receipt.get(field), str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', receipt[field]), 'input_invalid')
        bundle_id = receipt.get('bundle_id')
        require(isinstance(bundle_id, str) and re.fullmatch(r'bnd-[0-9a-f]{20}', bundle_id), 'input_invalid')
        expected = store / 'assessments' / receipt['assessment_id'] / 'imports' / bundle_id
        require(directory == expected, 'identity_mismatch')
        imported = datetime.fromisoformat(receipt['imported_at_utc'])
        require(imported.utcoffset() is not None and imported.utcoffset().total_seconds() == 0, 'input_invalid')
        raw_path = owned(directory, receipt.get('raw_bundle'))
        require(safe_relative(receipt['raw_bundle']).parts[0] == 'raw' and raw_path.stat().st_size <= 1024**3, 'input_invalid')
        with tempfile.TemporaryDirectory(prefix='canca-index-') as temp:
            snapshot = Path(temp) / 'snapshot.p01bundle'
            with raw_path.open('rb') as source, snapshot.open('xb') as target:
                total = 0
                while chunk := source.read(1024**2):
                    total += len(chunk)
                    require(total <= 1024**3, 'input_invalid')
                    target.write(chunk)
            sha = bundle.digest_file(snapshot)
            require(sha == receipt.get('bundle_sha256'), 'bundle_integrity_failed')
            try:
                validation = bundle.validate_bundle(snapshot)
                with zipfile.ZipFile(snapshot) as archive:
                    manifest = read_json(archive.read('bundle-manifest.json'))
            except Exception:
                raise PersistenceError('bundle_integrity_failed') from None
        for field in (*IDENTITY, 'bundle_id'):
            require(receipt.get(field) == manifest.get(field), 'identity_mismatch')
        artifacts = []
        for item in manifest['artifacts']:
            safe_relative(item['path'])
            require(item.get('role') in ROLES and type(item.get('size_bytes')) is int and item['size_bytes'] >= 0
                    and re.fullmatch(r'[0-9a-f]{64}', str(item.get('sha256'))), 'input_invalid')
            artifacts.append({key: item[key] for key in ('path', 'role', 'sha256', 'size_bytes')})
        require(artifacts and receipt.get('artifact_count') == validation['artifact_count'] == len(artifacts)
                and receipt.get('verified_inventory_entries') == validation['verified_inventory_entries']
                and receipt.get('credentialed_evidence_count') == validation['credentialed_evidence_count'], 'identity_mismatch')
        require(bundle._bundle_id(*(manifest[key] for key in IDENTITY), artifacts) == bundle_id, 'identity_mismatch')
        projection = {key: receipt[key] for key in IDENTITY}
        projection.update(bundle_id=bundle_id, bundle_sha256=sha, receipt_sha256=digest(raw_receipt),
                          imported_at_utc=receipt['imported_at_utc'], artifacts=sorted(artifacts, key=lambda x: x['path']))
        return projection
    except PersistenceError:
        raise
    except Exception:
        raise PersistenceError('input_invalid') from None


def lock_key(label):
    return int.from_bytes(hashlib.sha256(('canca:' + label).encode()).digest()[:8], 'big', signed=True)


def validate_projection(doc):
    try:
        for key in IDENTITY:
            require(isinstance(doc[key], str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', doc[key]), 'input_invalid')
        for key in ('bundle_sha256', 'receipt_sha256'):
            require(isinstance(doc[key], str) and re.fullmatch(r'[0-9a-f]{64}', doc[key]), 'input_invalid')
        date = datetime.fromisoformat(doc['imported_at_utc'])
        require(date.utcoffset() is not None and date.utcoffset().total_seconds() == 0, 'input_invalid')
        require(isinstance(doc['artifacts'], list) and doc['artifacts'], 'input_invalid')
        paths = set()
        for item in doc['artifacts']:
            require(isinstance(item, dict) and set(item) == {'path', 'role', 'sha256', 'size_bytes'}, 'input_invalid')
            safe_relative(item['path'])
            require(item['path'] not in paths and item['role'] in ROLES and type(item['size_bytes']) is int
                    and item['size_bytes'] >= 0 and isinstance(item['sha256'], str)
                    and re.fullmatch(r'[0-9a-f]{64}', item['sha256']), 'input_invalid')
            paths.add(item['path'])
        require(doc['artifacts'] == sorted(doc['artifacts'], key=lambda x: x['path']), 'input_invalid')
        require(doc['bundle_id'] == bundle._bundle_id(*(doc[key] for key in IDENTITY), doc['artifacts']), 'identity_mismatch')
    except PersistenceError:
        raise
    except Exception:
        raise PersistenceError('input_invalid') from None


def guard_connection(conn):
    require(conn.autocommit and conn.info.transaction_status == 0, 'connection_not_idle')
    require(conn.info.server_version >= 160000, 'database_version_unsupported')


def timeout(conn):
    conn.execute("SET LOCAL lock_timeout = '5s'")
    conn.execute("SET LOCAL statement_timeout = '30s'")


def migration_prefix(rows, *, workspace=False, runtime=False, model=False, recovery=False):
    migrations = RECOVERY_MIGRATIONS if recovery else MODEL_MIGRATIONS if model else RUNTIME_MIGRATIONS if runtime else WORKSPACE_MIGRATIONS if workspace else MIGRATIONS
    expected = [(i, digest(path.read_bytes())) for i, path in enumerate(migrations, 1)]
    require(len(rows) <= len(expected) and rows == expected[:len(rows)], 'schema_mismatch')
    return expected


def schema_check(conn, minimum=1, *, workspace=False, runtime=False, model=False, recovery=False):
    row = conn.execute("SELECT to_regclass('canca.schema_migrations')").fetchone()
    require(row and row[0] is not None, 'schema_required')
    rows = conn.execute('SELECT version, sha256 FROM canca.schema_migrations ORDER BY version').fetchall()
    migration_prefix(rows, workspace=workspace, runtime=runtime, model=model, recovery=recovery)
    require(len(rows) >= minimum, 'schema_required')


def migrate(conn, *, workspace=False, runtime=False, model=False, recovery=False):
    guard_connection(conn)
    migrations = RECOVERY_MIGRATIONS if recovery else MODEL_MIGRATIONS if model else RUNTIME_MIGRATIONS if runtime else WORKSPACE_MIGRATIONS if workspace else MIGRATIONS
    with conn.transaction():
        conn.execute('SET TRANSACTION ISOLATION LEVEL READ COMMITTED')
        timeout(conn)
        conn.execute('SELECT pg_advisory_xact_lock(%s)', (lock_key('migration'),))
        conn.execute('CREATE SCHEMA IF NOT EXISTS canca')
        conn.execute('CREATE TABLE IF NOT EXISTS canca.schema_migrations (version integer PRIMARY KEY, sha256 text NOT NULL)')
        rows = conn.execute('SELECT version, sha256 FROM canca.schema_migrations ORDER BY version').fetchall()
        expected = migration_prefix(rows, workspace=workspace, runtime=runtime, model=model, recovery=recovery)
        for version, sha in expected[len(rows):]:
            conn.execute(migrations[version - 1].read_text())
            conn.execute('INSERT INTO canca.schema_migrations VALUES (%s, %s)', (version, sha))
    return {'status': 'already_migrated' if len(rows) == len(expected) else 'migrated',
            'schema_version': '0.6', 'migration': len(expected)}


def index_import(conn, projection):
    """Caller prepares verified source with prepare_import; one atomic metadata write."""
    guard_connection(conn)
    # Only the CLI's verified
    # source path establishes the receipt/bundle provenance, not this hash alone.
    require(isinstance(projection, dict) and set(projection) == set(IDENTITY) | {
        'bundle_id', 'bundle_sha256', 'receipt_sha256', 'imported_at_utc', 'artifacts'}, 'input_invalid')
    validate_projection(projection)
    fingerprint = digest(canonical(projection))
    bid = projection['bundle_id']
    with conn.transaction():
        conn.execute('SET TRANSACTION ISOLATION LEVEL READ COMMITTED')
        timeout(conn)
        schema_check(conn)
        conn.execute('SELECT pg_advisory_xact_lock(%s)', (lock_key('bundle:' + bid),))
        existing = conn.execute('SELECT projection_sha256 FROM canca.imports WHERE bundle_id=%s', (bid,)).fetchone()
        if existing:
            require(existing[0] == fingerprint, 'bundle_conflict')
            return {'status': 'already_indexed', 'bundle_id': bid, 'artifact_count': len(projection['artifacts'])}
        aid, rid, nid = (projection[key] for key in IDENTITY)
        conn.execute('INSERT INTO canca.assessments (assessment_id) VALUES (%s) ON CONFLICT DO NOTHING', (aid,))
        conn.execute('INSERT INTO canca.nodes VALUES (%s) ON CONFLICT DO NOTHING', (nid,))
        conn.execute('INSERT INTO canca.runs VALUES (%s,%s,%s) ON CONFLICT DO NOTHING', (aid, rid, nid))
        conn.execute('''INSERT INTO canca.imports (bundle_id,assessment_id,run_id,node_id,bundle_sha256,
            receipt_sha256,projection_sha256,imported_at_utc,artifact_count) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
            (bid, aid, rid, nid, projection['bundle_sha256'], projection['receipt_sha256'], fingerprint,
             projection['imported_at_utc'], len(projection['artifacts'])))
        for item in projection['artifacts']:
            conn.execute('INSERT INTO canca.artifacts VALUES (%s,%s,%s,%s,%s)',
                         (bid, item['path'], item['role'], item['sha256'], item['size_bytes']))
    return {'status': 'indexed', 'bundle_id': bid, 'artifact_count': len(projection['artifacts'])}


def show_import(conn, bundle_id):
    guard_connection(conn)
    require(isinstance(bundle_id, str) and re.fullmatch(r'bnd-[0-9a-f]{20}', bundle_id), 'input_invalid')
    with conn.transaction():
        timeout(conn)
        schema_check(conn)
        row = conn.execute('SELECT assessment_id,run_id,node_id,bundle_sha256,receipt_sha256,artifact_count FROM canca.imports WHERE bundle_id=%s', (bundle_id,)).fetchone()
        if row is None:
            return {'status': 'not_found', 'bundle_id': bundle_id}
        artifacts = conn.execute('SELECT path,role,sha256,size_bytes FROM canca.artifacts WHERE bundle_id=%s ORDER BY path', (bundle_id,)).fetchall()
    return {'status': 'found', 'bundle_id': bundle_id, **dict(zip(IDENTITY, row[:3])),
            'bundle_sha256': row[3], 'receipt_sha256': row[4], 'artifact_count': row[5],
            'artifacts': [dict(zip(('path','role','sha256','size_bytes'), item)) for item in artifacts]}


def open_connection():
    require(all(os.environ.get(key) for key in ('PGHOST', 'PGDATABASE', 'PGUSER')), 'database_config_required')
    require(not os.environ.get('PGSERVICE'), 'database_config_required')
    try:
        import psycopg
    except ImportError:
        raise PersistenceError('database_driver_required') from None
    host = os.environ['PGHOST']
    local = host in {'localhost', '127.0.0.1', '::1'} or host.startswith('/')
    addr = os.environ.get('PGHOSTADDR')
    if addr:
        try:
            local = local and ipaddress.ip_address(addr).is_loopback
        except ValueError:
            local = False
    kwargs = dict(host=host, dbname=os.environ['PGDATABASE'], user=os.environ['PGUSER'], connect_timeout=5, autocommit=True)
    if not local:
        kwargs['sslmode'] = 'verify-full'
    return psycopg.connect('', **kwargs)


def cli(argv=None):
    parser = argparse.ArgumentParser(description='Cancã PostgreSQL foundation v' + VERSION)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('migrate')
    index = commands.add_parser('index-import')
    index.add_argument('--store-dir', required=True)
    index.add_argument('--import-dir', required=True)
    show = commands.add_parser('show-import')
    show.add_argument('--bundle-id', required=True)
    args = parser.parse_args(argv)
    try:
        projection = prepare_import(args.store_dir, args.import_dir) if args.command == 'index-import' else None
        with open_connection() as conn:
            result = migrate(conn) if args.command == 'migrate' else index_import(conn, projection) if projection else show_import(conn, args.bundle_id)
        print(json.dumps(dict(result, persistence_version=VERSION)))
        return 0
    except Exception as exc:
        code = str(exc) if isinstance(exc, PersistenceError) and str(exc) in ERRORS else 'database_failed'
        print(json.dumps({'status': 'failed', 'error_code': code, 'persistence_version': VERSION}))
        return 2


if __name__ == '__main__':
    raise SystemExit(cli())
