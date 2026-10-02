#!/usr/bin/env python3
"""Bounded read-only verification of the isolated synthetic PostgreSQL LAB pair."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'persistence'))
import P01_PostgreSQL as pg
import P01_Asset_Registry as assets
import P01_Findings as findings

VERSION = '0.6.7'
ASSESSMENT_ID = 'P01-PG-LAB-R1'
TABLES = ('schema_migrations', 'assessments', 'nodes', 'runs', 'imports', 'artifacts',
          'assessment_events', 'assets', 'asset_imports', 'asset_observations', 'asset_signals',
          'finding_analyses', 'finding_evaluations', 'findings')
MAX_ROWS = 200
MAX_FILES = 100
MAX_FILE_BYTES = 16 * 1024**2
MAX_STORE_BYTES = 64 * 1024**2


class RecoveryError(Exception):
    pass


def require(ok, code='recovery_invalid'):
    if not ok:
        raise RecoveryError(code)


def validate_database(value):
    require(isinstance(value, str) and re.fullmatch(r'[a-z][a-z0-9_]{0,62}', value) is not None)


def inventory(store):
    supplied = Path(store).expanduser().absolute()
    require(supplied.is_dir() and supplied == supplied.resolve() and not supplied.is_symlink())
    result = []
    total = 0
    # Limit directories too; a large empty tree must not bypass the file bound.
    entries = []
    for directory, folders, files in os.walk(supplied, followlinks=False):
        for name in sorted(folders + files):
            path = Path(directory) / name
            require(not path.is_symlink())
            entries.append(path)
            require(len(entries) <= 400, 'recovery_limit')
    for path in sorted(entries):
        if path.is_dir():
            continue
        require(path.is_file())
        sha = hashlib.sha256()
        size = 0
        with path.open('rb') as source:
            while chunk := source.read(1024**2):
                size += len(chunk)
                total += len(chunk)
                require(size <= MAX_FILE_BYTES and total <= MAX_STORE_BYTES, 'recovery_limit')
                sha.update(chunk)
        result.append(dict(path=path.relative_to(supplied).as_posix(), size_bytes=size, sha256=sha.hexdigest()))
        require(len(result) <= MAX_FILES, 'recovery_limit')
    require(result)
    return result


def capture(conn, store, expected_database):
    validate_database(expected_database)
    pg.guard_connection(conn)
    before_inventory = inventory(store)
    with conn.transaction():
        conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        pg.timeout(conn)
        require(conn.execute('SELECT current_database()').fetchone()[0] == expected_database)
        pg.schema_check(conn, minimum=4)
        imported = conn.execute('''SELECT i.bundle_id,i.projection_sha256,a.projection_sha256,f.projection_sha256
            FROM canca.imports i LEFT JOIN canca.asset_imports a USING (bundle_id)
            LEFT JOIN canca.finding_analyses f USING (bundle_id) ORDER BY i.bundle_id LIMIT 3''').fetchall()
        assessment = conn.execute('SELECT assessment_id FROM canca.assessments ORDER BY assessment_id LIMIT 2').fetchall()
        require(assessment == [(ASSESSMENT_ID,)] and len(imported) == 2
                and all(all(isinstance(v, str) for v in row) for row in imported))
        projections = []
        for bid, import_sha, asset_sha, finding_sha in imported:
            directory = Path(store) / 'assessments' / ASSESSMENT_ID / 'imports' / bid
            original = pg.prepare_import(store, directory)
            asset = assets.prepare_assets(store, directory)
            finding = findings.prepare_findings(store, directory)
            actual = [pg.digest(pg.canonical(p)) for p in (original, asset, finding)]
            require(actual == [import_sha, asset_sha, finding_sha], 'recovery_mismatch')
            projections.append(dict(bundle_id=bid, import_sha256=actual[0], asset_sha256=actual[1], finding_sha256=actual[2]))
        fingerprints = {}
        for table in TABLES:
            # Constant allowlist, bounded fetch; SQL rejects oversized row text before returning it.
            rows = conn.execute('SELECT CASE WHEN octet_length(to_jsonb(t)::text)>1048576 THEN NULL '
                                'ELSE to_jsonb(t)::text END FROM canca.' + table +
                                ' t ORDER BY to_jsonb(t)::text LIMIT %s', (MAX_ROWS + 1,)).fetchall()
            require(len(rows) <= MAX_ROWS and all(r[0] is not None for r in rows), 'recovery_limit')
            texts = [r[0] for r in rows]
            require(sum(len(t.encode()) for t in texts) <= 8 * 1024**2, 'recovery_limit')
            fingerprints[table] = dict(row_count=len(texts), sha256=pg.digest(pg.canonical(texts)))
        # The accepted R1 fixture must be fully present, even when the two sides are equally empty.
        require(all(fingerprints[t]['row_count'] == n for t, n in
                    {'imports':2, 'assets':1, 'asset_observations':2, 'finding_analyses':2,
                     'finding_evaluations':4, 'findings':2, 'schema_migrations':4}.items()))
        result = dict(verification_version=VERSION, scope='isolated_synthetic_lab_r1',
                      assessment_id=ASSESSMENT_ID, postgres_major=conn.info.server_version // 10000,
                      table_fingerprints=fingerprints, store_inventory=before_inventory,
                      source_projections=projections, source_bytes_revalidated=True)
    require(inventory(store) == before_inventory, 'recovery_mismatch')
    return result


def save_snapshot(doc, evidence_root):
    root = Path(evidence_root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    folder = root / ('P01-PG-RECOVERY-' + uuid.uuid4().hex[:12])
    folder.mkdir(mode=0o700)
    snapshot = folder / 'snapshot.json'
    raw = pg.canonical(doc)
    for path, content in [(snapshot, raw), (snapshot.with_suffix('.json.sha256'),
            (pg.digest(raw) + '  snapshot.json\n').encode())]:
        with path.open('xb') as target:
            os.chmod(path, 0o600)
            target.write(content)
    return snapshot


def load_snapshot(path):
    supplied = Path(path).expanduser().absolute()
    require(supplied == supplied.resolve() and supplied.is_file() and not supplied.is_symlink())
    sidecar = supplied.with_suffix(supplied.suffix + '.sha256')
    require(sidecar.is_file() and not sidecar.is_symlink())
    with supplied.open('rb') as source:
        raw = source.read(1024**2 + 1)
    with sidecar.open('rb') as source:
        fields = source.read(4097).decode().strip().split()
    require(len(raw) <= 1024**2 and len(fields) == 2 and fields[1] == supplied.name
            and fields[0] == pg.digest(raw))
    doc = pg.read_json(raw)
    require(doc.get('verification_version') == VERSION and doc.get('scope') == 'isolated_synthetic_lab_r1')
    return doc


def verify(conn, store, expected_database, reference):
    expected = load_snapshot(reference)  # Validate reference before querying the database.
    actual = capture(conn, store, expected_database)
    require(actual == expected, 'recovery_mismatch')
    return dict(status='POSTGRESQL LAB RECOVERY PASS', verification_version=VERSION,
                expected_database=expected_database,
                tables_compared=len(TABLES), store_file_count=len(actual['store_inventory']),
                snapshot_sha256=pg.digest(pg.canonical(actual)), source_bytes_revalidated=True,
                database_mutated=False, store_mutated=False)


def cli(argv=None):
    parser = argparse.ArgumentParser(description='Read-only isolated synthetic LAB recovery check')
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('capture', 'verify'):
        command = commands.add_parser(name)
        command.add_argument('--store-dir', required=True)
        command.add_argument('--expected-database', required=True)
        command.add_argument('--evidence-root' if name == 'capture' else '--reference', required=True)
    args = parser.parse_args(argv)
    try:
        validate_database(args.expected_database)
        require(os.environ.get('PGDATABASE') == args.expected_database)
        if args.command == 'verify':
            load_snapshot(args.reference)
        with pg.open_connection() as conn:
            if args.command == 'capture':
                doc = capture(conn, args.store_dir, args.expected_database)
                path = save_snapshot(doc, args.evidence_root)
                result = dict(status='POSTGRESQL LAB SNAPSHOT READY', verification_version=VERSION,
                              expected_database=args.expected_database,
                              snapshot_path=str(path), snapshot_sha256=pg.digest(pg.canonical(doc)),
                              tables_compared=len(TABLES), store_file_count=len(doc['store_inventory']),
                              source_bytes_revalidated=True, database_mutated=False, store_mutated=False)
            else:
                result = verify(conn, args.store_dir, args.expected_database, args.reference)
        print(json.dumps(result)); return 0
    except Exception as error:
        code = str(error) if isinstance(error, (RecoveryError, pg.PersistenceError)) else 'database_failed'
        if code not in pg.ERRORS | {'recovery_invalid', 'recovery_limit', 'recovery_mismatch'}:
            code = 'recovery_invalid'
        print(json.dumps(dict(status='failed', error_code=code, verification_version=VERSION))); return 2


if __name__ == '__main__':
    raise SystemExit(cli())
