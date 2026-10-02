#!/usr/bin/env python3
"""Assessment-scoped identity from verified evidence, with conservative association."""
from __future__ import annotations
import argparse
import base64
from collections import Counter
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
import tempfile
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'persistence'))
sys.path.insert(0, str(ROOT / 'asset_resolver'))
import P01_PostgreSQL as pg
import P01_Asset_Resolver as resolver

VERSION = '0.6.3'
STRONG = {'serial_number', 'ssh_host_key_sha256'}
KINDS = STRONG | {'fqdn', 'hostname', 'ip', 'mac'}
ERRORS = pg.ERRORS | {'asset_input_invalid', 'import_required', 'import_conflict', 'asset_projection_conflict'}


def fqdn(value):
    if not isinstance(value, str):
        return None
    value = value.strip().rstrip('.').lower()
    if len(value) > 253 or '.' not in value:
        return None
    labels = value.split('.')
    if all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels):
        return value
    return None


def serial(value):
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    if value not in resolver.GENERIC_SERIALS and re.fullmatch(r'[a-z0-9][a-z0-9 ._:/-]{0,127}', value):
        return value
    return None


def fingerprint(value):
    if not isinstance(value, str) or not value.startswith('SHA256:'):
        return None
    encoded = value[7:].rstrip('=')
    try:
        raw = base64.b64decode(encoded + '=' * (-len(encoded) % 4), validate=True)
        if len(raw) == 32 and base64.b64encode(raw).decode().rstrip('=') == encoded:
            return 'SHA256:' + encoded
    except Exception:
        pass
    return None


def normalized(kind, value):
    if kind == 'fqdn':
        return fqdn(value)
    if kind == 'serial_number':
        return serial(value)
    if kind == 'ssh_host_key_sha256':
        return fingerprint(value)
    if not isinstance(value, str):
        return None
    if kind == 'ip':
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None
    if kind == 'mac':
        value = value.lower()
        return value if re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', value) else None
    if kind == 'hostname':
        value = value.strip().lower()
        return value if re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,127}', value) else None
    return None


def observation(asset, ordinal, artifacts, docs, duplicate_ids, ambiguous_ids):
    signals = {}
    def add(kind, value, qualified, path):
        value = normalized(kind, value)
        if value:
            signals.setdefault((kind, value, qualified), set()).add(path)
    source_hashes = {item['sha256'] for item in asset['sources']}
    refs = [dict(item) for item in artifacts if item['sha256'] in source_hashes
            and item['role'] != 'asset_resolver']
    pg.require(source_hashes <= {item['sha256'] for item in refs}, 'asset_input_invalid')
    for ref in refs:
        doc = docs[ref['path']]
        if ref['role'] == 'credentialed_evidence':
            _, enrichment, authentication, _ = resolver._unwrap_credentialed(doc)
            if authentication.get('success') is True and enrichment.get('collection_status') == 'collected':
                identity = enrichment.get('identity', {})
                add('serial_number', identity.get('serial_number'), True, ref['path'])
                key = authentication.get('server_host_key', {})
                if isinstance(key, dict):
                    add('ssh_host_key_sha256', key.get('fingerprint_sha256'), True, ref['path'])
                add('fqdn', identity.get('fqdn'), True, ref['path'])
                # A Linux hostname may carry the actual collected FQDN.
                add('fqdn', identity.get('hostname'), True, ref['path'])
        elif ref['role'] == 'network_discovery':
            for row in doc.get('assets', []):
                if row.get('ip') in asset['addresses']:
                    add('ip', row.get('ip'), False, ref['path'])
                    add('hostname', row.get('hostname'), False, ref['path'])
                    add('fqdn', row.get('hostname'), False, ref['path'])
                    add('mac', resolver.norm_mac(row.get('mac')), False, ref['path'])
    values = [dict(kind=kind, value=value, qualified=qualified, sources=sorted(paths))
              for (kind, value, qualified), paths in sorted(signals.items())]
    qualified = {kind: {s['value'] for s in values if s['kind'] == kind and s['qualified']}
                 for kind in STRONG | {'fqdn'}}
    local_review = bool(asset['conflicts'] or asset['asset_id'] in duplicate_ids
                        or asset['asset_id'] in ambiguous_ids or any(len(v) > 1 for v in qualified.values()))
    pg.require(len(values) <= 64, 'asset_input_invalid')
    return dict(ordinal=ordinal, source_asset_id=asset['asset_id'], local_review=local_review,
                signals=values, source_refs=sorted(refs, key=lambda item: item['path']))


def prepare_assets(store, import_dir):
    """Validate source before connection; replay only in a private temporary directory."""
    try:
        imported = pg.prepare_import(store, import_dir)
        directory = Path(import_dir).resolve()
        with pg.owned(directory, 'receipt/import-receipt.json').open('rb') as source:
            raw_receipt = source.read(65537)
        pg.require(len(raw_receipt) <= 65536 and pg.digest(raw_receipt) == imported['receipt_sha256'], 'receipt_integrity_failed')
        receipt = pg.read_json(raw_receipt)
        raw_path = pg.owned(directory, receipt['raw_bundle'])
        with tempfile.TemporaryDirectory(prefix='canca-assets-') as temp:
            base = Path(temp)
            snapshot = base / 'snapshot.p01bundle'
            hasher = hashlib.sha256()
            with raw_path.open('rb') as source, snapshot.open('xb') as target:
                total = 0
                while chunk := source.read(1024**2):
                    total += len(chunk)
                    pg.require(total <= 1024**3, 'asset_input_invalid')
                    target.write(chunk)
                    hasher.update(chunk)
            pg.require(hasher.hexdigest() == imported['bundle_sha256'], 'bundle_integrity_failed')
            docs, roles = {}, {}
            selected = [a for a in imported['artifacts'] if a['role'] != 'asset_resolver']
            pg.require(sum(a['size_bytes'] for a in selected) <= 64 * 1024**2, 'asset_input_invalid')
            with zipfile.ZipFile(snapshot) as archive:
                for item in selected:
                    pg.require(item['size_bytes'] <= 16 * 1024**2, 'asset_input_invalid')
                    raw = archive.read(item['path'])
                    pg.require(len(raw) == item['size_bytes'] and pg.digest(raw) == item['sha256'], 'bundle_integrity_failed')
                    path = base.joinpath(*pg.safe_relative(item['path']).parts)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(raw)
                    docs[item['path']] = pg.read_json(raw)
                    roles.setdefault(item['role'], []).append(path)
            pg.require(len(roles.get('network_discovery', [])) == 1
                       and len(roles.get('assessment_manifest', [])) <= 1, 'asset_input_invalid')
            network_doc = docs[next(a['path'] for a in selected if a['role'] == 'network_discovery')]
            pg.require(isinstance(network_doc.get('assets'), list) and len(network_doc['assets']) <= 10000
                       and len(roles.get('credentialed_evidence', [])) <= 10000, 'asset_input_invalid')
            # No write_output, no existing processed/edge resolver decision is trusted.
            result = resolver.resolve(roles['network_discovery'][0], roles.get('credentialed_evidence', []),
                                      next(iter(roles.get('assessment_manifest', [])), None))
            pg.require(len(result['assets']) <= 10000, 'asset_input_invalid')
            duplicate_ids = {value for value, count in Counter(a['asset_id'] for a in result['assets']).items() if count > 1}
            ambiguous_ids = {item['new_asset_id'] for item in result['ambiguous_correlations']}
            observations = [observation(a, i, selected, docs, duplicate_ids, ambiguous_ids)
                            for i, a in enumerate(result['assets'])]
        return {'policy_version': VERSION, 'resolver_version': resolver.VERSION,
                'import': imported, 'observations': observations}
    except pg.PersistenceError:
        raise
    except Exception:
        raise pg.PersistenceError('asset_input_invalid') from None


def _validate_projection(doc):
    pg.require(isinstance(doc, dict) and set(doc) == {'policy_version','resolver_version','import','observations'}
               and doc['policy_version'] == VERSION and doc['resolver_version'] == resolver.VERSION, 'asset_input_invalid')
    pg.require(isinstance(doc['import'], dict) and set(doc['import']) == set(pg.IDENTITY) | {
        'bundle_id','bundle_sha256','receipt_sha256','imported_at_utc','artifacts'}, 'asset_input_invalid')
    pg.validate_projection(doc['import'])
    pg.require(isinstance(doc['observations'], list) and len(doc['observations']) <= 10000, 'asset_input_invalid')
    known_refs = {item['path']: item for item in doc['import']['artifacts']}
    for i, obs in enumerate(doc['observations']):
        pg.require(isinstance(obs, dict) and set(obs) == {'ordinal','source_asset_id','local_review','signals','source_refs'}
                   and type(obs['ordinal']) is int and obs['ordinal'] == i and type(obs['local_review']) is bool
                   and isinstance(obs['source_asset_id'], str) and re.fullmatch(r'ast-[0-9a-f]{16}', obs['source_asset_id']), 'asset_input_invalid')
        pg.require(isinstance(obs['source_refs'], list) and obs['source_refs']
                   and obs['source_refs'] == sorted(obs['source_refs'], key=lambda item: item['path']), 'asset_input_invalid')
        refs = {item['path']: item for item in obs['source_refs']}
        pg.require(len(refs) == len(obs['source_refs']) and all(item == known_refs.get(path) for path, item in refs.items()), 'asset_input_invalid')
        pg.require(isinstance(obs['signals'], list) and len(obs['signals']) <= 64, 'asset_input_invalid')
        seen = set()
        for signal in obs['signals']:
            pg.require(isinstance(signal, dict) and set(signal) == {'kind','value','qualified','sources'}
                       and isinstance(signal['kind'], str) and signal['kind'] in KINDS
                       and isinstance(signal['value'], str) and normalized(signal['kind'], signal['value']) == signal['value']
                       and type(signal['qualified']) is bool and isinstance(signal['sources'], list)
                       and signal['sources'] and signal['sources'] == sorted(set(signal['sources']))
                       and all(path in refs for path in signal['sources']), 'asset_input_invalid')
            pg.require(not signal['qualified'] or signal['kind'] in STRONG | {'fqdn'}
                       and all(refs[path]['role'] == 'credentialed_evidence' for path in signal['sources']), 'asset_input_invalid')
            key = (signal['kind'],signal['value'],signal['qualified'])
            pg.require(key not in seen, 'asset_input_invalid')
            seen.add(key)
        pg.require(obs['signals'] == sorted(obs['signals'], key=lambda s:(s['kind'],s['value'],s['qualified'])), 'asset_input_invalid')


def validate_projection(doc):
    try:
        _validate_projection(doc)
    except pg.PersistenceError:
        raise
    except Exception:
        raise pg.PersistenceError('asset_input_invalid') from None


def qualified(signals):
    return {(s['kind'], s['value']) for s in signals if s['qualified']}


def choose(conn, aid, obs):
    if obs['local_review']:
        return None, 'local_conflict', [], False
    signals = obs['signals']
    if not signals:
        return None, 'insufficient_identity', [], False
    conditions = ' OR '.join('(kind=%s AND value=%s)' for _ in signals)
    params = [aid]
    for signal in signals:
        params.extend((signal['kind'],signal['value']))
    rows = conn.execute('SELECT DISTINCT asset_id FROM canca.asset_signals WHERE assessment_id=%s '
                        'AND eligible AND (' + conditions + ') ORDER BY asset_id LIMIT 101', params).fetchall()
    candidates = [row[0] for row in rows[:100]]
    if len(rows) > 100:
        return None, 'candidate_bound_exceeded', candidates, True
    current = qualified(signals)
    if not candidates:
        kinds = {kind for kind, _ in current}
        sufficient = bool(kinds & STRONG) and len(kinds) >= 2
        return None, 'new_identity' if sufficient else 'insufficient_identity', [], False
    eligible, strong_conflict, history_bound = [], False, False
    for candidate in candidates:
        previous = conn.execute('SELECT kind,value FROM canca.asset_signals WHERE assessment_id=%s '
                                'AND asset_id=%s AND eligible AND qualified', (aid,candidate)).fetchall()
        old = set(previous)
        conflict = any({value for kind, value in current if kind == category}
                       and {value for kind, value in old if kind == category}
                       and not ({value for kind, value in current if kind == category}
                                & {value for kind, value in old if kind == category}) for category in STRONG)
        strong_conflict |= conflict
        if conflict:
            continue
        history = conn.execute("SELECT signals FROM canca.asset_observations WHERE assessment_id=%s AND asset_id=%s "
                               "AND decision IN ('new_asset','linked') ORDER BY bundle_id,ordinal LIMIT 101", (aid,candidate)).fetchall()
        if len(history) > 100:
            history_bound = True
            continue
        for row in history:
            match = current & qualified(row[0])
            kinds = {kind for kind, _ in match}
            if kinds & STRONG and len(kinds) >= 2:
                eligible.append(candidate)
                break
    if history_bound:
        return None, 'history_bound_exceeded', candidates, False
    # Other candidates (including a conflict) keep this association under review.
    if len(candidates) == 1 and len(eligible) == 1:
        return eligible[0], 'corroborated_identity', candidates, False
    reason = 'multiple_candidates' if len(candidates) > 1 else 'strong_conflict' if strong_conflict else 'uncorroborated_candidate'
    return None, reason, candidates, False


def project_import(conn, projection):
    """Trusted internal API: prepare_assets establishes provenance before connecting."""
    validate_projection(projection)
    pg.guard_connection(conn)
    imported = projection['import']
    bid, aid = imported['bundle_id'], imported['assessment_id']
    digest = pg.digest(pg.canonical(projection))
    with conn.transaction():
        conn.execute('SET TRANSACTION ISOLATION LEVEL READ COMMITTED')
        pg.timeout(conn)
        pg.schema_check(conn, minimum=3)
        conn.execute('SELECT pg_advisory_xact_lock(%s)', (pg.lock_key('assets:' + aid),))
        indexed = conn.execute('SELECT projection_sha256 FROM canca.imports WHERE bundle_id=%s', (bid,)).fetchone()
        pg.require(indexed is not None, 'import_required')
        pg.require(indexed[0] == pg.digest(pg.canonical(imported)), 'import_conflict')
        existing = conn.execute('SELECT projection_sha256 FROM canca.asset_imports WHERE bundle_id=%s', (bid,)).fetchone()
        if existing:
            pg.require(existing[0] == digest, 'asset_projection_conflict')
            return {'status':'already_projected','bundle_id':bid,'observation_count':len(projection['observations'])}
        conn.execute('INSERT INTO canca.asset_imports (bundle_id,assessment_id,projection_sha256,policy_version,observation_count) '
                     'VALUES (%s,%s,%s,%s,%s)', (bid,aid,digest,VERSION,len(projection['observations'])))
        decisions = Counter()
        for obs in projection['observations']:
            asset_id, reason, candidates, truncated = choose(conn, aid, obs)
            decision = 'linked' if asset_id else 'review_required' if candidates or obs['local_review'] else 'new_asset'
            if asset_id is None:
                asset_id = 'cas-' + uuid.uuid4().hex
                conn.execute('INSERT INTO canca.assets (assessment_id,asset_id) VALUES (%s,%s)', (aid,asset_id))
            conn.execute('INSERT INTO canca.asset_observations (bundle_id,ordinal,assessment_id,asset_id,source_asset_id,'
                         'decision,reason_code,candidates,candidates_truncated,signals,source_refs) '
                         'VALUES (%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s::jsonb,%s::jsonb)',
                         (bid,obs['ordinal'],aid,asset_id,obs['source_asset_id'],decision,reason,json.dumps(candidates),
                          truncated,json.dumps(obs['signals']),json.dumps(obs['source_refs'])))
            for signal in obs['signals']:
                conn.execute('INSERT INTO canca.asset_signals (assessment_id,asset_id,kind,value,qualified,eligible) '
                             'VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING',
                             (aid,asset_id,signal['kind'],signal['value'],signal['qualified'],decision != 'review_required'))
            decisions[decision] += 1
    return {'status':'projected','bundle_id':bid,'observation_count':len(projection['observations']),'decisions':dict(decisions)}


def show_import(conn, bundle_id, after_ordinal=-1, limit=100):
    pg.require(isinstance(bundle_id, str) and re.fullmatch(r'bnd-[0-9a-f]{20}', bundle_id)
               and type(after_ordinal) is int and -1 <= after_ordinal <= 9999
               and type(limit) is int and 1 <= limit <= 100, 'asset_input_invalid')
    pg.guard_connection(conn)
    with conn.transaction():
        # Guard must run before beginning the explicit transaction.
        conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        pg.timeout(conn)
        pg.schema_check(conn, minimum=3)
        imported = conn.execute('SELECT assessment_id,observation_count FROM canca.asset_imports WHERE bundle_id=%s', (bundle_id,)).fetchone()
        if imported is None:
            return {'status':'not_found','bundle_id':bundle_id}
        columns = ('ordinal','asset_id','source_asset_id','decision','reason_code','candidates','candidates_truncated','signals','source_refs')
        rows = conn.execute('SELECT ' + ','.join(columns) + ' FROM canca.asset_observations WHERE bundle_id=%s '
                            'AND ordinal>%s ORDER BY ordinal LIMIT %s', (bundle_id,after_ordinal,limit+1)).fetchall()
    return {'status':'found','bundle_id':bundle_id,'assessment_id':imported[0],'observation_count':imported[1],
            'observations':[dict(zip(columns,row)) for row in rows[:limit]],'has_more':len(rows)>limit,
            'next_after_ordinal':rows[min(len(rows),limit)-1][0] if rows else after_ordinal}


def show_asset(conn, assessment_id, asset_id):
    pg.require(isinstance(assessment_id, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', assessment_id)
               and isinstance(asset_id, str) and re.fullmatch(r'cas-[0-9a-f]{32}', asset_id), 'asset_input_invalid')
    pg.guard_connection(conn)
    with conn.transaction():
        conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        pg.timeout(conn)
        pg.schema_check(conn, minimum=3)
        row = conn.execute('SELECT created_at_utc FROM canca.assets WHERE assessment_id=%s AND asset_id=%s', (assessment_id,asset_id)).fetchone()
        if row is None:
            return {'status':'not_found','assessment_id':assessment_id,'asset_id':asset_id}
        columns = ('kind','value','qualified','eligible')
        signals = conn.execute('SELECT ' + ','.join(columns) + ' FROM canca.asset_signals WHERE assessment_id=%s AND asset_id=%s '
                               'ORDER BY kind,value,qualified,eligible LIMIT 101', (assessment_id,asset_id)).fetchall()
        count = conn.execute('SELECT count(*) FROM canca.asset_observations WHERE assessment_id=%s AND asset_id=%s', (assessment_id,asset_id)).fetchone()[0]
    return {'status':'found','assessment_id':assessment_id,'asset_id':asset_id,'observation_count':count,
            'signals':[dict(zip(columns,s)) for s in signals[:100]],'signals_truncated':len(signals)>100}


def cli(argv=None):
    parser = argparse.ArgumentParser(description='Cancã persistent asset registry v' + VERSION)
    commands = parser.add_subparsers(dest='command', required=True)
    project = commands.add_parser('project-import')
    project.add_argument('--store-dir', required=True)
    project.add_argument('--import-dir', required=True)
    show = commands.add_parser('show-import')
    show.add_argument('--bundle-id', required=True)
    show.add_argument('--after-ordinal', type=int, default=-1)
    show.add_argument('--limit', type=int, default=100)
    asset = commands.add_parser('show-asset')
    asset.add_argument('--assessment-id', required=True)
    asset.add_argument('--asset-id', required=True)
    args = parser.parse_args(argv)
    try:
        projection = prepare_assets(args.store_dir,args.import_dir) if args.command=='project-import' else None
        if args.command == 'show-import':
            pg.require(re.fullmatch(r'bnd-[0-9a-f]{20}', args.bundle_id) and -1 <= args.after_ordinal <= 9999
                       and 1 <= args.limit <= 100, 'asset_input_invalid')
        if args.command == 'show-asset':
            pg.require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', args.assessment_id)
                       and re.fullmatch(r'cas-[0-9a-f]{32}', args.asset_id), 'asset_input_invalid')
        with pg.open_connection() as conn:
            result = project_import(conn,projection) if projection else show_import(conn,args.bundle_id,args.after_ordinal,args.limit) if args.command=='show-import' else show_asset(conn,args.assessment_id,args.asset_id)
        print(json.dumps(dict(result, registry_version=VERSION)))
        return 0
    except Exception as exc:
        code = str(exc) if isinstance(exc, pg.PersistenceError) and str(exc) in ERRORS else 'database_failed'
        print(json.dumps({'status':'failed','error_code':code,'registry_version':VERSION}))
        return 2


if __name__ == '__main__':
    raise SystemExit(cli())
