#!/usr/bin/env python3
"""Explicit offline evaluations and immutable findings from verified bundle sources."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import P01_Asset_Registry as assets
pg = assets.pg
VERSION = '0.6.4'
CATALOG_PATH = Path(__file__).with_name('P01_Finding_Rules.json')
RULES = ('WIN-AD-001', 'WIN-FW-001')
RESULTS = {'finding','no_finding','insufficient_evidence','not_applicable','not_supported'}
ERRORS = assets.ERRORS | {'finding_input_invalid','assets_required','finding_projection_conflict'}


def catalog():
    raw = CATALOG_PATH.read_bytes()
    doc = pg.read_json(raw)
    pg.require(set(doc) == {'ruleset_name','ruleset_version','input_contract','rules'}
               and doc['ruleset_version'] == VERSION and doc['input_contract'] == 'inventoried_credentialed_winrm'
               and isinstance(doc['rules'],list) and tuple(r['id'] for r in doc['rules']) == RULES
               and all(r['version'] == VERSION and r['enabled'] is True and r['severity'] == 'High'
                       for r in doc['rules']), 'finding_input_invalid')
    return doc, pg.digest(raw)


def successful_section(enrichment, name):
    rows = enrichment.get('collection_sections')
    if not isinstance(rows,list):
        return False
    selected = [r for r in rows if isinstance(r,dict) and r.get('section') == name]
    return len(selected) == 1 and selected[0].get('success') is True \
        and type(selected[0].get('status_code')) is int and selected[0]['status_code'] == 0


def evaluate(doc, rule_id):
    """A negative result needs positive evidence of coverage; no raw errors retained."""
    action, enrichment, auth, _ = assets.resolver._unwrap_credentialed(doc)
    if action.get('protocol') != 'winrm':
        return 'not_supported', {}, []
    refs = ['/authentication/success','/enrichment/collection_status','/enrichment/collection_sections']
    if auth.get('success') is not True or enrichment.get('collection_status') not in {
            'collected','collected_with_section_failures'}:
        return 'insufficient_evidence', {}, refs
    security = enrichment.get('security')
    if not isinstance(security,dict):
        return 'insufficient_evidence', {}, refs
    if rule_id == 'WIN-FW-001':
        refs += ['/enrichment/security/firewall_profiles']
        profiles = security.get('firewall_profiles')
        if not successful_section(enrichment,'firewall') or not isinstance(profiles,list) or len(profiles) != 3:
            return 'insufficient_evidence', {}, refs
        values = {}
        for row in profiles:
            if not isinstance(row,dict) or not isinstance(row.get('name'),str) or type(row.get('enabled')) is not bool:
                return 'insufficient_evidence', {}, refs
            name = row['name'].lower()
            if name not in {'domain','private','public'} or name in values:
                return 'insufficient_evidence', {}, refs
            values[name] = row['enabled']
        disabled = sorted(name for name, enabled in values.items() if not enabled)
        return ('finding', {'disabled_profiles':disabled}, refs) if disabled else ('no_finding',{},refs)
    refs += ['/enrichment/identity','/enrichment/security/secure_channel_checked',
             '/enrichment/security/secure_channel_healthy']
    identity = enrichment.get('identity')
    if not successful_section(enrichment,'identity') or not isinstance(identity,dict) \
            or type(identity.get('part_of_domain')) is not bool or type(identity.get('domain_role')) is not int:
        return 'insufficient_evidence', {}, refs
    role = identity['domain_role']
    member = identity['part_of_domain']
    if (not member and role in (0,2)) or (member and role in (4,5)):
        return 'not_applicable', {}, refs
    if not member or role not in (1,3) or not successful_section(enrichment,'secure_channel') \
            or security.get('secure_channel_checked') is not True \
            or type(security.get('secure_channel_healthy')) is not bool:
        return 'insufficient_evidence', {}, refs
    return ('no_finding',{},refs) if security['secure_channel_healthy'] else \
        ('finding',{'secure_channel_healthy':False},refs)


def source_observation(projection, path):
    ordinals = [o['ordinal'] for o in projection['observations'] if any(r['path'] == path for r in o['source_refs'])]
    return (ordinals[0], 'unique_observation') if len(ordinals) == 1 else \
        (None, 'ambiguous' if ordinals else 'unresolved')


def prepare_findings(store, import_dir):
    """Read-only and offline. Verify all bytes before the caller opens PostgreSQL."""
    try:
        projection = assets.prepare_assets(store,import_dir)
        imported = projection['import']
        selected = [r for r in imported['artifacts'] if r['role'] == 'credentialed_evidence']
        pg.require(len(selected) <= 1000 and sum(r['size_bytes'] for r in selected) <= 64*1024**2
                   and all(r['size_bytes'] <= 16*1024**2 for r in selected), 'finding_input_invalid')
        directory = Path(import_dir).resolve()
        with pg.owned(directory,'receipt/import-receipt.json').open('rb') as source:
            receipt_raw = source.read(65537)
        pg.require(len(receipt_raw) <= 65536 and pg.digest(receipt_raw) == imported['receipt_sha256'], 'receipt_integrity_failed')
        raw_path = pg.owned(directory,pg.read_json(receipt_raw)['raw_bundle'])
        evaluations = []
        with tempfile.TemporaryDirectory(prefix='canca-findings-') as temp:
            snapshot = Path(temp)/'snapshot.p01bundle'
            hasher = hashlib.sha256(); total = 0
            with raw_path.open('rb') as source, snapshot.open('xb') as target:
                while chunk := source.read(1024**2):
                    total += len(chunk); pg.require(total <= 1024**3,'finding_input_invalid')
                    target.write(chunk); hasher.update(chunk)
            pg.require(hasher.hexdigest() == imported['bundle_sha256'],'bundle_integrity_failed')
            with zipfile.ZipFile(snapshot) as archive:
                for ref in selected:
                    raw = archive.read(ref['path'])
                    pg.require(len(raw) == ref['size_bytes'] and pg.digest(raw) == ref['sha256'],'bundle_integrity_failed')
                    doc = pg.read_json(raw)
                    ordinal, state = source_observation(projection,ref['path'])
                    for rule in RULES:
                        result, evidence, refs = evaluate(doc,rule)
                        evaluations.append(dict(ordinal=len(evaluations),source_ref=ref,rule_id=rule,result=result,
                                                observation_ordinal=ordinal,link_state=state,evidence_refs=refs,evidence=evidence))
        rules, sha = catalog()
        result = dict(policy_version=VERSION,engine_sha256=pg.digest(Path(__file__).read_bytes()),
                      catalog_sha256=sha,catalog=rules,assets=projection,evaluations=evaluations)
        validate_projection(result)
        return result
    except pg.PersistenceError:
        raise
    except Exception:
        raise pg.PersistenceError('finding_input_invalid') from None


def validate_projection(doc):
    try:
        rules, sha = catalog()
        pg.require(isinstance(doc,dict) and set(doc) == {'policy_version','engine_sha256','catalog_sha256','catalog','assets','evaluations'}
                   and doc['policy_version'] == VERSION and doc['engine_sha256'] == pg.digest(Path(__file__).read_bytes())
                   and doc['catalog_sha256'] == sha and doc['catalog'] == rules,'finding_input_invalid')
        assets.validate_projection(doc['assets'])
        refs = [r for r in doc['assets']['import']['artifacts'] if r['role'] == 'credentialed_evidence']
        rows = doc['evaluations']
        pg.require(isinstance(rows,list) and len(refs) <= 1000 and len(rows) == len(refs)*len(RULES),'finding_input_invalid')
        for i, (ref, rule) in enumerate((ref,rule) for ref in refs for rule in RULES):
            row = rows[i]
            pg.require(isinstance(row,dict) and set(row) == {'ordinal','source_ref','rule_id','result','observation_ordinal',
                        'link_state','evidence_refs','evidence'} and type(row['ordinal']) is int and row['ordinal'] == i
                       and row['source_ref'] == ref and row['rule_id'] == rule and row['result'] in RESULTS
                       and (row['observation_ordinal'],row['link_state']) == source_observation(doc['assets'],ref['path'])
                       and (row['observation_ordinal'] is None or type(row['observation_ordinal']) is int)
                       and isinstance(row['evidence_refs'],list) and len(row['evidence_refs']) <= 6
                       and len(set(row['evidence_refs'])) == len(row['evidence_refs'])
                       and all(isinstance(r,str) and r in {'/authentication/success','/enrichment/collection_status',
                           '/enrichment/collection_sections','/enrichment/security/firewall_profiles','/enrichment/identity',
                           '/enrichment/security/secure_channel_checked','/enrichment/security/secure_channel_healthy'}
                               for r in row['evidence_refs']), 'finding_input_invalid')
            if row['result'] != 'finding':
                pg.require(row['evidence'] == {},'finding_input_invalid')
            elif rule == 'WIN-AD-001':
                pg.require(isinstance(row['evidence'],dict) and set(row['evidence']) == {'secure_channel_healthy'}
                           and row['evidence']['secure_channel_healthy'] is False,'finding_input_invalid')
            else:
                evidence = row['evidence']
                pg.require(isinstance(evidence,dict) and set(evidence) == {'disabled_profiles'}
                           and isinstance(evidence['disabled_profiles'],list) and evidence['disabled_profiles']
                           and evidence['disabled_profiles'] == sorted(set(evidence['disabled_profiles']))
                           and set(evidence['disabled_profiles']) <= {'domain','private','public'},'finding_input_invalid')
    except pg.PersistenceError:
        raise
    except Exception:
        raise pg.PersistenceError('finding_input_invalid') from None


def project_import(conn, projection):
    """Trusted internal API; prepare_findings establishes source provenance."""
    validate_projection(projection); pg.guard_connection(conn)
    asset_projection = projection['assets']; imported = asset_projection['import']
    bid, aid = imported['bundle_id'], imported['assessment_id']
    sha = pg.digest(pg.canonical(projection)); analysis_id = 'ana-'+sha[:32]
    import_sha = pg.digest(pg.canonical(imported)); asset_sha = pg.digest(pg.canonical(asset_projection))
    rows = projection['evaluations']; count = sum(r['result']=='finding' for r in rows)
    with conn.transaction():
        conn.execute('SET TRANSACTION ISOLATION LEVEL READ COMMITTED'); pg.timeout(conn); pg.schema_check(conn,minimum=4)
        conn.execute('SELECT pg_advisory_xact_lock(%s)',(pg.lock_key('findings:'+bid),))
        indexed = conn.execute('SELECT projection_sha256 FROM canca.imports WHERE bundle_id=%s',(bid,)).fetchone()
        pg.require(indexed is not None,'import_required'); pg.require(indexed[0] == import_sha,'import_conflict')
        projected = conn.execute('SELECT projection_sha256 FROM canca.asset_imports WHERE bundle_id=%s',(bid,)).fetchone()
        pg.require(projected is not None,'assets_required'); pg.require(projected[0] == asset_sha,'asset_projection_conflict')
        old = conn.execute('SELECT projection_sha256 FROM canca.finding_analyses WHERE bundle_id=%s AND policy_version=%s',(bid,VERSION)).fetchone()
        if old:
            pg.require(old[0] == sha,'finding_projection_conflict')
            return dict(status='already_projected',analysis_id=analysis_id,bundle_id=bid,evaluation_count=len(rows),finding_count=count)
        conn.execute('''INSERT INTO canca.finding_analyses (analysis_id,bundle_id,assessment_id,policy_version,projection_sha256,
            import_projection_sha256,asset_projection_sha256,engine_sha256,catalog_sha256,catalog,evaluation_count,finding_count)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s)''',
            (analysis_id,bid,aid,VERSION,sha,import_sha,asset_sha,projection['engine_sha256'],projection['catalog_sha256'],
             json.dumps(projection['catalog']),len(rows),count))
        for row in rows:
            conn.execute('''INSERT INTO canca.finding_evaluations (analysis_id,ordinal,bundle_id,source_path,source_sha256,rule_id,
                result,observation_ordinal,link_state,evidence_refs) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)''',
                (analysis_id,row['ordinal'],bid,row['source_ref']['path'],row['source_ref']['sha256'],row['rule_id'],row['result'],
                 row['observation_ordinal'],row['link_state'],json.dumps(row['evidence_refs'])))
            if row['result'] == 'finding':
                finding_id = 'fnd-'+pg.digest(pg.canonical({'analysis_id':analysis_id,'ordinal':row['ordinal']}))[:32]
                conn.execute('INSERT INTO canca.findings (finding_id,analysis_id,evaluation_ordinal,evidence) VALUES (%s,%s,%s,%s::jsonb)',
                             (finding_id,analysis_id,row['ordinal'],json.dumps(row['evidence'])))
    return dict(status='projected',analysis_id=analysis_id,bundle_id=bid,evaluation_count=len(rows),finding_count=count)


def query_valid(bundle_id,after_ordinal,limit):
    pg.require(isinstance(bundle_id,str) and re.fullmatch(r'bnd-[0-9a-f]{20}',bundle_id)
               and type(after_ordinal) is int and -1 <= after_ordinal <= 1999
               and type(limit) is int and 1 <= limit <= 100,'finding_input_invalid')


def show_import(conn,bundle_id,after_ordinal=-1,limit=100):
    query_valid(bundle_id,after_ordinal,limit); pg.guard_connection(conn)
    with conn.transaction():
        conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY'); pg.timeout(conn); pg.schema_check(conn,minimum=4)
        columns = ('analysis_id','assessment_id','policy_version','engine_sha256','catalog_sha256','catalog','evaluation_count','finding_count')
        row = conn.execute('SELECT '+','.join(columns)+' FROM canca.finding_analyses WHERE bundle_id=%s AND policy_version=%s',(bundle_id,VERSION)).fetchone()
        if row is None:
            return dict(status='not_found',bundle_id=bundle_id)
        header = dict(zip(columns,row))
        fields = ('ordinal','source_path','source_sha256','rule_id','result','observation_ordinal','link_state','evidence_refs',
                  'asset_id','asset_decision','asset_reason_code','finding_id','finding_status','evidence')
        records = conn.execute('''SELECT e.ordinal,e.source_path,e.source_sha256,e.rule_id,e.result,e.observation_ordinal,
            e.link_state,e.evidence_refs,o.asset_id,o.decision,o.reason_code,f.finding_id,f.status,f.evidence
            FROM canca.finding_evaluations e LEFT JOIN canca.asset_observations o
            ON o.bundle_id=e.bundle_id AND o.ordinal=e.observation_ordinal
            LEFT JOIN canca.findings f ON f.analysis_id=e.analysis_id AND f.evaluation_ordinal=e.ordinal
            WHERE e.analysis_id=%s AND e.ordinal>%s ORDER BY e.ordinal LIMIT %s''',
            (header['analysis_id'],after_ordinal,limit+1)).fetchall()
    return dict(header,status='found',bundle_id=bundle_id,evaluations=[dict(zip(fields,r)) for r in records[:limit]],
                has_more=len(records)>limit,next_after_ordinal=records[min(len(records),limit)-1][0] if records else after_ordinal)


def cli(argv=None):
    parser = argparse.ArgumentParser(description='Cancã immutable findings v'+VERSION)
    commands = parser.add_subparsers(dest='command',required=True)
    project = commands.add_parser('project-import'); project.add_argument('--store-dir',required=True); project.add_argument('--import-dir',required=True)
    show = commands.add_parser('show-import'); show.add_argument('--bundle-id',required=True)
    show.add_argument('--after-ordinal',type=int,default=-1); show.add_argument('--limit',type=int,default=100)
    args = parser.parse_args(argv)
    try:
        projection = prepare_findings(args.store_dir,args.import_dir) if args.command == 'project-import' else None
        if args.command == 'show-import':
            query_valid(args.bundle_id,args.after_ordinal,args.limit)
        with pg.open_connection() as conn:
            result = project_import(conn,projection) if projection else show_import(conn,args.bundle_id,args.after_ordinal,args.limit)
        print(json.dumps(dict(result,findings_version=VERSION))); return 0
    except Exception as exc:
        code = str(exc) if isinstance(exc,pg.PersistenceError) and str(exc) in ERRORS else 'database_failed'
        print(json.dumps(dict(status='failed',error_code=code,findings_version=VERSION))); return 2


if __name__ == '__main__':
    raise SystemExit(cli())
