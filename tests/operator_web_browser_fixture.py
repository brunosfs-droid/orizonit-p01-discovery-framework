#!/usr/bin/env python3
"""Synthetic browser-only HTTP fixture; never connects to PostgreSQL or store."""
from copy import deepcopy
from contextlib import nullcontext
import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server'))
import P01_Operator_Auth as auth
import P01_Operator_Web as web

PASSWORD = 'Synthetic browser CI passphrase 01!'
ATTACK = '<img src=x onerror="window.cancaInjected=true">'
ANALYSES = ('ana-' + '1' * 32, 'ana-' + '2' * 32)
SCOPE = 'a' * 64
CATALOG = json.loads((Path(__file__).resolve().parents[1]/'persistence/P01_Finding_Rules.json').read_bytes())
for rule in CATALOG['rules']:
    rule['title'] = ATTACK
CATALOG_SHA = 'c' * 64
ENGINE_SHA = 'e' * 64


def read_report(self, token, assessment, *, after_analysis_id='', after_ordinal=-1, limit=100, expected_scope_sha256=None):
    self.auth.require(token, assessment)
    if assessment not in ('LAB-001', 'LAB-MANY', 'LAB-EMPTY'):
        return dict(status='not_found')
    return canonical_page(None, assessment, after_analysis_id, after_ordinal, limit, expected_scope_sha256)


def canonical_page(conn, assessment, after_analysis_id='', after_ordinal=-1, limit=100, expected_scope_sha256=None):
    web.api.report.validate_query(assessment, after_analysis_id, after_ordinal, limit, expected_scope_sha256)
    many = assessment == 'LAB-MANY'; empty = assessment == 'LAB-EMPTY'
    count = 0 if empty else 6 if many else 2
    analyses = tuple('ana-' + str(n + 1) * 32 for n in range(count))
    scope = 'f' * 64 if many else '0' * 64 if empty else SCOPE
    engines = [str(n + 1) * 64 if many else ENGINE_SHA for n in range(count)]
    if expected_scope_sha256 is not None and expected_scope_sha256 != scope:
        raise web.api.report.pg.PersistenceError('report_scope_conflict')
    rows = []
    for ordinal in range(count * 2):
        finding = many or ordinal < 2
        index = ordinal // 2; local_ordinal = ordinal % 2
        rows.append(dict(analysis_id=analyses[index], ordinal=local_ordinal, rule_id=CATALOG['rules'][local_ordinal]['id'],
            result='finding' if finding else 'no_finding', asset_id='asset-synthetic', source_path=ATTACK,
            source_sha256='b'*64, bundle_id='bnd-synthetic-'+str(index+1), link_state='linked',
            asset_decision='new_asset' if index == 0 else 'linked',
            asset_reason_code='exact', observation_ordinal=0, evidence_refs=[ATTACK],
            finding_id='finding-'+str(ordinal) if finding else None, finding_status='Open' if finding else None,
            evidence={'value':ATTACK} if finding else None, rule=deepcopy(CATALOG['rules'][local_ordinal])))
    selected = [r for r in rows if (r['analysis_id'], r['ordinal']) > (after_analysis_id, after_ordinal)]
    page = selected[:limit]; last = page[-1] if page else dict(analysis_id=after_analysis_id, ordinal=after_ordinal)
    return deepcopy(dict(status='found', report_version=web.api.report.VERSION, assessment_id=assessment, source_bytes_revalidated=False,
        scope_mode='all_persisted_imports', lifecycle=dict(state='completed', revision=4),
        identity=dict(central_asset_count=int(bool(count)), observation_count=count,
                      decisions=dict(new_asset=int(bool(count)), linked=max(0, count - 1), review_required=0),
                      reasons=dict(synthetic_new=1, synthetic_match=count - 1) if count else {}),
        recorded_finding_occurrences=sum(r['result'] == 'finding' for r in rows),
        snapshot_at_utc='2026-10-03T03:00:00Z', report_scope_sha256=scope,
        coverage=dict(evaluation_count=len(rows), import_count=count, asset_projected_import_count=count,
            analyzed_import_count=count, credentialed_sources_evaluated=count, credentialed_sources_indexed=count,
            projection_status='no_imports' if empty else 'all_imports_analyzed',
            outcomes=dict(finding=sum(r['result'] == 'finding' for r in rows), no_finding=sum(r['result'] == 'no_finding' for r in rows),
                          insufficient_evidence=0, not_applicable=0, not_supported=0),
            by_rule={rule:{result:sum(r['rule_id']==rule and r['result']==result for r in rows)
                           for result in web.api.report.RESULTS} for rule in web.api.report.RULES},
            imports_without_assets=[], imports_without_analysis=[]),
        imports=[dict(bundle_id='bnd-synthetic-'+str(n+1)) for n in range(count)],
        analyses=[dict(analysis_id=aid, bundle_id='bnd-synthetic-'+str(n+1), policy_version='0.6.4',
                       catalog_sha256=CATALOG_SHA, engine_sha256=engines[n], evaluation_count=2, finding_count=2 if many or n==0 else 0)
                  for n, aid in enumerate(analyses)],
        catalogs=[dict(policy_version='0.6.4', catalog_sha256=CATALOG_SHA, engine_sha256=engine, catalog=CATALOG)
                  for engine in sorted(set(engines))],
        evaluations=page, has_more=len(selected)>limit,
        next_cursor=dict(after_analysis_id=last['analysis_id'], after_ordinal=last['ordinal'])))


def main():
    # Account/server are temporary. CI child is stopped with SIGINT by the harness.
    with tempfile.TemporaryDirectory(prefix='canca-web-browser-ci-') as temporary:
        policy = Path(temporary) / 'accounts.json'
        auth.create_policy(policy, 'OP-BROWSER-CI', 'browser-reader', ['LAB-001', 'LAB-EMPTY', 'LAB-MANY', 'LAB-MISSING'], PASSWORD)
        doc = json.loads(policy.read_bytes())
        for operator, username, ids in [('OP-OTHER', 'other-reader', ['PRIVATE-OTHER']), ('OP-EMPTY', 'empty-reader', [])]:
            row = deepcopy(doc['accounts'][0])
            row.update(operator_id=operator, username=username,
                       grants=[dict(assessment_id=a, permissions=['assessment:read']) for a in ids])
            doc['accounts'].append(row)
        policy.write_text(json.dumps(doc))
        audit_path = Path(temporary) / 'browser-audit.jsonl'
        with web.create_server(policy, port=0, audit_path=audit_path) as server:
            from types import MethodType
            server.service.read_report = MethodType(read_report, server.service)
            web.exports.export.pg.open_connection = lambda: nullcontext(object())
            web.exports.export.report.show_assessment = canonical_page
            print(json.dumps(dict(url='http://127.0.0.1:'+str(server.server_port)+'/')), flush=True)
            try: server.serve_forever()
            except KeyboardInterrupt: pass
        # Independent synthetic audit check after all HTTP workers have closed.
        raw = audit_path.read_bytes(); assert raw.endswith(b'\n')
        records = [json.loads(line) for line in raw.splitlines()]
        assert records[0]['event'] == 'listener_started' and records[-1]['event'] == 'listener_stopped'
        pending = {}; finished = []
        for sequence, record in enumerate(records, 1):
            assert record['sequence'] == sequence and record['audit_version'] == '1'
            assert record['listener'] == 'web'
            if record['event'] == 'request_started':
                assert record['request_id'] not in pending
                pending[record['request_id']] = record['operation']
            elif record['event'] == 'request_finished':
                assert pending.pop(record['request_id']) == record['operation']
                finished.append(record)
        assert not pending
        assert {'login','logout','assessment_directory','report_page','executive_preview',
                'technical_export','executive_export'} <= {r['operation'] for r in finished}
        assert any(r['http_status'] == 403 and r['assessment_id'] is None for r in finished)
        assert not any(r['assessment_id'] == 'LAB-OTHER' for r in finished)
        assert PASSWORD.encode() not in raw and ATTACK.encode() not in raw
        assert all(doc['accounts'][0]['password'][key].encode() not in raw for key in ('salt','hash'))
        assert all(not (set(r) & {'username','password','token','access_token','headers','query','path'}) for r in records)


if __name__ == '__main__': main()
