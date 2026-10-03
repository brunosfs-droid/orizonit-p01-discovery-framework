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
ANALYSIS = 'ana-' + '1' * 32
SCOPE = 'a' * 64


def read_report(self, token, assessment, *, after_analysis_id='', after_ordinal=-1, limit=100, expected_scope_sha256=None):
    self.auth.require(token, assessment)
    return canonical_page(None, assessment, after_analysis_id, after_ordinal, limit, expected_scope_sha256)


def canonical_page(conn, assessment, after_analysis_id='', after_ordinal=-1, limit=100, expected_scope_sha256=None):
    web.api.report.validate_query(assessment, after_analysis_id, after_ordinal, limit, expected_scope_sha256)
    if expected_scope_sha256 is not None and expected_scope_sha256 != SCOPE:
        raise web.api.report.pg.PersistenceError('report_scope_conflict')
    rows = []
    for ordinal in range(4):
        finding = ordinal < 2
        rows.append(dict(analysis_id=ANALYSIS, ordinal=ordinal, rule_id='WIN-AD-001' if ordinal % 2 == 0 else 'WIN-FW-001',
            result='finding' if finding else 'no_finding', asset_id='asset-synthetic', source_path=ATTACK,
            source_sha256='b'*64, bundle_id='bundle-synthetic', link_state='linked', asset_decision='linked',
            asset_reason_code='exact', observation_ordinal=ordinal % 2, evidence_refs=[ATTACK],
            finding_id='finding-'+str(ordinal) if finding else None, finding_status='Open' if finding else None,
            evidence={'value':ATTACK} if finding else None, rule=dict(title=ATTACK, recommendation='Validar a configuração.')))
    selected = [r for r in rows if (r['analysis_id'], r['ordinal']) > (after_analysis_id, after_ordinal)]
    page = selected[:limit]; last = page[-1] if page else dict(analysis_id=after_analysis_id, ordinal=after_ordinal)
    return deepcopy(dict(status='found', report_version=web.api.report.VERSION, assessment_id=assessment, source_bytes_revalidated=False,
        lifecycle=dict(state='completed', revision=4), identity=dict(central_asset_count=1, observation_count=2),
        recorded_finding_occurrences=2, snapshot_at_utc='2026-10-03T03:00:00Z', report_scope_sha256=SCOPE,
        coverage=dict(evaluation_count=4, import_count=2, analyzed_import_count=2, credentialed_sources_evaluated=2,
            credentialed_sources_indexed=2, projection_status='all_imports_analyzed',
            outcomes=dict(finding=2, no_finding=2, insufficient_evidence=0, not_applicable=0, not_supported=0),
            by_rule={rule:{result:sum(r['rule_id']==rule and r['result']==result for r in rows)
                           for result in web.api.report.RESULTS} for rule in web.api.report.RULES},
            imports_without_assets=[], imports_without_analysis=[]),
        analyses=[dict(analysis_id=ANALYSIS,evaluation_count=4,finding_count=2)],
        evaluations=page, has_more=len(selected)>limit,
        next_cursor=dict(after_analysis_id=last['analysis_id'], after_ordinal=last['ordinal'])))


def main():
    # Account/server are temporary. CI child is stopped with SIGINT by the harness.
    with tempfile.TemporaryDirectory(prefix='canca-web-browser-ci-') as temporary:
        policy = Path(temporary) / 'accounts.json'
        auth.create_policy(policy, 'OP-BROWSER-CI', 'browser-reader', ['LAB-001'], PASSWORD)
        with web.create_server(policy, port=0) as server:
            from types import MethodType
            server.service.read_report = MethodType(read_report, server.service)
            web.exports.export.pg.open_connection = lambda: nullcontext(object())
            web.exports.export.report.show_assessment = canonical_page
            print(json.dumps(dict(url='http://127.0.0.1:'+str(server.server_port)+'/')), flush=True)
            try: server.serve_forever()
            except KeyboardInterrupt: pass


if __name__ == '__main__': main()
