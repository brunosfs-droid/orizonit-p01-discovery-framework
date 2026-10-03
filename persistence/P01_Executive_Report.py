#!/usr/bin/env python3
"""Read-only executive synthesis of complete, fenced historical reports."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import P01_Report_Export as export

pg = export.pg
report = export.report
VERSION = '0.6.14'
MAX_BYTES = 32 * 1024**2
SEVERITIES = ('Critical', 'High', 'Medium', 'Low', 'Informational')
DECISIONS = ('new_asset', 'linked', 'review_required')
COVERAGE_COUNTS = ('import_count', 'asset_projected_import_count', 'analyzed_import_count',
                   'credentialed_sources_indexed', 'credentialed_sources_evaluated', 'evaluation_count')
RULE_FIELDS = ('id', 'version', 'title', 'category', 'severity', 'recommendation')
ERRORS = export.ERRORS | {'executive_data_conflict', 'executive_limit_exceeded', 'executive_write_failed'}


def require(ok):
    pg.require(ok, 'executive_data_conflict')


def count(value):
    require(type(value) is int and value >= 0)
    return value


def sha(value):
    require(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value))
    return value


def text(value):
    require(isinstance(value, str) and 0 < len(value) <= 4096)
    return value


def bounded_json(value):
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('utf-8')
    pg.require(len(raw) <= MAX_BYTES, 'executive_limit_exceeded')
    return raw


def summarize(doc):
    """Internal API for a complete canonical export, never a paginated response."""
    try:
        return _summarize(doc)
    except pg.PersistenceError:
        raise
    except Exception:
        raise pg.PersistenceError('executive_data_conflict') from None


def _summarize(doc):
    require(doc['status'] == 'found' and doc['export_version'] == export.VERSION
            and doc['report_version'] == report.VERSION and doc['scope_mode'] == 'all_persisted_imports'
            and doc['source_bytes_revalidated'] is False)
    report.validate_query(doc['assessment_id'], expected_scope_sha256=doc['report_scope_sha256'])
    fence = doc['export_consistency']
    require(fence['mode'] == 'canonical_report_scope_fence' and fence['terminal_empty_page_verified'] is True)
    count(fence['data_pages'])
    text(fence['first_snapshot_at_utc']); text(fence['last_snapshot_at_utc'])
    coverage = {k: count(doc['coverage'][k]) for k in COVERAGE_COUNTS}
    for key in ('imports_without_assets', 'imports_without_analysis'):
        values = doc['coverage'][key]
        require(isinstance(values, list) and len(values) <= report.MAX_IMPORTS
                and all(isinstance(v, str) for v in values) and len(set(values)) == len(values))
        coverage[key] = list(values)
    imports = doc['imports']
    require(isinstance(imports, list) and len(imports) == coverage['import_count'] <= report.MAX_IMPORTS)
    bundles = {text(i['bundle_id']) for i in imports}
    require(len(bundles) == len(imports)
            and all(set(coverage[k]) <= bundles for k in ('imports_without_assets', 'imports_without_analysis'))
            and coverage['asset_projected_import_count'] == len(imports) - len(coverage['imports_without_assets'])
            and coverage['analyzed_import_count'] == len(imports) - len(coverage['imports_without_analysis']))
    status = ('no_imports' if not imports else 'missing_analyses'
              if coverage['imports_without_analysis'] else 'all_imports_analyzed')
    require(doc['coverage']['projection_status'] == status)
    coverage['projection_status'] = status
    coverage['outcomes'] = {r: count(doc['coverage']['outcomes'][r]) for r in report.RESULTS}
    coverage['by_rule'] = {r: {s: count(doc['coverage']['by_rule'][r][s]) for s in report.RESULTS}
                           for r in report.RULES}
    identity = {k: count(doc['identity'][k]) for k in ('central_asset_count', 'observation_count')}
    identity['decisions'] = {d: count(doc['identity']['decisions'][d]) for d in DECISIONS}
    identity['reasons'] = {text(k): count(v) for k, v in doc['identity']['reasons'].items()}
    require(sum(identity['decisions'].values()) == sum(identity['reasons'].values()) == identity['observation_count'])
    lifecycle = dict(state=text(doc['lifecycle']['state']), revision=count(doc['lifecycle']['revision']))

    catalog_entries = doc['catalogs']
    require(isinstance(catalog_entries, list) and len(catalog_entries) <= report.MAX_IMPORTS)
    catalogs = {}
    for entry in catalog_entries:
        key = (text(entry['policy_version']), sha(entry['catalog_sha256']), sha(entry['engine_sha256']))
        require(key not in catalogs and key[0] == entry['catalog']['ruleset_version'])
        catalogs[key] = report.stored_rules(entry['catalog'])
    analyses = doc['analyses']
    require(isinstance(analyses, list) and len(analyses) == coverage['analyzed_import_count'])
    by_analysis = {}
    for a in analyses:
        report.validate_query(doc['assessment_id'], a['analysis_id'], -1, 100, doc['report_scope_sha256'])
        key = (a['policy_version'], a['catalog_sha256'], a['engine_sha256'])
        require(a['analysis_id'] not in by_analysis and a['bundle_id'] in bundles and key in catalogs)
        count(a['evaluation_count']); count(a['finding_count'])
        by_analysis[a['analysis_id']] = (a, key)
    require({key for _, key in by_analysis.values()} == set(catalogs)
            and len({a['bundle_id'] for a, _ in by_analysis.values()}) == len(analyses)
            and {a['bundle_id'] for a, _ in by_analysis.values()} == bundles - set(coverage['imports_without_analysis']))

    rows = doc['evaluations']
    require(isinstance(rows, list) and len(rows) == coverage['evaluation_count'] <= report.MAX_EVALUATIONS)
    outcomes = Counter(); rule_results = Counter(); analysis_counts = Counter(); positives = Counter()
    groups = {}; findings = set(); previous = ('', -1)
    for row in rows:
        aid, ordinal = row['analysis_id'], row['ordinal']
        report.validate_query(doc['assessment_id'], aid, ordinal, 100, doc['report_scope_sha256'])
        require(ordinal >= 0 and (aid, ordinal) > previous and aid in by_analysis)
        previous = (aid, ordinal)
        analysis, catalog_key = by_analysis[aid]
        rule_id, result = row['rule_id'], row['result']
        require(rule_id in report.RULES and result in report.RESULTS
                and row['bundle_id'] == analysis['bundle_id'] and row['rule'] == catalogs[catalog_key][rule_id]
                and ((result == 'finding') == (row['finding_id'] is not None)))
        outcomes[result] += 1; rule_results[(rule_id, result)] += 1; analysis_counts[aid] += 1
        if result != 'finding':
            continue
        fid = text(row['finding_id'])
        require(fid not in findings)
        findings.add(fid); positives[aid] += 1
        key = (catalog_key, rule_id)
        if key not in groups:
            rule = {k: text(row['rule'][k]) for k in RULE_FIELDS}
            provenance = dict(policy_version=catalog_key[0], catalog_sha256=catalog_key[1], engine_sha256=catalog_key[2])
            group_id = 'rec-' + pg.digest(pg.canonical(dict(**provenance, rule_id=rule_id, rule_version=rule['version'])))[:32]
            groups[key] = dict(group_id=group_id, rule=rule, provenance=provenance, occurrences=[])
        asset = row['asset_id']; decision = row['asset_decision']
        require((asset is None or isinstance(asset, str) and 0 < len(asset) <= 128)
                and (decision is None or decision in DECISIONS))
        groups[key]['occurrences'].append(dict(finding_id=fid, finding_status=text(row['finding_status']),
            analysis_id=aid, evaluation_ordinal=ordinal, bundle_id=row['bundle_id'],
            source_sha256=sha(row['source_sha256']), asset_id=asset, asset_decision=decision))
    require({r: outcomes[r] for r in report.RESULTS} == coverage['outcomes']
            and {r: {s: rule_results[(r, s)] for s in report.RESULTS} for r in report.RULES} == coverage['by_rule']
            and len(findings) == count(doc['recorded_finding_occurrences'])
            and all(analysis_counts[aid] == a['evaluation_count'] and positives[aid] == a['finding_count']
                    for aid, (a, _) in by_analysis.items()))
    severity_counts = Counter()
    for group in groups.values():
        refs = group['occurrences']
        group.update(occurrence_count=len(refs), linked_central_asset_count=len({r['asset_id'] for r in refs if r['asset_id']}),
                     occurrences_without_central_asset=sum(r['asset_id'] is None for r in refs),
                     occurrences_requiring_identity_review=sum(r['asset_decision'] == 'review_required' for r in refs))
        severity_counts[group['rule']['severity']] += len(refs)
    ordered = sorted(groups.values(), key=lambda g: (
        SEVERITIES.index(g['rule']['severity']) if g['rule']['severity'] in SEVERITIES else len(SEVERITIES),
        g['rule']['severity'], g['rule']['id'], g['provenance']['policy_version'],
        g['provenance']['catalog_sha256'], g['provenance']['engine_sha256']))
    result = dict(executive_version=VERSION, assessment_id=doc['assessment_id'], report_scope_sha256=doc['report_scope_sha256'],
        source_report_version=report.VERSION, source_export_version=export.VERSION, scope_mode=doc['scope_mode'],
        lifecycle=lifecycle, coverage=coverage, identity=identity, recorded_finding_occurrences=len(findings),
        findings_by_recorded_severity=dict(sorted(severity_counts.items())), recommendation_group_count=len(ordered),
        recommendation_groups=ordered,
        consistency={k: deepcopy(fence[k]) for k in ('mode', 'terminal_empty_page_verified', 'data_pages',
                                                   'first_snapshot_at_utc', 'last_snapshot_at_utc')},
        semantics=dict(findings='historical_occurrences', lifecycle='administrative', severity='stored_rule_metadata',
                       recommendations='stored_catalog_per_rule_and_engine', source_bytes_revalidated=False,
                       raw_evidence_included=False, extracted_evidence_included=False, current_risk_assessed=False))
    bounded_json(result)
    return result


def collect(conn, assessment_id, page_size=100, *, expected_scope_sha256=None):
    return summarize(export.collect(conn, assessment_id, page_size, expected_scope_sha256=expected_scope_sha256))


def markdown(doc):
    cell = export.cell
    coverage, identity = doc['coverage'], doc['identity']
    lines = ['# Cancã — relatório executivo', '', '| Indicador | Valor |', '| --- | --- |',
        f"| Assessment | {cell(doc['assessment_id'])} |",
        f"| Lifecycle administrativo / revisão | {cell(doc['lifecycle']['state'])} / {doc['lifecycle']['revision']} |",
        f"| Imports / projetados em assets / analisados | {coverage['import_count']} / {coverage['asset_projected_import_count']} / {coverage['analyzed_import_count']} |",
        f"| Fontes credentialed indexadas / avaliadas | {coverage['credentialed_sources_indexed']} / {coverage['credentialed_sources_evaluated']} |",
        f"| Assets centrais / observações | {identity['central_asset_count']} / {identity['observation_count']} |",
        f"| Avaliações / ocorrências históricas de findings | {coverage['evaluation_count']} / {doc['recorded_finding_occurrences']} |",
        f"| Grupos de recomendações históricas | {doc['recommendation_group_count']} |", '',
        'Os indicadores abrangem os imports persistidos deste assessment. Não comprovam cobertura '
        'de todo o ambiente. Findings são ocorrências históricas: uma coleta posterior sem finding '
        'não encerra ocorrências anteriores. O lifecycle completed é administrativo.', '',
        '## Cobertura e pendências', '', f"Status da projeção: {cell(coverage['projection_status'])}.", '']
    if coverage['projection_status'] == 'no_imports':
        lines += ['Não há imports persistidos; não é possível concluir sobre a segurança do ambiente.', '']
    lines += ['| Resultado registrado | Avaliações |', '| --- | --- |']
    labels = dict(finding='Finding histórico', no_finding='Sem finding nessa avaliação',
                  insufficient_evidence='Evidência insuficiente', not_applicable='Não aplicável', not_supported='Não suportado')
    lines += [f'| {labels[r]} | {coverage["outcomes"][r]} |' for r in report.RESULTS]
    lines += ['', 'Sem finding nessa avaliação não equivale a ambiente seguro. Evidência insuficiente, '
              'não aplicável e não suportado permanecem resultados distintos.', '',
              '| Regra | Findings históricos | Sem finding | Evidência insuficiente | Não aplicável | Não suportado |',
              '| --- | --- | --- | --- | --- | --- |']
    for rule_id in report.RULES:
        lines.append('| ' + cell(rule_id) + ' | ' + ' | '.join(str(coverage['by_rule'][rule_id][r]) for r in report.RESULTS) + ' |')
    lines += ['', '| Pendência | Bundle |', '| --- | --- |']
    for key, label in (('imports_without_assets', 'Projeção de assets ausente'), ('imports_without_analysis', 'Análise ausente')):
        lines += [f'| {label} | {cell(bundle)} |' for bundle in coverage[key]]
    if not coverage['imports_without_assets'] and not coverage['imports_without_analysis']:
        lines.append('| Nenhuma pendência de projeção registrada | — |')
    lines += ['', '## Identidade dos assets', '', '| Decisão por observação | Quantidade |', '| --- | --- |']
    decision_labels = dict(new_asset='Novo asset', linked='Associada a asset existente', review_required='Revisão de identidade necessária')
    lines += [f'| {decision_labels[d]} | {identity["decisions"][d]} |' for d in DECISIONS]
    lines += ['', '| Motivo registrado | Observações |', '| --- | --- |']
    lines += [f'| {cell(reason)} | {n} |' for reason, n in sorted(identity['reasons'].items())] or ['| Sem observações | 0 |']
    lines += ['', '## Severidade registrada das ocorrências históricas', '', '| Severidade | Ocorrências |', '| --- | --- |']
    lines += [f'| {cell(severity)} | {n} |' for severity, n in doc['findings_by_recorded_severity'].items()] or ['| Sem ocorrências registradas | 0 |']
    lines += ['', 'A severidade vem do catálogo histórico. Não há cálculo de risco atual ou de vulnerabilidades únicas.', '',
              '## Recomendações consolidadas', '',
              'Cada grupo preserva a regra, o catálogo e o engine utilizados. Assets e contagens são históricos; '
              'grupos diferentes podem referenciar o mesmo asset. Valores de severidade fora de Critical, High, '
              'Medium, Low e Informational são preservados após essa ordem de apresentação.', '']
    if not doc['recommendation_groups']:
        lines += ['Não há recomendações derivadas de findings registrados. Isso não comprova segurança do ambiente.', '']
    for group in doc['recommendation_groups']:
        rule = group['rule']
        lines += [f"### {cell(rule['id'])} — {cell(rule['title'])}", '',
                  f"Categoria: {cell(rule['category'])}. Severidade registrada: {cell(rule['severity'])}.", '',
                  f"Ocorrências: {group['occurrence_count']}; assets centrais vinculados: {group['linked_central_asset_count']}; "
                  f"ocorrências sem asset central: {group['occurrences_without_central_asset']}; "
                  f"com revisão de identidade: {group['occurrences_requiring_identity_review']}.", '',
                  cell(rule['recommendation']), '', f"Referência do grupo: {cell(group['group_id'])}.", '']
    lines += ['## Rastreabilidade e limites', '', '| Grupo / versão da regra | Catálogo SHA256 | Engine SHA256 |', '| --- | --- | --- |']
    for group in doc['recommendation_groups']:
        lines.append(f"| {cell(group['group_id'])} / {cell(group['rule']['version'])} | {group['provenance']['catalog_sha256']} | {group['provenance']['engine_sha256']} |")
    lines += ['', 'executive.json contém todas as referências de ocorrências por grupo (finding, análise/ordinal, '
              'bundle, asset e SHA256 da fonte). Consulte o relatório técnico do mesmo escopo para detalhes. '
              'Este resumo não inclui caminhos de fontes, evidência extraída ou bruta e não abre o store.', '',
              f"Escopo do relatório técnico: {doc['report_scope_sha256']}", '',
              'Todas as páginas e a consulta terminal vazia passaram pela mesma cerca de escopo. '
              'Ela não é um snapshot durável nem assinatura contra alteração por DBA. Os hashes do manifesto '
              'verificam os bytes, sem autenticar autoria. Dados do assessment exigem controle de acesso local.', '']
    raw = '\n'.join(lines).encode('utf-8')
    pg.require(len(raw) <= MAX_BYTES, 'executive_limit_exceeded')
    return raw


def save(doc, root):
    root = export.output_root(root)
    payloads = {'executive.json': bounded_json(doc), 'executive.md': markdown(doc)}
    manifest = dict(executive_version=VERSION, assessment_id=doc['assessment_id'],
                    report_scope_sha256=doc['report_scope_sha256'],
                    files=[dict(name=name, size_bytes=len(raw), sha256=pg.digest(raw)) for name, raw in payloads.items()])
    payloads['manifest.json'] = bounded_json(manifest)
    checksum = pg.digest(payloads['manifest.json'])
    payloads['manifest.json.sha256'] = (checksum + '  manifest.json\n').encode('ascii')
    pg.require(sum(map(len, payloads.values())) <= MAX_BYTES, 'executive_limit_exceeded')
    stage = None
    try:
        stage = Path(tempfile.mkdtemp(prefix='.P01-EXECUTIVE-', dir=root))
        os.chmod(stage, 0o700)
        for name, raw in payloads.items():
            fd = os.open(stage / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        destination = root / ('P01-EXECUTIVE-' + uuid.uuid4().hex)
        pg.require(not os.path.lexists(destination), 'executive_write_failed')
        stage.rename(destination)
        stage = None
        return dict(status='exported', executive_version=VERSION, assessment_id=doc['assessment_id'],
                    export_dir=str(destination), report_scope_sha256=doc['report_scope_sha256'],
                    evaluation_count=doc['coverage']['evaluation_count'], recorded_finding_occurrences=doc['recorded_finding_occurrences'],
                    recommendation_group_count=doc['recommendation_group_count'], source_bytes_revalidated=False,
                    database_mutated=False, manifest_sha256=checksum)
    except Exception:
        raise pg.PersistenceError('executive_write_failed') from None
    finally:
        if stage is not None:
            shutil.rmtree(stage)


def cli(argv=None):
    parser = argparse.ArgumentParser(description='Cancã historical executive report v' + VERSION)
    parser.add_argument('--assessment-id', required=True)
    parser.add_argument('--output-root', required=True)
    parser.add_argument('--page-size', type=int, default=100)
    parser.add_argument('--expected-scope-sha256')
    args = parser.parse_args(argv)
    try:
        report.validate_query(args.assessment_id, limit=args.page_size, expected_scope_sha256=args.expected_scope_sha256)
        root = export.output_root(args.output_root)
        with pg.open_connection() as conn:
            doc = collect(conn, args.assessment_id, args.page_size, expected_scope_sha256=args.expected_scope_sha256)
        result = save(doc, root)
        print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        return 0
    except Exception as exc:
        code = str(exc) if isinstance(exc, pg.PersistenceError) and str(exc) in ERRORS else 'database_failed'
        print(json.dumps(dict(status='failed', error_code=code, executive_version=VERSION)))
        return 2


if __name__ == '__main__':
    raise SystemExit(cli())
