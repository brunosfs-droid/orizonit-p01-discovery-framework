#!/usr/bin/env python3
"""Bounded read-only export of the canonical historical assessment report."""
from __future__ import annotations

from collections import Counter
import argparse
import html
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import P01_Assessment_Report as report

pg = report.pg
VERSION = '0.6.9'
MAX_BYTES = 32 * 1024**2
ERRORS = report.ERRORS | {'export_output_invalid', 'export_limit_exceeded',
                          'export_data_conflict', 'export_write_failed', 'assessment_not_found'}
PAGE_FIELDS = {'evaluations', 'has_more', 'next_cursor', 'snapshot_at_utc'}


def output_root(value):
    try:
        root = Path(value).absolute()
        pg.require(root.is_dir() and root == root.resolve(), 'export_output_invalid')
        return root
    except pg.PersistenceError:
        raise
    except Exception:
        raise pg.PersistenceError('export_output_invalid') from None


def bounded_json(value):
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                      allow_nan=False) + '\n').encode('utf-8')
    pg.require(len(raw) <= MAX_BYTES, 'export_limit_exceeded')
    return raw


def collect(conn, assessment_id, page_size=100, *, expected_scope_sha256=None, checkpoint=None):
    """Each query is read-only. Fence every continuation and an empty end query."""
    report.validate_query(assessment_id, limit=page_size, expected_scope_sha256=expected_scope_sha256)
    header = None
    scope = expected_scope_sha256
    cursor = dict(after_analysis_id='', after_ordinal=-1)
    records = []
    previous = ('', -1)
    pages = 0
    total_bytes = 0
    first_snapshot = None
    last_snapshot = None
    # At least one record per nonempty page; one final empty query is mandatory.
    for _ in range(report.MAX_EVALUATIONS + 2):
        if checkpoint is not None:
            checkpoint()
        page = report.show_assessment(conn, assessment_id, **cursor, limit=page_size,
                                      expected_scope_sha256=scope)
        if checkpoint is not None:
            checkpoint()
        pg.require(page.get('status') != 'not_found', 'assessment_not_found')
        pg.require(page.get('status') == 'found' and page.get('report_version') == report.VERSION
                   and page.get('assessment_id') == assessment_id
                   and page.get('source_bytes_revalidated') is False, 'export_data_conflict')
        current = {k: v for k, v in page.items() if k not in PAGE_FIELDS}
        if header is None:
            header = current
            actual_scope = page['report_scope_sha256']
            pg.require(scope is None or actual_scope == scope, 'report_scope_conflict')
            scope = actual_scope
            pg.require(isinstance(scope, str) and re.fullmatch(r'[0-9a-f]{64}', scope), 'export_data_conflict')
            first_snapshot = page['snapshot_at_utc']
        pg.require(current == header, 'export_data_conflict')
        last_snapshot = page['snapshot_at_utc']
        rows = page['evaluations']
        pg.require(isinstance(rows, list) and len(rows) <= page_size
                   and type(page['has_more']) is bool, 'export_data_conflict')
        if not rows:
            pg.require(not page['has_more'] and page['next_cursor'] == cursor, 'export_data_conflict')
            break
        pages += 1
        for row in rows:
            key = (row['analysis_id'], row['ordinal'])
            report.validate_query(assessment_id, key[0], key[1], page_size, scope)
            pg.require(key > previous and row['rule_id'] in report.RULES
                       and row['result'] in report.RESULTS
                       and ((row['result'] == 'finding') == (row['finding_id'] is not None)), 'export_data_conflict')
            total_bytes += len(bounded_json(row))
            pg.require(total_bytes <= MAX_BYTES and len(records) < report.MAX_EVALUATIONS, 'export_limit_exceeded')
            records.append(row)
            previous = key
        cursor = dict(after_analysis_id=previous[0], after_ordinal=previous[1])
        pg.require(page['next_cursor'] == cursor
                   and (not page['has_more'] or len(rows) == page_size), 'export_data_conflict')
        # Continue even after has_more=false, to check the empty end under the fence.
    else:
        raise pg.PersistenceError('export_limit_exceeded')
    outcomes = Counter(row['result'] for row in records)
    by_rule = {rule: {result: sum(row['rule_id'] == rule and row['result'] == result for row in records)
                      for result in report.RESULTS} for rule in report.RULES}
    pg.require(len(records) == header['coverage']['evaluation_count']
               and {r: outcomes[r] for r in report.RESULTS} == header['coverage']['outcomes']
               and by_rule == header['coverage']['by_rule']
               and outcomes['finding'] == header['recorded_finding_occurrences'], 'export_data_conflict')
    actual = Counter(row['analysis_id'] for row in records)
    positives = Counter(row['analysis_id'] for row in records if row['result'] == 'finding')
    pg.require(set(actual) <= {a['analysis_id'] for a in header['analyses']}
               and all(actual[a['analysis_id']] == a['evaluation_count']
                       and positives[a['analysis_id']] == a['finding_count'] for a in header['analyses']), 'export_data_conflict')
    doc = dict(export_version=VERSION, **header, evaluations=records,
               export_consistency=dict(mode='canonical_report_scope_fence', terminal_empty_page_verified=True,
                                       data_pages=pages, first_snapshot_at_utc=first_snapshot,
                                       last_snapshot_at_utc=last_snapshot),
               semantics=dict(findings='historical_occurrences', lifecycle='administrative',
                              source_bytes_revalidated=False, raw_evidence_included=False))
    bounded_json(doc)
    return doc


def cell(value):
    """Keep persisted text inert in Markdown tables: no HTML/links/images."""
    text = html.escape(str(value), quote=True)
    return ''.join('&#' + str(ord(c)) + ';' if c in '\\`*_{}[]()#+.!|-:/@~=' else c
                   for c in text).replace('\r', ' ').replace('\n', ' ').replace('\t', ' ')


def markdown(doc):
    coverage = doc['coverage']
    lines = ['# Cancã — relatório consolidado', '',
             '| Campo | Valor |', '| --- | --- |',
             f"| Assessment | {cell(doc['assessment_id'])} |",
             f"| Lifecycle administrativo | {cell(doc['lifecycle']['state'])} |",
             f"| Revisão | {doc['lifecycle']['revision']} |",
             f"| Imports / analisados | {coverage['import_count']} / {coverage['analyzed_import_count']} |",
             f"| Status da projeção | {cell(coverage['projection_status'])} |",
             f"| Assets centrais / observações | {doc['identity']['central_asset_count']} / {doc['identity']['observation_count']} |",
             f"| Avaliações | {coverage['evaluation_count']} |",
             f"| Ocorrências históricas de findings | {doc['recorded_finding_occurrences']} |", '',
             'O lifecycle é administrativo. Ocorrências de runs anteriores são preservadas; '
             'completed não fecha findings nem comprova segurança do ambiente.', '',
             'Esta exportação consulta metadados persistidos. Não revalida bytes do store, '
             'não inclui evidência bruta e não comprova cobertura de todo o ambiente.', '',
             '## Cobertura por resultado', '', '| Resultado | Avaliações |', '| --- | --- |']
    lines += [f'| {cell(result)} | {coverage["outcomes"][result]} |' for result in report.RESULTS]
    lines += ['', '## Imports pendentes', '', '| Pendência | Bundle |', '| --- | --- |']
    for key in ('imports_without_assets', 'imports_without_analysis'):
        lines += [f'| {cell(key)} | {cell(bundle)} |' for bundle in coverage[key]]
    if not coverage['imports_without_assets'] and not coverage['imports_without_analysis']:
        lines += ['| Nenhuma pendência de projeção registrada | — |']
    lines += ['', '## Avaliações históricas', '',
              '| Análise / ordinal | Bundle | Regra | Resultado | CAS / decisão | Finding / status | Fonte / SHA256 |',
              '| --- | --- | --- | --- | --- | --- | --- |']
    for row in doc['evaluations']:
        values = (f"{row['analysis_id']} / {row['ordinal']}", row['bundle_id'],
                  f"{row['rule_id']} — {row['rule']['title']}", row['result'],
                  f"{row['asset_id'] or '—'} / {row['asset_decision'] or '—'}",
                  f"{row['finding_id'] or '—'} / {row['finding_status'] or '—'}",
                  f"{row['source_path']} / {row['source_sha256']}")
        lines.append('| ' + ' | '.join(cell(v) for v in values) + ' |')
    lines += ['', '## Consistência e origem', '',
              'O JSON contém o catálogo histórico, recomendações, referências de evidência, '
              'proveniência e metadados completos da consulta. A tabela acima é uma apresentação resumida.', '',
              f"Escopo: {doc['report_scope_sha256']}", '',
              'Todas as páginas e a consulta terminal vazia foram verificadas sob a mesma cerca de escopo. '
              'Ela detecta mudanças normais entre consultas; não é snapshot durável nem assinatura contra alteração por DBA.', '']
    raw = '\n'.join(lines).encode('utf-8')
    pg.require(len(raw) <= MAX_BYTES, 'export_limit_exceeded')
    return raw


def save(doc, root):
    root = output_root(root)
    payloads = {'report.json': bounded_json(doc), 'report.md': markdown(doc)}
    manifest = dict(export_version=VERSION, assessment_id=doc['assessment_id'],
                    report_scope_sha256=doc['report_scope_sha256'],
                    files=[dict(name=name, size_bytes=len(raw), sha256=pg.digest(raw))
                           for name, raw in payloads.items()])
    payloads['manifest.json'] = bounded_json(manifest)
    payloads['manifest.json.sha256'] = (pg.digest(payloads['manifest.json']) + '  manifest.json\n').encode('ascii')
    stage = None
    try:
        stage = Path(tempfile.mkdtemp(prefix='.P01-EXPORT-', dir=root))
        os.chmod(stage, 0o700)
        for name, raw in payloads.items():
            fd = os.open(stage / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        destination = root / ('P01-EXPORT-' + uuid.uuid4().hex)
        pg.require(not os.path.lexists(destination), 'export_write_failed')
        stage.rename(destination)
        stage = None
        return dict(status='exported', export_version=VERSION, assessment_id=doc['assessment_id'],
                    export_dir=str(destination), report_scope_sha256=doc['report_scope_sha256'],
                    evaluation_count=len(doc['evaluations']), source_bytes_revalidated=False,
                    database_mutated=False, manifest_sha256=pg.digest(payloads['manifest.json']))
    except Exception:
        raise pg.PersistenceError('export_write_failed') from None
    finally:
        if stage is not None:
            shutil.rmtree(stage)


def cli(argv=None):
    parser = argparse.ArgumentParser(description='Cancã historical report export v' + VERSION)
    parser.add_argument('--assessment-id', required=True)
    parser.add_argument('--output-root', required=True)
    parser.add_argument('--page-size', type=int, default=100)
    args = parser.parse_args(argv)
    try:
        report.validate_query(args.assessment_id, limit=args.page_size)
        root = output_root(args.output_root)
        with pg.open_connection() as conn:
            doc = collect(conn, args.assessment_id, args.page_size)
        result = save(doc, root)
        print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        return 0
    except Exception as exc:
        code = str(exc) if isinstance(exc, pg.PersistenceError) and str(exc) in ERRORS else 'database_failed'
        print(json.dumps(dict(status='failed', error_code=code, export_version=VERSION)))
        return 2


if __name__ == '__main__':
    raise SystemExit(cli())
