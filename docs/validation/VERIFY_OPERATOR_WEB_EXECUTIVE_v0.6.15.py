#!/usr/bin/env python3
"""Verify a selected executive ZIP without extraction, database or network."""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import io
import json
from pathlib import Path
import re
import zipfile

MAX_BYTES = 32 * 1024**2
NAMES = {'executive.json', 'executive.md', 'manifest.json', 'manifest.json.sha256'}
REF_FIELDS = {'finding_id', 'finding_status', 'analysis_id', 'evaluation_ordinal',
              'bundle_id', 'source_sha256', 'asset_id', 'asset_decision'}


def require(ok):
    if not ok:
        raise ValueError('operator_web_executive_file_invalid')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def verify(path, assessment, evaluations, findings, groups):
    require(isinstance(assessment, str) and bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', assessment))
            and all(type(v) is int for v in (evaluations, findings, groups))
            and 0 <= groups <= min(findings, 200) and 0 <= findings <= evaluations <= 10000)
    path = Path(path)
    require(path.is_file() and 0 < path.stat().st_size <= MAX_BYTES)
    raw = path.read_bytes(); require(len(raw) <= MAX_BYTES)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        require(len(entries) == 4 and {item.filename for item in entries} == NAMES
                and all(0 < item.file_size <= MAX_BYTES and item.compress_type == zipfile.ZIP_STORED
                        and not item.flag_bits & 1 for item in entries)
                and sum(item.file_size for item in entries) <= MAX_BYTES)
        payloads = {name: archive.read(name) for name in NAMES}
    doc = json.loads(payloads['executive.json'].decode('utf-8'), object_pairs_hook=unique)
    manifest = json.loads(payloads['manifest.json'].decode('utf-8'), object_pairs_hook=unique)
    payloads['executive.md'].decode('utf-8')
    require(manifest['executive_version'] == doc['executive_version'] == '0.6.14'
            and manifest['delivery_version'] == '0.6.15'
            and manifest['assessment_id'] == doc['assessment_id'] == assessment
            and manifest['report_scope_sha256'] == doc['report_scope_sha256']
            and bool(re.fullmatch(r'[0-9a-f]{64}', doc['report_scope_sha256']))
            and doc['source_report_version'] == '0.6.5' and doc['source_export_version'] == '0.6.9'
            and doc['consistency']['terminal_empty_page_verified'] is True
            and doc['consistency']['mode'] == 'canonical_report_scope_fence'
            and doc['semantics']['findings'] == 'historical_occurrences'
            and doc['semantics']['source_bytes_revalidated'] is False
            and doc['semantics']['raw_evidence_included'] is False
            and doc['semantics']['extracted_evidence_included'] is False
            and doc['semantics']['current_risk_assessed'] is False
            and doc['coverage']['evaluation_count'] == evaluations
            and sum(doc['coverage']['outcomes'].values()) == evaluations
            and doc['coverage']['outcomes']['finding'] == doc['recorded_finding_occurrences'] == findings
            and doc['recommendation_group_count'] == len(doc['recommendation_groups']) == groups)
    references = []; severities = Counter(); group_ids = set()
    for group in doc['recommendation_groups']:
        require(group['group_id'] not in group_ids and bool(re.fullmatch(r'rec-[0-9a-f]{32}', group['group_id']))
                and group['occurrence_count'] == len(group['occurrences']) > 0
                and all(set(ref) == REF_FIELDS for ref in group['occurrences'])
                and all(bool(re.fullmatch(r'[0-9a-f]{64}', group['provenance'][key]))
                        for key in ('catalog_sha256', 'engine_sha256')))
        group_ids.add(group['group_id']); references.extend(group['occurrences'])
        severities[group['rule']['severity']] += group['occurrence_count']
    require(len(references) == len({ref['finding_id'] for ref in references}) == findings
            and dict(severities) == doc['findings_by_recorded_severity'])
    files = manifest['files']
    require(len(files) == 2 and {item['name'] for item in files} == {'executive.json', 'executive.md'})
    for item in files:
        payload = payloads[item['name']]
        require(len(payload) == item['size_bytes'] and digest(payload) == item['sha256'])
    require(payloads['manifest.json.sha256'] == (digest(payloads['manifest.json'])+'  manifest.json\n').encode('ascii'))
    return dict(status='OPERATOR WEB EXECUTIVE FILE PASS', assessment_id=assessment,
                evaluations=evaluations, historical_findings=findings, recommendation_groups=groups,
                archive_sha256=digest(raw), report_scope_sha256=doc['report_scope_sha256'], files_verified=4,
                terminal_empty_page_verified=True, raw_evidence_included=False, extracted_evidence_included=False)


def cli(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True)
    parser.add_argument('--assessment-id', required=True)
    parser.add_argument('--evaluation-count', type=int, required=True)
    parser.add_argument('--finding-count', type=int, required=True)
    parser.add_argument('--recommendation-group-count', type=int, required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(verify(args.archive, args.assessment_id, args.evaluation_count,
                                args.finding_count, args.recommendation_group_count)))
        return 0
    except Exception:
        print(json.dumps(dict(status='failed', error_code='operator_web_executive_file_invalid')))
        return 2


if __name__ == '__main__': raise SystemExit(cli())
