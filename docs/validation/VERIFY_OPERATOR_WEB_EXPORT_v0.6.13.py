#!/usr/bin/env python3
"""Verify one explicitly selected ZIP; no extraction, database or network."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

MAX_BYTES = 32 * 1024**2
NAMES = {'report.json', 'report.md', 'manifest.json', 'manifest.json.sha256'}


def require(ok):
    if not ok:
        raise ValueError('operator_web_export_file_invalid')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def verify(path, assessment, evaluations, findings):
    require(bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', assessment))
            and 0 <= findings <= evaluations <= 10000)
    path = Path(path)
    require(path.is_file() and 0 < path.stat().st_size <= MAX_BYTES)
    raw = path.read_bytes()
    require(len(raw) <= MAX_BYTES)
    import io
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        require(len(entries) == 4 and {item.filename for item in entries} == NAMES
                and all(0 < item.file_size <= MAX_BYTES and item.compress_type == zipfile.ZIP_STORED
                        and not item.flag_bits & 1 for item in entries)
                and sum(item.file_size for item in entries) <= MAX_BYTES)
        payloads = {name: archive.read(name) for name in NAMES}
    doc = json.loads(payloads['report.json'].decode('utf-8'), object_pairs_hook=unique)
    manifest = json.loads(payloads['manifest.json'].decode('utf-8'), object_pairs_hook=unique)
    payloads['report.md'].decode('utf-8')
    require(manifest['export_version'] == doc['export_version'] == '0.6.9'
            and manifest['delivery_version'] == '0.6.13'
            and manifest['assessment_id'] == doc['assessment_id'] == assessment
            and manifest['report_scope_sha256'] == doc['report_scope_sha256']
            and bool(re.fullmatch(r'[0-9a-f]{64}', doc['report_scope_sha256']))
            and doc['source_bytes_revalidated'] is False
            and doc['export_consistency']['terminal_empty_page_verified'] is True
            and doc['export_consistency']['mode'] == 'canonical_report_scope_fence'
            and doc['semantics']['raw_evidence_included'] is False
            and doc['coverage']['evaluation_count'] == len(doc['evaluations']) == evaluations
            and doc['recorded_finding_occurrences'] == findings
            and sum(row['result']=='finding' for row in doc['evaluations']) == findings)
    files = manifest['files']
    require(len(files) == 2 and {item['name'] for item in files} == {'report.json','report.md'})
    for item in files:
        payload = payloads[item['name']]
        require(len(payload) == item['size_bytes'] and digest(payload) == item['sha256'])
    require(payloads['manifest.json.sha256'] ==
            (digest(payloads['manifest.json'])+'  manifest.json\n').encode('ascii'))
    return dict(status='OPERATOR WEB EXPORT FILE PASS', assessment_id=assessment,
        evaluations=evaluations, historical_findings=findings, archive_sha256=digest(raw),
        report_scope_sha256=doc['report_scope_sha256'], files_verified=4,
        terminal_empty_page_verified=True, raw_evidence_included=False)


def cli(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True)
    parser.add_argument('--assessment-id', required=True)
    parser.add_argument('--evaluation-count', type=int, required=True)
    parser.add_argument('--finding-count', type=int, required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(verify(args.archive,args.assessment_id,args.evaluation_count,args.finding_count)))
        return 0
    except Exception:
        print(json.dumps(dict(status='failed',error_code='operator_web_export_file_invalid')))
        return 2


if __name__ == '__main__': raise SystemExit(cli())
