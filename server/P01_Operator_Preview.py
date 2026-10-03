#!/usr/bin/env python3
"""Bounded, paginated executive view of a complete authorized assessment."""
from contextlib import contextmanager
from copy import deepcopy
import json

import P01_Operator_Export as exports
from P01_Operator_Auth import AccessError

VERSION = '0.6.17'
GROUP_LIMIT = 10
MAX_GROUPS = exports.export.report.MAX_IMPORTS * len(exports.export.report.RULES)
MAX_BYTES = 1024**2
GROUP_COUNTS = ('occurrence_count', 'linked_central_asset_count',
                'occurrences_without_central_asset', 'occurrences_requiring_identity_review')


def validate_offset(offset):
    if type(offset) is not int or not 0 <= offset <= MAX_GROUPS or offset % GROUP_LIMIT:
        raise AccessError('report_input_invalid', 400)


def project(summary, offset=0):
    """Internal projection of the qualified synthesis, never of a partial page."""
    validate_offset(offset)
    groups = summary['recommendation_groups']; total = summary['recommendation_group_count']
    if offset and offset >= total:
        raise AccessError('report_input_invalid', 400)
    selected = groups[offset:offset + GROUP_LIMIT]
    coverage = {k: summary['coverage'][k] for k in exports.executive.COVERAGE_COUNTS}
    coverage.update(projection_status=summary['coverage']['projection_status'],
                    outcomes={k:summary['coverage']['outcomes'][k] for k in exports.export.report.RESULTS},
                    pending_asset_import_count=len(summary['coverage']['imports_without_assets']),
                    pending_analysis_import_count=len(summary['coverage']['imports_without_analysis']))
    identity = {k: summary['identity'][k] for k in ('central_asset_count', 'observation_count')}
    identity['decisions'] = {k:summary['identity']['decisions'][k] for k in exports.executive.DECISIONS}
    more = offset + len(selected) < total
    return dict(status='found', preview_version=VERSION, executive_version=exports.executive.VERSION,
        assessment_id=summary['assessment_id'], report_scope_sha256=summary['report_scope_sha256'],
        scope_mode=summary['scope_mode'], lifecycle={k:summary['lifecycle'][k] for k in ('state','revision')}, coverage=coverage,
        identity=identity, recorded_finding_occurrences=summary['recorded_finding_occurrences'],
        findings_by_recorded_severity=deepcopy(summary['findings_by_recorded_severity']),
        recommendation_group_count=total,
        recommendation_groups=[dict(group_id=g['group_id'], rule={k:g['rule'][k] for k in exports.executive.RULE_FIELDS},
            provenance={k:g['provenance'][k] for k in ('policy_version','catalog_sha256','engine_sha256')},
            **{k:g[k] for k in GROUP_COUNTS}) for g in selected],
        pagination=dict(offset=offset, page_size=GROUP_LIMIT, has_more=more,
                        next_offset=offset + GROUP_LIMIT if more else None),
        consistency={k:summary['consistency'][k] for k in ('mode','terminal_empty_page_verified','data_pages',
                                                        'first_snapshot_at_utc','last_snapshot_at_utc')},
        semantics=dict(**{k:summary['semantics'][k] for k in ('findings','lifecycle','severity','recommendations',
            'source_bytes_revalidated','raw_evidence_included','extracted_evidence_included','current_risk_assessed')},
            occurrence_references_included=False))


class ExecutivePreview:
    def __init__(self, delivery):
        self.delivery = delivery

    @contextmanager
    def build(self, token, assessment, scope, offset=0, *, limit=100):
        self.delivery.auth.require(token, assessment)
        validate_offset(offset)
        with self.delivery.snapshot(token, assessment, scope, limit) as (canonical, checkpoint):
            summary = exports.executive.summarize(canonical)
            checkpoint()
            doc = project(summary, offset)
            raw = (json.dumps(doc, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('utf-8')
            if len(raw) > MAX_BYTES:
                raise AccessError('executive_preview_limit_exceeded', 413)
            checksum = exports.export.pg.digest(raw)
            checkpoint()
            # Same slot as both ZIP deliveries, retained during the HTTP write.
            yield raw, checksum
