#!/usr/bin/env python3
"""Authenticated bounded in-memory delivery of technical/executive reports."""
from __future__ import annotations

from contextlib import contextmanager
import io
from pathlib import Path
import sys
import threading
import time
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'persistence'))
from P01_Operator_Auth import AccessError
import P01_Report_Export as export
import P01_Executive_Report as executive

VERSION = '0.6.15'
TECHNICAL_DELIVERY_VERSION = '0.6.13'
MAX_ARCHIVE_BYTES = 32 * 1024**2
MAX_SECONDS = 60


class ExportDelivery:
    def __init__(self, auth):
        self.auth = auth
        self._slot = threading.BoundedSemaphore(1)

    @contextmanager
    def build(self, token, assessment, expected_scope_sha256, limit=100, *, kind='technical'):
        # Authorization and query validation precede slot acquisition and any SQL.
        self.auth.require(token, assessment)
        export.report.validate_query(assessment, limit=limit,
                                     expected_scope_sha256=expected_scope_sha256)
        if expected_scope_sha256 is None or not isinstance(kind, str) or kind not in {'technical', 'executive'}:
            raise AccessError('report_input_invalid', 400)
        if not self._slot.acquire(blocking=False):
            raise AccessError('export_busy', 429)
        deadline = time.monotonic() + MAX_SECONDS

        def checkpoint():
            self.auth.require(token, assessment)
            if time.monotonic() > deadline:
                raise AccessError('export_timeout', 503)

        try:
            checkpoint()
            with export.pg.open_connection() as conn:
                doc = export.collect(conn, assessment, limit,
                    expected_scope_sha256=expected_scope_sha256, checkpoint=checkpoint)
            checkpoint()
            if kind == 'executive':
                doc = executive.summarize(doc)
                checkpoint()
                payloads = {'executive.json': executive.bounded_json(doc), 'executive.md': executive.markdown(doc)}
                versions = dict(executive_version=executive.VERSION, delivery_version=VERSION)
            else:
                payloads = {'report.json': export.bounded_json(doc), 'report.md': export.markdown(doc)}
                versions = dict(export_version=export.VERSION, delivery_version=TECHNICAL_DELIVERY_VERSION)
            checkpoint()
            manifest = dict(**versions,
                assessment_id=assessment, report_scope_sha256=expected_scope_sha256,
                files=[dict(name=name, size_bytes=len(raw), sha256=export.pg.digest(raw))
                       for name, raw in payloads.items()])
            payloads['manifest.json'] = export.bounded_json(manifest)
            payloads['manifest.json.sha256'] = (export.pg.digest(payloads['manifest.json']) +
                                              '  manifest.json\n').encode('ascii')
            if sum(map(len, payloads.values())) + 1024 > MAX_ARCHIVE_BYTES:
                raise AccessError('export_limit_exceeded', 413)
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
                for name, raw in payloads.items():
                    checkpoint()
                    member = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                    member.create_system = 3
                    member.external_attr = 0o100600 << 16
                    archive.writestr(member, raw)
            raw = buffer.getvalue()
            if len(raw) > MAX_ARCHIVE_BYTES:
                raise AccessError('export_limit_exceeded', 413)
            checksum = export.pg.digest(raw)
            checkpoint()
            # Retain the slot while the HTTP handler sends the archive.
            yield raw, checksum
        finally:
            self._slot.release()
