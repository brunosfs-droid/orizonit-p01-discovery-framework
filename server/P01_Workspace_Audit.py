#!/usr/bin/env python3
"""Opt-in private workspace HTTP audit with fixed redacted metadata."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
from urllib.parse import urlsplit

VERSION = '0.6.29'
AUDIT_VERSION = '1'
MAX_BYTES = 8 * 1024**2
MAX_RECORD_BYTES = 1024
MAX_ACTIVE = 8
OPERATIONS = frozenset({
    'login', 'logout', 'health', 'workspace_directory', 'workspace_open',
    'workspace_close', 'object_list', 'object_read', 'graph_read',
    'category_coverage', 'category_signal_coverage', 'observed_signals', 'signal_summary', 'signal_quality', 'observation_comparison', 'object_declare', 'declaration_write', 'relationship_write',
    'import_preview', 'import_apply', 'legacy_preview', 'legacy_apply',
    'historical_report', 'other',
})
OUTCOMES = frozenset({'response_written', 'delivery_failed', 'handler_failed'})
IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}')
RESOURCE = re.compile(
    r'/api/v1/workspaces/[A-Za-z0-9][A-Za-z0-9._-]{0,127}/'
    r'(?P<route>open|close|categories/(?:compute|network|services|components)(?:/(?:coverage|signal-coverage))?|objects|objects/[A-Za-z0-9][A-Za-z0-9._-]{0,127}(?:/signals(?:/(?:summary|quality|comparison))?)?|'
    r'graph/[A-Za-z0-9][A-Za-z0-9._-]{0,127}|declarations|relationships|'
    r'imports/preview|imports/apply|legacy/preview|legacy/apply|'
    r'legacy/bnd-[0-9a-f]{20}/report)'
)


class AuditError(ValueError):
    def __init__(self):
        super().__init__('workspace_audit_unavailable')


class _Capacity(AuditError):
    pass


def require(ok):
    if not ok:
        raise AuditError()


def operation(method, target):
    """Classify an untrusted route without copying route/query values into output."""
    try:
        if not isinstance(target, str) or len(target) > 2048:
            return 'other'
        route = urlsplit(target).path
        if route == '/api/v1/operator/session':
            return {'POST': 'login', 'DELETE': 'logout'}.get(method, 'other')
        if method == 'GET' and route == '/healthz':
            return 'health'
        if method == 'GET' and route == '/api/v1/workspaces':
            return 'workspace_directory'
        match = RESOURCE.fullmatch(route)
        if not match:
            return 'other'
        item = match['route']
        if item == 'open':
            return 'workspace_open' if method == 'POST' else 'other'
        if item == 'close':
            return 'workspace_close' if method == 'POST' else 'other'
        if item.startswith('categories/'):
            return ('category_signal_coverage' if item.endswith('/signal-coverage') else 'category_coverage' if item.endswith('/coverage') else 'category_read') if method == 'GET' else 'other'
        if item == 'objects':
            return {'GET': 'object_list', 'POST': 'object_declare'}.get(method, 'other')
        if item.startswith('objects/'):
            return ('observation_comparison' if item.endswith('/signals/comparison') else 'signal_quality' if item.endswith('/signals/quality') else 'signal_summary' if item.endswith('/signals/summary') else 'observed_signals' if item.endswith('/signals') else 'object_read') if method == 'GET' else 'other'
        if item.startswith('graph/'):
            return 'graph_read' if method == 'GET' else 'other'
        if item == 'declarations':
            return 'declaration_write' if method == 'POST' else 'other'
        if item == 'relationships':
            return 'relationship_write' if method == 'POST' else 'other'
        if item == 'imports/preview':
            return 'import_preview' if method == 'POST' else 'other'
        if item == 'imports/apply':
            return 'import_apply' if method == 'POST' else 'other'
        if item == 'legacy/preview':
            return 'legacy_preview' if method == 'POST' else 'other'
        if item == 'legacy/apply':
            return 'legacy_apply' if method == 'POST' else 'other'
        if item.startswith('legacy/') and item.endswith('/report'):
            return 'historical_report' if method == 'GET' else 'other'
    except (ValueError, TypeError):
        pass
    return 'other'


def _identity(info):
    return info.st_dev, info.st_ino


def _stamp(info):
    return (
        _identity(info), info.st_mode, info.st_uid, info.st_nlink, info.st_size,
        info.st_mtime_ns, info.st_ctime_ns,
    )


def _reparse(info):
    return bool(
        getattr(info, 'st_file_attributes', 0)
        & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 1024)
    )


def _directory(path):
    require(path == path.resolve())
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and not _reparse(info))
    if os.name == 'posix':
        require(info.st_uid in {0, os.geteuid()} and not info.st_mode & 0o077)
    return _identity(info)


class FileAudit:
    """One listener owns one exclusive file; failure latches until controlled restart."""

    def __init__(self, path, *, max_bytes=MAX_BYTES):
        self._fd = None
        self._closed = False
        self._failed = False
        self._full = False
        self._lock = threading.RLock()
        self._pending = {}
        self._size = 0
        self._sequence = 0
        try:
            require(type(max_bytes) is int and 4096 <= max_bytes <= MAX_BYTES)
            require(
                isinstance(path, (str, os.PathLike))
                and not str(path).startswith(('\\\\', '//'))
            )
            self.path = Path(path).absolute()
            self.listener = 'workspace'
            self._limit = max_bytes
            self._parent = _directory(self.path.parent)
            flags = (
                os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
            )
            self._fd = os.open(self.path, flags, 0o600)
            self._stamp = _stamp(os.fstat(self._fd))
            self._append('listener_started', reserve=MAX_RECORD_BYTES)
            self._sync_directory()
        except Exception:
            if self._fd is not None:
                os.close(self._fd)
            self._closed = True
            raise AuditError() from None

    def _check(self):
        require(not self._closed and not self._failed)
        info = os.fstat(self._fd)
        current = self.path.lstat()
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and not _reparse(info)
            and not _reparse(current)
            and _identity(info) == _identity(current)
            and info.st_size == self._size
            and _stamp(info) == self._stamp
            and _directory(self.path.parent) == self._parent
        )
        if os.name == 'posix':
            require(info.st_uid in {0, os.geteuid()} and not info.st_mode & 0o077)

    def _append(self, event, *, reserve=0, **fields):
        try:
            self._check()
            record = dict(
                audit_version=AUDIT_VERSION,
                sequence=self._sequence + 1,
                at_utc=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                listener=self.listener,
                event=event,
                **fields,
            )
            raw = (
                json.dumps(
                    record, ensure_ascii=True, sort_keys=True,
                    separators=(',', ':'), allow_nan=False,
                ) + '\n'
            ).encode('ascii')
            require(len(raw) <= MAX_RECORD_BYTES)
            if self._size + len(raw) + reserve > self._limit:
                self._full = True
                raise _Capacity()
            offset = 0
            while offset < len(raw):
                written = os.write(self._fd, raw[offset:])
                require(type(written) is int and 0 < written <= len(raw) - offset)
                offset += written
            os.fsync(self._fd)
            info = os.fstat(self._fd)
            self._size += len(raw)
            self._stamp = _stamp(info)
            self._check()
            self._sequence += 1
        except _Capacity:
            raise
        except Exception:
            self._failed = True
            raise AuditError() from None

    def begin(self, label):
        with self._lock:
            require(
                not self._full
                and isinstance(label, str)
                and label in OPERATIONS
                and len(self._pending) < MAX_ACTIVE
            )
            request_id = secrets.token_hex(16)
            require(request_id not in self._pending)
            self._append(
                'request_started',
                request_id=request_id,
                operation=label,
                reserve=(len(self._pending) + 2) * MAX_RECORD_BYTES,
            )
            self._pending[request_id] = label
            return request_id

    def finish(
        self, request_id, *, http_status, outcome,
        operator_id=None, workspace_id=None,
    ):
        with self._lock:
            try:
                require(
                    request_id in self._pending
                    and outcome in OUTCOMES
                    and (
                        http_status is None
                        or type(http_status) is int and 100 <= http_status <= 599
                    )
                )
                require(
                    all(
                        value is None
                        or isinstance(value, str) and IDENTIFIER.fullmatch(value)
                        for value in (operator_id, workspace_id)
                    )
                    and (workspace_id is None or operator_id is not None)
                )
                self._append(
                    'request_finished',
                    request_id=request_id,
                    operation=self._pending[request_id],
                    http_status=http_status,
                    outcome=outcome,
                    operator_id=operator_id,
                    workspace_id=workspace_id,
                    reserve=len(self._pending) * MAX_RECORD_BYTES,
                )
                del self._pending[request_id]
            except Exception:
                self._failed = True
                raise AuditError() from None

    def _sync_directory(self):
        if os.name == 'posix':
            fd = os.open(
                self.path.parent,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0),
            )
            try:
                os.fsync(fd)
            finally:
                os.close(fd)

    def close(self):
        with self._lock:
            if self._closed:
                return
            try:
                require(not self._pending)
                self._append('listener_stopped')
                self._sync_directory()
            except Exception:
                self._failed = True
                raise AuditError() from None
            finally:
                self._closed = True
                try:
                    os.close(self._fd)
                except Exception:
                    raise AuditError() from None
