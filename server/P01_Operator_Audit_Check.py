#!/usr/bin/env python3
"""Read-only, redacted structural review of private operator audit v1 snapshots."""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

VERSION = '0.6.20'
AUDIT_VERSION = '1'
MAX_BYTES = 8 * 1024**2
MAX_RECORD_BYTES = 1024
MAX_ACTIVE = 8
CORE = frozenset({'audit_version', 'sequence', 'at_utc', 'listener', 'event'})
START = CORE | {'request_id', 'operation'}
FINISH = START | {'http_status', 'outcome', 'operator_id', 'assessment_id'}
OPERATIONS = frozenset({'login', 'logout', 'assessment_directory', 'report_page',
    'executive_preview', 'technical_export', 'executive_export', 'public_asset', 'health', 'other'})
OUTCOMES = frozenset({'response_written', 'delivery_failed', 'handler_failed'})
IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}')
REQUEST_ID = re.compile(r'[0-9a-f]{32}')
SHA = re.compile(r'[0-9a-f]{64}')
UTC = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z')
ERRORS = frozenset({'operator_audit_input_invalid', 'operator_audit_read_failed',
    'operator_audit_structure_invalid', 'operator_audit_digest_conflict'})


class CheckError(ValueError):
    pass


def require(ok, code='operator_audit_structure_invalid'):
    if not ok:
        raise CheckError(code)


def _reparse(info):
    return bool(getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 1024))


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory(path):
    require(path == path.resolve(), 'operator_audit_read_failed')
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and not _reparse(info), 'operator_audit_read_failed')
    if os.name == 'posix':
        require(info.st_uid in {0, os.geteuid()} and not info.st_mode & 0o077,
                'operator_audit_read_failed')
    return info.st_dev, info.st_ino


def read_snapshot(value):
    """Bounded read; timestamps checked exclude atime changed by ordinary reads."""
    fd = None
    try:
        require(isinstance(value, (str, os.PathLike)) and not str(value).startswith(('\\\\', '//')),
                'operator_audit_read_failed')
        path = Path(value).absolute(); parent = _directory(path.parent)
        current = path.lstat()
        require(stat.S_ISREG(current.st_mode) and not _reparse(current), 'operator_audit_read_failed')
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0)
        fd = os.open(path, flags)
        before = os.fstat(fd)
        # Windows path/fd ctime can mean creation/change time respectively.
        # Bind identity/size across APIs, then compare each full stamp to itself.
        require(_stamp(before)[:6] == _stamp(current)[:6] and before.st_nlink == 1
                and 0 < before.st_size <= MAX_BYTES, 'operator_audit_read_failed')
        if os.name == 'posix':
            require(before.st_uid in {0, os.geteuid()} and not before.st_mode & 0o077,
                    'operator_audit_read_failed')
        with os.fdopen(fd, 'rb') as stream:
            fd = None
            raw = stream.read(MAX_BYTES + 1)
            after = os.fstat(stream.fileno())
        require(_stamp(before) == _stamp(after) and _stamp(current) == _stamp(path.lstat())
                and _directory(path.parent) == parent and len(raw) == before.st_size,
                'operator_audit_read_failed')
        return raw
    except Exception:
        raise CheckError('operator_audit_read_failed') from None
    finally:
        if fd is not None:
            try: os.close(fd)
            except Exception: raise CheckError('operator_audit_read_failed') from None


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def _invalid_constant(_):
    raise CheckError('operator_audit_structure_invalid')


def _record(line):
    require(0 < len(line) + 1 <= MAX_RECORD_BYTES and b'\r' not in line)
    row = json.loads(line.decode('ascii'), object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    require(type(row) is dict and type(row.get('event')) is str)
    event = row['event']
    require(event in {'listener_started', 'listener_stopped', 'request_started', 'request_finished'})
    require(set(row) == (START if event == 'request_started' else FINISH if event == 'request_finished' else CORE))
    require(row['audit_version'] == AUDIT_VERSION and type(row['sequence']) is int
            and type(row['at_utc']) is str and UTC.fullmatch(row['at_utc'])
            and row['listener'] in {'api', 'web'})
    datetime.strptime(row['at_utc'], '%Y-%m-%dT%H:%M:%S.%fZ')
    if event.startswith('request_'):
        require(type(row['request_id']) is str and REQUEST_ID.fullmatch(row['request_id'])
                and row['operation'] in OPERATIONS)
    if event == 'request_finished':
        require(row['outcome'] in OUTCOMES and (row['http_status'] is None or
                type(row['http_status']) is int and 100 <= row['http_status'] <= 599))
        require(all(value is None or type(value) is str and IDENTIFIER.fullmatch(value)
                    for value in (row['operator_id'], row['assessment_id']))
                and (row['assessment_id'] is None or row['operator_id'] is not None))
    return row


def review_bytes(raw):
    """Validate complete records only; never echo record fields or partial tail."""
    try:
        require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES)
        lines = raw.split(b'\n'); tail = lines.pop()
        require(len(tail) < MAX_RECORD_BYTES and lines)
        events = {e: 0 for e in ('listener_started', 'request_started', 'request_finished', 'listener_stopped')}
        operations = {op: dict(started=0, finished=0) for op in sorted(OPERATIONS)}
        outcomes = {name: 0 for name in sorted(OUTCOMES)}
        http_classes = {name: 0 for name in ('1xx', '2xx', '3xx', '4xx', '5xx', 'none')}
        pending = {}; seen = set(); listener = None; closed = False
        for sequence, line in enumerate(lines, 1):
            row = _record(line); event = row['event']
            require(row['sequence'] == sequence and not closed)
            if sequence == 1:
                require(event == 'listener_started')
                listener = row['listener']
            else:
                require(event != 'listener_started' and row['listener'] == listener)
            if event == 'request_started':
                request_id = row['request_id']
                require(request_id not in seen and len(pending) < MAX_ACTIVE)
                seen.add(request_id); pending[request_id] = row['operation']
                operations[row['operation']]['started'] += 1
            elif event == 'request_finished':
                require(pending.pop(row['request_id']) == row['operation'])
                operations[row['operation']]['finished'] += 1
                outcomes[row['outcome']] += 1
                status = row['http_status']
                http_classes['none' if status is None else str(status // 100) + 'xx'] += 1
            elif event == 'listener_stopped':
                require(not pending)
                closed = True
            events[event] += 1
        require(not (closed and tail))
        state = 'closed' if closed else 'partial_prefix' if tail else 'open_prefix'
        return dict(status='closed_structure' if closed else 'valid_prefix', version=VERSION,
            audit_version=AUDIT_VERSION, audit_sha256=hashlib.sha256(raw).hexdigest(),
            size_bytes=len(raw), state=state, listener=listener, valid_records=len(lines),
            partial_tail_bytes=len(tail), unfinished_requests=len(pending), events=events,
            operations=operations, outcomes=outcomes, http_classes=http_classes)
    except Exception:
        raise CheckError('operator_audit_structure_invalid') from None


def inspect_log(path, expected_sha256=None):
    if expected_sha256 is not None:
        require(type(expected_sha256) is str and SHA.fullmatch(expected_sha256), 'operator_audit_input_invalid')
    raw = read_snapshot(path)
    require(expected_sha256 is None or hashlib.sha256(raw).hexdigest() == expected_sha256,
            'operator_audit_digest_conflict')
    return review_bytes(raw)


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise CheckError('operator_audit_input_invalid')


def cli(argv=None):
    try:
        arguments = list(sys.argv[1:] if argv is None else argv)
        options = [arg.split('=', 1)[0] for arg in arguments if arg.startswith('--')]
        require(len(options) == len(set(options)), 'operator_audit_input_invalid')
        parser = _Parser(description='Revisar estrutura de auditoria privada, sem alterar registros.', allow_abbrev=False)
        parser.add_argument('--audit-file', required=True)
        parser.add_argument('--expected-sha256')
        args = parser.parse_args(arguments)
        result = inspect_log(args.audit_file, args.expected_sha256)
        print(json.dumps(result, sort_keys=True, allow_nan=False))
        return 0 if result['state'] == 'closed' else 3
    except (Exception, KeyboardInterrupt) as error:
        code = str(error) if isinstance(error, CheckError) and str(error) in ERRORS else 'operator_audit_input_invalid'
        print(json.dumps(dict(status='failed', version=VERSION, error_code=code)))
        return 2


if __name__ == '__main__':
    raise SystemExit(cli())
