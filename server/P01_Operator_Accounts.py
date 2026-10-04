#!/usr/bin/env python3
"""Inspect private operator policies and publish explicit offline revisions."""
from __future__ import annotations

import argparse
from copy import deepcopy
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

import P01_Operator_Auth as auth

VERSION = '0.6.18'
SHA = re.compile(r'[0-9a-f]{64}')
CHANGES = {'add', 'set-grants', 'enable', 'disable', 'rotate-password'}
ERRORS = {'operator_policy_input_invalid', 'operator_policy_read_failed',
          'operator_policy_base_conflict', 'operator_policy_write_failed'}


class PolicyError(ValueError):
    pass


def require(ok, code='operator_policy_input_invalid'):
    if not ok:
        raise PolicyError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _reparse(info):
    return bool(getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 1024))


def _identity(info):
    return info.st_dev, info.st_ino


def _stamp(info):
    return (_identity(info), info.st_mode, info.st_uid, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _path(value):
    require(isinstance(value, (str, os.PathLike)) and not str(value).startswith(('\\\\', '//')))
    path = Path(value).absolute()
    require(path.parent == path.parent.resolve())
    return path


def _directory(path, *, private=False, code='operator_policy_input_invalid'):
    require(path == path.resolve(), code)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and not _reparse(info), code)
    if os.name == 'posix':
        require(info.st_uid in {0, os.geteuid()} and not info.st_mode & (0o077 if private else 0o022), code)
    return _identity(info)


def read_snapshot(value):
    fd = None
    try:
        path = _path(value); _directory(path.parent)
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        before = os.fstat(fd); current = path.lstat()
        require(stat.S_ISREG(before.st_mode) and not _reparse(before) and not _reparse(current)
                and _identity(before) == _identity(current) and before.st_nlink == 1
                and 0 < before.st_size <= auth.MAX_POLICY_BYTES, 'operator_policy_read_failed')
        if os.name == 'posix':
            require(not before.st_mode & 0o077 and before.st_uid in {0, os.geteuid()}, 'operator_policy_read_failed')
        with os.fdopen(fd, 'rb') as stream:
            fd = None
            raw = stream.read(auth.MAX_POLICY_BYTES + 1)
            after = os.fstat(stream.fileno())
        require(_stamp(before) == _stamp(after) and _identity(after) == _identity(path.lstat())
                and len(raw) == before.st_size, 'operator_policy_read_failed')
        auth.AccountPolicy(raw)
        doc = json.loads(raw.decode('utf-8'), object_pairs_hook=auth.unique_object)
        return path, raw, doc, _stamp(before)
    except Exception:
        raise PolicyError('operator_policy_read_failed') from None
    finally:
        if fd is not None:
            os.close(fd)


def inspect_policy(path):
    _, raw, doc, _ = read_snapshot(path)
    return dict(status='inspected', version=VERSION, policy_version=doc['policy_version'],
        policy_sha256=digest(raw), account_count=len(doc['accounts']),
        accounts=[dict(operator_id=row['operator_id'], username=row['username'], enabled=row['enabled'],
            assessment_ids=sorted(g['assessment_id'] for g in row['grants']))
            for row in sorted(doc['accounts'], key=lambda row: row['username'].lower())])


def _scopes(values):
    require(isinstance(values, (list, tuple)) and len(values) <= auth.MAX_GRANTS)
    scopes = [auth.identifier(value) for value in values]
    require(len(set(scopes)) == len(scopes))
    return sorted(scopes)


def _destination(value, source):
    try:
        path = _path(value); identity = _directory(path.parent, private=True)
        require(path != source and not os.path.lexists(path), 'operator_policy_write_failed')
        return path, identity
    except Exception:
        raise PolicyError('operator_policy_write_failed') from None


def _same_source(path, raw, stamp):
    _, now, _, now_stamp = read_snapshot(path)
    require(now == raw and now_stamp == stamp, 'operator_policy_base_conflict')


def _remove_owned(path, identity):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISREG(info.st_mode) and _identity(info) == identity:
        path.unlink()


def _publish(path, raw, parent_identity, checkpoint):
    stage = None; identity = None
    try:
        try:
            fd, name = tempfile.mkstemp(prefix='.canca-accounts-', suffix='.tmp', dir=path.parent)
            stage = Path(name)
            with os.fdopen(fd, 'wb') as stream:
                identity = _identity(os.fstat(stream.fileno()))
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            checkpoint()
            # Confirm the owned stage and private parent immediately before linking.
            stage_info = stage.lstat()
            require(stat.S_ISREG(stage_info.st_mode) and stage_info.st_nlink == 1 and not _reparse(stage_info)
                    and _identity(stage_info) == identity
                    and _directory(path.parent, private=True, code='operator_policy_write_failed') == parent_identity,
                    'operator_policy_write_failed')
            link_options = {'follow_symlinks': False} if os.link in os.supports_follow_symlinks else {}
            os.link(stage, path, **link_options)  # Exclusive publication of the checked regular stage.
            _remove_owned(stage, identity); stage = None
            if os.name == 'posix':
                directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0))
                try: os.fsync(directory_fd)
                finally: os.close(directory_fd)
        finally:
            if stage is not None and identity is not None:
                _remove_owned(stage, identity)
    except PolicyError:
        raise
    except Exception:
        raise PolicyError('operator_policy_write_failed') from None


def _password():
    require(os.isatty(0))
    password = getpass.getpass('Nova senha (15–256 caracteres): ')
    confirmation = getpass.getpass('Confirme a senha: ')
    require(password == confirmation)
    return auth.password_record(password)


def revise_policy(source, output, expected_sha256, change, username, *, operator_id=None, assessments=None, clear_grants=False):
    require(isinstance(expected_sha256, str) and SHA.fullmatch(expected_sha256) and change in CHANGES)
    username = auth.identifier(username)
    source, original, doc, stamp = read_snapshot(source)
    require(digest(original) == expected_sha256, 'operator_policy_base_conflict')
    destination, parent_identity = _destination(output, source)
    rows = deepcopy(doc['accounts']); matches = [row for row in rows if row['username'].lower() == username.lower()]
    if change == 'add':
        operator_id = auth.identifier(operator_id); scopes = _scopes(assessments)
        require(scopes and not matches and len(rows) < auth.MAX_ACCOUNTS
                and all(row['operator_id'] != operator_id for row in rows) and not clear_grants)
        row = dict(operator_id=operator_id, username=username, enabled=True, password=_password(),
                   grants=[dict(assessment_id=a, permissions=['assessment:read']) for a in scopes])
        rows.append(row)
    else:
        require(len(matches) == 1 and operator_id is None)
        row = matches[0]
        if change == 'set-grants':
            require(type(clear_grants) is bool and ((clear_grants and assessments is None)
                    or (not clear_grants and isinstance(assessments, (list, tuple)) and len(assessments) > 0)))
            scopes = [] if clear_grants else _scopes(assessments)
            require(set(scopes) != {g['assessment_id'] for g in row['grants']})
            row['grants'] = [dict(assessment_id=a, permissions=['assessment:read']) for a in scopes]
        else:
            require(assessments is None and clear_grants is False)
            if change == 'rotate-password': row['password'] = _password()
            else:
                enabled = change == 'enable'
                require(row['enabled'] != enabled); row['enabled'] = enabled
    raw = (json.dumps(dict(policy_version='1', accounts=rows), ensure_ascii=False, sort_keys=True,
                      indent=2, allow_nan=False) + '\n').encode('utf-8')
    auth.AccountPolicy(raw)
    _publish(destination, raw, parent_identity, lambda: _same_source(source, original, stamp))
    return dict(status='revision_created', version=VERSION, policy_version='1', change=change,
                operator_id=row['operator_id'], username=row['username'], account_count=len(rows),
                source_policy_sha256=expected_sha256, policy_sha256=digest(raw),
                restart_required=True, live_sessions_updated=False)


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise PolicyError('operator_policy_input_invalid')


def cli(argv=None):
    try:
        parser = Parser(description='Cancã private offline operator account revisions v' + VERSION, allow_abbrev=False)
        parser.add_argument('--policy', required=True)
        commands = parser.add_subparsers(dest='change', required=True)
        commands.add_parser('inspect', allow_abbrev=False)
        for change in sorted(CHANGES):
            command = commands.add_parser(change, allow_abbrev=False)
            command.add_argument('--output', required=True)
            command.add_argument('--expected-policy-sha256', required=True)
            command.add_argument('--username', required=True)
            if change == 'add':
                command.add_argument('--operator-id', required=True)
                command.add_argument('--assessment-id', action='append', required=True)
            elif change == 'set-grants':
                group = command.add_mutually_exclusive_group(required=True)
                group.add_argument('--assessment-id', action='append')
                group.add_argument('--clear-grants', action='store_true')
        args = parser.parse_args(argv)
        result = inspect_policy(args.policy) if args.change == 'inspect' else revise_policy(args.policy, args.output,
            args.expected_policy_sha256, args.change, args.username, operator_id=getattr(args, 'operator_id', None),
            assessments=getattr(args, 'assessment_id', None), clear_grants=getattr(args, 'clear_grants', False))
        print(json.dumps(result, ensure_ascii=False, allow_nan=False)); return 0
    except (Exception, KeyboardInterrupt) as error:
        code = str(error) if isinstance(error, PolicyError) and str(error) in ERRORS else 'operator_policy_input_invalid'
        print(json.dumps(dict(status='failed', version=VERSION, error_code=code))); return 2


if __name__ == '__main__':
    raise SystemExit(cli())
