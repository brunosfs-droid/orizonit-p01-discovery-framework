#!/usr/bin/env python3
"""Local human principals; private startup grants and bounded opaque sessions."""
from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass, field
import getpass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time
from types import MappingProxyType

VERSION = '0.6.11'
MAX_POLICY_BYTES = 65536
MAX_ACCOUNTS = 128
MAX_GRANTS = 128
MAX_SESSIONS = 128
SESSION_SECONDS = 900
FAILURE_WINDOW = 300
MAX_FAILURES = 5
MAX_LOGIN_ATTEMPTS = 20
LOGIN_WINDOW = 60
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}')
TOKEN = re.compile(r'[A-Za-z0-9_-]{43}')
SCHEME = 'scrypt-32768-8-3-v1'


class AccessError(ValueError):
    def __init__(self, code, status=401):
        super().__init__(code)
        self.status = status


def unique_object(pairs):
    doc = {}
    for key, value in pairs:
        if key in doc:
            raise ValueError('duplicate key')
        doc[key] = value
    return doc


def identifier(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ValueError('invalid identifier')
    return value


def password_bytes(password):
    if not isinstance(password, str) or not 15 <= len(password) <= 256:
        raise ValueError('invalid password length')
    raw = password.encode('utf-8')
    if len(raw) > 1024:
        raise ValueError('invalid password length')
    return raw


def derive(password, salt):
    return hashlib.scrypt(password, salt=salt, n=32768, r=8, p=3,
                          dklen=32, maxmem=64 * 1024 * 1024)


def password_record(password):
    raw = password_bytes(password)
    salt = secrets.token_bytes(16)
    return dict(scheme=SCHEME, salt=salt.hex(), hash=derive(raw, salt).hex())


@dataclass(frozen=True, repr=False)
class Account:
    operator_id: str
    enabled: bool
    salt: bytes = field(repr=False)
    password_hash: bytes = field(repr=False)
    assessments: frozenset


class AccountPolicy:
    __slots__ = ('accounts',)

    def __init__(self, raw):
        try:
            if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_POLICY_BYTES:
                raise ValueError('invalid size')
            doc = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object)
            if not isinstance(doc, dict) or set(doc) != {'policy_version', 'accounts'} or doc['policy_version'] != '1':
                raise ValueError('invalid root')
            rows = doc['accounts']
            if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_ACCOUNTS:
                raise ValueError('invalid accounts')
            accounts = {}; operators = set()
            for row in rows:
                if not isinstance(row, dict) or set(row) != {'operator_id', 'username', 'enabled', 'password', 'grants'}:
                    raise ValueError('invalid account')
                operator = identifier(row['operator_id']); username = identifier(row['username']).lower()
                if operator in operators or username in accounts or type(row['enabled']) is not bool:
                    raise ValueError('duplicate/invalid account')
                password = row['password']
                if not isinstance(password, dict) or set(password) != {'scheme', 'salt', 'hash'} or password['scheme'] != SCHEME:
                    raise ValueError('invalid hash')
                if not isinstance(password['salt'], str) or not re.fullmatch(r'[0-9a-f]{32}', password['salt']):
                    raise ValueError('invalid salt')
                if not isinstance(password['hash'], str) or not re.fullmatch(r'[0-9a-f]{64}', password['hash']):
                    raise ValueError('invalid hash')
                grants = row['grants']
                if not isinstance(grants, list) or len(grants) > MAX_GRANTS:
                    raise ValueError('invalid grants')
                scopes = set()
                for grant in grants:
                    if not isinstance(grant, dict) or set(grant) != {'assessment_id', 'permissions'}:
                        raise ValueError('invalid grant')
                    assessment = identifier(grant['assessment_id'])
                    if assessment in scopes or grant['permissions'] != ['assessment:read']:
                        raise ValueError('invalid permission')
                    scopes.add(assessment)
                accounts[username] = Account(operator, row['enabled'], bytes.fromhex(password['salt']),
                                             bytes.fromhex(password['hash']), frozenset(scopes))
                operators.add(operator)
            object.__setattr__(self, 'accounts', MappingProxyType(accounts))
        except (ValueError, TypeError, UnicodeError, RecursionError, KeyError):
            raise ValueError('invalid operator account policy') from None

    def __setattr__(self, name, value):
        raise AttributeError('operator account policy is immutable')

    def __delattr__(self, name):
        raise AttributeError('operator account policy is immutable')


def load_policy(path):
    fd = None
    try:
        path = Path(path)
        if path.parent.absolute() != path.parent.resolve():
            raise ValueError('invalid parent')
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_POLICY_BYTES:
            raise ValueError('invalid file')
        if os.name == 'posix' and (info.st_mode & 0o077 or info.st_uid not in {0, os.geteuid()}):
            raise ValueError('private file required')
        with os.fdopen(fd, 'rb') as stream:
            fd = None
            return AccountPolicy(stream.read(MAX_POLICY_BYTES + 1))
    except (OSError, ValueError, TypeError):
        raise ValueError('invalid operator account policy') from None
    finally:
        if fd is not None:
            os.close(fd)


class LocalAuth:
    def __init__(self, policy, *, clock=time.monotonic):
        if not isinstance(policy, AccountPolicy):
            raise ValueError('validated operator policy required')
        self.policy = policy
        self.clock = clock
        self._lock = threading.RLock()
        self._sessions = {}
        self._failures = {}
        self._attempts = deque()
        self._dummy_salt = secrets.token_bytes(16)
        self._dummy_hash = derive(secrets.token_bytes(32), self._dummy_salt)

    def _prune(self, now):
        self._sessions = {key: value for key, value in self._sessions.items() if value[1] > now}
        self._failures = {key: value for key, value in self._failures.items() if value[1] > now}
        while self._attempts and self._attempts[0] <= now - LOGIN_WINDOW:
            self._attempts.popleft()

    def login(self, username, password):
        try:
            key = identifier(username).lower()
            raw = password_bytes(password)
        except (ValueError, UnicodeError):
            raise AccessError('invalid_credentials') from None
        with self._lock:
            now = self.clock(); self._prune(now)
            account = self.policy.accounts.get(key)
            bucket = key if account else None
            failures = self._failures.get(bucket, (0, now + FAILURE_WINDOW))
            if len(self._attempts) >= MAX_LOGIN_ATTEMPTS or failures[0] >= MAX_FAILURES:
                raise AccessError('login_throttled', 429)
            self._attempts.append(now)
            salt = account.salt if account else self._dummy_salt
            expected = account.password_hash if account else self._dummy_hash
            valid = hmac.compare_digest(derive(raw, salt), expected)
            if not valid or account is None or not account.enabled:
                self._failures[bucket] = (failures[0] + 1, failures[1])
                raise AccessError('invalid_credentials')
            if len(self._sessions) >= MAX_SESSIONS:
                raise AccessError('session_capacity', 503)
            self._failures.pop(bucket, None)
            token = secrets.token_urlsafe(32)
            self._sessions[hashlib.sha256(token.encode('ascii')).digest()] = (account, self.clock() + SESSION_SECONDS)
            return dict(access_token=token, token_type='Bearer', expires_in=SESSION_SECONDS,
                        operator_id=account.operator_id)

    def _session(self, token):
        if not isinstance(token, str) or not TOKEN.fullmatch(token):
            raise AccessError('authentication_required')
        self._prune(self.clock())
        key = hashlib.sha256(token.encode('ascii')).digest()
        session = self._sessions.get(key)
        if session is None:
            raise AccessError('authentication_required')
        return key, session[0]

    def require(self, token, assessment_id):
        with self._lock:
            _, account = self._session(token)
            if not isinstance(assessment_id, str) or assessment_id not in account.assessments:
                raise AccessError('assessment_access_denied', 403)
            return account.operator_id

    def logout(self, token):
        with self._lock:
            key, _ = self._session(token)
            del self._sessions[key]


def create_policy(path, operator_id, username, assessments, password):
    operator_id = identifier(operator_id); username = identifier(username)
    scopes = [identifier(a) for a in assessments]
    if not scopes or len(scopes) != len(set(scopes)):
        raise ValueError('invalid assessments')
    record = password_record(password)
    doc = dict(policy_version='1', accounts=[dict(operator_id=operator_id, username=username,
        enabled=True, password=record,
        grants=[dict(assessment_id=a, permissions=['assessment:read']) for a in scopes])])
    raw = (json.dumps(doc, ensure_ascii=False, indent=2) + '\n').encode()
    AccountPolicy(raw)
    path = Path(path)
    if path.parent.absolute() != path.parent.resolve():
        raise ValueError('invalid parent')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def cli(argv=None):
    parser = argparse.ArgumentParser(description='Create a private local operator policy (never overwrites)')
    parser.add_argument('--policy', required=True)
    parser.add_argument('--operator-id', required=True)
    parser.add_argument('--username', required=True)
    parser.add_argument('--assessment-id', action='append', required=True)
    args = parser.parse_args(argv)
    try:
        if not os.isatty(0):
            raise ValueError('interactive terminal required')
        password = getpass.getpass('Nova senha (15–256 caracteres): ')
        confirmation = getpass.getpass('Confirme a senha: ')
        if password != confirmation:
            raise ValueError('password mismatch')
        create_policy(args.policy, args.operator_id, args.username, args.assessment_id, password)
        print(json.dumps(dict(status='created',version=VERSION)))
        return 0
    except (OSError, ValueError, UnicodeError, EOFError):
        print(json.dumps(dict(status='failed',error_code='operator_policy_creation_failed')))
        return 2


if __name__ == '__main__':
    raise SystemExit(cli())
