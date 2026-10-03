"""Real scrypt, strict startup grants and bounded local operator sessions."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server'))
import P01_Operator_Auth as auth

PASSWORD = 'Synthetic LAB passphrase 01!'
RECORD = auth.password_record(PASSWORD)


def document():
    return dict(policy_version='1', accounts=[dict(operator_id='OP-01', username='reader', enabled=True,
        password=copy.deepcopy(RECORD), grants=[dict(assessment_id='LAB-001', permissions=['assessment:read'])])])


def policy(doc=None):
    return auth.AccountPolicy(json.dumps(document() if doc is None else doc).encode())


class OperatorAuthTests(unittest.TestCase):
    def test_real_password_salt_and_no_truncation(self):
        second = auth.password_record(PASSWORD)
        self.assertNotEqual(RECORD['salt'], second['salt'])
        self.assertNotEqual(RECORD['hash'], second['hash'])
        record = auth.password_record(' ação ' * 12)
        self.assertEqual(bytes.fromhex(record['hash']), auth.derive((' ação ' * 12).encode(), bytes.fromhex(record['salt'])))
        for password in ('short', 'a' * 257, None, '\ud800' * 15):
            with self.assertRaises((ValueError, UnicodeError)):
                auth.password_record(password)

    def test_invalid_unknown_and_disabled_login_fixed(self):
        docs = [document(), document()]
        docs[1]['accounts'][0]['enabled'] = False
        for doc, username, password in [(docs[0], 'reader', PASSWORD+'wrong'),
                                        (docs[0], 'unknown', PASSWORD), (docs[1], 'reader', PASSWORD)]:
            with self.assertRaisesRegex(auth.AccessError, '^invalid_credentials$'):
                auth.LocalAuth(policy(doc)).login(username, password)

    def test_exact_grant_case_sensitive_assessment_and_logout(self):
        service = auth.LocalAuth(policy())
        result = service.login('READER', PASSWORD); token = result['access_token']
        self.assertEqual(result['operator_id'], 'OP-01')
        self.assertEqual(service.require(token, 'LAB-001'), 'OP-01')
        for scope in ['lab-001', 'LAB-002', '*', None]:
            with self.assertRaises(auth.AccessError) as exc:
                service.require(token, scope)
            self.assertEqual(exc.exception.status, 403)
        self.assertNotIn(token, repr(service._sessions))
        service.logout(token)
        with self.assertRaises(auth.AccessError): service.require(token, 'LAB-001')
        with self.assertRaises(auth.AccessError): service.logout(token)

    def test_expiry_and_new_instance_revoke_old_tokens(self):
        now = [100.0]; service = auth.LocalAuth(policy(), clock=lambda: now[0])
        token = service.login('reader', PASSWORD)['access_token']
        now[0] += auth.SESSION_SECONDS - 1; service.require(token, 'LAB-001')
        with self.assertRaises(auth.AccessError): auth.LocalAuth(policy()).require(token, 'LAB-001')
        now[0] += 1
        with self.assertRaises(auth.AccessError): service.require(token, 'LAB-001')
        self.assertEqual(service._sessions, {})

    def test_failure_window_unknown_bucket_and_global_attempt_bound(self):
        now = [100.0]; service = auth.LocalAuth(policy(), clock=lambda: now[0])
        for i in range(auth.MAX_FAILURES):
            with self.assertRaisesRegex(auth.AccessError, 'invalid_credentials'):
                service.login('unknown-'+str(i), PASSWORD)
        with self.assertRaises(auth.AccessError) as exc: service.login('unknown-new', PASSWORD)
        self.assertEqual(exc.exception.status, 429); self.assertEqual(len(service._failures), 1)
        now[0] += auth.FAILURE_WINDOW
        with self.assertRaisesRegex(auth.AccessError, 'invalid_credentials'): service.login('unknown', PASSWORD)
        for _ in range(auth.MAX_LOGIN_ATTEMPTS - 1): service.login('reader', PASSWORD)
        with self.assertRaisesRegex(auth.AccessError, 'login_throttled'): service.login('reader', PASSWORD)
        self.assertEqual(len(service._attempts), auth.MAX_LOGIN_ATTEMPTS)

    def test_session_capacity_does_not_evict_active_sessions(self):
        service = auth.LocalAuth(policy())
        with patch.object(auth, 'MAX_SESSIONS', 1):
            token = service.login('reader', PASSWORD)['access_token']
            with self.assertRaisesRegex(auth.AccessError, 'session_capacity'): service.login('reader', PASSWORD)
            service.require(token, 'LAB-001')

    def test_malformed_and_duplicate_policy_fixed_and_no_unknown_permissions(self):
        docs = [None, [], {}, {'policy_version': True, 'accounts': []}]
        for key, value in [('operator_id', '*'), ('username', '../PRIVATE'), ('enabled', 1), ('grants', {}), ('extra', 'PRIVATE')]:
            doc = document(); doc['accounts'][0][key] = value; docs.append(doc)
        for key, value in [('scheme', 'fast-sha256'), ('salt', 'A'*32), ('hash', 'bad'), ('extra', 'PRIVATE')]:
            doc = document(); doc['accounts'][0]['password'][key] = value; docs.append(doc)
        for grants in [[dict(assessment_id='*', permissions=['assessment:read'])],
                       [dict(assessment_id='LAB-001', permissions=['admin'])],
                       [dict(assessment_id='LAB-001', permissions=['assessment:read','assessment:read'])],
                       document()['accounts'][0]['grants'] * 2]:
            doc = document(); doc['accounts'][0]['grants'] = grants; docs.append(doc)
        duplicate = document(); duplicate['accounts'] *= 2; docs.append(duplicate)
        for doc in docs:
            with self.subTest(doc=doc), self.assertRaisesRegex(ValueError, '^invalid operator account policy$'):
                auth.AccountPolicy(json.dumps(doc).encode())
        for raw in [b'', b'PRIVATE', b'\xff', b' '*65537, b'{"accounts":[],"accounts":[],"policy_version":"1"}']:
            with self.assertRaisesRegex(ValueError, '^invalid operator account policy$'): auth.AccountPolicy(raw)

    def test_policy_and_nested_accounts_immutable(self):
        p = policy()
        with self.assertRaises(AttributeError): p.accounts = {}
        with self.assertRaises(AttributeError): del p.accounts
        with self.assertRaises(TypeError): p.accounts['new'] = p.accounts['reader']
        with self.assertRaises(AttributeError): p.accounts['reader'].enabled = False

    def test_private_creation_no_overwrite_or_plaintext_and_bounded_loader(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'accounts.json'
            auth.create_policy(path, 'OP-01', 'reader', ['LAB-001'], PASSWORD)
            before = path.read_bytes(); self.assertNotIn(PASSWORD.encode(), before)
            auth.load_policy(path)
            with self.assertRaises(FileExistsError): auth.create_policy(path, 'OP-02', 'other', ['LAB-002'], PASSWORD)
            self.assertEqual(before, path.read_bytes())
            alias = Path(tmp)/'alias'
            if hasattr(os, 'O_NOFOLLOW'):
                alias.symlink_to(path)
                with self.assertRaises(ValueError): auth.load_policy(alias)
            if os.name == 'posix':
                path.chmod(0o644)
                with self.assertRaises(ValueError): auth.load_policy(path)
                path.chmod(0o600)
            path.write_bytes(b' '*65537)
            with self.assertRaises(ValueError): auth.load_policy(path)
            with self.assertRaises(ValueError): auth.load_policy(Path(tmp))


if __name__ == '__main__':
    unittest.main()
