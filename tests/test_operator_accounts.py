"""Private offline policy revisions: real auth, exclusive files and fixed errors."""
from contextlib import redirect_stdout, redirect_stderr
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server'))
import P01_Operator_Accounts as accounts
import test_operator_auth as fixture

auth = accounts.auth
PASSWORD = fixture.PASSWORD
NEW_PASSWORD = 'New synthetic CI passphrase 02!'


class OperatorAccountRevisionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='canca-account-ci-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve(); self.source = self.root / 'accounts.json'
        self.doc = fixture.document(); self.save_source(self.doc)

    def save_source(self, doc):
        raw = json.dumps(doc).encode('utf-8'); self.source.write_bytes(raw)
        if os.name == 'posix': self.source.chmod(0o600)
        self.raw = raw; self.sha = accounts.digest(raw)

    def revise(self, change, username='reader', output=None, **kwargs):
        target = self.root / 'revision.json' if output is None else output
        prior_stages = set(self.root.glob('.canca-accounts-*.tmp'))
        result = accounts.revise_policy(self.source, target, self.sha, change, username, **kwargs)
        self.assertEqual(self.source.read_bytes(), self.raw)
        self.assertEqual(result['source_policy_sha256'], self.sha)
        self.assertEqual(result['policy_sha256'], accounts.digest(target.read_bytes()))
        self.assertTrue(result['restart_required']); self.assertFalse(result['live_sessions_updated'])
        self.assertEqual(target.stat().st_nlink, 1)
        if os.name == 'posix': self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(set(self.root.glob('.canca-accounts-*.tmp')), prior_stages)
        self.assertNotIn(PASSWORD, json.dumps(result)); self.assertNotIn(NEW_PASSWORD, json.dumps(result))
        return result, json.loads(target.read_bytes()), target

    def assert_failure(self, argv, code=None):
        stdout = io.StringIO(); stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr): result = accounts.cli(argv)
        self.assertEqual(result, 2); doc = json.loads(stdout.getvalue())
        self.assertEqual(doc['status'], 'failed'); self.assertEqual(doc['version'], '0.6.18')
        self.assertIn(doc['error_code'], accounts.ERRORS)
        if code: self.assertEqual(doc['error_code'], code)
        for marker in [PASSWORD, NEW_PASSWORD, 'NEVER-SECRET', fixture.RECORD['hash'], fixture.RECORD['salt']]:
            self.assertNotIn(marker, stdout.getvalue() + stderr.getvalue())
        return doc

    def arguments(self, change, *, output=None, sha=None):
        return ['--policy', str(self.source), change, '--output', str(output or self.root / 'revision.json'),
                '--expected-policy-sha256', self.sha if sha is None else sha, '--username', 'reader']

    def test_inspection_is_sanitized_sorted_and_never_changes_the_source(self):
        other = deepcopy(self.doc['accounts'][0]); other.update(operator_id='OP-02', username='Another', enabled=False)
        other['grants'] = [dict(assessment_id=a, permissions=['assessment:read']) for a in ['Z', 'a', 'A']]
        self.doc['accounts'].append(other); self.save_source(self.doc)
        result = accounts.inspect_policy(self.source)
        self.assertEqual(result['account_count'], 2); self.assertEqual(result['policy_sha256'], self.sha)
        self.assertEqual([r['username'] for r in result['accounts']], ['Another', 'reader'])
        self.assertEqual(result['accounts'][0]['assessment_ids'], ['A', 'Z', 'a'])
        self.assertNotIn('password', json.dumps(result)); self.assertNotIn(fixture.RECORD['hash'], json.dumps(result))
        self.assertEqual(self.source.read_bytes(), self.raw)
        stdout = io.StringIO()
        with redirect_stdout(stdout): self.assertEqual(accounts.cli(['--policy', str(self.source), 'inspect']), 0)
        self.assertEqual(json.loads(stdout.getvalue()), result)

    def test_added_account_uses_real_scrypt_and_preserves_the_other_account(self):
        with patch.object(accounts.os, 'isatty', return_value=True), patch.object(accounts.getpass, 'getpass', side_effect=[NEW_PASSWORD] * 2):
            result, doc, target = self.revise('add', 'Second', operator_id='OP-02', assessments=['LAB-002', 'lab-002'])
        self.assertEqual(result['account_count'], 2); self.assertEqual(doc['accounts'][0], self.doc['accounts'][0])
        self.assertEqual(doc['policy_version'], '1'); self.assertNotIn(NEW_PASSWORD.encode(), target.read_bytes())
        service = auth.LocalAuth(auth.load_policy(target)); token = service.login('SECOND', NEW_PASSWORD)['access_token']
        self.assertEqual(service.require(token, 'LAB-002'), 'OP-02'); service.require(token, 'lab-002')
        with self.assertRaises(auth.AccessError): service.require(token, 'LAB-001')
        old = service.login('reader', PASSWORD)['access_token']; service.require(old, 'LAB-001')
        with self.assertRaises(auth.AccessError): service.require(old, 'LAB-002')

    def test_add_cli_uses_explicit_flags_two_hidden_prompts_and_fixed_success_metadata(self):
        output = self.root / 'from-cli.json'; stdout = io.StringIO()
        argv = ['--policy', str(self.source), 'add', '--output', str(output), '--expected-policy-sha256', self.sha,
                '--username', 'Second', '--operator-id', 'OP-02', '--assessment-id', 'Z', '--assessment-id', 'A']
        with patch.object(accounts.os, 'isatty', return_value=True), \
                patch.object(accounts.getpass, 'getpass', side_effect=[NEW_PASSWORD] * 2) as prompts, redirect_stdout(stdout):
            self.assertEqual(accounts.cli(argv), 0)
        self.assertEqual(prompts.call_count, 2); result = json.loads(stdout.getvalue())
        self.assertEqual(result['change'], 'add'); self.assertEqual(result['version'], '0.6.18')
        self.assertTrue(result['restart_required']); self.assertFalse(result['live_sessions_updated'])
        self.assertNotIn(NEW_PASSWORD, stdout.getvalue()); self.assertNotIn('password', stdout.getvalue())
        self.assertEqual(accounts.inspect_policy(output)['accounts'][1]['assessment_ids'], ['A', 'Z'])
        self.assertEqual(self.source.read_bytes(), self.raw)

    def test_grant_replacement_is_exact_sorted_and_isolated(self):
        other = deepcopy(self.doc['accounts'][0]); other.update(operator_id='OP-02', username='second')
        self.doc['accounts'].append(other); self.save_source(self.doc)
        _, doc, target = self.revise('set-grants', 'READER', assessments=['Z', 'A', 'a'])
        self.assertEqual(doc['accounts'][1], self.doc['accounts'][1])
        self.assertEqual(doc['accounts'][0]['password'], self.doc['accounts'][0]['password'])
        self.assertEqual([g['assessment_id'] for g in doc['accounts'][0]['grants']], ['A', 'Z', 'a'])
        service = auth.LocalAuth(auth.load_policy(target)); token = service.login('reader', PASSWORD)['access_token']
        self.assertEqual(service.assessment_grants(token), ('A', 'Z', 'a'))
        with self.assertRaises(auth.AccessError): service.require(token, 'LAB-001')

    def test_clear_grants_keeps_login_but_authorizes_no_assessment(self):
        _, doc, target = self.revise('set-grants', clear_grants=True)
        self.assertEqual(doc['accounts'][0]['grants'], [])
        service = auth.LocalAuth(auth.load_policy(target)); token = service.login('reader', PASSWORD)['access_token']
        self.assertEqual(service.assessment_grants(token), ())
        for assessment in ['LAB-001', '*', 'OTHER']:
            with self.assertRaises(auth.AccessError): service.require(token, assessment)

    def test_disable_and_enable_preserve_the_password_and_grants(self):
        _, disabled, target = self.revise('disable')
        self.assertFalse(disabled['accounts'][0]['enabled'])
        self.assertEqual(disabled['accounts'][0]['password'], self.doc['accounts'][0]['password'])
        with self.assertRaises(auth.AccessError): auth.LocalAuth(auth.load_policy(target)).login('reader', PASSWORD)
        self.save_source(disabled)
        _, enabled, final = self.revise('enable', output=self.root / 'enabled.json')
        self.assertTrue(enabled['accounts'][0]['enabled']); self.assertEqual(enabled['accounts'][0]['grants'], self.doc['accounts'][0]['grants'])
        auth.LocalAuth(auth.load_policy(final)).login('reader', PASSWORD)

    def test_rotation_does_not_reload_live_sessions_and_restart_uses_the_new_password(self):
        live = auth.LocalAuth(auth.load_policy(self.source)); old = live.login('reader', PASSWORD)['access_token']
        with patch.object(accounts.os, 'isatty', return_value=True), patch.object(accounts.getpass, 'getpass', side_effect=[NEW_PASSWORD] * 2):
            _, doc, target = self.revise('rotate-password')
        self.assertNotEqual(doc['accounts'][0]['password']['salt'], fixture.RECORD['salt'])
        self.assertEqual(doc['accounts'][0]['grants'], self.doc['accounts'][0]['grants'])
        live.require(old, 'LAB-001'); live.login('reader', PASSWORD)
        restarted = auth.LocalAuth(auth.load_policy(target))
        with self.assertRaises(auth.AccessError): restarted.require(old, 'LAB-001')
        with self.assertRaises(auth.AccessError): restarted.login('reader', PASSWORD)
        restarted.login('reader', NEW_PASSWORD)

    def test_disabled_revision_also_preserves_old_snapshot_until_restart(self):
        live = auth.LocalAuth(auth.load_policy(self.source)); token = live.login('reader', PASSWORD)['access_token']
        _, _, target = self.revise('disable'); live.require(token, 'LAB-001')
        restarted = auth.LocalAuth(auth.load_policy(target))
        with self.assertRaises(auth.AccessError): restarted.require(token, 'LAB-001')
        with self.assertRaises(auth.AccessError): restarted.login('reader', PASSWORD)

    def test_invalid_identifiers_duplicates_limits_and_noops_precede_password_prompts(self):
        with patch.object(accounts.getpass, 'getpass') as prompts:
            for change, username, extras in [('add', 'READER', dict(operator_id='OP-02', assessments=['LAB-001'])),
                ('add', 'second', dict(operator_id='OP-01', assessments=['LAB-001'])),
                ('add', 'second', dict(operator_id='OP-02', assessments=['*'])),
                ('add', 'second', dict(operator_id='OP-02', assessments=['A', 'A'])),
                ('add', 'second', dict(operator_id='OP-02', assessments=[])),
                ('add', 'second', dict(operator_id='OP-02', assessments=['A' + str(n) for n in range(129)])),
                ('rotate-password', 'unknown', {}), ('set-grants', 'reader', dict(assessments=['LAB-001'])),
                ('set-grants', 'reader', dict(assessments=[])), ('set-grants', 'reader', dict(assessments=['A'], clear_grants=True)),
                ('enable', 'reader', {}), ('disable', '../NEVER-SECRET', {})]:
                with self.subTest(change=change, username=username), self.assertRaises(ValueError):
                    accounts.revise_policy(self.source, self.root / 'revision.json', self.sha, change, username, **extras)
            full = dict(policy_version='1', accounts=[])
            for n in range(128):
                row = deepcopy(self.doc['accounts'][0]); row.update(operator_id='OP-' + str(n), username='user-' + str(n)); full['accounts'].append(row)
            self.save_source(full)
            with self.assertRaises(ValueError): accounts.revise_policy(self.source, self.root / 'revision.json', self.sha, 'add', 'extra', operator_id='OP-EXTRA', assessments=['A'])
        prompts.assert_not_called(); self.assertFalse((self.root / 'revision.json').exists())

    def test_wrong_or_invalid_fences_do_not_prompt_or_create_files(self):
        with patch.object(accounts.getpass, 'getpass') as prompts:
            for sha in ['0' * 64, 'A' * 64, '', 'bad', self.sha + '0']:
                self.assert_failure(self.arguments('rotate-password', sha=sha))
        prompts.assert_not_called(); self.assertEqual(self.source.read_bytes(), self.raw)
        self.assertFalse((self.root / 'revision.json').exists())

    def test_readable_source_drift_during_password_work_blocks_publication(self):
        changed = deepcopy(self.doc); changed['accounts'][0]['grants'] = []
        def prompt(_):
            self.source.write_bytes(json.dumps(changed).encode()); return NEW_PASSWORD
        with patch.object(accounts.os, 'isatty', return_value=True), patch.object(accounts.getpass, 'getpass', side_effect=prompt):
            self.assert_failure(self.arguments('rotate-password'), 'operator_policy_base_conflict')
        self.assertEqual(json.loads(self.source.read_bytes()), changed)
        self.assertFalse((self.root / 'revision.json').exists()); self.assertEqual(list(self.root.glob('.canca-accounts-*.tmp')), [])

    def test_identical_bytes_in_a_replaced_source_inode_are_also_stale(self):
        def prompt(_):
            next_path = self.root / 'replacement.json'; next_path.write_bytes(self.raw)
            if os.name == 'posix': next_path.chmod(0o600)
            os.replace(next_path, self.source); return NEW_PASSWORD
        with patch.object(accounts.os, 'isatty', return_value=True), patch.object(accounts.getpass, 'getpass', side_effect=prompt):
            self.assert_failure(self.arguments('rotate-password'), 'operator_policy_base_conflict')
        self.assertEqual(self.source.read_bytes(), self.raw); self.assertFalse((self.root / 'revision.json').exists())

    def test_password_mismatch_short_noninteractive_and_interruptions_never_emit_secrets(self):
        with patch.object(accounts.os, 'isatty', return_value=False), patch.object(accounts.getpass, 'getpass') as prompts:
            self.assert_failure(self.arguments('rotate-password')); prompts.assert_not_called()
        for replies in [[PASSWORD, NEW_PASSWORD], ['short', 'short'], ['x' * 257] * 2]:
            with patch.object(accounts.os, 'isatty', return_value=True), patch.object(accounts.getpass, 'getpass', side_effect=replies):
                self.assert_failure(self.arguments('rotate-password'))
        for error in [EOFError('NEVER-SECRET'), KeyboardInterrupt('NEVER-SECRET'), RuntimeError('NEVER-SECRET')]:
            with patch.object(accounts.os, 'isatty', return_value=True), patch.object(accounts.getpass, 'getpass', side_effect=error):
                self.assert_failure(self.arguments('rotate-password'))
        self.assertEqual(self.source.read_bytes(), self.raw); self.assertFalse((self.root / 'revision.json').exists())

    def test_parser_rejects_password_flags_pipes_unknowns_and_abbreviations_without_echo(self):
        for extra in [['--password', 'NEVER-SECRET'], ['--password-env', 'NEVER-SECRET'], ['--stdin-password'],
                      ['--user', 'NEVER-SECRET'], ['--bogus', 'NEVER-SECRET']]:
            self.assert_failure(self.arguments('disable') + extra, 'operator_policy_input_invalid')
        self.assert_failure(['--policy', str(self.source), 'set-grants', '--username', 'reader'], 'operator_policy_input_invalid')
        self.assertEqual(self.source.read_bytes(), self.raw)

    def test_invalid_oversize_duplicate_policies_fail_before_prompts(self):
        bad = deepcopy(self.doc); bad['accounts'][0]['password']['extra'] = 'NEVER-SECRET'
        with patch.object(accounts.getpass, 'getpass') as prompts:
            for raw in [b'NEVER-SECRET', b'\xff', b' ' * 65537, json.dumps(bad).encode(),
                        b'{"policy_version":"1","accounts":[],"accounts":[]}']:
                self.source.write_bytes(raw)
                self.assert_failure(self.arguments('rotate-password'), 'operator_policy_read_failed')
                self.assertEqual(self.source.read_bytes(), raw)
        prompts.assert_not_called(); self.assertFalse((self.root / 'revision.json').exists())

    def test_output_collision_or_alias_never_replaces_any_existing_file(self):
        target = self.root / 'revision.json'; target.write_bytes(b'NEVER-SECRET existing destination')
        with patch.object(accounts.getpass, 'getpass') as prompts:
            self.assert_failure(self.arguments('rotate-password'), 'operator_policy_write_failed')
            self.assert_failure(self.arguments('rotate-password', output=self.source), 'operator_policy_write_failed')
        prompts.assert_not_called(); self.assertEqual(target.read_bytes(), b'NEVER-SECRET existing destination')
        self.assertEqual(self.source.read_bytes(), self.raw)
        target.unlink()
        os.link(self.source, target)
        self.assert_failure(self.arguments('disable'), 'operator_policy_read_failed')
        self.assertEqual(target.read_bytes(), self.raw)

    @unittest.skipUnless(os.name == 'posix', 'POSIX mode and FIFO checks')
    def test_public_files_directories_fifo_and_symlinks_fail_closed(self):
        self.source.chmod(0o644)
        self.assert_failure(['--policy', str(self.source), 'inspect'], 'operator_policy_read_failed')
        self.source.chmod(0o600)
        public = self.root / 'public'; public.mkdir(mode=0o777); public.chmod(0o777)
        self.assert_failure(self.arguments('disable', output=public / 'output.json'), 'operator_policy_write_failed')
        alias = self.root / 'alias.json'; alias.symlink_to(self.source)
        self.assert_failure(['--policy', str(alias), 'inspect'], 'operator_policy_read_failed')
        parent_alias = self.root / 'alias-dir'; parent_alias.symlink_to(self.root, target_is_directory=True)
        self.assert_failure(self.arguments('disable', output=parent_alias / 'new.json'), 'operator_policy_write_failed')
        fifo = self.root / 'fifo'; os.mkfifo(fifo, mode=0o600)
        self.assert_failure(['--policy', str(fifo), 'inspect'], 'operator_policy_read_failed')
        self.assert_failure(['--policy', str(self.root), 'inspect'], 'operator_policy_read_failed')

    @unittest.skipUnless(os.name == 'nt', 'Native Windows reparse-point checks')
    def test_windows_file_and_directory_symlinks_and_unc_are_rejected(self):
        alias = self.root / 'alias.json'; alias.symlink_to(self.source)
        self.assert_failure(['--policy', str(alias), 'inspect'], 'operator_policy_read_failed')
        parent_alias = self.root / 'alias-dir'; parent_alias.symlink_to(self.root, target_is_directory=True)
        self.assert_failure(self.arguments('disable', output=parent_alias / 'new.json'), 'operator_policy_write_failed')
        self.assert_failure(['--policy', '\\\\NEVER-SECRET\\share\\accounts.json', 'inspect'], 'operator_policy_read_failed')
        self.assertEqual(self.source.read_bytes(), self.raw); self.assertFalse((self.root / 'new.json').exists())

    def test_fsync_and_hardlink_failures_clean_stage_and_preserve_source(self):
        for name in ['fsync', 'link']:
            with patch.object(accounts.os, name, side_effect=OSError('NEVER-SECRET path')):
                self.assert_failure(self.arguments('disable'), 'operator_policy_write_failed')
            self.assertFalse((self.root / 'revision.json').exists()); self.assertEqual(list(self.root.glob('.canca-accounts-*.tmp')), [])
            self.assertEqual(self.source.read_bytes(), self.raw)

    @unittest.skipUnless(os.name == 'posix', 'POSIX output directory mode checks')
    def test_output_directory_becoming_public_during_password_work_blocks_publication(self):
        def prompt(_):
            self.root.chmod(0o755); return NEW_PASSWORD
        with patch.object(accounts.os, 'isatty', return_value=True), patch.object(accounts.getpass, 'getpass', side_effect=prompt):
            self.assert_failure(self.arguments('rotate-password'), 'operator_policy_write_failed')
        self.assertFalse((self.root / 'revision.json').exists()); self.assertEqual(self.source.read_bytes(), self.raw)
        self.assertEqual(list(self.root.glob('.canca-accounts-*.tmp')), [])

    def test_racing_destination_creation_is_preserved_by_exclusive_publication(self):
        link = os.link; output = self.root / 'revision.json'
        def race(source, target, **kwargs):
            output.write_bytes(b'NEVER-SECRET other writer'); return link(source, target, **kwargs)
        with patch.object(accounts.os, 'link', side_effect=race):
            self.assert_failure(self.arguments('disable'), 'operator_policy_write_failed')
        self.assertEqual(output.read_bytes(), b'NEVER-SECRET other writer'); self.assertEqual(self.source.read_bytes(), self.raw)
        self.assertEqual(list(self.root.glob('.canca-accounts-*.tmp')), [])

    def test_oversize_revision_is_rejected_before_stage_or_output(self):
        with patch.object(auth, 'MAX_POLICY_BYTES', len(self.raw) + 1), patch.object(accounts.tempfile, 'mkstemp') as create:
            self.assert_failure(self.arguments('disable')); create.assert_not_called()
        self.assertEqual(self.source.read_bytes(), self.raw)

    def test_process_exit_before_publication_retains_only_private_unapplied_stage(self):
        output = self.root / 'revision.json'
        code = "import os,sys; sys.path.insert(0,sys.argv[1]); import P01_Operator_Accounts as a; a.os.link=lambda *args,**kwargs: os._exit(23); a.revise_policy(sys.argv[2],sys.argv[3],a.inspect_policy(sys.argv[2])['policy_sha256'],'disable','reader')"
        result = subprocess.run([sys.executable, '-c', code, str(Path(accounts.__file__).parent), str(self.source), str(output)],
                                capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 23, result.stderr.decode()); self.assertEqual(result.stdout, b'')
        self.assertFalse(output.exists()); self.assertEqual(self.source.read_bytes(), self.raw)
        stages = list(self.root.glob('.canca-accounts-*.tmp')); self.assertEqual(len(stages), 1)
        auth.load_policy(stages[0]); self.assertFalse(json.loads(stages[0].read_bytes())['accounts'][0]['enabled'])
        if os.name == 'posix': self.assertEqual(stat.S_IMODE(stages[0].stat().st_mode), 0o600)
        _, _, final = self.revise('disable', output=self.root / 'later.json')
        self.assertTrue(stages[0].exists()); self.assertTrue(final.exists())

    @unittest.skipUnless(os.name == 'posix', 'POSIX directory sync behavior')
    def test_directory_sync_failure_can_leave_complete_unapplied_output_and_fixed_error(self):
        fsync = os.fsync
        def directory_failure(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode): raise OSError('NEVER-SECRET directory')
            return fsync(fd)
        with patch.object(accounts.os, 'fsync', side_effect=directory_failure):
            self.assert_failure(self.arguments('disable'), 'operator_policy_write_failed')
        output = self.root / 'revision.json'; auth.load_policy(output)
        self.assertEqual(output.stat().st_nlink, 1); self.assertEqual(self.source.read_bytes(), self.raw)
        self.assertEqual(list(self.root.glob('.canca-accounts-*.tmp')), [])


if __name__ == '__main__': unittest.main()
