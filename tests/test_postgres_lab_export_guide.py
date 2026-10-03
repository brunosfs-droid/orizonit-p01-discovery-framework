"""Run the operator's actual install block against real Git and hostile TARs.

All paths are redirected to disposable fixtures; no PostgreSQL connection is used.
"""
import hashlib
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / 'docs/LAB_POSTGRESQL_EXPORT_R1_v0.6.9.md'
LAB_ROOT = '/root/p01/canca-postgres-lab-v0.6.5'
LAB_PACKAGE = '/root/p01/canca-export-v0.6.9.tar'
ENGINE_SHA = '57c0b7834095d00512e6046bd884c03556f46738e97d7fdb4dcb9847efcc2365'
EXPORT_PATH = 'persistence/P01_Report_Export.py'


class ExportLabGuideTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='canca-export-guide-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / 'deployment'
        self.root.mkdir()
        (self.root / 'persistence').mkdir()
        self.engine = self.root / 'persistence/P01_Findings.py'
        # Reproduce the already accepted Windows-origin LAB bytes, only in fixture.
        self.engine_bytes = (ROOT / 'persistence/P01_Findings.py').read_bytes().replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
        self.assertEqual(hashlib.sha256(self.engine_bytes).hexdigest(), ENGINE_SHA)
        self.engine.write_bytes(self.engine_bytes)
        self.source = (ROOT / EXPORT_PATH).read_bytes().replace(b'\r\n', b'\n')
        self.package = self.base / 'export.tar'
        self.target = self.root / EXPORT_PATH
        text = GUIDE.read_text(encoding='utf-8')
        self.blocks = re.findall(r'```bash\n(.*?)\n```', text, re.S)
        self.assertEqual(len(self.blocks), 2)
        self.install = self.blocks[0].split("if python - <<'PY'\n", 1)[1].split('\nPY\n', 1)[0]

    def run_install(self, root=None):
        code = self.install.replace(LAB_ROOT, str(root or self.root)).replace(LAB_PACKAGE, str(self.package))
        env = os.environ.copy()
        env.pop('PYTHONOPTIMIZE', None)
        result = subprocess.run([sys.executable, '-c', code], env=env, capture_output=True, text=True, timeout=15)
        self.assertEqual(self.engine.read_bytes(), self.engine_bytes)
        return result

    def make_tar(self, entries):
        with tarfile.open(self.package, 'w', format=tarfile.PAX_FORMAT) as archive:
            for name, kind, payload in entries:
                member = tarfile.TarInfo(name)
                member.type = kind
                if kind == tarfile.REGTYPE:
                    member.size = len(payload)
                    archive.addfile(member, io.BytesIO(payload))
                else:
                    member.linkname = EXPORT_PATH if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ''
                    archive.addfile(member)

    def expected_file(self, payload=None):
        return (EXPORT_PATH, tarfile.REGTYPE, self.source if payload is None else payload)

    @unittest.skipUnless(shutil.which('git'), 'Git required to reproduce operator archive')
    def test_actual_git_archive_includes_directory_and_installs_exact_bytes(self):
        repo = self.base / 'git-source'
        repo.mkdir()
        (repo / 'persistence').mkdir()
        (repo / EXPORT_PATH).write_bytes(self.source)
        # Force both Windows-style and Linux-style archive payloads, independent of host.
        for eol in ('lf', 'crlf'):
            with self.subTest(eol=eol):
                if self.target.exists():
                    self.target.unlink()
                (repo / '.gitattributes').write_text(f'{EXPORT_PATH} text eol={eol}\n', encoding='utf-8')
                for args in (['init', '-q'], ['add', '.'],
                             ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', eol],
                             ['archive', '--format=tar', '--output', str(self.package), 'HEAD', EXPORT_PATH]):
                    result = subprocess.run(['git', '-C', str(repo)] + args, capture_output=True, text=True, timeout=15)
                    self.assertEqual(result.returncode, 0, result.stderr)
                with tarfile.open(self.package) as archive:
                    members = archive.getmembers()
                    self.assertEqual(len(members), 2)  # Reproduces the reported rejection.
                    self.assertTrue(members[0].isdir())
                    payload = archive.extractfile(EXPORT_PATH).read()
                expected = self.source if eol == 'lf' else self.source.replace(b'\n', b'\r\n')
                self.assertEqual(payload, expected)
                installed = self.run_install()
                self.assertEqual(installed.returncode, 0, installed.stderr)
                self.assertIn('EXPORTADOR OK', installed.stdout)
                self.assertEqual(self.target.read_bytes(), payload)
                self.assertEqual({p.relative_to(self.root).as_posix() for p in self.root.rglob('*') if p.is_file()},
                                 {'persistence/P01_Findings.py', EXPORT_PATH})

    def test_file_only_and_identical_repeat_preserve_installed_bytes(self):
        self.make_tar([self.expected_file()])
        first = self.run_install()
        self.assertEqual(first.returncode, 0, first.stderr)
        before = self.target.stat().st_mtime_ns
        repeat = self.run_install()
        self.assertEqual(repeat.returncode, 0, repeat.stderr)
        self.assertEqual(self.target.read_bytes(), self.source)
        self.assertEqual(self.target.stat().st_mtime_ns, before)

    def test_unexpected_duplicate_traversal_and_link_members_block_before_install(self):
        directory = ('persistence/', tarfile.DIRTYPE, b'')
        cases = [[], [directory],
                 [self.expected_file(), self.expected_file()],
                 [directory, directory, self.expected_file()],
                 [self.expected_file(), ('extra.py', tarfile.REGTYPE, b'x')],
                 [self.expected_file(), ('../escape.py', tarfile.REGTYPE, b'x')],
                 [self.expected_file(), ('/absolute.py', tarfile.REGTYPE, b'x')],
                 [self.expected_file(), ('extra/', tarfile.DIRTYPE, b'')],
                 [(EXPORT_PATH, tarfile.SYMTYPE, b'')],
                 [(EXPORT_PATH, tarfile.LNKTYPE, b'')],
                 [('persistence/', tarfile.SYMTYPE, b''), self.expected_file()]]
        for entries in cases:
            with self.subTest(entries=[(e[0], e[1]) for e in entries]):
                self.make_tar(entries)
                result = self.run_install()
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('EXPORTADOR OK', result.stdout)
                self.assertFalse(self.target.exists())
                self.assertFalse((self.base / 'escape.py').exists())

    def test_wrong_payload_empty_oversized_or_broken_tar_blocks(self):
        for payload in (b'', b"VERSION = '0.6.9'\n# unqualified", b'x' * (1024**2 + 1)):
            with self.subTest(size=len(payload)):
                self.make_tar([self.expected_file(payload)])
                self.assertNotEqual(self.run_install().returncode, 0)
                self.assertFalse(self.target.exists())
        for raw in (b'not a tar', b'x' * (2 * 1024**2 + 1)):
            self.package.write_bytes(raw)
            self.assertNotEqual(self.run_install().returncode, 0)
            self.assertFalse(self.target.exists())

    def test_existing_different_exporter_is_preserved(self):
        self.make_tar([self.expected_file()])
        self.target.write_bytes(b'previous exporter: preserve for diagnosis')
        before = self.target.read_bytes()
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('exportador existente diferente', result.stderr)
        self.assertEqual(self.target.read_bytes(), before)

    def test_wrong_engine_blocks_before_install(self):
        self.make_tar([self.expected_file()])
        self.engine_bytes = b'changed engine: preserve'
        self.engine.write_bytes(self.engine_bytes)
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('engine original diferente', result.stderr)
        self.assertFalse(self.target.exists())

    @unittest.skipIf(os.name == 'nt', 'symlink fixture requires Unix')
    def test_deployment_and_target_aliases_are_rejected(self):
        self.make_tar([self.expected_file()])
        alias = self.base / 'deployment-link'
        alias.symlink_to(self.root, target_is_directory=True)
        self.assertNotEqual(self.run_install(alias).returncode, 0)
        self.assertFalse(self.target.exists())
        outside = self.base / 'outside.py'
        outside.write_bytes(self.source)
        self.target.symlink_to(outside)
        self.assertNotEqual(self.run_install().returncode, 0)
        self.assertTrue(self.target.is_symlink())
        self.assertEqual(outside.read_bytes(), self.source)

    @unittest.skipUnless(shutil.which('bash'), 'Bash required for operator shell gate')
    def test_shell_syntax_and_false_ready_gate_never_launch_export(self):
        for block in self.blocks:
            result = subprocess.run(['bash', '-n'], input=block, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
        # In a failed-install session the block must not prompt, connect, or create output.
        sentinel = self.base / 'python-called'
        bin_dir = self.base / 'bin'
        bin_dir.mkdir()
        stub = bin_dir / 'python'
        stub.write_text(f'#!/bin/sh\ntouch "{sentinel}"\nexit 99\n', encoding='utf-8')
        stub.chmod(0o700)
        env = os.environ.copy()
        env['PATH'] = str(bin_dir) + os.pathsep + env['PATH']
        env['P01_EXPORT_READY'] = 'false'
        env['PGPASSWORD'] = 'fixture-secret-must-be-cleared'
        result = subprocess.run(['bash'], input=self.blocks[1] + '\ntest -z "${PGPASSWORD+x}"\n',
                                env=env, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('execute a instalacao validada', result.stdout)
        self.assertIn('Exportacao validada nesta sessao: false', result.stdout)
        self.assertNotIn('fixture-secret', result.stdout + result.stderr)
        self.assertFalse(sentinel.exists())


if __name__ == '__main__':
    unittest.main()
