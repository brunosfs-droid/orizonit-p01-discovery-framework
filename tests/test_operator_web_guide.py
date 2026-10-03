"""Run the eight-source Web installer against actual archive and hostile TAR."""
import io
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
from qualified_git_source import guide_revision, source_bytes

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ['server/P01_Operator_Auth.py', 'server/P01_Operator_API.py', 'server/P01_Operator_Web.py',
    'server/web/index.html', 'server/web/operator.css', 'server/web/operator.js',
    'docs/validation/LOCAL_OPERATOR_LAB_R1_v0.6.11.py', 'docs/validation/LOCAL_OPERATOR_WEB_LAB_R1_v0.6.12.py']


class OperatorWebGuideTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve(); self.package = self.base / 'web.tar'; self.target = self.base / 'deployment'
        text = (ROOT / 'docs/LAB_LOCAL_OPERATOR_WEB_R1_v0.6.12.md').read_text()
        self.revision = guide_revision('docs/LAB_LOCAL_OPERATOR_WEB_R1_v0.6.12.md')
        blocks = re.findall(r'```bash\n(.*?)\n```', text, re.S)
        self.script = blocks[1].split("python3 - <<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        self.script = self.script.replace('/root/p01/canca-operator-web-v0.6.12.tar', str(self.package)).replace('/root/p01/canca-operator-web-lab-v0.6.12', str(self.target))

    def install(self):
        return subprocess.run([sys.executable, '-c', self.script], capture_output=True, text=True)

    def make_tar(self, mutation=None):
        with tarfile.open(self.package, 'w') as archive:
            for name in SOURCES:
                raw = source_bytes(self.revision, name)
                if mutation: raw = mutation(name, raw)
                member = tarfile.TarInfo(name); member.size = len(raw); archive.addfile(member, io.BytesIO(raw))

    def test_actual_git_archive_installs_web_assets_and_refuses_overwrite(self):
        subprocess.run(['git', 'archive', '--format=tar', '--output', str(self.package), self.revision, *SOURCES], cwd=ROOT, check=True)
        result = self.install(); self.assertEqual(result.returncode, 0, result.stderr)
        before = {str(p):p.read_bytes() for p in self.target.rglob('*') if p.is_file()}
        self.assertEqual(len(before), 8); self.assertNotEqual(self.install().returncode, 0)
        self.assertEqual(before, {str(p):p.read_bytes() for p in self.target.rglob('*') if p.is_file()})

    def test_tampered_web_script_and_extra_symlink_fail_before_destination(self):
        self.make_tar(lambda name, raw: raw + b'changed' if name == 'server/web/operator.js' else raw)
        self.assertNotEqual(self.install().returncode, 0); self.assertFalse(self.target.exists())
        self.make_tar()
        with tarfile.open(self.package, 'a') as archive:
            member = tarfile.TarInfo('server/web/accounts.json'); member.type = tarfile.SYMTYPE; member.linkname = '/etc/passwd'; archive.addfile(member)
        self.assertNotEqual(self.install().returncode, 0); self.assertFalse(self.target.exists())

    def test_crlf_archive_normalizes_to_qualified_sources(self):
        self.make_tar(lambda name, raw: raw.replace(b'\n', b'\r\n'))
        result = self.install(); self.assertEqual(result.returncode, 0, result.stderr)
        for name in SOURCES: self.assertEqual((self.target / name).read_bytes(), source_bytes(self.revision, name))


if __name__ == '__main__': unittest.main()
