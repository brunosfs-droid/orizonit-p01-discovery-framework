"""Execute the documented installer against actual Git archive and hostile TARs."""
import io
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCES=['server/P01_Operator_Auth.py','server/P01_Operator_API.py','docs/validation/LOCAL_OPERATOR_LAB_R1_v0.6.11.py']


class OperatorGuideTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name).resolve();self.package=self.base/'operator.tar';self.target=self.base/'deployment'
        text=(ROOT/'docs/LAB_LOCAL_OPERATOR_R1_v0.6.11.md').read_text()
        blocks=re.findall(r'```bash\n(.*?)\n```',text,re.S)
        self.script=blocks[1].split("python3 - <<'PY'\n",1)[1].rsplit('\nPY',1)[0]
        self.script=self.script.replace('/root/p01/canca-operator-v0.6.11.tar',str(self.package)).replace('/root/p01/canca-operator-lab-v0.6.11',str(self.target))

    def install(self):
        return subprocess.run([__import__('sys').executable,'-c',self.script],capture_output=True,text=True)

    def make_tar(self,mutate=None):
        with tarfile.open(self.package,'w') as archive:
            for name in SOURCES:
                raw=(ROOT/name).read_bytes()
                if mutate:raw=mutate(name,raw)
                member=tarfile.TarInfo(name);member.size=len(raw);archive.addfile(member,io.BytesIO(raw))

    def test_actual_git_archive_optional_directories_accepted_and_no_overwrite(self):
        subprocess.run(['git','archive','--format=tar','--output',str(self.package),'HEAD',*SOURCES],cwd=ROOT,check=True)
        result=self.install();self.assertEqual(result.returncode,0,result.stderr)
        before={str(p):p.read_bytes() for p in self.target.rglob('*') if p.is_file()}
        self.assertEqual(len(before),3)
        self.assertNotEqual(self.install().returncode,0)
        self.assertEqual(before,{str(p):p.read_bytes() for p in self.target.rglob('*') if p.is_file()})

    def test_tampered_source_and_symlink_rejected_before_destination(self):
        self.make_tar(lambda name,raw:raw+b'# changed\n' if name==SOURCES[0] else raw)
        self.assertNotEqual(self.install().returncode,0);self.assertFalse(self.target.exists())
        self.make_tar()
        with tarfile.open(self.package,'a') as archive:
            member=tarfile.TarInfo('link');member.type=tarfile.SYMTYPE;member.linkname='/etc/passwd';archive.addfile(member)
        self.assertNotEqual(self.install().returncode,0);self.assertFalse(self.target.exists())

    def test_crlf_sources_normalized_to_qualified_bytes(self):
        self.make_tar(lambda name,raw:raw.replace(b'\n',b'\r\n'))
        result=self.install();self.assertEqual(result.returncode,0,result.stderr)
        for name in SOURCES:self.assertEqual((self.target/name).read_bytes(),(ROOT/name).read_bytes())


if __name__=='__main__':unittest.main()
