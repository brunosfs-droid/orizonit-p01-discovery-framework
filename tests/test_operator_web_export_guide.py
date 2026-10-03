"""Exercise the new eleven-source installer without touching the LAB."""
import io
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest

from qualified_git_source import guide_revision, source_bytes

ROOT=Path(__file__).resolve().parents[1]
GUIDE='docs/LAB_OPERATOR_WEB_EXPORT_R1_v0.6.13.md'
SOURCES=['server/P01_Operator_Auth.py','server/P01_Operator_API.py','server/P01_Operator_Web.py',
    'server/P01_Operator_Export.py','server/web/index.html','server/web/operator.css','server/web/operator.js',
    'persistence/P01_Report_Export.py','docs/validation/LOCAL_OPERATOR_LAB_R1_v0.6.11.py',
    'docs/validation/LOCAL_OPERATOR_WEB_EXPORT_LAB_R1_v0.6.13.py',
    'docs/validation/VERIFY_OPERATOR_WEB_EXPORT_v0.6.13.py']


class OperatorWebExportGuideTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.base=Path(temporary.name).resolve(); self.package=self.base/'export.tar'; self.target=self.base/'deployment'
        self.revision=guide_revision(GUIDE)
        blocks=re.findall(r'```bash\n(.*?)\n```',(ROOT/GUIDE).read_text(),re.S)
        self.script=blocks[1].split("python3 - <<'PY'\n",1)[1].rsplit('\nPY',1)[0]
        self.script=self.script.replace('/root/p01/canca-operator-web-export-v0.6.13.tar',str(self.package))
        self.script=self.script.replace('/root/p01/canca-operator-web-export-lab-v0.6.13',str(self.target))

    def install(self):
        return subprocess.run([sys.executable,'-c',self.script],capture_output=True,text=True,timeout=15)

    def make_tar(self,crlf=False,tamper=False):
        with tarfile.open(self.package,'w') as archive:
            for name in SOURCES:
                raw=source_bytes(self.revision,name)
                if crlf: raw=raw.replace(b'\n',b'\r\n')
                if tamper and name=='server/P01_Operator_Export.py': raw+=b'changed'
                member=tarfile.TarInfo(name); member.size=len(raw); archive.addfile(member,io.BytesIO(raw))

    def test_actual_pinned_archive_installs_eleven_files_and_preserves_existing_deployment(self):
        subprocess.run(['git','archive','--format=tar','--output',str(self.package),self.revision,*SOURCES],cwd=ROOT,check=True)
        result=self.install(); self.assertEqual(result.returncode,0,result.stderr)
        files={str(p):p.read_bytes() for p in self.target.rglob('*') if p.is_file()}
        self.assertEqual(len(files),11); self.assertIn('PACKAGE OK',result.stdout)
        self.assertNotEqual(self.install().returncode,0)
        self.assertEqual(files,{str(p):p.read_bytes() for p in self.target.rglob('*') if p.is_file()})

    def test_crlf_normalizes_and_tamper_extra_link_or_duplicate_fail_before_destination(self):
        self.make_tar(crlf=True); result=self.install(); self.assertEqual(result.returncode,0,result.stderr)
        for name in SOURCES: self.assertEqual((self.target/name).read_bytes(),source_bytes(self.revision,name))
        self.target=self.base/'new-deployment'
        self.script=self.script.replace(str(self.base/'deployment'),str(self.target))
        for mode in ['tamper','link','duplicate']:
            self.make_tar(tamper=mode=='tamper')
            if mode!='tamper':
                with tarfile.open(self.package,'a') as archive:
                    member=tarfile.TarInfo(SOURCES[0] if mode=='duplicate' else 'server/extra')
                    if mode=='link': member.type=tarfile.SYMTYPE; member.linkname='/etc/passwd'; archive.addfile(member)
                    else: member.size=1; archive.addfile(member,io.BytesIO(b'x'))
            self.assertNotEqual(self.install().returncode,0); self.assertFalse(self.target.exists())


if __name__=='__main__': unittest.main()
