"""Bounded file verifier: rejects damaged content, duplicates and compressed bombs."""
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import test_operator_web_export as fixture
import test_operator_auth as auth_fixture

spec=importlib.util.spec_from_file_location('export_file_verifier',Path(__file__).resolve().parents[1]/
    'docs/validation/VERIFY_OPERATOR_WEB_EXPORT_v0.6.13.py')
verify=importlib.util.module_from_spec(spec); spec.loader.exec_module(verify)


class ExportFileVerifierTests(unittest.TestCase):
    def test_complete_file_and_tampered_member_manifest_scope_or_counts(self):
        auth=auth_fixture.auth.LocalAuth(auth_fixture.policy())
        token=auth.login('reader',auth_fixture.PASSWORD)['access_token']
        delivery=fixture.web.exports.ExportDelivery(auth)
        with patch.object(fixture.export.pg,'open_connection'), \
                patch.object(fixture.export.report,'show_assessment',side_effect=list(fixture.sample())):
            with delivery.build(token,'LAB-001','3'*64,1) as (raw,_):
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    payloads={name:archive.read(name) for name in archive.namelist()}
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'report.zip'; path.write_bytes(raw)
            self.assertEqual(verify.verify(path,'LAB-001',1,0)['files_verified'],4)
            for aid,count,findings in [('OTHER',1,0),('LAB-001',2,0),('LAB-001',1,1)]:
                with self.assertRaises(ValueError): verify.verify(path,aid,count,findings)
            for name in payloads:
                changed=dict(payloads); changed[name]=changed[name]+b'changed'
                with zipfile.ZipFile(path,'w') as archive:
                    for key,value in changed.items(): archive.writestr(key,value)
                with self.assertRaises((ValueError,json.JSONDecodeError)):
                    verify.verify(path,'LAB-001',1,0)
            for compression in [zipfile.ZIP_DEFLATED,zipfile.ZIP_STORED]:
                with zipfile.ZipFile(path,'w',compression=compression) as archive:
                    for name,value in payloads.items(): archive.writestr(name,value)
                    if compression==zipfile.ZIP_STORED: archive.writestr('../extra',b'outside')
                with self.assertRaises(ValueError): verify.verify(path,'LAB-001',1,0)


if __name__=='__main__': unittest.main()
