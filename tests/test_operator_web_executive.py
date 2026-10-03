"""Executive HTTP delivery, shared resource boundary and downloaded file integrity."""
from copy import deepcopy
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import test_operator_auth as auth_fixture
import test_operator_web as http_fixture
from test_postgres_executive import history
import P01_Operator_Web as web

export = web.exports.export
executive = web.exports.executive
VERIFIER = Path(__file__).resolve().parents[1]/'docs/validation/VERIFY_OPERATOR_WEB_EXECUTIVE_v0.6.15.py'
spec = importlib.util.spec_from_file_location('executive_file_verifier', VERIFIER)
verify = importlib.util.module_from_spec(spec); spec.loader.exec_module(verify)


def canonical_page(conn, assessment, after_analysis_id='', after_ordinal=-1, limit=100, expected_scope_sha256=None):
    doc = history()
    if expected_scope_sha256 is not None and expected_scope_sha256 != doc['report_scope_sha256']:
        raise export.pg.PersistenceError('report_scope_conflict')
    selected = [r for r in doc['evaluations'] if (r['analysis_id'], r['ordinal']) > (after_analysis_id, after_ordinal)]
    rows = selected[:limit]
    last = rows[-1] if rows else dict(analysis_id=after_analysis_id, ordinal=after_ordinal)
    header = {k:v for k,v in doc.items() if k not in {'export_version','evaluations','export_consistency'}}
    return deepcopy(dict(**header, snapshot_at_utc='2026-10-03T16:00:00+00:00', evaluations=rows,
                         has_more=len(selected)>limit, next_cursor=dict(after_analysis_id=last['analysis_id'], after_ordinal=last['ordinal'])))


def archive_bytes(payloads, compression=zipfile.ZIP_STORED):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=compression) as archive:
        for name, raw in payloads.items(): archive.writestr(name, raw)
    return buffer.getvalue()


class OperatorWebExecutiveTests(unittest.TestCase):
    setUp = http_fixture.OperatorWebTests.setUp
    stop = http_fixture.OperatorWebTests.stop
    request = http_fixture.OperatorWebTests.request

    def login(self):
        code, _, raw = self.request('POST','/api/v1/operator/session',dict(username='reader',password=auth_fixture.PASSWORD),
                                    {'Content-Type':'application/json'})
        self.assertEqual(code,201)
        return json.loads(raw)['access_token']

    def target(self, assessment='LAB-001', query=None, kind='executive'):
        return '/api/v1/assessments/'+assessment+'/report/'+('executive/' if kind=='executive' else '')+'export?'+(
            query if query is not None else 'expected_scope_sha256='+'d'*64+'&limit=1')

    def test_complete_archive_matches_qualified_synthesis_and_seven_fenced_queries(self):
        token=self.login()
        with patch.object(export.pg,'open_connection'), patch.object(export.report,'show_assessment',side_effect=canonical_page) as query:
            code, headers, raw=self.request('GET',self.target(),headers={'Authorization':'Bearer '+token})
        self.assertEqual(code,200)
        self.assertEqual(headers['Content-Disposition'],'attachment; filename="canca-LAB-001-executive.zip"')
        self.assertEqual(headers['Content-Type'],'application/zip'); self.assertEqual(int(headers['Content-Length']),len(raw))
        self.assertEqual(headers['X-Canca-Report-Scope-SHA256'],'d'*64)
        self.assertEqual(headers['X-Canca-Export-SHA256'],export.pg.digest(raw))
        self.assertEqual(query.call_count,7)
        self.assertTrue(all(c.kwargs['expected_scope_sha256']=='d'*64 for c in query.call_args_list))
        self.assertNotIn(token.encode(),raw); self.assertNotIn(auth_fixture.PASSWORD.encode(),raw)
        self.assertNotIn(b'NEVER-EXPORT',raw)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            self.assertEqual(set(archive.namelist()),verify.NAMES)
            self.assertTrue(all(i.compress_type==zipfile.ZIP_STORED and i.external_attr>>16==0o100600 for i in archive.infolist()))
            doc=json.loads(archive.read('executive.json')); manifest=json.loads(archive.read('manifest.json'))
            self.assertEqual(manifest['executive_version'],executive.VERSION); self.assertEqual(manifest['delivery_version'],web.exports.VERSION)
            self.assertEqual(doc['consistency']['data_pages'],6); self.assertTrue(doc['consistency']['terminal_empty_page_verified'])
            expected=executive.summarize(history())
            expected.pop('consistency'); doc.pop('consistency'); self.assertEqual(doc,expected)
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'executive.zip'; path.write_bytes(raw)
            self.assertEqual(verify.verify(path,'LAB-001',6,4,2)['files_verified'],4)

    def test_auth_origin_and_query_denials_precede_database_for_the_new_route(self):
        token=self.login(); headers={'Authorization':'Bearer '+token}
        with patch.object(export.pg,'open_connection') as connect:
            self.assertEqual(self.request('GET',self.target())[0],401)
            self.assertEqual(self.request('GET',self.target('OTHER'),headers=headers)[0],403)
            self.assertEqual(self.request('GET',self.target(),headers={**headers,'Origin':'http://other.invalid'})[0],403)
            for query in ('','expected_scope_sha256=bad','expected_scope_sha256='+'d'*64+'&limit=0',
                          'expected_scope_sha256='+'d'*64+'&limit=101','expected_scope_sha256='+'d'*64+'&kind=technical',
                          'expected_scope_sha256='+'d'*64+'&expected_scope_sha256='+'d'*64,
                          'expected_scope_sha256='+'d'*64+'&after_ordinal=0','expected_scope_sha256='+'d'*64+'&password=PRIVATE'):
                code,_,raw=self.request('GET',self.target(query=query),headers=headers)
                self.assertEqual(code,400); self.assertNotIn(b'PRIVATE',raw)
            self.assertEqual(self.request('GET',self.target(),headers={**headers,'Content-Length':'1'})[0],400)
        connect.assert_not_called()

    def test_missing_changed_or_failed_data_never_publish_an_archive_or_private_error(self):
        token=self.login(); headers={'Authorization':'Bearer '+token}
        for failure, expected in ((export.pg.PersistenceError('report_scope_conflict'),409),(RuntimeError('password=NEVER-LOG'),503)):
            with patch.object(export.pg,'open_connection'), patch.object(export.report,'show_assessment',side_effect=failure):
                code,actual,raw=self.request('GET',self.target(),headers=headers)
            self.assertEqual(code,expected); self.assertNotIn('Content-Disposition',actual); self.assertNotIn(b'NEVER-LOG',raw)
        with patch.object(export.pg,'open_connection'), patch.object(export.report,'show_assessment',return_value=dict(status='not_found')):
            self.assertEqual(self.request('GET',self.target(),headers=headers)[0],404)
        for error, expected in (('executive_data_conflict',503),('executive_limit_exceeded',413)):
            with patch.object(export.pg,'open_connection'), patch.object(export.report,'show_assessment',side_effect=canonical_page), \
                    patch.object(executive,'summarize',side_effect=export.pg.PersistenceError(error)):
                code,actual,_=self.request('GET',self.target(),headers=headers)
            self.assertEqual(code,expected); self.assertNotIn('Content-Disposition',actual)

    def test_technical_and_executive_exports_share_one_slot_until_delivery_finishes(self):
        token=self.login()
        for held, requested in (('technical','executive'),('executive','technical')):
            with patch.object(export.pg,'open_connection'), patch.object(export.report,'show_assessment',side_effect=canonical_page):
                with self.server.report_exports.build(token,'LAB-001','d'*64,1,kind=held):
                    with patch.object(export.pg,'open_connection') as blocked:
                        code,_,raw=self.request('GET',self.target(kind=requested),headers={'Authorization':'Bearer '+token})
                    self.assertEqual(code,429); self.assertEqual(json.loads(raw)['error_code'],'export_busy'); blocked.assert_not_called()
                self.assertEqual(self.request('GET',self.target(kind=requested),headers={'Authorization':'Bearer '+token})[0],200)
        with patch.object(export.pg,'open_connection') as connect:
            with self.assertRaises(web.api.AccessError):
                with self.server.report_exports.build(token,'LAB-001','d'*64,kind='unknown'): pass
        connect.assert_not_called()

    def test_archive_and_summary_limits_and_expired_deadline_release_the_shared_slot(self):
        token=self.login(); headers={'Authorization':'Bearer '+token}
        for target, name, value in ((web.exports,'MAX_ARCHIVE_BYTES',128),(executive,'MAX_BYTES',16)):
            with patch.object(target,name,value), patch.object(export.pg,'open_connection'), \
                    patch.object(export.report,'show_assessment',side_effect=canonical_page):
                code,actual,_=self.request('GET',self.target(),headers=headers)
            self.assertEqual(code,413); self.assertNotIn('Content-Disposition',actual)
        expired=False; summarize=executive.summarize
        def slow(doc):
            nonlocal expired
            result=summarize(doc); expired=True; return result
        with patch.object(web.exports.time,'monotonic',side_effect=lambda:61 if expired else 0), \
                patch.object(executive,'summarize',side_effect=slow), patch.object(export.pg,'open_connection'), \
                patch.object(export.report,'show_assessment',side_effect=canonical_page):
            self.assertEqual(self.request('GET',self.target(),headers=headers)[0],503)
        with patch.object(export.pg,'open_connection'), patch.object(export.report,'show_assessment',side_effect=canonical_page):
            self.assertEqual(self.request('GET',self.target(),headers=headers)[0],200)

    def test_revocation_during_collection_or_synthesis_prevents_download_and_releases_slot(self):
        summarize=executive.summarize
        for phase in ('collection','synthesis'):
            token=self.login()
            def revoke_query(*args,**kwargs):
                self.server.service.auth.logout(token); return canonical_page(*args,**kwargs)
            def revoke_summary(doc):
                result=summarize(doc); self.server.service.auth.logout(token); return result
            with patch.object(export.pg,'open_connection'), patch.object(export.report,'show_assessment',
                    side_effect=revoke_query if phase=='collection' else canonical_page), \
                    patch.object(executive,'summarize',side_effect=revoke_summary if phase=='synthesis' else summarize):
                code,headers,_=self.request('GET',self.target(),headers={'Authorization':'Bearer '+token})
            self.assertEqual(code,401); self.assertNotIn('Content-Disposition',headers)
        token=self.login()
        with patch.object(export.pg,'open_connection'), patch.object(export.report,'show_assessment',side_effect=canonical_page):
            self.assertEqual(self.request('GET',self.target(),headers={'Authorization':'Bearer '+token})[0],200)


class ExecutiveArchiveVerifierTests(unittest.TestCase):
    def payloads(self):
        auth=auth_fixture.auth.LocalAuth(auth_fixture.policy()); token=auth.login('reader',auth_fixture.PASSWORD)['access_token']
        with patch.object(export.pg,'open_connection'), patch.object(export.report,'show_assessment',side_effect=canonical_page):
            with web.exports.ExportDelivery(auth).build(token,'LAB-001','d'*64,1,kind='executive') as (raw,_):
                with zipfile.ZipFile(io.BytesIO(raw)) as archive: return {name:archive.read(name) for name in archive.namelist()}

    def test_hashes_counts_and_fixed_archive_members_reject_tamper_and_compression(self):
        payloads=self.payloads()
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'executive.zip'; path.write_bytes(archive_bytes(payloads))
            self.assertEqual(verify.verify(path,'LAB-001',6,4,2)['files_verified'],4)
            for assessment, evaluations, findings, groups in (('OTHER',6,4,2),('LAB-001',5,4,2),('LAB-001',6,3,2),('LAB-001',6,4,1)):
                with self.assertRaises(ValueError): verify.verify(path,assessment,evaluations,findings,groups)
            for name in payloads:
                changed=dict(payloads); changed[name]+=b'changed'; path.write_bytes(archive_bytes(changed))
                with self.assertRaises(ValueError): verify.verify(path,'LAB-001',6,4,2)
            changed=dict(payloads); changed['../extra']=b'outside'
            for raw in (archive_bytes(changed),archive_bytes(payloads,zipfile.ZIP_DEFLATED)):
                path.write_bytes(raw)
                with self.assertRaises(ValueError): verify.verify(path,'LAB-001',6,4,2)

    def test_semantics_duplicate_json_and_evidence_in_refs_are_rejected_even_with_new_hashes(self):
        payloads=self.payloads()
        for mutation in ('semantics','duplicates','evidence','finding_count'):
            changed=dict(payloads); doc=json.loads(changed['executive.json'])
            if mutation=='semantics': doc['semantics']['source_bytes_revalidated']=True
            if mutation=='evidence': doc['recommendation_groups'][0]['occurrences'][0]['evidence']='secret'
            if mutation=='finding_count': doc['recommendation_groups'][0]['occurrences'][1]['finding_id']=doc['recommendation_groups'][0]['occurrences'][0]['finding_id']
            changed['executive.json']=executive.bounded_json(doc)
            if mutation=='duplicates': changed['executive.json']=changed['executive.json'].replace(b'{',b'{"executive_version":"0.6.14",',1)
            manifest=json.loads(changed['manifest.json'])
            for item in manifest['files']:
                item['sha256']=export.pg.digest(changed[item['name']]); item['size_bytes']=len(changed[item['name']])
            changed['manifest.json']=export.bounded_json(manifest)
            changed['manifest.json.sha256']=(export.pg.digest(changed['manifest.json'])+'  manifest.json\n').encode()
            with tempfile.TemporaryDirectory() as td:
                path=Path(td)/'executive.zip'; path.write_bytes(archive_bytes(changed))
                with self.assertRaises(ValueError): verify.verify(path,'LAB-001',6,4,2)

    def test_standalone_ascii_crlf_verifier_and_private_path_redaction(self):
        payloads=self.payloads(); source=VERIFIER.read_bytes(); source.decode('ascii')
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'executive.zip'; path.write_bytes(archive_bytes(payloads))
            args=['--archive',str(path),'--assessment-id','LAB-001','--evaluation-count','6','--finding-count','4','--recommendation-group-count','2']
            result=subprocess.run([sys.executable,'-']+args,input=source.replace(b'\n',b'\r\n'),capture_output=True,check=False,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr); self.assertEqual(json.loads(result.stdout)['files_verified'],4)
            output=io.StringIO()
            with redirect_stdout(output): self.assertEqual(verify.cli(['--archive',str(Path(td)/'NEVER-LOG-PATH')]+args[2:]),2)
            self.assertNotIn('NEVER-LOG-PATH',output.getvalue())


if __name__=='__main__': unittest.main()
