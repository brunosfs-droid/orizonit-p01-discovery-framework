"""Complete fenced executive previews, whitelisted pages and shared delivery limits."""
from copy import deepcopy
import json
import unittest
from unittest.mock import patch

import test_operator_auth as auth_fixture
import test_operator_web as http_fixture
from test_postgres_executive import history
import P01_Operator_Web as web

preview = web.previews
export = web.exports.export
executive = web.exports.executive


def many_history():
    doc = history([('finding','finding')] * 6)
    for index, analysis in enumerate(doc['analyses'][1:], 1):
        catalog = deepcopy(doc['catalogs'][0]); catalog['engine_sha256'] = f'{index:064x}'
        doc['catalogs'].append(catalog); analysis['engine_sha256'] = catalog['engine_sha256']
    return doc


def page_for(doc):
    def page(conn, assessment, after_analysis_id='', after_ordinal=-1, limit=100, expected_scope_sha256=None):
        if expected_scope_sha256 != doc['report_scope_sha256']:
            raise export.pg.PersistenceError('report_scope_conflict')
        selected = [r for r in doc['evaluations'] if (r['analysis_id'],r['ordinal']) > (after_analysis_id,after_ordinal)]
        rows = selected[:limit]; last = rows[-1] if rows else dict(analysis_id=after_analysis_id,ordinal=after_ordinal)
        header = {k:v for k,v in doc.items() if k not in {'export_version','evaluations','export_consistency'}}
        return deepcopy(dict(**header, snapshot_at_utc='2026-10-03T16:00:00+00:00', evaluations=rows,
            has_more=len(selected)>limit, next_cursor=dict(after_analysis_id=last['analysis_id'],after_ordinal=last['ordinal'])))
    return page


class ExecutivePreviewProjectionTests(unittest.TestCase):
    def test_twelve_distinct_groups_page_without_merging_historical_engines(self):
        summary = executive.summarize(many_history()); saved = deepcopy(summary)
        first = preview.project(summary); last = preview.project(summary,10)
        self.assertEqual(len(first['recommendation_groups']),10); self.assertEqual(len(last['recommendation_groups']),2)
        self.assertEqual(first['pagination'],dict(offset=0,page_size=10,has_more=True,next_offset=10))
        self.assertEqual(last['pagination'],dict(offset=10,page_size=10,has_more=False,next_offset=None))
        groups = first['recommendation_groups'] + last['recommendation_groups']
        self.assertEqual([g['group_id'] for g in groups],[g['group_id'] for g in summary['recommendation_groups']])
        self.assertEqual(len({g['group_id'] for g in groups}),12)
        self.assertEqual(first['recorded_finding_occurrences'],12); self.assertEqual(summary,saved)
        for offset in [-1,True,1,11,210,None,'0']:
            with self.assertRaises(web.api.AccessError): preview.project(summary,offset)
        with self.assertRaises(web.api.AccessError): preview.project(summary,20)

    def test_empty_history_and_whitelists_exclude_occurrence_data_and_arbitrary_extras(self):
        empty = preview.project(executive.summarize(history([])))
        self.assertEqual(empty['recommendation_groups'],[]); self.assertEqual(empty['coverage']['projection_status'],'no_imports')
        self.assertFalse(empty['pagination']['has_more']); self.assertFalse(empty['semantics']['current_risk_assessed'])
        doc = executive.summarize(history())
        for area in [doc,doc['lifecycle'],doc['coverage'],doc['identity'],doc['identity']['decisions'],doc['semantics'],doc['consistency']]:
            area['secret_extra'] = 'NEVER-PREVIEW-EXTRA'
        for group in doc['recommendation_groups']:
            group['rule']['extra'] = 'NEVER-PREVIEW-RULE'
            group['provenance']['extra'] = 'NEVER-PREVIEW-PROVENANCE'
            group['source_path'] = 'NEVER-PREVIEW-PATH'
        result = preview.project(doc); raw = json.dumps(result)
        self.assertNotIn('NEVER-',raw); self.assertNotIn('finding_id',raw); self.assertNotIn('bundle_id',raw)
        self.assertNotIn('"occurrences":',raw); self.assertNotIn('imports_without_analysis',raw)
        self.assertTrue(result['consistency']['terminal_empty_page_verified'])


class OperatorWebPreviewTests(unittest.TestCase):
    setUp = http_fixture.OperatorWebTests.setUp
    stop = http_fixture.OperatorWebTests.stop
    request = http_fixture.OperatorWebTests.request

    def login(self):
        code,_,raw = self.request('POST','/api/v1/operator/session',dict(username='reader',password=auth_fixture.PASSWORD),
                                {'Content-Type':'application/json'})
        self.assertEqual(code,201); return json.loads(raw)['access_token']

    def target(self, assessment='LAB-001', query=None):
        return '/api/v1/assessments/'+assessment+'/report/executive?'+(
            query if query is not None else 'expected_scope_sha256='+'d'*64)

    def test_complete_history_even_for_one_evaluation_pages_and_bounded_http_headers(self):
        token = self.login()
        with patch.object(export.pg,'open_connection'), patch.object(export.report,'show_assessment',side_effect=page_for(history())) as query:
            with self.server.executive_previews.build(token,'LAB-001','d'*64,limit=1) as (raw,checksum):
                doc = json.loads(raw); self.assertEqual(doc['consistency']['data_pages'],6)
                self.assertEqual(query.call_count,7); self.assertEqual(checksum,export.pg.digest(raw))
            code,headers,raw = self.request('GET',self.target(),headers={'Authorization':'Bearer '+token})
        self.assertEqual(code,200); self.assertEqual(headers['Content-Type'],'application/json; charset=utf-8')
        self.assertEqual(headers['X-Canca-Executive-Preview-SHA256'],export.pg.digest(raw))
        self.assertEqual(headers['X-Canca-Report-Scope-SHA256'],'d'*64); self.assertNotIn('Content-Disposition',headers)
        self.assertLess(len(raw),preview.MAX_BYTES)
        doc = json.loads(raw); self.assertEqual(doc['coverage']['evaluation_count'],6)
        self.assertEqual(doc['recorded_finding_occurrences'],4); self.assertEqual(doc['coverage']['outcomes']['no_finding'],2)
        self.assertEqual(doc['identity']['decisions']['review_required'],1)
        self.assertEqual(doc['recommendation_group_count'],2); self.assertFalse(doc['semantics']['current_risk_assessed'])
        self.assertNotIn(b'NEVER-',raw); self.assertNotIn(token.encode(),raw); self.assertNotIn(auth_fixture.PASSWORD.encode(),raw)

    def test_real_http_group_pagination_recollects_the_same_fenced_complete_history(self):
        token = self.login(); rows = []
        with patch.object(export.pg,'open_connection'), patch.object(export.report,'show_assessment',side_effect=page_for(many_history())) as query:
            for offset in [0,10]:
                code,_,raw = self.request('GET',self.target(query='expected_scope_sha256='+'d'*64+'&group_offset='+str(offset)),
                                          headers={'Authorization':'Bearer '+token})
                self.assertEqual(code,200); rows += json.loads(raw)['recommendation_groups']
        self.assertEqual(query.call_count,4); self.assertEqual(len(rows),12)
        self.assertTrue(all(c.kwargs['expected_scope_sha256']=='d'*64 for c in query.call_args_list))
        self.assertEqual([g['group_id'] for g in rows],[g['group_id'] for g in executive.summarize(many_history())['recommendation_groups']])

    def test_auth_origin_body_and_invalid_query_denials_precede_sql(self):
        token = self.login(); headers = {'Authorization':'Bearer '+token}
        with patch.object(export.pg,'open_connection') as connect:
            self.assertEqual(self.request('GET',self.target())[0],401)
            self.assertEqual(self.request('GET',self.target('OTHER'),headers=headers)[0],403)
            self.assertEqual(self.request('GET',self.target(),headers={**headers,'Origin':'http://attacker.invalid'})[0],403)
            self.assertEqual(self.request('GET',self.target(),headers={**headers,'Content-Length':'1'})[0],400)
            for query in ['', 'expected_scope_sha256=', 'expected_scope_sha256=bad',
                'expected_scope_sha256='+'d'*64+'&group_offset=-1', 'expected_scope_sha256='+'d'*64+'&group_offset=1',
                'expected_scope_sha256='+'d'*64+'&group_offset=210','expected_scope_sha256='+'d'*64+'&group_offset=00',
                'expected_scope_sha256='+'d'*64+'&group_offset=0&group_offset=10', 'expected_scope_sha256='+'d'*64+'&limit=1',
                'expected_scope_sha256='+'d'*64+'&password=PRIVATE']:
                code,_,raw = self.request('GET',self.target(query=query),headers=headers)
                self.assertEqual(code,400); self.assertNotIn(b'PRIVATE',raw)
            for method in ['POST','DELETE']:
                self.assertEqual(self.request(method,self.target(),headers=headers)[0],404)
            with patch.object(self.server,'RequestHandlerClass',web.api.OperatorHandler):
                self.assertEqual(self.request('GET',self.target(),headers=headers)[0],404)
        connect.assert_not_called()

    def test_missing_changed_out_of_range_and_unexpected_errors_do_not_emit_previews(self):
        token = self.login(); headers = {'Authorization':'Bearer '+token}
        with patch.object(export.pg,'open_connection'):
            for error,status in [(export.pg.PersistenceError('report_scope_conflict'),409), (RuntimeError('PRIVATE/password/path'),503)]:
                with patch.object(export.report,'show_assessment',side_effect=error):
                    code,h,raw = self.request('GET',self.target(),headers=headers)
                self.assertEqual(code,status); self.assertNotIn('X-Canca-Executive-Preview-SHA256',h); self.assertNotIn(b'PRIVATE',raw)
            with patch.object(export.report,'show_assessment',return_value=dict(status='not_found')):
                self.assertEqual(self.request('GET',self.target(),headers=headers)[0],404)
            with patch.object(export.report,'show_assessment',side_effect=page_for(history())):
                self.assertEqual(self.request('GET',self.target(query='expected_scope_sha256='+'d'*64+'&group_offset=10'),headers=headers)[0],400)

    def test_preview_and_both_zip_kinds_share_slot_until_context_exit(self):
        token = self.login(); headers = {'Authorization':'Bearer '+token}
        with patch.object(export.pg,'open_connection'), patch.object(export.report,'show_assessment',side_effect=page_for(history())):
            with self.server.executive_previews.build(token,'LAB-001','d'*64):
                with patch.object(export.pg,'open_connection') as blocked:
                    for suffix in ['/report/export','/report/executive/export','/report/executive']:
                        path='/api/v1/assessments/LAB-001'+suffix+'?expected_scope_sha256='+'d'*64
                        self.assertEqual(self.request('GET',path,headers=headers)[0],429)
                blocked.assert_not_called()
            for kind in ['technical','executive']:
                with self.server.report_exports.build(token,'LAB-001','d'*64,kind=kind):
                    with patch.object(export.pg,'open_connection') as blocked:
                        self.assertEqual(self.request('GET',self.target(),headers=headers)[0],429)
                    blocked.assert_not_called()
            self.assertEqual(self.request('GET',self.target(),headers=headers)[0],200)

    def test_byte_deadline_and_serialization_failures_release_the_shared_slot(self):
        token = self.login(); headers = {'Authorization':'Bearer '+token}
        with patch.object(web.exports,'MAX_SECONDS',-1), patch.object(export.pg,'open_connection') as connect:
            self.assertEqual(self.request('GET',self.target(),headers=headers)[0],503)
        connect.assert_not_called()
        with patch.object(export.pg,'open_connection'), patch.object(export.report,'show_assessment',side_effect=page_for(history())):
            with patch.object(preview,'MAX_BYTES',128):
                self.assertEqual(self.request('GET',self.target(),headers=headers)[0],413)
            with patch.object(preview,'project',side_effect=RuntimeError('PRIVATE/path')):
                code,_,raw = self.request('GET',self.target(),headers=headers)
                self.assertEqual(code,503); self.assertNotIn(b'PRIVATE',raw)
            clock=[0.0]; project=preview.project
            def expired(*args):
                doc=project(*args); clock[0]=61.0; return doc
            with patch.object(web.exports.time,'monotonic',side_effect=lambda:clock[0]), patch.object(preview,'project',side_effect=expired):
                self.assertEqual(self.request('GET',self.target(),headers=headers)[0],503)
            self.assertEqual(self.request('GET',self.target(),headers=headers)[0],200)

    def test_revocation_during_collection_synthesis_or_projection_suppresses_the_response(self):
        for phase in ['query','synthesis','projection']:
            token=self.login(); target={'query':export.report,'synthesis':executive,'projection':preview}[phase]
            name={'query':'show_assessment','synthesis':'summarize','projection':'project'}[phase]
            original=page_for(history()) if phase=='query' else getattr(target,name)
            def revoke(*args,**kwargs):
                result=original(*args,**kwargs); self.server.service.auth.logout(token); return result
            with patch.object(export.pg,'open_connection'), patch.object(export.report,'show_assessment',side_effect=page_for(history())), \
                    patch.object(target,name,side_effect=revoke):
                code,headers,_=self.request('GET',self.target(),headers={'Authorization':'Bearer '+token})
            self.assertEqual(code,401); self.assertNotIn('X-Canca-Executive-Preview-SHA256',headers)
        token=self.login()
        with patch.object(export.pg,'open_connection'), patch.object(export.report,'show_assessment',side_effect=page_for(history())):
            self.assertEqual(self.request('GET',self.target(),headers={'Authorization':'Bearer '+token})[0],200)


if __name__ == '__main__': unittest.main()
