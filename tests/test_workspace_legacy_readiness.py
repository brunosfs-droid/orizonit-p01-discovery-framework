"""R01/R03 legacy readiness: input, SQL, HTTP and redacted audit gates."""
from contextlib import contextmanager
import http.client
import json
import os
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'server'))
import P01_Workspace_Legacy_Readiness as readiness
import P01_Workspace_Service as backend
import P01_Workspace_API as api
import P01_Workspace_Audit as audit
import test_workspace_legacy as legacy_tests
import test_workspace_model as models
import test_workspace_api as human_tests

pg, legacy, runtime = readiness.pg, readiness.legacy, readiness.runtime


class ReadinessInputTests(unittest.TestCase):
    def test_invalid_revision_rejected_without_sql_or_source_access(self):
        conn=Mock()
        for revision in (True,-1,'2',1.5,{},[]):
            with self.assertRaises(pg.PersistenceError):
                readiness.inspect(conn,'A',runtime.Token('A',1,'a'*32),{}, {},
                                  expected_revision=revision)
        conn.execute.assert_not_called()

    def test_invalid_snapshot_is_not_considered_ready(self):
        conn=Mock()
        with self.assertRaises(pg.PersistenceError):
            readiness.inspect(conn,'A',runtime.Token('A',1,'a'*32),{}, {})
        conn.execute.assert_not_called()

    def test_source_drift_before_receipt_lookup_fails_closed(self):
        conn=Mock()
        imported={'bundle_id':'bnd-'+'a'*20,'assessment_id':'LAB-001'}
        token=runtime.Token('A',1,'a'*32)
        @contextmanager
        def fake_scope(*args):
            yield 3
        with patch.object(legacy,'validate_snapshot'),patch.object(legacy,'scope',fake_scope),patch.object(
                legacy,'_snapshot',return_value={'different':'source'}):
            with self.assertRaisesRegex(pg.PersistenceError,'legacy_source_conflict'):
                readiness.inspect(conn,'A',token,{'import':imported},
                                  {'import':imported})
        conn.execute.assert_not_called()

    def test_http_route_and_audit_have_fixed_classification(self):
        bundle='bnd-'+'a'*20
        url=api.BASE+'/A/legacy/'+bundle+'/readiness'
        match=api.ROUTE.fullmatch(url)
        self.assertIsNotNone(match)
        self.assertEqual(match[5],bundle)
        self.assertEqual(audit.operation('GET',url+'?generation=1&secret=unsafe'),'legacy_readiness')
        self.assertEqual(audit.operation('POST',url),'other')
        self.assertEqual(audit.operation('GET',url+'/../../B'),'other')
        self.assertEqual(api.WorkspaceHandler._query(
            'generation=1&expected_revision=0', {'generation','expected_revision'}),
            {'generation':1,'expected_revision':0})
        with self.assertRaises(api.authn.AccessError):
            api.WorkspaceHandler._query('generation=1&limit=2',
                                        {'generation','expected_revision'})


@unittest.skipUnless(os.environ.get('CANCA_TEST_WORKSPACE_POSTGRES')=='1',
                     'workspace SQL opt-in required')
class ReadinessPostgreSQLTests(unittest.TestCase):
    setUp=legacy_tests.LegacyPostgreSQLTests.setUp
    legacy_rows=legacy_tests.LegacyPostgreSQLTests.legacy_rows
    role=legacy_tests.LegacyPostgreSQLTests.role
    human=legacy_tests.LegacyPostgreSQLTests.human

    def inspect(self,role='canca_ws_a',**opts):
        with self.role(role):
            return self.adapter.legacy_readiness(self.conn,self.token,self.bid,**opts)

    def test_reader_can_classify_before_and_after_atomic_backfill_without_mutation(self):
        before=self.legacy_rows()
        first=self.inspect(expected_revision=0)
        self.assertEqual(first['status'],'preview_required')
        self.assertEqual(first['revision'],0)
        self.assertEqual(first['identity_scope'],'identity_only')
        self.assertFalse(first['automatic_apply'])
        self.assertFalse(first['migration_complete'])
        self.assertEqual(first['historical_analysis'],'recorded')
        self.assertEqual(first['evaluation_count'],2)
        self.assertEqual(self.legacy_rows(),before)
        self.assertEqual(self.conn.execute(
            'SELECT count(*) FROM canca.workspace_legacy_imports').fetchone()[0],0)
        with self.role('canca_ws_writer'):
            plan=self.adapter.preview_legacy(self.conn,self.token,self.bid)
            applied=self.adapter.apply_legacy(self.conn,self.token,plan['plan_id'],'ready-case')
        self.assertEqual(applied['status'],'backfilled')
        second=self.inspect(expected_revision=1)
        self.assertEqual(second['status'],'already_backfilled')
        self.assertEqual(second['revision'],1)
        self.assertEqual(self.legacy_rows(),before)
        self.assertFalse(self.c._jobs)

    def test_stale_revision_is_rejected_without_writing(self):
        result=self.inspect(expected_revision=0)
        self.assertEqual(result['status'],'preview_required')
        with self.role('canca_ws_writer'):
            plan=self.adapter.preview_legacy(self.conn,self.token,self.bid)
            self.adapter.apply_legacy(self.conn,self.token,plan['plan_id'],'drift-test')
        with self.assertRaisesRegex(pg.PersistenceError,'model_revision_stale'):
            self.inspect(expected_revision=0)
        self.assertFalse(self.c._jobs)

    def test_cross_workspace_and_revoked_reader_denied_before_source_read(self):
        with self.role('canca_ws_b'),patch.object(self.adapter.legacy_sources,'prepare') as source:
            with self.assertRaises(pg.PersistenceError):
                self.adapter.legacy_readiness(self.conn,self.token,self.bid)
            source.assert_not_called()
        readiness.ws.revoke_workspace(self.conn,'A','canca_ws_a','workspace:read')
        with self.role('canca_ws_a'),patch.object(self.adapter.legacy_sources,'prepare') as source:
            with self.assertRaisesRegex(pg.PersistenceError,'workspace_access_denied'):
                self.adapter.legacy_readiness(self.conn,self.token,self.bid)
            source.assert_not_called()

    def test_source_tamper_is_denied_without_prior_receipt(self):
        receipt=self.rawdir/'receipt/import-receipt.json'
        receipt.write_bytes(receipt.read_bytes()+b'tampered')
        with self.assertRaises(pg.PersistenceError):
            self.inspect()
        self.assertEqual(self.conn.execute(
            'SELECT count(*) FROM canca.workspace_legacy_imports').fetchone()[0],0)

    def test_http_readiness_and_missing_generation_are_bounded(self):
        human,bearer=self.human()
        human.workspace.legacy_sources=self.adapter.legacy_sources
        server=api.WorkspaceServer(('127.0.0.1',0),human)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        def request(path):
            conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=10)
            try:
                conn.request('GET',path,headers={'Authorization':'Bearer '+bearer})
                response=conn.getresponse()
                return response.status,json.loads(response.read())
            finally:conn.close()
        path=api.BASE+'/A/legacy/'+self.bid+'/readiness'
        try:
            code,doc=request(path+'?generation='+str(self.token.generation)+'&expected_revision=0')
            self.assertEqual(code,200,doc)
            self.assertEqual(doc['status'],'preview_required')
            self.assertEqual(doc['readiness_version'],'0.6.38')
            self.assertNotIn('source_refs',doc)
            self.assertNotIn('source_sha256',doc)
            self.assertEqual(request(path)[0],400)
            self.assertEqual(request(path+'?generation='+str(self.token.generation)+'&limit=5')[0],400)
            self.assertEqual(request(path+'?generation='+str(self.token.generation)+'&expected_revision=1')[0],409)
        finally:
            server.shutdown();thread.join(5);server.server_close()


if __name__=='__main__':unittest.main()
