"""Durable non-executing review lifecycle with real PostgreSQL opt-in."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'persistence'))
import P01_Workspace_Intent_Ledger as ledger
import P01_Workspace_Service as service
import test_workspace_model as models
import test_postgres_workspace as foundation
pg, ws, runtime, model = ledger.pg, ledger.ws, ledger.runtime, ledger.model


class InputTests(unittest.TestCase):
    def test_invalid_inputs_never_touch_database(self):
        for kwargs in ({'ttl_seconds':True}, {'ttl_seconds':301}, {'ack_authorized_access':False}):
            with self.assertRaises(pg.PersistenceError):
                ledger.record(Mock(),None,'lab','auth_only','a'*64,'request',**kwargs)
        with self.assertRaises(pg.PersistenceError):
            ledger.history(Mock(),'A',runtime.Token('A',1,'a'*32),'../B')

    def test_migration_prefix_pins_old_contract(self):
        rows=[(i,pg.digest(p.read_bytes())) for i,p in enumerate(pg.INTENT_MIGRATIONS,1)]
        self.assertEqual(len(pg.migration_prefix(rows,intents=True)),10)
        with self.assertRaises(pg.PersistenceError):pg.migration_prefix(rows,legacy=True)
        rows[-1]=(10,'0'*64)
        with self.assertRaises(pg.PersistenceError):pg.migration_prefix(rows,intents=True)

    def test_migration_errors_redacted(self):
        with patch.object(pg,'open_connection',side_effect=RuntimeError('private password')),redirect_stdout(io.StringIO()) as output:
            self.assertEqual(ledger.cli(['migrate']),2)
        self.assertNotIn('private',output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['error_code'],'database_failed')


@unittest.skipUnless(os.environ.get('CANCA_TEST_WORKSPACE_POSTGRES')=='1','workspace SQL opt-in required')
class LedgerTests(unittest.TestCase):
    role=foundation.WorkspacePostgreSQLTests.role
    legacy_rows=foundation.WorkspacePostgreSQLTests.legacy_rows

    def setUp(self):
        models.ModelPostgreSQLTests.setUp(self)
        self.c.shutdown(timeout=0)
        self.assertEqual(pg.migrate(self.conn,intents=True)['migration'],10)
        for role in ('canca_ws_a','canca_ws_b','canca_ws_writer'):
            from psycopg import sql
            self.conn.execute(sql.SQL('GRANT SELECT ON canca.workspace_scan_intents,canca.workspace_scan_decisions TO {}').format(sql.Identifier(role)))
        self.conn.execute('GRANT INSERT ON canca.workspace_scan_intents,canca.workspace_scan_decisions TO canca_ws_writer')
        self.restart()
        self.service=service.WorkspaceService(self.c,service.SourceRoots({}),approved_scan_scopes=ledger.live.ApprovedScopes({
            'A':{'lab':{'networks':['192.168.100.20/32'],'modes':['auth_only','full_enrichment']}},
            'B':{'lab':{'networks':['192.168.100.20/32'],'modes':['auth_only']}}}))
        with self.role('canca_ws_writer'):
            self.digest=self.service.live_scan_intent(self.conn,self.token,'lab','auth_only',ack_authorized_access=True)['scope_digest_sha256']

    def restart(self):
        control=pg.open_connection(); self.addCleanup(control.close); control.execute('SET ROLE canca_ws_coordinator')
        self.c=runtime.Coordinator(runtime.SessionLease(control),heartbeat_seconds=30); self.c.start()
        self.addCleanup(lambda:self.c.shutdown(timeout=0) if not self.c._terminated else None)
        with self.role('canca_ws_writer'):self.token=self.c.open(self.conn,'A',self.c.generation)

    def record(self,request='request',**kwargs):
        with self.role('canca_ws_writer'):
            return self.service.persist_scan_intent(self.conn,self.token,'lab','auth_only',self.digest,request,
                                                   ack_authorized_access=True,**kwargs)

    def decide(self,intent,decision,request):
        with self.role('canca_ws_writer'):
            return self.service.decide_scan_intent(self.conn,self.token,'lab','auth_only',self.digest,
                intent,decision,request,ack_authorized_access=True)

    def test_durable_lifecycle_replay_and_no_execution(self):
        one=self.record(); self.assertTrue(self.record()['replayed']); ident=one['intent_id']
        self.assertFalse(one['execution_authorized'])
        self.decide(ident,'approved','approve')
        consumed=self.decide(ident,'consumed','consume')
        self.assertFalse(consumed['execution_authorized'])
        self.assertTrue(self.decide(ident,'consumed','consume')['replayed'])
        with self.assertRaisesRegex(pg.PersistenceError,'intent_transition_denied'):
            self.decide(ident,'consumed','consume-again')
        with self.role('canca_ws_a'):
            result=self.service.scan_intent_history(self.conn,self.token,ident)
        self.assertEqual([e['decision'] for e in result['decisions']],['approved','consumed'])
        self.assertTrue(all(e['author_role']=='canca_ws_writer' for e in result['decisions']))
        self.assertNotIn('192.168',str(result)); self.assertNotIn('lease_sha256',str(result))
        self.assertEqual(self.before,self.legacy_rows())

    def test_rejection_revocation_and_conflicting_replay(self):
        first=self.record()['intent_id']; second=self.record('other')['intent_id']
        self.decide(first,'rejected','reject')
        with self.assertRaisesRegex(pg.PersistenceError,'intent_transition_denied'):self.decide(first,'approved','approve')
        self.decide(second,'approved','approve');self.decide(second,'revoked','revoke')
        with self.assertRaisesRegex(pg.PersistenceError,'intent_transition_denied'):self.decide(second,'consumed','consume')
        with self.assertRaisesRegex(pg.PersistenceError,'intent_conflict'):self.decide(second,'rejected','reject')
        with self.assertRaisesRegex(pg.PersistenceError,'intent_conflict'):self.record(ttl_seconds=90)

    def test_restart_preserves_history_but_never_rearms(self):
        ident=self.record()['intent_id'];self.decide(ident,'approved','approve')
        self.c.shutdown(timeout=0);self.restart();self.service.coordinator=self.c
        with self.role('canca_ws_writer'):
            history=self.service.scan_intent_history(self.conn,self.token,ident)
            self.assertFalse(history['context_current']);self.assertFalse(history['execution_authorized'])
            self.digest=self.service.live_scan_intent(self.conn,self.token,'lab','auth_only',ack_authorized_access=True)['scope_digest_sha256']
        with self.assertRaisesRegex(pg.PersistenceError,'intent_stale'):self.decide(ident,'consumed','consume')
        with self.assertRaisesRegex(pg.PersistenceError,'intent_stale'):self.record()

    def test_expired_intent_and_scope_change_fail_closed(self):
        ident=self.record()['intent_id']
        # Trusted maintenance simulates elapsed server time, without sleeps.
        self.conn.execute("UPDATE canca.workspace_scan_intents SET created_at=clock_timestamp()-interval '120 seconds',expires_at=clock_timestamp()-interval '60 seconds'")
        with self.assertRaisesRegex(pg.PersistenceError,'intent_stale'):self.decide(ident,'approved','approve')
        with self.role('canca_ws_a'):
            self.assertTrue(self.service.scan_intent_history(self.conn,self.token,ident)['expired'])
        self.digest='0'*64
        with self.assertRaisesRegex(pg.PersistenceError,'intent_stale'):self.record('new')

    def test_cross_workspace_and_reader_cannot_write(self):
        ident=self.record()['intent_id']
        with self.role('canca_ws_a'),self.assertRaises(pg.PersistenceError):
            self.service.persist_scan_intent(self.conn,self.token,'lab','auth_only',self.digest,'bad',ack_authorized_access=True)
        with self.role('canca_ws_writer'):self.c.close(self.conn,'A',self.token.generation)
        with self.role('canca_ws_writer'):b=self.c.open(self.conn,'B',self.c.generation)
        with self.role('canca_ws_writer'),self.assertRaisesRegex(pg.PersistenceError,'intent_not_found'):
            self.service.scan_intent_history(self.conn,b,ident)
        self.conn.execute("DELETE FROM canca.workspace_grants WHERE workspace_id='B' AND principal_role='canca_ws_writer'")
        with self.role('canca_ws_writer'),self.assertRaises(pg.PersistenceError):
            self.service.scan_intent_history(self.conn,b,ident)

    def test_revoked_workspace_reader_cannot_retrieve_ledger_history(self):
        ident=self.record()['intent_id']
        with self.role('canca_ws_a'):
            history=self.service.scan_intent_history(self.conn,self.token,ident)
            self.assertEqual(history['intent_id'],ident)
            self.assertFalse(history['execution_authorized'])
        self.conn.execute(
            "DELETE FROM canca.workspace_grants WHERE workspace_id='A' AND principal_role='canca_ws_a'")
        with self.role('canca_ws_a'),self.assertRaises(pg.PersistenceError):
            self.service.scan_intent_history(self.conn,self.token,ident)
        with self.role('canca_ws_writer'):
            allowed=self.service.scan_intent_history(self.conn,self.token,ident)
            self.assertEqual(allowed['intent_id'],ident)
            self.assertFalse(allowed['execution_authorized'])

    def test_reader_regrant_restores_history_without_execution(self):
        ident=self.record()['intent_id']
        self.conn.execute(
            "DELETE FROM canca.workspace_grants WHERE workspace_id='A' AND principal_role='canca_ws_a'")
        with self.role('canca_ws_a'),self.assertRaises(pg.PersistenceError):
            self.service.scan_intent_history(self.conn,self.token,ident)
        self.conn.execute(
            "INSERT INTO canca.workspace_grants VALUES ('A','canca_ws_a','workspace:read')")
        with self.role('canca_ws_a'):
            restored=self.service.scan_intent_history(self.conn,self.token,ident)
        self.assertEqual(restored['intent_id'],ident)
        self.assertEqual(restored['decisions'],[])
        self.assertFalse(restored['execution_authorized'])
        self.assertFalse(restored['network_activity_performed'])

    def test_regranted_reader_cannot_change_approved_ledger(self):
        ident=self.record()['intent_id']
        self.decide(ident,'approved','approve')
        with self.role('canca_ws_a'):
            before=self.service.scan_intent_history(self.conn,self.token,ident)
        self.conn.execute(
            "DELETE FROM canca.workspace_grants WHERE workspace_id='A' AND principal_role='canca_ws_a'")
        with self.role('canca_ws_a'),self.assertRaises(pg.PersistenceError):
            self.service.scan_intent_history(self.conn,self.token,ident)
        self.conn.execute(
            "INSERT INTO canca.workspace_grants VALUES ('A','canca_ws_a','workspace:read')")
        with self.role('canca_ws_a'):
            after=self.service.scan_intent_history(self.conn,self.token,ident)
            with self.assertRaises(pg.PersistenceError):
                self.service.decide_scan_intent(
                    self.conn,self.token,'lab','auth_only',self.digest,
                    ident,'consumed','reader-attempt',ack_authorized_access=True)
        self.assertEqual(before['decisions'],after['decisions'])
        self.assertFalse(after['execution_authorized'])
        with self.role('canca_ws_writer'):
            final=self.service.scan_intent_history(self.conn,self.token,ident)
        self.assertEqual(final['decisions'],before['decisions'])

    def test_workspace_b_reader_never_sees_workspace_a_intent(self):
        intent=self.record()['intent_id']
        self.decide(intent,'approved','approve')
        with self.role('canca_ws_a'):
            visible=self.service.scan_intent_history(self.conn,self.token,intent)
        self.assertEqual([row['decision'] for row in visible['decisions']],['approved'])
        with self.role('canca_ws_writer'):
            self.c.close(self.conn,'A',self.token.generation)
            b=self.c.open(self.conn,'B',self.c.generation)
        with self.role('canca_ws_b'),self.assertRaisesRegex(pg.PersistenceError,'intent_not_found'):
            self.service.scan_intent_history(self.conn,b,intent)
        with self.role('canca_ws_writer'),self.assertRaisesRegex(pg.PersistenceError,'intent_not_found'):
            self.service.scan_intent_history(self.conn,b,intent)

    def test_switchback_history_is_nonexecuting_and_fenced(self):
        ident=self.record()['intent_id']
        self.decide(ident,'approved','approve')
        old_token=self.token
        with self.role('canca_ws_writer'):
            self.c.close(self.conn,'A',old_token.generation)
            other=self.c.open(self.conn,'B',self.c.generation)
        with self.role('canca_ws_b'),self.assertRaisesRegex(pg.PersistenceError,'intent_not_found'):
            self.service.scan_intent_history(self.conn,other,ident)
        with self.role('canca_ws_writer'):
            self.c.close(self.conn,'B',other.generation)
            new_token=self.c.open(self.conn,'A',self.c.generation)
            history=self.service.scan_intent_history(self.conn,new_token,ident)
        self.assertEqual([x['decision'] for x in history['decisions']],['approved'])
        self.assertFalse(history['context_current'])
        self.assertFalse(history['execution_authorized'])
        with self.role('canca_ws_writer'),self.assertRaisesRegex(pg.PersistenceError,'intent_stale'):
            self.service.decide_scan_intent(
                self.conn,new_token,'lab','auth_only',self.digest,ident,
                'consumed','switchback-consume',ack_authorized_access=True)

    def test_old_generation_token_cannot_read_after_workspace_switchback(self):
        ident=self.record()['intent_id']
        old_token=self.token
        with self.role('canca_ws_writer'):
            self.c.close(self.conn,'A',old_token.generation)
            b=self.c.open(self.conn,'B',self.c.generation)
            self.c.close(self.conn,'B',b.generation)
            fresh=self.c.open(self.conn,'A',self.c.generation)
        with self.role('canca_ws_writer'),self.assertRaises(pg.PersistenceError):
            self.service.scan_intent_history(self.conn,old_token,ident)
        with self.role('canca_ws_writer'):
            restored=self.service.scan_intent_history(self.conn,fresh,ident)
        self.assertEqual(restored['intent_id'],ident)
        self.assertFalse(restored['context_current'])
        self.assertFalse(restored['execution_authorized'])

    def test_workspace_a_reader_grant_does_not_authorize_workspace_b(self):
        ident=self.record()['intent_id']
        with self.role('canca_ws_a'):
            visible=self.service.scan_intent_history(self.conn,self.token,ident)
        self.assertEqual(visible['intent_id'],ident)
        with self.role('canca_ws_writer'):
            self.c.close(self.conn,'A',self.token.generation)
            b=self.c.open(self.conn,'B',self.c.generation)
        with self.role('canca_ws_a'),self.assertRaises(pg.PersistenceError):
            self.service.scan_intent_history(self.conn,b,ident)
        with self.role('canca_ws_b'),self.assertRaisesRegex(pg.PersistenceError,'intent_not_found'):
            self.service.scan_intent_history(self.conn,b,ident)

    def test_new_workspace_b_read_grant_does_not_expose_a_history(self):
        ident=self.record()['intent_id']
        self.decide(ident,'approved','approve')
        self.conn.execute(
            "INSERT INTO canca.workspace_grants VALUES ('B','canca_ws_a','workspace:read')")
        with self.role('canca_ws_writer'):
            self.c.close(self.conn,'A',self.token.generation)
            b=self.c.open(self.conn,'B',self.c.generation)
        with self.role('canca_ws_a'),self.assertRaisesRegex(pg.PersistenceError,'intent_not_found'):
            self.service.scan_intent_history(self.conn,b,ident)
        with self.role('canca_ws_writer'):
            self.c.close(self.conn,'B',b.generation)
            reopened=self.c.open(self.conn,'A',self.c.generation)
        with self.role('canca_ws_a'):
            history=self.service.scan_intent_history(self.conn,reopened,ident)
        self.assertEqual([x['decision'] for x in history['decisions']],['approved'])
        self.assertFalse(history['context_current'])
        self.assertFalse(history['execution_authorized'])

    def test_revoking_b_reader_grant_preserves_a_history_permission(self):
        ident=self.record()['intent_id']
        self.conn.execute(
            "INSERT INTO canca.workspace_grants VALUES ('B','canca_ws_a','workspace:read')")
        self.conn.execute(
            "DELETE FROM canca.workspace_grants WHERE workspace_id='B' AND principal_role='canca_ws_a'")
        with self.role('canca_ws_a'):
            history=self.service.scan_intent_history(self.conn,self.token,ident)
        self.assertEqual(history['intent_id'],ident)
        self.assertFalse(history['execution_authorized'])
        with self.role('canca_ws_writer'):
            self.c.close(self.conn,'A',self.token.generation)
            b=self.c.open(self.conn,'B',self.c.generation)
        with self.role('canca_ws_a'),self.assertRaises(pg.PersistenceError):
            self.service.scan_intent_history(self.conn,b,ident)

    def test_selective_b_regrant_cannot_expose_a_history(self):
        ident=self.record()['intent_id']
        self.decide(ident,'approved','approve')
        self.conn.execute(
            "INSERT INTO canca.workspace_grants VALUES ('B','canca_ws_a','workspace:read')")
        self.conn.execute(
            "DELETE FROM canca.workspace_grants WHERE workspace_id='B' AND principal_role='canca_ws_a'")
        self.conn.execute(
            "INSERT INTO canca.workspace_grants VALUES ('B','canca_ws_a','workspace:read')")
        with self.role('canca_ws_writer'):
            self.c.close(self.conn,'A',self.token.generation)
            b=self.c.open(self.conn,'B',self.c.generation)
        with self.role('canca_ws_a'),self.assertRaisesRegex(pg.PersistenceError,'intent_not_found'):
            self.service.scan_intent_history(self.conn,b,ident)
        with self.role('canca_ws_writer'):
            self.c.close(self.conn,'B',b.generation)
            reopened=self.c.open(self.conn,'A',self.c.generation)
        with self.role('canca_ws_a'):
            history=self.service.scan_intent_history(self.conn,reopened,ident)
        self.assertEqual([x['decision'] for x in history['decisions']],['approved'])
        self.assertFalse(history['context_current'])
        self.assertFalse(history['execution_authorized'])

    def test_reader_revocation_does_not_mutate_persisted_decisions(self):
        ident=self.record()['intent_id']
        self.decide(ident,'approved','approve')
        with self.role('canca_ws_a'):
            before=self.service.scan_intent_history(self.conn,self.token,ident)
        self.conn.execute(
            "DELETE FROM canca.workspace_grants WHERE workspace_id='A' AND principal_role='canca_ws_a'")
        with self.role('canca_ws_a'),self.assertRaises(pg.PersistenceError):
            self.service.scan_intent_history(self.conn,self.token,ident)
        with self.role('canca_ws_writer'):
            after=self.service.scan_intent_history(self.conn,self.token,ident)
        self.assertEqual(before['decisions'],after['decisions'])
        self.assertEqual([x['decision'] for x in after['decisions']],['approved'])
        self.assertFalse(after['execution_authorized'])

    def test_reader_regrant_preserves_approved_history_integrity(self):
        ident=self.record()['intent_id']
        self.decide(ident,'approved','approve')
        with self.role('canca_ws_a'):
            before=self.service.scan_intent_history(self.conn,self.token,ident)
        self.conn.execute(
            "DELETE FROM canca.workspace_grants WHERE workspace_id='A' AND principal_role='canca_ws_a'")
        with self.role('canca_ws_a'),self.assertRaises(pg.PersistenceError):
            self.service.scan_intent_history(self.conn,self.token,ident)
        self.conn.execute(
            "INSERT INTO canca.workspace_grants VALUES ('A','canca_ws_a','workspace:read')")
        with self.role('canca_ws_a'):
            after=self.service.scan_intent_history(self.conn,self.token,ident)
        self.assertEqual(before['decisions'],after['decisions'])
        self.assertEqual([e['decision'] for e in after['decisions']],['approved'])
        self.assertFalse(after['execution_authorized'])
        self.assertFalse(after['network_activity_performed'])

    def test_reader_regrant_preserves_full_terminal_decision_chain(self):
        ident=self.record()['intent_id']
        self.decide(ident,'approved','approve')
        self.decide(ident,'consumed','consume')
        with self.role('canca_ws_a'):
            before=self.service.scan_intent_history(self.conn,self.token,ident)
        self.assertEqual([event['decision'] for event in before['decisions']],
                         ['approved','consumed'])
        self.conn.execute(
            "DELETE FROM canca.workspace_grants WHERE workspace_id='A' AND principal_role='canca_ws_a'")
        with self.role('canca_ws_a'),self.assertRaises(pg.PersistenceError):
            self.service.scan_intent_history(self.conn,self.token,ident)
        self.conn.execute(
            "INSERT INTO canca.workspace_grants VALUES ('A','canca_ws_a','workspace:read')")
        with self.role('canca_ws_a'):
            after=self.service.scan_intent_history(self.conn,self.token,ident)
        self.assertEqual(before['decisions'],after['decisions'])
        self.assertEqual([event['sequence'] for event in after['decisions']],[1,2])
        self.assertFalse(after['execution_authorized'])
        self.assertFalse(after['network_activity_performed'])

    def test_terminal_chain_remains_closed_after_reader_regrant(self):
        ident=self.record()['intent_id']
        self.decide(ident,'approved','approve')
        self.decide(ident,'consumed','consume')
        self.conn.execute(
            "DELETE FROM canca.workspace_grants WHERE workspace_id='A' AND principal_role='canca_ws_a'")
        self.conn.execute(
            "INSERT INTO canca.workspace_grants VALUES ('A','canca_ws_a','workspace:read')")
        with self.role('canca_ws_a'):
            history=self.service.scan_intent_history(self.conn,self.token,ident)
        self.assertEqual([e['decision'] for e in history['decisions']],['approved','consumed'])
        self.assertFalse(history['execution_authorized'])
        with self.assertRaisesRegex(pg.PersistenceError,'intent_transition_denied'):
            self.decide(ident,'consumed','consume-after-regrant')
        with self.role('canca_ws_writer'):
            unchanged=self.service.scan_intent_history(self.conn,self.token,ident)
        self.assertEqual(unchanged['decisions'],history['decisions'])

    def test_terminal_replay_after_reader_regrant_is_idempotent(self):
        ident=self.record()['intent_id']
        self.decide(ident,'approved','approve')
        self.decide(ident,'consumed','consume')
        with self.role('canca_ws_writer'):
            before=self.service.scan_intent_history(self.conn,self.token,ident)
        self.conn.execute(
            "DELETE FROM canca.workspace_grants WHERE workspace_id='A' AND principal_role='canca_ws_a'")
        self.conn.execute(
            "INSERT INTO canca.workspace_grants VALUES ('A','canca_ws_a','workspace:read')")
        repeated=self.decide(ident,'consumed','consume')
        self.assertTrue(repeated['replayed'])
        self.assertFalse(repeated['execution_authorized'])
        with self.role('canca_ws_a'):
            after=self.service.scan_intent_history(self.conn,self.token,ident)
        self.assertEqual(before['decisions'],after['decisions'])
        self.assertEqual([x['sequence'] for x in after['decisions']],[1,2])
        self.assertFalse(after['network_activity_performed'])

    def test_terminal_replay_conflict_after_reader_regrant_is_denied(self):
        ident=self.record()['intent_id']
        self.decide(ident,'approved','approve')
        self.decide(ident,'consumed','consume')
        with self.role('canca_ws_writer'):
            before=self.service.scan_intent_history(self.conn,self.token,ident)
        self.conn.execute(
            "DELETE FROM canca.workspace_grants WHERE workspace_id='A' AND principal_role='canca_ws_a'")
        self.conn.execute(
            "INSERT INTO canca.workspace_grants VALUES ('A','canca_ws_a','workspace:read')")
        with self.assertRaises(pg.PersistenceError):
            self.decide(ident,'rejected','consume')
        with self.role('canca_ws_a'):
            after=self.service.scan_intent_history(self.conn,self.token,ident)
        self.assertEqual(before['decisions'],after['decisions'])
        self.assertEqual([x['decision'] for x in after['decisions']],['approved','consumed'])
        self.assertFalse(after['execution_authorized'])

    def test_regranted_reader_cannot_change_consumed_intent(self):
        ident=self.record()['intent_id']
        self.decide(ident,'approved','approve')
        self.decide(ident,'consumed','consume')
        self.conn.execute(
            "DELETE FROM canca.workspace_grants WHERE workspace_id='A' AND principal_role='canca_ws_a'")
        self.conn.execute(
            "INSERT INTO canca.workspace_grants VALUES ('A','canca_ws_a','workspace:read')")
        with self.role('canca_ws_a'):
            history=self.service.scan_intent_history(self.conn,self.token,ident)
            with self.assertRaises(pg.PersistenceError):
                self.service.decide_scan_intent(
                    self.conn,self.token,'lab','auth_only',self.digest,
                    ident,'rejected','reader-terminal-attempt',ack_authorized_access=True)
        with self.role('canca_ws_writer'):
            unchanged=self.service.scan_intent_history(self.conn,self.token,ident)
        self.assertEqual(unchanged['decisions'],history['decisions'])
        self.assertFalse(unchanged['execution_authorized'])

    def test_regranted_reader_cannot_insert_direct_ledger_decisions(self):
        from psycopg import errors
        ident=self.record()['intent_id']
        self.decide(ident,'approved','approve')
        self.conn.execute(
            "DELETE FROM canca.workspace_grants WHERE workspace_id='A' AND principal_role='canca_ws_a'")
        self.conn.execute(
            "INSERT INTO canca.workspace_grants VALUES ('A','canca_ws_a','workspace:read')")
        with self.role('canca_ws_a'),model.scope(self.conn,'A',self.token,writing=False):
            # Isolate the expected SQL error in a nested transaction/savepoint:
            # the enclosing role and model scopes must remain usable.
            with self.assertRaises(errors.InsufficientPrivilege):
                with self.conn.transaction():
                    self.conn.execute(
                        "INSERT INTO canca.workspace_scan_decisions "
                        "(workspace_id,intent_id,sequence,request_id,decision,created_revision) "
                        "VALUES('A',%s,2,'reader-forged','consumed',0)",(ident,))
        with self.role('canca_ws_writer'):
            history=self.service.scan_intent_history(self.conn,self.token,ident)
        self.assertEqual([e['decision'] for e in history['decisions']],['approved'])
        self.assertFalse(history['execution_authorized'])

    def test_regranted_reader_cannot_update_or_delete_ledger_decisions(self):
        from psycopg import errors
        ident=self.record()['intent_id']
        self.decide(ident,'approved','approve')
        self.conn.execute(
            "DELETE FROM canca.workspace_grants WHERE workspace_id='A' AND principal_role='canca_ws_a'")
        self.conn.execute(
            "INSERT INTO canca.workspace_grants VALUES ('A','canca_ws_a','workspace:read')")
        with self.role('canca_ws_a'),model.scope(self.conn,'A',self.token,writing=False):
            for statement in (
                "UPDATE canca.workspace_scan_decisions SET decision='rejected' "
                "WHERE workspace_id='A' AND intent_id=%s",
                "DELETE FROM canca.workspace_scan_decisions "
                "WHERE workspace_id='A' AND intent_id=%s",
            ):
                with self.assertRaises(errors.InsufficientPrivilege):
                    with self.conn.transaction():
                        self.conn.execute(statement,(ident,))
        with self.role('canca_ws_writer'):
            history=self.service.scan_intent_history(self.conn,self.token,ident)
        self.assertEqual([e['decision'] for e in history['decisions']],['approved'])
        self.assertFalse(history['execution_authorized'])

    def test_regranted_reader_cannot_truncate_ledger_decisions(self):
        from psycopg import errors
        ident=self.record()['intent_id']
        self.decide(ident,'approved','approve')
        self.conn.execute(
            "DELETE FROM canca.workspace_grants WHERE workspace_id='A' AND principal_role='canca_ws_a'")
        self.conn.execute(
            "INSERT INTO canca.workspace_grants VALUES ('A','canca_ws_a','workspace:read')")
        with self.role('canca_ws_a'),model.scope(self.conn,'A',self.token,writing=False):
            with self.assertRaises(errors.InsufficientPrivilege):
                with self.conn.transaction():
                    self.conn.execute("TRUNCATE TABLE canca.workspace_scan_decisions")
        with self.role('canca_ws_writer'):
            history=self.service.scan_intent_history(self.conn,self.token,ident)
        self.assertEqual([event['decision'] for event in history['decisions']],['approved'])
        self.assertFalse(history['execution_authorized'])

    def test_regranted_reader_cannot_truncate_scan_intents(self):
        from psycopg import errors
        ident=self.record()['intent_id']
        self.decide(ident,'approved','approve')
        self.conn.execute(
            "DELETE FROM canca.workspace_grants WHERE workspace_id='A' AND principal_role='canca_ws_a'")
        self.conn.execute(
            "INSERT INTO canca.workspace_grants VALUES ('A','canca_ws_a','workspace:read')")
        with self.role('canca_ws_a'),model.scope(self.conn,'A',self.token,writing=False):
            with self.assertRaises(errors.InsufficientPrivilege):
                with self.conn.transaction():
                    self.conn.execute("TRUNCATE TABLE canca.workspace_scan_intents CASCADE")
        with self.role('canca_ws_writer'):
            history=self.service.scan_intent_history(self.conn,self.token,ident)
        self.assertEqual([event['decision'] for event in history['decisions']],['approved'])
        self.assertFalse(history['execution_authorized'])

    def test_regranted_reader_cannot_delete_scan_intent(self):
        from psycopg import errors
        ident=self.record()['intent_id']
        self.decide(ident,'approved','approve')
        self.conn.execute(
            "DELETE FROM canca.workspace_grants WHERE workspace_id='A' AND principal_role='canca_ws_a'")
        self.conn.execute(
            "INSERT INTO canca.workspace_grants VALUES ('A','canca_ws_a','workspace:read')")
        with self.role('canca_ws_a'),model.scope(self.conn,'A',self.token,writing=False):
            with self.assertRaises(errors.InsufficientPrivilege):
                with self.conn.transaction():
                    self.conn.execute(
                        "DELETE FROM canca.workspace_scan_intents "
                        "WHERE workspace_id='A' AND intent_id=%s",(ident,))
        with self.role('canca_ws_writer'):
            history=self.service.scan_intent_history(self.conn,self.token,ident)
        self.assertEqual([event['decision'] for event in history['decisions']],['approved'])
        self.assertFalse(history['execution_authorized'])

    def test_regranted_reader_cannot_update_scan_intent(self):
        from psycopg import errors
        ident=self.record()['intent_id']
        self.decide(ident,'approved','approve')
        self.conn.execute(
            "DELETE FROM canca.workspace_grants WHERE workspace_id='A' AND principal_role='canca_ws_a'")
        self.conn.execute(
            "INSERT INTO canca.workspace_grants VALUES ('A','canca_ws_a','workspace:read')")
        with self.role('canca_ws_a'),model.scope(self.conn,'A',self.token,writing=False):
            with self.assertRaises(errors.InsufficientPrivilege):
                with self.conn.transaction():
                    self.conn.execute(
                        "UPDATE canca.workspace_scan_intents SET workspace_id='B' "
                        "WHERE workspace_id='A' AND intent_id=%s",(ident,))
        with self.role('canca_ws_writer'):
            history=self.service.scan_intent_history(self.conn,self.token,ident)
        self.assertEqual([event['decision'] for event in history['decisions']],['approved'])
        self.assertFalse(history['execution_authorized'])

    def test_regranted_reader_cannot_insert_scan_intent(self):
        from psycopg import errors
        ident=self.record()['intent_id']
        self.decide(ident,'approved','approve')
        self.conn.execute(
            "DELETE FROM canca.workspace_grants WHERE workspace_id='A' AND principal_role='canca_ws_a'")
        self.conn.execute(
            "INSERT INTO canca.workspace_grants VALUES ('A','canca_ws_a','workspace:read')")
        with self.role('canca_ws_a'),model.scope(self.conn,'A',self.token,writing=False):
            with self.assertRaises(errors.InsufficientPrivilege):
                with self.conn.transaction():
                    self.conn.execute(
                        "INSERT INTO canca.workspace_scan_intents "
                        "(workspace_id,intent_id) VALUES ('A','reader-forged-intent')")
        with self.role('canca_ws_writer'):
            history=self.service.scan_intent_history(self.conn,self.token,ident)
        self.assertEqual([event['decision'] for event in history['decisions']],['approved'])
        self.assertFalse(history['execution_authorized'])

    def test_regranted_reader_cannot_truncate_scan_intents_without_cascade(self):
        from psycopg import errors
        ident=self.record()['intent_id']
        self.decide(ident,'approved','approve')
        self.conn.execute(
            "DELETE FROM canca.workspace_grants WHERE workspace_id='A' AND principal_role='canca_ws_a'")
        self.conn.execute(
            "INSERT INTO canca.workspace_grants VALUES ('A','canca_ws_a','workspace:read')")
        with self.role('canca_ws_a'),model.scope(self.conn,'A',self.token,writing=False):
            with self.assertRaises(errors.InsufficientPrivilege):
                with self.conn.transaction():
                    self.conn.execute("TRUNCATE TABLE canca.workspace_scan_intents")
        with self.role('canca_ws_writer'):
            history=self.service.scan_intent_history(self.conn,self.token,ident)
        self.assertEqual([event['decision'] for event in history['decisions']],['approved'])
        self.assertFalse(history['execution_authorized'])

    def test_a_reader_regrant_never_exposes_a_history_in_b_context(self):
        ident=self.record()['intent_id']
        self.decide(ident,'approved','approve')
        self.conn.execute(
            "DELETE FROM canca.workspace_grants WHERE workspace_id='A' AND principal_role='canca_ws_a'")
        self.conn.execute(
            "INSERT INTO canca.workspace_grants VALUES ('A','canca_ws_a','workspace:read')")
        with self.role('canca_ws_a'):
            before=self.service.scan_intent_history(self.conn,self.token,ident)
        with self.role('canca_ws_writer'):
            self.c.close(self.conn,'A',self.token.generation)
            b=self.c.open(self.conn,'B',self.c.generation)
        with self.role('canca_ws_a'),self.assertRaises(pg.PersistenceError):
            self.service.scan_intent_history(self.conn,b,ident)
        with self.role('canca_ws_writer'):
            self.c.close(self.conn,'B',b.generation)
            reopened=self.c.open(self.conn,'A',self.c.generation)
        with self.role('canca_ws_a'):
            after=self.service.scan_intent_history(self.conn,reopened,ident)
        self.assertEqual(before['decisions'],after['decisions'])
        self.assertFalse(after['execution_authorized'])

    def test_append_only_and_sql_transition_guard(self):
        from psycopg import errors
        ident=self.record()['intent_id']
        self.conn.execute('GRANT UPDATE,DELETE ON canca.workspace_scan_intents,canca.workspace_scan_decisions TO canca_ws_writer')
        with self.role('canca_ws_writer'),model.scope(self.conn,'A',self.token,writing=True):
            self.assertEqual(self.conn.execute('DELETE FROM canca.workspace_scan_intents RETURNING intent_id').fetchall(),[])
            self.assertEqual(self.conn.execute("UPDATE canca.workspace_scan_intents SET ttl_seconds=300 RETURNING intent_id").fetchall(),[])
        with self.assertRaises(errors.ObjectNotInPrerequisiteState),self.role('canca_ws_writer'),model.scope(self.conn,'A',self.token,writing=True):
            self.conn.execute("INSERT INTO canca.workspace_scan_decisions(workspace_id,intent_id,sequence,request_id,decision,created_revision) VALUES('A',%s,1,'direct','consumed',0)",(ident,))
        with self.assertRaises(errors.InsufficientPrivilege),self.role('canca_ws_writer'),model.scope(self.conn,'A',self.token,writing=True):
            self.conn.execute("INSERT INTO canca.workspace_scan_decisions(workspace_id,intent_id,sequence,request_id,decision,author_role,created_revision) VALUES('A',%s,1,'forged','approved','canca_ws_a',0)",(ident,))

    def test_failure_rolls_back_revision_and_decision(self):
        ident=self.record()['intent_id']
        before=self.conn.execute("SELECT revision FROM canca.workspace_revisions WHERE workspace_id='A'").fetchone()
        from contextlib import contextmanager
        original=model.scope
        @contextmanager
        def interrupted(*args,**kwargs):
            with original(*args,**kwargs) as revision:
                yield revision
                raise RuntimeError('interrupt')
        with self.assertRaisesRegex(RuntimeError,'interrupt'),patch.object(model,'scope',interrupted):
            self.decide(ident,'approved','approve')
        self.assertEqual(self.conn.execute('SELECT count(*) FROM canca.workspace_scan_decisions').fetchone()[0],0)
        self.assertEqual(before,self.conn.execute("SELECT revision FROM canca.workspace_revisions WHERE workspace_id='A'").fetchone())

    def test_concurrent_consumers_commit_once(self):
        import concurrent.futures
        import threading
        ident=self.record()['intent_id'];self.decide(ident,'approved','approve')
        barrier=threading.Barrier(2)
        def consume(request):
            with pg.open_connection() as conn:
                conn.execute('SET ROLE canca_ws_writer')
                barrier.wait(timeout=10)
                try:
                    result=self.service.decide_scan_intent(conn,self.token,'lab','auth_only',self.digest,
                        ident,'consumed',request,ack_authorized_access=True)
                    return result['status']
                except pg.PersistenceError as exc:return str(exc)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            results=list(executor.map(consume,['race-1','race-2']))
        self.assertCountEqual(results,['consumed_recorded_only','intent_transition_denied'])
        self.assertEqual(self.conn.execute("SELECT count(*) FROM canca.workspace_scan_decisions WHERE decision='consumed'").fetchone()[0],1)

    def _race_decisions(self, intent_id, attempts):
        """Simultaneous same-ledger decisions with separate SQL connections."""
        import concurrent.futures
        import threading
        barrier = threading.Barrier(len(attempts))

        def attempt(values):
            decision, request_id = values
            with pg.open_connection() as conn:
                conn.execute('SET ROLE canca_ws_writer')
                barrier.wait(timeout=10)
                try:
                    result = self.service.decide_scan_intent(
                        conn, self.token, 'lab', 'auth_only', self.digest,
                        intent_id, decision, request_id, ack_authorized_access=True)
                    return (result['status'], result['replayed'])
                except pg.PersistenceError as exc:
                    return (str(exc), None)

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(attempts)) as pool:
            return list(pool.map(attempt, attempts))

    def test_concurrent_conflicting_pending_decisions_commit_one(self):
        ident = self.record('pending-race')['intent_id']
        before = self.conn.execute(
            "SELECT revision FROM canca.workspace_revisions WHERE workspace_id='A'").fetchone()[0]
        results = self._race_decisions(
            ident, [('approved', 'race-approve'), ('rejected', 'race-reject')])
        statuses = [status for status, _ in results]
        self.assertEqual(statuses.count('intent_transition_denied'), 1)
        self.assertEqual(len([status for status in statuses
                              if status in ('approved_recorded_only', 'rejected_recorded_only')]), 1)
        events = self.conn.execute(
            "SELECT sequence, decision FROM canca.workspace_scan_decisions "
            "WHERE workspace_id='A' AND intent_id=%s ORDER BY sequence", (ident,)).fetchall()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][0], 1)
        self.assertIn(events[0][1], ('approved', 'rejected'))
        after = self.conn.execute(
            "SELECT revision FROM canca.workspace_revisions WHERE workspace_id='A'").fetchone()[0]
        self.assertEqual(after, before + 1)
        with self.role('canca_ws_a'):
            history = self.service.scan_intent_history(self.conn, self.token, ident)
        self.assertFalse(history['execution_authorized'])

    def test_concurrent_same_request_replays_without_extra_revision(self):
        ident = self.record('same-request-race')['intent_id']
        before = self.conn.execute(
            "SELECT revision FROM canca.workspace_revisions WHERE workspace_id='A'").fetchone()[0]
        results = self._race_decisions(
            ident, [('approved', 'approve-once'), ('approved', 'approve-once')])
        self.assertCountEqual(results, [
            ('approved_recorded_only', False), ('approved_recorded_only', True)])
        rows = self.conn.execute(
            "SELECT decision FROM canca.workspace_scan_decisions "
            "WHERE workspace_id='A' AND intent_id=%s", (ident,)).fetchall()
        self.assertEqual(rows, [('approved',)])
        after = self.conn.execute(
            "SELECT revision FROM canca.workspace_revisions WHERE workspace_id='A'").fetchone()[0]
        self.assertEqual(after, before + 1)

    def test_concurrent_approved_terminal_decisions_commit_one(self):
        ident = self.record('terminal-race')['intent_id']
        self.decide(ident, 'approved', 'terminal-approve')
        results = self._race_decisions(
            ident, [('revoked', 'terminal-revoke'), ('consumed', 'terminal-consume')])
        statuses = [status for status, _ in results]
        self.assertEqual(statuses.count('intent_transition_denied'), 1)
        self.assertEqual(len([status for status in statuses
                              if status in ('revoked_recorded_only', 'consumed_recorded_only')]), 1)
        rows = self.conn.execute(
            "SELECT sequence, decision FROM canca.workspace_scan_decisions "
            "WHERE workspace_id='A' AND intent_id=%s ORDER BY sequence", (ident,)).fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0], (1, 'approved'))
        self.assertEqual(rows[1][0], 2)
        self.assertIn(rows[1][1], ('revoked', 'consumed'))
        with self.role('canca_ws_a'):
            history = self.service.scan_intent_history(self.conn, self.token, ident)
        self.assertFalse(history['execution_authorized'])

