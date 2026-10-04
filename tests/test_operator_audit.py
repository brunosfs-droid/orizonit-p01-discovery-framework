"""Private native JSONL and real HTTP audit without logging submitted secrets."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, nullcontext, redirect_stdout
from copy import deepcopy
import http.client
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import test_operator_auth as fixture
import P01_Operator_Audit as audit
import P01_Operator_API as api
import P01_Operator_Web as web
import operator_web_browser_fixture as browser_fixture

CORE = {'audit_version', 'sequence', 'at_utc', 'listener', 'event'}
START = CORE | {'request_id', 'operation'}
FINISH = START | {'http_status', 'outcome', 'operator_id', 'assessment_id'}
MARKER = 'NEVER-SECRET-REQUEST'


def records(path, *, closed=True):
    raw = path.read_bytes()
    assert raw.endswith(b'\n')
    rows = [json.loads(line) for line in raw.splitlines()]
    lines = raw.splitlines(keepends=True)
    pending = {}
    for index, row in enumerate(rows, 1):
        assert row['audit_version'] == '1' and row['sequence'] == index
        assert len(lines[index-1]) <= 1024
        assert row['listener'] in {'api','web'} and row['at_utc'].endswith('Z')
        if row['event'] == 'request_started':
            assert set(row) == START and row['request_id'] not in pending
            assert row['operation'] in audit.OPERATIONS
            pending[row['request_id']] = row['operation']
        elif row['event'] == 'request_finished':
            assert set(row) == FINISH and pending.pop(row['request_id']) == row['operation']
            assert row['outcome'] in audit.OUTCOMES
        else:
            assert set(row) == CORE and row['event'] in {'listener_started','listener_stopped'}
    assert rows[0]['event'] == 'listener_started'
    if closed:
        assert rows[-1]['event'] == 'listener_stopped' and not pending
    for value in (fixture.PASSWORD, fixture.RECORD['salt'], fixture.RECORD['hash'], MARKER):
        assert value.encode() not in raw
    return rows


class PrivateAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve(); self.path = self.root/'audit.jsonl'

    def make(self, **kwargs):
        sink = audit.FileAudit(self.path, 'api', **kwargs)
        def cleanup():
            try: sink.close()
            except audit.AuditError: pass
        self.addCleanup(cleanup)
        return sink

    def test_regular_private_exclusive_native_file_and_schema(self):
        sink = self.make()
        request = sink.begin('login')
        sink.finish(request,http_status=201,outcome='response_written',operator_id='OP-01')
        sink.close(); rows=records(self.path)
        self.assertEqual(len(rows),4); self.assertEqual(len(request),32)
        self.assertEqual(self.path.stat().st_nlink,1)
        if os.name=='posix': self.assertEqual(stat.S_IMODE(self.path.stat().st_mode),0o600)

    def test_existing_file_directory_and_hardlink_are_never_reused(self):
        self.path.write_bytes(b'PRIVATE-EXISTING')
        for path in (self.path,self.root):
            with self.assertRaisesRegex(audit.AuditError,'^operator_audit_unavailable$'):
                audit.FileAudit(path,'api')
        alias=self.root/'hardlink'; os.link(self.path,alias)
        with self.assertRaises(audit.AuditError): audit.FileAudit(alias,'api')
        self.assertEqual(self.path.read_bytes(),b'PRIVATE-EXISTING')

    def test_bounds_and_invalid_listener_do_not_create_any_file(self):
        for kwargs in [dict(listener='PRIVATE'),dict(listener='api',max_bytes=True),
                       dict(listener='api',max_bytes=4095),dict(listener='api',max_bytes=audit.MAX_BYTES+1)]:
            with self.assertRaisesRegex(audit.AuditError,'^operator_audit_unavailable$'):
                audit.FileAudit(self.path,**kwargs)
            self.assertFalse(self.path.exists())

    @unittest.skipUnless(os.name=='posix','POSIX private modes and FIFO')
    def test_posix_public_parent_alias_and_fifo_rejected(self):
        self.root.chmod(0o755)
        with self.assertRaises(audit.AuditError): audit.FileAudit(self.path,'api')
        self.root.chmod(0o700)
        alias=self.root/'alias'; alias.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(audit.AuditError): audit.FileAudit(alias/'new.jsonl','api')
        alias.unlink(); fifo=self.root/'fifo'; os.mkfifo(fifo)
        with self.assertRaises(audit.AuditError): audit.FileAudit(fifo,'api')
        self.assertFalse(self.path.exists())

    @unittest.skipUnless(os.name=='nt','native Windows reparse/UNC')
    def test_windows_file_directory_symlinks_and_unc_rejected(self):
        source=self.root/'source'; source.write_bytes(b'PRIVATE-SOURCE')
        alias=self.root/'alias'; alias.symlink_to(source)
        with self.assertRaises(audit.AuditError): audit.FileAudit(alias,'api')
        parent=self.root/'parent'; parent.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(audit.AuditError): audit.FileAudit(parent/'new.jsonl','api')
        with self.assertRaises(audit.AuditError): audit.FileAudit('\\\\invalid-host\\share\\audit.jsonl','api')
        self.assertEqual(source.read_bytes(),b'PRIVATE-SOURCE')

    def test_capacity_reserves_completions_and_stop_without_overflow(self):
        sink=self.make(max_bytes=4096); pending=[]
        while True:
            try: pending.append(sink.begin('report_page'))
            except audit.AuditError: break
        self.assertGreater(len(pending),0)
        for request in pending:
            sink.finish(request,http_status=200,outcome='response_written',operator_id='O'*128,assessment_id='A'*128)
        with self.assertRaises(audit.AuditError): sink.begin('health')
        sink.close(); records(self.path)
        self.assertLessEqual(self.path.stat().st_size,4096)

    def test_active_request_capacity_keeps_already_admitted_requests(self):
        sink=self.make(); pending=[sink.begin('health') for _ in range(audit.MAX_ACTIVE)]
        with self.assertRaises(audit.AuditError): sink.begin('health')
        for request in pending: sink.finish(request,http_status=200,outcome='response_written')
        request=sink.begin('logout'); sink.finish(request,http_status=401,outcome='response_written')
        sink.close(); self.assertEqual(len(records(self.path)),20)

    def test_threads_serialize_sequences_and_pair_independent_request_ids(self):
        sink=self.make(); barrier=threading.Barrier(8)
        def use(_):
            for _ in range(4):
                barrier.wait(timeout=5)
                request=sink.begin('report_page')
                barrier.wait(timeout=5)
                sink.finish(request,http_status=200,outcome='response_written',operator_id='OP-01',assessment_id='LAB-001')
        with ThreadPoolExecutor(max_workers=8) as pool: list(pool.map(use,range(8)))
        sink.close(); rows=records(self.path)
        self.assertEqual(len(rows),66)
        self.assertEqual(len({r['request_id'] for r in rows if r['event']=='request_started'}),32)

    def test_short_native_writes_are_completed_and_zero_write_fails_closed(self):
        sink=self.make(); original=audit.os.write
        with patch.object(audit.os,'write',side_effect=lambda fd,raw:original(fd,raw[:7])):
            request=sink.begin('health'); sink.finish(request,http_status=200,outcome='response_written')
        sink.close(); records(self.path)
        other=audit.FileAudit(self.root/'zero.jsonl','web')
        with patch.object(audit.os,'write',return_value=0):
            with self.assertRaisesRegex(audit.AuditError,'^operator_audit_unavailable$'): other.begin('login')
        with self.assertRaises(audit.AuditError): other.begin('health')
        with self.assertRaises(audit.AuditError): other.close()

    def test_append_truncate_and_hardlink_drift_latch_failure(self):
        for change in ('append','truncate','hardlink'):
            path=self.root/(change+'.jsonl'); sink=audit.FileAudit(path,'api')
            if change=='append':
                with path.open('ab') as stream: stream.write(b'PRIVATE-APPEND')
            elif change=='truncate': path.write_bytes(b'')
            else: os.link(path,self.root/'hardlink-live')
            before=path.read_bytes()
            with self.assertRaises(audit.AuditError): sink.begin('health')
            self.assertEqual(path.read_bytes(),before)
            with self.assertRaises(audit.AuditError): sink.close()

    @unittest.skipUnless(os.name=='posix','POSIX replacement of an open regular file')
    def test_posix_replacement_never_writes_into_unrelated_destination(self):
        sink=self.make(); self.path.unlink(); self.path.write_bytes(b'PRIVATE-REPLACEMENT'); self.path.chmod(0o600)
        with self.assertRaises(audit.AuditError): sink.begin('login')
        self.assertEqual(self.path.read_bytes(),b'PRIVATE-REPLACEMENT')
        with self.assertRaises(audit.AuditError): sink.close()

    @unittest.skipUnless(os.name=='posix','POSIX private metadata drift')
    def test_posix_file_and_parent_privacy_drift_block_new_records(self):
        for target in ('file','parent'):
            path=self.root/(target+'.jsonl'); sink=audit.FileAudit(path,'api'); before=path.read_bytes()
            changed=path if target=='file' else self.root; old=stat.S_IMODE(changed.stat().st_mode)
            changed.chmod(0o644 if target=='file' else 0o755)
            with self.assertRaises(audit.AuditError): sink.begin('login')
            changed.chmod(old); self.assertEqual(path.read_bytes(),before)
            with self.assertRaises(audit.AuditError): sink.close()

    def test_fsync_failure_preserves_bytes_and_never_resumes_on_same_sink(self):
        sink=self.make()
        with patch.object(audit.os,'fsync',side_effect=OSError(MARKER)):
            with self.assertRaisesRegex(audit.AuditError,'^operator_audit_unavailable$'): sink.begin('login')
        before=self.path.read_bytes()
        with self.assertRaises(audit.AuditError): sink.begin('health')
        self.assertEqual(self.path.read_bytes(),before)
        with self.assertRaises(audit.AuditError): sink.close()
        self.assertNotIn(MARKER.encode(),before)

    def test_startup_fsync_failure_preserves_new_private_run_without_reuse(self):
        with patch.object(audit.os,'fsync',side_effect=OSError(MARKER)):
            with self.assertRaisesRegex(audit.AuditError,'^operator_audit_unavailable$'):
                audit.FileAudit(self.path,'api')
        rows=records(self.path,closed=False); self.assertEqual(len(rows),1)
        before=self.path.read_bytes()
        with self.assertRaises(audit.AuditError): audit.FileAudit(self.path,'api')
        self.assertEqual(self.path.read_bytes(),before)

    def test_invalid_finish_fields_never_echo_or_append_and_halt_sink(self):
        for fields in [dict(operator_id='../'+MARKER),dict(assessment_id='LAB-001'),
                       dict(http_status=True),dict(outcome=MARKER),dict(operator_id=['PRIVATE'])]:
            path=self.root/('invalid-'+str(len(list(self.root.iterdir())))+'.jsonl'); sink=audit.FileAudit(path,'api')
            request=sink.begin('login'); before=path.read_bytes()
            values=dict(http_status=401,outcome='response_written'); values.update(fields)
            with self.assertRaisesRegex(audit.AuditError,'^operator_audit_unavailable$'): sink.finish(request,**values)
            self.assertEqual(path.read_bytes(),before)
            with self.assertRaises(audit.AuditError): sink.close()

    def test_route_classifier_never_returns_untrusted_paths_or_queries(self):
        cases=[('POST','/api/v1/operator/session?password='+MARKER,'login'),
               ('GET','/api/v1/assessments/'+MARKER+'/report?token='+MARKER,'report_page'),
               ('GET','http://[invalid','other'),('GET','/'+MARKER*300,'other'),
               ('PATCH','/api/v1/operator/session','other'),('GET','/../'+MARKER,'other')]
        for method,target,expected in cases: self.assertEqual(audit.operation(method,target),expected)

    def test_abrupt_process_exit_keeps_unfinished_private_prefix_and_no_reuse(self):
        code="""import os,sys
sys.path.insert(0,sys.argv[1])
import P01_Operator_Audit as audit
sink=audit.FileAudit(sys.argv[2],'api'); sink.begin('login'); os._exit(23)
"""
        run=subprocess.run([sys.executable,'-c',code,str(Path(audit.__file__).parent),str(self.path)],
                           capture_output=True,timeout=10)
        self.assertEqual(run.returncode,23); self.assertFalse(run.stdout+run.stderr)
        rows=records(self.path,closed=False)
        self.assertEqual([r['event'] for r in rows],['listener_started','request_started'])
        before=self.path.read_bytes()
        with self.assertRaises(audit.AuditError): audit.FileAudit(self.path,'api')
        self.assertEqual(self.path.read_bytes(),before)
        next_path=self.root/'next.jsonl'; next_sink=audit.FileAudit(next_path,'api'); next_sink.close()
        records(next_path); self.assertEqual(self.path.read_bytes(),before)


class OperatorAuditHTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve(); self.policy=self.root/'accounts.json'
        self.policy.write_text(json.dumps(fixture.document())); self.policy.chmod(0o600)
        self.path=self.root/'audit.jsonl'; self.server=None; self.worker=None
        self.addCleanup(self.cleanup_server)

    def start(self, module=api, *, enabled=True):
        self.server=module.create_server(self.policy,port=0,audit_path=self.path if enabled else None)
        self.worker=threading.Thread(target=self.server.serve_forever,daemon=True); self.worker.start()

    def stop(self):
        server=self.server
        if server is None: return
        self.server=None; server.shutdown()
        try: server.server_close()
        finally: self.worker.join(timeout=5)

    def cleanup_server(self):
        try: self.stop()
        except audit.AuditError: pass

    def request(self, method, path, payload=None, headers=None):
        with closing(http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=10)) as conn:
            conn.request(method,path,json.dumps(payload) if payload is not None else None,headers or {})
            response=conn.getresponse(); raw=response.read()
            self.assertEqual(response.getheader('Cache-Control'),'no-store')
            return response.status,dict(response.getheaders()),raw

    def login(self):
        status,_,raw=self.request('POST','/api/v1/operator/session',dict(username='reader',password=fixture.PASSWORD),
                                {'Content-Type':'application/json'})
        self.assertEqual(status,201); token=json.loads(raw)['access_token']
        return token,{'Authorization':'Bearer '+token}

    def finished(self):
        self.stop(); return [row for row in records(self.path) if row['event']=='request_finished']

    def drain_audit(self):
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            with self.server.audit._lock: pending=bool(self.server.audit._pending)
            if not pending: return
            time.sleep(0.01)
        self.fail('HTTP worker did not finish its audit record')

    def test_default_off_has_no_file_and_preserves_api_and_web_contracts(self):
        for module in (api,web):
            self.start(module,enabled=False)
            self.assertIsNone(self.server.audit); token,headers=self.login()
            self.assertEqual(self.request('GET','/healthz')[0],200)
            self.assertEqual(self.request('DELETE','/api/v1/operator/session',headers=headers)[0],200)
            self.stop(); self.assertFalse(self.path.exists())

    def test_login_report_denial_logout_audit_uses_only_trusted_ids(self):
        self.start(); token,headers=self.login()
        with patch.object(api.report.pg,'open_connection',return_value=nullcontext(object())),\
             patch.object(api.report,'show_assessment',return_value=dict(status='found',assessment_id='LAB-001',
                                                                      private_backend_value=MARKER)):
            self.assertEqual(self.request('GET','/api/v1/assessments/LAB-001/report',headers=headers)[0],200)
        with patch.object(api.report.pg,'open_connection') as connect:
            self.assertEqual(self.request('GET','/api/v1/assessments/'+MARKER+'/report',headers=headers)[0],403)
        connect.assert_not_called()
        self.assertEqual(self.request('DELETE','/api/v1/operator/session',headers=headers)[0],200)
        rows=self.finished()
        self.assertEqual([r['operation'] for r in rows],['login','report_page','report_page','logout'])
        self.assertEqual([r['http_status'] for r in rows],[201,200,403,200])
        self.assertTrue(all(r['operator_id']=='OP-01' for r in rows))
        self.assertEqual([r['assessment_id'] for r in rows],[None,'LAB-001',None,None])
        self.assertNotIn(token.encode(),self.path.read_bytes())
        import hashlib
        self.assertNotIn(hashlib.sha256(token.encode()).hexdigest().encode(),self.path.read_bytes())

    def test_failed_unknown_disabled_and_malformed_login_never_log_submitted_username(self):
        doc=fixture.document(); disabled=deepcopy(doc['accounts'][0]); disabled.update(operator_id='OP-02',username='disabled',enabled=False)
        doc['accounts'].append(disabled); self.policy.write_text(json.dumps(doc)); self.start()
        for username,password in [('reader',MARKER),('unknown-'+MARKER,fixture.PASSWORD),('disabled',fixture.PASSWORD)]:
            self.assertEqual(self.request('POST','/api/v1/operator/session',dict(username=username,password=password),
                                        {'Content-Type':'application/json'})[0],401)
        self.assertEqual(self.request('POST','/api/v1/operator/session?password='+MARKER,{},
                                     {'Content-Type':'application/json'})[0],400)
        rows=self.finished(); self.assertTrue(all(r['operator_id'] is None for r in rows))
        self.assertNotIn(b'disabled',self.path.read_bytes()); self.assertNotIn(b'reader',self.path.read_bytes())

    def test_expiry_forgery_query_and_backend_errors_are_sanitized(self):
        self.start(); token,headers=self.login()
        with patch.object(api.report.pg,'open_connection',side_effect=RuntimeError(MARKER)):
            self.assertEqual(self.request('GET','/api/v1/assessments/LAB-001/report',headers=headers)[0],503)
        with patch.object(api.report.pg,'open_connection') as connect:
            for suffix in ('password='+MARKER,'limit=1&limit=2','limit=1&','&'):
                self.assertEqual(self.request('GET','/api/v1/assessments/LAB-001/report?'+suffix,headers=headers)[0],400)
            connect.assert_not_called()
        self.assertEqual(self.request('GET','/api/v1/assessments/LAB-001/report',headers={'Authorization':'Bearer '+'x'*43})[0],401)
        self.server.service.auth.clock=lambda:time.monotonic()+1000
        self.assertEqual(self.request('GET','/api/v1/assessments/LAB-001/report',headers=headers)[0],401)
        rows=self.finished(); self.assertEqual([r['http_status'] for r in rows],[201,503,400,400,400,400,401,401])
        self.assertIsNone(rows[-1]['operator_id']); self.assertIsNone(rows[-2]['operator_id'])

    def test_web_origin_denial_directory_preview_and_both_downloads(self):
        self.start(web)
        self.assertEqual(self.request('POST','/api/v1/operator/session',dict(username=MARKER,password=fixture.PASSWORD),
            {'Content-Type':'application/json','Origin':'http://'+MARKER+'.invalid'})[0],403)
        token,headers=self.login()
        with patch.object(web.exports.export.pg,'open_connection',return_value=nullcontext(object())),\
             patch.object(web.exports.export.report,'show_assessment',side_effect=browser_fixture.canonical_page):
            self.assertEqual(self.request('GET','/api/v1/operator/assessments',headers=headers)[0],200)
            for suffix in ('/executive','/export','/executive/export'):
                status,_,raw=self.request('GET','/api/v1/assessments/LAB-001/report'+suffix+
                                         '?expected_scope_sha256='+browser_fixture.SCOPE,headers=headers)
                self.assertEqual(status,200); self.assertTrue(raw)
        rows=self.finished(); self.assertEqual([r['operation'] for r in rows],
            ['login','login','assessment_directory','executive_preview','technical_export','executive_export'])
        self.assertIsNone(rows[0]['operator_id']); self.assertIsNone(rows[2]['assessment_id'])
        self.assertTrue(all(r['assessment_id']=='LAB-001' for r in rows[-3:]))
        self.assertTrue(all(r['listener']=='web' for r in rows))
        self.assertNotIn(token.encode(),self.path.read_bytes()); self.assertNotIn(browser_fixture.ATTACK.encode(),self.path.read_bytes())
        self.assertNotIn(browser_fixture.SCOPE.encode(),self.path.read_bytes())

    def test_audit_drift_blocks_login_logout_and_read_before_backend_work(self):
        self.start(); token,headers=self.login()
        # Drain the completed login before introducing an external append.
        self.drain_audit()
        with self.path.open('ab') as stream: stream.write(b'EXTERNAL\n')
        with patch.object(self.server.service.auth,'login') as login,\
             patch.object(self.server.service.auth,'logout') as logout,\
             patch.object(api.report.pg,'open_connection') as connect:
            for method,path,payload in [('POST','/api/v1/operator/session',dict(username='reader',password=fixture.PASSWORD)),
                    ('DELETE','/api/v1/operator/session',None),('GET','/api/v1/assessments/LAB-001/report',None)]:
                status,_,raw=self.request(method,path,payload,{'Content-Type':'application/json',**headers})
                self.assertEqual(status,503); self.assertEqual(json.loads(raw)['error_code'],'operator_audit_unavailable')
            login.assert_not_called(); logout.assert_not_called(); connect.assert_not_called()
        self.assertEqual(self.server.service.auth.require(token,'LAB-001'),'OP-01')
        with self.assertRaises(audit.AuditError): self.stop()

    def test_audit_full_blocks_new_work_but_has_reserved_clean_shutdown(self):
        original=audit.FileAudit
        with patch.object(api.audit,'FileAudit',side_effect=lambda path,listener:original(path,listener,max_bytes=4096)):
            self.start()
        status=200
        for _ in range(30):
            status,_,raw=self.request('GET','/healthz')
            if status==503: break
        self.assertEqual(status,503)
        with patch.object(self.server.service.auth,'login') as login:
            self.assertEqual(self.request('POST','/api/v1/operator/session',dict(username='reader',password=fixture.PASSWORD),
                                         {'Content-Type':'application/json'})[0],503)
            login.assert_not_called()
        self.stop(); records(self.path); self.assertLessEqual(self.path.stat().st_size,4096)

    def test_failure_in_finish_can_follow_response_and_latches_future_admission(self):
        self.start(); sink=self.server.audit; original=sink.finish; done=threading.Event()
        def fail(request,**fields):
            try:
                with patch.object(audit.os,'fsync',side_effect=OSError(MARKER)):
                    return original(request,**fields)
            finally: done.set()
        with patch.object(sink,'finish',side_effect=fail):
            self.assertEqual(self.request('GET','/healthz')[0],200)
            self.assertTrue(done.wait(3))
        with patch.object(self.server.service.auth,'login') as login:
            self.assertEqual(self.request('POST','/api/v1/operator/session',dict(username='reader',password=fixture.PASSWORD),
                                         {'Content-Type':'application/json'})[0],503)
            login.assert_not_called()
        with self.assertRaises(audit.AuditError): self.stop()
        self.assertNotIn(MARKER.encode(),self.path.read_bytes())

    def test_delivery_failure_is_fixed_metadata_without_exception_content(self):
        self.start()
        with patch.object(api.OperatorHandler,'_dispatch',side_effect=BrokenPipeError(MARKER)):
            with self.assertRaises(http.client.RemoteDisconnected): self.request('GET','/healthz')
        rows=self.finished(); self.assertEqual(rows[0]['outcome'],'delivery_failed')
        self.assertIsNone(rows[0]['http_status']); self.assertIsNone(rows[0]['operator_id'])

    def test_web_download_disconnect_is_not_misreported_as_written(self):
        self.start(web); token,headers=self.login()
        with patch.object(web.exports.export.pg,'open_connection',return_value=nullcontext(object())),\
             patch.object(web.exports.export.report,'show_assessment',side_effect=browser_fixture.canonical_page),\
             patch.object(web.WebHandler,'_asset_headers',side_effect=BrokenPipeError(MARKER)):
            with self.assertRaises(http.client.RemoteDisconnected):
                self.request('GET','/api/v1/assessments/LAB-001/report/export?expected_scope_sha256='+
                             browser_fixture.SCOPE,headers=headers)
        row=self.finished()[-1]
        self.assertEqual(row['outcome'],'delivery_failed'); self.assertEqual(row['http_status'],200)
        self.assertEqual(row['operator_id'],'OP-01'); self.assertEqual(row['assessment_id'],'LAB-001')

    def test_startup_collision_and_cli_failures_never_echo_paths(self):
        self.path.write_bytes(b'PRIVATE-PREVIOUS'); before=self.path.read_bytes()
        for module in (api,web):
            stdout=io.StringIO()
            with redirect_stdout(stdout):
                code=module.cli(['--accounts',str(self.policy),'--port','0','--audit-file',str(self.path)])
            self.assertEqual(code,2); self.assertEqual(json.loads(stdout.getvalue())['error_code'],'operator_audit_unavailable')
            self.assertNotIn(str(self.path),stdout.getvalue())
            self.assertEqual(self.path.read_bytes(),before)


if __name__=='__main__': unittest.main()
