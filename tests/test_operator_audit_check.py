"""Independent malformed-record cases plus real private files, HTTP and interruption."""
from contextlib import closing, redirect_stdout
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server'))
import P01_Operator_Audit as producer
import P01_Operator_Audit_Check as check
import P01_Operator_API as api
import P01_Operator_Auth as auth

MARKER = 'NEVER-SECRET-AUDIT-REVIEW'
REQUEST = '1' * 32
CORE = dict(audit_version='1', sequence=1, at_utc='2026-10-04T10:00:00.000001Z', listener='api')


def line(event, **fields):
    return dict(CORE, event=event, **fields)


def serialize(rows):
    return b''.join((json.dumps(row, separators=(',', ':')) + '\n').encode('ascii') for row in rows)


def complete():
    return [line('listener_started'),
        line('request_started', sequence=2, request_id=REQUEST, operation='report_page'),
        line('request_finished', sequence=3, request_id=REQUEST, operation='report_page',
             outcome='response_written', http_status=200, operator_id=MARKER, assessment_id=MARKER),
        line('listener_stopped', sequence=4)]


class AuditStructureTests(unittest.TestCase):
    def invalid(self, raw):
        with self.assertRaisesRegex(check.CheckError, '^operator_audit_structure_invalid$'):
            check.review_bytes(raw)

    def test_closed_structure_has_bounded_aggregates_without_private_fields(self):
        raw = serialize(complete()); result = check.review_bytes(raw)
        self.assertEqual(result['state'], 'closed')
        self.assertEqual(result['status'], 'closed_structure')
        self.assertEqual(result['valid_records'], 4)
        self.assertEqual(result['unfinished_requests'], 0)
        self.assertEqual(result['audit_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result['operations']['report_page'], dict(started=1, finished=1))
        self.assertEqual(result['http_classes']['2xx'], 1)
        output = json.dumps(result)
        self.assertNotIn(MARKER, output); self.assertNotIn(REQUEST, output)
        self.assertNotIn(CORE['at_utc'], output)
        self.assertLess(len(output), 4096)
        self.assertEqual(set(result), {'status','version','audit_version','audit_sha256','size_bytes',
            'state','listener','valid_records','partial_tail_bytes','unfinished_requests',
            'events','operations','outcomes','http_classes'})

    def test_open_prefix_distinguishes_pending_and_finished_without_fabricating_stop(self):
        for count, unfinished in [(1, 0), (2, 1), (3, 0)]:
            result = check.review_bytes(serialize(complete()[:count]))
            self.assertEqual(result['state'], 'open_prefix')
            self.assertEqual(result['status'], 'valid_prefix')
            self.assertEqual(result['unfinished_requests'], unfinished)
            self.assertEqual(result['events']['listener_stopped'], 0)

    def test_unterminated_tail_including_complete_json_is_uninterpreted_and_hashed(self):
        prefix = serialize(complete()[:2])
        for tail in [b'{"password":"' + MARKER.encode(), b'x' * 1023,
                     serialize(complete()[2:3]).rstrip(b'\n'), b'\xff\x00PRIVATE']:
            raw = prefix + tail; result = check.review_bytes(raw)
            self.assertEqual(result['state'], 'partial_prefix')
            self.assertEqual(result['valid_records'], 2)
            self.assertEqual(result['unfinished_requests'], 1)
            self.assertEqual(result['partial_tail_bytes'], len(tail))
            self.assertEqual(result['audit_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertNotIn(MARKER, json.dumps(result))

    def test_empty_startless_tail_and_oversize_records_or_file_are_invalid(self):
        for raw in [b'', b'{"event":"listener_started"}', b'\n',
                    serialize(complete()[:1]) + b'x' * 1024,
                    b' ' * 1024 + b'\n', b'x' * (check.MAX_BYTES + 1), bytearray(b'PRIVATE')]:
            self.invalid(raw)

    def test_complete_malformed_middle_or_last_line_is_never_treated_as_partial(self):
        prefix = serialize(complete()[:1])
        for tail in [b'\n', b'PRIVATE\n', b'{"password":"' + MARKER.encode() + b'"}\n',
                     b'\xff\n', b'{}\r\n', b'[]\n', b'null\n', b'{"x":NaN}\n']:
            self.invalid(prefix + tail)

    def test_duplicate_json_keys_are_rejected_at_every_object_level(self):
        raw = serialize(complete())
        self.invalid(raw.replace(b'"sequence":1', b'"sequence":1,"sequence":1', 1))
        self.invalid(raw.replace(b'"operator_id":"' + MARKER.encode() + b'"',
                    b'"operator_id":{"x":1,"x":2}', 1))

    def test_fixed_schema_rejects_extra_missing_and_untrusted_values(self):
        mutations = [('token', MARKER), ('event', MARKER), ('audit_version', 1),
                     ('listener', MARKER), ('sequence', True), ('sequence', 1.0),
                     ('at_utc', MARKER), ('at_utc', '2026-02-30T10:00:00.000001Z'),
                     ('at_utc', '2026-10-04T10:00:00.1Z'), ('at_utc', 12)]
        for key, value in mutations:
            rows = complete(); rows[0][key] = value
            with self.subTest(key=key, value=value): self.invalid(serialize(rows))
        for index, key in [(0,'listener'), (1,'operation'), (2,'assessment_id')]:
            rows = complete(); del rows[index][key]; self.invalid(serialize(rows))

    def test_finish_fields_enforce_nullability_identity_bounds_and_http_types(self):
        for key, value in [('http_status', True), ('http_status', 200.0), ('http_status', 99),
                           ('http_status', 600), ('outcome', MARKER), ('operator_id', ''),
                           ('operator_id', 'a' * 129), ('operator_id', '../' + MARKER),
                           ('operator_id', None), ('assessment_id', ['PRIVATE'])]:
            rows = complete(); rows[2][key] = value
            with self.subTest(key=key, value=value): self.invalid(serialize(rows))
        rows = complete(); rows[2].update(operator_id=None, assessment_id=None, http_status=None, outcome='handler_failed')
        result = check.review_bytes(serialize(rows))
        self.assertEqual(result['http_classes']['none'], 1)
        self.assertEqual(result['outcomes']['handler_failed'], 1)

    def test_sequences_listener_and_pair_operations_cannot_change(self):
        for index, key, value in [(1,'sequence',3), (2,'sequence',2), (2,'listener','web'),
                                  (1,'request_id','A'*32), (2,'request_id','2'*32),
                                  (2,'operation','login'), (1,'operation',MARKER)]:
            rows = complete(); rows[index][key] = value; self.invalid(serialize(rows))

    def test_lifecycle_rejects_duplicate_start_stop_open_requests_and_trailing_data(self):
        rows = complete()
        for modified in [rows[1:], [rows[0], dict(rows[0], sequence=2)],
                         [rows[0], rows[1], dict(rows[3], sequence=3)],
                         [rows[0], dict(rows[2], sequence=2)],
                         rows + [dict(rows[3], sequence=5)],
                         rows + [dict(rows[1], sequence=5)]]:
            self.invalid(serialize(modified))
        self.invalid(serialize(rows) + b'PRIVATE-PARTIAL')

    def test_reused_request_id_is_rejected_after_completion_and_while_pending(self):
        rows = complete()
        self.invalid(serialize(rows[:2] + [dict(rows[1], sequence=3)]))
        self.invalid(serialize(rows[:3] + [dict(rows[1], sequence=4)]))
        self.invalid(serialize(rows[:3] + [dict(rows[2], sequence=4)]))

    def test_eight_overlapping_pairs_close_but_ninth_start_is_invalid(self):
        rows = [line('listener_started')]
        for index in range(8): rows.append(line('request_started', sequence=len(rows)+1,
                request_id=f'{index:032x}', operation='health'))
        valid_prefix = serialize(rows)
        self.assertEqual(check.review_bytes(valid_prefix)['unfinished_requests'], 8)
        ninth = line('request_started', sequence=10, request_id='f'*32, operation='health')
        self.invalid(valid_prefix + serialize([ninth]))
        for index in reversed(range(8)): rows.append(line('request_finished', sequence=len(rows)+1,
                request_id=f'{index:032x}', operation='health', outcome='response_written',
                http_status=200, operator_id=None, assessment_id=None))
        rows.append(line('listener_stopped', sequence=len(rows)+1))
        self.assertEqual(check.review_bytes(serialize(rows))['state'], 'closed')

    def test_host_clock_regression_does_not_invalidate_ordered_sequence(self):
        rows = complete(); rows[2]['at_utc'] = '2025-01-01T00:00:00.000000Z'
        self.assertEqual(check.review_bytes(serialize(rows))['state'], 'closed')

    def test_http_classes_all_outcomes_and_operations_use_fixed_count_keys(self):
        rows = [line('listener_started')]
        for index, operation in enumerate(sorted(check.OPERATIONS)):
            request_id = f'{index:032x}'
            rows.append(line('request_started', sequence=len(rows)+1, request_id=request_id, operation=operation))
            rows.append(line('request_finished', sequence=len(rows)+1, request_id=request_id, operation=operation,
                http_status=[101,201,302,403,503,None][index%6], outcome=sorted(check.OUTCOMES)[index%3],
                operator_id=None, assessment_id=None))
        rows.append(line('listener_stopped', sequence=len(rows)+1))
        result = check.review_bytes(serialize(rows))
        self.assertTrue(all(count == dict(started=1,finished=1) for count in result['operations'].values()))
        self.assertTrue(all(result['http_classes'].values()))
        self.assertTrue(all(result['outcomes'].values()))


class PrivateAuditReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve(); self.path = self.root/'private-audit.jsonl'
        self.write(serialize(complete()))

    def write(self, raw):
        self.path.write_bytes(raw); self.path.chmod(0o600)

    def cli(self, arguments):
        out = io.StringIO()
        with redirect_stdout(out): code = check.cli(arguments)
        self.assertEqual(len(out.getvalue().splitlines()), 1)
        return code, json.loads(out.getvalue())

    def test_native_private_snapshot_and_optional_digest_preserve_input(self):
        raw = self.path.read_bytes(); before = check._stamp(self.path.stat())
        sha = hashlib.sha256(raw).hexdigest()
        result = check.inspect_log(self.path, sha)
        self.assertEqual(result['state'],'closed')
        self.assertEqual(self.path.read_bytes(),raw)
        self.assertEqual(check._stamp(self.path.stat()),before)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()),['private-audit.jsonl'])
        with self.assertRaisesRegex(check.CheckError,'^operator_audit_digest_conflict$'):
            check.inspect_log(self.path,'f'*64)

    def test_input_digest_invalid_is_rejected_before_any_file_read(self):
        for sha in ['',MARKER,'A'*64,1,True,['f'*64]]:
            with patch.object(check,'read_snapshot') as read:
                with self.assertRaisesRegex(check.CheckError,'^operator_audit_input_invalid$'):
                    check.inspect_log(self.path,sha)
                read.assert_not_called()

    def test_missing_directory_empty_large_hardlink_and_unc_are_fixed_errors(self):
        alias = self.root/'linked'; os.link(self.path,alias)
        for path in [self.path,alias,self.root,self.root/'missing','\\\\invalid-host\\share\\PRIVATE']:
            with self.assertRaisesRegex(check.CheckError,'^operator_audit_read_failed$'): check.inspect_log(path)
        alias.unlink()
        for raw in [b'',b'x'*(check.MAX_BYTES+1)]:
            self.write(raw)
            with self.assertRaisesRegex(check.CheckError,'^operator_audit_read_failed$'): check.inspect_log(self.path)

    @unittest.skipUnless(os.name=='posix','POSIX modes and nonblocking FIFO')
    def test_posix_private_file_directory_alias_and_fifo(self):
        self.path.chmod(0o644)
        with self.assertRaises(check.CheckError): check.inspect_log(self.path)
        self.path.chmod(0o600); self.root.chmod(0o755)
        with self.assertRaises(check.CheckError): check.inspect_log(self.path)
        self.root.chmod(0o700)
        alias = self.root/'alias'; alias.symlink_to(self.path)
        parent = self.root/'parent'; parent.symlink_to(self.root,target_is_directory=True)
        fifo = self.root/'fifo'; os.mkfifo(fifo)
        for path in [alias,parent/self.path.name,fifo]:
            with self.assertRaisesRegex(check.CheckError,'^operator_audit_read_failed$'): check.inspect_log(path)

    @unittest.skipUnless(os.name=='nt','native Windows symlink and reparse checks')
    def test_windows_private_snapshot_symlinks_and_unc(self):
        file_alias = self.root/'alias'; file_alias.symlink_to(self.path)
        directory_alias = self.root/'parent'; directory_alias.symlink_to(self.root,target_is_directory=True)
        for path in [file_alias,directory_alias/self.path.name,'\\\\invalid-host\\share\\PRIVATE']:
            with self.assertRaisesRegex(check.CheckError,'^operator_audit_read_failed$'): check.inspect_log(path)
        self.assertEqual(check.inspect_log(self.path)['state'],'closed')

    def test_append_during_read_is_rejected_without_changing_or_echoing_bytes(self):
        original = check.os.fstat; count = 0
        def changed(fd):
            nonlocal count
            count += 1
            if count == 2:
                with self.path.open('ab') as stream: stream.write(MARKER.encode())
            return original(fd)
        with patch.object(check.os,'fstat',side_effect=changed):
            with self.assertRaisesRegex(check.CheckError,'^operator_audit_read_failed$'): check.inspect_log(self.path)
        self.assertTrue(self.path.read_bytes().endswith(MARKER.encode()))

    def test_path_and_descriptor_ctime_semantics_can_differ_for_stable_same_file(self):
        original = check.os.fstat
        def by_descriptor(fd):
            info = original(fd)
            values = {name:getattr(info,name) for name in
                      ('st_dev','st_ino','st_mode','st_uid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
            values['st_ctime_ns'] += 1000000
            return SimpleNamespace(**values)
        raw = self.path.read_bytes()
        with patch.object(check.os,'fstat',side_effect=by_descriptor):
            self.assertEqual(check.inspect_log(self.path)['state'],'closed')
        self.assertEqual(self.path.read_bytes(),raw)

    def test_descriptor_ctime_drift_is_rejected_even_when_path_and_bytes_are_unchanged(self):
        original = check.os.fstat; count = 0
        def by_descriptor(fd):
            nonlocal count
            count += 1
            info = original(fd)
            values = {name:getattr(info,name) for name in
                      ('st_dev','st_ino','st_mode','st_uid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
            values['st_ctime_ns'] += count * 1000000
            return SimpleNamespace(**values)
        raw = self.path.read_bytes()
        with patch.object(check.os,'fstat',side_effect=by_descriptor):
            with self.assertRaisesRegex(check.CheckError,'^operator_audit_read_failed$'): check.inspect_log(self.path)
        self.assertEqual(self.path.read_bytes(),raw)

    @unittest.skipUnless(os.name=='posix','POSIX directory privacy drift')
    def test_posix_directory_privacy_change_during_read_blocks_review(self):
        original = check.os.fstat; count = 0
        def changed(fd):
            nonlocal count
            count += 1
            if count == 2: self.root.chmod(0o755)
            return original(fd)
        try:
            with patch.object(check.os,'fstat',side_effect=changed):
                with self.assertRaisesRegex(check.CheckError,'^operator_audit_read_failed$'): check.inspect_log(self.path)
        finally: self.root.chmod(0o700)

    @unittest.skipUnless(os.name=='posix','POSIX replacement during snapshot read')
    def test_posix_replacement_with_identical_bytes_during_read_is_rejected(self):
        raw = self.path.read_bytes(); original = check.os.fstat; count = 0
        def replaced(fd):
            nonlocal count
            count += 1
            if count == 2: self.path.unlink(); self.write(raw)
            return original(fd)
        with patch.object(check.os,'fstat',side_effect=replaced):
            with self.assertRaisesRegex(check.CheckError,'^operator_audit_read_failed$'): check.inspect_log(self.path)
        self.assertEqual(self.path.read_bytes(),raw)

    def test_real_producer_capacity_and_delivery_failure_review(self):
        path = self.root/'producer.jsonl'; sink = producer.FileAudit(path,'web',max_bytes=4096)
        pending = []
        while True:
            try: pending.append(sink.begin('technical_export'))
            except producer.AuditError: break
        for request in pending: sink.finish(request,http_status=200,outcome='delivery_failed',operator_id='PRIVATE-OP',assessment_id='PRIVATE-LAB')
        sink.close(); result = check.inspect_log(path)
        self.assertEqual(result['state'],'closed')
        self.assertEqual(result['outcomes']['delivery_failed'],len(pending))
        self.assertNotIn('PRIVATE-',json.dumps(result))

    def test_real_end_fsync_failure_is_open_prefix_even_if_complete_line_is_observed(self):
        path = self.root/'fsync.jsonl'; sink = producer.FileAudit(path,'api')
        request = sink.begin('login')
        with patch.object(producer.os,'fsync',side_effect=OSError(MARKER)):
            with self.assertRaises(producer.AuditError): sink.finish(request,http_status=201,outcome='response_written',operator_id='PRIVATE-OP')
        with self.assertRaises(producer.AuditError): sink.close()
        result = check.inspect_log(path)
        self.assertEqual(result['state'],'open_prefix')
        self.assertEqual(result['events']['request_finished'],1)
        self.assertEqual(result['unfinished_requests'],0)
        self.assertEqual(result['events']['listener_stopped'],0)

    def test_real_process_exit_preserves_unfinished_prefix_without_repair(self):
        path = self.root/'interrupted.jsonl'
        program = "import os, sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); import P01_Operator_Audit as a; s=a.FileAudit(sys.argv[2],'api'); s.begin('login'); os._exit(23)"
        result = subprocess.run([sys.executable,'-c',program,str(Path(check.__file__).parent),str(path)],capture_output=True,timeout=15)
        self.assertEqual(result.returncode,23); before = path.read_bytes()
        summary = check.inspect_log(path)
        self.assertEqual(summary['state'],'open_prefix'); self.assertEqual(summary['unfinished_requests'],1)
        self.assertEqual(path.read_bytes(),before)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()),['interrupted.jsonl','private-audit.jsonl'])

    def test_real_http_login_logout_denial_and_closed_summary_do_not_expose_ids_or_tokens(self):
        policy = self.root/'accounts.json'; password = 'Synthetic private review passphrase 01!'
        auth.create_policy(policy,'PRIVATE-OP','private-reader',['PRIVATE-LAB'],password)
        path = self.root/'http.jsonl'; server = api.create_server(policy,port=0,audit_path=path)
        worker = threading.Thread(target=server.serve_forever,daemon=True); worker.start()
        def request(method,target,payload=None,token=None):
            headers = {'Content-Type':'application/json'} if payload else {}
            if token: headers['Authorization'] = 'Bearer ' + token
            with closing(http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=10)) as conn:
                conn.request(method,target,json.dumps(payload) if payload else None,headers)
                response = conn.getresponse(); return response.status,json.loads(response.read())
        try:
            status, body = request('POST','/api/v1/operator/session',dict(username='private-reader',password=password))
            self.assertEqual(status,201); token = body['access_token']
            self.assertEqual(request('GET','/api/v1/assessments/PRIVATE-DENIED/report',token=token)[0],403)
            self.assertEqual(request('DELETE','/api/v1/operator/session',token=token)[0],200)
        finally:
            server.shutdown(); server.server_close(); worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        summary = check.inspect_log(path); output = json.dumps(summary)
        self.assertEqual(summary['state'],'closed'); self.assertEqual(summary['events']['request_finished'],3)
        self.assertEqual(summary['http_classes']['4xx'],1)
        for private in ('PRIVATE-','private-reader',password,token,hashlib.sha256(token.encode()).hexdigest()):
            self.assertNotIn(private,output)

    def test_cli_closed_open_partial_invalid_and_digest_conflict_have_distinct_codes(self):
        base = ['--audit-file',str(self.path)]
        self.assertEqual(self.cli(base)[0],0)
        for raw, state in [(serialize(complete()[:2]),'open_prefix'),
                           (serialize(complete()[:2])+MARKER.encode(),'partial_prefix')]:
            self.write(raw); code, output = self.cli(base)
            self.assertEqual(code,3); self.assertEqual(output['state'],state)
            self.assertNotIn(MARKER,json.dumps(output)); self.assertNotIn(str(self.path),json.dumps(output))
        self.write(b'PRIVATE-INVALID\n'); code, output = self.cli(base)
        self.assertEqual(code,2); self.assertEqual(output['error_code'],'operator_audit_structure_invalid')
        self.write(serialize(complete()))
        code, output = self.cli(base+['--expected-sha256','f'*64])
        self.assertEqual(code,2); self.assertEqual(output['error_code'],'operator_audit_digest_conflict')

    def test_cli_missing_duplicate_abbreviated_unknown_and_untrusted_arguments_are_redacted(self):
        for args in [[],['--audit-file'],['--audit',str(self.path)],['--token',MARKER],
                     ['--audit-file',str(self.path),'--audit-file='+MARKER],
                     ['--audit-file',str(self.path),'--expected-sha256',MARKER]]:
            code, output = self.cli(args)
            self.assertEqual(code,2); self.assertEqual(output['error_code'],'operator_audit_input_invalid')
            self.assertNotIn(MARKER,json.dumps(output)); self.assertNotIn(str(self.path),json.dumps(output))
        with patch.object(check,'read_snapshot',side_effect=OSError(MARKER)):
            code, output = self.cli(['--audit-file',str(self.path)])
        self.assertEqual(code,2); self.assertNotIn(MARKER,json.dumps(output))


if __name__ == '__main__': unittest.main()
