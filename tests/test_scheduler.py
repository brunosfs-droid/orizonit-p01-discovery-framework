"""Scheduler contract tests: accelerated waits here; native helper uses real 60s."""
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'agent'))
import P01_Scheduler as scheduler
import P01_Windows_Service as windows
import P01_Linux_Service as linux


class Clock:
    def __init__(self, callback=None):
        self.intervals = []
        self.callback = callback
        self.stopped = False

    def is_set(self):
        return self.stopped

    def wait(self, interval):
        self.intervals.append(interval)
        if self.callback:
            self.callback(self)
        return self.stopped


class SchedulerContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.rt = scheduler.agent.runtime
        self.workspace = Path(self.rt.init_workspace(root, 'S1', 'R1', 'NODE-01')['workspace'])
        self.policy = self.workspace / 'config/agent-policy.json'
        self.policy_doc = {'schema_version': '0.5f', 'identity': {
            'assessment_id': 'S1', 'run_id': 'R1', 'node_id': 'NODE-01'}, 'grants': {},
            'schedule': {'kind': 'interval', 'interval_seconds': 60}}
        self.write_policy()
        self.config = root / 'service.json'
        self.config_doc = {'schema_version': '0.5f.3', 'workspace': str(self.workspace),
                           'policy': str(self.policy), 'scheduler': {'enabled': True, 'max_invocations': 3}}
        self.write_config()

    def write_policy(self):
        self.policy.write_text(json.dumps(self.policy_doc))

    def write_config(self):
        self.config.write_text(json.dumps(self.config_doc))

    def run_scheduler(self, clock=None):
        return scheduler.run(self.config, clock or Clock(), windows.load_config)

    def session(self):
        paths = list((self.workspace / 'logs/scheduler').glob('*.json'))
        self.assertEqual(len(paths), 1)
        return paths[0], self.rt.load_json(paths[0])

    def test_strict_opt_in_budget_legacy_defaults_and_unknown_keys(self):
        base = {key: value for key, value in self.config_doc.items() if key != 'scheduler'}
        self.assertFalse(scheduler.validate_config(base, '0.5f.1')['enabled'])
        self.assertFalse(scheduler.validate_config(dict(base, schema_version='0.5f.1'), '0.5f.1')['enabled'])
        for value in ({'enabled': 1, 'max_invocations': 2}, {'enabled': True, 'max_invocations': True},
                      {'enabled': True, 'max_invocations': 0}, {'enabled': True, 'max_invocations': 10001},
                      {'enabled': True, 'max_invocations': 2, 'transport': 'SENTINEL'}):
            with self.assertRaises(scheduler.SchedulerError):
                scheduler.validate_config(dict(base, scheduler=value), '0.5f.1')
        with self.assertRaises(scheduler.SchedulerError):
            scheduler.validate_config(dict(self.config_doc, schema_version='0.5f.1'), '0.5f.1')

    def test_pre_stopped_never_reads_or_invokes(self):
        stop = threading.Event()
        stop.set()
        with mock.patch.object(windows, 'load_config') as load, mock.patch.object(scheduler.agent, 'run_once') as run:
            self.assertEqual(self.run_scheduler(stop)['status'], 'stopped')
        load.assert_not_called()
        run.assert_not_called()

    def test_200_denied_ticks_fixed_delay_state_unchanged_no_dispatch(self):
        self.config_doc['scheduler']['max_invocations'] = 200
        self.write_config()
        before = (self.workspace / self.rt.STATE_REL).read_bytes()
        clock = Clock()
        with mock.patch.object(scheduler.agent, '_dispatch') as dispatch:
            result = self.run_scheduler(clock)
        self.assertEqual((result['status'], result['reason'], result['invocations']), ('completed', 'max_invocations', 200))
        self.assertEqual(clock.intervals, [60] * 199)
        self.assertEqual(len(list((self.workspace / 'logs/agent').glob('*.json'))), 200)
        self.assertEqual((self.workspace / self.rt.STATE_REL).read_bytes(), before)
        self.assertFalse(scheduler.audit(self.workspace)['review_required'])
        dispatch.assert_not_called()

    def test_policy_and_interval_reread_each_tick(self):
        def change(clock):
            self.policy_doc['limits'] = {'max_actions': len(clock.intervals) + 25}
            self.policy_doc['schedule']['interval_seconds'] = 90
            self.write_policy()
        clock = Clock(change)
        self.assertEqual(self.run_scheduler(clock)['invocations'], 3)
        hashes = {self.rt.load_json(p)['policy_sha256'] for p in (self.workspace / 'logs/agent').glob('*.json')}
        self.assertEqual(len(hashes), 3)
        self.assertEqual(clock.intervals, [60, 90])

    def test_policy_revocation_halts_without_second_attempt_and_blocks_restart(self):
        def revoke(_):
            self.policy_doc['identity']['node_id'] = 'OTHER'
            self.write_policy()
        result = self.run_scheduler(Clock(revoke))
        self.assertEqual((result['reason'], result['invocations'], result['error_code']),
                         ('failed', 1, 'workspace_identity_mismatch'))
        self.policy_doc['identity']['node_id'] = 'NODE-01'
        self.write_policy()
        with mock.patch.object(scheduler.agent, 'run_once') as run:
            self.assertEqual(self.run_scheduler()['reason'], 'review_required')
        run.assert_not_called()

    def test_cooperative_stop_during_wait_no_retry(self):
        result = self.run_scheduler(Clock(lambda clock: setattr(clock, 'stopped', True)))
        self.assertEqual((result['reason'], result['invocations']), ('stopped', 1))
        self.assertFalse(scheduler.audit(self.workspace)['review_required'])

    def test_disabling_schedule_while_waiting_stops_without_extra_invocation(self):
        def disable(_):
            self.config_doc['scheduler']['enabled'] = False
            self.write_config()
        result = self.run_scheduler(Clock(disable))
        self.assertEqual((result['reason'], result['invocations']), ('schedule_disabled', 1))

    def test_changed_budget_requires_review_without_extra_invocation(self):
        def change(_):
            self.config_doc['scheduler']['max_invocations'] = 5
            self.write_config()
        result = self.run_scheduler(Clock(change))
        self.assertEqual((result['reason'], result['invocations']), ('config_changed', 1))
        self.assertTrue(scheduler.audit(self.workspace)['review_required'])

    def test_pending_canonical_intent_halts_and_preserves_bytes(self):
        intent = self.workspace / 'logs/agent/intent.json'
        self.rt.write_json_with_sidecar(intent, {'schema_version': '0.5f', 'status': 'running'})
        raw = intent.read_bytes()
        with mock.patch.object(scheduler.agent, '_dispatch') as dispatch:
            result = self.run_scheduler()
        self.assertEqual((result['reason'], result['invocations']), ('review_required', 1))
        self.assertEqual(intent.read_bytes(), raw)
        dispatch.assert_not_called()

    def test_running_scheduler_intent_blocks_replay_even_with_no_canonical_intent(self):
        self.run_scheduler()
        path, doc = self.session()
        doc.update(status='running', reason='in_progress', finished_at_utc=None)
        self.rt.write_json_with_sidecar(path, doc)
        raw = path.read_bytes()
        with mock.patch.object(scheduler.agent, 'run_once') as run:
            result = self.run_scheduler()
        self.assertEqual((result['reason'], result['invocations']), ('review_required', 0))
        self.assertEqual(path.read_bytes(), raw)
        run.assert_not_called()

    def test_manual_host_cannot_bypass_scheduler_review_by_disabling(self):
        with mock.patch.object(scheduler.agent, 'run_once', side_effect=RuntimeError('SENTINEL')):
            self.assertEqual(self.run_scheduler()['reason'], 'failed')
        self.config_doc['scheduler']['enabled'] = False
        self.write_config()
        for host in ((windows, linux) if sys.platform == 'linux' else (windows,)):
            with mock.patch.object(scheduler.agent, 'run_once') as run:
                self.assertEqual(host.invoke_once(self.config, threading.Event())['status'], 'review_required')
            run.assert_not_called()

    def test_error_is_fixed_redacted_and_no_retry(self):
        with mock.patch.object(scheduler.agent, 'run_once', side_effect=RuntimeError('password=SENTINEL')) as run:
            result = self.run_scheduler()
        self.assertEqual((result['error_code'], result['invocations']), ('service_failed', 1))
        self.assertEqual(run.call_count, 1)
        path, _ = self.session()
        self.assertNotIn('SENTINEL', path.read_text() + json.dumps(result))

    def test_valid_advanced_results_loop_but_already_complete_stops(self):
        with mock.patch.object(scheduler.agent, 'run_once', side_effect=[{'status': 'advanced', 'stage': 'discovery'},
              {'status': 'already_complete', 'stage': None}]) as run:
            result = self.run_scheduler()
        self.assertEqual((result['reason'], result['invocations']), ('already_complete', 2))
        self.assertEqual(run.call_count, 2)
        self.assertFalse(scheduler.audit(self.workspace)['review_required'])

    def test_invalid_result_halts_redacted(self):
        with mock.patch.object(scheduler.agent, 'run_once', return_value={'status': 'SENTINEL'}) as run:
            result = self.run_scheduler()
        self.assertEqual(result['error_code'], 'service_failed')
        self.assertEqual(run.call_count, 1)
        self.assertNotIn('SENTINEL', self.session()[0].read_text())

    def test_schedule_required_and_invalid_interval_never_invokes(self):
        for settings in (None, {'kind': 'interval', 'interval_seconds': 59}):
            if settings is None:
                self.policy_doc.pop('schedule', None)
            else:
                self.policy_doc['schedule'] = settings
            self.write_policy()
            with mock.patch.object(scheduler.agent, 'run_once') as run:
                self.assertEqual(self.run_scheduler()['reason'], 'failed')
            run.assert_not_called()

    def test_journal_tamper_or_semantic_corruption_blocks_before_dispatch(self):
        self.run_scheduler()
        path, original = self.session()
        for changes in ({'node_id': 'OTHER'}, {'status': 'completed', 'reason': 'failed'},
                        {'invocations': True}, {'error_code': 'SENTINEL'}, {'unexpected': 'SENTINEL'}):
            self.rt.write_json_with_sidecar(path, dict(original, **changes))
            with mock.patch.object(scheduler.agent, 'run_once') as run:
                self.assertEqual(self.run_scheduler()['error_code'], 'scheduler_integrity_failed')
            run.assert_not_called()
        path.write_bytes(b'tampered')
        self.assertEqual(self.run_scheduler()['error_code'], 'scheduler_integrity_failed')

    def test_shared_busy_workspace_never_creates_scheduler_intent(self):
        with mock.patch.object(scheduler.agent, 'workspace_lock', side_effect=scheduler.agent.WorkspaceBusy('workspace_busy')):
            self.assertEqual(self.run_scheduler()['error_code'], 'workspace_busy')
        self.assertFalse((self.workspace / 'logs/scheduler').exists())


if __name__ == '__main__':
    unittest.main()
