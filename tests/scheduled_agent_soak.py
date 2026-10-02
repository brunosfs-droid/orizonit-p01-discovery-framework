"""Native SCM/systemd bounded scheduling and interrupted-wait R1, all grants denied.

Real 60-second intervals. Default two ticks is a short soak, not multi-day proof.
--lab-root retains a unique fixture and proof; refuses any preexisting service.
"""
import argparse
from contextlib import nullcontext
from datetime import datetime
import json
import importlib.util
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'agent'))
WINDOWS = sys.platform == 'win32'
if WINDOWS:
    import P01_Windows_Service as service
    from windows_service_scm_smoke import acl, wait_for
else:
    import P01_Linux_Service as service
    from linux_service_systemd_smoke import ensure_account, permissions, wait_for
import P01_Scheduler as scheduler


def verified(rt, path):
    try:
        return rt.load_json(path) if rt.verify_sidecar(path) else None
    except (OSError, ValueError):
        return None  # A reader may observe the atomic JSON/sidecar replacement boundary.


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab-root', type=Path)
    parser.add_argument('--node-id', default='P01-CI')
    parser.add_argument('--ticks', type=int, default=2)
    args = parser.parse_args(argv)
    assert 2 <= args.ticks <= 10, 'ticks_must_be_2_to_10'
    assert not service.inspect_service()['installed'], 'preexisting_service_preserved'
    if WINDOWS:
        ws, _, _ = service.windows_modules()
        account = None
        base = args.lab_root or Path(tempfile.gettempdir())
    else:
        service.require_root()
        assert Path('/proc/1/comm').read_text().strip() == 'systemd', 'native_systemd_required'
        account = ensure_account()
        base = (args.lab_root or Path('/var/lib/canca/scheduled-ci')).resolve()
        assert base.is_relative_to(Path('/var/lib')), 'lab_root_must_be_under_var_lib'
        base.mkdir(parents=True, exist_ok=True)
        service.protected(base)
        base.chmod(0o755)
    if args.lab_root:
        root = base.resolve() / ('P01-SCHEDULED-R1-' + uuid.uuid4().hex[:12])
        root.mkdir(parents=True)
        folder = nullcontext(str(root))
    else:
        folder = tempfile.TemporaryDirectory(prefix='P01-SCHEDULED-CI-', dir=base)
    installed = False
    with folder as temp:
        root = Path(temp).resolve()
        if WINDOWS:
            script = ROOT / 'agent/P01_Windows_Service.py'
        else:
            root.chmod(0o755)
            deployment = root / 'deployment'
            for relative in ('agent/P01_Agent.py', 'agent/P01_Linux_Service.py', 'agent/P01_Scheduler.py',
                             'runtime/P01_Discovery_Node.py', 'runtime/P01_Workspace_Lock.py'):
                target = deployment / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
                target.chmod(0o644)
            for directory in (deployment, *deployment.rglob('*')):
                if directory.is_dir():
                    directory.chmod(0o755)
            script = deployment / 'agent/P01_Linux_Service.py'
        rt = service.agent.runtime
        workspace = Path(rt.init_workspace(root / 'runs', 'P01CI', 'P01LAB-AGENT-NEG-SCHEDULED', args.node_id)['workspace'])
        if not WINDOWS:
            for parent in (root / 'runs', root / 'runs/P01CI'):
                parent.chmod(0o755)
        policy = workspace / 'config/agent-policy.json'
        policy_doc = {'schema_version': '0.5f', 'identity': {'assessment_id': 'P01CI',
            'run_id': 'P01LAB-AGENT-NEG-SCHEDULED', 'node_id': args.node_id}, 'grants': {},
            'schedule': {'kind': 'interval', 'interval_seconds': 60}, 'limits': {'max_actions': 25}}
        policy.write_text(json.dumps(policy_doc))
        config = root / 'service.json'
        cfg = {'schema_version': '0.5f.3', 'workspace': str(workspace), 'policy': str(policy),
               'scheduler': {'enabled': False, 'max_invocations': args.ticks}}
        config.write_text(json.dumps(cfg))
        if not WINDOWS:
            config.chmod(0o644)
        before_state = (workspace / rt.STATE_REL).read_bytes()
        agent_dir, session_dir = workspace / 'logs/agent', workspace / 'logs/scheduler'

        def command(action):
            result = subprocess.run([sys.executable, str(script), action, '--config', str(config)],
                                    capture_output=True, text=True, timeout=30)
            assert result.returncode == 0, action + '_failed: ' + result.stdout
            return json.loads(result.stdout)

        def info():
            return service.inspect_service(config) if WINDOWS else command('query')

        def active():
            return info()['state'] == ('running' if WINDOWS else 'active')

        def stop():
            command('stop')
            wait_for(lambda: info()['state'] == ('stopped' if WINDOWS else 'inactive'), 'service_not_stopped')

        def journals():
            return {p: doc for p in agent_dir.glob('*.json') if (doc := verified(rt, p)) is not None}

        def final_session(previous, reason):
            new = set(session_dir.glob('*.json')) - previous
            if len(new) == 1:
                doc = verified(rt, next(iter(new)))
                return doc if doc and doc['reason'] == reason and doc['finished_at_utc'] else None
            return None

        try:
            service.agent.agent_status(workspace, policy)  # Creates retained lock before ACL/DAC.
            if not WINDOWS:
                permissions(workspace, account)
            command('install')  # Disabled scheduler, all-denied policy are required for installation.
            installed = True
            if WINDOWS:
                acl(ROOT, 'RX')
                for python_root in {Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve()}:
                    acl(python_root, 'RX')
                acl(root, 'RX')
                for directory in rt.WORKSPACE_DIRS:
                    if directory != 'config':
                        acl(workspace / directory, 'M')
                result = subprocess.run(['icacls', str(workspace / '.canca-workspace.lock'), '/grant',
                    f'NT SERVICE\\{service.NAME}:(M)'], capture_output=True)
                assert result.returncode == 0, 'lock_acl_failed'
            check = info()
            assert check['configuration_matches'] and check['manual_start'] and not check['automatic_recovery_enabled']
            # Explicit operator opt-in after installation, while stopped. Same fixed config path.
            cfg['scheduler']['enabled'] = True
            config.write_text(json.dumps(cfg))
            started = time.monotonic()
            command('start')
            wait_for(active, 'service_not_active')
            wait_for(lambda: len(journals()) == 1, 'first_tick_missing')
            first_hash = next(iter(journals().values()))['policy_sha256']
            policy_doc['limits']['max_actions'] = 26
            policy.write_text(json.dumps(policy_doc))  # Prove the next tick rereads validated policy.
            completed = wait_for(lambda: final_session(set(), 'max_invocations'), 'scheduled_budget_not_completed',
                                 timeout=(args.ticks - 1) * 60 + 45)
            elapsed = time.monotonic() - started
            docs = sorted(journals().values(), key=lambda doc: doc['started_at_utc'])
            assert len(docs) == args.ticks and all(doc['status'] == 'policy_denied' for doc in docs)
            assert docs[0]['policy_sha256'] == first_hash and docs[1]['policy_sha256'] != first_hash, 'policy_not_reread'
            assert all((datetime.fromisoformat(b['started_at_utc']) - datetime.fromisoformat(a['finished_at_utc'])).total_seconds()
                       >= 59.5 for a, b in zip(docs, docs[1:])), 'interval_shortened'
            assert elapsed >= (args.ticks - 1) * 60, 'real_wait_not_observed'
            assert completed['invocations'] == args.ticks
            time.sleep(1)
            assert active() and len(journals()) == args.ticks, 'budget_did_not_idle'
            stop()
            previous = set(session_dir.glob('*.json'))
            command('start')
            wait_for(lambda: active() and len(journals()) == args.ticks + 1, 'second_session_first_tick_missing')

            def waiting_intent():
                new = set(session_dir.glob('*.json')) - previous
                if len(new) == 1:
                    path = next(iter(new))
                    doc = verified(rt, path)
                    return path if doc and doc['status'] == 'running' and doc['last_status'] == 'policy_denied' else None
                return None

            intent = wait_for(waiting_intent, 'waiting_scheduler_intent_missing')
            intent_raw = intent.read_bytes()
            owned = info()
            assert owned['configuration_matches'] and active(), 'owned_host_required'
            if WINDOWS:
                with service.handle(ws.OpenSCManager(None, None, ws.SC_MANAGER_CONNECT)) as scm:
                    with service.handle(ws.OpenService(scm, service.NAME, ws.SERVICE_QUERY_STATUS)) as handle:
                        pid = ws.QueryServiceStatusEx(handle)['ProcessId']
                assert pid > 0
                subprocess.run(['taskkill', '/PID', str(pid), '/F'], capture_output=True, check=True)
            else:
                assert owned['main_pid'] > 1
                os.kill(owned['main_pid'], signal.SIGKILL)  # Verified test-owned host, waiting between denied ticks.
            dead_state = 'stopped' if WINDOWS else 'failed'
            wait_for(lambda: info()['state'] == dead_state, 'host_not_dead')
            time.sleep(2)
            assert info()['state'] == dead_state and len(journals()) == args.ticks + 1, 'automatic_restart_detected'
            with service.agent.workspace_lock(workspace):
                pass
            previous = set(session_dir.glob('*.json'))
            command('start')
            review = wait_for(lambda: final_session(previous, 'review_required'), 'restart_not_blocked_for_review')
            assert review['invocations'] == 0 and len(journals()) == args.ticks + 1, 'interrupted_cycle_replayed'
            assert intent.read_bytes() == intent_raw, 'scheduler_intent_changed'
            stop()
            scheduler_audit = scheduler.audit(workspace)
            module_spec = importlib.util.spec_from_file_location('canca_scheduled_audit', ROOT / 'docs/validation/OPTIONAL_AGENT_INTERRUPTION_R1.py')
            lab = importlib.util.module_from_spec(module_spec)
            module_spec.loader.exec_module(lab)
            journal_audit = lab.audit(workspace)
            command('remove')
            installed = False
            wait_for(lambda: not service.inspect_service()['installed'], 'service_not_removed')
            assert (workspace / rt.STATE_REL).read_bytes() == before_state, 'source_state_changed'
            proof = {'status': 'SCHEDULED AGENT SOAK PASS', 'service_version': service.VERSION,
                'scheduler_version': scheduler.VERSION, 'platform': sys.platform, 'starts': 3,
                'scheduled_ticks': args.ticks, 'real_interval_seconds': 60, 'bounded_cycle_elapsed_seconds': round(elapsed, 3),
                'policy_reread': True, 'all_grants_denied': True, 'source_state_unchanged': True,
                'budget_idles_host': True, 'automatic_recovery_enabled': False, 'interrupted_wait_intent_preserved': True,
                'restart_review_invocations': 0, 'lock_reacquired': True, 'service_removed': True,
                'journal_audit': journal_audit, 'scheduler_audit': scheduler_audit,
                'fixture_directory': str(root), 'evidence_retained': bool(args.lab_root)}
            if args.lab_root:
                rt.write_json_with_sidecar(root / 'scheduled-agent-proof.json', proof)
            print(json.dumps(proof, indent=2))
        finally:
            if installed:
                if info()['state'] not in {'stopped', 'inactive', 'failed'}:
                    stop()
                command('remove')


if __name__ == '__main__':
    main()
