"""Root-only real systemd lifecycle test, offline and isolated; no live stages.

--lab-root retains the new fixture and proof. Refuses any preexisting unit.
Leaves the dedicated unprivileged account in place; removes only its own unit.
"""
import argparse
from contextlib import nullcontext
import importlib.util
import json
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
sys.path.insert(0, str(ROOT / "agent"))
import P01_Linux_Service as service


def wait_for(check, code, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.2)
    raise AssertionError(code)


def ensure_account():
    import pwd
    try:
        pwd.getpwnam(service.ACCOUNT)
    except KeyError:
        subprocess.run(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent",
                        "--shell", "/sbin/nologin", service.ACCOUNT], check=True, capture_output=True)
    return service.account_check()


def permissions(workspace, account):
    # Keep workspace parent/config root-owned and non-writable to the service.
    # Give only outputs/state/logs and the retained lock to the dedicated UID.
    workspace.chmod(0o755)
    (workspace / "config").chmod(0o755)
    for path in (workspace / "config").iterdir():
        path.chmod(0o644)
    for directory in service.agent.runtime.WORKSPACE_DIRS:
        if directory == "config":
            continue
        root = workspace / directory
        for path in (root, *root.rglob("*")):
            os.chown(path, account.pw_uid, account.pw_gid)
            path.chmod(0o750 if path.is_dir() else 0o640)
    lock = workspace / ".canca-workspace.lock"
    os.chown(lock, account.pw_uid, account.pw_gid)
    lock.chmod(0o640)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab-root", type=Path)
    parser.add_argument("--node-id", default="P01-CI")
    args = parser.parse_args(argv)
    service.require_root()
    assert Path("/proc/1/comm").read_text().strip() == "systemd", "native_systemd_required"
    assert not service.inspect_service()["installed"], "preexisting_service_preserved"
    account = ensure_account()
    base = (args.lab_root or Path("/var/lib/canca/service-ci")).resolve()
    # A root-owned /var/lib location works with ProtectHome and PrivateTmp.
    assert base.is_relative_to(Path("/var/lib")), "lab_root_must_be_under_var_lib"
    base.mkdir(parents=True, exist_ok=True)
    service.protected(base)
    base.chmod(0o755)
    if args.lab_root:
        root = base / ("P01-SYSTEMD-R1-" + uuid.uuid4().hex[:12])
        root.mkdir()
        folder = nullcontext(str(root))
    else:
        folder = tempfile.TemporaryDirectory(prefix="P01-SYSTEMD-CI-", dir=base)
    installed = False
    with folder as temp:
        root = Path(temp).resolve()
        root.chmod(0o755)
        deployment = root / "deployment"
        # Stage only the core needed for this all-denied lifecycle fixture.
        # No profiles, keys, manifests, customer artifacts or ingestion server.
        for relative in ("agent/P01_Agent.py", "agent/P01_Linux_Service.py",
                         "runtime/P01_Discovery_Node.py", "runtime/P01_Workspace_Lock.py"):
            target = deployment / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
            target.chmod(0o644)
        for directory in deployment.rglob("*"):
            if directory.is_dir():
                directory.chmod(0o755)
        deployment.chmod(0o755)
        rt = service.agent.runtime
        workspace = Path(rt.init_workspace(root / "runs", "P01CI", "P01LAB-AGENT-NEG-SYSTEMD", args.node_id)["workspace"])
        for parent in (root / "runs", root / "runs/P01CI"):
            parent.chmod(0o755)
        policy = workspace / "config/agent-policy.json"
        policy.write_text(json.dumps({"schema_version": "0.5f", "identity": {
            "assessment_id": "P01CI", "run_id": "P01LAB-AGENT-NEG-SYSTEMD", "node_id": args.node_id},
            "grants": {}, "schedule": {"kind": "interval", "interval_seconds": 60}}))
        config = root / "service.json"
        config.write_text(json.dumps({"schema_version": service.VERSION, "workspace": str(workspace), "policy": str(policy)}))
        config.chmod(0o644)
        before_state = (workspace / rt.STATE_REL).read_bytes()
        journal_dir = workspace / "logs/agent"
        script = deployment / "agent/P01_Linux_Service.py"

        def command(action):
            result = subprocess.run([sys.executable, str(script), action, "--config", str(config)],
                                    capture_output=True, text=True, timeout=30)
            assert result.returncode == 0, action + "_failed: " + result.stdout
            return json.loads(result.stdout)

        def info():
            return command("query")

        def start_expect(status):
            previous = set(journal_dir.glob("*.json"))
            command("start")
            wait_for(lambda: info()["state"] == "active", "service_not_active")

            def complete():
                new = set(journal_dir.glob("*.json")) - previous
                if len(new) != 1:
                    return False
                path = new.pop()
                return path if rt.verify_sidecar(path) and rt.load_json(path)["status"] == status else False

            path = wait_for(complete, "service_invocation_wrong")
            time.sleep(1)
            assert set(journal_dir.glob("*.json")) - previous == {path}, "idle_service_repeated"
            assert (workspace / rt.STATE_REL).read_bytes() == before_state, "service_changed_state"

        def stop():
            command("stop")
            wait_for(lambda: info()["state"] == "inactive" and info()["main_pid"] == 0, "service_not_stopped")

        try:
            # Preflight creates the retained kernel lock before DAC setup.
            service.agent.agent_status(workspace, policy)
            permissions(workspace, account)
            unit = root / service.NAME
            # Generate with the staged script path, as the actual CLI does.
            with importlib_context(script) as staged:
                unit.write_text(staged.unit_text(config))
            subprocess.run(["systemd-analyze", "verify", str(unit)], capture_output=True, text=True, check=True)
            command("install")
            installed = True
            actual = info()
            assert actual["configuration_matches"] and actual["manual_start"] and actual["dedicated_account"]
            assert not actual["automatic_recovery_enabled"] and not actual["dropins_present"]
            start_expect("policy_denied")
            failed = subprocess.run([sys.executable, str(script), "remove", "--config", str(config)], capture_output=True, text=True)
            assert failed.returncode == 2 and json.loads(failed.stdout)["error_code"] == "service_not_stopped"
            stop()
            start_expect("policy_denied")
            stop()
            with importlib_context(ROOT / "docs/validation/OPTIONAL_AGENT_INTERRUPTION_R1.py") as lab:
                assert lab.interruption(workspace, "127.0.0.1/32")["running_intent_preserved"]
                permissions(workspace, account)  # Root-created negative journals become service-readable.
                intents = {p: p.read_bytes() for p in journal_dir.glob("*.json") if rt.load_json(p)["status"] == "running"}
                assert len(intents) == 1
                start_expect("review_required")
                owned = info()
                assert owned["configuration_matches"] and owned["state"] == "active" and owned["main_pid"] > 1
                os.kill(owned["main_pid"], signal.SIGKILL)  # Only the verified test-owned idle host.
                wait_for(lambda: info()["state"] == "failed" and info()["main_pid"] == 0, "host_not_failed")
                count = len(list(journal_dir.glob("*.json")))
                time.sleep(2)
                assert info()["state"] == "failed" and len(list(journal_dir.glob("*.json"))) == count, "automatic_restart_detected"
                with service.agent.workspace_lock(workspace):
                    pass
                start_expect("review_required")
                stop()
                assert all(path.read_bytes() == raw for path, raw in intents.items()), "intent_changed"
                audit = lab.audit(workspace)
            command("remove")
            installed = False
            wait_for(lambda: not service.inspect_service()["installed"], "service_not_removed")
            assert (workspace / rt.STATE_REL).read_bytes() == before_state
            proof = {"status": "LINUX SYSTEMD SMOKE PASS", "service_version": service.VERSION, "starts": 4,
                     "one_invocation_per_start": True, "policy_denied_starts": 2, "review_required_starts": 2,
                     "idle_repeat": False, "automatic_recovery_enabled": False, "source_state_unchanged": True,
                     "intent_preserved": True, "lock_reacquired": True, "service_removed": True,
                     "journal_audit": audit, "fixture_directory": str(root), "evidence_retained": bool(args.lab_root)}
            if args.lab_root:
                rt.write_json_with_sidecar(root / "linux-service-proof.json", proof)
            print(json.dumps(proof, indent=2))
        finally:
            if installed:
                stop()
                command("remove")


class importlib_context:
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        spec = importlib.util.spec_from_file_location("canca_smoke_" + uuid.uuid4().hex, self.path)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        return self.module

    def __exit__(self, *_):
        return False


if __name__ == "__main__":
    main()
