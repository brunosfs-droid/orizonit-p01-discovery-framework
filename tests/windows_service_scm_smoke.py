"""Windows CI only: real SCM lifecycle, idle/crash and review preservation.

Uses an isolated all-denied workspace and test-owned service. No live discovery,
credentials or upload. Run elevated on a disposable Windows runner.
"""
import argparse
from contextlib import nullcontext
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))
import P01_Windows_Service as service


def wait_for(check, code, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.2)
    raise AssertionError(code)


def acl(path, permission):
    result = subprocess.run(["icacls", str(path), "/grant", f"NT SERVICE\\{service.NAME}:(OI)(CI)({permission})",
                             "/T", "/C", "/Q"], capture_output=True, text=True)
    if result.returncode:
        raise AssertionError("service_acl_failed")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab-root", type=Path, help="Retain an isolated LAB fixture and proof under this directory")
    parser.add_argument("--node-id", default="P01-CI")
    args = parser.parse_args(argv)
    ws, _, _ = service.windows_modules()
    assert not service.inspect_service()["installed"], "preexisting_service_preserved"
    installed = False
    if args.lab_root:
        lab_root = args.lab_root.resolve() / ("P01-WINSERVICE-R1-" + uuid.uuid4().hex[:12])
        lab_root.mkdir(parents=True)
        folder = nullcontext(str(lab_root))
    else:
        folder = tempfile.TemporaryDirectory(prefix="canca-service-ci-")
    with folder as temp:
        root = Path(temp).resolve()
        rt = service.agent.runtime
        workspace = Path(rt.init_workspace(root / "runs", "P01CI",
                         "P01LAB-AGENT-NEG-SERVICE", args.node_id)["workspace"])
        policy = workspace / "config/agent-policy.json"
        policy.write_text(json.dumps({"schema_version": "0.5f", "identity": {
            "assessment_id": "P01CI", "run_id": "P01LAB-AGENT-NEG-SERVICE", "node_id": args.node_id},
            "grants": {}, "schedule": {"kind": "interval", "interval_seconds": 60}}))
        config = root / "service.json"
        config.write_text(json.dumps({"schema_version": "0.5f.1", "workspace": str(workspace), "policy": str(policy)}))
        before_state = (workspace / rt.STATE_REL).read_bytes()
        journal_dir = workspace / "logs/agent"

        def start_expect(status):
            previous = set(journal_dir.glob("*.json"))
            service.control("start", config)
            wait_for(lambda: service.inspect_service(config)["state"] == "running", "service_not_running")

            def complete():
                new = set(journal_dir.glob("*.json")) - previous
                if len(new) != 1:
                    return False
                path = new.pop()
                return path if rt.verify_sidecar(path) and rt.load_json(path)["status"] == status else False

            path = wait_for(complete, "service_invocation_wrong")
            time.sleep(1)
            assert set(journal_dir.glob("*.json")) - previous == {path}, "idle_service_repeated_invocation"
            assert (workspace / rt.STATE_REL).read_bytes() == before_state, "service_changed_denied_state"
            return path

        def stop():
            service.control("stop", config)
            wait_for(lambda: service.inspect_service(config)["state"] == "stopped", "service_not_stopped")

        try:
            service.install(config)
            installed = True
            acl(ROOT, "RX")
            for python_root in {Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve()}:
                acl(python_root, "RX")
            acl(root, "RX")
            for directory in rt.WORKSPACE_DIRS:
                if directory != "config":
                    acl(workspace / directory, "M")
            lock = workspace / ".canca-workspace.lock"
            result = subprocess.run(["icacls", str(lock), "/grant", f"NT SERVICE\\{service.NAME}:(M)"], capture_output=True)
            assert result.returncode == 0, "lock_acl_failed"
            info = service.inspect_service(config)
            assert all(info[key] for key in ("manual_start", "local_service_account", "service_sid_enabled", "configuration_matches"))
            assert not info["automatic_recovery_enabled"]
            start_expect("policy_denied")
            try:
                service.control("remove", config)
            except service.ServiceError as exc:
                assert str(exc) == "service_not_stopped"
            else:
                raise AssertionError("removed_running_service")
            stop()
            start_expect("policy_denied")
            stop()
            # Produce a real running intent before dispatch in the same isolated
            # workspace, then prove the real SCM host cannot replay it.
            path = ROOT / "docs/validation/OPTIONAL_AGENT_INTERRUPTION_R1.py"
            spec = importlib.util.spec_from_file_location("canca_ci_interruption", path)
            lab = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(lab)
            interruption = lab.interruption(workspace, "127.0.0.1/32")
            assert interruption["running_intent_preserved"]
            intents = {p: p.read_bytes() for p in journal_dir.glob("*.json") if rt.load_json(p)["status"] == "running"}
            assert len(intents) == 1
            start_expect("review_required")
            with service.handle(ws.OpenSCManager(None, None, ws.SC_MANAGER_CONNECT)) as scm:
                with service.handle(ws.OpenService(scm, service.NAME, ws.SERVICE_QUERY_STATUS)) as handle:
                    pid = ws.QueryServiceStatusEx(handle)["ProcessId"]
            assert pid > 0
            subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, check=True)
            wait_for(lambda: service.inspect_service(config)["state"] == "stopped", "killed_service_not_stopped")
            time.sleep(2)
            assert service.inspect_service(config)["state"] == "stopped", "automatic_restart_detected"
            with service.agent.workspace_lock(workspace):
                pass
            start_expect("review_required")
            stop()
            assert all(path.read_bytes() == raw for path, raw in intents.items()), "intent_changed"
            audit = lab.audit(workspace)
            service.control("remove", config)
            installed = False
            wait_for(lambda: not service.inspect_service()["installed"], "service_not_removed")
            assert (workspace / rt.STATE_REL).read_bytes() == before_state
            proof = {"status": "WINDOWS SCM SMOKE PASS", "service_version": service.VERSION, "starts": 4,
                "one_invocation_per_start": True, "policy_denied_starts": 2,
                "review_required_starts": 2, "idle_repeat": False,
                "automatic_recovery_enabled": False, "source_state_unchanged": True,
                "intent_preserved": True, "lock_reacquired": True,
                "service_removed": True, "journal_audit": audit,
                "fixture_directory": str(root), "evidence_retained": bool(args.lab_root)}
            if args.lab_root:
                rt.write_json_with_sidecar(root / "windows-service-proof.json", proof)
            print(json.dumps(proof, indent=2))
        finally:
            if installed:
                stop()
                service.control("remove", config)


if __name__ == "__main__":
    main()
