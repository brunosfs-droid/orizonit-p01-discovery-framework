#!/usr/bin/env python3
"""Cancã Windows Service v0.5f.1: one agent invocation per manual SCM start."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import subprocess
import sys
import threading

sys.path.insert(0, str(Path(__file__).resolve().parent))
import P01_Agent as agent

VERSION = "0.5f.1"
NAME = "CancaP01Agent"
ACCOUNT = r"NT AUTHORITY\LocalService"
DISPLAY_NAME = "Cancã P01 Optional Agent"
DELETE_ACCESS = 0x00010000  # Standard Windows DELETE access right.
DEFAULT_CONFIG = Path(r"C:\ProgramData\Canca\windows-service.json")
STATUSES = {"advanced", "already_complete", "policy_denied", "review_required", "failed", "stopped_before_invocation"}
ERRORS = {"invalid_policy", "workspace_integrity_failed", "workspace_identity_mismatch",
          "interactive_provider_denied", "credential_configuration_invalid", "transport_required",
          "stage_invalid", "runtime_failed", "journal_integrity_failed", "workspace_busy",
          "service_config_invalid", "service_failed"}


class ServiceError(RuntimeError):
    """Fixed public codes only."""


def require(condition, code):
    if not condition:
        raise ServiceError(code)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "service_config_invalid")
        result[key] = value
    return result


def load_config(path):
    try:
        raw = Path(path).read_bytes()
        require(len(raw) <= 16384, "service_config_invalid")
        doc = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique)
        require(isinstance(doc, dict) and set(doc) == {"schema_version", "workspace", "policy"}
                and doc["schema_version"] == VERSION, "service_config_invalid")
        for name in ("workspace", "policy"):
            value = doc[name]
            require(isinstance(value, str) and "\x00" not in value and Path(value).is_absolute()
                    and not value.startswith(("\\\\", "//")), "service_config_invalid")
        workspace, policy = (Path(doc[name]).resolve() for name in ("workspace", "policy"))
        require(workspace.is_dir() and policy.is_file() and policy.is_relative_to(workspace),
                "service_config_invalid")
        return workspace, policy
    except ServiceError:
        raise
    except Exception:
        raise ServiceError("service_config_invalid") from None


def public_error(exc):
    code = str(exc)
    return code if code in ERRORS else "service_failed"


def invoke_once(config_path, stop_event):
    """No loop/retry/transport: canonical run_once owns lock, intent and journal."""
    if stop_event.is_set():
        return {"status": "stopped_before_invocation", "stage": None, "error_code": None}
    try:
        workspace, policy = load_config(config_path)
        if stop_event.is_set():
            return {"status": "stopped_before_invocation", "stage": None, "error_code": None}
        result = agent.run_once(workspace, policy)
        status = result.get("status")
        require(status in STATUSES - {"failed", "stopped_before_invocation"}, "service_failed")
        stage = result.get("stage")
        require(stage is None or stage in agent.STAGES, "service_failed")
        return {"status": status, "stage": stage, "error_code": None}
    except Exception as exc:
        return {"status": "failed", "stage": None, "error_code": public_error(exc)}


def worker(config_path, stop_event, done_event, output):
    try:
        output.update(invoke_once(config_path, stop_event))
    finally:
        if not output:
            output.update(status="failed", stage=None, error_code="service_failed")
        done_event.set()


def windows_modules():
    require(sys.platform == "win32", "windows_required")
    try:
        import win32service
        import win32serviceutil
        import servicemanager
        return win32service, win32serviceutil, servicemanager
    except ImportError:
        raise ServiceError("pywin32_required") from None


@contextmanager
def handle(value):
    try:
        yield value
    finally:
        value.Close()


def binary_path(config_path):
    return subprocess.list2cmdline([str(Path(sys.executable).resolve()),
        str(Path(__file__).resolve()), "host", "--config", str(Path(config_path).resolve())])


def inspect_service(config_path=None):
    ws, _, _ = windows_modules()
    with handle(ws.OpenSCManager(None, None, ws.SC_MANAGER_CONNECT)) as scm:
        try:
            service = ws.OpenService(scm, NAME, ws.SERVICE_QUERY_CONFIG | ws.SERVICE_QUERY_STATUS)
        except Exception as exc:
            if getattr(exc, "winerror", None) == 1060:
                return {"installed": False, "state": "not_installed"}
            raise
        with handle(service):
            cfg = ws.QueryServiceConfig(service)
            state = ws.QueryServiceStatus(service)[1]
            recovery = ws.QueryServiceConfig2(service, ws.SERVICE_CONFIG_FAILURE_ACTIONS)
            sid = ws.QueryServiceConfig2(service, ws.SERVICE_CONFIG_SERVICE_SID_INFO)
            owned = config_path is not None and cfg[3] == binary_path(config_path)
            states = {ws.SERVICE_STOPPED: "stopped", ws.SERVICE_START_PENDING: "start_pending",
                ws.SERVICE_STOP_PENDING: "stop_pending", ws.SERVICE_RUNNING: "running",
                ws.SERVICE_PAUSED: "paused"}
            return {"installed": True, "state": states.get(state, "other"),
                "configuration_matches": owned, "manual_start": cfg[1] == ws.SERVICE_DEMAND_START,
                "local_service_account": cfg[7].lower() == ACCOUNT.lower(),
                "automatic_recovery_enabled": bool(recovery.get("Actions")),
                "service_sid_enabled": sid == ws.SERVICE_SID_TYPE_UNRESTRICTED}


def preflight(config_path):
    workspace, policy = load_config(config_path)
    status = agent.agent_status(workspace, policy)
    parsed, _ = agent.load_policy(policy)
    return {"service_version": VERSION, "agent_version": agent.VERSION,
        "runtime_version": agent.runtime.VERSION, "service_name": NAME,
        "status": "ready", "next_status": status["status"], "next_stage": status["next_stage"],
        "all_grants_denied": not any(parsed.get("grants", {}).values()),
        "one_invocation_per_start": True, "schedule_enabled": False,
        "upload_transport_persisted": False, "network_activity_performed": False,
        "secret_resolution_performed": False, "service": inspect_service(config_path)}


def install(config_path):
    check = preflight(config_path)
    require(check["all_grants_denied"], "install_requires_denied_policy")
    require(not check["service"]["installed"], "service_already_installed")
    ws, _, _ = windows_modules()
    with handle(ws.OpenSCManager(None, None, ws.SC_MANAGER_CREATE_SERVICE)) as scm:
        service = ws.CreateService(scm, NAME, DISPLAY_NAME, ws.SERVICE_ALL_ACCESS,
            ws.SERVICE_WIN32_OWN_PROCESS, ws.SERVICE_DEMAND_START, ws.SERVICE_ERROR_NORMAL,
            binary_path(config_path), None, 0, None, ACCOUNT, None)
        with handle(service):
            try:
                ws.ChangeServiceConfig2(service, ws.SERVICE_CONFIG_DESCRIPTION,
                    "One policy-gated Cancã invocation per manual start; no scheduler or automatic retry.")
                ws.ChangeServiceConfig2(service, ws.SERVICE_CONFIG_SERVICE_SID_INFO,
                    ws.SERVICE_SID_TYPE_UNRESTRICTED)
                ws.ChangeServiceConfig2(service, ws.SERVICE_CONFIG_FAILURE_ACTIONS,
                    {"ResetPeriod": 0, "RebootMsg": None, "Command": None, "Actions": []})
                ws.ChangeServiceConfig2(service, ws.SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, False)
            except Exception:
                ws.DeleteService(service)
                raise
    return {"status": "installed", "service": inspect_service(config_path)}


def control(command, config_path):
    info = inspect_service(config_path)
    require(info["installed"], "service_not_installed")
    require(info["configuration_matches"] and info["manual_start"]
            and info["local_service_account"] and not info["automatic_recovery_enabled"]
            and info["service_sid_enabled"], "service_configuration_mismatch")
    ws, _, _ = windows_modules()
    access = {"start": ws.SERVICE_START, "stop": ws.SERVICE_STOP, "remove": DELETE_ACCESS}[command]
    with handle(ws.OpenSCManager(None, None, ws.SC_MANAGER_CONNECT)) as scm:
        with handle(ws.OpenService(scm, NAME, access | ws.SERVICE_QUERY_STATUS)) as service:
            if command == "start":
                require(info["state"] == "stopped", "service_not_stopped")
                # Revalidate immediately before start. SCM host reads policy again.
                preflight(config_path)
                ws.StartService(service, None)
            elif command == "stop":
                if info["state"] not in {"stopped", "stop_pending"}:
                    ws.ControlService(service, ws.SERVICE_CONTROL_STOP)
            else:
                require(info["state"] == "stopped", "service_not_stopped")
                ws.DeleteService(service)
    return {"status": command + "_requested", "evidence_preserved": True}


def host(config_path):
    ws, util, manager = windows_modules()

    class CancaService(util.ServiceFramework):
        _svc_name_ = NAME
        _svc_display_name_ = DISPLAY_NAME

        def __init__(self, args):
            super().__init__(args)
            self.stop_event = threading.Event()

        def SvcStop(self):
            self.stop_event.set()
            self.ReportServiceStatus(ws.SERVICE_STOP_PENDING, waitHint=30000)

        def SvcShutdown(self):
            self.SvcStop()

        def SvcInterrogate(self):
            self.ReportServiceStatus(ws.SERVICE_STOP_PENDING if self.stop_event.is_set()
                                     else ws.SERVICE_RUNNING, waitHint=30000)

        def SvcDoRun(self):
            manager.LogInfoMsg("Canca v0.5f.1 started; one invocation")
            done, result = threading.Event(), {}
            thread = threading.Thread(target=worker, args=(config_path, self.stop_event, done, result),
                                      name="canca-agent-invocation", daemon=False)
            thread.start()
            while not done.wait(1):
                if self.stop_event.is_set():
                    self.ReportServiceStatus(ws.SERVICE_STOP_PENDING, waitHint=30000)
            thread.join()
            # Result contains only whitelisted codes, never raw errors or paths.
            message = "Canca v0.5f.1 invocation: " + json.dumps(result, sort_keys=True)
            (manager.LogErrorMsg if result.get("status") == "failed" else manager.LogInfoMsg)(message)
            # Stay idle: no timers, repeat, retry or automatic dispatch.
            self.stop_event.wait()
            manager.LogInfoMsg("Canca v0.5f.1 stopped; invocation finished")

    manager.Initialize()
    manager.PrepareToHostSingle(CancaService)
    manager.StartServiceCtrlDispatcher()


def cli(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("doctor", "query", "install", "start", "stop", "remove", "host"))
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args(argv)
    try:
        if args.command == "host":
            host(args.config)
            return 0
        if args.command == "doctor":
            result = preflight(args.config)
        elif args.command == "query":
            result = inspect_service(args.config)
        elif args.command == "install":
            result = install(args.config)
        else:
            result = control(args.command, args.config)
        print(json.dumps(result, indent=2))
        return 0
    except (ServiceError, agent.AgentError, agent.WorkspaceBusy) as exc:
        print(json.dumps({"status": "failed", "error_code": str(exc)}))
        return 2
    except Exception as exc:
        code = "access_denied" if getattr(exc, "winerror", None) == 5 else "service_control_failed"
        print(json.dumps({"status": "failed", "error_code": code}))
        return 2


if __name__ == "__main__":
    raise SystemExit(cli())
