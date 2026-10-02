#!/usr/bin/env python3
"""Cancã Linux/systemd v0.5f.2: one invocation per manual start, then idle."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import threading

sys.path.insert(0, str(Path(__file__).resolve().parent))
import P01_Agent as agent
import P01_Scheduler as scheduler

VERSION = "0.5f.3"
LEGACY_VERSION = "0.5f.2"
NAME = "canca-p01-agent.service"
ACCOUNT = "canca-agent"
UNIT_PATH = Path("/etc/systemd/system") / NAME
DEFAULT_CONFIG = Path("/etc/canca/linux-service.json")
STATUSES = {"advanced", "already_complete", "policy_denied", "review_required"}
ERRORS = {"invalid_policy", "workspace_integrity_failed", "workspace_identity_mismatch",
          "interactive_provider_denied", "credential_configuration_invalid", "transport_required",
          "stage_invalid", "runtime_failed", "journal_integrity_failed", "workspace_busy",
          "service_config_invalid", "service_failed"}


class ServiceError(RuntimeError):
    """Only fixed public error codes."""


def require(condition, code):
    if not condition:
        raise ServiceError(code)


def unique(pairs):
    doc = {}
    for key, value in pairs:
        require(key not in doc, "service_config_invalid")
        doc[key] = value
    return doc


def local_path(value):
    require(isinstance(value, str) and value.startswith("/") and not value.startswith("//")
            and not any(ord(char) < 32 or char in "%$" for char in value), "service_config_invalid")
    return Path(value).resolve()


def load_config(path):
    try:
        raw = Path(path).read_bytes()
        require(len(raw) <= 16384, "service_config_invalid")
        doc = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique)
        scheduler.validate_config(doc, LEGACY_VERSION)
        workspace, policy = (local_path(doc[name]) for name in ("workspace", "policy"))
        require(workspace.is_dir() and policy.is_file() and policy.is_relative_to(workspace),
                "service_config_invalid")
        return workspace, policy
    except ServiceError:
        raise
    except Exception:
        raise ServiceError("service_config_invalid") from None


def invoke_once(config, stop_event):
    if stop_event.is_set():
        return {"status": "stopped_before_invocation", "stage": None, "error_code": None}
    try:
        workspace, policy = load_config(config)
        if stop_event.is_set():
            return {"status": "stopped_before_invocation", "stage": None, "error_code": None}
        with agent.workspace_lock(workspace):
            if scheduler.audit(workspace)["review_required"]:
                return {"status": "review_required", "stage": None, "error_code": None}
            result = agent.run_once(workspace, policy)
        require(result.get("status") in STATUSES and
                (result.get("stage") is None or result["stage"] in agent.STAGES), "service_failed")
        return {"status": result["status"], "stage": result.get("stage"), "error_code": None}
    except Exception as exc:
        code = str(exc)
        return {"status": "failed", "stage": None,
                "error_code": code if code in ERRORS | scheduler.ERRORS else "service_failed"}


def worker(config, stop_event, done_event, output):
    try:
        load_config(config)
        if scheduler.settings(config)["enabled"]:
            output.update(scheduler.run(config, stop_event, load_config))
        else:
            output.update(invoke_once(config, stop_event))
    except Exception as exc:
        output.update(status="failed", stage=None, error_code=scheduler.public_error(exc))
    finally:
        if not output:
            output.update(status="failed", stage=None, error_code="service_failed")
        done_event.set()


def host(config):
    require(sys.platform == "linux", "linux_required")
    require(sys.version_info >= (3, 10), "python_version_unsupported")
    stop, done, output = threading.Event(), threading.Event(), {}
    previous = {sig: signal.signal(sig, lambda *_: stop.set()) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        print("Canca v0.5f.3 started; policy-gated worker", flush=True)
        thread = threading.Thread(target=worker, args=(config, stop, done, output), daemon=False)
        thread.start()
        done.wait()  # Cooperatively finish an in-flight call before exiting.
        thread.join()
        print(json.dumps(output, sort_keys=True), flush=True)
        stop.wait()  # Idle, no timer, retry or second dispatch.
        print("Canca v0.5f.3 stopped; invocation finished", flush=True)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def quote(value):
    value = str(value)
    require(not any(ord(char) < 32 or char in "%$" for char in value), "service_config_invalid")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def unit_text(config):
    workspace, _ = load_config(config)
    paths = [workspace / directory for directory in agent.runtime.WORKSPACE_DIRS if directory != "config"]
    paths.append(workspace / ".canca-workspace.lock")
    command = " ".join(quote(value) for value in (Path(sys.executable).resolve(),
                       Path(__file__).resolve(), "host", "--config", local_path(str(Path(config).absolute()))))
    return "\n".join([
        "[Unit]", "Description=Canca P01 Optional Agent (manual start, policy-gated worker)", "",
        "[Service]", "Type=simple", "User=" + ACCOUNT, "Group=" + ACCOUNT,
        "ExecStart=" + command, "Restart=no", "KillSignal=SIGTERM", "KillMode=mixed", "TimeoutStopSec=infinity",
        "UMask=0077", "NoNewPrivileges=yes", "PrivateTmp=yes", "ProtectSystem=strict",
        "ProtectHome=yes", "ReadWritePaths=" + " ".join(quote(path) for path in paths),
        "StandardOutput=journal", "StandardError=journal", "",
        "# Deliberately no [Install] section: do not enable or attach a timer.", ""])


def systemctl(*args, missing_ok=False):
    require(sys.platform == "linux", "linux_required")
    try:
        result = subprocess.run(["systemctl", "--no-pager", *args], capture_output=True, text=True, timeout=30)
    except Exception:
        raise ServiceError("systemd_unavailable") from None
    require(result.returncode == 0 or (missing_ok and result.returncode in (1, 4)), "service_control_failed")
    return result.stdout


def inspect_service(config=None):
    properties = ("LoadState", "ActiveState", "SubState", "MainPID", "FragmentPath", "DropInPaths",
                  "UnitFileState", "User", "Group", "Restart")
    raw = systemctl("show", NAME, "--property=" + ",".join(properties), missing_ok=True)
    values = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    # A manager communication failure must not be mistaken for an absent unit.
    require("LoadState" in values, "systemd_unavailable")
    installed = values["LoadState"] != "not-found" or UNIT_PATH.exists() or UNIT_PATH.is_symlink()
    if not installed:
        return {"installed": False, "state": "not_installed", "main_pid": 0}
    matches = False
    if config is not None:
        try:
            matches = (not UNIT_PATH.is_symlink() and UNIT_PATH.read_text() == unit_text(config)
                       and values.get("FragmentPath") == str(UNIT_PATH) and not values.get("DropInPaths")
                       and values.get("User") == ACCOUNT and values.get("Group") == ACCOUNT
                       and values.get("Restart") == "no" and values.get("UnitFileState") == "static")
        except (OSError, ServiceError):
            pass
    try:
        pid = int(values.get("MainPID", "0"))
    except ValueError:
        raise ServiceError("service_configuration_mismatch") from None
    return {"installed": True, "state": values.get("ActiveState", "unknown"),
            "substate": values.get("SubState", "unknown"), "main_pid": pid,
            "configuration_matches": matches, "manual_start": values.get("UnitFileState") == "static",
            "dedicated_account": values.get("User") == ACCOUNT and values.get("Group") == ACCOUNT,
            "automatic_recovery_enabled": values.get("Restart") != "no",
            "dropins_present": bool(values.get("DropInPaths"))}


def preflight(config):
    require(sys.version_info >= (3, 10), "python_version_unsupported")
    workspace, policy = load_config(config)
    status = agent.agent_status(workspace, policy)
    parsed, _ = agent.load_policy(policy)
    with agent.workspace_lock(workspace):
        schedule_check = scheduler.audit(workspace)
    return {"service_version": VERSION, "agent_version": agent.VERSION, "runtime_version": agent.runtime.VERSION,
            "status": "ready", "next_status": "review_required" if schedule_check["review_required"] else status["status"],
        "next_stage": None if schedule_check["review_required"] else status["next_stage"], "scheduler_audit": schedule_check,
            "all_grants_denied": not any(parsed.get("grants", {}).values()),
            "one_invocation_per_start": not scheduler.settings(config)["enabled"], "schedule_enabled": scheduler.settings(config)["enabled"], "scheduler_version": scheduler.VERSION, "upload_transport_persisted": False,
            "network_activity_performed": False, "secret_resolution_performed": False,
            "service": inspect_service(config)}


def require_root():
    require(sys.platform == "linux" and os.geteuid() == 0, "root_required")


def account_check():
    import grp
    import pwd
    try:
        user = pwd.getpwnam(ACCOUNT)
        group = grp.getgrnam(ACCOUNT)
        require(user.pw_uid != 0 and user.pw_gid == group.gr_gid != 0
                and user.pw_shell in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false")
                and set(os.getgrouplist(ACCOUNT, user.pw_gid)) == {user.pw_gid}, "service_account_invalid")
    except KeyError:
        raise ServiceError("service_account_required") from None
    return user


def protected(path):
    # Validate root-owned, non-writable deployment/config and every ancestor.
    path = Path(path)
    require(not path.is_symlink(), "service_permissions_invalid")
    for item in (path, *path.parents):
        info = item.stat()
        require(info.st_uid == 0 and not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH),
                "service_permissions_invalid")


def install(config):
    require_root()
    account_check()
    check = preflight(config)
    require(check["all_grants_denied"], "install_requires_denied_policy")
    require(not check["schedule_enabled"], "install_requires_disabled_schedule")
    require(not check["service"]["installed"], "service_already_installed")
    workspace, policy = load_config(config)
    for path in (Path(config).absolute(), policy, workspace / "config", workspace,
                 Path(__file__).resolve(), Path(__file__).resolve().parent / "P01_Agent.py",
                 Path(scheduler.__file__).resolve(), Path(agent.runtime.__file__).resolve(), Path(agent.runtime.__file__).resolve().parent / "P01_Workspace_Lock.py"):
        protected(path)
    # Exclusive creation: never overwrite a same-name unit/symlink.
    text = unit_text(config)
    created = False
    try:
        with UNIT_PATH.open("x", encoding="utf-8") as stream:
            created = True
            stream.write(text)
        UNIT_PATH.chmod(0o644)
        systemctl("daemon-reload")
        info = inspect_service(config)
        require(info["configuration_matches"], "service_configuration_mismatch")
    except Exception:
        if created:
            UNIT_PATH.unlink()
            systemctl("daemon-reload")
        raise
    return {"status": "installed", "service": info}


def control(command, config):
    require_root()
    info = inspect_service(config)
    require(info["installed"], "service_not_installed")
    require(info["configuration_matches"], "service_configuration_mismatch")
    if command == "start":
        require(info["state"] in {"inactive", "failed"} and info["main_pid"] == 0, "service_not_stopped")
        account_check()
        preflight(config)
        systemctl("start", NAME, "--no-block")
    elif command == "stop":
        systemctl("stop", NAME, "--no-block")
    else:
        require(info["state"] in {"inactive", "failed"} and info["main_pid"] == 0, "service_not_stopped")
        UNIT_PATH.unlink()
        systemctl("daemon-reload")
        # Forget only this unit's historical failed state, after removing it.
        systemctl("reset-failed", NAME, missing_ok=True)
    return {"status": command + "_requested", "evidence_preserved": True}


def cli(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("doctor", "query", "install", "start", "stop", "remove", "host"))
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args(argv)
    try:
        if args.command == "host":
            host(args.config)
            return 0
        function = {"doctor": preflight, "query": inspect_service, "install": install}.get(args.command)
        result = function(args.config) if function else control(args.command, args.config)
        print(json.dumps(result, indent=2))
        return 0
    except (ServiceError, agent.AgentError, agent.WorkspaceBusy) as exc:
        # All three exception classes contain fixed codes from this runtime.
        print(json.dumps({"status": "failed", "error_code": str(exc)}))
        return 2
    except Exception:
        print(json.dumps({"status": "failed", "error_code": "service_control_failed"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(cli())
