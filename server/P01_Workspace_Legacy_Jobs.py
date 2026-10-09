#!/usr/bin/env python3
"""Read-only legacy runtime checkpoint under a workspace coordinator operation.

Only the local `P01_Discovery_Node.py status --json` subprocess is permitted.
There is deliberately NO scanner, AUTH, FULL, export, upload, or public HTTP API.
"""
import os
import signal
from pathlib import Path
import stat
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import P01_Workspace_Coordinator as coordinator

pg, ws = coordinator.pg, coordinator.ws
VERSION = "0.6.40"
SCRIPT = Path(__file__).resolve().parents[1] / "runtime" / "P01_Discovery_Node.py"
CHECK_INTERVAL = 0.05


def _directory(path):
    try:
        # A trusted configured location must not resolve through a symlink.
        pg.require(path == path.resolve(), "workspace_input_invalid")
        info = path.lstat()
        pg.require(stat.S_ISDIR(info.st_mode), "workspace_input_invalid")
        return (info.st_dev, info.st_ino)
    except (OSError, RuntimeError):
        raise pg.PersistenceError("workspace_input_invalid") from None


class LegacyRunRoots:
    """Private operator-configured roots; never selected by HTTP input."""
    def __init__(self, roots):
        pg.require(type(roots) is dict and len(roots) <= 1024, "workspace_input_invalid")
        self._roots = {}
        for workspace_id, value in roots.items():
            ws.identifier(workspace_id)
            pg.require(isinstance(value, (str, Path)) and "\x00" not in str(value),
                       "workspace_input_invalid")
            path = Path(value).expanduser().absolute()
            _directory(path)
            pg.require(all(path != other and path not in other.parents and other not in path.parents
                           for other in self._roots.values()), "workspace_input_invalid")
            self._roots[workspace_id] = path

    def get(self, workspace_id):
        ws.identifier(workspace_id)
        path = self._roots.get(workspace_id)
        pg.require(path is not None, "workspace_access_denied")
        _directory(path)
        return path


def _stop(process):
    """Bounded best-effort process-group cleanup before releasing the workspace job.

    On POSIX the child owns a fresh session/group. Signal its *entire group*
    even when its leader has already exited; otherwise orphaned subprocesses
    could survive a successful status command or workspace close. Child
    processes that explicitly detach to other sessions remain out of scope.
    On Windows only direct-child termination is currently supported.
    """
    if os.name == "posix":
        pgid = process.pid
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError:
            raise pg.PersistenceError("workspace_legacy_job_failed") from None
        # The parent may exit before its descendants. Inspect the whole group,
        # not process.poll(), and escalate after a strictly bounded grace.
        deadline = time.monotonic() + 0.35
        while time.monotonic() < deadline:
            try:
                os.killpg(pgid, 0)
            except ProcessLookupError:
                break
            except OSError:
                raise pg.PersistenceError("workspace_legacy_job_failed") from None
            time.sleep(0.025)
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            raise pg.PersistenceError("workspace_legacy_job_failed") from None
        try:
            process.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            raise pg.PersistenceError("workspace_legacy_job_failed") from None
        return
    if process.poll() is not None:
        return
    try:
        process.terminate()
        process.wait(timeout=0.75)
    except (OSError, subprocess.TimeoutExpired):
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)


def checkpoint(operation, workspace_root, *, timeout=10):
    """Launch one fixed read-only subprocess and fence its entire lifetime.

    Its stdout/stderr are discarded, not parsed, persisted, cached or echoed;
    a nonzero exit is a redacted failure. No external command/argv supplied by
    a client. On POSIX even orphaned children still in the session are terminated; this\n    does not qualify cancellation of live credentialed scanners.
    """
    pg.require(type(operation) is coordinator.Operation, "workspace_input_invalid")
    pg.require(type(timeout) is int and 1 <= timeout <= 30, "workspace_input_invalid")
    pg.require(isinstance(workspace_root, Path), "workspace_input_invalid")
    origin = _directory(workspace_root)
    pg.require(SCRIPT == SCRIPT.resolve() and SCRIPT.is_file(), "workspace_input_invalid")
    operation.check()
    deadline = time.monotonic() + timeout
    child = None
    try:
        child = subprocess.Popen(
            [sys.executable, "-I", str(SCRIPT), "status",
             "--workspace", str(workspace_root), "--json"],
            shell=False, cwd=str(SCRIPT.parents[1]), stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True,
            start_new_session=(os.name == "posix"),
        )
        while True:
            operation.check()
            result = child.poll()
            if result is not None:
                operation.check()
                pg.require(result == 0, "workspace_legacy_job_failed")
                pg.require(_directory(workspace_root) == origin, "workspace_legacy_job_failed")
                return dict(status="checkpoint_executed",
                            job="legacy_runtime_status", version=VERSION,
                            network_activity_performed=False,
                            authentication_performed=False,
                            mutations_performed=False)
            remaining = deadline - time.monotonic()
            pg.require(remaining > 0, "workspace_legacy_job_timeout")
            operation.cancel.wait(min(CHECK_INTERVAL, remaining))
    except OSError:
        raise pg.PersistenceError("workspace_legacy_job_failed") from None
    finally:
        if child is not None:
            _stop(child)
