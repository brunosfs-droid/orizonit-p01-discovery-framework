#!/usr/bin/env python3
"""Offline R02 checkpoint multiprocess drain qualification (Linux/POSIX only).

Launches a fixed synthetic local sleeping Python script, never a real scanner.
No database, network connection, or real laboratory credentials are used.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
from unittest.mock import patch

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[1]
sys.path.insert(0, str(ROOT / "server"))
import P01_Workspace_Coordinator as coordinator
import P01_Workspace_Legacy_Jobs as jobs
import P01_Workspace_Service as service

SPEC = importlib.util.spec_from_file_location(
    "r02_synthetic_load_v089", BASE / "ALPHA_R02_COORDINATOR_LOAD_SMOKE_v0.6.89.py")
SYNTHETIC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SYNTHETIC)
pg = coordinator.pg


def pid_active(pid):
    """On Linux, zombies are not executing children and count as terminated."""
    try:
        stat = (Path("/proc") / str(pid) / "stat").read_text(encoding="utf-8")
        return stat.split(") ", 1)[1][0] not in ("Z", "X")
    except (OSError, IndexError):
        return False


def qualification(*, cycles=2, workers=2):
    if os.name != "posix" or not sys.platform.startswith("linux"):
        raise ValueError("multiprocess qualification requires Linux/POSIX")
    if type(cycles) is not int or type(workers) is not int or not (
        1 <= cycles <= 8 and 2 <= workers <= 4
    ):
        raise ValueError("workload exceeds offline limits")
    def authorize(actor, workspace, permission, target):
        permitted = (workspace in ("A", "B") and
                     ((actor == "reader" and permission == "workspace:read") or
                      (actor == "writer" and permission in ("workspace:read", "workspace:write"))))
        pg.require(permitted and target == ("offline", 0, "synthetic"),
                   "workspace_access_denied")
    runtime = coordinator.Coordinator(
        SYNTHETIC.SimulatedLease(), authorizer=authorize,
        heartbeat_seconds=30, max_jobs=workers,
    )
    timings = []
    total_fenced = 0
    started = False
    try:
        with tempfile.TemporaryDirectory(prefix="canca-r02-offline-") as directory:
            parent = Path(directory)
            roots = {}
            for label in ("A", "B"):
                root = parent / ("workspace-" + label)
                root.mkdir()
                roots[label] = root
            marks = parent / "started"
            marks.mkdir()
            child_script = parent / "local_status.py"
            # Child ignores supplied CLI args and only marks its PID and sleeps.
            # No secrets, network clients or workspace files are accessed.
            child_script.write_text(
                "import os, time\nfrom pathlib import Path\n"
                + f"Path({str(marks)!r}, str(os.getpid()) + '.pid').write_text('ready')\n"
                + "time.sleep(60)\n", encoding="utf-8",
            )
            adapter = service.WorkspaceService(
                runtime, service.SourceRoots({}),
                legacy_runs=jobs.LegacyRunRoots(roots),
            )
            runtime.start()
            started = True
            with patch.object(jobs, "SCRIPT", child_script):
                for index in range(cycles):
                    workspace = "A" if index % 2 == 0 else "B"
                    token = runtime.open("writer", workspace, runtime.generation)
                    failures_this_cycle = []
                    completed = []
                    threads = []
                    found = set()

                    def run():
                        try:
                            outcome = adapter.legacy_checkpoint("reader", token, timeout=12)
                            completed.append(outcome["status"])
                        except pg.PersistenceError as exc:
                            failures_this_cycle.append(str(exc))
                        except Exception:
                            failures_this_cycle.append("unexpected_worker_exception")

                    try:
                        for _ in range(workers):
                            thread = threading.Thread(target=run)
                            threads.append(thread)
                            thread.start()
                        deadline = time.monotonic() + 6
                        while time.monotonic() < deadline:
                            found = set(int(p.stem) for p in marks.glob("*.pid"))
                            if len(found) == workers and len(runtime._jobs) == workers:
                                break
                            time.sleep(0.02)
                        found = set(int(p.stem) for p in marks.glob("*.pid"))
                        if len(found) != workers or len(runtime._jobs) != workers:
                            raise AssertionError("synthetic jobs did not start")
                        start = time.monotonic()
                        runtime.close("writer", workspace, token.generation, timeout=7)
                        timings.append((time.monotonic() - start) * 1000)
                        for thread in threads:
                            thread.join(timeout=4)
                        if any(thread.is_alive() for thread in threads):
                            raise AssertionError("synthetic job survived drain")
                        if completed or failures_this_cycle != ["workspace_generation_stale"] * workers:
                            raise AssertionError("stale worker published or returned unexpected error")
                        if runtime._jobs or runtime._cache or runtime._bytes:
                            raise AssertionError("drain leaked coordinator resources")
                        for pid in found:
                            deadline = time.monotonic() + 2
                            while pid_active(pid) and time.monotonic() < deadline:
                                time.sleep(0.02)
                            if pid_active(pid):
                                raise AssertionError("synthetic subprocess survived drain")
                        try:
                            adapter.legacy_checkpoint("reader", token, timeout=1)
                        except pg.PersistenceError as exc:
                            if str(exc) != "workspace_generation_stale":
                                raise AssertionError("stale token rejected for wrong reason")
                        else:
                            raise AssertionError("stale token was accepted")
                        total_fenced += workers
                    finally:
                        runtime._cancel.set()
                        for thread in threads:
                            if thread.is_alive():
                                thread.join(timeout=4)
                        for pid in found:
                            if pid_active(pid):
                                # Fail closed: a leaked process must be killed
                                # even if a preceding assertion failed.
                                try:
                                    os.kill(pid, 9)
                                except ProcessLookupError:
                                    pass
                        for marker in marks.glob("*.pid"):
                            marker.unlink()
        return {
            "status": "OFFLINE_MULTIPROCESS_QUALIFIED",
            "operational_go": False,
            "lab_executed": False,
            "scope": "synthetic_local_status_processes",
            "cycles": cycles,
            "workers_per_cycle": workers,
            "cancellations_fenced": total_fenced,
            "stale_tokens_denied": cycles,
            "close_p50_ms": SYNTHETIC.percentile(timings, 50),
            "close_p95_ms": SYNTHETIC.percentile(timings, 95),
            "close_max_ms": round(max(timings), 3),
            "threshold_qualification": "not_established",
        }
    finally:
        if started:
            runtime.shutdown(timeout=7)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline R02 subprocess drain smoke")
    parser.add_argument("--cycles", type=int, default=2)
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args(argv)
    try:
        output = qualification(cycles=args.cycles, workers=args.workers)
    except (ValueError, AssertionError, pg.PersistenceError, RuntimeError, OSError):
        print(json.dumps({"status": "FAILED", "operational_go": False,
                          "error_code": "r02_offline_multiprocess_failure"}))
        return 2
    print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
