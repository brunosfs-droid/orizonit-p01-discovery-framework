#!/usr/bin/env python3
"""Bounded offline coordinator drain/switch stress; never launches scanners.

Reports synthetic p50/p95 timing and peak Python allocations as observations,
not as operational SLA qualification or EVE-NG evidence.
"""
import argparse
import json
from pathlib import Path
import sys
import threading
import time
import tracemalloc

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "server"))
import P01_Workspace_Coordinator as coordinator

pg = coordinator.pg


class SimulatedLease:
    """In-memory lease for concurrency fault checks; NOT a SQL lease test."""
    def __init__(self):
        self.target = ("offline", 0, "synthetic")
        self.lease_id = "synthetic-lease"
        self.generation = 0
        self.stopped = False

    def start(self):
        pg.require(not self.stopped, "workspace_lease_lost")
        self.generation += 1
        return self.generation

    def check(self, generation):
        pg.require(not self.stopped and self.generation == generation,
                   "workspace_lease_lost")

    def transition(self, generation, state, workspace_id):
        self.check(generation)
        self.generation += 1
        return self.generation

    def stop(self, generation):
        self.check(generation)
        self.stopped = True


def percentile(values, rank):
    """Nearest-rank percentile in milliseconds for observable distribution."""
    if not values or not 0 < rank <= 100:
        raise ValueError("invalid percentile data")
    ordered = sorted(values)
    index = max(0, (len(ordered) * rank + 99) // 100 - 1)
    return round(ordered[index], 3)


def qualify(*, cycles=5, workers=4):
    if type(cycles) is not int or type(workers) is not int or not (1 <= cycles <= 50 and 1 <= workers <= 16):
        raise ValueError("cycles/workers outside bounded offline limits")
    # Both test actors can read both contexts: generation fences must hold
    # independently of authorization success. No DB, network, or files touched.
    def authorizer(actor, workspace, permission, target):
        pg.require(actor in ("reader", "writer") and workspace in ("A", "B")
                   and permission == "workspace:read" or
                   actor == "writer" and workspace in ("A", "B") and permission == "workspace:write",
                   "workspace_access_denied")
        pg.require(target == ("offline", 0, "synthetic"), "workspace_connection_mismatch")

    lease = SimulatedLease()
    runtime = coordinator.Coordinator(lease, authorizer=authorizer,
                                      max_jobs=workers, heartbeat_seconds=30)
    latencies = []
    failures = []
    cancellations = 0
    tracemalloc.start()
    try:
        runtime.start()
        for iteration in range(cycles):
            workspace = "A" if iteration % 2 == 0 else "B"
            token = runtime.open("writer", workspace, runtime.generation)
            ready = threading.Barrier(workers + 1, timeout=5)
            canceled = [False] * workers

            def borrow_and_cancel(i):
                try:
                    with runtime.borrow("reader", token) as operation:
                        ready.wait()
                        # close() must cancel all operations; never publish
                        # or reuse a result after observing cancellation.
                        if not operation.cancel.wait(5):
                            failures.append("job did not receive cancellation")
                            return
                        try:
                            operation.check()
                        except pg.PersistenceError as exc:
                            if str(exc) == "workspace_generation_stale":
                                canceled[i] = True
                            else:
                                failures.append("unexpected operation failure")
                        else:
                            failures.append("stale job remained authorized")
                except Exception:
                    failures.append("worker failed before cancellation")

            threads = [threading.Thread(target=borrow_and_cancel, args=(i,))
                       for i in range(workers)]
            try:
                for thread in threads:
                    thread.start()
                ready.wait()
                start = time.monotonic()
                runtime.close("writer", workspace, token.generation, timeout=5)
                latencies.append((time.monotonic() - start) * 1000)
                for thread in threads:
                    thread.join(timeout=5)
                if any(thread.is_alive() for thread in threads):
                    failures.append("job thread survived workspace close")
                cancellations += sum(canceled)
                if not all(canceled):
                    failures.append("a canceled operation was not fenced")
                if runtime._jobs or runtime._cache or runtime._bytes:
                    failures.append("job/cache resources leaked after drain")
                try:
                    with runtime.borrow("reader", token):
                        failures.append("old workspace token was accepted")
                except pg.PersistenceError as exc:
                    if str(exc) != "workspace_generation_stale":
                        failures.append("old token denied for unexpected reason")
                if failures:
                    raise AssertionError("synthetic coordinator invariant failed")
            finally:
                for thread in threads:
                    if thread.is_alive():
                        thread.join(timeout=5)
        _, peak = tracemalloc.get_traced_memory()
        return {
            "status": "OFFLINE_QUALIFIED",
            "operational_go": False,
            "lab_executed": False,
            "cycles": cycles,
            "workers_per_cycle": workers,
            "cancellations_fenced": cancellations,
            "stale_tokens_denied": cycles,
            "close_p50_ms": percentile(latencies, 50),
            "close_p95_ms": percentile(latencies, 95),
            "close_max_ms": round(max(latencies), 3),
            "peak_python_allocations_kib": round(peak / 1024, 1),
            "scope": "in_memory_coordinator_only",
            "threshold_qualification": "not_established",
        }
    finally:
        try:
            if runtime._started:
                runtime.shutdown(timeout=5)
        finally:
            tracemalloc.stop()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Cancã offline R02 coordinator smoke")
    parser.add_argument("--cycles", type=int, default=5)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args(argv)
    try:
        outcome = qualify(cycles=args.cycles, workers=args.workers)
    except (ValueError, AssertionError, pg.PersistenceError, RuntimeError,
            threading.BrokenBarrierError):
        print(json.dumps({"status": "FAILED", "operational_go": False,
                          "error_code": "r02_offline_qualification_failed"}))
        return 2
    print(json.dumps(outcome, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
