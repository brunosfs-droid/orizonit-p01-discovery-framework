"""v0.5f.3 bounded, opt-in fixed-delay scheduler around canonical run_once."""
from __future__ import annotations
import json
from pathlib import Path
import uuid
from datetime import datetime

import P01_Agent as agent

VERSION = "0.5f.3"
REASONS = {"in_progress", "stopped", "max_invocations", "already_complete", "review_required",
           "failed", "schedule_disabled", "config_changed"}
STATUSES = {"running", "completed", "halted", "stopped"}
RESULTS = {None, "advanced", "policy_denied", "review_required", "already_complete", "failed"}
ERRORS = {"invalid_policy", "workspace_integrity_failed", "workspace_identity_mismatch",
          "interactive_provider_denied", "credential_configuration_invalid", "transport_required",
          "stage_invalid", "runtime_failed", "journal_integrity_failed", "workspace_busy",
          "service_config_invalid", "service_failed", "scheduler_integrity_failed", "schedule_required",
          "scheduler_config_invalid"}
FIELDS = {"schema_version", "scheduler_version", "session_id", "started_at_utc", "finished_at_utc",
          "assessment_id", "run_id", "node_id", "status", "reason", "invocations", "max_invocations",
          "last_status", "last_stage", "error_code", "config_sha256"}


class SchedulerError(RuntimeError):
    pass


def require(ok, code):
    if not ok:
        raise SchedulerError(code)


def unique(pairs):
    doc = {}
    for key, value in pairs:
        require(key not in doc, "scheduler_config_invalid")
        doc[key] = value
    return doc


def read_doc(path):
    raw = Path(path).read_bytes()
    require(len(raw) <= 16384, "scheduler_config_invalid")
    return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique), raw


def validate_config(doc, legacy):
    require(isinstance(doc, dict), "scheduler_config_invalid")
    base = {"schema_version", "workspace", "policy"}
    version = doc.get("schema_version")
    require(version in {legacy, VERSION}, "scheduler_config_invalid")
    require(base <= set(doc) and set(doc) <= base | {"scheduler"}, "scheduler_config_invalid")
    if version == legacy:
        require(set(doc) == base, "scheduler_config_invalid")
    settings = doc.get("scheduler", {"enabled": False, "max_invocations": 1})
    require(isinstance(settings, dict) and set(settings) == {"enabled", "max_invocations"}
            and type(settings["enabled"]) is bool and type(settings["max_invocations"]) is int
            and 1 <= settings["max_invocations"] <= 10000, "scheduler_config_invalid")
    return settings


def settings(path):
    doc, _ = read_doc(path)
    # Host-specific validation handles legacy versions and path semantics.
    return doc.get("scheduler", {"enabled": False, "max_invocations": 1})


def public_error(exc):
    code = str(exc)
    return code if code in ERRORS else "service_failed"


def audit(workspace):
    """Strict flat journal contract, filename, UTC, SHA256 and identity."""
    count, running, blocking = 0, False, False
    state = agent.runtime._load_state(workspace)
    for path in (Path(workspace) / "logs/scheduler").glob("*.json"):
        try:
            require(agent.runtime.verify_sidecar(path), "scheduler_integrity_failed")
            doc = json.loads(path.read_text(), object_pairs_hook=unique)
            require(set(doc) == FIELDS and doc["schema_version"] == VERSION
                    and doc["scheduler_version"] == VERSION, "scheduler_integrity_failed")
            require(str(uuid.UUID(doc["session_id"])) == path.stem, "scheduler_integrity_failed")
            for key in ("assessment_id", "run_id", "node_id"):
                require(doc[key] == state[key], "scheduler_integrity_failed")
            require(doc["status"] in STATUSES and doc["reason"] in REASONS
                    and doc["last_status"] in RESULTS
                    and (doc["last_stage"] is None or doc["last_stage"] in agent.STAGES)
                    and (doc["error_code"] is None or doc["error_code"] in ERRORS), "scheduler_integrity_failed")
            require(type(doc["max_invocations"]) is int and 1 <= doc["max_invocations"] <= 10000
                    and type(doc["invocations"]) is int and 0 <= doc["invocations"] <= doc["max_invocations"],
                    "scheduler_integrity_failed")
            require(isinstance(doc["config_sha256"], str) and len(doc["config_sha256"]) == 64
                    and all(c in "0123456789abcdef" for c in doc["config_sha256"]), "scheduler_integrity_failed")
            require((doc["status"] == "running") == (doc["finished_at_utc"] is None), "scheduler_integrity_failed")
            for value in (doc["started_at_utc"], doc["finished_at_utc"]):
                if value is not None:
                    require(isinstance(value, str) and datetime.fromisoformat(value).utcoffset().total_seconds() == 0,
                            "scheduler_integrity_failed")
            require(doc["started_at_utc"] is not None, "scheduler_integrity_failed")
            require((doc["status"] == "running") == (doc["reason"] == "in_progress"), "scheduler_integrity_failed")
            allowed = {"running": {"in_progress"}, "completed": {"max_invocations", "already_complete"},
                       "halted": {"review_required", "failed", "config_changed"},
                       "stopped": {"stopped", "schedule_disabled"}}
            require(doc["reason"] in allowed[doc["status"]], "scheduler_integrity_failed")
            if doc["finished_at_utc"] is not None:
                require(datetime.fromisoformat(doc["finished_at_utc"]) >= datetime.fromisoformat(doc["started_at_utc"]),
                        "scheduler_integrity_failed")
            running |= doc["status"] == "running"
            blocking |= doc["status"] in {"running", "halted"}
            count += 1
        except Exception:
            raise SchedulerError("scheduler_integrity_failed") from None
    return {"status": "SCHEDULER AUDIT PASS", "sessions_checked": count,
            "sha256_valid": True, "contract_fields_valid": True, "unfinished_session": running, "review_required": blocking}


def run(config, stop, load_config):
    """No catch-up, overlap, transport or retry. A crashed session blocks restart."""
    output = {"status": "stopped", "reason": "stopped", "invocations": 0,
              "scheduler_version": VERSION, "error_code": None}
    if stop.is_set():
        return output
    session, workspace = None, None
    try:
        workspace, policy_path = load_config(config)
        doc, raw = read_doc(config)
        cfg = validate_config(doc, "unsupported")
        require(cfg["enabled"], "scheduler_config_invalid")
        budget = cfg["max_invocations"]
        digest = agent.runtime.digest_bytes(raw)
        with agent.workspace_lock(workspace):
            policy, _ = agent.load_policy(policy_path)
            state = agent.inspect_workspace(workspace, policy)
            require("schedule" in policy, "schedule_required")
            old = audit(workspace)
            if stop.is_set():
                return output
            session = {"schema_version": VERSION, "scheduler_version": VERSION,
                "session_id": str(uuid.uuid4()), "started_at_utc": agent.runtime.utc_now_iso(),
                "finished_at_utc": None, "status": "running", "reason": "in_progress",
                "invocations": 0, "max_invocations": budget, "last_status": None,
                "last_stage": None, "error_code": None, "config_sha256": digest,
                **{key: state[key] for key in ("assessment_id", "run_id", "node_id")}}
            path = workspace / "logs/scheduler" / (session["session_id"] + ".json")
            if old["review_required"]:
                session.update(status="halted", reason="review_required", finished_at_utc=agent.runtime.utc_now_iso())
                agent.runtime.write_json_with_sidecar(path, session)
                return summary(session)
            agent.runtime.write_json_with_sidecar(path, session)  # Durable intent before the first tick.
        while True:
            with agent.workspace_lock(workspace):
                new_workspace, new_policy = load_config(config)
                current_doc, _ = read_doc(config)
                current = validate_config(current_doc, "unsupported")
                if (new_workspace, new_policy) != (workspace, policy_path) or current["max_invocations"] != budget:
                    session.update(status="halted", reason="config_changed")
                    break
                if stop.is_set():
                    session.update(status="stopped", reason="stopped")
                    break
                if not current["enabled"]:
                    session.update(status="stopped", reason="schedule_disabled")
                    break
                policy, _ = agent.load_policy(policy_path)
                agent.inspect_workspace(workspace, policy)
                require("schedule" in policy, "schedule_required")
                interval = policy["schedule"]["interval_seconds"]
                # Count attempts before invocation, including an invocation that raises.
                session["invocations"] += 1
                agent.runtime.write_json_with_sidecar(path, session)
                result = agent.run_once(workspace, policy_path)  # Shared reentrant lock, no transport.
                require(result.get("status") in RESULTS - {None, "failed"}
                        and (result.get("stage") is None or result["stage"] in agent.STAGES), "service_failed")
                session.update(last_status=result["status"], last_stage=result.get("stage"))
                if result["status"] in {"review_required", "already_complete"}:
                    session.update(status="halted" if result["status"] == "review_required" else "completed",
                                   reason=result["status"])
                    break
                if session["invocations"] >= budget:
                    session.update(status="completed", reason="max_invocations")
                    break
                agent.runtime.write_json_with_sidecar(path, session)
            # Fixed delay from completion, monotonic Event.wait; no missed-tick replay.
            if stop.wait(interval):
                session.update(status="stopped", reason="stopped")
                break
        session["finished_at_utc"] = agent.runtime.utc_now_iso()
        with agent.workspace_lock(workspace):
            agent.runtime.write_json_with_sidecar(path, session)
        return summary(session)
    except Exception as exc:
        code = public_error(exc)
        if session is not None:
            session.update(status="halted", reason="failed", last_status="failed", error_code=code,
                           finished_at_utc=agent.runtime.utc_now_iso())
            try:
                with agent.workspace_lock(workspace):
                    agent.runtime.write_json_with_sidecar(path, session)
            except Exception:
                pass  # Retain running intent if the lock/write cannot be acquired; never replay.
            return summary(session)
        return dict(output, status="halted", reason="failed", error_code=code)


def summary(session):
    return {key: session[key] for key in ("scheduler_version", "status", "reason", "invocations", "error_code")}
