#!/usr/bin/env python3
"""Offline LAB proof of crash intent/review gating and journal sanitization.

Only the child dispatch hook is replaced: it exits after the real agent writes
its running intent, before calling a runtime stage. Production files are not
patched. Evidence and intent are retained in the isolated negative workspace.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
from datetime import datetime
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "agent"))
import P01_Agent as agent

runtime = agent.runtime
CRASH_EXIT = 71
REQUIRED = {"schema_version", "agent_version", "invocation_id", "started_at_utc",
            "status", "stage", "policy_sha256"}
ALLOWED = REQUIRED | {"finished_at_utc", "error_code"}
STATUSES = {"running", "advanced", "already_complete", "policy_denied", "review_required", "failed"}
ERRORS = {"invalid_policy", "workspace_integrity_failed", "workspace_identity_mismatch",
          "interactive_provider_denied", "credential_configuration_invalid", "transport_required",
          "stage_invalid", "runtime_failed", "journal_integrity_failed"}


class LabError(RuntimeError):
    pass


def require(condition, code):
    if not condition:
        raise LabError(code)


def write_policy(path, policy):
    path.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")


def read_journal(path):
    require(runtime.verify_sidecar(path), "journal_hash_failed")
    try:
        doc = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=agent._reject_duplicates)
        require(isinstance(doc, dict) and REQUIRED <= doc.keys() <= ALLOWED, "journal_contract_failed")
        require(doc["schema_version"] == "0.5f" and doc["agent_version"] == "0.5f.0", "journal_contract_failed")
        identifier = str(uuid.UUID(doc["invocation_id"]))
        require(identifier == doc["invocation_id"] == path.stem, "journal_contract_failed")
        require(doc["status"] in STATUSES and doc["stage"] in (None, *agent.STAGES), "journal_contract_failed")
        digest = doc["policy_sha256"]
        require(digest is None or (isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)),
                "journal_contract_failed")
        for key in ("started_at_utc", "finished_at_utc"):
            if key not in doc:
                continue
            value = doc[key]
            require(isinstance(value, str) and re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)", value),
                "journal_contract_failed")
            require(datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None,
                    "journal_contract_failed")
        if "error_code" in doc:
            require(doc["error_code"] in ERRORS, "journal_contract_failed")
        return doc
    except LabError:
        raise
    except Exception:
        raise LabError("journal_contract_failed") from None


def audit(workspace):
    require(workspace.is_dir() and (workspace / "logs" / "agent").is_dir(), "journal_directory_missing")
    with agent.workspace_lock(workspace):
        paths = sorted((workspace / "logs" / "agent").glob("*.json"))
        require(bool(paths), "journal_directory_empty")
        for path in paths:
            read_journal(path)
    # Flat fields have only fixed enums, UUIDs, UTC timestamps and SHA256 values.
    # No arbitrary result/message, secret/provider reference or path is allowed.
    return {"status": "JOURNAL AUDIT PASS", "journals_checked": len(paths),
            "sha256_valid": True, "contract_fields_valid": True}


def preflight(workspace, discovery_granted=False):
    require(workspace.is_dir(), "negative_workspace_missing")
    policy_path = workspace / "config" / "agent-policy.json"
    policy, _ = agent.load_policy(policy_path)
    with agent.workspace_lock(workspace):
        state = agent.inspect_workspace(workspace, policy)
        require(state["run_id"].startswith("P01LAB-AGENT-NEG-"), "negative_run_required")
        require(not state["artifacts"] and all(
            step["status"] == ("completed" if name == "initialized" else "pending")
            for name, step in state["steps"].items()), "negative_run_not_fresh")
        require(all(policy.get("grants", {}).get(stage, False) ==
                    (discovery_granted and stage == "discovery") for stage in agent.STAGES),
                "unexpected_grants")
        status, stage = agent._decision(state, policy, workspace)
        require((status, stage) == (("ready" if discovery_granted else "policy_denied"), "discovery"),
                "negative_run_not_fresh")
    return policy_path, policy


def crash_child(workspace):
    policy_path, _ = preflight(workspace, discovery_granted=True)

    def stop_before_runtime(*_args, **_kwargs):
        print("LAB CRASH BEFORE RUNTIME DISPATCH", flush=True)
        os._exit(CRASH_EXIT)

    agent._dispatch = stop_before_runtime
    agent.run_once(workspace, policy_path)
    raise LabError("crash_hook_not_reached")


def interruption(workspace, target):
    require(ipaddress.ip_network(target, strict=False).version == 4, "ipv4_target_required")
    policy_path, policy = preflight(workspace)
    state_path = workspace / "state" / "run-state.json"
    state_before = runtime.digest_file(state_path)
    config_path = workspace / "config" / "runtime.json"
    config_before = runtime.digest_file(config_path)
    original_policy = policy_path.read_bytes()
    backup = workspace / "logs" / "policy-before-interruption.json"
    require(not backup.exists(), "interruption_already_prepared")
    backup.write_bytes(original_policy)
    policy["grants"] = {stage: stage == "discovery" for stage in agent.STAGES}
    policy["discovery"] = {"targets": [target]}
    dispatch_attempts = []
    original_dispatch = agent._dispatch

    def prohibit_dispatch(*_args, **_kwargs):
        dispatch_attempts.append(True)
        raise RuntimeError("LAB dispatch guard")

    try:
        write_policy(policy_path, policy)
        child = subprocess.run([sys.executable, str(Path(__file__).resolve()),
                                "--workspace", str(workspace), "--crash-child"],
                               cwd=ROOT, capture_output=True, text=True, timeout=30)
        require(child.returncode == CRASH_EXIT and "LAB CRASH BEFORE RUNTIME DISPATCH" in child.stdout,
                "controlled_crash_failed")
        # Acquiring the retained lock proves native process exit released it.
        with agent.workspace_lock(workspace):
            journals = [read_journal(path) for path in (workspace / "logs" / "agent").glob("*.json")]
            require(sum(doc["status"] == "running" for doc in journals) == 1, "running_intent_missing")
            status = agent.agent_status(workspace, policy_path)
            require(status["status"] == "review_required", "review_gate_failed")
            agent._dispatch = prohibit_dispatch
            repeats = []
            for _ in range(2):
                output = io.StringIO()
                with redirect_stdout(output):
                    code = agent.cli(["run-once", "--workspace", str(workspace), "--policy", str(policy_path)])
                result = json.loads(output.getvalue())
                require(code == 3 and result.get("status") == "review_required", "review_gate_failed")
                repeats.append({"status": result["status"], "exit": code})
            require(not dispatch_attempts, "unexpected_runtime_dispatch")
            require(runtime.digest_file(state_path) == state_before and runtime.digest_file(config_path) == config_before,
                    "workspace_changed")
    finally:
        agent._dispatch = original_dispatch
        policy_path.write_bytes(original_policy)
    require(policy_path.read_bytes() == original_policy, "policy_restore_failed")
    require(agent.agent_status(workspace, policy_path)["status"] == "review_required", "review_gate_failed")
    audit_result = audit(workspace)
    return {"status": "INTERRUPTION PASS", "child_exit": CRASH_EXIT,
            "crash_boundary": "running_intent_before_runtime_dispatch",
            "review_repeats": repeats, "runtime_dispatch_calls_after_crash": len(dispatch_attempts),
            "state_unchanged": True, "config_unchanged": True, "policy_restored": True,
            "lock_released_after_process_exit": True, "running_intent_preserved": True,
            "journal_audit": audit_result, "negative_workspace": str(workspace)}


def self_test(target):
    root = Path(tempfile.mkdtemp(prefix="canca-agent-interruption-"))
    run_id = "P01LAB-AGENT-NEG-CI-" + uuid.uuid4().hex[:12]
    workspace = Path(runtime.init_workspace(root, "P01CI", run_id, "P01-CI")["workspace"])
    write_policy(workspace / "config" / "agent-policy.json", {
        "schema_version": "0.5f", "identity": {"assessment_id": "P01CI", "run_id": run_id, "node_id": "P01-CI"},
        "grants": {stage: False for stage in agent.STAGES}})
    result = interruption(workspace, target)
    path = next((workspace / "logs" / "agent").glob("*.json"))
    original = path.read_bytes()
    sidecar = Path(str(path) + ".sha256")
    original_sidecar = sidecar.read_bytes()
    doc = read_journal(path)
    doc["provider_reference"] = "LAB_SENTINEL_DO_NOT_PRINT"
    try:
        # A hash-valid fixture with an extra field must fail content auditing.
        runtime.write_json_with_sidecar(path, doc)
        try:
            audit(workspace)
        except LabError as exc:
            require(str(exc) == "journal_contract_failed", "audit_negative_fixture_failed")
        else:
            raise LabError("audit_negative_fixture_failed")
    finally:
        path.write_bytes(original)
        sidecar.write_bytes(original_sidecar)
    result["audit_negative_fixture_rejected"] = True
    audit(workspace)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--workspace", type=Path)
    mode.add_argument("--self-test", action="store_true")
    parser.add_argument("--target", default="127.0.0.1/32")
    parser.add_argument("--audit-only", action="store_true")
    parser.add_argument("--crash-child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if args.self_test:
            require(not args.audit_only and not args.crash_child, "invalid_lab_mode")
            result = self_test(args.target)
        else:
            workspace = args.workspace.expanduser().resolve()
            if args.crash_child:
                require(not args.audit_only, "invalid_lab_mode")
                crash_child(workspace)
                return 2
            result = audit(workspace) if args.audit_only else interruption(workspace, args.target)
        print(json.dumps(result, indent=2))
        return 0
    except LabError as exc:
        print(json.dumps({"status": "failed", "error_code": str(exc)}))
        return 2
    except Exception:
        print(json.dumps({"status": "failed", "error_code": "lab_helper_failed"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
