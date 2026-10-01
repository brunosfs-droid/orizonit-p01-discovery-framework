#!/usr/bin/env python3
"""Offline artifact/target tamper proof on an isolated completed-run fixture.

Copy only integrity-bound evidence, config and state; rebase the copy's bindings.
Never dispatch a runtime stage or modify evidence in the completed source run.
The copy retains source identity for provenance, not as a new executable run.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import copy
import io
import json
from pathlib import Path
import shutil
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "agent"))
import P01_Agent as agent

runtime = agent.runtime


class LabError(RuntimeError):
    pass


def require(condition, code):
    if not condition:
        raise LabError(code)


def sidecar(path):
    return path.with_suffix(path.suffix + ".sha256")


def owned(source, value):
    path = runtime._workspace_owned_path(source, value).resolve()
    require(path.is_relative_to(source), "evidence_outside_source")
    return path


def bindings(value):
    if isinstance(value, dict):
        if "path" in value:
            yield value
        for child in value.values():
            yield from bindings(child)
    elif isinstance(value, list):
        for child in value:
            yield from bindings(child)


def snapshot(paths):
    return {str(path): runtime.digest_file(path) for path in paths}


def prepare_copy(source, policy_path, destination):
    policy, _ = agent.load_policy(policy_path)
    state = agent.inspect_workspace(source, policy)
    require(agent.agent_status(source, policy_path)["status"] == "already_complete",
            "source_not_already_complete")
    paths = {source / runtime.CONFIG_REL, source / runtime.STATE_REL}
    external = state.get("source_refs", {}).get("assessment_manifest")
    external = Path(external).resolve() if external else None
    for binding in bindings(state["artifacts"]):
        path = runtime._workspace_owned_path(source, binding["path"]).resolve()
        if path == external:
            continue
        paths.add(owned(source, binding["path"]))
    jobs = {}
    for name in ("credentialed_execution_auth", "credentialed_execution_full"):
        path = owned(source, state["artifacts"][name]["path"])
        job = runtime.load_json(path)
        jobs[path] = job
        for action in job.get("actions", []):
            if action.get("execution_status") == "completed":
                paths.add(owned(source, action["target_result_file"]))
    # Fingerprint all files read/copied, source policy and preexisting journals.
    tracked = paths | {sidecar(path) for path in paths} | {policy_path}
    tracked |= set((source / "logs/agent").glob("*.json*"))
    before = snapshot(tracked)
    destination.mkdir()  # Never overwrite a previously retained test fixture.
    for directory in runtime.WORKSPACE_DIRS:
        (destination / directory).mkdir(parents=True, exist_ok=True)
    for path in paths:
        target = destination / path.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        shutil.copyfile(sidecar(path), sidecar(target))
    # Only AUTH/FULL aggregate target locators change. Original targets/bundle/
    # receipt retain their bytes. New hashes are fixture setup, before tampering.
    for path, job in jobs.items():
        job = copy.deepcopy(job)
        for action in job.get("actions", []):
            if action.get("execution_status") == "completed":
                original = owned(source, action["target_result_file"])
                action["target_result_file"] = str(destination / original.relative_to(source))
        runtime.write_json_with_sidecar(destination / path.relative_to(source), job)
    state = copy.deepcopy(state)
    state["workspace"]["root"] = str(destination)
    for binding in bindings(state["artifacts"]):
        original = runtime._workspace_owned_path(source, binding["path"]).resolve()
        if original == external:
            continue
        target = destination / original.relative_to(source)
        binding.update(path=str(target), sha256=runtime.digest_file(target))
        if "sha256_path" in binding:
            binding["sha256_path"] = str(sidecar(target))
        if "size_bytes" in binding:
            binding["size_bytes"] = target.stat().st_size
    runtime.write_json_with_sidecar(destination / runtime.STATE_REL, state)
    clone_policy = destination / "config/agent-policy.json"
    clone_policy.write_text(json.dumps({"schema_version": policy["schema_version"],
        "identity": policy["identity"], "grants": dict.fromkeys(agent.STAGES, False)}, indent=2)
        + "\n", encoding="utf-8")
    require(agent.agent_status(destination, clone_policy)["status"] == "already_complete",
            "copy_baseline_failed")
    return clone_policy, tracked, before


def cli(command, workspace, policy):
    output = io.StringIO()
    with redirect_stdout(output):
        code = agent.cli([command, "--workspace", str(workspace), "--policy", str(policy)])
    result = json.loads(output.getvalue())
    return {"command": command, "exit_code": code, "status": result.get("status"),
            "error_code": result.get("error_code")}


def tamper_case(workspace, policy, path, label):
    original = path.read_bytes()
    original_sidecar = sidecar(path).read_bytes()
    state_bytes = (workspace / runtime.STATE_REL).read_bytes()
    backup = workspace / "logs" / (label + "-original.bin")
    backup.parent.mkdir(parents=True, exist_ok=True)
    backup.write_bytes(original)
    try:
        path.write_bytes(original + b" ")
        results = [cli(command, workspace, policy) for command in ("doctor", "run-once")]
        require(all(item["exit_code"] == 2 and item["error_code"] == "workspace_integrity_failed"
                    for item in results), label + "_not_rejected")
        require((workspace / runtime.STATE_REL).read_bytes() == state_bytes,
                label + "_state_changed")
    finally:
        path.write_bytes(original)  # Never rewrite the sidecar to accept tampering.
    require(path.read_bytes() == original and sidecar(path).read_bytes() == original_sidecar,
            label + "_restore_failed")
    require(agent.agent_status(workspace, policy)["status"] == "already_complete",
            label + "_restored_status_failed")
    return {"test": label, "file": str(path.relative_to(workspace)),
            "rejections": results, "bytes_restored": True,
            "sidecar_unchanged": True, "state_unchanged": True,
            "restored_status": "already_complete"}


def proof(source, policy_path=None):
    source = Path(source).expanduser().resolve()
    policy_path = Path(policy_path).resolve() if policy_path else source / "config/agent-policy.json"
    destination = source.parent / ("P01LAB-AGENT-ARTIFACT-NEG-" + uuid.uuid4().hex[:12])
    dispatch_calls = 0
    original_dispatch = agent._dispatch

    def never_dispatch(*args, **kwargs):
        nonlocal dispatch_calls
        dispatch_calls += 1
        raise LabError("unexpected_dispatch")

    # Keep a stable source checkpoint through copy/proof/fingerprint comparison.
    with agent.workspace_lock(source):
        agent._dispatch = never_dispatch
        try:
            policy, tracked, before = prepare_copy(source, policy_path, destination)
            state = runtime._load_state(destination)
            artifact = owned(destination, state["artifacts"]["credentialed_execution_full"]["path"])
            auth_job = owned(destination, state["artifacts"]["credentialed_execution_auth"]["path"])
            job = runtime.load_json(auth_job)
            completed = [a for a in job.get("actions", []) if a.get("execution_status") == "completed"]
            require(bool(completed), "no_completed_auth_target")
            target = owned(destination, completed[0]["target_result_file"])
            # AUTH targets are not export inputs. Test their aggregate binding,
            # using the same nested integrity gate applied to FULL targets.
            # Ensure target is tested via the aggregate binding, independently
            # of any top-level artifact binding to that same file.
            top_paths = {str(Path(b["path"]).resolve()) for b in bindings(state["artifacts"])}
            require(str(target) not in top_paths, "target_also_top_level_artifact")
            results = [tamper_case(destination, policy, artifact, "artifact"),
                       tamper_case(destination, policy, target, "target")]
            require(dispatch_calls == 0, "runtime_dispatch_attempted")
            require(snapshot(tracked) == before, "source_changed")
            require(set((source / "logs/agent").glob("*.json*")) <= tracked,
                    "source_journals_changed")
            result = {"status": "ARTIFACT/TARGET TAMPER PASS", "tests": results,
                "runtime_dispatch_calls": 0, "all_grants_denied": True,
                "source_unchanged": True, "source_files_checked": len(tracked),
                "negative_workspace": str(destination),
                "fixture_identity": "retained_from_source_for_offline_validation_only"}
            (destination / "logs/tamper-proof.json").write_text(
                json.dumps(result, indent=2) + "\n", encoding="utf-8")
            return result
        finally:
            agent._dispatch = original_dispatch


def self_test():
    # Reuse the established offline complete-run fixture, never a live executor.
    sys.path.insert(0, str(ROOT / "tests"))
    from test_optional_agent import AgentTests
    case = AgentTests()
    case.setUp()
    try:
        try:
            proof(case.workspace, case.policy_path)
        except LabError as exc:
            require(str(exc) == "source_not_already_complete", "incomplete_guard_failed")
        else:
            raise LabError("incomplete_source_accepted")
        case.test_actual_auth_full_resolver_export_upload_gates_and_complete_resume()
        return proof(case.workspace, case.policy_path)
    finally:
        case.doCleanups()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--workspace", help="Completed source workspace; read under lock")
    modes.add_argument("--self-test", action="store_true", help="Offline CI fixture")
    parser.add_argument("--policy", help="Source policy path (default: config/agent-policy.json)")
    args = parser.parse_args(argv)
    try:
        result = self_test() if args.self_test else proof(args.workspace, args.policy)
        print(json.dumps(result, indent=2))
        return 0
    except LabError as exc:
        print(json.dumps({"status": "ARTIFACT/TARGET TAMPER FAILED", "error_code": str(exc)}))
        return 2
    except Exception:
        # Fixed failure marker; preserve fixture/backups locally for inspection.
        print(json.dumps({"status": "ARTIFACT/TARGET TAMPER FAILED"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
