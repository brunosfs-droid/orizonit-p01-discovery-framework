#!/usr/bin/env python3
"""Cancã optional agent v0.5f.0: policy gate around the canonical runtime."""
from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import re
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime"))
import P01_Discovery_Node as runtime
from P01_Workspace_Lock import WorkspaceBusy, workspace_lock

VERSION = "0.5f.0"
STAGES = ("discovery", "planning", "dry_run", "auth_only", "full", "resolver", "export", "upload")
ACTION_STAGE = dict(zip((
    "run_network_discovery", "run_credential_plan", "run_credentialed_execution_dry_run",
    "run_credentialed_execution_auth_only", "run_credentialed_execution_full",
    "run_asset_resolver", "export", "upload_or_copy_bundle_offline",
), STAGES))


class AgentError(RuntimeError):
    """Fixed public code; never include user input or a raw exception."""


def _reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AgentError("invalid_policy")
        result[key] = value
    return result


def _keys(value, allowed, required=()):
    if not isinstance(value, dict) or set(value) - set(allowed) or set(required) - set(value):
        raise AgentError("invalid_policy")


def _integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise AgentError("invalid_policy")


def load_policy(path):
    """Strict built-in validation equivalent to the versioned JSON schema."""
    try:
        raw = Path(path).read_bytes()
        if len(raw) > 65536:
            raise AgentError("invalid_policy")
        policy = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_reject_duplicates,
                            parse_constant=lambda _: (_ for _ in ()).throw(AgentError("invalid_policy")))
        _keys(policy, ("schema_version", "identity", "grants", "discovery", "limits", "schedule"),
              ("schema_version", "identity"))
        if policy["schema_version"] != "0.5f":
            raise AgentError("invalid_policy")
        identity = policy["identity"]
        _keys(identity, ("assessment_id", "run_id", "node_id"), ("assessment_id", "run_id", "node_id"))
        for value in identity.values():
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value):
                raise AgentError("invalid_policy")
        grants = policy.get("grants", {})
        _keys(grants, STAGES)
        if any(type(value) is not bool for value in grants.values()):
            raise AgentError("invalid_policy")
        discovery = policy.get("discovery", {})
        _keys(discovery, ("targets",))
        targets = discovery.get("targets", [])
        if not isinstance(targets, list) or len(targets) > 128:
            raise AgentError("invalid_policy")
        for value in targets:
            if not isinstance(value, str) or ipaddress.ip_network(value, strict=False).version != 4:
                raise AgentError("invalid_policy")
        if grants.get("discovery", False) and not targets:
            raise AgentError("invalid_policy")
        limits = policy.get("limits", {})
        _keys(limits, ("max_hosts", "max_actions"))
        _integer(limits.get("max_hosts", 2048), 1, 2048)
        _integer(limits.get("max_actions", 25), 1, 250)
        if "schedule" in policy:
            schedule = policy["schedule"]
            _keys(schedule, ("kind", "interval_seconds"), ("kind", "interval_seconds"))
            if schedule["kind"] != "interval":
                raise AgentError("invalid_policy")
            _integer(schedule["interval_seconds"], 60, 86400)
        # Exact properties prevent persisting secrets, key paths or provider refs.
        runtime.assert_no_secret_material(policy)
        return policy, runtime.digest_bytes(raw)
    except AgentError:
        raise
    except Exception:
        raise AgentError("invalid_policy") from None


def _artifact_integrity(workspace, value):
    if isinstance(value, dict):
        if "path" in value:
            path = runtime._workspace_owned_path(workspace, str(value["path"])).resolve()
            if not path.is_relative_to(workspace):
                raise AgentError("workspace_integrity_failed")
            if (not path.is_file() or not value.get("sha256")
                    or runtime.digest_file(path) != value["sha256"]
                    or not runtime.verify_sidecar(path)):
                raise AgentError("workspace_integrity_failed")
        for child in value.values():
            _artifact_integrity(workspace, child)
    elif isinstance(value, list):
        for child in value:
            _artifact_integrity(workspace, child)


def inspect_workspace(workspace, policy):
    try:
        state = runtime._load_state(workspace)
        if not runtime.verify_sidecar(workspace / runtime.CONFIG_REL):
            raise AgentError("workspace_integrity_failed")
        config = runtime.load_json(workspace / runtime.CONFIG_REL)
        runtime.assert_no_secret_material(config)
        for field, value in policy["identity"].items():
            if state.get(field) != value or config.get(field) != value:
                raise AgentError("workspace_identity_mismatch")
        if config.get("schema_version") != runtime.SCHEMA_VERSION or config.get("source_refs") != state.get("source_refs"):
            raise AgentError("workspace_integrity_failed")
        if Path(state["workspace"]["root"]).resolve() != workspace:
            raise AgentError("workspace_integrity_failed")
        steps = state["steps"]
        allowed = {
            "initialized": {"completed"},
            "network_discovery": {"pending", "completed", "failed", "running"},
            "credential_plan": {"pending", "completed", "external_required", "failed", "running"},
            "credentialed_execution": {"pending", "external_required", "preview_completed", "auth_validated", "full_completed", "failed", "running"},
            "asset_resolver": {"pending", "completed", "external_required", "failed", "running"},
            "evidence_bundle": {"pending", "completed", "failed", "running"},
            "upload": {"pending", "completed", "failed", "running"},
        }
        for name, statuses in allowed.items():
            if steps[name].get("status") not in statuses:
                raise AgentError("workspace_integrity_failed")
        artifacts = state["artifacts"]
        if not isinstance(artifacts, dict):
            raise AgentError("workspace_integrity_failed")
        required = []
        for step, artifact in (("network_discovery", "network_discovery"), ("credential_plan", "credential_plan"),
                               ("asset_resolver", "asset_resolver"), ("evidence_bundle", "evidence_bundle"),
                               ("upload", "upload_receipt")):
            if steps[step]["status"] == "completed":
                required.append(artifact)
        execution = steps["credentialed_execution"]["status"]
        for checkpoint, names in (
            ("preview_completed", ("credentialed_execution_preview",)),
            ("auth_validated", ("credentialed_execution_preview", "credentialed_execution_auth")),
            ("full_completed", ("credentialed_execution_preview", "credentialed_execution_auth", "credentialed_execution_full")),
        ):
            if execution == checkpoint:
                required.extend(names)
        if any(not isinstance(artifacts.get(name), dict) or "path" not in artifacts[name] for name in required):
            raise AgentError("workspace_integrity_failed")
        # The canonical export records its external, non-secret manifest input.
        # Permit that one exact source binding; all evidence remains workspace-owned.
        for name, info in artifacts.items():
            if name != "export_inputs":
                _artifact_integrity(workspace, info)
                continue
            for input_name, binding in info.items():
                if input_name != "assessment_manifest":
                    _artifact_integrity(workspace, binding)
                    continue
                source = state.get("source_refs", {}).get("assessment_manifest")
                path = Path(binding["path"]).resolve()
                if not source or path != Path(source).resolve() or not path.is_file() or runtime.digest_file(path) != binding.get("sha256"):
                    raise AgentError("workspace_integrity_failed")
        # Aggregate jobs also bind per-target AUTH/FULL evidence outside artifacts.
        for name in ("credentialed_execution_auth", "credentialed_execution_full"):
            if name not in artifacts:
                continue
            info = artifacts[name]
            job = runtime.load_json(runtime._workspace_owned_path(workspace, info["path"]))
            count = 0
            for action in job.get("actions", []):
                if action.get("execution_status") == "completed":
                    _artifact_integrity(workspace, {"path": action["target_result_file"],
                                                  "sha256": action["target_result_sha256"]})
                    count += 1
            if count != info.get("target_evidence_count"):
                raise AgentError("workspace_integrity_failed")
        # A later completed checkpoint cannot conceal an earlier unfinished step.
        sequence = [steps[n]["status"] == "completed" for n in ("network_discovery", "credential_plan")]
        sequence += [execution == "full_completed"]
        sequence += [steps[n]["status"] == "completed" for n in ("asset_resolver", "evidence_bundle", "upload")]
        if any(sequence[i] and not all(sequence[:i]) for i in range(len(sequence))):
            raise AgentError("workspace_integrity_failed")
        if execution in {"preview_completed", "auth_validated", "full_completed"} and not all(sequence[:2]):
            raise AgentError("workspace_integrity_failed")
        return state
    except AgentError:
        raise
    except Exception:
        raise AgentError("workspace_integrity_failed") from None


def _decision(state, policy, workspace=None):
    if workspace is not None:
        # Upload can be interrupted after a POST but before its runtime checkpoint.
        # Persisted dispatch intent blocks replay even if state remains pending.
        for path in (workspace / "logs" / "agent").glob("*.json"):
            if not runtime.verify_sidecar(path):
                raise AgentError("journal_integrity_failed")
            try:
                journal = runtime.load_json(path)
                if journal.get("schema_version") != "0.5f":
                    raise AgentError("journal_integrity_failed")
                if journal.get("status") == "running":
                    return "review_required", None
            except AgentError:
                raise
            except Exception:
                raise AgentError("journal_integrity_failed") from None
    if any(step["status"] in {"failed", "running"} for step in state["steps"].values()):
        return "review_required", None
    action = runtime.next_action(state)
    if action == "complete":
        return "already_complete", None
    stage = ACTION_STAGE.get(action)
    if stage is None:
        return "review_required", None
    return ("ready" if policy.get("grants", {}).get(stage, False) else "policy_denied"), stage


def _noninteractive_profiles(state):
    """No unattended prompt fallback, even if an unrelated profile uses prompt."""
    try:
        credential_root = str(ROOT / "credential_manager")
        if credential_root not in sys.path:
            sys.path.insert(0, credential_root)
        from P01_Credential_Manager import load_profiles
        profiles = load_profiles(Path(state["source_refs"]["credential_profiles"]))
        for profile in profiles["profiles"]:
            for ref in profile.get("secret_refs", {}).values():
                if not str(ref).startswith(("env://", "wincred://")):
                    raise AgentError("interactive_provider_denied")
    except AgentError:
        raise
    except Exception:
        raise AgentError("credential_configuration_invalid") from None


def _dispatch(workspace, state, policy, stage, transport):
    limits = policy.get("limits", {})
    actions = limits.get("max_actions", 25)
    if stage == "discovery":
        return runtime.run_network_discovery(workspace, policy["discovery"]["targets"], [],
            ack_authorized_scan=True, profile="safe", max_hosts=limits.get("max_hosts", 2048), disable_ssdp=True)
    if stage == "planning":
        return runtime.run_credential_plan(workspace)
    if stage == "dry_run":
        return runtime.run_credentialed_execution_dry_run(workspace, max_actions=actions)
    if stage in {"auth_only", "full"}:
        _noninteractive_profiles(state)
        function = runtime.run_credentialed_execution_auth_only if stage == "auth_only" else runtime.run_credentialed_execution_full
        return function(workspace, ack_authorized_access=True, max_actions=actions, ssh_host_key_policy="strict")
    if stage == "resolver":
        return runtime.run_asset_resolver(workspace)
    if stage == "export":
        return runtime.export_bundle(workspace)
    if stage == "upload":
        if not isinstance(transport, dict) or set(transport) != {"server_url", "ca_cert", "client_cert", "client_key"} or not all(transport.values()):
            raise AgentError("transport_required")
        return runtime.upload_bundle(workspace, **transport)
    raise AgentError("stage_invalid")


def agent_status(workspace, policy_path):
    workspace = Path(workspace).expanduser().resolve()
    policy, digest = load_policy(policy_path)
    with workspace_lock(workspace):
        state = inspect_workspace(workspace, policy)
        status, stage = _decision(state, policy, workspace)
    return {"agent_version": VERSION, "status": status, "next_stage": stage,
            "policy_sha256": digest, "network_activity_performed": False,
            "secret_resolution_performed": False, "authentication_attempts_performed": False}


def doctor(workspace, policy_path):
    result = agent_status(workspace, policy_path)
    checks = runtime.doctor(Path(workspace))
    result.update(ready=checks["ready"], checks=checks["checks"], schedule_installed=False, os_service_installed=False)
    return result


def run_once(workspace, policy_path, transport=None):
    workspace = Path(workspace).expanduser().resolve()
    # A busy invocation cannot safely write to another invocation's workspace.
    with workspace_lock(workspace):
        journal = {"schema_version": "0.5f", "agent_version": VERSION,
                   "invocation_id": str(uuid.uuid4()), "started_at_utc": runtime.utc_now_iso(),
                   "status": "failed", "stage": None, "policy_sha256": None}
        error = None
        try:
            policy, digest = load_policy(policy_path)
            journal["policy_sha256"] = digest
            state = inspect_workspace(workspace, policy)
            status, stage = _decision(state, policy, workspace)
            journal.update(status=status, stage=stage)
            if status == "ready":
                started = dict(journal, status="running")
                path = workspace / "logs" / "agent" / (journal["invocation_id"] + ".json")
                runtime.write_json_with_sidecar(path, started)
                result = _dispatch(workspace, state, policy, stage, transport)
                # Never journal result text or exception details; they may contain secrets.
                updated = inspect_workspace(workspace, policy)
                follow, _ = _decision(updated, policy)
                journal["status"] = "review_required" if follow == "review_required" else "advanced"
                if not isinstance(result, dict):
                    raise AgentError("runtime_failed")
        except AgentError as exc:
            error = str(exc)
            journal.update(status="failed", error_code=error)
        except Exception:
            error = "runtime_failed"
            journal.update(status="failed", error_code=error)
        journal["finished_at_utc"] = runtime.utc_now_iso()
        path = workspace / "logs" / "agent" / (journal["invocation_id"] + ".json")
        runtime.write_json_with_sidecar(path, journal)
        if error:
            raise AgentError(error)
        return dict(journal, journal_path=str(path))


def cli(argv=None):
    parser = argparse.ArgumentParser(description=f"Cancã Optional Agent v{VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("doctor", "status", "run-once"):
        command = sub.add_parser(name)
        command.add_argument("--workspace", required=True)
        command.add_argument("--policy", required=True)
        if name == "run-once":
            for flag in ("server-url", "ca-cert", "client-cert", "client-key"):
                command.add_argument("--" + flag)
    validate = sub.add_parser("validate-policy")
    validate.add_argument("--policy", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "validate-policy":
            _, digest = load_policy(args.policy)
            result = {"status": "valid", "policy_sha256": digest}
        elif args.command == "doctor":
            result = doctor(args.workspace, args.policy)
        elif args.command == "status":
            result = agent_status(args.workspace, args.policy)
        else:
            transport = {"server_url": args.server_url, "ca_cert": Path(args.ca_cert) if args.ca_cert else None,
                         "client_cert": Path(args.client_cert) if args.client_cert else None,
                         "client_key": Path(args.client_key) if args.client_key else None}
            result = run_once(args.workspace, args.policy, transport)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        if result.get("ready") is False:
            return 2
        return 3 if result.get("status") in {"policy_denied", "review_required"} else 0
    except (AgentError, WorkspaceBusy) as exc:
        print(json.dumps({"status": "failed", "error_code": str(exc)}))
        return 2
    except Exception:
        print(json.dumps({"status": "failed", "error_code": "agent_failed"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(cli())
