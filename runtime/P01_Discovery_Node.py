#!/usr/bin/env python3
"""Cancã / Orizon IT Portable Discovery Node Runtime v0.5e.6.

Portable-first operator workflow foundation.

v0.5e.6 closes the connected-upload runtime gate after workspace-driven bundle
creation. A live upload still requires explicit mTLS transport inputs, while a
completed upload can be resumed/status-checked with workspace identity only.

Security properties:
- no plaintext credential values are accepted or persisted;
- no Secret Provider references are persisted in runtime state;
- doctor/init/status/export perform no customer-network authentication;
- upload is explicit and outbound-only;
- completed upload is never repeated silently;
- state changes are auditable and protected by SHA256 sidecars.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
import platform
import re
import socket
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlparse

# One module identity shares reentrant lock ownership with the optional agent.
_LOCK_ROOT = str(Path(__file__).resolve().parent)
if _LOCK_ROOT not in sys.path:
    sys.path.insert(0, _LOCK_ROOT)
from P01_Workspace_Lock import locked_workspace, workspace_lock


NAME = "Canca-Portable-Discovery-Node"
DISPLAY_NAME = "Cancã Portable Discovery Node"
VERSION = "0.5e.6"
SCHEMA_VERSION = "0.5e"

REPO_ROOT = Path(__file__).resolve().parents[1]
STATE_REL = Path("state") / "run-state.json"
CONFIG_REL = Path("config") / "runtime.json"

WORKSPACE_DIRS = (
    "config",
    "evidence",
    "resolved",
    "bundle",
    "receipts",
    "logs",
    "state",
)

STEP_ORDER = (
    "initialized",
    "network_discovery",
    "credential_plan",
    "credentialed_execution",
    "asset_resolver",
    "evidence_bundle",
    "upload",
)

FORBIDDEN_VALUE_RE = re.compile(
    r"(?:wincred|prompt|env)://|-----BEGIN[^\n]*PRIVATE KEY-----",
    re.IGNORECASE,
)
FORBIDDEN_KEY_RE = re.compile(
    r"(?:^|_)(?:password|passphrase|secret_value|secret_values|secret_refs|"
    r"api_key|access_token|refresh_token|private_key)(?:$|_)",
    re.IGNORECASE,
)
SAFE_FALSE_SECURITY_FLAGS = {
    "secret_values_persisted",
    "secret_values_persisted_to_output",
    "secret_provider_references_persisted",
    "private_key_material_persisted",
    "contains_secret_values",
    "contains_secret_provider_references",
    "contains_private_key_material",
}


class RuntimeErrorSafe(RuntimeError):
    """Operator-safe runtime failure."""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def digest_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_label(value: str, field: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        raise RuntimeErrorSafe(f"{field} is required")
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", raw).strip("-.")
    if not cleaned:
        raise RuntimeErrorSafe(f"{field} has no safe filename characters")
    return cleaned[:128]


def assert_no_secret_material(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            if FORBIDDEN_KEY_RE.search(key_text):
                safe_false_flag = key_text in SAFE_FALSE_SECURITY_FLAGS and child is False
                if not safe_false_flag:
                    raise RuntimeErrorSafe(
                        f"sensitive field prohibited in runtime state/config: {path}.{key_text}"
                    )
            assert_no_secret_material(child, f"{path}.{key_text}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            assert_no_secret_material(child, f"{path}[{index}]")
    elif isinstance(value, str):
        if FORBIDDEN_VALUE_RE.search(value):
            raise RuntimeErrorSafe(
                f"secret/private-key material prohibited in runtime state/config: {path}"
            )


def _atomic_write_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, path)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def write_json_with_sidecar(path: Path, value: Mapping[str, Any]) -> Tuple[Path, Path]:
    assert_no_secret_material(value)
    raw = canonical_json_bytes(value)
    _atomic_write_bytes(path, raw)
    sha = path.with_suffix(path.suffix + ".sha256")
    _atomic_write_bytes(sha, f"{digest_bytes(raw)}  {path.name}\n".encode("utf-8"))
    return path, sha


def verify_sidecar(path: Path) -> bool:
    sidecar = path.with_suffix(path.suffix + ".sha256")
    if not path.exists() or not sidecar.exists():
        return False
    text = sidecar.read_text(encoding="utf-8-sig").strip()
    if not text:
        return False
    expected = text.split()[0].lower()
    return bool(re.fullmatch(r"[0-9a-f]{64}", expected)) and digest_file(path) == expected


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists() or not path.is_file():
        raise RuntimeErrorSafe(f"JSON file not found: {path}")
    try:
        doc = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        raise RuntimeErrorSafe(f"invalid JSON file {path}: {exc}") from exc
    if not isinstance(doc, dict):
        raise RuntimeErrorSafe(f"JSON root must be an object: {path}")
    return doc


def _path_ref(path: Optional[Path]) -> Optional[str]:
    if path is None:
        return None
    return str(path.expanduser().resolve())


def _workspace_path(root: Path, assessment_id: str, run_id: str) -> Path:
    return (
        root.expanduser().resolve()
        / safe_label(assessment_id, "assessment_id")
        / safe_label(run_id, "run_id")
    )


def _state_path(workspace: Path) -> Path:
    return workspace / STATE_REL


def _config_path(workspace: Path) -> Path:
    return workspace / CONFIG_REL


def _load_state(workspace: Path, require_integrity: bool = True) -> Dict[str, Any]:
    state_path = _state_path(workspace)
    if require_integrity and not verify_sidecar(state_path):
        raise RuntimeErrorSafe(f"runtime state SHA256 missing or invalid: {state_path}")
    state = load_json(state_path)
    if state.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeErrorSafe(
            f"unsupported runtime state schema {state.get('schema_version')!r}; "
            f"expected {SCHEMA_VERSION!r}"
        )
    assert_no_secret_material(state)
    return state


def _write_state(workspace: Path, state: Dict[str, Any]) -> None:
    state["updated_at_utc"] = utc_now_iso()
    write_json_with_sidecar(_state_path(workspace), state)


def _append_event(
    state: Dict[str, Any],
    action: str,
    status: str,
    detail: Optional[Mapping[str, Any]] = None,
) -> None:
    event = {
        "at_utc": utc_now_iso(),
        "action": action,
        "status": status,
    }
    if detail:
        event["detail"] = dict(detail)
    state.setdefault("events", []).append(event)
    # Keep state bounded for long-running portable workspaces.
    if len(state["events"]) > 200:
        state["events"] = state["events"][-200:]


def _platform_metadata() -> Dict[str, Any]:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python_version": platform.python_version(),
        "hostname": socket.gethostname(),
    }


def _init_workspace_unlocked(
    workspace_root: Path,
    assessment_id: str,
    run_id: str,
    node_id: str,
    manifest: Optional[Path] = None,
    profiles: Optional[Path] = None,
) -> Dict[str, Any]:
    workspace = _workspace_path(workspace_root, assessment_id, run_id)
    state_path = _state_path(workspace)

    if state_path.exists():
        state = _load_state(workspace)
        identity = (
            state.get("assessment_id"),
            state.get("run_id"),
            state.get("node_id"),
        )
        requested = (assessment_id, run_id, node_id)
        if identity != requested:
            raise RuntimeErrorSafe(
                "workspace already exists with different assessment/run/node identity"
            )
        return {
            "status": "already_initialized",
            "workspace": str(workspace),
            "state": state,
        }

    if manifest is not None and not manifest.is_file():
        raise RuntimeErrorSafe(f"assessment manifest not found: {manifest}")
    if profiles is not None and not profiles.is_file():
        raise RuntimeErrorSafe(f"credential profiles file not found: {profiles}")

    for name in WORKSPACE_DIRS:
        (workspace / name).mkdir(parents=True, exist_ok=True)

    now = utc_now_iso()
    steps = {
        "initialized": {
            "status": "completed",
            "completed_at_utc": now,
            "managed_by": VERSION,
        },
        "network_discovery": {
            "status": "pending",
            "managed_by": VERSION,
        },
        "credential_plan": {
            "status": "pending",
            "managed_by": VERSION,
        },
        "credentialed_execution": {
            "status": "pending",
            "managed_by": VERSION,
        },
        "asset_resolver": {
            "status": "pending",
            "managed_by": VERSION,
        },
        "evidence_bundle": {"status": "pending"},
        "upload": {"status": "pending"},
    }

    state: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "runtime_name": NAME,
        "runtime_version": VERSION,
        "created_at_utc": now,
        "updated_at_utc": now,
        "assessment_id": assessment_id,
        "run_id": run_id,
        "node_id": node_id,
        "platform": _platform_metadata(),
        "source_refs": {
            "assessment_manifest": _path_ref(manifest),
            "credential_profiles": _path_ref(profiles),
        },
        "workspace": {
            "root": str(workspace),
            "directories": list(WORKSPACE_DIRS),
        },
        "security": {
            "plaintext_credentials_persisted": False,
            "secret_provider_references_persisted": False,
            "private_key_material_persisted": False,
            "server_initiated_remote_execution": False,
            "active_discovery_managed_in_this_version": True,
            "credential_planning_managed_in_this_version": True,
            "credentialed_execution_dry_run_managed_in_this_version": True,
            "credentialed_execution_auth_only_managed_in_this_version": True,
            "credentialed_execution_full_managed_in_this_version": True,
            "asset_resolver_managed_in_this_version": True,
            "workspace_driven_bundle_managed_in_this_version": True,
            "zero_input_upload_resume_supported": True,
        },
        "steps": steps,
        "artifacts": {},
        "events": [],
    }
    _append_event(
        state,
        "init",
        "completed",
        {"runtime_version": VERSION, "portable": True},
    )
    _write_state(workspace, state)

    runtime_config = {
        "schema_version": SCHEMA_VERSION,
        "assessment_id": assessment_id,
        "run_id": run_id,
        "node_id": node_id,
        "source_refs": dict(state["source_refs"]),
        "portable": True,
        "service_installation_required": False,
        "security": {
            "contains_plaintext_credentials": False,
            "contains_secret_provider_references": False,
            "contains_private_key_material": False,
        },
    }
    write_json_with_sidecar(_config_path(workspace), runtime_config)

    return {
        "status": "initialized",
        "workspace": str(workspace),
        "state": state,
    }


def init_workspace(
    workspace_root: Path, assessment_id: str, run_id: str, node_id: str,
    manifest: Optional[Path] = None, profiles: Optional[Path] = None,
) -> Dict[str, Any]:
    workspace = _workspace_path(workspace_root, assessment_id, run_id)
    with workspace_lock(workspace):
        return _init_workspace_unlocked(
            workspace_root, assessment_id, run_id, node_id, manifest, profiles
        )


def _existing_parent(path: Path) -> Path:
    candidate = path.expanduser()
    while not candidate.exists() and candidate.parent != candidate:
        candidate = candidate.parent
    return candidate


def doctor(
    workspace_root: Path,
    server_url: Optional[str] = None,
    ca_cert: Optional[Path] = None,
    client_cert: Optional[Path] = None,
    client_key: Optional[Path] = None,
) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str) -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    add(
        "python_version",
        sys.version_info >= (3, 10),
        platform.python_version(),
    )
    add(
        "supported_os",
        platform.system() in {"Windows", "Linux"},
        platform.system(),
    )

    required_components = {
        "network_discovery": REPO_ROOT / "network_discovery" / "P01_Network_Discovery_Scanner.py",
        "planner": REPO_ROOT / "orchestrator" / "P01_Credentialed_Discovery_Planner.py",
        "executor": REPO_ROOT / "orchestrator" / "P01_Credentialed_Discovery_Executor.py",
        "asset_resolver": REPO_ROOT / "asset_resolver" / "P01_Asset_Resolver.py",
        "evidence_bundle": REPO_ROOT / "evidence_bundle" / "P01_Evidence_Bundle.py",
        "connected_uploader": REPO_ROOT / "connected" / "P01_Discovery_Node_Uploader.py",
    }
    for name, path in required_components.items():
        add(f"component_{name}", path.is_file(), str(path))

    parent = _existing_parent(workspace_root.expanduser().resolve())
    writable = parent.exists() and os.access(parent, os.W_OK)
    add("workspace_parent_writable", writable, str(parent))

    if server_url:
        parsed = urlparse(server_url)
        url_ok = parsed.scheme.lower() == "https" and bool(parsed.hostname)
        add("server_url_https", url_ok, server_url)
        for name, path in (
            ("ca_cert", ca_cert),
            ("client_cert", client_cert),
            ("client_key", client_key),
        ):
            add(
                f"tls_{name}",
                bool(path and path.is_file()),
                "present" if path and path.is_file() else "missing",
            )
    else:
        add("connected_transport_configured", True, "not requested; offline-capable")

    result = {
        "runtime": {"name": NAME, "version": VERSION},
        "platform": _platform_metadata(),
        "ready": all(item["ok"] for item in checks),
        "checks": checks,
        "network_activity_performed": False,
        "secret_resolution_performed": False,
        "authentication_attempts_performed": False,
    }
    return result


def _load_component(relative_path: str, module_name: str):
    path = REPO_ROOT / relative_path
    if not path.is_file():
        raise RuntimeErrorSafe(f"required component not found: {path}")
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeErrorSafe(f"unable to load component: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _workspace_owned_path(workspace: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else workspace / path


def _relative_if_owned(workspace: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(workspace.resolve()))
    except ValueError:
        return str(path.resolve())


def _artifact_ref(path: Path) -> Dict[str, Any]:
    return {
        "path": str(path.resolve()),
        "sha256": digest_file(path),
        "size_bytes": path.stat().st_size,
    }



def _authorized_ipv4_networks(manifest: Mapping[str, Any]) -> List[ipaddress.IPv4Network]:
    values = manifest.get("authorized_scopes")
    if not isinstance(values, list) or not values:
        raise RuntimeErrorSafe("Assessment Manifest has no authorized_scopes")
    networks: List[ipaddress.IPv4Network] = []
    for raw in values:
        try:
            net = ipaddress.ip_network(str(raw), strict=False)
        except ValueError as exc:
            raise RuntimeErrorSafe(f"invalid authorized scope {raw!r}: {exc}") from exc
        if not isinstance(net, ipaddress.IPv4Network):
            raise RuntimeErrorSafe("v0.5e.6 managed discovery supports IPv4 only")
        networks.append(net)
    return networks


@locked_workspace
def run_network_discovery(
    workspace: Path,
    targets: Sequence[str],
    excludes: Sequence[str],
    *,
    ack_authorized_scan: bool,
    profile: str = "safe",
    ports: Optional[str] = None,
    timeout: float = 0.35,
    workers: int = 64,
    max_hosts: int = 2048,
    allow_large_scope: bool = False,
    disable_ssdp: bool = False,
    force_rescan: bool = False,
) -> Dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    state = _load_state(workspace)
    step = state["steps"]["network_discovery"]

    if step.get("status") == "completed" and not force_rescan:
        existing = state.get("artifacts", {}).get("network_discovery", {})
        path_value = existing.get("path")
        if path_value:
            path = _workspace_owned_path(workspace, str(path_value))
            if path.is_file() and digest_file(path) == existing.get("sha256"):
                return {
                    "status": "already_complete",
                    "network_json": str(path),
                    "network_sha256": existing.get("sha256"),
                    "hosts_discovered": existing.get("hosts_discovered"),
                    "network_activity_performed": False,
                }
        raise RuntimeErrorSafe(
            "network discovery is completed but recorded evidence is missing or changed"
        )

    if force_rescan:
        downstream = ("credential_plan", "credentialed_execution", "asset_resolver", "evidence_bundle", "upload")
        completed = [
            name
            for name in downstream
            if (state.get("steps", {}).get(name) or {}).get("status") == "completed"
        ]
        if completed:
            raise RuntimeErrorSafe(
                "refusing --force-rescan because downstream completed steps would become stale: "
                + ", ".join(completed)
            )

    if not ack_authorized_scan:
        raise RuntimeErrorSafe(
            "--ack-authorized-scan is required before managed active discovery"
        )
    if not targets:
        raise RuntimeErrorSafe("provide at least one --target")

    manifest_ref = state.get("source_refs", {}).get("assessment_manifest")
    if not manifest_ref:
        raise RuntimeErrorSafe(
            "managed discovery requires an Assessment Manifest with authorized_scopes"
        )
    manifest_path = Path(str(manifest_ref))
    manifest = load_json(manifest_path)
    if str(manifest.get("assessment_id") or "") != str(state.get("assessment_id") or ""):
        raise RuntimeErrorSafe(
            "Assessment Manifest assessment_id does not match workspace assessment_id"
        )

    scanner = _load_component(
        "network_discovery/P01_Network_Discovery_Scanner.py",
        "p01_runtime_network_discovery",
    )

    manifest_excludes = [
        str(x)
        for x in (manifest.get("exclude_scopes") or [])
        if str(x).strip()
    ]
    effective_excludes = list(manifest_excludes) + [str(x) for x in excludes]

    try:
        effective_ips, _resolved_excludes = scanner.resolve_scope(
            list(targets),
            effective_excludes,
        )
    except Exception as exc:
        raise RuntimeErrorSafe(f"unable to resolve requested discovery scope: {exc}") from exc

    authorized = _authorized_ipv4_networks(manifest)
    outside = [
        ip
        for ip in effective_ips
        if not any(ipaddress.ip_address(ip) in net for net in authorized)
    ]
    if outside:
        preview = ", ".join(outside[:5])
        more = "" if len(outside) <= 5 else f" (+{len(outside)-5} more)"
        raise RuntimeErrorSafe(
            "requested effective discovery scope contains addresses outside "
            f"Assessment Manifest authorization: {preview}{more}"
        )

    output_dir = workspace / "evidence" / "network"
    output_dir.mkdir(parents=True, exist_ok=True)
    run_label = f"{safe_label(state['run_id'], 'run_id')}-NETWORK"
    before = {p.resolve() for p in output_dir.glob("P01-Network-Discovery_*.json")}

    argv: List[str] = []
    for target in targets:
        argv.extend(["--target", str(target)])
    for exclude in effective_excludes:
        argv.extend(["--exclude", exclude])
    argv.extend([
        "--profile", profile,
        "--timeout", str(timeout),
        "--workers", str(workers),
        "--max-hosts", str(max_hosts),
        "--output-dir", str(output_dir),
        "--run-label", run_label,
        "--ack-authorized-scan",
    ])
    if ports:
        argv.extend(["--ports", ports])
    if allow_large_scope:
        argv.append("--allow-large-scope")
    if disable_ssdp:
        argv.append("--disable-ssdp")

    step.clear()
    step.update({
        "status": "running",
        "started_at_utc": utc_now_iso(),
        "managed_by": VERSION,
        "authorization_acknowledged": True,
    })
    _append_event(
        state,
        "network_discovery",
        "started",
        {
            "target_count": len(targets),
            "effective_ip_count": len(effective_ips),
            "profile": profile,
        },
    )
    _write_state(workspace, state)

    try:
        rc = int(scanner.main(argv))
    except SystemExit as exc:
        rc = int(exc.code or 0)
    except Exception as exc:
        step["status"] = "failed"
        step["failed_at_utc"] = utc_now_iso()
        step["last_error"] = str(exc)[:1200]
        _append_event(state, "network_discovery", "failed", {"error": str(exc)[:500]})
        _write_state(workspace, state)
        raise RuntimeErrorSafe(str(exc)) from exc

    after = sorted(
        {p.resolve() for p in output_dir.glob("P01-Network-Discovery_*.json")} - before,
        key=lambda p: p.stat().st_mtime_ns,
    )
    if not after:
        step["status"] = "failed"
        step["failed_at_utc"] = utc_now_iso()
        step["last_error"] = "Network Discovery did not produce a new JSON artifact"
        _append_event(state, "network_discovery", "failed", {"return_code": rc})
        _write_state(workspace, state)
        raise RuntimeErrorSafe(step["last_error"])

    network_json = after[-1]
    sidecar = network_json.with_suffix(network_json.suffix + ".sha256")
    if not verify_sidecar(network_json):
        step["status"] = "failed"
        step["failed_at_utc"] = utc_now_iso()
        step["last_error"] = "Network Discovery output SHA256 sidecar is missing or invalid"
        _append_event(state, "network_discovery", "failed", {"return_code": rc})
        _write_state(workspace, state)
        raise RuntimeErrorSafe(step["last_error"])

    network_doc = load_json(network_json)
    hosts = int((network_doc.get("summary") or {}).get("hosts_discovered") or 0)
    state["artifacts"]["network_discovery"] = {
        "path": _relative_if_owned(workspace, network_json),
        "sha256_path": _relative_if_owned(workspace, sidecar),
        "sha256": digest_file(network_json),
        "hosts_discovered": hosts,
        "effective_ip_count": len(effective_ips),
        "targets": list(targets),
        "excludes": effective_excludes,
    }

    if rc != 0:
        step["status"] = "failed"
        step["failed_at_utc"] = utc_now_iso()
        step["last_error"] = f"Network Discovery returned code {rc}; partial evidence retained"
        _append_event(
            state,
            "network_discovery",
            "failed",
            {"return_code": rc, "partial_evidence_retained": True},
        )
        _write_state(workspace, state)
        raise RuntimeErrorSafe(step["last_error"])

    step.clear()
    step.update({
        "status": "completed",
        "completed_at_utc": utc_now_iso(),
        "managed_by": VERSION,
        "authorization_acknowledged": True,
        "network_activity_performed": True,
        "authentication_attempts": False,
        "hosts_discovered": hosts,
        "effective_ip_count": len(effective_ips),
    })
    _append_event(
        state,
        "network_discovery",
        "completed",
        {
            "hosts_discovered": hosts,
            "effective_ip_count": len(effective_ips),
        },
    )
    _write_state(workspace, state)
    return {
        "status": "completed",
        "network_json": str(network_json),
        "network_sha256": digest_file(network_json),
        "hosts_discovered": hosts,
        "effective_ip_count": len(effective_ips),
        "network_activity_performed": True,
        "authentication_attempts_performed": False,
    }


@locked_workspace
def run_credential_plan(
    workspace: Path,
    *,
    max_candidates: int = 2,
    force_replan: bool = False,
) -> Dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    state = _load_state(workspace)
    state["runtime_version"] = VERSION
    state.setdefault("security", {})["credential_planning_managed_in_this_version"] = True
    step = state["steps"]["credential_plan"]

    if step.get("status") == "completed" and not force_replan:
        existing = state.get("artifacts", {}).get("credential_plan", {})
        path_value = existing.get("path")
        if path_value:
            path = _workspace_owned_path(workspace, str(path_value))
            if path.is_file() and digest_file(path) == existing.get("sha256"):
                return {
                    "status": "already_complete",
                    "plan_json": str(path),
                    "plan_sha256": existing.get("sha256"),
                    "assets_seen": existing.get("assets_seen"),
                    "adapter_candidates": existing.get("adapter_candidates"),
                    "network_activity_performed": False,
                    "secret_resolution_performed": False,
                    "authentication_attempts_performed": False,
                }
        raise RuntimeErrorSafe(
            "credential plan is completed but recorded evidence is missing or changed"
        )

    if not (1 <= int(max_candidates) <= 5):
        raise RuntimeErrorSafe("--max-candidates must be 1..5")

    network_step = state.get("steps", {}).get("network_discovery") or {}
    if network_step.get("status") != "completed":
        raise RuntimeErrorSafe(
            "managed Credential Planner requires completed Network Discovery"
        )

    if force_replan:
        downstream = ("credentialed_execution", "asset_resolver", "evidence_bundle", "upload")
        completed = [
            name
            for name in downstream
            if (state.get("steps", {}).get(name) or {}).get("status") == "completed"
        ]
        if completed:
            raise RuntimeErrorSafe(
                "refusing --force-replan because downstream completed steps would become stale: "
                + ", ".join(completed)
            )

    network_artifact = (state.get("artifacts") or {}).get("network_discovery") or {}
    network_value = network_artifact.get("path")
    expected_network_sha = network_artifact.get("sha256")
    if not network_value or not expected_network_sha:
        raise RuntimeErrorSafe("Network Discovery artifact metadata is incomplete")
    network_path = _workspace_owned_path(workspace, str(network_value))
    if not network_path.is_file() or digest_file(network_path) != expected_network_sha:
        raise RuntimeErrorSafe(
            "Network Discovery artifact is missing or its SHA256 no longer matches state"
        )

    refs = state.get("source_refs") or {}
    manifest_ref = refs.get("assessment_manifest")
    profiles_ref = refs.get("credential_profiles")
    if not manifest_ref:
        raise RuntimeErrorSafe("managed Credential Planner requires an Assessment Manifest")
    if not profiles_ref:
        raise RuntimeErrorSafe("managed Credential Planner requires Credential Profiles")

    manifest_path = Path(str(manifest_ref)).expanduser().resolve()
    profiles_path = Path(str(profiles_ref)).expanduser().resolve()
    if not manifest_path.is_file():
        raise RuntimeErrorSafe(f"assessment manifest not found: {manifest_path}")
    if not profiles_path.is_file():
        raise RuntimeErrorSafe(f"credential profiles file not found: {profiles_path}")

    planner = _load_component(
        "orchestrator/P01_Credentialed_Discovery_Planner.py",
        "p01_runtime_credential_planner",
    )

    output_dir = workspace / "evidence" / "credential_plan"
    output_dir.mkdir(parents=True, exist_ok=True)
    run_label = f"{safe_label(state['run_id'], 'run_id')}-PLAN"

    step.clear()
    step.update({
        "status": "running",
        "started_at_utc": utc_now_iso(),
        "managed_by": VERSION,
    })
    _append_event(
        state,
        "credential_plan",
        "started",
        {
            "max_candidates": int(max_candidates),
            "network_sha256": expected_network_sha,
        },
    )
    _write_state(workspace, state)

    try:
        discovery = planner.load_json(network_path)
        profiles = planner.load_profiles(profiles_path)
        manifest = planner.load_manifest(manifest_path)
        if str(manifest.get("assessment_id") or "") != str(state.get("assessment_id") or ""):
            raise RuntimeErrorSafe(
                "Assessment Manifest assessment_id does not match workspace assessment_id"
            )
        payload = planner.build_plan(
            discovery,
            profiles,
            realm_map=None,
            max_candidates=int(max_candidates),
            manifest=manifest,
        )
        payload.setdefault("metadata", {})["assessment_manifest_sha256"] = digest_file(
            manifest_path
        )
        assert_no_secret_material(payload)
        plan_json, plan_sha = planner.write_output(output_dir, run_label, payload)
    except Exception as exc:
        step["status"] = "failed"
        step["failed_at_utc"] = utc_now_iso()
        step["last_error"] = str(exc)[:1200]
        _append_event(state, "credential_plan", "failed", {"error": str(exc)[:500]})
        _write_state(workspace, state)
        if isinstance(exc, RuntimeErrorSafe):
            raise
        raise RuntimeErrorSafe(str(exc)) from exc

    plan_json = Path(plan_json).resolve()
    plan_sha = Path(plan_sha).resolve()
    if not verify_sidecar(plan_json):
        step["status"] = "failed"
        step["failed_at_utc"] = utc_now_iso()
        step["last_error"] = "Credential Planner output SHA256 sidecar is missing or invalid"
        _append_event(state, "credential_plan", "failed")
        _write_state(workspace, state)
        raise RuntimeErrorSafe(step["last_error"])

    plan_doc = load_json(plan_json)
    assert_no_secret_material(plan_doc)
    summary = plan_doc.get("summary") or {}
    assets_seen = int(summary.get("assets_seen") or 0)
    adapter_candidates = int(summary.get("adapter_candidates") or 0)

    state["artifacts"]["credential_plan"] = {
        "path": _relative_if_owned(workspace, plan_json),
        "sha256_path": _relative_if_owned(workspace, plan_sha),
        "sha256": digest_file(plan_json),
        "source_network_sha256": expected_network_sha,
        "assessment_manifest_sha256": digest_file(manifest_path),
        "credential_profiles_sha256": digest_file(profiles_path),
        "assets_seen": assets_seen,
        "adapter_candidates": adapter_candidates,
        "max_candidates": int(max_candidates),
    }

    step.clear()
    step.update({
        "status": "completed",
        "completed_at_utc": utc_now_iso(),
        "managed_by": VERSION,
        "network_activity_performed": False,
        "secret_resolution": False,
        "authentication_attempts": False,
        "assets_seen": assets_seen,
        "adapter_candidates": adapter_candidates,
    })
    _append_event(
        state,
        "credential_plan",
        "completed",
        {
            "assets_seen": assets_seen,
            "adapter_candidates": adapter_candidates,
        },
    )
    _write_state(workspace, state)
    return {
        "status": "completed",
        "plan_json": str(plan_json),
        "plan_sha256": digest_file(plan_json),
        "assets_seen": assets_seen,
        "adapter_candidates": adapter_candidates,
        "network_activity_performed": False,
        "secret_resolution_performed": False,
        "authentication_attempts_performed": False,
    }


@locked_workspace
def run_credentialed_execution_dry_run(
    workspace: Path,
    *,
    max_actions: int = 25,
) -> Dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    state = _load_state(workspace)
    state["runtime_version"] = VERSION
    state.setdefault("security", {})[
        "credentialed_execution_dry_run_managed_in_this_version"
    ] = True
    step = state["steps"]["credentialed_execution"]

    if step.get("status") == "failed" and step.get("mode") in {"auth_only", "full"}:
        raise RuntimeErrorSafe(
            "previous live credentialed execution failed or was partial; review it "
            "before running any new credentialed-execution stage"
        )

    if step.get("status") in {"preview_completed", "auth_validated", "full_completed"}:
        existing = state.get("artifacts", {}).get("credentialed_execution_preview", {})
        path_value = existing.get("path")
        if path_value:
            path = _workspace_owned_path(workspace, str(path_value))
            if path.is_file() and digest_file(path) == existing.get("sha256"):
                return {
                    "status": "already_complete",
                    "job_json": str(path),
                    "job_sha256": existing.get("sha256"),
                    "actions_total": existing.get("actions_total"),
                    "actions_ready": existing.get("actions_ready"),
                    "network_activity_performed": False,
                    "secret_resolution_performed": False,
                    "authentication_attempts_performed": False,
                }
        raise RuntimeErrorSafe(
            "credentialed execution preview is completed but recorded evidence is missing or changed"
        )

    if not (1 <= int(max_actions) <= 250):
        raise RuntimeErrorSafe("--max-actions must be 1..250")

    plan_step = state.get("steps", {}).get("credential_plan") or {}
    if plan_step.get("status") != "completed":
        raise RuntimeErrorSafe(
            "managed Credentialed Executor dry-run requires completed Credential Plan"
        )

    plan_artifact = (state.get("artifacts") or {}).get("credential_plan") or {}
    plan_value = plan_artifact.get("path")
    expected_plan_sha = plan_artifact.get("sha256")
    if not plan_value or not expected_plan_sha:
        raise RuntimeErrorSafe("Credential Plan artifact metadata is incomplete")
    plan_path = _workspace_owned_path(workspace, str(plan_value))
    if not plan_path.is_file() or digest_file(plan_path) != expected_plan_sha:
        raise RuntimeErrorSafe(
            "Credential Plan artifact is missing or its SHA256 no longer matches state"
        )

    profiles_ref = (state.get("source_refs") or {}).get("credential_profiles")
    if not profiles_ref:
        raise RuntimeErrorSafe(
            "managed Credentialed Executor dry-run requires Credential Profiles"
        )
    profiles_path = Path(str(profiles_ref)).expanduser().resolve()
    if not profiles_path.is_file():
        raise RuntimeErrorSafe(f"credential profiles file not found: {profiles_path}")

    executor = _load_component(
        "orchestrator/P01_Credentialed_Discovery_Executor.py",
        "p01_runtime_credentialed_executor",
    )
    output_dir = workspace / "evidence" / "credentialed_execution"
    output_dir.mkdir(parents=True, exist_ok=True)
    run_label = f"{safe_label(state['run_id'], 'run_id')}-EXEC-DRY"

    step.clear()
    step.update({
        "status": "running",
        "started_at_utc": utc_now_iso(),
        "managed_by": VERSION,
        "mode": "dry_run",
    })
    _append_event(
        state,
        "credentialed_execution",
        "started",
        {
            "mode": "dry_run",
            "max_actions": int(max_actions),
            "plan_sha256": expected_plan_sha,
        },
    )
    _write_state(workspace, state)

    try:
        plan_doc = executor.load(plan_path)
        profiles = executor.load_profiles(profiles_path)
        payload = executor.run_job(
            plan_doc,
            profiles,
            expected_plan_sha,
            output_dir,
            run_label,
            False,
            False,
            int(max_actions),
            None,
            "strict",
        )
        assert_no_secret_material(payload)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out = output_dir / (
            f"P01-Credentialed-Job_{timestamp}_{safe_label(run_label, 'run_label')}.json"
        )
        job_json, job_sha, job_hash = executor.write(out, payload)
    except Exception as exc:
        step["status"] = "failed"
        step["failed_at_utc"] = utc_now_iso()
        step["last_error"] = str(exc)[:1200]
        _append_event(
            state,
            "credentialed_execution",
            "failed",
            {"mode": "dry_run", "error": str(exc)[:500]},
        )
        _write_state(workspace, state)
        if isinstance(exc, RuntimeErrorSafe):
            raise
        raise RuntimeErrorSafe(str(exc)) from exc

    job_json = Path(job_json).resolve()
    job_sha = Path(job_sha).resolve()
    if not verify_sidecar(job_json):
        step["status"] = "failed"
        step["failed_at_utc"] = utc_now_iso()
        step["last_error"] = "Credentialed Job output SHA256 sidecar is missing or invalid"
        _append_event(state, "credentialed_execution", "failed", {"mode": "dry_run"})
        _write_state(workspace, state)
        raise RuntimeErrorSafe(step["last_error"])

    job_doc = load_json(job_json)
    assert_no_secret_material(job_doc)
    metadata = job_doc.get("metadata") or {}
    summary = job_doc.get("summary") or {}
    if metadata.get("execution_mode") != "dry_run":
        raise RuntimeErrorSafe("managed v0.5e.3 executor must remain in dry_run mode")
    if bool(metadata.get("secret_resolution")) or bool(metadata.get("authentication_attempts")):
        raise RuntimeErrorSafe(
            "dry-run executor unexpectedly reported secret resolution/authentication"
        )

    actions_total = int(summary.get("actions_total") or 0)
    actions_ready = int(summary.get("actions_ready") or 0)
    state["artifacts"]["credentialed_execution_preview"] = {
        "path": _relative_if_owned(workspace, job_json),
        "sha256_path": _relative_if_owned(workspace, job_sha),
        "sha256": job_hash,
        "source_plan_sha256": expected_plan_sha,
        "credential_profiles_sha256": digest_file(profiles_path),
        "actions_total": actions_total,
        "actions_ready": actions_ready,
        "mode": "dry_run",
    }

    step.clear()
    step.update({
        "status": "preview_completed",
        "completed_at_utc": utc_now_iso(),
        "managed_by": VERSION,
        "mode": "dry_run",
        "network_activity_performed": False,
        "secret_resolution": False,
        "authentication_attempts": False,
        "actions_total": actions_total,
        "actions_ready": actions_ready,
    })
    _append_event(
        state,
        "credentialed_execution",
        "preview_completed",
        {
            "actions_total": actions_total,
            "actions_ready": actions_ready,
        },
    )
    _write_state(workspace, state)
    return {
        "status": "preview_completed",
        "job_json": str(job_json),
        "job_sha256": job_hash,
        "actions_total": actions_total,
        "actions_ready": actions_ready,
        "network_activity_performed": False,
        "secret_resolution_performed": False,
        "authentication_attempts_performed": False,
    }


@locked_workspace
def run_credentialed_execution_auth_only(
    workspace: Path,
    *,
    ack_authorized_access: bool,
    max_actions: int = 25,
    ssh_known_hosts: Optional[Path] = None,
    ssh_host_key_policy: str = "strict",
    force_auth_retry: bool = False,
) -> Dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    state = _load_state(workspace)
    state["runtime_version"] = VERSION
    state.setdefault("security", {})[
        "credentialed_execution_auth_only_managed_in_this_version"
    ] = True
    step = state["steps"]["credentialed_execution"]

    if step.get("status") in {"auth_validated", "full_completed"}:
        existing = state.get("artifacts", {}).get("credentialed_execution_auth", {})
        path_value = existing.get("path")
        if path_value:
            path = _workspace_owned_path(workspace, str(path_value))
            if path.is_file() and digest_file(path) == existing.get("sha256"):
                return {
                    "status": "already_complete",
                    "job_json": str(path),
                    "job_sha256": existing.get("sha256"),
                    "actions_total": existing.get("actions_total"),
                    "completed": existing.get("completed"),
                    "authentication_successes": existing.get("authentication_successes"),
                    "authentication_failures": existing.get("authentication_failures"),
                    "open_credential_circuits": existing.get("open_credential_circuits"),
                    "network_activity_performed": False,
                    "secret_resolution_performed": False,
                    "authentication_attempts_performed": False,
                }
        raise RuntimeErrorSafe(
            "AUTH-only execution is completed but recorded evidence is missing or changed"
        )

    if step.get("status") == "failed" and step.get("mode") == "full":
        raise RuntimeErrorSafe(
            "previous FULL execution failed or was partial; review it and retry the "
            "FULL stage explicitly rather than repeating AUTH-only"
        )
    if step.get("status") == "failed" and step.get("mode") == "auth_only" and not force_auth_retry:
        raise RuntimeErrorSafe(
            "previous AUTH-only execution failed or was partial; review evidence and use "
            "--force-auth-retry with --ack-authorized-access to retry explicitly"
        )

    if not ack_authorized_access:
        raise RuntimeErrorSafe(
            "--ack-authorized-access is required before managed credentialed authentication"
        )
    if not (1 <= int(max_actions) <= 250):
        raise RuntimeErrorSafe("--max-actions must be 1..250")
    if ssh_host_key_policy not in {"strict", "tofu"}:
        raise RuntimeErrorSafe("--ssh-host-key-policy must be strict or tofu")

    preview = state.get("artifacts", {}).get("credentialed_execution_preview") or {}
    preview_value = preview.get("path")
    preview_sha = preview.get("sha256")
    if not preview_value or not preview_sha:
        raise RuntimeErrorSafe(
            "managed AUTH-only execution requires a completed Executor dry-run preview"
        )
    preview_path = _workspace_owned_path(workspace, str(preview_value))
    if not preview_path.is_file() or digest_file(preview_path) != preview_sha:
        raise RuntimeErrorSafe(
            "Executor dry-run preview artifact is missing or its SHA256 no longer matches state"
        )

    plan_step = state.get("steps", {}).get("credential_plan") or {}
    if plan_step.get("status") != "completed":
        raise RuntimeErrorSafe(
            "managed AUTH-only execution requires completed Credential Plan"
        )
    plan_artifact = (state.get("artifacts") or {}).get("credential_plan") or {}
    plan_value = plan_artifact.get("path")
    expected_plan_sha = plan_artifact.get("sha256")
    if not plan_value or not expected_plan_sha:
        raise RuntimeErrorSafe("Credential Plan artifact metadata is incomplete")
    plan_path = _workspace_owned_path(workspace, str(plan_value))
    if not plan_path.is_file() or digest_file(plan_path) != expected_plan_sha:
        raise RuntimeErrorSafe(
            "Credential Plan artifact is missing or its SHA256 no longer matches state"
        )
    if preview.get("source_plan_sha256") != expected_plan_sha:
        raise RuntimeErrorSafe(
            "Executor dry-run preview is not bound to the current Credential Plan"
        )

    profiles_ref = (state.get("source_refs") or {}).get("credential_profiles")
    if not profiles_ref:
        raise RuntimeErrorSafe(
            "managed AUTH-only execution requires Credential Profiles"
        )
    profiles_path = Path(str(profiles_ref)).expanduser().resolve()
    if not profiles_path.is_file():
        raise RuntimeErrorSafe(f"credential profiles file not found: {profiles_path}")
    expected_profiles_sha = preview.get("credential_profiles_sha256")
    current_profiles_sha = digest_file(profiles_path)
    if expected_profiles_sha and current_profiles_sha != expected_profiles_sha:
        raise RuntimeErrorSafe(
            "Credential Profiles changed after dry-run preview; regenerate the plan/preview before authentication"
        )

    executor = _load_component(
        "orchestrator/P01_Credentialed_Discovery_Executor.py",
        "p01_runtime_credentialed_executor_auth",
    )
    output_dir = workspace / "evidence" / "credentialed_execution"
    output_dir.mkdir(parents=True, exist_ok=True)
    known_hosts = (
        ssh_known_hosts.expanduser().resolve()
        if ssh_known_hosts is not None
        else Path.home() / ".orizonit" / "p01" / "known_hosts"
    )
    run_label = f"{safe_label(state['run_id'], 'run_id')}-EXEC-AUTH"

    step.clear()
    step.update({
        "status": "running",
        "started_at_utc": utc_now_iso(),
        "managed_by": VERSION,
        "mode": "auth_only",
        "authorization_acknowledged": True,
    })
    _append_event(
        state,
        "credentialed_execution",
        "started",
        {
            "mode": "auth_only",
            "max_actions": int(max_actions),
            "plan_sha256": expected_plan_sha,
            "preview_sha256": preview_sha,
            "authorization_acknowledged": True,
        },
    )
    _write_state(workspace, state)

    try:
        plan_doc = executor.load(plan_path)
        profiles = executor.load_profiles(profiles_path)
        payload = executor.run_job(
            plan_doc,
            profiles,
            expected_plan_sha,
            output_dir,
            run_label,
            True,
            True,
            int(max_actions),
            known_hosts,
            ssh_host_key_policy,
        )
        assert_no_secret_material(payload)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out = output_dir / (
            f"P01-Credentialed-Job_{timestamp}_{safe_label(run_label, 'run_label')}.json"
        )
        job_json, job_sha, job_hash = executor.write(out, payload)
    except Exception as exc:
        step["status"] = "failed"
        step["failed_at_utc"] = utc_now_iso()
        step["last_error"] = str(exc)[:1200]
        step["mode"] = "auth_only"
        step["authorization_acknowledged"] = True
        _append_event(
            state,
            "credentialed_execution",
            "failed",
            {"mode": "auth_only", "error": str(exc)[:500]},
        )
        _write_state(workspace, state)
        if isinstance(exc, RuntimeErrorSafe):
            raise
        raise RuntimeErrorSafe(str(exc)) from exc

    job_json = Path(job_json).resolve()
    job_sha = Path(job_sha).resolve()
    if not verify_sidecar(job_json):
        step["status"] = "failed"
        step["failed_at_utc"] = utc_now_iso()
        step["last_error"] = "AUTH-only Credentialed Job SHA256 sidecar is missing or invalid"
        step["mode"] = "auth_only"
        _append_event(state, "credentialed_execution", "failed", {"mode": "auth_only"})
        _write_state(workspace, state)
        raise RuntimeErrorSafe(step["last_error"])

    job_doc = load_json(job_json)
    assert_no_secret_material(job_doc)
    metadata = job_doc.get("metadata") or {}
    summary = job_doc.get("summary") or {}
    if metadata.get("execution_mode") != "execute" or not bool(metadata.get("auth_only")):
        raise RuntimeErrorSafe("managed v0.5e.3.1 executor must run execute=true, auth_only=true")
    if not bool(metadata.get("secret_resolution")) or not bool(metadata.get("authentication_attempts")):
        raise RuntimeErrorSafe(
            "AUTH-only executor did not report expected secret resolution/authentication activity"
        )
    if int(metadata.get("concurrency") or 0) != 1:
        raise RuntimeErrorSafe("managed AUTH-only executor must remain concurrency=1")

    target_files: List[Path] = []
    for action in job_doc.get("actions") or []:
        if not isinstance(action, Mapping):
            continue
        value = action.get("target_result_file")
        if not value:
            continue
        target_path = Path(str(value)).expanduser().resolve()
        if not target_path.is_file() or not verify_sidecar(target_path):
            raise RuntimeErrorSafe(
                f"AUTH-only target evidence missing or failed SHA256 verification: {target_path}"
            )
        assert_no_secret_material(load_json(target_path))
        target_files.append(target_path)

    actions_total = int(summary.get("actions_total") or 0)
    actions_ready = int(summary.get("actions_ready") or 0)
    completed = int(summary.get("completed") or 0)
    skipped = int(summary.get("skipped") or 0)
    auth_successes = int(summary.get("authentication_successes") or 0)
    auth_failures = int(summary.get("authentication_failures") or 0)
    open_circuits = int(summary.get("open_credential_circuits") or 0)

    state["artifacts"]["credentialed_execution_auth"] = {
        "path": _relative_if_owned(workspace, job_json),
        "sha256_path": _relative_if_owned(workspace, job_sha),
        "sha256": job_hash,
        "source_plan_sha256": expected_plan_sha,
        "source_preview_sha256": preview_sha,
        "credential_profiles_sha256": current_profiles_sha,
        "actions_total": actions_total,
        "actions_ready": actions_ready,
        "completed": completed,
        "skipped": skipped,
        "authentication_successes": auth_successes,
        "authentication_failures": auth_failures,
        "open_credential_circuits": open_circuits,
        "target_evidence_count": len(target_files),
        "mode": "auth_only",
    }

    auth_success = (
        actions_total > 0
        and actions_ready == actions_total
        and completed == actions_total
        and auth_successes == actions_total
        and auth_failures == 0
        and skipped == 0
        and open_circuits == 0
        and len(target_files) == actions_total
    )
    if not auth_success:
        step.clear()
        step.update({
            "status": "failed",
            "failed_at_utc": utc_now_iso(),
            "managed_by": VERSION,
            "mode": "auth_only",
            "authorization_acknowledged": True,
            "network_activity_performed": True,
            "secret_resolution": True,
            "authentication_attempts": True,
            "actions_total": actions_total,
            "actions_ready": actions_ready,
            "completed": completed,
            "skipped": skipped,
            "authentication_successes": auth_successes,
            "authentication_failures": auth_failures,
            "open_credential_circuits": open_circuits,
            "last_error": "AUTH-only execution completed with partial/failed target results",
        })
        _append_event(
            state,
            "credentialed_execution",
            "failed",
            {
                "mode": "auth_only",
                "actions_total": actions_total,
                "completed": completed,
                "authentication_failures": auth_failures,
                "skipped": skipped,
            },
        )
        _write_state(workspace, state)
        raise RuntimeErrorSafe(
            "AUTH-only execution produced partial/failed results; evidence was preserved. "
            "Review it before an explicit --force-auth-retry."
        )

    step.clear()
    step.update({
        "status": "auth_validated",
        "completed_at_utc": utc_now_iso(),
        "managed_by": VERSION,
        "mode": "auth_only",
        "authorization_acknowledged": True,
        "network_activity_performed": True,
        "secret_resolution": True,
        "authentication_attempts": True,
        "actions_total": actions_total,
        "actions_ready": actions_ready,
        "completed": completed,
        "authentication_successes": auth_successes,
        "authentication_failures": auth_failures,
        "open_credential_circuits": open_circuits,
    })
    _append_event(
        state,
        "credentialed_execution",
        "auth_validated",
        {
            "actions_total": actions_total,
            "completed": completed,
            "authentication_successes": auth_successes,
            "authentication_failures": auth_failures,
            "open_credential_circuits": open_circuits,
        },
    )
    _write_state(workspace, state)
    return {
        "status": "auth_validated",
        "job_json": str(job_json),
        "job_sha256": job_hash,
        "actions_total": actions_total,
        "completed": completed,
        "authentication_successes": auth_successes,
        "authentication_failures": auth_failures,
        "open_credential_circuits": open_circuits,
        "network_activity_performed": True,
        "secret_resolution_performed": True,
        "authentication_attempts_performed": True,
    }


@locked_workspace
def run_credentialed_execution_full(
    workspace: Path,
    *,
    ack_authorized_access: bool,
    max_actions: int = 25,
    ssh_known_hosts: Optional[Path] = None,
    ssh_host_key_policy: str = "strict",
    force_full_retry: bool = False,
) -> Dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    state = _load_state(workspace)
    state["runtime_version"] = VERSION
    state.setdefault("security", {})[
        "credentialed_execution_full_managed_in_this_version"
    ] = True
    step = state["steps"]["credentialed_execution"]

    if step.get("status") == "full_completed":
        existing = state.get("artifacts", {}).get("credentialed_execution_full", {})
        path_value = existing.get("path")
        if path_value:
            path = _workspace_owned_path(workspace, str(path_value))
            if path.is_file() and digest_file(path) == existing.get("sha256"):
                return {
                    "status": "already_complete",
                    "job_json": str(path),
                    "job_sha256": existing.get("sha256"),
                    "actions_total": existing.get("actions_total"),
                    "completed": existing.get("completed"),
                    "collected": existing.get("collected"),
                    "authentication_successes": existing.get("authentication_successes"),
                    "authentication_failures": existing.get("authentication_failures"),
                    "open_credential_circuits": existing.get("open_credential_circuits"),
                    "network_activity_performed": False,
                    "secret_resolution_performed": False,
                    "authentication_attempts_performed": False,
                }
        raise RuntimeErrorSafe(
            "FULL credentialed execution is completed but recorded evidence is missing or changed"
        )

    if step.get("status") == "failed" and step.get("mode") == "auth_only":
        raise RuntimeErrorSafe(
            "AUTH-only execution is not validated; resolve/retry AUTH-only before FULL enrichment"
        )
    if step.get("status") == "failed" and step.get("mode") == "full" and not force_full_retry:
        raise RuntimeErrorSafe(
            "previous FULL execution failed or was partial; review evidence and use "
            "--force-full-retry with --ack-authorized-access to retry explicitly"
        )
    if step.get("status") not in {"auth_validated", "failed"}:
        raise RuntimeErrorSafe(
            "managed FULL enrichment requires credentialed_execution: auth_validated"
        )

    if not ack_authorized_access:
        raise RuntimeErrorSafe(
            "--ack-authorized-access is required before managed FULL credentialed enrichment"
        )
    if not (1 <= int(max_actions) <= 250):
        raise RuntimeErrorSafe("--max-actions must be 1..250")
    if ssh_host_key_policy not in {"strict", "tofu"}:
        raise RuntimeErrorSafe("--ssh-host-key-policy must be strict or tofu")

    plan_artifact = (state.get("artifacts") or {}).get("credential_plan") or {}
    plan_value = plan_artifact.get("path")
    expected_plan_sha = plan_artifact.get("sha256")
    if not plan_value or not expected_plan_sha:
        raise RuntimeErrorSafe("Credential Plan artifact metadata is incomplete")
    plan_path = _workspace_owned_path(workspace, str(plan_value))
    if not plan_path.is_file() or digest_file(plan_path) != expected_plan_sha:
        raise RuntimeErrorSafe(
            "Credential Plan artifact is missing or its SHA256 no longer matches state"
        )

    preview = (state.get("artifacts") or {}).get("credentialed_execution_preview") or {}
    preview_value = preview.get("path")
    preview_sha = preview.get("sha256")
    if not preview_value or not preview_sha:
        raise RuntimeErrorSafe("managed FULL enrichment requires a validated dry-run preview")
    preview_path = _workspace_owned_path(workspace, str(preview_value))
    if not preview_path.is_file() or digest_file(preview_path) != preview_sha:
        raise RuntimeErrorSafe(
            "Executor dry-run preview artifact is missing or its SHA256 no longer matches state"
        )
    if preview.get("source_plan_sha256") != expected_plan_sha:
        raise RuntimeErrorSafe(
            "Executor dry-run preview is not bound to the current Credential Plan"
        )

    auth = (state.get("artifacts") or {}).get("credentialed_execution_auth") or {}
    auth_value = auth.get("path")
    auth_sha = auth.get("sha256")
    if not auth_value or not auth_sha:
        raise RuntimeErrorSafe("managed FULL enrichment requires validated AUTH-only evidence")
    auth_path = _workspace_owned_path(workspace, str(auth_value))
    if not auth_path.is_file() or digest_file(auth_path) != auth_sha:
        raise RuntimeErrorSafe(
            "AUTH-only job artifact is missing or its SHA256 no longer matches state"
        )
    if auth.get("source_plan_sha256") != expected_plan_sha:
        raise RuntimeErrorSafe(
            "AUTH-only evidence is not bound to the current Credential Plan"
        )
    if auth.get("source_preview_sha256") != preview_sha:
        raise RuntimeErrorSafe(
            "AUTH-only evidence is not bound to the current dry-run preview"
        )
    if int(auth.get("authentication_failures") or 0) != 0:
        raise RuntimeErrorSafe(
            "AUTH-only evidence contains authentication failures; FULL enrichment is blocked"
        )
    if int(auth.get("authentication_successes") or 0) <= 0:
        raise RuntimeErrorSafe(
            "AUTH-only evidence contains no successful authentications; FULL enrichment is blocked"
        )

    profiles_ref = (state.get("source_refs") or {}).get("credential_profiles")
    if not profiles_ref:
        raise RuntimeErrorSafe("managed FULL enrichment requires Credential Profiles")
    profiles_path = Path(str(profiles_ref)).expanduser().resolve()
    if not profiles_path.is_file():
        raise RuntimeErrorSafe(f"credential profiles file not found: {profiles_path}")
    current_profiles_sha = digest_file(profiles_path)
    for name, artifact in (("preview", preview), ("AUTH-only", auth)):
        expected_profiles_sha = artifact.get("credential_profiles_sha256")
        if expected_profiles_sha and current_profiles_sha != expected_profiles_sha:
            raise RuntimeErrorSafe(
                f"Credential Profiles changed after {name}; regenerate the staged "
                "credentialed-execution flow before FULL enrichment"
            )

    executor = _load_component(
        "orchestrator/P01_Credentialed_Discovery_Executor.py",
        "p01_runtime_credentialed_executor_full",
    )
    output_dir = workspace / "evidence" / "credentialed_execution"
    output_dir.mkdir(parents=True, exist_ok=True)
    known_hosts = (
        ssh_known_hosts.expanduser().resolve()
        if ssh_known_hosts is not None
        else Path.home() / ".orizonit" / "p01" / "known_hosts"
    )
    run_label = f"{safe_label(state['run_id'], 'run_id')}-EXEC-FULL"

    step.clear()
    step.update({
        "status": "running",
        "started_at_utc": utc_now_iso(),
        "managed_by": VERSION,
        "mode": "full",
        "authorization_acknowledged": True,
    })
    _append_event(
        state,
        "credentialed_execution",
        "started",
        {
            "mode": "full",
            "max_actions": int(max_actions),
            "plan_sha256": expected_plan_sha,
            "preview_sha256": preview_sha,
            "auth_sha256": auth_sha,
            "authorization_acknowledged": True,
        },
    )
    _write_state(workspace, state)

    try:
        plan_doc = executor.load(plan_path)
        profiles = executor.load_profiles(profiles_path)
        payload = executor.run_job(
            plan_doc,
            profiles,
            expected_plan_sha,
            output_dir,
            run_label,
            True,
            False,
            int(max_actions),
            known_hosts,
            ssh_host_key_policy,
        )
        assert_no_secret_material(payload)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out = output_dir / (
            f"P01-Credentialed-Job_{timestamp}_{safe_label(run_label, 'run_label')}.json"
        )
        job_json, job_sha, job_hash = executor.write(out, payload)
    except Exception as exc:
        step["status"] = "failed"
        step["failed_at_utc"] = utc_now_iso()
        step["last_error"] = str(exc)[:1200]
        step["mode"] = "full"
        step["authorization_acknowledged"] = True
        _append_event(
            state,
            "credentialed_execution",
            "failed",
            {"mode": "full", "error": str(exc)[:500]},
        )
        _write_state(workspace, state)
        if isinstance(exc, RuntimeErrorSafe):
            raise
        raise RuntimeErrorSafe(str(exc)) from exc

    job_json = Path(job_json).resolve()
    job_sha = Path(job_sha).resolve()
    if not verify_sidecar(job_json):
        step["status"] = "failed"
        step["failed_at_utc"] = utc_now_iso()
        step["last_error"] = "FULL Credentialed Job SHA256 sidecar is missing or invalid"
        step["mode"] = "full"
        _append_event(state, "credentialed_execution", "failed", {"mode": "full"})
        _write_state(workspace, state)
        raise RuntimeErrorSafe(step["last_error"])

    job_doc = load_json(job_json)
    assert_no_secret_material(job_doc)
    metadata = job_doc.get("metadata") or {}
    summary = job_doc.get("summary") or {}
    if metadata.get("execution_mode") != "execute" or bool(metadata.get("auth_only")):
        raise RuntimeErrorSafe("managed v0.5e.3.2 executor must run execute=true, auth_only=false")
    if not bool(metadata.get("secret_resolution")) or not bool(metadata.get("authentication_attempts")):
        raise RuntimeErrorSafe(
            "FULL executor did not report expected secret resolution/authentication activity"
        )
    if int(metadata.get("concurrency") or 0) != 1:
        raise RuntimeErrorSafe("managed FULL executor must remain concurrency=1")

    target_files: List[Path] = []
    collected = 0
    for action in job_doc.get("actions") or []:
        if not isinstance(action, Mapping):
            continue
        if action.get("collection_status") == "collected":
            collected += 1
        value = action.get("target_result_file")
        if not value:
            continue
        target_path = Path(str(value)).expanduser().resolve()
        if not target_path.is_file() or not verify_sidecar(target_path):
            raise RuntimeErrorSafe(
                f"FULL target evidence missing or failed SHA256 verification: {target_path}"
            )
        assert_no_secret_material(load_json(target_path))
        target_files.append(target_path)

    actions_total = int(summary.get("actions_total") or 0)
    actions_ready = int(summary.get("actions_ready") or 0)
    completed = int(summary.get("completed") or 0)
    skipped = int(summary.get("skipped") or 0)
    auth_successes = int(summary.get("authentication_successes") or 0)
    auth_failures = int(summary.get("authentication_failures") or 0)
    open_circuits = int(summary.get("open_credential_circuits") or 0)

    state["artifacts"]["credentialed_execution_full"] = {
        "path": _relative_if_owned(workspace, job_json),
        "sha256_path": _relative_if_owned(workspace, job_sha),
        "sha256": job_hash,
        "source_plan_sha256": expected_plan_sha,
        "source_preview_sha256": preview_sha,
        "source_auth_sha256": auth_sha,
        "credential_profiles_sha256": current_profiles_sha,
        "actions_total": actions_total,
        "actions_ready": actions_ready,
        "completed": completed,
        "collected": collected,
        "skipped": skipped,
        "authentication_successes": auth_successes,
        "authentication_failures": auth_failures,
        "open_credential_circuits": open_circuits,
        "target_evidence_count": len(target_files),
        "mode": "full",
    }

    full_success = (
        actions_total > 0
        and actions_ready == actions_total
        and completed == actions_total
        and collected == actions_total
        and auth_successes == actions_total
        and auth_failures == 0
        and skipped == 0
        and open_circuits == 0
        and len(target_files) == actions_total
    )
    if not full_success:
        step.clear()
        step.update({
            "status": "failed",
            "failed_at_utc": utc_now_iso(),
            "managed_by": VERSION,
            "mode": "full",
            "authorization_acknowledged": True,
            "network_activity_performed": True,
            "secret_resolution": True,
            "authentication_attempts": True,
            "actions_total": actions_total,
            "actions_ready": actions_ready,
            "completed": completed,
            "collected": collected,
            "skipped": skipped,
            "authentication_successes": auth_successes,
            "authentication_failures": auth_failures,
            "open_credential_circuits": open_circuits,
            "last_error": "FULL execution completed with partial/failed target results",
        })
        _append_event(
            state,
            "credentialed_execution",
            "failed",
            {
                "mode": "full",
                "actions_total": actions_total,
                "completed": completed,
                "collected": collected,
                "authentication_failures": auth_failures,
                "skipped": skipped,
            },
        )
        _write_state(workspace, state)
        raise RuntimeErrorSafe(
            "FULL execution produced partial/failed results; evidence was preserved. "
            "Review it before an explicit --force-full-retry."
        )

    step.clear()
    step.update({
        "status": "full_completed",
        "completed_at_utc": utc_now_iso(),
        "managed_by": VERSION,
        "mode": "full",
        "authorization_acknowledged": True,
        "network_activity_performed": True,
        "secret_resolution": True,
        "authentication_attempts": True,
        "actions_total": actions_total,
        "completed": completed,
        "collected": collected,
        "authentication_successes": auth_successes,
        "authentication_failures": auth_failures,
        "open_credential_circuits": open_circuits,
    })
    _append_event(
        state,
        "credentialed_execution",
        "full_completed",
        {
            "actions_total": actions_total,
            "completed": completed,
            "collected": collected,
            "authentication_successes": auth_successes,
        },
    )
    _write_state(workspace, state)
    return {
        "status": "full_completed",
        "job_json": str(job_json),
        "job_sha256": job_hash,
        "actions_total": actions_total,
        "completed": completed,
        "collected": collected,
        "authentication_successes": auth_successes,
        "authentication_failures": auth_failures,
        "open_credential_circuits": open_circuits,
        "network_activity_performed": True,
        "secret_resolution_performed": True,
        "authentication_attempts_performed": True,
    }


@locked_workspace
def run_asset_resolver(
    workspace: Path,
    *,
    force_reresolve: bool = False,
) -> Dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    state = _load_state(workspace)
    state["runtime_version"] = VERSION
    state.setdefault("security", {})["asset_resolver_managed_in_this_version"] = True
    step = state["steps"]["asset_resolver"]

    if step.get("status") == "completed" and not force_reresolve:
        existing = (state.get("artifacts") or {}).get("asset_resolver") or {}
        path_value = existing.get("path")
        if path_value:
            path = _workspace_owned_path(workspace, str(path_value)).resolve()
            if path.is_file() and digest_file(path) == existing.get("sha256"):
                return {
                    "status": "already_complete",
                    "resolver_json": str(path),
                    "resolver_sha256": existing.get("sha256"),
                    "network_assets_seen": existing.get("network_assets_seen"),
                    "credentialed_observations_seen": existing.get("credentialed_observations_seen"),
                    "logical_assets_resolved": existing.get("logical_assets_resolved"),
                    "unresolved_observations": existing.get("unresolved_observations"),
                    "ambiguous_correlations": existing.get("ambiguous_correlations"),
                    "assets_with_conflicts": existing.get("assets_with_conflicts"),
                    "network_activity_performed": False,
                    "secret_resolution_performed": False,
                    "authentication_attempts_performed": False,
                }
        raise RuntimeErrorSafe(
            "Asset Resolver is completed but recorded evidence is missing or changed"
        )

    if force_reresolve:
        downstream = ("evidence_bundle", "upload")
        completed = [
            name
            for name in downstream
            if (state.get("steps", {}).get(name) or {}).get("status") == "completed"
        ]
        if completed:
            raise RuntimeErrorSafe(
                "refusing --force-reresolve because downstream completed steps would become stale: "
                + ", ".join(completed)
            )

    execution_step = (state.get("steps") or {}).get("credentialed_execution") or {}
    if execution_step.get("status") != "full_completed":
        raise RuntimeErrorSafe(
            "managed Asset Resolver requires credentialed_execution: full_completed"
        )

    network = (state.get("artifacts") or {}).get("network_discovery") or {}
    network_value = network.get("path")
    network_sha = network.get("sha256")
    if not network_value or not network_sha:
        raise RuntimeErrorSafe("Network Discovery artifact metadata is incomplete")
    network_path = _workspace_owned_path(workspace, str(network_value)).resolve()
    if not network_path.is_file() or digest_file(network_path) != network_sha:
        raise RuntimeErrorSafe(
            "Network Discovery artifact is missing or its SHA256 no longer matches state"
        )
    if not verify_sidecar(network_path):
        raise RuntimeErrorSafe("Network Discovery SHA256 sidecar is missing or invalid")

    full = (state.get("artifacts") or {}).get("credentialed_execution_full") or {}
    full_value = full.get("path")
    full_sha = full.get("sha256")
    if not full_value or not full_sha:
        raise RuntimeErrorSafe("FULL credentialed execution artifact metadata is incomplete")
    full_path = _workspace_owned_path(workspace, str(full_value)).resolve()
    if not full_path.is_file() or digest_file(full_path) != full_sha:
        raise RuntimeErrorSafe(
            "FULL credentialed job is missing or its SHA256 no longer matches state"
        )
    if not verify_sidecar(full_path):
        raise RuntimeErrorSafe("FULL credentialed job SHA256 sidecar is missing or invalid")

    full_doc = load_json(full_path)
    assert_no_secret_material(full_doc)
    metadata = full_doc.get("metadata") or {}
    if metadata.get("execution_mode") != "execute" or bool(metadata.get("auth_only")):
        raise RuntimeErrorSafe(
            "recorded credentialed job is not a validated FULL execution"
        )

    evidence_paths: List[Path] = []
    workspace_root = workspace.resolve()
    for action in full_doc.get("actions") or []:
        if not isinstance(action, Mapping):
            continue
        if action.get("execution_status") != "completed":
            continue
        if action.get("collection_status") != "collected":
            continue
        value = action.get("target_result_file")
        if not value:
            raise RuntimeErrorSafe(
                "FULL job contains a collected action without target_result_file"
            )
        target = Path(str(value)).expanduser().resolve()
        if not target.is_relative_to(workspace_root):
            raise RuntimeErrorSafe(
                f"FULL target evidence is outside the runtime workspace: {target}"
            )
        if not target.is_file() or not verify_sidecar(target):
            raise RuntimeErrorSafe(
                f"FULL target evidence missing or failed SHA256 verification: {target}"
            )
        expected = action.get("target_result_sha256")
        if expected and digest_file(target) != str(expected).lower():
            raise RuntimeErrorSafe(
                f"FULL target evidence SHA256 differs from aggregate job: {target}"
            )
        assert_no_secret_material(load_json(target))
        evidence_paths.append(target)

    expected_target_count = int(full.get("target_evidence_count") or 0)
    if not evidence_paths:
        raise RuntimeErrorSafe("FULL job contains no collected target evidence")
    if expected_target_count and len(evidence_paths) != expected_target_count:
        raise RuntimeErrorSafe(
            "FULL target evidence count does not match runtime state"
        )

    manifest_path: Optional[Path] = None
    manifest_ref = (state.get("source_refs") or {}).get("assessment_manifest")
    if manifest_ref:
        manifest_path = Path(str(manifest_ref)).expanduser().resolve()
        if not manifest_path.is_file():
            raise RuntimeErrorSafe(f"assessment manifest not found: {manifest_path}")

    resolver = _load_component(
        "asset_resolver/P01_Asset_Resolver.py",
        "p01_runtime_asset_resolver",
    )
    run_label = f"{safe_label(state['run_id'], 'run_id')}-ASSET-RESOLVER"

    step.clear()
    step.update({
        "status": "running",
        "started_at_utc": utc_now_iso(),
        "managed_by": VERSION,
    })
    _append_event(
        state,
        "asset_resolver",
        "started",
        {
            "network_sha256": network_sha,
            "full_job_sha256": full_sha,
            "credentialed_evidence_count": len(evidence_paths),
        },
    )
    _write_state(workspace, state)

    try:
        payload = resolver.resolve(
            network_path,
            evidence_paths,
            manifest_path=manifest_path,
            require_evidence_sidecars=True,
        )
        assert_no_secret_material(payload)
        out, sha = resolver.write_output(workspace / "resolved", run_label, payload)
    except Exception as exc:
        step["status"] = "failed"
        step["failed_at_utc"] = utc_now_iso()
        step["last_error"] = str(exc)[:1200]
        _append_event(
            state,
            "asset_resolver",
            "failed",
            {"error": str(exc)[:500]},
        )
        _write_state(workspace, state)
        if isinstance(exc, RuntimeErrorSafe):
            raise
        raise RuntimeErrorSafe(str(exc)) from exc

    out = Path(out).resolve()
    sha = Path(sha).resolve()
    if not out.is_relative_to(workspace_root):
        raise RuntimeErrorSafe("Asset Resolver output escaped the runtime workspace")
    if not verify_sidecar(out):
        step["status"] = "failed"
        step["failed_at_utc"] = utc_now_iso()
        step["last_error"] = "Asset Resolver output SHA256 sidecar is missing or invalid"
        _append_event(state, "asset_resolver", "failed")
        _write_state(workspace, state)
        raise RuntimeErrorSafe(step["last_error"])

    resolved_doc = load_json(out)
    assert_no_secret_material(resolved_doc)
    resolver_meta = resolved_doc.get("metadata") or {}
    if (
        bool(resolver_meta.get("network_access_performed"))
        or bool(resolver_meta.get("secret_resolution"))
        or bool(resolver_meta.get("authentication_attempts"))
    ):
        raise RuntimeErrorSafe(
            "Asset Resolver unexpectedly reported network/secret/authentication activity"
        )
    summary = resolved_doc.get("summary") or {}
    network_assets = int(summary.get("network_assets_seen") or 0)
    credentialed_seen = int(summary.get("credentialed_observations_seen") or 0)
    logical_assets = int(summary.get("logical_assets_resolved") or 0)
    unresolved = int(summary.get("unresolved_observations") or 0)
    ambiguous = int(summary.get("ambiguous_correlations") or 0)
    conflicts = int(summary.get("assets_with_conflicts") or 0)

    state["artifacts"]["asset_resolver"] = {
        "path": _relative_if_owned(workspace, out),
        "sha256_path": _relative_if_owned(workspace, sha),
        "sha256": digest_file(out),
        "source_network_sha256": network_sha,
        "source_full_job_sha256": full_sha,
        "source_full_target_sha256": sorted(digest_file(p) for p in evidence_paths),
        "assessment_manifest_sha256": (
            digest_file(manifest_path) if manifest_path is not None else None
        ),
        "network_assets_seen": network_assets,
        "credentialed_observations_seen": credentialed_seen,
        "logical_assets_resolved": logical_assets,
        "unresolved_observations": unresolved,
        "ambiguous_correlations": ambiguous,
        "assets_with_conflicts": conflicts,
    }

    step.clear()
    step.update({
        "status": "completed",
        "completed_at_utc": utc_now_iso(),
        "managed_by": VERSION,
        "network_activity_performed": False,
        "secret_resolution": False,
        "authentication_attempts": False,
        "network_assets_seen": network_assets,
        "credentialed_observations_seen": credentialed_seen,
        "logical_assets_resolved": logical_assets,
        "unresolved_observations": unresolved,
        "ambiguous_correlations": ambiguous,
        "assets_with_conflicts": conflicts,
    })
    _append_event(
        state,
        "asset_resolver",
        "completed",
        {
            "network_assets_seen": network_assets,
            "credentialed_observations_seen": credentialed_seen,
            "logical_assets_resolved": logical_assets,
            "unresolved_observations": unresolved,
            "ambiguous_correlations": ambiguous,
            "assets_with_conflicts": conflicts,
        },
    )
    _write_state(workspace, state)
    return {
        "status": "completed",
        "resolver_json": str(out),
        "resolver_sha256": digest_file(out),
        "network_assets_seen": network_assets,
        "credentialed_observations_seen": credentialed_seen,
        "logical_assets_resolved": logical_assets,
        "unresolved_observations": unresolved,
        "ambiguous_correlations": ambiguous,
        "assets_with_conflicts": conflicts,
        "network_activity_performed": False,
        "secret_resolution_performed": False,
        "authentication_attempts_performed": False,
    }


def _workspace_bundle_inputs(
    workspace: Path,
    state: Mapping[str, Any],
    *,
    require_sidecars: bool,
) -> Tuple[Path, List[Path], Optional[Path], Path, Dict[str, Any]]:
    if not require_sidecars:
        raise RuntimeErrorSafe(
            "workspace-driven export requires source SHA256 sidecars"
        )

    steps = state.get("steps") or {}
    for name, expected in (
        ("network_discovery", "completed"),
        ("credentialed_execution", "full_completed"),
        ("asset_resolver", "completed"),
    ):
        actual = (steps.get(name) or {}).get("status")
        if actual != expected:
            raise RuntimeErrorSafe(
                f"workspace-driven export requires {name}: {expected}; got {actual!r}"
            )

    workspace_root = workspace.resolve()
    artifacts = state.get("artifacts") or {}

    network_info = artifacts.get("network_discovery") or {}
    network_value = network_info.get("path")
    network_sha = network_info.get("sha256")
    if not network_value or not network_sha:
        raise RuntimeErrorSafe("Network Discovery artifact metadata is incomplete")
    network = _workspace_owned_path(workspace, str(network_value)).resolve()
    if not network.is_relative_to(workspace_root):
        raise RuntimeErrorSafe("workspace Network Discovery artifact is outside the workspace")
    if (
        not network.is_file()
        or digest_file(network) != str(network_sha).lower()
        or not verify_sidecar(network)
    ):
        raise RuntimeErrorSafe(
            "workspace Network Discovery artifact is missing or failed SHA256 verification"
        )

    full_info = artifacts.get("credentialed_execution_full") or {}
    full_value = full_info.get("path")
    full_sha = full_info.get("sha256")
    if not full_value or not full_sha:
        raise RuntimeErrorSafe("FULL credentialed execution artifact metadata is incomplete")
    full_job = _workspace_owned_path(workspace, str(full_value)).resolve()
    if not full_job.is_relative_to(workspace_root):
        raise RuntimeErrorSafe("workspace FULL job artifact is outside the workspace")
    if (
        not full_job.is_file()
        or digest_file(full_job) != str(full_sha).lower()
        or not verify_sidecar(full_job)
    ):
        raise RuntimeErrorSafe(
            "workspace FULL job artifact is missing or failed SHA256 verification"
        )

    full_doc = load_json(full_job)
    assert_no_secret_material(full_doc)
    full_meta = full_doc.get("metadata") or {}
    if full_meta.get("execution_mode") != "execute" or bool(full_meta.get("auth_only")):
        raise RuntimeErrorSafe(
            "recorded credentialed job is not a validated FULL execution"
        )

    credentialed: List[Path] = []
    target_hashes: List[str] = []
    for action in full_doc.get("actions") or []:
        if not isinstance(action, Mapping):
            continue
        if action.get("execution_status") != "completed":
            continue
        if action.get("collection_status") != "collected":
            continue
        value = action.get("target_result_file")
        if not value:
            raise RuntimeErrorSafe(
                "FULL job contains a collected action without target_result_file"
            )
        target = Path(str(value)).expanduser().resolve()
        if not target.is_relative_to(workspace_root):
            raise RuntimeErrorSafe(
                f"FULL target evidence is outside the runtime workspace: {target}"
            )
        if not target.is_file() or not verify_sidecar(target):
            raise RuntimeErrorSafe(
                f"FULL target evidence missing or failed SHA256 verification: {target}"
            )
        actual_sha = digest_file(target)
        expected_sha = action.get("target_result_sha256")
        if expected_sha and actual_sha != str(expected_sha).lower():
            raise RuntimeErrorSafe(
                f"FULL target evidence SHA256 differs from aggregate job: {target}"
            )
        assert_no_secret_material(load_json(target))
        credentialed.append(target)
        target_hashes.append(actual_sha)

    expected_target_count = int(full_info.get("target_evidence_count") or 0)
    if not credentialed:
        raise RuntimeErrorSafe("FULL job contains no collected target evidence")
    if expected_target_count and len(credentialed) != expected_target_count:
        raise RuntimeErrorSafe(
            "FULL target evidence count does not match runtime state"
        )

    resolver_info = artifacts.get("asset_resolver") or {}
    resolver_value = resolver_info.get("path")
    resolver_sha = resolver_info.get("sha256")
    if not resolver_value or not resolver_sha:
        raise RuntimeErrorSafe("Asset Resolver artifact metadata is incomplete")
    resolver_path = _workspace_owned_path(workspace, str(resolver_value)).resolve()
    if not resolver_path.is_relative_to(workspace_root):
        raise RuntimeErrorSafe("workspace Asset Resolver artifact is outside the workspace")
    if (
        not resolver_path.is_file()
        or digest_file(resolver_path) != str(resolver_sha).lower()
        or not verify_sidecar(resolver_path)
    ):
        raise RuntimeErrorSafe(
            "workspace Asset Resolver artifact is missing or failed SHA256 verification"
        )
    if (
        resolver_info.get("source_network_sha256")
        and resolver_info.get("source_network_sha256") != network_sha
    ):
        raise RuntimeErrorSafe(
            "Asset Resolver artifact is not bound to the current Network Discovery"
        )
    if (
        resolver_info.get("source_full_job_sha256")
        and resolver_info.get("source_full_job_sha256") != full_sha
    ):
        raise RuntimeErrorSafe(
            "Asset Resolver artifact is not bound to the current FULL job"
        )
    resolver_target_hashes = resolver_info.get("source_full_target_sha256")
    if resolver_target_hashes:
        if sorted(str(x).lower() for x in resolver_target_hashes) != sorted(target_hashes):
            raise RuntimeErrorSafe(
                "Asset Resolver artifact is not bound to the current FULL target set"
            )

    manifest_path: Optional[Path] = None
    manifest_sha: Optional[str] = None
    manifest_ref = (state.get("source_refs") or {}).get("assessment_manifest")
    if manifest_ref:
        manifest_path = Path(str(manifest_ref)).expanduser().resolve()
        if not manifest_path.is_file():
            raise RuntimeErrorSafe(f"assessment manifest not found: {manifest_path}")
        manifest_sha = digest_file(manifest_path)
        bound_manifest_sha = resolver_info.get("assessment_manifest_sha256")
        if bound_manifest_sha and manifest_sha != str(bound_manifest_sha).lower():
            raise RuntimeErrorSafe(
                "Assessment Manifest changed after Asset Resolver completion"
            )
        assert_no_secret_material(load_json(manifest_path))

    bindings = {
        "selection_mode": "workspace_state",
        "network_sha256": str(network_sha).lower(),
        "full_job_sha256": str(full_sha).lower(),
        "full_target_sha256": sorted(target_hashes),
        "asset_resolver_sha256": str(resolver_sha).lower(),
        "assessment_manifest_sha256": manifest_sha,
    }
    return network, credentialed, manifest_path, resolver_path, bindings


@locked_workspace
def export_bundle(
    workspace: Path,
    network: Optional[Path] = None,
    evidence_dir: Optional[Path] = None,
    evidence_run_label: Optional[str] = None,
    asset_resolver: Optional[Path] = None,
    manifest: Optional[Path] = None,
    require_sidecars: bool = True,
    force_rebuild: bool = False,
) -> Dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    state = _load_state(workspace)
    state["runtime_version"] = VERSION
    state.setdefault("security", {})[
        "workspace_driven_bundle_managed_in_this_version"
    ] = True
    step = state["steps"]["evidence_bundle"]

    if step.get("status") == "completed" and not force_rebuild:
        existing = state.get("artifacts", {}).get("evidence_bundle", {})
        bundle_value = existing.get("path")
        if bundle_value:
            bundle_path = _workspace_owned_path(workspace, bundle_value)
            if bundle_path.is_file() and digest_file(bundle_path) == existing.get("sha256"):
                return {
                    "status": "already_complete",
                    "bundle": str(bundle_path),
                    "bundle_id": existing.get("bundle_id"),
                    "bundle_sha256": existing.get("sha256"),
                    "artifact_count": existing.get("artifact_count"),
                    "credentialed_evidence_count": existing.get(
                        "credentialed_evidence_count"
                    ),
                    "selection_mode": existing.get("selection_mode"),
                    "network_activity_performed": False,
                    "secret_resolution_performed": False,
                    "authentication_attempts_performed": False,
                }
        raise RuntimeErrorSafe(
            "bundle step is completed but recorded artifact is missing or changed; "
            "use --force-rebuild only after review"
        )

    workspace_driven = (
        network is None
        and evidence_dir is None
        and asset_resolver is None
        and evidence_run_label is None
        and manifest is None
    )

    bindings: Dict[str, Any]
    full_job_for_binding: Optional[Path] = None
    if workspace_driven:
        (
            network_path,
            credentialed,
            manifest_path,
            asset_resolver_path,
            bindings,
        ) = _workspace_bundle_inputs(
            workspace,
            state,
            require_sidecars=require_sidecars,
        )
        full_info = (state.get("artifacts") or {}).get(
            "credentialed_execution_full"
        ) or {}
        full_value = full_info.get("path")
        if full_value:
            full_job_for_binding = _workspace_owned_path(
                workspace, str(full_value)
            ).resolve()
        selection_mode = "workspace_state"
    else:
        if network is None or evidence_dir is None:
            raise RuntimeErrorSafe(
                "explicit export requires both --network and --evidence-dir; "
                "or omit all evidence-path options for workspace-driven export"
            )
        network_path = network.expanduser().resolve()
        evidence_dir = evidence_dir.expanduser().resolve()
        manifest_path = manifest.expanduser().resolve() if manifest else None
        if manifest_path is None:
            ref = state.get("source_refs", {}).get("assessment_manifest")
            manifest_path = Path(ref).expanduser().resolve() if ref else None
        asset_resolver_path = (
            asset_resolver.expanduser().resolve()
            if asset_resolver is not None
            else None
        )

        bundle_mod = _load_component(
            "evidence_bundle/P01_Evidence_Bundle.py",
            "p01_runtime_evidence_bundle",
        )
        credentialed = bundle_mod.collect_credentialed_paths(
            evidence_dir,
            evidence_run_label,
        )
        if not credentialed:
            raise RuntimeErrorSafe(
                "no credentialed evidence files matched the requested run"
            )
        bindings = {
            "selection_mode": "explicit_paths",
            "network_sha256": digest_file(network_path) if network_path.is_file() else None,
            "full_target_sha256": [
                digest_file(path) for path in credentialed if path.is_file()
            ],
            "asset_resolver_sha256": (
                digest_file(asset_resolver_path)
                if asset_resolver_path is not None and asset_resolver_path.is_file()
                else None
            ),
            "assessment_manifest_sha256": (
                digest_file(manifest_path)
                if manifest_path is not None and manifest_path.is_file()
                else None
            ),
        }
        selection_mode = "explicit_paths"

    bundle_mod = _load_component(
        "evidence_bundle/P01_Evidence_Bundle.py",
        "p01_runtime_evidence_bundle",
    )

    output = workspace / "bundle" / (
        f"{safe_label(state['assessment_id'], 'assessment_id')}_"
        f"{safe_label(state['run_id'], 'run_id')}.p01bundle"
    )

    try:
        result = bundle_mod.create_bundle(
            output=output,
            assessment_id=state["assessment_id"],
            run_id=state["run_id"],
            node_id=state["node_id"],
            network_path=network_path,
            credentialed_paths=credentialed,
            manifest_path=manifest_path,
            asset_resolver_path=asset_resolver_path,
            require_evidence_sidecars=require_sidecars,
        )
        validation = bundle_mod.validate_bundle(output)
    except Exception as exc:
        step["status"] = "failed"
        step["failed_at_utc"] = utc_now_iso()
        step["last_error"] = str(exc)[:1200]
        step["selection_mode"] = selection_mode
        _append_event(state, "export", "failed", {"error": str(exc)[:500]})
        _write_state(workspace, state)
        raise RuntimeErrorSafe(str(exc)) from exc

    if not bool(validation.get("valid")):
        step["status"] = "failed"
        step["failed_at_utc"] = utc_now_iso()
        step["last_error"] = "Evidence Bundle validation did not return valid=true"
        step["selection_mode"] = selection_mode
        _append_event(state, "export", "failed", {"error": step["last_error"]})
        _write_state(workspace, state)
        raise RuntimeErrorSafe(step["last_error"])

    inputs: Dict[str, Any] = {
        "selection_mode": selection_mode,
        "network_discovery": _artifact_ref(network_path),
        "credentialed_evidence": [_artifact_ref(path) for path in credentialed],
        "input_bindings": bindings,
    }
    if full_job_for_binding is not None:
        inputs["credentialed_execution_full_job"] = _artifact_ref(
            full_job_for_binding
        )
    if manifest_path:
        inputs["assessment_manifest"] = _artifact_ref(manifest_path)
    if asset_resolver_path:
        inputs["asset_resolver"] = _artifact_ref(asset_resolver_path)

    step.clear()
    step.update({
        "status": "completed",
        "completed_at_utc": utc_now_iso(),
        "managed_by": VERSION,
        "selection_mode": selection_mode,
        "source_sidecars_required": bool(require_sidecars),
        "input_count": 1 + len(credentialed)
        + (1 if manifest_path else 0)
        + (1 if asset_resolver_path else 0),
        "network_activity_performed": False,
        "secret_resolution": False,
        "authentication_attempts": False,
    })

    state["artifacts"]["export_inputs"] = inputs
    state["artifacts"]["evidence_bundle"] = {
        "path": _relative_if_owned(workspace, output),
        "sha256_path": _relative_if_owned(
            workspace,
            output.with_suffix(output.suffix + ".sha256"),
        ),
        "sha256": result["bundle_sha256"],
        "bundle_id": result["bundle_id"],
        "artifact_count": result["artifact_count"],
        "credentialed_evidence_count": result["credentialed_evidence_count"],
        "validated": bool(validation.get("valid")),
        "selection_mode": selection_mode,
    }
    _append_event(
        state,
        "export",
        "completed",
        {
            "bundle_id": result["bundle_id"],
            "artifact_count": result["artifact_count"],
            "selection_mode": selection_mode,
        },
    )
    _write_state(workspace, state)
    return {
        "status": "completed",
        "selection_mode": selection_mode,
        "network_activity_performed": False,
        "secret_resolution_performed": False,
        "authentication_attempts_performed": False,
        **result,
        "validation": validation,
    }


@locked_workspace
def upload_bundle(
    workspace: Path,
    server_url: Optional[str] = None,
    ca_cert: Optional[Path] = None,
    client_cert: Optional[Path] = None,
    client_key: Optional[Path] = None,
    timeout: float = 30.0,
    max_retries: int = 2,
    force_resend: bool = False,
) -> Dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    state = _load_state(workspace)
    state["runtime_version"] = VERSION
    state.setdefault("security", {})["zero_input_upload_resume_supported"] = True

    bundle_info = state.get("artifacts", {}).get("evidence_bundle")
    if state["steps"]["evidence_bundle"].get("status") != "completed" or not bundle_info:
        raise RuntimeErrorSafe("evidence bundle must be completed before upload")

    upload_step = state["steps"]["upload"]
    if upload_step.get("status") == "completed" and not force_resend:
        return {
            "status": "already_complete",
            "server_status": upload_step.get("server_status"),
            "http_status": upload_step.get("http_status"),
            "receipt": state.get("artifacts", {}).get("upload_receipt"),
            "network_activity_performed": False,
            "secret_resolution_performed": False,
            "authentication_attempts_performed": False,
        }

    missing = []
    if not server_url:
        missing.append("--server-url")
    if ca_cert is None:
        missing.append("--ca-cert")
    if client_cert is None:
        missing.append("--client-cert")
    if client_key is None:
        missing.append("--client-key")
    if missing:
        reason = (
            "forced resend"
            if force_resend and upload_step.get("status") == "completed"
            else "live connected upload"
        )
        raise RuntimeErrorSafe(
            f"{reason} requires explicit transport inputs: " + ", ".join(missing)
        )

    bundle = _workspace_owned_path(workspace, str(bundle_info["path"]))
    if (
        not bundle.is_file()
        or digest_file(bundle) != bundle_info.get("sha256")
        or not verify_sidecar(bundle)
    ):
        raise RuntimeErrorSafe(
            "recorded evidence bundle is missing or failed SHA256 verification"
        )

    parsed = urlparse(server_url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise RuntimeErrorSafe("connected upload requires a valid https:// server URL")
    for label, path in (
        ("CA certificate", ca_cert),
        ("client certificate", client_cert),
        ("client private key", client_key),
    ):
        if not path.is_file():
            raise RuntimeErrorSafe(f"{label} not found: {path}")

    uploader = _load_component(
        "connected/P01_Discovery_Node_Uploader.py",
        "p01_runtime_connected_uploader",
    )

    try:
        manifest = uploader.bundle_manifest(bundle)
        if str(manifest.get("node_id") or "") != str(state["node_id"]):
            raise RuntimeErrorSafe(
                "bundle node_id does not match workspace node_id"
            )

        result = uploader.upload_with_retries(
            server_url,
            bundle,
            state["node_id"],
            ca_cert,
            client_cert,
            client_key,
            timeout=timeout,
            max_retries=max_retries,
        )
        receipt, receipt_sha = uploader.write_receipt(
            workspace / "receipts",
            state["node_id"],
            bundle,
            server_url,
            result,
        )
    except Exception as exc:
        upload_step["status"] = "failed"
        upload_step["failed_at_utc"] = utc_now_iso()
        upload_step["last_error"] = str(exc)[:1200]
        upload_step["automatic_retry_of_completed_step"] = False
        _append_event(state, "upload", "failed", {"error": str(exc)[:500]})
        _write_state(workspace, state)
        raise RuntimeErrorSafe(str(exc)) from exc

    response = result.get("server_response") or {}
    upload_step.clear()
    upload_step.update({
        "status": "completed",
        "completed_at_utc": utc_now_iso(),
        "managed_by": VERSION,
        "server_url": server_url,
        "http_status": result.get("http_status"),
        "server_status": response.get("status"),
        "semantic_match": response.get("semantic_match"),
        "authenticated_node_id": response.get("authenticated_node_id"),
        "attempts": result.get("attempts"),
        "network_access_performed": True,
        "tls_server_verification": True,
        "mtls_client_certificate_used": True,
        "automatic_retry_of_completed_step": False,
    })
    state["artifacts"]["upload_receipt"] = {
        "path": _relative_if_owned(workspace, receipt),
        "sha256_path": _relative_if_owned(workspace, receipt_sha),
        "sha256": digest_file(receipt),
    }
    _append_event(
        state,
        "upload",
        "completed",
        {
            "http_status": result.get("http_status"),
            "server_status": response.get("status"),
            "attempts": result.get("attempts"),
        },
    )
    _write_state(workspace, state)
    return {
        "status": "completed",
        "result": result,
        "receipt": str(receipt),
        "receipt_sha256": str(receipt_sha),
        "network_activity_performed": True,
        "secret_resolution_performed": False,
        "authentication_attempts_performed": False,
    }


def next_action(state: Mapping[str, Any]) -> str:
    steps = state.get("steps") or {}
    network_status = (steps.get("network_discovery") or {}).get("status")
    if network_status in {"pending", "failed"}:
        return "run_network_discovery"
    if network_status == "completed":
        plan_status = (steps.get("credential_plan") or {}).get("status")
        if plan_status in {"pending", "failed", "external_required"}:
            return "run_credential_plan"
        if plan_status == "completed":
            execution_status = (steps.get("credentialed_execution") or {}).get("status")
            if execution_status in {"pending", "external_required"}:
                return "run_credentialed_execution_dry_run"
            if execution_status == "failed":
                mode = (steps.get("credentialed_execution") or {}).get("mode")
                if mode == "auth_only":
                    return "review_auth_failure_then_retry_explicitly"
                if mode == "full":
                    return "review_full_failure_then_retry_explicitly"
                return "run_credentialed_execution_dry_run"
            if execution_status == "preview_completed":
                return "run_credentialed_execution_auth_only"
            if execution_status == "auth_validated":
                return "run_credentialed_execution_full"
            if execution_status == "full_completed":
                resolver_status = (steps.get("asset_resolver") or {}).get("status")
                if resolver_status in {"pending", "failed", "external_required"}:
                    return "run_asset_resolver"
                if resolver_status == "completed":
                    pass
    if (steps.get("evidence_bundle") or {}).get("status") != "completed":
        return "export"
    if (steps.get("upload") or {}).get("status") == "failed":
        return "review_upload_failure_then_retry_explicitly"
    if (steps.get("upload") or {}).get("status") != "completed":
        return "upload_or_copy_bundle_offline"
    return "complete"


def status(workspace: Path) -> Dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    state = _load_state(workspace)
    artifact_checks: Dict[str, Any] = {}
    for name, info in (state.get("artifacts") or {}).items():
        if not isinstance(info, Mapping) or "path" not in info:
            continue
        path = _workspace_owned_path(workspace, str(info["path"]))
        expected = info.get("sha256")
        artifact_checks[name] = {
            "exists": path.is_file(),
            "sha256_match": (
                path.is_file() and bool(expected) and digest_file(path) == expected
            ) if expected else None,
            "path": str(path),
        }

    return {
        "runtime": {"name": NAME, "version": VERSION},
        "workspace": str(workspace),
        "state_integrity": verify_sidecar(_state_path(workspace)),
        "assessment_id": state.get("assessment_id"),
        "run_id": state.get("run_id"),
        "node_id": state.get("node_id"),
        "steps": state.get("steps"),
        "artifact_checks": artifact_checks,
        "next_action": next_action(state),
        "security": state.get("security"),
    }


def _print_doctor(result: Mapping[str, Any]) -> None:
    print(f"{DISPLAY_NAME} v{VERSION}")
    print(f"Ready: {result.get('ready')}")
    for item in result.get("checks") or []:
        mark = "PASS" if item.get("ok") else "FAIL"
        print(f"[{mark}] {item.get('name')}: {item.get('detail')}")
    print("Network activity performed: false")
    print("Secret resolution performed: false")
    print("Authentication attempts performed: false")


def _print_status(result: Mapping[str, Any]) -> None:
    print(f"{DISPLAY_NAME} v{VERSION}")
    print(f"Workspace: {result.get('workspace')}")
    print(f"Assessment: {result.get('assessment_id')}")
    print(f"Run: {result.get('run_id')}")
    print(f"Node: {result.get('node_id')}")
    print(f"State integrity: {result.get('state_integrity')}")
    print("Steps:")
    steps = result.get("steps") or {}
    for step_name in STEP_ORDER:
        item = steps.get(step_name) or {}
        print(f"  {step_name}: {item.get('status')}")
    print(f"Next action: {result.get('next_action')}")


def cli(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="P01_Discovery_Node.py",
        description=f"{DISPLAY_NAME} v{VERSION}",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    doctor_p = sub.add_parser(
        "doctor",
        help="Check portable runtime prerequisites without scanning/authentication",
    )
    doctor_p.add_argument("--workspace-root", default="./canca-runs")
    doctor_p.add_argument("--server-url")
    doctor_p.add_argument("--ca-cert")
    doctor_p.add_argument("--client-cert")
    doctor_p.add_argument("--client-key")
    doctor_p.add_argument("--json", action="store_true")

    init_p = sub.add_parser("init", help="Create an isolated assessment run workspace")
    init_p.add_argument("--workspace-root", default="./canca-runs")
    init_p.add_argument("--assessment-id", required=True)
    init_p.add_argument("--run-id", required=True)
    init_p.add_argument("--node-id", required=True)
    init_p.add_argument("--manifest")
    init_p.add_argument("--profiles")

    status_p = sub.add_parser("status", help="Show checkpoint/artifact status")
    status_p.add_argument("--workspace", required=True)
    status_p.add_argument("--json", action="store_true")

    run_p = sub.add_parser(
        "run",
        help="Advance managed runtime through FULL execution and offline Asset Resolver",
    )
    run_p.add_argument("--workspace", required=True)
    run_p.add_argument("--target", action="append", default=[])
    run_p.add_argument("--exclude", action="append", default=[])
    run_p.add_argument("--profile", choices=["safe", "standard"], default="safe")
    run_p.add_argument("--ports")
    run_p.add_argument("--timeout", type=float, default=0.35)
    run_p.add_argument("--workers", type=int, default=64)
    run_p.add_argument("--max-hosts", type=int, default=2048)
    run_p.add_argument("--allow-large-scope", action="store_true")
    run_p.add_argument("--disable-ssdp", action="store_true")
    run_p.add_argument("--ack-authorized-scan", action="store_true")
    run_p.add_argument("--force-rescan", action="store_true")
    run_p.add_argument("--max-candidates", type=int, default=2)
    run_p.add_argument("--force-replan", action="store_true")
    run_p.add_argument("--max-actions", type=int, default=25)
    run_p.add_argument("--execute", action="store_true")
    run_p.add_argument("--auth-only", action="store_true")
    run_p.add_argument("--full-enrichment", action="store_true")
    run_p.add_argument("--ack-authorized-access", action="store_true")
    run_p.add_argument("--force-auth-retry", action="store_true")
    run_p.add_argument("--force-full-retry", action="store_true")
    run_p.add_argument("--force-reresolve", action="store_true")
    run_p.add_argument(
        "--ssh-host-key-policy",
        choices=["strict", "tofu"],
        default="strict",
    )
    run_p.add_argument(
        "--ssh-known-hosts",
        default=str(Path.home() / ".orizonit" / "p01" / "known_hosts"),
    )

    export_p = sub.add_parser(
        "export",
        help="Create a validated .p01bundle from workspace state or explicit evidence paths",
    )
    export_p.add_argument("--workspace", required=True)
    export_p.add_argument("--network")
    export_p.add_argument("--evidence-dir")
    export_p.add_argument("--evidence-run-label")
    export_p.add_argument("--asset-resolver")
    export_p.add_argument("--manifest")
    export_p.add_argument("--allow-missing-sidecars", action="store_true")
    export_p.add_argument("--force-rebuild", action="store_true")

    upload_p = sub.add_parser(
        "upload",
        help="Upload the completed bundle using the validated v0.5d mTLS transport",
    )
    upload_p.add_argument("--workspace", required=True)
    upload_p.add_argument("--server-url")
    upload_p.add_argument("--ca-cert")
    upload_p.add_argument("--client-cert")
    upload_p.add_argument("--client-key")
    upload_p.add_argument("--timeout", type=float, default=30.0)
    upload_p.add_argument("--max-retries", type=int, default=2)
    upload_p.add_argument(
        "--force-resend",
        action="store_true",
        help="Explicitly resend a bundle after a completed upload",
    )

    args = parser.parse_args(argv)

    try:
        if args.command == "doctor":
            result = doctor(
                Path(args.workspace_root),
                args.server_url,
                Path(args.ca_cert) if args.ca_cert else None,
                Path(args.client_cert) if args.client_cert else None,
                Path(args.client_key) if args.client_key else None,
            )
            if args.json:
                print(json.dumps(result, indent=2, ensure_ascii=False))
            else:
                _print_doctor(result)
            return 0 if result["ready"] else 2

        if args.command == "init":
            result = init_workspace(
                Path(args.workspace_root),
                args.assessment_id,
                args.run_id,
                args.node_id,
                Path(args.manifest) if args.manifest else None,
                Path(args.profiles) if args.profiles else None,
            )
            print(f"{DISPLAY_NAME} v{VERSION}")
            print(f"Status: {result['status']}")
            print(f"Workspace: {result['workspace']}")
            print(f"State: {_state_path(Path(result['workspace']))}")
            print("Active discovery performed: false")
            print("Authentication attempts performed: false")
            return 0

        if args.command == "status":
            result = status(Path(args.workspace))
            if args.json:
                print(json.dumps(result, indent=2, ensure_ascii=False))
            else:
                _print_status(result)
            return 0

        if args.command == "run":
            workspace = Path(args.workspace)
            current_state = _load_state(workspace.expanduser().resolve())
            network_status = (
                (current_state.get("steps", {}).get("network_discovery") or {}).get("status")
            )
            if network_status != "completed" or args.force_rescan or bool(args.target):
                result = run_network_discovery(
                    workspace=workspace,
                    targets=args.target,
                    excludes=args.exclude,
                    ack_authorized_scan=args.ack_authorized_scan,
                    profile=args.profile,
                    ports=args.ports,
                    timeout=args.timeout,
                    workers=args.workers,
                    max_hosts=args.max_hosts,
                    allow_large_scope=args.allow_large_scope,
                    disable_ssdp=args.disable_ssdp,
                    force_rescan=args.force_rescan,
                )
                print(f"{DISPLAY_NAME} v{VERSION}")
                print(f"Network Discovery status: {result.get('status')}")
                print(f"Hosts discovered: {result.get('hosts_discovered')}")
                print(f"Effective IPs: {result.get('effective_ip_count')}")
                print(f"JSON: {result.get('network_json')}")
                print(f"SHA256: {result.get('network_sha256')}")
                print(f"Network activity performed: {str(bool(result.get('network_activity_performed'))).lower()}")
                print("Authentication attempts performed: false")
                return 0

            current_state = _load_state(workspace.expanduser().resolve())
            plan_status = (
                (current_state.get("steps", {}).get("credential_plan") or {}).get("status")
            )
            if plan_status != "completed" or args.force_replan:
                result = run_credential_plan(
                    workspace=workspace,
                    max_candidates=args.max_candidates,
                    force_replan=args.force_replan,
                )
                print(f"{DISPLAY_NAME} v{VERSION}")
                print(f"Credential Planner status: {result.get('status')}")
                print(f"Assets: {result.get('assets_seen')}")
                print(f"Adapter candidates: {result.get('adapter_candidates')}")
                print(f"JSON: {result.get('plan_json')}")
                print(f"SHA256: {result.get('plan_sha256')}")
                print("Network activity performed: false")
                print("Secret resolution performed: false")
                print("Authentication attempts performed: false")
                return 0

            if (args.auth_only or args.full_enrichment) and not args.execute:
                raise RuntimeErrorSafe(
                    "--auth-only/--full-enrichment require --execute"
                )
            if args.execute and args.auth_only == args.full_enrichment:
                raise RuntimeErrorSafe(
                    "live execution requires exactly one mode: --auth-only or --full-enrichment"
                )

            current_state = _load_state(workspace.expanduser().resolve())
            execution_status = (
                (current_state.get("steps", {}).get("credentialed_execution") or {}).get("status")
            )
            if args.execute and args.auth_only:
                if execution_status not in {
                    "preview_completed", "auth_validated", "full_completed", "failed"
                }:
                    raise RuntimeErrorSafe(
                        "run the managed Executor dry-run preview before AUTH-only execution"
                    )
                result = run_credentialed_execution_auth_only(
                    workspace=workspace,
                    ack_authorized_access=args.ack_authorized_access,
                    max_actions=args.max_actions,
                    ssh_known_hosts=Path(args.ssh_known_hosts),
                    ssh_host_key_policy=args.ssh_host_key_policy,
                    force_auth_retry=args.force_auth_retry,
                )
                print(f"{DISPLAY_NAME} v{VERSION}")
                print(f"Credentialed Executor status: {result.get('status')}")
                print("Mode: auth_only")
                print(f"Actions: {result.get('actions_total')}")
                print(f"Completed: {result.get('completed')}")
                print(f"Authentication successes: {result.get('authentication_successes')}")
                print(f"Authentication failures: {result.get('authentication_failures')}")
                print(f"Open credential circuits: {result.get('open_credential_circuits')}")
                print(f"JSON: {result.get('job_json')}")
                print(f"SHA256: {result.get('job_sha256')}")
                print(
                    "Network activity performed: "
                    f"{str(bool(result.get('network_activity_performed'))).lower()}"
                )
                print(
                    "Secret resolution performed: "
                    f"{str(bool(result.get('secret_resolution_performed'))).lower()}"
                )
                print(
                    "Authentication attempts performed: "
                    f"{str(bool(result.get('authentication_attempts_performed'))).lower()}"
                )
                return 0

            if args.execute and args.full_enrichment:
                if execution_status not in {"auth_validated", "full_completed", "failed"}:
                    raise RuntimeErrorSafe(
                        "complete managed AUTH-only validation before FULL enrichment"
                    )
                result = run_credentialed_execution_full(
                    workspace=workspace,
                    ack_authorized_access=args.ack_authorized_access,
                    max_actions=args.max_actions,
                    ssh_known_hosts=Path(args.ssh_known_hosts),
                    ssh_host_key_policy=args.ssh_host_key_policy,
                    force_full_retry=args.force_full_retry,
                )
                print(f"{DISPLAY_NAME} v{VERSION}")
                print(f"Credentialed Executor status: {result.get('status')}")
                print("Mode: full")
                print(f"Actions: {result.get('actions_total')}")
                print(f"Completed: {result.get('completed')}")
                print(f"Collected: {result.get('collected')}")
                print(f"Authentication successes: {result.get('authentication_successes')}")
                print(f"Authentication failures: {result.get('authentication_failures')}")
                print(f"Open credential circuits: {result.get('open_credential_circuits')}")
                print(f"JSON: {result.get('job_json')}")
                print(f"SHA256: {result.get('job_sha256')}")
                print(
                    "Network activity performed: "
                    f"{str(bool(result.get('network_activity_performed'))).lower()}"
                )
                print(
                    "Secret resolution performed: "
                    f"{str(bool(result.get('secret_resolution_performed'))).lower()}"
                )
                print(
                    "Authentication attempts performed: "
                    f"{str(bool(result.get('authentication_attempts_performed'))).lower()}"
                )
                return 0

            if execution_status == "full_completed":
                result = run_asset_resolver(
                    workspace=workspace,
                    force_reresolve=args.force_reresolve,
                )
                print(f"{DISPLAY_NAME} v{VERSION}")
                print(f"Asset Resolver status: {result.get('status')}")
                print(f"Network assets: {result.get('network_assets_seen')}")
                print(
                    "Credentialed observations: "
                    f"{result.get('credentialed_observations_seen')}"
                )
                print(f"Logical assets: {result.get('logical_assets_resolved')}")
                print(f"Unresolved: {result.get('unresolved_observations')}")
                print(f"Ambiguous: {result.get('ambiguous_correlations')}")
                print(f"Conflicts: {result.get('assets_with_conflicts')}")
                print(f"JSON: {result.get('resolver_json')}")
                print(f"SHA256: {result.get('resolver_sha256')}")
                print("Network activity performed: false")
                print("Secret resolution performed: false")
                print("Authentication attempts performed: false")
                return 0

            result = run_credentialed_execution_dry_run(
                workspace=workspace,
                max_actions=args.max_actions,
            )
            print(f"{DISPLAY_NAME} v{VERSION}")
            print(f"Credentialed Executor status: {result.get('status')}")
            print("Mode: dry_run")
            print(f"Actions: {result.get('actions_total')}")
            print(f"Ready: {result.get('actions_ready')}")
            print(f"JSON: {result.get('job_json')}")
            print(f"SHA256: {result.get('job_sha256')}")
            print("Network activity performed: false")
            print("Secret resolution performed: false")
            print("Authentication attempts performed: false")
            return 0

        if args.command == "export":
            result = export_bundle(
                workspace=Path(args.workspace),
                network=Path(args.network) if args.network else None,
                evidence_dir=Path(args.evidence_dir) if args.evidence_dir else None,
                evidence_run_label=args.evidence_run_label,
                asset_resolver=Path(args.asset_resolver) if args.asset_resolver else None,
                manifest=Path(args.manifest) if args.manifest else None,
                require_sidecars=not args.allow_missing_sidecars,
                force_rebuild=args.force_rebuild,
            )
            print(f"{DISPLAY_NAME} v{VERSION}")
            print(f"Export status: {result.get('status')}")
            print(f"Bundle: {result.get('bundle_path') or result.get('bundle')}")
            print(f"Bundle ID: {result.get('bundle_id')}")
            print(f"SHA256: {result.get('bundle_sha256')}")
            print(f"Selection mode: {result.get('selection_mode')}")
            print(f"Artifacts: {result.get('artifact_count')}")
            print(
                "Credentialed evidence: "
                f"{result.get('credentialed_evidence_count')}"
            )
            print("Network activity performed: false")
            print("Secret resolution performed: false")
            print("Authentication attempts performed: false")
            return 0

        if args.command == "upload":
            result = upload_bundle(
                workspace=Path(args.workspace),
                server_url=args.server_url,
                ca_cert=Path(args.ca_cert) if args.ca_cert else None,
                client_cert=Path(args.client_cert) if args.client_cert else None,
                client_key=Path(args.client_key) if args.client_key else None,
                timeout=args.timeout,
                max_retries=args.max_retries,
                force_resend=args.force_resend,
            )
            print(f"{DISPLAY_NAME} v{VERSION}")
            print(f"Upload step status: {result.get('status')}")
            if result.get("result"):
                response = result["result"].get("server_response") or {}
                print(f"HTTP status: {result['result'].get('http_status')}")
                print(f"Server status: {response.get('status')}")
                print(f"Semantic match: {response.get('semantic_match')}")
                print(f"Authenticated node: {response.get('authenticated_node_id')}")
                print(f"Receipt: {result.get('receipt')}")
            else:
                print(f"HTTP status: {result.get('http_status')}")
                print(f"Server status: {result.get('server_status')}")
                print("No network retry performed because upload was already completed.")
            print(
                "Network activity performed: "
                f"{str(bool(result.get('network_activity_performed'))).lower()}"
            )
            print("Secret resolution performed: false")
            print("Authentication attempts performed: false")
            return 0

    except RuntimeErrorSafe as exc:
        parser.error(str(exc))
    except Exception as exc:
        parser.error(str(exc))

    return 2


if __name__ == "__main__":
    raise SystemExit(cli())

