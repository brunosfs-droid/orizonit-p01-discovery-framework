#!/usr/bin/env python3
"""Cancã / Orizon IT Portable Discovery Node Runtime v0.5e.1.

Portable-first operator workflow foundation.

v0.5e.1 internalizes authorized Network Discovery as the first managed active
stage. Credential planning/execution and Asset Resolver remain externally
managed until later incremental releases. Evidence Bundle and Connected Upload
continue to reuse the already validated components.

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


NAME = "Canca-Portable-Discovery-Node"
DISPLAY_NAME = "Cancã Portable Discovery Node"
VERSION = "0.5e.1"
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


def init_workspace(
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
            "status": "external_required",
            "managed_from_version": "0.5e.1",
        },
        "credentialed_execution": {
            "status": "external_required",
            "managed_from_version": "0.5e.1",
        },
        "asset_resolver": {
            "status": "external_required",
            "managed_from_version": "0.5e.1",
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
            raise RuntimeErrorSafe("v0.5e.1 managed discovery supports IPv4 only")
        networks.append(net)
    return networks


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


def export_bundle(
    workspace: Path,
    network: Path,
    evidence_dir: Path,
    evidence_run_label: Optional[str],
    asset_resolver: Optional[Path],
    manifest: Optional[Path],
    require_sidecars: bool = True,
    force_rebuild: bool = False,
) -> Dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    state = _load_state(workspace)
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
                }
        raise RuntimeErrorSafe(
            "bundle step is completed but recorded artifact is missing or changed; "
            "use --force-rebuild only after review"
        )

    manifest_path = manifest
    if manifest_path is None:
        ref = state.get("source_refs", {}).get("assessment_manifest")
        manifest_path = Path(ref) if ref else None

    bundle_mod = _load_component(
        "evidence_bundle/P01_Evidence_Bundle.py",
        "p01_runtime_evidence_bundle",
    )
    credentialed = bundle_mod.collect_credentialed_paths(
        evidence_dir,
        evidence_run_label,
    )
    if not credentialed:
        raise RuntimeErrorSafe("no credentialed evidence files matched the requested run")

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
            network_path=network,
            credentialed_paths=credentialed,
            manifest_path=manifest_path,
            asset_resolver_path=asset_resolver,
            require_evidence_sidecars=require_sidecars,
        )
        validation = bundle_mod.validate_bundle(output)
    except Exception as exc:
        step["status"] = "failed"
        step["failed_at_utc"] = utc_now_iso()
        step["last_error"] = str(exc)[:1200]
        _append_event(state, "export", "failed", {"error": str(exc)[:500]})
        _write_state(workspace, state)
        raise RuntimeErrorSafe(str(exc)) from exc

    inputs: Dict[str, Any] = {
        "network_discovery": _artifact_ref(network),
        "credentialed_evidence": [_artifact_ref(path) for path in credentialed],
    }
    if manifest_path:
        inputs["assessment_manifest"] = _artifact_ref(manifest_path)
    if asset_resolver:
        inputs["asset_resolver"] = _artifact_ref(asset_resolver)

    step.clear()
    step.update({
        "status": "completed",
        "completed_at_utc": utc_now_iso(),
        "managed_by": VERSION,
        "source_sidecars_required": bool(require_sidecars),
        "input_count": 1 + len(credentialed)
        + (1 if manifest_path else 0)
        + (1 if asset_resolver else 0),
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
    }
    _append_event(
        state,
        "export",
        "completed",
        {
            "bundle_id": result["bundle_id"],
            "artifact_count": result["artifact_count"],
        },
    )
    _write_state(workspace, state)
    return {
        "status": "completed",
        **result,
        "validation": validation,
    }


def upload_bundle(
    workspace: Path,
    server_url: str,
    ca_cert: Path,
    client_cert: Path,
    client_key: Path,
    timeout: float = 30.0,
    max_retries: int = 2,
    force_resend: bool = False,
) -> Dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    state = _load_state(workspace)
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
        }

    bundle = _workspace_owned_path(workspace, str(bundle_info["path"]))
    if not bundle.is_file() or digest_file(bundle) != bundle_info.get("sha256"):
        raise RuntimeErrorSafe("recorded evidence bundle is missing or failed SHA256 verification")

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
    }


def next_action(state: Mapping[str, Any]) -> str:
    steps = state.get("steps") or {}
    network_status = (steps.get("network_discovery") or {}).get("status")
    if network_status in {"pending", "failed"}:
        return "run_network_discovery"
    if network_status == "completed":
        plan_status = (steps.get("credential_plan") or {}).get("status")
        if plan_status == "external_required":
            return "credential_plan_external"
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
        help="Run the currently managed active stage (Network Discovery in v0.5e.1)",
    )
    run_p.add_argument("--workspace", required=True)
    run_p.add_argument("--target", action="append", required=True)
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

    export_p = sub.add_parser(
        "export",
        help="Create the validated .p01bundle from existing evidence",
    )
    export_p.add_argument("--workspace", required=True)
    export_p.add_argument("--network", required=True)
    export_p.add_argument("--evidence-dir", required=True)
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
    upload_p.add_argument("--server-url", required=True)
    upload_p.add_argument("--ca-cert", required=True)
    upload_p.add_argument("--client-cert", required=True)
    upload_p.add_argument("--client-key", required=True)
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
            result = run_network_discovery(
                workspace=Path(args.workspace),
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

        if args.command == "export":
            result = export_bundle(
                workspace=Path(args.workspace),
                network=Path(args.network),
                evidence_dir=Path(args.evidence_dir),
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
            return 0

        if args.command == "upload":
            result = upload_bundle(
                workspace=Path(args.workspace),
                server_url=args.server_url,
                ca_cert=Path(args.ca_cert),
                client_cert=Path(args.client_cert),
                client_key=Path(args.client_key),
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
            return 0

    except RuntimeErrorSafe as exc:
        parser.error(str(exc))
    except Exception as exc:
        parser.error(str(exc))

    return 2


if __name__ == "__main__":
    raise SystemExit(cli())
