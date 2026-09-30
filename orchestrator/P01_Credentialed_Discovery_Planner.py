#!/usr/bin/env python3
"""P01 Credentialed Discovery Planner v0.4b.3.2.

Consumes Network Discovery evidence and Credential Profiles to produce a safe,
non-secret execution plan. It does not resolve secrets and does not authenticate.

The planner is the bridge between discovery context and protocol adapters.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import sys
import datetime as dt
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

ROOT = Path(__file__).resolve().parents[1]
CRED_DIR = ROOT / "credential_manager"
ASSESSMENT_DIR = ROOT / "assessment"
if str(CRED_DIR) not in sys.path:
    sys.path.insert(0, str(CRED_DIR))
if str(ASSESSMENT_DIR) not in sys.path:
    sys.path.insert(0, str(ASSESSMENT_DIR))

from P01_Credential_Manager import (  # noqa: E402
    context_from_network_asset,
    load_profiles,
    match_profiles,
    _safe_profile_view,
)
from P01_Assessment_Context import load_manifest, manifest_context_for_asset  # noqa: E402

PLANNER_NAME = "P01-Credentialed-Discovery-Planner"
PLANNER_VERSION = "0.4b.3.2"

SERVICE_TO_PROTOCOL = {
    "ssh": "ssh",
    "winrm-http": "winrm",
    "winrm-https": "winrm",
}


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as f:
        value = json.load(f)
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def detect_protocols(asset: Mapping[str, Any]) -> List[str]:
    protocols = set()
    for port in asset.get("open_ports", []) or []:
        if not isinstance(port, Mapping):
            continue
        service = str(port.get("service") or "").strip().lower()
        protocol = SERVICE_TO_PROTOCOL.get(service)
        if protocol:
            protocols.add(protocol)
    return sorted(protocols)


def build_plan(
    discovery: Mapping[str, Any],
    profiles: Mapping[str, Any],
    realm_map: Optional[Mapping[str, str]] = None,
    max_candidates: int = 2,
    manifest: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    realm_map = realm_map or {}
    assets_out: List[Dict[str, Any]] = []

    for asset in discovery.get("assets", []) or []:
        if not isinstance(asset, Mapping):
            continue
        ip = str(asset.get("ip") or "")
        if not ip:
            continue

        manifest_ctx = manifest_context_for_asset(asset, manifest) if manifest else {
            "assessment_id": None,
            "target_classes": [],
            "declared_realm_candidates": [],
            "realm": None,
            "realm_kind": None,
            "realm_evidence_state": None,
            "realm_source": None,
        }
        mapped_realm = realm_map.get(ip)
        observed_realm = manifest_ctx.get("realm")
        realm = None
        realm_kind = None
        realm_evidence_state = None
        realm_source = None
        context_conflicts: List[str] = []

        if observed_realm and mapped_realm and str(observed_realm).lower() != str(mapped_realm).lower():
            context_conflicts.append("realm_map_conflicts_with_observed_manifest_domain")
            realm_source = "conflict"
        elif observed_realm:
            realm = str(observed_realm)
            realm_kind = manifest_ctx.get("realm_kind")
            realm_evidence_state = manifest_ctx.get("realm_evidence_state")
            realm_source = manifest_ctx.get("realm_source")
        elif mapped_realm:
            realm = str(mapped_realm)
            realm_kind = "local_host" if str(mapped_realm).lower() == "local" else None
            realm_evidence_state = "declared"
            realm_source = "realm_map"

        context = context_from_network_asset(
            asset,
            realm=realm,
            realm_kind=realm_kind,
            realm_evidence_state=realm_evidence_state,
            target_classes=manifest_ctx.get("target_classes") or [],
        )
        protocols = detect_protocols(asset)
        protocol_plans = []

        for protocol in protocols:
            matches = match_profiles(
                profiles,
                target_ip=ip,
                protocol=protocol,
                max_candidates=max_candidates,
                context=context,
            )
            protocol_plans.append({
                "protocol": protocol,
                "eligible_profile_count": len(matches),
                "eligible_profiles": [
                    {
                        "profile": _safe_profile_view(m.profile),
                        "matched_scope": m.matched_scope,
                        "scope_prefix_length": m.prefix_length,
                        "selector_score": m.selector_score,
                        "matched_selectors": list(m.matched_selectors),
                    }
                    for m in matches
                ],
                "action": "adapter_candidate" if matches else "no_eligible_profile",
            })

        has_candidate = any(p["action"] == "adapter_candidate" for p in protocol_plans)
        if has_candidate:
            action_status = "adapter_candidate"
            skip_reasons = []
        elif context_conflicts:
            action_status = "not_planned"
            skip_reasons = ["context_conflict"]
        elif not protocols:
            action_status = "not_planned"
            skip_reasons = ["no_supported_management_protocol_detected"]
        else:
            action_status = "not_planned"
            skip_reasons = ["no_eligible_profile_for_detected_protocols"]

        assets_out.append({
            "ip": ip,
            "hostname": asset.get("hostname"),
            "device_type": asset.get("device_type_guess"),
            "os_family": asset.get("os_guess"),
            "confidence": asset.get("confidence"),
            "target_classes": context.get("target_classes", []),
            "realm": realm,
            "realm_kind": realm_kind,
            "realm_evidence_state": realm_evidence_state,
            "realm_source": realm_source,
            "declared_realm_candidates": manifest_ctx.get("declared_realm_candidates", []),
            "context_conflicts": context_conflicts,
            "detected_protocols": protocols,
            "protocol_plans": protocol_plans,
            "credentialed_action_status": action_status,
            "skip_reasons": skip_reasons,
        })

    return {
        "metadata": {
            "planner_name": PLANNER_NAME,
            "planner_version": PLANNER_VERSION,
            "generated_at_utc": utc_now_iso(),
            "execution_host": socket.gethostname(),
            "secret_resolution": False,
            "authentication_attempts": False,
            "assessment_id": manifest.get("assessment_id") if manifest else None,
            "assessment_manifest_applied": bool(manifest),
        },
        "source": {
            "scanner_name": discovery.get("metadata", {}).get("scanner_name"),
            "scanner_version": discovery.get("metadata", {}).get("scanner_version"),
            "run_label": discovery.get("metadata", {}).get("run_label"),
        },
        "summary": {
            "assets_seen": len(assets_out),
            "assets_with_protocols": sum(1 for a in assets_out if a["detected_protocols"]),
            "adapter_candidates": sum(
                1
                for a in assets_out
                for p in a["protocol_plans"]
                if p["action"] == "adapter_candidate"
            ),
            "assets_with_adapter_candidates": sum(
                1 for a in assets_out if a["credentialed_action_status"] == "adapter_candidate"
            ),
            "assets_skipped_no_protocol": sum(
                1 for a in assets_out
                if "no_supported_management_protocol_detected" in a["skip_reasons"]
            ),
            "assets_skipped_no_profile": sum(
                1 for a in assets_out
                if "no_eligible_profile_for_detected_protocols" in a["skip_reasons"]
            ),
            "assets_with_declared_realm_candidates": sum(
                1 for a in assets_out if a["declared_realm_candidates"]
            ),
            "assets_with_observed_realm": sum(
                1 for a in assets_out if a["realm_evidence_state"] == "observed"
            ),
            "assets_with_context_conflicts": sum(
                1 for a in assets_out if a["context_conflicts"]
            ),
            "protocols": sorted({
                p
                for a in assets_out
                for p in a["detected_protocols"]
            }),
        },
        "assets": assets_out,
    }

def write_output(output_dir: Path, run_label: str, payload: Mapping[str, Any]) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in run_label).strip("-") or "plan"
    path = output_dir / f"P01-Credential-Plan_{timestamp}_{safe}.json"
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    sha = path.with_suffix(path.suffix + ".sha256")
    sha.write_text(f"{digest}  {path.name}\n", encoding="utf-8")
    return path, sha


def cli(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="P01 Context-aware Credentialed Discovery Planner v0.4b.3.2")
    p.add_argument("--discovery", required=True, help="Network Discovery JSON")
    p.add_argument("--profiles", required=True, help="Credential Profiles JSON")
    p.add_argument("--realm-map", help="Optional JSON object mapping IP -> realm")
    p.add_argument("--manifest", help="Optional v0.4b.6 Assessment Manifest")
    p.add_argument("--max-candidates", type=int, default=2)
    p.add_argument("--run-label", default="credential-plan")
    p.add_argument("--output-dir", default="./output")
    args = p.parse_args(argv)

    if not (1 <= args.max_candidates <= 5):
        p.error("--max-candidates must be 1..5")

    discovery = load_json(Path(args.discovery))
    profiles = load_profiles(Path(args.profiles))

    realm_map = {}
    if args.realm_map:
        realm_doc = load_json(Path(args.realm_map))
        realm_map = {str(k): str(v) for k, v in realm_doc.items()}

    manifest = None
    manifest_hash = None
    if args.manifest:
        manifest_path = Path(args.manifest)
        manifest = load_manifest(manifest_path)
        manifest_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()

    payload = build_plan(
        discovery,
        profiles,
        realm_map=realm_map,
        max_candidates=args.max_candidates,
        manifest=manifest,
    )
    if manifest_hash:
        payload["metadata"]["assessment_manifest_sha256"] = manifest_hash
    out, sha = write_output(Path(args.output_dir), args.run_label, payload)

    print("Credentialed discovery plan finalizado.")
    print(f"Assets: {payload['summary']['assets_seen']}")
    print(f"Adapter candidates: {payload['summary']['adapter_candidates']}")
    print(f"JSON: {out}")
    print(f"SHA256: {sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
