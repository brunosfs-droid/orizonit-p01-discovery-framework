#!/usr/bin/env python3
"""Orizon IT P01 Offline Import v0.5b.0.

Imports a validated .p01bundle into a local/server evidence store and can
reprocess the imported raw evidence with the Asset Resolver.

Security properties:
- validates the entire bundle before materialization;
- never executes payload content;
- never resolves secrets or authenticates;
- safe extraction only after archive/inventory validation;
- idempotent by bundle_id + bundle SHA256;
- preserves the original bundle as immutable raw evidence;
- server-side processing consumes only imported bundle evidence.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import socket
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

NAME = "P01-Offline-Import"
VERSION = "0.5b.0"
RECEIPT_SCHEMA_VERSION = "0.5b"

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_DIR = ROOT / "evidence_bundle"
RESOLVER_DIR = ROOT / "asset_resolver"
for p in (BUNDLE_DIR, RESOLVER_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from P01_Evidence_Bundle import validate_bundle  # noqa: E402
from P01_Asset_Resolver import resolve as resolve_assets, write_output as write_asset_output  # noqa: E402


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest_file(path: Path) -> str:
    return digest_bytes(path.read_bytes())


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as f:
        value = json.load(f)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: JSON root must be an object")
    return value


def load_json_bytes(raw: bytes, source: str) -> Dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8-sig"))
    except Exception as exc:
        raise ValueError(f"{source}: invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{source}: JSON root must be an object")
    return value


def safe_label(value: str) -> str:
    import re
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "import")).strip("-")
    return cleaned or "import"


def _read_outer_sidecar(bundle: Path) -> Tuple[Optional[Path], Optional[bool]]:
    side = bundle.with_suffix(bundle.suffix + ".sha256")
    if not side.exists():
        return None, None
    text = side.read_text(encoding="utf-8-sig").strip()
    if not text:
        return side, False
    expected = text.split()[0].lower()
    return side, expected == digest_file(bundle).lower()


def _bundle_manifest(bundle: Path) -> Dict[str, Any]:
    with zipfile.ZipFile(bundle, "r") as zf:
        return load_json_bytes(zf.read("bundle-manifest.json"), "bundle-manifest.json")


def _safe_materialize(bundle: Path, destination: Path) -> None:
    """Materialize validated members without using extractall."""
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(bundle, "r") as zf:
        for info in zf.infolist():
            pure = PurePosixPath(info.filename)
            if pure.is_absolute() or ".." in pure.parts:
                raise ValueError(f"unsafe bundle path during import: {info.filename}")
            if info.is_dir():
                (destination / Path(*pure.parts)).mkdir(parents=True, exist_ok=True)
                continue
            target = destination / Path(*pure.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(zf.read(info.filename))


def _artifacts_by_role(payload_dir: Path, manifest: Mapping[str, Any]) -> Dict[str, list[Path]]:
    result: Dict[str, list[Path]] = {}
    for item in manifest.get("artifacts", []) or []:
        if not isinstance(item, Mapping):
            continue
        role = str(item.get("role") or "")
        rel = PurePosixPath(str(item.get("path") or ""))
        path = payload_dir / Path(*rel.parts)
        if not path.exists() or not path.is_file():
            raise ValueError(f"materialized artifact missing: {rel}")
        result.setdefault(role, []).append(path)
    for role in result:
        result[role] = sorted(result[role], key=lambda p: p.name.lower())
    return result


def semantic_projection(doc: Mapping[str, Any]) -> Dict[str, Any]:
    """Stable Asset Resolver semantic view for edge/server equivalence checks."""
    assets = []
    for asset in doc.get("assets", []) or []:
        if not isinstance(asset, Mapping):
            continue
        assets.append({
            "asset_id": asset.get("asset_id"),
            "identity": asset.get("identity"),
            "identifiers": asset.get("identifiers", []),
            "addresses": asset.get("addresses", []),
            "mac_addresses": asset.get("mac_addresses", []),
            "services": asset.get("services", []),
            "conflicts": asset.get("conflicts", []),
            "confidence": asset.get("confidence"),
        })
    assets.sort(key=lambda x: str(x.get("asset_id") or ""))

    summary = doc.get("summary") if isinstance(doc.get("summary"), Mapping) else {}
    return {
        "summary": {
            "network_assets_seen": summary.get("network_assets_seen"),
            "credentialed_observations_seen": summary.get("credentialed_observations_seen"),
            "logical_assets_resolved": summary.get("logical_assets_resolved"),
            "unresolved_observations": summary.get("unresolved_observations"),
            "ambiguous_correlations": summary.get("ambiguous_correlations"),
            "assets_with_conflicts": summary.get("assets_with_conflicts"),
            "assets_with_strong_identifiers": summary.get("assets_with_strong_identifiers"),
        },
        "assets": assets,
        "unresolved_observations": doc.get("unresolved_observations", []),
        "ambiguous_correlations": doc.get("ambiguous_correlations", []),
    }


def semantic_digest(doc: Mapping[str, Any]) -> str:
    return digest_bytes(canonical_json_bytes(semantic_projection(doc)))


def _receipt_paths(import_dir: Path) -> Tuple[Path, Path]:
    receipt = import_dir / "receipt" / "import-receipt.json"
    return receipt, receipt.with_suffix(receipt.suffix + ".sha256")


def _load_existing_receipt(import_dir: Path) -> Optional[Dict[str, Any]]:
    receipt, sha = _receipt_paths(import_dir)
    if not receipt.exists():
        return None
    if not sha.exists():
        raise ValueError(f"existing import receipt missing SHA256 sidecar: {receipt}")
    expected = sha.read_text(encoding="utf-8-sig").strip().split()[0].lower()
    if digest_file(receipt).lower() != expected:
        raise ValueError(f"existing import receipt SHA256 mismatch: {receipt}")
    return load_json(receipt)


def _write_receipt(import_dir: Path, receipt: Mapping[str, Any]) -> Tuple[Path, Path]:
    receipt_path, sha_path = _receipt_paths(import_dir)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_bytes(canonical_json_bytes(receipt))
    digest = digest_file(receipt_path)
    sha_path.write_text(f"{digest}  {receipt_path.name}\n", encoding="utf-8")
    return receipt_path, sha_path


def import_bundle(
    bundle: Path,
    store_dir: Path,
    process: bool = False,
    require_outer_sidecar: bool = False,
    process_run_label: str = "server-reprocess",
) -> Dict[str, Any]:
    validation = validate_bundle(bundle)
    sidecar_path, outer_verified = _read_outer_sidecar(bundle)

    if require_outer_sidecar and outer_verified is not True:
        raise ValueError("offline import requires a valid outer bundle SHA256 sidecar")

    manifest = _bundle_manifest(bundle)
    bundle_id = str(manifest.get("bundle_id") or "")
    assessment_id = str(manifest.get("assessment_id") or "")
    if not bundle_id or not assessment_id:
        raise ValueError("bundle manifest missing bundle_id or assessment_id")

    bundle_sha = digest_file(bundle)
    final_dir = store_dir / "assessments" / safe_label(assessment_id) / "imports" / safe_label(bundle_id)

    if final_dir.exists():
        existing = _load_existing_receipt(final_dir)
        if not existing:
            raise ValueError(f"import destination exists without a valid receipt: {final_dir}")
        if str(existing.get("bundle_sha256") or "").lower() != bundle_sha.lower():
            raise ValueError("bundle_id collision: existing import has a different bundle SHA256")
        return {
            "status": "already_imported",
            "bundle_id": bundle_id,
            "assessment_id": assessment_id,
            "import_dir": str(final_dir),
            "receipt_path": str(_receipt_paths(final_dir)[0]),
            "receipt_sha256_path": str(_receipt_paths(final_dir)[1]),
            "semantic_match": existing.get("processing", {}).get("semantic_match"),
        }

    store_dir.mkdir(parents=True, exist_ok=True)
    temp_parent = store_dir / ".staging"
    temp_parent.mkdir(parents=True, exist_ok=True)
    temp_dir = Path(tempfile.mkdtemp(prefix=safe_label(bundle_id) + "-", dir=temp_parent))

    try:
        payload_dir = temp_dir / "payload"
        _safe_materialize(bundle, payload_dir)
        roles = _artifacts_by_role(payload_dir, manifest)

        raw_dir = temp_dir / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_bundle = raw_dir / bundle.name
        shutil.copy2(bundle, raw_bundle)
        raw_sidecar = None
        if sidecar_path:
            raw_sidecar = raw_dir / sidecar_path.name
            shutil.copy2(sidecar_path, raw_sidecar)

        processing: Dict[str, Any] = {
            "requested": bool(process),
            "asset_resolver_executed": False,
            "semantic_match": None,
            "edge_semantic_sha256": None,
            "server_semantic_sha256": None,
            "server_asset_resolver_json": None,
            "server_asset_resolver_sha256": None,
        }

        if process:
            network = roles.get("network_discovery", [])
            credentialed = roles.get("credentialed_evidence", [])
            manifests = roles.get("assessment_manifest", [])
            edge_resolved = roles.get("asset_resolver", [])
            if len(network) != 1:
                raise ValueError(f"server processing requires exactly one network_discovery artifact, got {len(network)}")
            if not credentialed:
                raise ValueError("server processing requires credentialed_evidence artifacts")
            if len(manifests) > 1:
                raise ValueError("server processing supports at most one assessment_manifest artifact")
            if len(edge_resolved) > 1:
                raise ValueError("server processing supports at most one embedded asset_resolver artifact")

            resolved = resolve_assets(
                network[0],
                credentialed,
                manifest_path=manifests[0] if manifests else None,
                require_evidence_sidecars=False,
            )
            processed_dir = temp_dir / "processed" / "asset_resolver"
            server_json, server_sha = write_asset_output(
                processed_dir,
                process_run_label,
                resolved,
            )
            server_semantic = semantic_digest(resolved)
            edge_semantic = None
            semantic_match = None
            if edge_resolved:
                edge_doc = load_json(edge_resolved[0])
                edge_semantic = semantic_digest(edge_doc)
                semantic_match = edge_semantic == server_semantic
                if not semantic_match:
                    raise ValueError(
                        "server-side Asset Resolver semantic result differs from embedded edge result"
                    )

            processing.update({
                "asset_resolver_executed": True,
                "semantic_match": semantic_match,
                "edge_semantic_sha256": edge_semantic,
                "server_semantic_sha256": server_semantic,
                "server_asset_resolver_json": str(server_json.relative_to(temp_dir)).replace("\\", "/"),
                "server_asset_resolver_sha256": str(server_sha.relative_to(temp_dir)).replace("\\", "/"),
            })

        receipt = {
            "schema_version": RECEIPT_SCHEMA_VERSION,
            "importer_name": NAME,
            "importer_version": VERSION,
            "status": "imported",
            "imported_at_utc": utc_now_iso(),
            "import_host": socket.gethostname(),
            "bundle_id": bundle_id,
            "bundle_sha256": bundle_sha,
            "outer_sha256_verified": outer_verified,
            "assessment_id": assessment_id,
            "run_id": manifest.get("run_id"),
            "node_id": manifest.get("node_id"),
            "format_version": manifest.get("format_version"),
            "artifact_count": validation.get("artifact_count"),
            "verified_inventory_entries": validation.get("verified_inventory_entries"),
            "credentialed_evidence_count": validation.get("credentialed_evidence_count"),
            "raw_bundle": f"raw/{raw_bundle.name}",
            "raw_bundle_sidecar": f"raw/{raw_sidecar.name}" if raw_sidecar else None,
            "payload_root": "payload",
            "processing": processing,
            "security": {
                "offline_only": True,
                "read_only_input": True,
                "secret_resolution": False,
                "authentication_attempts": False,
                "network_access_performed": False,
                "arbitrary_payload_execution": False,
            },
        }
        receipt_path, receipt_sha = _write_receipt(temp_dir, receipt)

        final_dir.parent.mkdir(parents=True, exist_ok=True)
        os.replace(temp_dir, final_dir)

        return {
            "status": "imported",
            "bundle_id": bundle_id,
            "assessment_id": assessment_id,
            "import_dir": str(final_dir),
            "receipt_path": str(final_dir / receipt_path.relative_to(temp_dir)),
            "receipt_sha256_path": str(final_dir / receipt_sha.relative_to(temp_dir)),
            "semantic_match": processing.get("semantic_match"),
        }
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


def cli(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description=f"{NAME} v{VERSION}")
    sub = p.add_subparsers(dest="command", required=True)

    imp = sub.add_parser("import", help="Validate and import a .p01bundle into a server/local evidence store")
    imp.add_argument("--bundle", required=True)
    imp.add_argument("--store-dir", required=True)
    imp.add_argument("--require-outer-sidecar", action="store_true")
    imp.add_argument("--process", action="store_true", help="Re-run Asset Resolver using only imported bundle evidence")
    imp.add_argument("--process-run-label", default="server-reprocess")

    args = p.parse_args(argv)

    if args.command == "import":
        try:
            result = import_bundle(
                Path(args.bundle),
                Path(args.store_dir),
                process=args.process,
                require_outer_sidecar=args.require_outer_sidecar,
                process_run_label=args.process_run_label,
            )
        except Exception as exc:
            p.error(str(exc))

        print("Offline Import finalizado.")
        print(f"Status: {result['status']}")
        print(f"Bundle ID: {result['bundle_id']}")
        print(f"Assessment: {result['assessment_id']}")
        print(f"Import dir: {result['import_dir']}")
        print(f"Receipt: {result['receipt_path']}")
        print(f"Receipt SHA256: {result['receipt_sha256_path']}")
        if result.get("semantic_match") is not None:
            print(f"Semantic match: {str(result['semantic_match']).lower()}")
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(cli())
