#!/usr/bin/env python3
"""Orizon IT P01 Evidence Bundle v0.5a.0.

Creates and validates portable .p01bundle files for both:
- connected upload to a future P01 Ingestion API; and
- offline/manual transfer to a P01 Server.

The same bundle format is used for both transports.

Security properties of v0.5a:
- SHA256 inventory for every payload file;
- optional verification of source evidence sidecars before packaging;
- outer bundle SHA256 sidecar;
- path traversal / duplicate-entry / zip-bomb guards;
- rejection of Secret Provider references and secret-like JSON fields.

Important limitation:
SHA256 inventory proves consistency, not publisher authenticity. Cryptographic
bundle signatures are intentionally reserved for the signed-bundle stage.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import socket
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

NAME = "P01-Evidence-Bundle"
VERSION = "0.5a.0"
FORMAT_VERSION = "0.5a"

MAX_FILES_DEFAULT = 10000
MAX_UNCOMPRESSED_BYTES_DEFAULT = 4 * 1024 * 1024 * 1024

SAFE_SECRET_METADATA_KEYS = {
    "secret_resolution",
    "secret_values_persisted_to_output",
    "secret_ref_names",
}
SENSITIVE_KEY_RE = re.compile(
    r"(^|_)(password|passwd|pwd|secret|token|community|passphrase|private_key)(_|$)",
    re.IGNORECASE,
)
SENSITIVE_VALUE_PREFIXES = ("wincred://", "prompt://", "env://")
SUPPORTED_ROLES = {
    "network_discovery",
    "assessment_manifest",
    "credentialed_evidence",
    "asset_resolver",
}
ROLE_DIR = {
    "network_discovery": "evidence/network",
    "assessment_manifest": "context",
    "credentialed_evidence": "evidence/credentialed",
    "asset_resolver": "evidence/resolved",
}


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest_file(path: Path) -> str:
    return digest_bytes(path.read_bytes())


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def load_json_bytes(raw: bytes, source: str) -> Dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8-sig"))
    except Exception as exc:
        raise ValueError(f"{source}: invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{source}: JSON root must be an object")
    return value


def load_json(path: Path) -> Dict[str, Any]:
    return load_json_bytes(path.read_bytes(), str(path))


def safe_label(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "bundle")).strip("-")
    return cleaned or "bundle"


def verify_sidecar(path: Path) -> Optional[bool]:
    side = path.with_suffix(path.suffix + ".sha256")
    if not side.exists():
        return None
    text = side.read_text(encoding="utf-8-sig").strip()
    if not text:
        return False
    expected = text.split()[0].lower()
    return expected == digest_file(path).lower()


def assert_no_secret_material(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            if SENSITIVE_KEY_RE.search(key_text) and key_text not in SAFE_SECRET_METADATA_KEYS:
                raise ValueError(f"secret-like JSON key prohibited in bundle payload: {path}.{key_text}")
            assert_no_secret_material(child, f"{path}.{key_text}")
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            assert_no_secret_material(child, f"{path}[{idx}]")
    elif isinstance(value, str):
        lowered = value.strip().lower()
        if any(lowered.startswith(prefix) for prefix in SENSITIVE_VALUE_PREFIXES):
            raise ValueError(f"Secret Provider reference prohibited in bundle payload: {path}")


def component_metadata(role: str, doc: Mapping[str, Any]) -> Dict[str, Any]:
    meta = doc.get("metadata") if isinstance(doc.get("metadata"), Mapping) else {}
    result: Dict[str, Any] = {"role": role}
    if role == "network_discovery":
        result.update({
            "component_name": meta.get("scanner_name"),
            "component_version": meta.get("scanner_version"),
            "schema_version": meta.get("schema_version"),
            "run_label": meta.get("run_label"),
        })
    elif role == "credentialed_evidence":
        result.update({
            "component_name": meta.get("executor_name") or meta.get("adapter_name") or meta.get("enricher_name"),
            "component_version": meta.get("executor_version") or meta.get("adapter_version") or meta.get("enricher_version"),
            "schema_version": meta.get("schema_version"),
            "run_label": meta.get("run_label"),
        })
    elif role == "asset_resolver":
        result.update({
            "component_name": meta.get("resolver_name"),
            "component_version": meta.get("resolver_version"),
            "schema_version": meta.get("schema_version"),
            "run_label": meta.get("run_label"),
        })
    elif role == "assessment_manifest":
        result.update({
            "component_name": "P01-Assessment-Manifest",
            "component_version": doc.get("schema_version"),
            "schema_version": doc.get("schema_version"),
            "run_label": doc.get("assessment_id"),
        })
    return result


def normalized_arcname(role: str, source: Path) -> str:
    if role not in ROLE_DIR:
        raise ValueError(f"unsupported role: {role}")
    return f"{ROLE_DIR[role]}/{source.name}"


def _validate_input_file(path: Path, role: str) -> Tuple[bytes, Dict[str, Any]]:
    if not path.exists() or not path.is_file():
        raise ValueError(f"input not found: {path}")
    if path.suffix.lower() != ".json":
        raise ValueError(f"only JSON evidence/config is accepted in v0.5a: {path}")
    raw = path.read_bytes()
    doc = load_json_bytes(raw, str(path))
    assert_no_secret_material(doc, str(path))
    return raw, doc


def collect_credentialed_paths(directory: Path, run_label: Optional[str]) -> List[Path]:
    if not directory.exists() or not directory.is_dir():
        raise ValueError(f"credentialed evidence directory not found: {directory}")
    paths = []
    for path in directory.glob("P01-Credentialed-Target_*.json"):
        if run_label and run_label not in path.name:
            continue
        paths.append(path)
    return sorted(paths, key=lambda p: p.name.lower())


def _bundle_id(assessment_id: str, run_id: str, node_id: str, artifacts: Sequence[Mapping[str, Any]]) -> str:
    identity = {
        "assessment_id": assessment_id,
        "run_id": run_id,
        "node_id": node_id,
        "artifacts": [
            {"role": x["role"], "path": x["path"], "sha256": x["sha256"], "size_bytes": x["size_bytes"]}
            for x in sorted(artifacts, key=lambda a: (str(a["role"]), str(a["path"])))
        ],
    }
    return "bnd-" + digest_bytes(canonical_json_bytes(identity))[:20]


def create_bundle(
    output: Path,
    assessment_id: str,
    run_id: str,
    node_id: str,
    network_path: Path,
    credentialed_paths: Sequence[Path],
    manifest_path: Optional[Path] = None,
    asset_resolver_path: Optional[Path] = None,
    require_evidence_sidecars: bool = False,
) -> Dict[str, Any]:
    if output.suffix.lower() != ".p01bundle":
        raise ValueError("output must use the .p01bundle extension")
    if not assessment_id.strip() or not run_id.strip() or not node_id.strip():
        raise ValueError("assessment_id, run_id and node_id are required")
    if not credentialed_paths:
        raise ValueError("at least one credentialed evidence JSON is required")

    selected: List[Tuple[str, Path]] = [("network_discovery", network_path)]
    selected.extend(("credentialed_evidence", p) for p in credentialed_paths)
    if manifest_path:
        selected.append(("assessment_manifest", manifest_path))
    if asset_resolver_path:
        selected.append(("asset_resolver", asset_resolver_path))

    arc_seen = set()
    payloads: List[Tuple[str, Path, str, bytes, Dict[str, Any]]] = []
    artifacts: List[Dict[str, Any]] = []

    for role, path in selected:
        raw, doc = _validate_input_file(path, role)

        if require_evidence_sidecars and role != "assessment_manifest":
            state = verify_sidecar(path)
            if state is not True:
                raise ValueError(f"missing or invalid source SHA256 sidecar: {path}")

        arcname = normalized_arcname(role, path)
        if arcname in arc_seen:
            raise ValueError(f"duplicate bundle path: {arcname}")
        arc_seen.add(arcname)

        sha = digest_bytes(raw)
        item = {
            "role": role,
            "path": arcname,
            "file_name": path.name,
            "sha256": sha,
            "size_bytes": len(raw),
            "source_sidecar_verified": verify_sidecar(path),
            "component": component_metadata(role, doc),
        }
        artifacts.append(item)
        payloads.append((role, path, arcname, raw, doc))

    bundle_id = _bundle_id(assessment_id, run_id, node_id, artifacts)

    bundle_manifest = {
        "format": "p01-evidence-bundle",
        "format_version": FORMAT_VERSION,
        "bundle_id": bundle_id,
        "assessment_id": assessment_id,
        "run_id": run_id,
        "node_id": node_id,
        "created_at_utc": utc_now_iso(),
        "created_by": {
            "component": NAME,
            "version": VERSION,
            "host": socket.gethostname(),
        },
        "transport": {
            "portable_offline_import_supported": True,
            "connected_upload_supported_by_format": True,
            "transport_selected_at_creation": "agnostic",
        },
        "security": {
            "contains_secret_values": False,
            "contains_secret_provider_references": False,
            "integrity_mode": "sha256_inventory",
            "digital_signature": None,
        },
        "artifacts": sorted(artifacts, key=lambda a: (a["role"], a["path"])),
        "limitations": [
            "v0.5a SHA256 inventory verifies consistency but not publisher authenticity",
            "cryptographic bundle signatures are reserved for the signed-bundle stage",
            "the bundle contains immutable raw evidence and should be treated as sensitive customer data",
        ],
    }
    manifest_raw = canonical_json_bytes(bundle_manifest)

    sha_manifest = {
        "format": "p01-sha256-inventory",
        "format_version": FORMAT_VERSION,
        "bundle_id": bundle_id,
        "entries": [
            {"path": a["path"], "sha256": a["sha256"], "size_bytes": a["size_bytes"]}
            for a in bundle_manifest["artifacts"]
        ] + [{
            "path": "bundle-manifest.json",
            "sha256": digest_bytes(manifest_raw),
            "size_bytes": len(manifest_raw),
        }],
    }
    sha_manifest_raw = canonical_json_bytes(sha_manifest)

    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        zf.writestr("bundle-manifest.json", manifest_raw)
        zf.writestr("integrity/sha256-manifest.json", sha_manifest_raw)
        for _role, _path, arcname, raw, _doc in sorted(payloads, key=lambda x: x[2]):
            zf.writestr(arcname, raw)

    bundle_sha = digest_file(output)
    sidecar = output.with_suffix(output.suffix + ".sha256")
    sidecar.write_text(f"{bundle_sha}  {output.name}\n", encoding="utf-8")

    return {
        "bundle_path": str(output),
        "bundle_sha256_path": str(sidecar),
        "bundle_sha256": bundle_sha,
        "bundle_id": bundle_id,
        "artifact_count": len(artifacts),
        "credentialed_evidence_count": sum(1 for a in artifacts if a["role"] == "credentialed_evidence"),
    }


def _zip_member_is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0o170000
    return mode == 0o120000


def _safe_zip_names(
    infos: Sequence[zipfile.ZipInfo],
    max_files: int,
    max_uncompressed_bytes: int,
) -> None:
    if len(infos) > max_files:
        raise ValueError(f"bundle contains too many files: {len(infos)} > {max_files}")
    total = sum(int(i.file_size) for i in infos)
    if total > max_uncompressed_bytes:
        raise ValueError(f"bundle uncompressed size exceeds safety limit: {total} bytes")

    names = set()
    for info in infos:
        name = info.filename
        if name in names:
            raise ValueError(f"duplicate ZIP entry: {name}")
        names.add(name)
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts:
            raise ValueError(f"unsafe bundle path: {name}")
        if _zip_member_is_symlink(info):
            raise ValueError(f"symlink entry prohibited: {name}")


def validate_bundle(
    bundle: Path,
    max_files: int = MAX_FILES_DEFAULT,
    max_uncompressed_bytes: int = MAX_UNCOMPRESSED_BYTES_DEFAULT,
) -> Dict[str, Any]:
    if not bundle.exists() or not bundle.is_file():
        raise ValueError(f"bundle not found: {bundle}")
    if bundle.suffix.lower() != ".p01bundle":
        raise ValueError("bundle must use the .p01bundle extension")

    outer_sidecar = bundle.with_suffix(bundle.suffix + ".sha256")
    outer_sha_verified: Optional[bool] = None
    if outer_sidecar.exists():
        outer_sha_verified = verify_sidecar(bundle)

    with zipfile.ZipFile(bundle, "r") as zf:
        infos = zf.infolist()
        _safe_zip_names(infos, max_files, max_uncompressed_bytes)
        names = {i.filename for i in infos}
        required = {"bundle-manifest.json", "integrity/sha256-manifest.json"}
        missing = sorted(required - names)
        if missing:
            raise ValueError("bundle missing required entries: " + ", ".join(missing))

        manifest_raw = zf.read("bundle-manifest.json")
        manifest = load_json_bytes(manifest_raw, "bundle-manifest.json")
        if manifest.get("format") != "p01-evidence-bundle":
            raise ValueError("unsupported bundle format")
        if manifest.get("format_version") != FORMAT_VERSION:
            raise ValueError(
                f"unsupported bundle format_version {manifest.get('format_version')!r}; expected {FORMAT_VERSION!r}"
            )
        assert_no_secret_material(manifest, "bundle-manifest.json")

        sha_doc = load_json_bytes(
            zf.read("integrity/sha256-manifest.json"),
            "integrity/sha256-manifest.json",
        )
        if sha_doc.get("bundle_id") != manifest.get("bundle_id"):
            raise ValueError("integrity inventory bundle_id does not match bundle manifest")

        entries = sha_doc.get("entries")
        if not isinstance(entries, list) or not entries:
            raise ValueError("integrity inventory entries must be a non-empty array")

        verified_entries = 0
        inventory_paths = set()
        for idx, entry in enumerate(entries):
            if not isinstance(entry, Mapping):
                raise ValueError(f"integrity entry {idx} must be an object")
            path = str(entry.get("path") or "")
            expected_sha = str(entry.get("sha256") or "").lower()
            expected_size = entry.get("size_bytes")
            if path in inventory_paths:
                raise ValueError(f"duplicate integrity inventory path: {path}")
            inventory_paths.add(path)
            if path not in names:
                raise ValueError(f"integrity inventory path missing from bundle: {path}")
            raw = zf.read(path)
            if digest_bytes(raw) != expected_sha:
                raise ValueError(f"SHA256 mismatch: {path}")
            if expected_size != len(raw):
                raise ValueError(f"size mismatch: {path}")
            if path.endswith(".json"):
                assert_no_secret_material(load_json_bytes(raw, path), path)
            verified_entries += 1

        artifacts = manifest.get("artifacts")
        if not isinstance(artifacts, list):
            raise ValueError("bundle manifest artifacts must be an array")
        artifact_paths = set()
        for idx, artifact in enumerate(artifacts):
            if not isinstance(artifact, Mapping):
                raise ValueError(f"artifact {idx} must be an object")
            role = str(artifact.get("role") or "")
            path = str(artifact.get("path") or "")
            if role not in SUPPORTED_ROLES:
                raise ValueError(f"unsupported artifact role: {role}")
            if path in artifact_paths:
                raise ValueError(f"duplicate artifact path: {path}")
            artifact_paths.add(path)
            if path not in inventory_paths:
                raise ValueError(f"artifact missing from integrity inventory: {path}")
            if str(artifact.get("sha256") or "").lower() != digest_bytes(zf.read(path)):
                raise ValueError(f"artifact SHA256 mismatch with manifest: {path}")

        expected_payload_paths = names - {"integrity/sha256-manifest.json"}
        if inventory_paths != expected_payload_paths:
            extra = sorted(expected_payload_paths - inventory_paths)
            unexpected = sorted(inventory_paths - expected_payload_paths)
            raise ValueError(
                f"integrity inventory coverage mismatch; untracked={extra}, unexpected={unexpected}"
            )

    return {
        "valid": True,
        "bundle_id": manifest.get("bundle_id"),
        "format_version": manifest.get("format_version"),
        "assessment_id": manifest.get("assessment_id"),
        "run_id": manifest.get("run_id"),
        "node_id": manifest.get("node_id"),
        "artifact_count": len(manifest.get("artifacts") or []),
        "credentialed_evidence_count": sum(
            1 for a in manifest.get("artifacts") or []
            if isinstance(a, Mapping) and a.get("role") == "credentialed_evidence"
        ),
        "verified_inventory_entries": verified_entries,
        "outer_sha256_verified": outer_sha_verified,
        "integrity_mode": manifest.get("security", {}).get("integrity_mode"),
        "digital_signature": manifest.get("security", {}).get("digital_signature"),
    }


def cli(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description=f"{NAME} v{VERSION}")
    sub = p.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="Create a portable P01 evidence bundle")
    create.add_argument("--assessment-id", required=True)
    create.add_argument("--run-id", required=True)
    create.add_argument("--node-id", required=True)
    create.add_argument("--network", required=True)
    create.add_argument("--manifest")
    create.add_argument("--asset-resolver")
    create.add_argument("--evidence-dir", required=True)
    create.add_argument("--evidence-run-label")
    create.add_argument("--require-evidence-sidecars", action="store_true")
    create.add_argument("--output", required=True)

    validate = sub.add_parser("validate", help="Validate bundle structure and SHA256 inventory")
    validate.add_argument("--bundle", required=True)
    validate.add_argument("--max-files", type=int, default=MAX_FILES_DEFAULT)
    validate.add_argument("--max-uncompressed-bytes", type=int, default=MAX_UNCOMPRESSED_BYTES_DEFAULT)

    args = p.parse_args(argv)

    try:
        if args.command == "create":
            cred = collect_credentialed_paths(Path(args.evidence_dir), args.evidence_run_label)
            result = create_bundle(
                output=Path(args.output),
                assessment_id=args.assessment_id,
                run_id=args.run_id,
                node_id=args.node_id,
                network_path=Path(args.network),
                credentialed_paths=cred,
                manifest_path=Path(args.manifest) if args.manifest else None,
                asset_resolver_path=Path(args.asset_resolver) if args.asset_resolver else None,
                require_evidence_sidecars=args.require_evidence_sidecars,
            )
            print("Evidence Bundle criado.")
            print(f"Bundle ID: {result['bundle_id']}")
            print(f"Artifacts: {result['artifact_count']}")
            print(f"Credentialed evidence: {result['credentialed_evidence_count']}")
            print(f"Bundle: {result['bundle_path']}")
            print(f"SHA256: {result['bundle_sha256_path']}")
            return 0

        result = validate_bundle(
            Path(args.bundle),
            max_files=args.max_files,
            max_uncompressed_bytes=args.max_uncompressed_bytes,
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0

    except Exception as exc:
        p.error(str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(cli())
