#!/usr/bin/env python3
"""Orizon IT P01 Central Ingestion API v0.5c.0.

Localhost-only HTTP ingestion foundation for .p01bundle.

The API does not implement a second import pipeline. Uploaded bytes are staged,
SHA256-verified, bundle-validated, and then handed to the same v0.5b
import_bundle() function used by offline/manual ingestion.

Security boundaries in v0.5c:
- loopback bind only;
- raw application/octet-stream uploads;
- mandatory Content-Length and X-P01-Bundle-SHA256;
- bounded streaming upload, never read whole request into memory;
- caller-supplied paths/filenames are ignored;
- staging before validation/import;
- common v0.5b importer remains authoritative;
- no customer-network access, authentication, secret resolution or command execution.

Remote/TLS/node-authenticated operation is intentionally deferred to v0.5d.
"""

from __future__ import annotations

import argparse
import hashlib
import http.server
import ipaddress
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import threading
from io import BufferedReader
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence
from urllib.parse import unquote, urlparse

NAME = "P01-Central-Ingestion-API"
VERSION = "0.5c.0"
API_VERSION = "v1"

DEFAULT_BIND = "127.0.0.1"
DEFAULT_PORT = 8088
DEFAULT_MAX_UPLOAD_MIB = 1024
CHUNK_SIZE = 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
BUNDLE_ID_RE = re.compile(r"^bnd-[0-9a-f]{20}$")

ROOT = Path(__file__).resolve().parents[1]
INGESTION_DIR = ROOT / "ingestion"
BUNDLE_DIR = ROOT / "evidence_bundle"
for p in (INGESTION_DIR, BUNDLE_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from P01_Offline_Import import import_bundle, load_json, safe_label  # noqa: E402
from P01_Evidence_Bundle import validate_bundle  # noqa: E402


class IngestionError(ValueError):
    """Expected client-facing ingestion error."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


def digest_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def is_loopback_bind(value: str) -> bool:
    text = str(value or "").strip().lower()
    if text == "localhost":
        return True
    try:
        return ipaddress.ip_address(text).is_loopback
    except ValueError:
        return False


def require_loopback_bind(value: str) -> str:
    if not is_loopback_bind(value):
        raise ValueError(
            "v0.5c is localhost-only. Use 127.0.0.1, ::1 or localhost. "
            "Remote/TLS/node-authenticated transport belongs to v0.5d."
        )
    return value


def _bundle_manifest_from_validated_file(path: Path) -> Dict[str, Any]:
    import zipfile
    with zipfile.ZipFile(path, "r") as zf:
        try:
            raw = zf.read("bundle-manifest.json")
        except KeyError as exc:
            raise IngestionError("bundle-manifest.json missing", 400) from exc
    try:
        doc = json.loads(raw.decode("utf-8-sig"))
    except Exception as exc:
        raise IngestionError(f"invalid bundle manifest JSON: {exc}", 400) from exc
    if not isinstance(doc, dict):
        raise IngestionError("bundle manifest root must be an object", 400)
    return doc


def json_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


class IngestionService:
    def __init__(
        self,
        store_dir: Path,
        process: bool = False,
        max_upload_bytes: int = DEFAULT_MAX_UPLOAD_MIB * 1024 * 1024,
        process_run_label: str = "P01LAB-API-SERVER-REPROCESS",
    ) -> None:
        if max_upload_bytes < 1:
            raise ValueError("max_upload_bytes must be positive")
        self.store_dir = Path(store_dir)
        self.process = bool(process)
        self.max_upload_bytes = int(max_upload_bytes)
        self.process_run_label = safe_label(process_run_label)
        self.staging_dir = self.store_dir / ".api-staging"
        self.staging_dir.mkdir(parents=True, exist_ok=True)
        self._lock_guard = threading.Lock()
        self._bundle_locks: Dict[str, threading.Lock] = {}

    def _bundle_lock(self, bundle_id: str) -> threading.Lock:
        with self._lock_guard:
            return self._bundle_locks.setdefault(bundle_id, threading.Lock())

    def _stage_stream(
        self,
        stream: Any,
        content_length: int,
        supplied_sha256: str,
    ) -> Path:
        if content_length < 1:
            raise IngestionError("Content-Length must be positive", 411)
        if content_length > self.max_upload_bytes:
            raise IngestionError(
                f"upload exceeds maximum allowed size: {content_length} > {self.max_upload_bytes}",
                413,
            )
        if not SHA256_RE.fullmatch(supplied_sha256 or ""):
            raise IngestionError("X-P01-Bundle-SHA256 must be a 64-character hex SHA256", 400)

        fd, name = tempfile.mkstemp(prefix="p01-upload-", suffix=".p01bundle", dir=self.staging_dir)
        staged = Path(name)
        digest = hashlib.sha256()
        remaining = content_length
        try:
            with os.fdopen(fd, "wb") as out:
                while remaining:
                    chunk = stream.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise IngestionError(
                            f"request body ended early with {remaining} bytes remaining",
                            400,
                        )
                    out.write(chunk)
                    digest.update(chunk)
                    remaining -= len(chunk)
            actual = digest.hexdigest()
            if actual.lower() != supplied_sha256.lower():
                raise IngestionError(
                    f"uploaded bundle SHA256 mismatch: expected {supplied_sha256.lower()}, got {actual}",
                    422,
                )
            return staged
        except Exception:
            staged.unlink(missing_ok=True)
            raise

    def ingest_stream(
        self,
        stream: Any,
        content_length: int,
        supplied_sha256: str,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        staged = self._stage_stream(stream, content_length, supplied_sha256)
        sidecar: Optional[Path] = None
        try:
            try:
                validation = validate_bundle(staged)
            except Exception as exc:
                raise IngestionError(f"bundle validation failed: {exc}", 422) from exc

            manifest = _bundle_manifest_from_validated_file(staged)
            bundle_id = str(manifest.get("bundle_id") or "")
            if not BUNDLE_ID_RE.fullmatch(bundle_id):
                raise IngestionError("validated bundle contains an invalid bundle_id", 422)

            if idempotency_key:
                key = idempotency_key.strip()
                if key != bundle_id:
                    raise IngestionError(
                        f"Idempotency-Key does not match validated bundle_id {bundle_id}",
                        409,
                    )

            lock = self._bundle_lock(bundle_id)
            with lock:
                canonical_stage = self.staging_dir / f"{bundle_id}.p01bundle"
                if canonical_stage.exists():
                    canonical_stage.unlink()
                os.replace(staged, canonical_stage)
                staged = canonical_stage
                sidecar = staged.with_suffix(staged.suffix + ".sha256")
                sidecar.write_text(
                    f"{supplied_sha256.lower()}  {staged.name}\n",
                    encoding="utf-8",
                )

                result = import_bundle(
                    staged,
                    self.store_dir,
                    process=self.process,
                    require_outer_sidecar=True,
                    process_run_label=self.process_run_label,
                )

            return {
                "api_version": API_VERSION,
                "status": result["status"],
                "bundle_id": result["bundle_id"],
                "assessment_id": result["assessment_id"],
                "semantic_match": result.get("semantic_match"),
                "artifact_count": validation.get("artifact_count"),
                "credentialed_evidence_count": validation.get("credentialed_evidence_count"),
                "verified_inventory_entries": validation.get("verified_inventory_entries"),
                "outer_sha256": supplied_sha256.lower(),
                "processing_requested": self.process,
            }
        finally:
            staged.unlink(missing_ok=True)
            if sidecar:
                sidecar.unlink(missing_ok=True)

    def lookup(self, bundle_id: str) -> Dict[str, Any]:
        if not BUNDLE_ID_RE.fullmatch(bundle_id):
            raise IngestionError("invalid bundle_id", 400)

        matches = list(
            self.store_dir.glob(
                f"assessments/*/imports/{safe_label(bundle_id)}/receipt/import-receipt.json"
            )
        )
        if not matches:
            raise IngestionError("bundle_id not found", 404)
        if len(matches) > 1:
            raise IngestionError("bundle_id resolved to multiple assessments", 409)

        receipt = load_json(matches[0])
        processing = receipt.get("processing") if isinstance(receipt.get("processing"), Mapping) else {}
        return {
            "api_version": API_VERSION,
            "status": receipt.get("status"),
            "bundle_id": receipt.get("bundle_id"),
            "assessment_id": receipt.get("assessment_id"),
            "run_id": receipt.get("run_id"),
            "node_id": receipt.get("node_id"),
            "outer_sha256_verified": receipt.get("outer_sha256_verified"),
            "artifact_count": receipt.get("artifact_count"),
            "credentialed_evidence_count": receipt.get("credentialed_evidence_count"),
            "verified_inventory_entries": receipt.get("verified_inventory_entries"),
            "processing": {
                "requested": processing.get("requested"),
                "asset_resolver_executed": processing.get("asset_resolver_executed"),
                "semantic_match": processing.get("semantic_match"),
                "edge_semantic_sha256": processing.get("edge_semantic_sha256"),
                "server_semantic_sha256": processing.get("server_semantic_sha256"),
            },
        }


class P01HTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address: tuple[str, int], handler: type[http.server.BaseHTTPRequestHandler], service: IngestionService):
        super().__init__(server_address, handler)
        self.service = service


class P01IngestionHandler(http.server.BaseHTTPRequestHandler):
    server_version = f"P01Ingestion/{VERSION}"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("%s - - [%s] %s\n" % (self.client_address[0], self.log_date_time_string(), fmt % args))

    @property
    def service(self) -> IngestionService:
        return self.server.service  # type: ignore[attr-defined]

    def _send_json(self, status: int, payload: Mapping[str, Any]) -> None:
        raw = json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)

    def _send_error_json(self, status: int, message: str) -> None:
        self._send_json(status, {
            "api_version": API_VERSION,
            "error": {
                "status": status,
                "message": message,
            },
        })

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            self._send_json(200, {
                "status": "ok",
                "service": NAME,
                "version": VERSION,
                "bind_policy": "loopback_only",
                "processing_enabled": self.service.process,
            })
            return

        prefix = "/api/v1/bundles/"
        if parsed.path.startswith(prefix):
            bundle_id = unquote(parsed.path[len(prefix):]).strip("/")
            try:
                result = self.service.lookup(bundle_id)
                self._send_json(200, result)
            except IngestionError as exc:
                self._send_error_json(exc.status_code, str(exc))
            except Exception as exc:
                self._send_error_json(500, f"internal ingestion error: {exc}")
            return

        self._send_error_json(404, "endpoint not found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/api/v1/bundles":
            self._send_error_json(404, "endpoint not found")
            return

        content_type = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if content_type not in {"application/octet-stream", "application/vnd.orizon.p01bundle"}:
            self._send_error_json(415, "Content-Type must be application/octet-stream")
            return

        raw_length = self.headers.get("Content-Length")
        if not raw_length:
            self._send_error_json(411, "Content-Length is required")
            return
        try:
            content_length = int(raw_length)
        except ValueError:
            self._send_error_json(400, "invalid Content-Length")
            return

        supplied_sha = (self.headers.get("X-P01-Bundle-SHA256") or "").strip()
        idem = self.headers.get("Idempotency-Key")

        try:
            result = self.service.ingest_stream(
                self.rfile,
                content_length,
                supplied_sha,
                idempotency_key=idem,
            )
            status = 201 if result["status"] == "imported" else 200
            self._send_json(status, result)
        except IngestionError as exc:
            self._send_error_json(exc.status_code, str(exc))
        except Exception as exc:
            self._send_error_json(500, f"internal ingestion error: {exc}")


def serve(
    store_dir: Path,
    bind: str = DEFAULT_BIND,
    port: int = DEFAULT_PORT,
    process: bool = False,
    max_upload_mib: int = DEFAULT_MAX_UPLOAD_MIB,
    process_run_label: str = "P01LAB-API-SERVER-REPROCESS",
) -> None:
    require_loopback_bind(bind)
    if port < 1 or port > 65535:
        raise ValueError("port must be 1..65535")
    if max_upload_mib < 1:
        raise ValueError("max-upload-mib must be positive")

    service = IngestionService(
        store_dir=store_dir,
        process=process,
        max_upload_bytes=max_upload_mib * 1024 * 1024,
        process_run_label=process_run_label,
    )
    server = P01HTTPServer((bind, port), P01IngestionHandler, service)

    print(f"{NAME} v{VERSION}")
    print(f"Listening: http://{bind}:{port}")
    print("Bind policy: loopback_only")
    print(f"Store: {store_dir}")
    print(f"Process imported bundles: {str(process).lower()}")
    print(f"Max upload MiB: {max_upload_mib}")
    print("Press Ctrl+C to stop.")

    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def cli(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description=f"{NAME} v{VERSION}")
    sub = p.add_subparsers(dest="command", required=True)

    srv = sub.add_parser("serve", help="Start localhost-only central ingestion API")
    srv.add_argument("--store-dir", required=True)
    srv.add_argument("--bind", default=DEFAULT_BIND)
    srv.add_argument("--port", type=int, default=DEFAULT_PORT)
    srv.add_argument("--max-upload-mib", type=int, default=DEFAULT_MAX_UPLOAD_MIB)
    srv.add_argument("--process", action="store_true")
    srv.add_argument("--process-run-label", default="P01LAB-API-SERVER-REPROCESS")

    args = p.parse_args(argv)

    if args.command == "serve":
        try:
            serve(
                Path(args.store_dir),
                bind=args.bind,
                port=args.port,
                process=args.process,
                max_upload_mib=args.max_upload_mib,
                process_run_label=args.process_run_label,
            )
        except Exception as exc:
            p.error(str(exc))
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(cli())
