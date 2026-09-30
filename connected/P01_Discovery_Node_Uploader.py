#!/usr/bin/env python3
"""Orizon IT P01 Discovery Node Uploader v0.5d.0.

Uploads an existing .p01bundle to a remote P01 Central Ingestion API over
mutual TLS. The uploader changes transport only; it does not rebuild evidence,
resolve secrets, authenticate to customer assets, or execute bundle payloads.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import http.client
import json
import socket
import ssl
import sys
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlparse

NAME = "P01-Discovery-Node-Uploader"
VERSION = "0.5d.0"
CHUNK_SIZE = 1024 * 1024

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_DIR = ROOT / "evidence_bundle"
if str(BUNDLE_DIR) not in sys.path:
    sys.path.insert(0, str(BUNDLE_DIR))

from P01_Evidence_Bundle import validate_bundle  # noqa: E402


class UploadError(RuntimeError):
    pass


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def bundle_manifest(path: Path) -> Dict[str, Any]:
    validate_bundle(path)
    with zipfile.ZipFile(path, "r") as zf:
        raw = zf.read("bundle-manifest.json")
    doc = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(doc, dict):
        raise UploadError("bundle manifest root must be an object")
    return doc


def validate_server_url(server_url: str) -> Tuple[str, int, str]:
    parsed = urlparse(server_url)
    if parsed.scheme.lower() != "https":
        raise UploadError("server-url must use https")
    if not parsed.hostname:
        raise UploadError("server-url must contain a hostname")
    if parsed.username or parsed.password:
        raise UploadError("server-url must not contain userinfo")
    if parsed.query or parsed.fragment:
        raise UploadError("server-url must not contain query or fragment")

    port = parsed.port or 443
    base = parsed.path.rstrip("/")
    endpoint = (base + "/api/v1/bundles") if base else "/api/v1/bundles"
    return parsed.hostname, port, endpoint


def build_ssl_context(ca_cert: Path, client_cert: Path, client_key: Path) -> ssl.SSLContext:
    for label, path in (
        ("ca-cert", ca_cert),
        ("client-cert", client_cert),
        ("client-key", client_key),
    ):
        if not Path(path).is_file():
            raise UploadError(f"{label} file not found: {path}")

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_cert))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key))
    if hasattr(ssl, "OP_NO_COMPRESSION"):
        context.options |= ssl.OP_NO_COMPRESSION
    return context


def _json_response(raw: bytes) -> Dict[str, Any]:
    try:
        payload = json.loads(raw.decode("utf-8-sig"))
    except Exception as exc:
        raise UploadError(f"server returned non-JSON response: {exc}") from exc
    if not isinstance(payload, dict):
        raise UploadError("server response root must be an object")
    return payload


def upload_once(
    server_url: str,
    bundle: Path,
    node_id: str,
    ca_cert: Path,
    client_cert: Path,
    client_key: Path,
    timeout: float = 30.0,
) -> Tuple[int, Dict[str, Any]]:
    host, port, endpoint = validate_server_url(server_url)
    manifest = bundle_manifest(bundle)

    bundle_node = str(manifest.get("node_id") or "").strip()
    if bundle_node.lower() != str(node_id).strip().lower():
        raise UploadError(
            f"local node-id {node_id} does not match bundle node_id {bundle_node}"
        )

    bundle_id = str(manifest.get("bundle_id") or "").strip()
    if not bundle_id:
        raise UploadError("bundle manifest does not contain bundle_id")

    bundle_sha = digest_file(bundle)
    size = bundle.stat().st_size
    context = build_ssl_context(ca_cert, client_cert, client_key)

    conn = http.client.HTTPSConnection(host, port, context=context, timeout=timeout)
    try:
        conn.putrequest("POST", endpoint)
        conn.putheader("Content-Type", "application/vnd.orizon.p01bundle")
        conn.putheader("Content-Length", str(size))
        conn.putheader("X-P01-Bundle-SHA256", bundle_sha)
        conn.putheader("Idempotency-Key", bundle_id)
        conn.putheader("X-P01-Node-ID", node_id)
        conn.endheaders()

        with bundle.open("rb") as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
                conn.send(chunk)

        response = conn.getresponse()
        raw = response.read()
        payload = _json_response(raw)
        return response.status, payload
    finally:
        conn.close()


def upload_with_retries(
    server_url: str,
    bundle: Path,
    node_id: str,
    ca_cert: Path,
    client_cert: Path,
    client_key: Path,
    timeout: float = 30.0,
    max_retries: int = 2,
) -> Dict[str, Any]:
    if max_retries < 0 or max_retries > 10:
        raise UploadError("max-retries must be between 0 and 10")
    if timeout <= 0:
        raise UploadError("timeout must be positive")

    attempt = 0
    while True:
        attempt += 1
        try:
            status, payload = upload_once(
                server_url,
                bundle,
                node_id,
                ca_cert,
                client_cert,
                client_key,
                timeout=timeout,
            )

            if 200 <= status < 300:
                return {
                    "status": "success",
                    "http_status": status,
                    "attempts": attempt,
                    "server_response": payload,
                }

            # Never retry application/TLS-auth/validation failures automatically.
            raise UploadError(
                f"server rejected upload with HTTP {status}: "
                + json.dumps(payload, ensure_ascii=False, sort_keys=True)
            )
        except ssl.SSLCertVerificationError as exc:
            raise UploadError(f"server certificate verification failed: {exc}") from exc
        except ssl.SSLError as exc:
            raise UploadError(f"TLS handshake failed: {exc}") from exc
        except UploadError:
            raise
        except (ConnectionRefusedError, ConnectionResetError, TimeoutError, socket.timeout, OSError) as exc:
            if attempt > max_retries + 1:
                raise UploadError(
                    f"transport failed after {attempt} attempts: {exc}"
                ) from exc
            if attempt >= max_retries + 1:
                raise UploadError(
                    f"transport failed after {attempt} attempts: {exc}"
                ) from exc
            time.sleep(min(2 ** (attempt - 1), 4))


def write_receipt(output_dir: Path, node_id: str, bundle: Path, server_url: str, result: Mapping[str, Any]) -> Tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = bundle_manifest(bundle)
    receipt = {
        "schema_version": "0.5d",
        "uploader_name": NAME,
        "uploader_version": VERSION,
        "created_at_utc": utc_now_iso(),
        "node_id": node_id,
        "bundle_id": manifest.get("bundle_id"),
        "assessment_id": manifest.get("assessment_id"),
        "bundle_sha256": digest_file(bundle),
        "bundle_size_bytes": bundle.stat().st_size,
        "server_url": server_url,
        "tls_server_verification": True,
        "mtls_client_certificate_used": True,
        "secret_values_persisted": False,
        "result": dict(result),
    }
    bundle_id = str(manifest.get("bundle_id") or "unknown")
    out = output_dir / f"P01-Upload-Receipt_{bundle_id}.json"
    out.write_text(json.dumps(receipt, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    sha = out.with_suffix(out.suffix + ".sha256")
    sha.write_text(f"{digest_file(out)}  {out.name}\n", encoding="utf-8")
    return out, sha


def cli(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description=f"{NAME} v{VERSION}")
    p.add_argument("--server-url", required=True, help="HTTPS base URL, e.g. https://p01-server:8443")
    p.add_argument("--bundle", required=True)
    p.add_argument("--node-id", required=True)
    p.add_argument("--ca-cert", required=True)
    p.add_argument("--client-cert", required=True)
    p.add_argument("--client-key", required=True)
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--max-retries", type=int, default=2)
    p.add_argument("--output-dir", default="./output")
    args = p.parse_args(argv)

    try:
        result = upload_with_retries(
            args.server_url,
            Path(args.bundle),
            args.node_id,
            Path(args.ca_cert),
            Path(args.client_cert),
            Path(args.client_key),
            timeout=args.timeout,
            max_retries=args.max_retries,
        )
        receipt, sha = write_receipt(
            Path(args.output_dir),
            args.node_id,
            Path(args.bundle),
            args.server_url,
            result,
        )
    except Exception as exc:
        p.error(str(exc))

    response = result.get("server_response", {})
    print(f"{NAME} v{VERSION}")
    print(f"Upload status: {result.get('status')}")
    print(f"HTTP status: {result.get('http_status')}")
    print(f"Attempts: {result.get('attempts')}")
    print(f"Bundle ID: {response.get('bundle_id')}")
    print(f"Assessment: {response.get('assessment_id')}")
    print(f"Server status: {response.get('status')}")
    print(f"Semantic match: {response.get('semantic_match')}")
    print(f"Authenticated node: {response.get('authenticated_node_id')}")
    print(f"Receipt: {receipt}")
    print(f"Receipt SHA256: {sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
