import hashlib
import importlib.util
import io
import json
import pathlib
import tempfile
import threading
import unittest
from unittest import mock
from urllib import request, error

ROOT = pathlib.Path(__file__).resolve().parents[1]
path = ROOT / "ingestion" / "P01_Ingestion_API.py"
spec = importlib.util.spec_from_file_location("p01_ingestion_api", path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class IngestionAPITests(unittest.TestCase):
    def test_loopback_policy(self):
        self.assertTrue(mod.is_loopback_bind("127.0.0.1"))
        self.assertTrue(mod.is_loopback_bind("::1"))
        self.assertTrue(mod.is_loopback_bind("localhost"))
        self.assertFalse(mod.is_loopback_bind("0.0.0.0"))
        self.assertFalse(mod.is_loopback_bind("192.168.100.20"))
        with self.assertRaises(ValueError):
            mod.require_loopback_bind("0.0.0.0")

    def test_stage_rejects_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            service = mod.IngestionService(pathlib.Path(td), max_upload_bytes=1024)
            data = b"not-a-real-bundle"
            with self.assertRaises(mod.IngestionError) as ctx:
                service._stage_stream(io.BytesIO(data), len(data), "0" * 64)
            self.assertEqual(ctx.exception.status_code, 422)

    def test_stage_rejects_oversized_upload(self):
        with tempfile.TemporaryDirectory() as td:
            service = mod.IngestionService(pathlib.Path(td), max_upload_bytes=4)
            with self.assertRaises(mod.IngestionError) as ctx:
                service._stage_stream(io.BytesIO(b"12345"), 5, hashlib.sha256(b"12345").hexdigest())
            self.assertEqual(ctx.exception.status_code, 413)

    @mock.patch.object(mod, "import_bundle")
    @mock.patch.object(mod, "_bundle_manifest_from_validated_file")
    @mock.patch.object(mod, "validate_bundle")
    def test_ingest_uses_common_offline_importer(self, validate, manifest, importer):
        validate.return_value = {
            "bundle_id": "bnd-0123456789abcdef0123",
            "artifact_count": 8,
            "credentialed_evidence_count": 5,
            "verified_inventory_entries": 9,
        }
        manifest.return_value = {
            "bundle_id": "bnd-0123456789abcdef0123",
            "assessment_id": "P01LAB-CTX-R1",
        }
        importer.return_value = {
            "status": "imported",
            "bundle_id": "bnd-0123456789abcdef0123",
            "assessment_id": "P01LAB-CTX-R1",
            "semantic_match": True,
        }

        data = b"synthetic-bundle-bytes"
        sha = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as td:
            service = mod.IngestionService(pathlib.Path(td), process=True)
            result = service.ingest_stream(
                io.BytesIO(data),
                len(data),
                sha,
                idempotency_key="bnd-0123456789abcdef0123",
            )

        self.assertEqual(result["status"], "imported")
        self.assertTrue(result["semantic_match"])
        importer.assert_called_once()
        kwargs = importer.call_args.kwargs
        self.assertTrue(kwargs["require_outer_sidecar"])
        self.assertTrue(kwargs["process"])

    @mock.patch.object(mod, "_bundle_manifest_from_validated_file")
    @mock.patch.object(mod, "validate_bundle")
    def test_idempotency_key_must_match_validated_bundle(self, validate, manifest):
        validate.return_value = {
            "bundle_id": "bnd-0123456789abcdef0123",
            "artifact_count": 8,
            "credentialed_evidence_count": 5,
            "verified_inventory_entries": 9,
        }
        manifest.return_value = {
            "bundle_id": "bnd-0123456789abcdef0123",
            "assessment_id": "P01LAB-CTX-R1",
        }
        data = b"synthetic-bundle-bytes"
        sha = hashlib.sha256(data).hexdigest()

        with tempfile.TemporaryDirectory() as td:
            service = mod.IngestionService(pathlib.Path(td))
            with self.assertRaises(mod.IngestionError) as ctx:
                service.ingest_stream(
                    io.BytesIO(data),
                    len(data),
                    sha,
                    idempotency_key="bnd-ffffffffffffffffffff",
                )
            self.assertEqual(ctx.exception.status_code, 409)

    def test_lookup_returns_receipt_summary_only(self):
        bundle_id = "bnd-0123456789abcdef0123"
        with tempfile.TemporaryDirectory() as td:
            store = pathlib.Path(td)
            receipt = store / "assessments" / "P01LAB-CTX-R1" / "imports" / bundle_id / "receipt" / "import-receipt.json"
            receipt.parent.mkdir(parents=True)
            receipt.write_text(json.dumps({
                "status": "imported",
                "bundle_id": bundle_id,
                "assessment_id": "P01LAB-CTX-R1",
                "run_id": "R1",
                "node_id": "P01-MGMT01",
                "outer_sha256_verified": True,
                "artifact_count": 8,
                "credentialed_evidence_count": 5,
                "verified_inventory_entries": 9,
                "processing": {
                    "requested": True,
                    "asset_resolver_executed": True,
                    "semantic_match": True,
                    "edge_semantic_sha256": "a" * 64,
                    "server_semantic_sha256": "a" * 64,
                },
                "sensitive_internal_path": "must-not-be-returned",
            }), encoding="utf-8")
            service = mod.IngestionService(store)
            result = service.lookup(bundle_id)

        self.assertEqual(result["bundle_id"], bundle_id)
        self.assertTrue(result["processing"]["semantic_match"])
        self.assertNotIn("sensitive_internal_path", result)

    def test_health_endpoint(self):
        with tempfile.TemporaryDirectory() as td:
            service = mod.IngestionService(pathlib.Path(td), process=False)
            server = mod.P01HTTPServer(("127.0.0.1", 0), mod.P01IngestionHandler, service)
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=3) as resp:
                    payload = json.loads(resp.read().decode())
                    self.assertEqual(resp.status, 200)
                    self.assertEqual(payload["status"], "ok")
                    self.assertEqual(payload["bind_policy"], "loopback_only")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

    def test_http_missing_sha_closes_connection(self):
        with tempfile.TemporaryDirectory() as td:
            service = mod.IngestionService(pathlib.Path(td), process=False)
            server = mod.P01HTTPServer(("127.0.0.1", 0), mod.P01IngestionHandler, service)
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                req = request.Request(
                    f"http://127.0.0.1:{port}/api/v1/bundles",
                    data=b"abc",
                    method="POST",
                    headers={"Content-Type": "application/octet-stream"},
                )
                with self.assertRaises(error.HTTPError) as ctx:
                    request.urlopen(req, timeout=3)
                self.assertEqual(ctx.exception.code, 400)
                self.assertEqual(ctx.exception.headers.get("Connection"), "close")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

    def test_http_oversized_upload_closes_connection(self):
        with tempfile.TemporaryDirectory() as td:
            service = mod.IngestionService(pathlib.Path(td), process=False, max_upload_bytes=4)
            server = mod.P01HTTPServer(("127.0.0.1", 0), mod.P01IngestionHandler, service)
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                data = b"12345"
                req = request.Request(
                    f"http://127.0.0.1:{port}/api/v1/bundles",
                    data=data,
                    method="POST",
                    headers={
                        "Content-Type": "application/octet-stream",
                        "X-P01-Bundle-SHA256": hashlib.sha256(data).hexdigest(),
                    },
                )
                with self.assertRaises(error.HTTPError) as ctx:
                    request.urlopen(req, timeout=3)
                self.assertEqual(ctx.exception.code, 413)
                self.assertEqual(ctx.exception.headers.get("Connection"), "close")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

    def test_http_rejects_non_bundle_content_type(self):
        with tempfile.TemporaryDirectory() as td:
            service = mod.IngestionService(pathlib.Path(td), process=False)
            server = mod.P01HTTPServer(("127.0.0.1", 0), mod.P01IngestionHandler, service)
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                req = request.Request(
                    f"http://127.0.0.1:{port}/api/v1/bundles",
                    data=b"abc",
                    method="POST",
                    headers={"Content-Type": "text/plain", "X-P01-Bundle-SHA256": hashlib.sha256(b"abc").hexdigest()},
                )
                with self.assertRaises(error.HTTPError) as ctx:
                    request.urlopen(req, timeout=3)
                self.assertEqual(ctx.exception.code, 415)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
