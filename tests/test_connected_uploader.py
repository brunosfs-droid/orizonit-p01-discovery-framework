import importlib.util
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
path = ROOT / "connected" / "P01_Discovery_Node_Uploader.py"
spec = importlib.util.spec_from_file_location("p01_connected_uploader", path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ConnectedUploaderTests(unittest.TestCase):
    def test_server_url_requires_https(self):
        with self.assertRaises(mod.UploadError):
            mod.validate_server_url("http://127.0.0.1:8443")

    def test_server_url_builds_endpoint(self):
        host, port, endpoint = mod.validate_server_url("https://p01-server.example:8443")
        self.assertEqual(host, "p01-server.example")
        self.assertEqual(port, 8443)
        self.assertEqual(endpoint, "/api/v1/bundles")

    def test_missing_tls_files_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            base = pathlib.Path(td)
            with self.assertRaises(mod.UploadError):
                mod.build_ssl_context(
                    base / "missing-ca.crt",
                    base / "missing-client.crt",
                    base / "missing-client.key",
                )

    @mock.patch.object(mod, "bundle_manifest")
    def test_local_node_must_match_bundle_node(self, manifest):
        manifest.return_value = {
            "bundle_id": "bnd-0123456789abcdef0123",
            "node_id": "P01-MGMT01",
        }
        with tempfile.TemporaryDirectory() as td:
            bundle = pathlib.Path(td) / "x.p01bundle"
            bundle.write_bytes(b"synthetic")
            with self.assertRaises(mod.UploadError):
                mod.upload_once(
                    "https://localhost:8443",
                    bundle,
                    "OTHER-NODE",
                    pathlib.Path(td) / "ca.crt",
                    pathlib.Path(td) / "client.crt",
                    pathlib.Path(td) / "client.key",
                )

    @mock.patch.object(mod.time, "sleep")
    @mock.patch.object(mod, "upload_once")
    def test_transport_failure_retries_then_succeeds(self, upload_once, sleep):
        upload_once.side_effect = [
            ConnectionRefusedError("temporary"),
            (201, {
                "status": "imported",
                "bundle_id": "bnd-0123456789abcdef0123",
                "assessment_id": "P01LAB-CTX-R1",
            }),
        ]
        result = mod.upload_with_retries(
            "https://localhost:8443",
            pathlib.Path("bundle.p01bundle"),
            "P01-MGMT01",
            pathlib.Path("ca.crt"),
            pathlib.Path("client.crt"),
            pathlib.Path("client.key"),
            max_retries=2,
        )
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(upload_once.call_count, 2)
        sleep.assert_called_once()

    @mock.patch.object(mod, "upload_once")
    def test_http_rejection_is_not_retried(self, upload_once):
        upload_once.return_value = (
            403,
            {"error": {"status": 403, "message": "node mismatch"}},
        )
        with self.assertRaises(mod.UploadError):
            mod.upload_with_retries(
                "https://localhost:8443",
                pathlib.Path("bundle.p01bundle"),
                "P01-MGMT01",
                pathlib.Path("ca.crt"),
                pathlib.Path("client.crt"),
                pathlib.Path("client.key"),
                max_retries=2,
            )
        self.assertEqual(upload_once.call_count, 1)

    @mock.patch.object(mod, "upload_once")
    def test_tls_error_is_not_retried(self, upload_once):
        upload_once.side_effect = __import__("ssl").SSLError("certificate failed")
        with self.assertRaises(mod.UploadError):
            mod.upload_with_retries(
                "https://localhost:8443",
                pathlib.Path("bundle.p01bundle"),
                "P01-MGMT01",
                pathlib.Path("ca.crt"),
                pathlib.Path("client.crt"),
                pathlib.Path("client.key"),
                max_retries=2,
            )
        self.assertEqual(upload_once.call_count, 1)


if __name__ == "__main__":
    unittest.main()
