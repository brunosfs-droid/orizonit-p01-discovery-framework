"""No-network tests of E0 artifact integrity and path confinement."""
import copy
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "docs/validation/E0_EVIDENCE_ARTIFACT_CHECK_v0.6.84.py"
REGISTER = ROOT / "docs/validation/E0_EVIDENCE_REGISTER_v0.6.82.json"
SPEC = importlib.util.spec_from_file_location("e0_artifact_verifier", SCRIPT)
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


class E0ArtifactIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "evidence"
        self.root.mkdir()
        self.document = json.loads(REGISTER.read_text(encoding="utf-8"))
        self.document.update({
            "release_commit": "a" * 40,
            "topology_sha256": "b" * 64,
            "scope_approval_ref": "lab-approval-01",
            "operator": "lab-operator",
            "executed_at_utc": "2026-10-10T12:00:00Z",
            "security_reviewer": "security-checker",
            "release_reviewer": "release-checker",
        })
        for gate in self.document["gates"]:
            gid = gate["gate_id"]
            folder = self.root / gid
            folder.mkdir()
            contents = f"offline sanitized artifact for {gid}\n".encode()
            (folder / "report.txt").write_bytes(contents)
            gate.update({
                "result": "PASS",
                "evidence_uri": f"evidence://local/{gid}/report.txt",
                "evidence_sha256": hashlib.sha256(contents).hexdigest(),
                "reviewer": "independent-reviewer",
                "executed_at_utc": "2026-10-10T12:30:00Z",
            })

    def test_all_local_bytes_match_but_never_operational_go(self):
        valid, verified, report = checker.verify(self.document, self.root)
        self.assertTrue(valid)
        self.assertTrue(verified)
        self.assertEqual(report["verified_artifacts"], 10)
        target = Path(self.temp.name) / "register.json"
        target.write_text(json.dumps(self.document), encoding="utf-8")
        out = io.StringIO()
        with redirect_stdout(out):
            code = checker.main(["--check", str(target), "--evidence-root", str(self.root)])
        self.assertEqual(code, 0)
        result = json.loads(out.getvalue())
        self.assertEqual(result["verdict"], "ARTIFACTS_VERIFIED")
        self.assertFalse(result["operational_go"])
        self.assertNotIn(str(self.root), out.getvalue())

    def test_tampering_detected_without_disclosing_content(self):
        (self.root / "E0-01" / "report.txt").write_bytes(b"secret data changed")
        valid, verified, report = checker.verify(self.document, self.root)
        self.assertTrue(valid)
        self.assertFalse(verified)
        self.assertIn("E0-01: SHA-256 mismatch", report["artifact_errors"])
        self.assertNotIn("secret", json.dumps(report))

    def test_missing_and_oversized_artifacts_are_rejected(self):
        (self.root / "E0-01" / "report.txt").unlink()
        self.assertFalse(checker.verify(self.document, self.root)[1])
        with patch.object(checker, "MAX_ARTIFACT_BYTES", 2):
            valid, verified, report = checker.verify(self.document, self.root)
        self.assertTrue(valid)
        self.assertFalse(verified)
        self.assertIn("E0-02: artifact unavailable or unsafe", report["artifact_errors"])

    def test_traversal_other_gate_and_remote_uri_invalid(self):
        for uri in (
            "evidence://local/E0-01/../E0-02/report.txt",
            "evidence://local/E0-02/report.txt",
            "https://example.com/report.txt",
            "evidence://local/E0-01/%2e%2e/report.txt",
            "evidence://local/E0-01/report.txt?token=secret",
        ):
            with self.subTest(uri=uri):
                d = copy.deepcopy(self.document)
                d["gates"][0]["evidence_uri"] = uri
                valid, verified, report = checker.verify(d, self.root)
                self.assertFalse(valid)
                self.assertFalse(verified)
                self.assertIn("E0-01: invalid local artifact reference", report["artifact_errors"])
                self.assertNotIn("token=secret", json.dumps(report))

    def test_symlink_artifact_and_directory_are_refused(self):
        if not hasattr(os, "symlink") or not hasattr(os, "O_NOFOLLOW"):
            self.skipTest("secure symlink checks unavailable")
        source = self.root / "E0-01" / "report.txt"
        source.unlink()
        try:
            source.symlink_to(self.root / "E0-02" / "report.txt")
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks unavailable: {type(exc).__name__}")
        self.assertFalse(checker.verify(self.document, self.root)[1])
        source.unlink()
        source.write_bytes(b"offline sanitized artifact for E0-01\n")
        folder = self.root / "E0-01"
        folder.rename(self.root / "relocated")
        folder.symlink_to(self.root / "relocated", target_is_directory=True)
        self.assertFalse(checker.verify(self.document, self.root)[1])

    def test_incomplete_register_never_reads_files_or_verifies(self):
        d = copy.deepcopy(self.document)
        d["gates"][0]["result"] = "NOT RUN"
        valid, verified, report = checker.verify(d, self.root / "nonexistent")
        self.assertTrue(valid)
        self.assertFalse(verified)
        self.assertEqual(report["verified_artifacts"], 0)

    def test_incomplete_evidence_metadata_invalid(self):
        d = copy.deepcopy(self.document)
        d["gates"][0]["evidence_sha256"] = None
        valid, verified, report = checker.verify(d, self.root)
        self.assertFalse(valid)
        self.assertFalse(verified)
        self.assertEqual(report["verified_artifacts"], 0)


if __name__ == "__main__":
    unittest.main()
