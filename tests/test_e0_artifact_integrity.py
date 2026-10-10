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

SNAPSHOT_SCRIPT = ROOT / "docs/validation/E0_EVIDENCE_SNAPSHOT_v0.6.85.py"
SNAPSHOT_SPEC = importlib.util.spec_from_file_location("e0_snapshot_v085", SNAPSHOT_SCRIPT)
snapshot_checker = importlib.util.module_from_spec(SNAPSHOT_SPEC)
SNAPSHOT_SPEC.loader.exec_module(snapshot_checker)


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


    def test_snapshot_is_reproducible_and_gate_order_independent(self):
        valid, ready, first = snapshot_checker.snapshot(self.document, self.root)
        self.assertTrue(valid)
        self.assertTrue(ready)
        self.assertFalse(first["operational_go"])
        self.assertEqual(len(first["snapshot_sha256"]), 64)
        reordered = copy.deepcopy(self.document)
        reordered["gates"].reverse()
        valid, ready, second = snapshot_checker.snapshot(reordered, self.root)
        self.assertTrue(valid)
        self.assertTrue(ready)
        self.assertEqual(first["snapshot_sha256"], second["snapshot_sha256"])

    def test_snapshot_tracks_release_topology_and_reviewer_changes(self):
        first = snapshot_checker.snapshot(self.document, self.root)[2]["snapshot_sha256"]
        updates = (
            ("release_commit", "d" * 40),
            ("topology_sha256", "e" * 64),
            ("security_reviewer", "new-independent-security-checker"),
            ("scope_approval_ref", "lab-approval-02"),
        )
        for field, value in updates:
            with self.subTest(field=field):
                document = copy.deepcopy(self.document)
                document[field] = value
                valid, ready, report = snapshot_checker.snapshot(document, self.root)
                self.assertTrue(valid)
                self.assertTrue(ready)
                self.assertNotEqual(first, report["snapshot_sha256"])

    def test_snapshot_tracks_verified_artifact_change(self):
        first = snapshot_checker.snapshot(self.document, self.root)[2]["snapshot_sha256"]
        path = self.root / "E0-01" / "report.txt"
        changed = b"altered synthetic evidence bytes\n"
        path.write_bytes(changed)
        amended = copy.deepcopy(self.document)
        amended["gates"][0]["evidence_sha256"] = hashlib.sha256(changed).hexdigest()
        valid, ready, report = snapshot_checker.snapshot(amended, self.root)
        self.assertTrue(valid)
        self.assertTrue(ready)
        self.assertNotEqual(first, report["snapshot_sha256"])

    def test_snapshot_is_absent_on_mismatch_or_pending_e0_gate(self):
        (self.root / "E0-01" / "report.txt").write_bytes(b"tampered")
        valid, ready, report = snapshot_checker.snapshot(self.document, self.root)
        self.assertTrue(valid)
        self.assertFalse(ready)
        self.assertNotIn("snapshot_sha256", report)
        pending = copy.deepcopy(self.document)
        pending["gates"][0]["result"] = "NOT RUN"
        valid, ready, report = snapshot_checker.snapshot(pending, self.root)
        self.assertTrue(valid)
        self.assertFalse(ready)
        self.assertNotIn("snapshot_sha256", report)

    def test_snapshot_cli_never_reports_operational_approval(self):
        filename = Path(self.temp.name) / "private-e0.json"
        filename.write_text(json.dumps(self.document), encoding="utf-8")
        out = io.StringIO()
        with redirect_stdout(out):
            code = snapshot_checker.main(["--check", str(filename),
                                          "--evidence-root", str(self.root)])
        self.assertEqual(code, 0)
        report = json.loads(out.getvalue())
        self.assertEqual(report["verdict"], "SNAPSHOT_READY")
        self.assertFalse(report["operational_go"])
        self.assertNotIn("lab-approval-01", out.getvalue())
        self.assertNotIn(str(self.root), out.getvalue())

if __name__ == "__main__":
    unittest.main()
