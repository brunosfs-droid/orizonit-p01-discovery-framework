"""Offline E0 evidence-gate contract tests: no EVE-NG invocation."""
import copy
import importlib.util
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "docs/validation/E0_EVIDENCE_CHECK_v0.6.82.py"
REGISTER = ROOT / "docs/validation/E0_EVIDENCE_REGISTER_v0.6.82.json"
spec = importlib.util.spec_from_file_location("e0_evidence_check", SCRIPT)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class E0EvidenceGateTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(REGISTER.read_text(encoding="utf-8"))

    def complete(self):
        d = copy.deepcopy(self.document)
        d.update({
            "release_commit": "a" * 40,
            "topology_sha256": "b" * 64,
            "scope_approval_ref": "lab-approval-01",
            "operator": "lab-reviewer",
            "executed_at_utc": "2026-10-10T12:00:00Z",
            "security_reviewer": "security-reviewer",
            "release_reviewer": "release-reviewer",
        })
        for gate in d["gates"]:
            gate.update({
                "result": "PASS",
                "evidence_uri": "evidence://restricted/" + gate["gate_id"],
                "evidence_sha256": "c" * 64,
                "reviewer": "independent-reviewer",
                "executed_at_utc": "2026-10-10T12:30:00Z",
            })
        return d

    def test_initial_register_is_valid_and_no_go(self):
        valid, go, summary = checker.assess(self.document)
        self.assertTrue(valid)
        self.assertFalse(go)
        self.assertEqual(summary["counts"]["NOT RUN"], 10)
        self.assertEqual(summary["counts"]["PASS"], 0)

    def test_validated_complete_register_can_reach_go(self):
        valid, go, summary = checker.assess(self.complete())
        self.assertTrue(valid)
        self.assertTrue(go)
        self.assertEqual(summary["counts"]["PASS"], 10)

    def test_pass_without_evidence_is_invalid(self):
        self.document["gates"][0]["result"] = "PASS"
        valid, go, summary = checker.assess(self.document)
        self.assertFalse(valid)
        self.assertFalse(go)
        self.assertTrue(any("PASS requires" in error for error in summary["errors"]))

    def test_failed_or_blocked_gate_must_not_go(self):
        for state in ("FAIL", "BLOCKED", "NOT RUN"):
            with self.subTest(state=state):
                d = self.complete()
                d["gates"][0]["result"] = state
                valid, go, _ = checker.assess(d)
                self.assertTrue(valid)
                self.assertFalse(go)

    def test_duplicate_or_missing_gate_id_invalid(self):
        self.document["gates"][0]["gate_id"] = "E0-02"
        valid, go, _ = checker.assess(self.document)
        self.assertFalse(valid)
        self.assertFalse(go)

    def test_malformed_gate_fields_are_rejected_without_crashing(self):
        for field, value in (("gate_id", ["E0-01"]), ("result", ["PASS"])):
            with self.subTest(field=field):
                d = copy.deepcopy(self.document)
                d["gates"][0][field] = value
                valid, go, summary = checker.assess(d)
                self.assertFalse(valid)
                self.assertFalse(go)
                self.assertTrue(summary["errors"])

    def test_invalid_hash_and_timestamp_rejected(self):
        d = self.complete()
        d["gates"][0]["evidence_sha256"] = "not-a-sha"
        d["gates"][1]["executed_at_utc"] = "2026-10-10T12:00:00-03:00"
        valid, go, summary = checker.assess(d)
        self.assertFalse(valid)
        self.assertFalse(go)
        self.assertGreaterEqual(len(summary["errors"]), 2)

    def test_unpinned_release_never_goes(self):
        d = self.complete()
        d["release_commit"] = None
        valid, go, summary = checker.assess(d)
        self.assertTrue(valid)
        self.assertFalse(go)
        self.assertIn("metadata: release_commit", summary["missing"])

    def test_lab_operator_cannot_review_own_pass_gate(self):
        for candidate in ("lab-reviewer", "  LAB-REVIEWER  "):
            with self.subTest(candidate=candidate):
                d = self.complete()
                d["gates"][0]["reviewer"] = candidate
                valid, go, detail = checker.assess(d)
                self.assertFalse(valid)
                self.assertFalse(go)
                self.assertIn("E0-01: gate reviewer must differ from operator", detail["errors"])

    def test_security_and_release_reviewers_must_be_independent(self):
        for field, value in (
            ("security_reviewer", "  LAB-REVIEWER "),
            ("release_reviewer", "lab-reviewer"),
            ("release_reviewer", " SECURITY-REVIEWER "),
        ):
            with self.subTest(field=field, value=value):
                d = self.complete()
                d[field] = value
                valid, go, detail = checker.assess(d)
                self.assertFalse(valid)
                self.assertFalse(go)
                self.assertIn(
                    "operator, security_reviewer and release_reviewer must be distinct",
                    detail["errors"],
                )

    def test_untrusted_gate_id_never_echoes_suspected_secret(self):
        d = self.complete()
        d["gates"][0]["gate_id"] = "secret-value-should-never-appear"
        d["gates"][0]["result"] = "not-a-state"
        valid, go, detail = checker.assess(d)
        self.assertFalse(valid)
        self.assertFalse(go)
        self.assertNotIn("secret-value-should-never-appear", json.dumps(detail))
        self.assertIn("gate[1]: invalid result", detail["errors"])

    def test_checkers_with_distinct_identities_still_go(self):
        d = self.complete()
        valid, go, detail = checker.assess(d)
        self.assertTrue(valid)
        self.assertTrue(go)
        self.assertEqual(detail["errors"], [])

    def test_cli_no_go_exit_code_and_ci_structure_mode(self):
        for ci_mode, expected in ((False, 1), (True, 0)):
            with self.subTest(ci_mode=ci_mode):
                args = ["--check", str(REGISTER)]
                if ci_mode:
                    args.append("--allow-no-go")
                out = io.StringIO()
                with redirect_stdout(out):
                    code = checker.main(args)
                self.assertEqual(code, expected)
                payload = json.loads(out.getvalue())
                self.assertEqual(payload["verdict"], "NO_GO")
                self.assertNotIn("evidence://", out.getvalue())


if __name__ == "__main__":
    unittest.main()
