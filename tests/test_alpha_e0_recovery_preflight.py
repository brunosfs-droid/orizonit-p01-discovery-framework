"""Non-destructive, cross-platform unit tests for the E0 offline artifact gate."""
import json
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "docs" / "validation" / "ALPHA_E0_RECOVERY_PREFLIGHT.py"
SPEC = importlib.util.spec_from_file_location("alpha_e0_recovery_preflight", GATE)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class E0RecoveryArtifactTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.dump = self.root / "database.dump"
        self.roles = self.root / "globals.sql"
        self.store = self.root / "store"
        self.config = self.root / "private-config"
        self.output = self.root / "proof.json"
        self.dump.write_bytes(b"pg_custom_dump_fixture")
        self.roles.write_bytes(b"CREATE ROLE fixture;")
        (self.store / "assessments").mkdir(parents=True)
        (self.store / "assessments" / "receipt.json").write_bytes(
            b'{"assessment_id":"sensitive-alpha"}')
        self.config.mkdir()
        (self.config / "client.key").write_bytes(b"SECRET-DO-NOT-LOG")

    def run_gate(self, action, **options):
        args = [sys.executable, str(GATE), action,
                "--database-dump", str(options.get("dump", self.dump)),
                "--roles-snapshot", str(options.get("roles", self.roles)),
                "--store-root", str(options.get("store", self.store)),
                "--config-root", str(options.get("config", self.config))]
        args += (["--output", str(options.get("output", self.output))]
                 if action == "capture" else
                 ["--manifest", str(options.get("manifest", self.output))])
        process = subprocess.run(args, capture_output=True, text=True, timeout=15)
        self.assertNotIn("SECRET-DO-NOT-LOG", process.stdout + process.stderr)
        self.assertNotIn("sensitive-alpha", process.stdout + process.stderr)
        self.assertNotIn(str(self.root), process.stdout + process.stderr)
        return process, json.loads(process.stdout)

    def capture(self):
        process, result = self.run_gate("capture")
        self.assertEqual(process.returncode, 0, result)
        self.assertEqual(result["status"], "CAPTURED")
        return json.loads(self.output.read_text())

    def test_round_trip_copied_artifacts_and_sanitized_manifest(self):
        manifest = self.capture()
        self.assertEqual(manifest["schema"], "canca-alpha-e0-artifacts-v1")
        self.assertEqual(manifest["artifacts"]["store"]["files"], 1)
        self.assertEqual(manifest["artifacts"]["configuration"]["files"], 1)
        self.assertNotIn("client.key", self.output.read_text())
        self.assertNotIn("SECRET-DO-NOT-LOG", self.output.read_text())
        self.assertNotIn("database.dump", self.output.read_text())
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        verified, result = self.run_gate("verify")
        self.assertEqual(verified.returncode, 0, result)
        self.assertEqual(result["status"], "PASS")
        other = self.root / "copied"
        other.mkdir()
        copy_store = other / "store"
        copy_config = other / "config"
        shutil.copytree(self.store, copy_store, copy_function=shutil.copy2)
        shutil.copytree(self.config, copy_config, copy_function=shutil.copy2)
        dump_copy = other / "database.dump"
        roles_copy = other / "globals.sql"
        shutil.copy2(self.dump, dump_copy)
        shutil.copy2(self.roles, roles_copy)
        copied, result = self.run_gate(
            "verify", store=copy_store, config=copy_config,
            dump=dump_copy, roles=roles_copy)
        self.assertEqual(copied.returncode, 0, result)

    def test_tampered_bundle_data_is_rejected(self):
        self.capture()
        (self.store / "assessments" / "receipt.json").write_bytes(b"changed")
        process, result = self.run_gate("verify")
        self.assertEqual(process.returncode, 2)
        self.assertEqual(result["reason"], "artifact_mismatch")

    def test_renamed_or_chmod_file_is_rejected(self):
        self.capture()
        file = self.store / "assessments" / "receipt.json"
        file.rename(file.with_name("renamed.json"))
        self.assertEqual(self.run_gate("verify")[0].returncode, 2)
        file.with_name("renamed.json").rename(file)
        file.chmod(0o600)
        self.assertEqual(self.run_gate("verify")[0].returncode, 2)

    def test_dump_or_role_snapshot_modified_is_rejected(self):
        self.capture()
        self.dump.write_bytes(b"corrupted")
        self.assertEqual(self.run_gate("verify")[0].returncode, 2)
        self.dump.write_bytes(b"pg_custom_dump_fixture")
        self.roles.write_bytes(b"CREATE ROLE unauthorized;")
        self.assertEqual(self.run_gate("verify")[0].returncode, 2)

    def test_symlinks_and_special_entries_are_rejected(self):
        target = self.root / "external-secret"
        target.write_bytes(b"secret")
        link = self.config / "external-link"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation unsupported")
        process, result = self.run_gate("capture")
        self.assertEqual(process.returncode, 2)
        self.assertEqual(result["reason"], "unsupported_tree_entry")
        self.assertFalse(self.output.exists())
        link.unlink()
        self.store = self.root / "store-link"
        self.store.symlink_to(self.root / "store", target_is_directory=True)
        self.assertEqual(self.run_gate("capture")[0].returncode, 2)

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW") and
                         os.open in os.supports_dir_fd,
                         "directory-descriptor nofollow test requires POSIX")
    def test_parent_symlink_is_rejected_before_any_source_bytes_are_read(self):
        real = self.root / "real-roles"
        real.mkdir()
        (real / "globals.sql").write_bytes(b"PRIVATE-INDIRECT-ROLE")
        alias = self.root / "symlink-roles"
        try:
            alias.symlink_to(real, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation unsupported")
        process, result = self.run_gate("capture", roles=alias / "globals.sql")
        self.assertEqual(process.returncode, 2)
        self.assertEqual(result["reason"], "input_unavailable")
        self.assertFalse(self.output.exists())

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW") and
                         os.open in os.supports_dir_fd,
                         "lstat/open race test requires POSIX")
    def test_symlink_swap_between_lstat_and_open_fails_closed(self):
        sensitive = self.root / "sensitive-roles.sql"
        sensitive.write_bytes(b"SECRET-NEVER-READ")
        backup = self.root / "original-roles.sql"
        original = gate._regular
        swapped = False

        def replace_after_initial_lstat(path):
            nonlocal swapped
            info = original(path)
            if path == self.roles and not swapped:
                swapped = True
                self.roles.rename(backup)
                self.roles.symlink_to(sensitive)
            return info

        with patch.object(gate, "_regular", side_effect=replace_after_initial_lstat):
            with self.assertRaisesRegex(gate.GateError, "input_unavailable"):
                gate._file(self.roles)
        self.assertTrue(swapped)
        self.assertEqual(sensitive.read_bytes(), b"SECRET-NEVER-READ")
        self.assertFalse(self.output.exists())

    def test_same_backup_bytes_keep_round_trip_valid_after_hardening(self):
        self.capture()
        outcome, result = self.run_gate("verify")
        self.assertEqual(outcome.returncode, 0)
        self.assertEqual(result["status"], "PASS")

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW") and
                         os.open in os.supports_dir_fd and
                         os.stat in os.supports_dir_fd,
                         "fd-anchored tree traversal requires POSIX")
    def test_nested_tree_preserves_v1_manifest_digest(self):
        nested = self.store / "assessments" / "nested"
        nested.mkdir()
        (nested / "inventory.json").write_bytes(b"synthetic-inventory")
        expected = hashlib.sha256()
        expected.update(("ROOT\\0" + oct(stat.S_IMODE(self.store.lstat().st_mode)) +
                         "\\n").encode())
        for path in sorted(self.store.rglob("*"),
                           key=lambda p: p.relative_to(self.store).as_posix()):
            info = path.lstat()
            name = path.relative_to(self.store).as_posix()
            if path.is_dir():
                line = ["D", name, oct(stat.S_IMODE(info.st_mode))]
            else:
                line = ["F", name, str(info.st_size),
                        hashlib.sha256(path.read_bytes()).hexdigest(),
                        oct(stat.S_IMODE(info.st_mode))]
            expected.update(("\\0".join(line) + "\\n").encode("utf-8"))
        result = gate._directory(self.store)
        self.assertEqual(result["sha256"], expected.hexdigest())
        self.assertEqual(result["files"], 2)
        self.assertEqual(result["directories"], 2)
        self.assertEqual(self.capture()["artifacts"]["store"]["sha256"],
                         expected.hexdigest())

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW") and
                         os.open in os.supports_dir_fd and
                         os.stat in os.supports_dir_fd,
                         "fd-anchored tree traversal requires POSIX")
    def test_nested_file_symlink_swap_before_open_is_blocked(self):
        entry = self.store / "assessments" / "receipt.json"
        original_file = self.root / "original-receipt"
        target = self.root / "external-secret"
        target.write_bytes(b"PRIVATE-TARGET-NOT-IN-SNAPSHOT")
        opened = os.open
        swapped = False

        def swap_before_open(path, flags, *args, **kwargs):
            nonlocal swapped
            if path == "receipt.json" and kwargs.get("dir_fd") is not None and not swapped:
                swapped = True
                entry.rename(original_file)
                entry.symlink_to(target)
            return opened(path, flags, *args, **kwargs)

        with (
            patch.object(gate, "_secure_tree_supported", return_value=True),
            patch.object(gate.os, "open", side_effect=swap_before_open),
        ):
            with self.assertRaisesRegex(gate.GateError, "input_unavailable"):
                gate._directory(self.store)
        self.assertTrue(swapped)
        self.assertEqual(target.read_bytes(), b"PRIVATE-TARGET-NOT-IN-SNAPSHOT")

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW") and
                         os.open in os.supports_dir_fd and
                         os.stat in os.supports_dir_fd,
                         "fd-anchored tree traversal requires POSIX")
    def test_subdirectory_symlink_swap_before_open_is_blocked(self):
        entry = self.store / "assessments"
        old = self.root / "old-assessments"
        target = self.root / "external-directory"
        target.mkdir()
        (target / "secret.key").write_bytes(b"PRIVATE-OUTSIDE-TREE")
        opened = os.open
        swapped = False

        def swap_before_open(path, flags, *args, **kwargs):
            nonlocal swapped
            if path == "assessments" and kwargs.get("dir_fd") is not None and not swapped:
                swapped = True
                entry.rename(old)
                entry.symlink_to(target, target_is_directory=True)
            return opened(path, flags, *args, **kwargs)

        with (
            patch.object(gate, "_secure_tree_supported", return_value=True),
            patch.object(gate.os, "open", side_effect=swap_before_open),
        ):
            with self.assertRaisesRegex(gate.GateError, "input_unavailable"):
                gate._directory(self.store)
        self.assertTrue(swapped)

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW") and
                         os.open in os.supports_dir_fd and
                         os.stat in os.supports_dir_fd,
                         "fd-anchored tree traversal requires POSIX")
    def test_new_entry_created_during_walk_invalidates_tree(self):
        original_listdir = os.listdir
        changed = False

        def mutate_after_enumeration(fd):
            nonlocal changed
            names = original_listdir(fd)
            if not changed:
                changed = True
                (self.store / "new-unlisted.txt").write_bytes(b"new-child")
            return names

        with patch.object(gate.os, "listdir", side_effect=mutate_after_enumeration):
            with self.assertRaisesRegex(gate.GateError, "input_changed"):
                gate._directory(self.store)
        self.assertTrue(changed)

    def test_no_overwrite_and_no_output_inside_source_tree(self):
        self.capture()
        contents = self.output.read_bytes()
        process, _ = self.run_gate("capture")
        self.assertEqual(process.returncode, 2)
        self.assertEqual(self.output.read_bytes(), contents)
        process, result = self.run_gate("capture", output=self.config / "proof.json")
        self.assertEqual(process.returncode, 2)
        self.assertEqual(result["reason"], "unsafe_output")

    def test_missing_and_empty_inputs_fail_closed(self):
        self.roles.unlink()
        self.assertEqual(self.run_gate("capture")[0].returncode, 2)
        self.roles.write_bytes(b"CREATE ROLE fixture;")
        (self.store / "assessments" / "receipt.json").unlink()
        self.assertEqual(self.run_gate("capture")[0].returncode, 2)

    def test_tampered_or_malformed_manifest_is_rejected(self):
        manifest = self.capture()
        manifest["artifacts"]["store"]["files"] = 999
        self.output.write_text(json.dumps(manifest))
        self.assertEqual(self.run_gate("verify")[0].returncode, 2)
        self.output.write_bytes(b"{not-json")
        process, result = self.run_gate("verify")
        self.assertEqual(process.returncode, 2)
        self.assertEqual(result["reason"], "manifest_invalid")

    def test_nonprivate_manifest_directory_is_rejected(self):
        self.root.chmod(0o755)
        process, result = self.run_gate("capture")
        self.assertEqual(process.returncode, 2)
        self.assertEqual(result["reason"], "unsafe_output")

    def test_overlapping_inputs_are_rejected(self):
        process, result = self.run_gate("capture", store=self.config)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(result["reason"], "overlapping_inputs")


if __name__ == "__main__":
    unittest.main()
