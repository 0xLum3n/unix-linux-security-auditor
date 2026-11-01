"""Unit tests for unix_security_auditor.py (Python standard library only)."""
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from unix_security_auditor import (
    PosixACL, READ, WRITE, EXECUTE, acl_access_decision,
    mode_access_decision, sha256_file, create_baseline, verify_baseline,
    audit_directory,
)


def fake_stat(uid=1000, gid=2000, mode=0o640, file_type=stat.S_IFREG):
    """Create a minimal stat_result with the needed st_mode/st_uid/st_gid."""
    values = [0] * 10
    values[0] = file_type | mode
    values[4] = uid
    values[5] = gid
    return os.stat_result(values)


class SecurityModelTests(unittest.TestCase):
    def test_unsupported_platform_exits_before_unix_only_imports(self):
        """Windows and non-Unix platforms get a clear message and exit early."""
        script_path = Path(__file__).with_name("unix_security_auditor.py")
        for unsupported_platform in ("win32", "emscripten"):
            with self.subTest(platform=unsupported_platform):
                code = (
                    "import sys; "
                    f"sys.platform = {unsupported_platform!r}; "
                    "import runpy; "
                    f"runpy.run_path({str(script_path)!r}, run_name='__main__')"
                )
                result = subprocess.run(
                    [sys.executable, "-c", code],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 2)
                combined = result.stdout + result.stderr
                self.assertIn("UNSUPPORTED OPERATING SYSTEM", combined)
                self.assertIn(unsupported_platform, combined)
                self.assertIn("No inspection, audit or simulation was started", combined)
                self.assertNotIn("ModuleNotFoundError", combined)
                self.assertNotIn("Traceback", combined)

    def test_owner_uses_owner_bits(self):
        decision = mode_access_decision(fake_stat(mode=0o640), 1000, {2000}, "write")
        self.assertTrue(decision.allowed)
        self.assertIn("owner", decision.reason)

    def test_group_uses_group_bits(self):
        decision = mode_access_decision(fake_stat(mode=0o640), 1001, {2000, 3000}, "read")
        self.assertTrue(decision.allowed)

    def test_supplementary_group_is_considered(self):
        decision = mode_access_decision(fake_stat(mode=0o640), 1001, {3000, 2000}, "read")
        self.assertTrue(decision.allowed)

    def test_other_user_is_denied(self):
        decision = mode_access_decision(fake_stat(mode=0o640), 1001, {3000}, "read")
        self.assertFalse(decision.allowed)

    def test_root_can_read_but_cannot_execute_regular_file_without_execute_bit(self):
        self.assertTrue(mode_access_decision(fake_stat(mode=0o600), 0, {0}, "read").allowed)
        self.assertFalse(mode_access_decision(fake_stat(mode=0o600), 0, {0}, "execute").allowed)

    def test_root_can_search_directory_even_without_execute_mode_bit(self):
        directory_stat = fake_stat(mode=0o600, file_type=stat.S_IFDIR)
        self.assertTrue(mode_access_decision(directory_stat, 0, {0}, "execute").allowed)

    def test_acl_named_user_and_mask(self):
        acl = PosixACL(1000, 2000, 6, 4, 0, named_users={1002: 6}, mask=4)
        decision = acl_access_decision(acl, 1002, {3000}, "write")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.effective_permissions, 4)

    def test_acl_owner_is_not_limited_by_mask(self):
        acl = PosixACL(1000, 2000, 6, 4, 0, named_users={1002: 6}, mask=4)
        decision = acl_access_decision(acl, 1000, {2000}, "write")
        self.assertTrue(decision.allowed)

    def test_acl_named_user_match_does_not_fall_through(self):
        acl = PosixACL(1000, 2000, 6, 4, 7, named_users={1002: 4}, mask=7)
        decision = acl_access_decision(acl, 1002, {2000}, "write")
        self.assertFalse(decision.allowed)

    def test_acl_matching_groups_are_unioned_then_masked(self):
        acl = PosixACL(1000, 2000, 6, 4, 0,
                       named_groups={3000: 2}, mask=6)
        decision = acl_access_decision(acl, 1002, {2000, 3000}, "write")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.effective_permissions, 6)

    def test_acl_other_entry_used_when_no_other_entry_matches(self):
        acl = PosixACL(1000, 2000, 6, 4, 4)
        self.assertTrue(acl_access_decision(acl, 1002, {3000}, "read").allowed)
        self.assertFalse(acl_access_decision(acl, 1002, {3000}, "write").allowed)

    def test_sha256_baseline_detects_modification(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            folder = Path(temp_dir)
            target = folder / "important.conf"
            baseline = folder / "baseline.json"
            target.write_text("system=secure\n", encoding="utf-8")
            create_baseline(target, baseline)
            unchanged, _, _ = verify_baseline(target, baseline)
            self.assertTrue(unchanged)
            target.write_text("system=modified\n", encoding="utf-8")
            unchanged, old, new = verify_baseline(target, baseline)
            self.assertFalse(unchanged)
            self.assertNotEqual(old, new)

    def test_audit_finds_world_writable_file_and_skips_symlinks(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            folder = Path(temp_dir)
            risky = folder / "public-write.txt"
            risky.write_text("demo\n", encoding="utf-8")
            risky.chmod(0o666)
            link = folder / "linked-risk.txt"
            try:
                link.symlink_to(risky)
            except (OSError, NotImplementedError):
                pass
            findings = audit_directory(folder)
            self.assertTrue(any("WORLD_WRITABLE_FILE" in x.findings for x in findings))
            self.assertFalse(any(x.path == str(link) for x in findings))


if __name__ == "__main__":
    unittest.main(verbosity=2)
