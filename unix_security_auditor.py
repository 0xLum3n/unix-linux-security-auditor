#!/usr/bin/env python3
"""Unix/Linux security models: interactive auditor and educational simulator.

Features
--------
1. Inspect real file metadata and query the kernel using os.access().
2. Simulate traditional Unix owner/group/other permission decisions.
3. Demonstrate POSIX ACL decision order, named entries and ACL masks.
4. Recursively audit a directory for risky permission bits.
5. Create and verify SHA-256 file-integrity baselines.
6. Run deterministic self-tests.

The program is read-only with respect to inspected permissions. It never calls
chmod/chown/setfacl and never changes the permissions of existing files.
Creating a SHA-256 baseline writes only the JSON baseline file selected by the
operator. The self-test uses temporary files and removes them automatically.

Target: Linux and other POSIX systems with Python 3.9+.
No third-party packages are required.
"""

from __future__ import annotations

# Perform this check before importing POSIX-only modules such as pwd and grp.
# This ensures Windows and other unsupported platforms receive a clear message
# instead of failing with an import error or starting any audit operation.
import sys

_SUPPORTED_UNIX_PLATFORM_PREFIXES = (
    "linux", "darwin", "freebsd", "openbsd", "netbsd",
    "dragonfly", "sunos", "aix",
)

if not sys.platform.startswith(_SUPPORTED_UNIX_PLATFORM_PREFIXES):
    print("=" * 68, file=sys.stderr)
    print("UNSUPPORTED OPERATING SYSTEM", file=sys.stderr)
    print(
        "This program can run only on supported Unix-like systems "
        "(Linux, macOS and BSD/Solaris/AIX).",
        file=sys.stderr,
    )
    print(f"Detected platform: {sys.platform}", file=sys.stderr)
    print(
        "On Windows, open an Ubuntu WSL terminal and run the program there.",
        file=sys.stderr,
    )
    print("No inspection, audit or simulation was started.", file=sys.stderr)
    print("=" * 68, file=sys.stderr)
    raise SystemExit(2)

import argparse
import hashlib
import json
import os
import pwd
import grp
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

READ = 4
WRITE = 2
EXECUTE = 1
OPERATION_BITS = {"r": READ, "read": READ, "w": WRITE, "write": WRITE,
                  "x": EXECUTE, "execute": EXECUTE}
OPERATION_LABELS = {"r": "READ", "w": "WRITE", "x": "EXECUTE"}


@dataclass(frozen=True)
class Decision:
    allowed: bool
    effective_permissions: int
    reason: str


@dataclass(frozen=True)
class PosixACL:
    """Small POSIX ACL model for teaching the ACL access-check order.

    ACL entries are represented by numeric IDs, as the kernel ultimately
    evaluates UID/GID identities. If extended entries are present, a mask is
    required by POSIX ACL rules. The model is deliberately limited to access
    ACL decisions; it does not model default ACL inheritance or Linux
    capabilities.
    """
    owner_uid: int
    owning_group_gid: int
    owner_permissions: int
    owning_group_permissions: int
    other_permissions: int
    named_users: dict[int, int] = field(default_factory=dict)
    named_groups: dict[int, int] = field(default_factory=dict)
    mask: Optional[int] = None

    def __post_init__(self) -> None:
        values = [self.owner_permissions, self.owning_group_permissions,
                  self.other_permissions, *self.named_users.values(),
                  *self.named_groups.values()]
        if self.mask is not None:
            values.append(self.mask)
        if any(not isinstance(value, int) or value < 0 or value > 7 for value in values):
            raise ValueError("ACL permission values must be integers from 0 to 7")
        if (self.named_users or self.named_groups) and self.mask is None:
            raise ValueError("An extended POSIX ACL requires a mask entry")


def permission_text(bits: int) -> str:
    """Convert a 3-bit permission value to rwx notation."""
    return "".join(("r" if bits & READ else "-",
                    "w" if bits & WRITE else "-",
                    "x" if bits & EXECUTE else "-"))


def operation_bit(operation: str) -> int:
    """Return a permission bit for read, write or execute."""
    key = operation.strip().lower()
    if key not in OPERATION_BITS:
        raise ValueError("Operation must be read/r, write/w or execute/x")
    return OPERATION_BITS[key]


def has_permission(granted: int, requested: int) -> bool:
    """True only if every requested bit is present."""
    return (granted & requested) == requested


def mode_access_decision(st: os.stat_result, uid: int, gids: Iterable[int],
                         operation: str) -> Decision:
    """Evaluate classic Unix mode bits for one inode.

    This is an educational *mode-bit* calculation, not a full kernel access
    check. It accounts for the owner, primary/supplementary group IDs and the
    traditional root execute-bit rule. It does not evaluate ACLs, path search
    permissions, capabilities, mount options or MAC policies.
    """
    requested = operation_bit(operation)
    group_ids = set(gids)

    if uid == 0:
        # Linux CAP_DAC_OVERRIDE requires some execute bit for regular files;
        # directory search checks can be bypassed by privileged root.
        if requested == EXECUTE and stat.S_ISREG(st.st_mode) and not (st.st_mode & 0o111):
            return Decision(False, 0, "root cannot execute a regular file with no execute bit set")
        return Decision(True, 7, "root privilege model (special kernel capabilities are simplified)")

    if uid == st.st_uid:
        permissions = (st.st_mode >> 6) & 0o7
        source = "owner bits"
    elif st.st_gid in group_ids:
        permissions = (st.st_mode >> 3) & 0o7
        source = "group bits (primary or supplementary group)"
    else:
        permissions = st.st_mode & 0o7
        source = "other bits"

    allowed = has_permission(permissions, requested)
    return Decision(allowed, permissions, f"{source}: {permission_text(permissions)}")


def acl_access_decision(acl: PosixACL, uid: int, gids: Iterable[int],
                        operation: str) -> Decision:
    """Evaluate an access ACL using POSIX owner -> user -> group -> other order."""
    requested = operation_bit(operation)
    group_ids = set(gids)
    if uid == 0:
        raise ValueError("The ACL policy demo models ordinary users; root/CAP_DAC_OVERRIDE is outside its scope")

    if uid == acl.owner_uid:
        effective = acl.owner_permissions  # ACL mask does not limit owner::
        return Decision(has_permission(effective, requested), effective,
                        f"ACL owner entry: {permission_text(effective)}")

    if uid in acl.named_users:
        raw = acl.named_users[uid]
        effective = raw if acl.mask is None else raw & acl.mask
        return Decision(has_permission(effective, requested), effective,
                        f"named-user ACL {permission_text(raw)}; effective after mask: "
                        f"{permission_text(effective)}")

    matching_group_entries: list[int] = []
    if acl.owning_group_gid in group_ids:
        matching_group_entries.append(acl.owning_group_permissions)
    for gid, permissions in acl.named_groups.items():
        if gid in group_ids:
            matching_group_entries.append(permissions)

    if matching_group_entries:
        combined = 0
        for permissions in matching_group_entries:
            combined |= permissions
        effective = combined if acl.mask is None else combined & acl.mask
        return Decision(has_permission(effective, requested), effective,
                        f"matching group ACL entries combine to {permission_text(combined)}; "
                        f"effective after mask: {permission_text(effective)}")

    effective = acl.other_permissions
    return Decision(has_permission(effective, requested), effective,
                    f"ACL other entry: {permission_text(effective)}")


def owner_name(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def group_name(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def current_identity() -> tuple[int, int, set[int]]:
    """Return the real UID, real GID and supplementary group list."""
    uid = os.getuid()
    gid = os.getgid()
    groups = set(os.getgroups())
    groups.add(gid)
    return uid, gid, groups


def getfacl_output(path: Path) -> tuple[Optional[str], Optional[str]]:
    """Return getfacl output when installed; otherwise return a clear reason."""
    executable = shutil.which("getfacl")
    if not executable:
        return None, "getfacl is not installed (on Debian/Ubuntu, install the 'acl' package)."
    try:
        result = subprocess.run([executable, "-cp", "--", str(path)],
                                capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"Could not run getfacl: {exc}"
    if result.returncode != 0:
        message = result.stderr.strip() or f"getfacl returned exit code {result.returncode}"
        return None, message
    return result.stdout.rstrip(), None


def has_extended_acl(acl_text: Optional[str]) -> Optional[bool]:
    """Detect named access ACL entries from getfacl text; None means unknown."""
    if acl_text is None:
        return None
    for line in acl_text.splitlines():
        line = line.strip()
        if line.startswith("user:") and line.count(":") >= 2:
            qualifier = line.split(":", 2)[1]
            if qualifier:
                return True
        if line.startswith("group:") and line.count(":") >= 2:
            qualifier = line.split(":", 2)[1]
            if qualifier:
                return True
    return False


def inspect_file(path: Path) -> int:
    """Display real metadata and kernel access checks for the current process."""
    if not path.exists() and not path.is_symlink():
        print(f"ERROR: path does not exist: {path}")
        return 2
    try:
        st = path.stat()  # follows symlink, matching normal file access behavior
    except OSError as exc:
        print(f"ERROR: cannot stat {path}: {exc}")
        return 2

    uid, gid, groups = current_identity()
    acl_text, acl_error = getfacl_output(path)
    extended = has_extended_acl(acl_text)

    print("\n=== FILE INSPECTION ===")
    print(f"Path            : {path}")
    if path.is_symlink():
        print(f"Symbolic link   : yes -> {os.readlink(path)} (metadata below is for target)")
    print(f"Type            : {'directory' if stat.S_ISDIR(st.st_mode) else 'regular file' if stat.S_ISREG(st.st_mode) else 'other'}")
    print(f"Permissions     : {stat.filemode(st.st_mode)} (octal {stat.S_IMODE(st.st_mode):04o})")
    print(f"Owner           : {owner_name(st.st_uid)} (UID {st.st_uid})")
    print(f"Group           : {group_name(st.st_gid)} (GID {st.st_gid})")
    print(f"Size            : {st.st_size} bytes")
    print(f"Current process : real UID={uid}, real GID={gid}, groups={sorted(groups)}")

    special = []
    if st.st_mode & stat.S_ISUID:
        special.append("SUID")
    if st.st_mode & stat.S_ISGID:
        special.append("SGID")
    if st.st_mode & stat.S_ISVTX:
        special.append("STICKY")
    print(f"Special bits    : {', '.join(special) if special else 'none'}")
    if st.st_mode & stat.S_IWOTH:
        print("Warning         : world-writable permission is set")

    print("\nPermission comparison for the current process:")
    print("  Request         Mode-bit estimate       os.access() kernel check")
    for operation, flag, short_op in (("READ", os.R_OK, "read"),
                                      ("WRITE", os.W_OK, "write"),
                                      ("EXECUTE/SEARCH", os.X_OK, "execute")):
        try:
            kernel_result = os.access(path, flag)
            mode_result = mode_access_decision(st, uid, groups, short_op)
        except OSError as exc:
            print(f"  {operation:14}: check error: {exc}")
            continue
        mode_text = "ALLOWED" if mode_result.allowed else "DENIED"
        kernel_text = "ALLOWED" if kernel_result else "DENIED"
        match_text = "MATCH" if mode_result.allowed == kernel_result else "DIFFERS"
        print(f"  {operation:14} {mode_text:21} {kernel_text:12} [{match_text}]")

    if acl_text is not None:
        print("\nAccess ACL (getfacl):")
        print(acl_text)
        if extended:
            print("Note: extended ACL entries are present; a simple rwx-only model cannot fully predict the kernel result.")
    else:
        print(f"\nACL details    : {acl_error}")

    print("\nCaution: os.access() is an observation, not a safe authorization gate before open().")
    print("A real operation can still fail because of races, parent-directory permissions, ACLs, capabilities or filesystem rules.")
    return 0


def simulate_file_access(path: Path, uid: int, gids: set[int], operation: str) -> int:
    """Simulate only the classic owner/group/other mode-bit decision for a path."""
    try:
        st = path.stat()
    except OSError as exc:
        print(f"ERROR: cannot stat {path}: {exc}")
        return 2
    decision = mode_access_decision(st, uid, gids, operation)
    print("\n=== MODE-BIT ACCESS SIMULATION ===")
    print(f"File            : {path}")
    print(f"Mode            : {stat.filemode(st.st_mode)} ({stat.S_IMODE(st.st_mode):04o})")
    print(f"File owner/group: {st.st_uid}/{st.st_gid}")
    print(f"Request         : UID {uid}, groups {sorted(gids)}, {operation.upper()}")
    print(f"Selected rights : {permission_text(decision.effective_permissions)}")
    print(f"Reason          : {decision.reason}")
    print(f"Decision        : {'ACCESS GRANTED' if decision.allowed else 'ACCESS DENIED'}")
    acl_text, acl_error = getfacl_output(path)
    if acl_text is not None and has_extended_acl(acl_text):
        print("LIMITATION      : extended ACL found; this result is a mode-bit simulation, not the complete ACL/kernel decision.")
    elif acl_text is None:
        print(f"ACL NOTE        : {acl_error}")
    print("This command does not switch OS identities or alter file permissions.")
    return 0


@dataclass
class AuditFinding:
    path: str
    file_type: str
    permissions: str
    octal_mode: str
    uid: int
    owner: str
    gid: int
    group: str
    findings: list[str]
    severity: str


def classify_entry(path: Path, mode: int, uid: int, gid: int) -> Optional[AuditFinding]:
    """Classify risky permission patterns on one non-symlink filesystem entry."""
    flags: list[str] = []
    is_dir = stat.S_ISDIR(mode)
    is_regular = stat.S_ISREG(mode)

    if mode & stat.S_ISUID:
        flags.append("SETUID_ROOT" if uid == 0 else "SETUID_NONROOT")
    if mode & stat.S_ISGID:
        flags.append("SETGID")
    if mode & stat.S_IWOTH:
        if is_dir and mode & stat.S_ISVTX:
            flags.append("WORLD_WRITABLE_DIRECTORY_WITH_STICKY_BIT")
        elif is_dir:
            flags.append("WORLD_WRITABLE_DIRECTORY_WITHOUT_STICKY_BIT")
        elif is_regular:
            flags.append("WORLD_WRITABLE_FILE")
        else:
            flags.append("WORLD_WRITABLE_SPECIAL_ENTRY")
    if not flags:
        return None

    if any(item in flags for item in ("SETUID_ROOT", "WORLD_WRITABLE_FILE",
                                      "WORLD_WRITABLE_DIRECTORY_WITHOUT_STICKY_BIT",
                                      "WORLD_WRITABLE_SPECIAL_ENTRY")):
        severity = "HIGH"
    elif "SETUID_NONROOT" in flags or "SETGID" in flags:
        severity = "MEDIUM"
    else:
        severity = "INFO"

    if is_dir:
        file_type = "directory"
    elif is_regular:
        file_type = "regular file"
    else:
        file_type = "other"
    return AuditFinding(str(path), file_type, stat.filemode(mode),
                        f"{stat.S_IMODE(mode):04o}", uid, owner_name(uid),
                        gid, group_name(gid), flags, severity)


def audit_directory(folder: Path) -> list[AuditFinding]:
    """Walk a directory tree without following symlinks and return findings."""
    findings: list[AuditFinding] = []
    errors: list[str] = []

    def onerror(error: OSError) -> None:
        errors.append(f"{error.filename}: {error.strerror}")

    for root, dirs, files in os.walk(folder, topdown=True, followlinks=False, onerror=onerror):
        # Remove symlinked directories from traversal, then inspect normal dirs.
        safe_dirs: list[str] = []
        for name in dirs:
            item = Path(root) / name
            try:
                mode = item.lstat().st_mode
            except OSError as exc:
                errors.append(f"{item}: {exc}")
                continue
            if stat.S_ISLNK(mode):
                continue
            safe_dirs.append(name)
            result = classify_entry(item, mode, item.lstat().st_uid, item.lstat().st_gid)
            if result:
                findings.append(result)
        dirs[:] = safe_dirs

        for name in files:
            item = Path(root) / name
            try:
                st = item.lstat()
            except OSError as exc:
                errors.append(f"{item}: {exc}")
                continue
            if stat.S_ISLNK(st.st_mode):
                continue
            result = classify_entry(item, st.st_mode, st.st_uid, st.st_gid)
            if result:
                findings.append(result)

    findings.sort(key=lambda item: (item.severity, item.path))
    if errors:
        print(f"\nAudit note: {len(errors)} path(s) could not be inspected; the report may be incomplete.")
        for error in errors[:5]:
            print(f"  - {error}")
    return findings


def print_audit(findings: list[AuditFinding], folder: Path) -> None:
    print("\n=== DIRECTORY PERMISSION AUDIT ===")
    print(f"Scanned folder : {folder}")
    if not findings:
        print("No configured risk patterns were found in the accessible entries.")
        return
    for item in findings:
        print(f"[{item.severity}] {','.join(item.findings)} | {item.permissions} {item.path}")
    print("\nSummary:")
    print(f"  Findings : {len(findings)}")
    print(f"  High     : {sum(x.severity == 'HIGH' for x in findings)}")
    print(f"  Medium   : {sum(x.severity == 'MEDIUM' for x in findings)}")
    print(f"  Info     : {sum(x.severity == 'INFO' for x in findings)}")
    print("Note: SUID/SGID can be legitimate; findings require administrator review, not automatic deletion.")


def export_audit_json(findings: list[AuditFinding], output: Path, scanned: Path) -> None:
    payload = {
        "schema_version": 1,
        "scanned_directory": str(scanned.resolve()),
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "finding_count": len(findings),
        "findings": [item.__dict__ for item in findings],
    }
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def sha256_file(path: Path) -> str:
    """Hash a file in chunks so large files are not read into memory at once."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def create_baseline(target: Path, baseline_path: Path) -> dict[str, Any]:
    """Create a JSON SHA-256 baseline. Protect this baseline separately."""
    target = target.resolve(strict=True)
    if not target.is_file():
        raise ValueError("Integrity baseline currently supports regular files only")
    if baseline_path.resolve() == target:
        raise ValueError("Baseline JSON must not overwrite the monitored file")
    st = target.stat()
    record = {
        "schema_version": 1,
        "target_path": str(target),
        "filename": target.name,
        "size_bytes": st.st_size,
        "sha256": sha256_file(target),
        "created_utc": datetime.now(timezone.utc).isoformat(),
    }
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


def verify_baseline(target: Path, baseline_path: Path) -> tuple[bool, str, str]:
    """Compare a file's current SHA-256 digest with a saved JSON baseline."""
    target = target.resolve(strict=True)
    if not target.is_file():
        raise ValueError("Integrity verification currently supports regular files only")
    payload = json.loads(baseline_path.read_text(encoding="utf-8"))
    expected = payload.get("sha256")
    if not isinstance(expected, str) or len(expected) != 64:
        raise ValueError("Invalid baseline: expected a 64-character SHA-256 digest")
    current = sha256_file(target)
    return current == expected, expected, current


def show_acl(path: Path) -> int:
    output, error = getfacl_output(path)
    print("\n=== POSIX ACL INSPECTION ===")
    print(f"Path: {path}")
    if output is None:
        print(f"Unavailable: {error}")
        print("On Debian/Ubuntu: sudo apt install acl")
        return 1
    print(output)
    print("\nInterpretation: the ACL mask limits named-user and group-class entries; it does not limit the owner:: or other:: entries.")
    return 0


def run_acl_demo() -> None:
    """Run a deterministic named-user/group ACL example without changing files."""
    acl = PosixACL(
        owner_uid=1000, owning_group_gid=2000,
        owner_permissions=READ | WRITE,
        owning_group_permissions=READ, other_permissions=0,
        named_users={1002: READ}, named_groups={3000: WRITE}, mask=READ | WRITE,
    )
    cases = [
        ("owner", 1000, {2000}, "write"),
        ("named auditor", 1002, {4500}, "read"),
        ("named auditor", 1002, {4500}, "write"),
        ("faculty + IT group member", 1003, {2000, 3000}, "write"),
        ("unmatched student", 1004, {4000}, "read"),
    ]
    print("\n=== POSIX ACL POLICY SIMULATION ===")
    print("Sample ACL: owner=rw-, owning-group=r--, named-user UID 1002=r--,")
    print("            named-group GID 3000=-w-, mask=rw-, other=---")
    for label, uid, gids, operation in cases:
        decision = acl_access_decision(acl, uid, gids, operation)
        print(f"\nPrincipal       : {label} (UID {uid}, GIDs {sorted(gids)})")
        print(f"Requested right : {operation.upper()}")
        print(f"Effective rights: {permission_text(decision.effective_permissions)}")
        print(f"Reason          : {decision.reason}")
        print(f"Decision        : {'ACCESS GRANTED' if decision.allowed else 'ACCESS DENIED'}")
    print("\nNote: this is a policy simulation; it does not install ACL entries on the filesystem.")


def self_test() -> int:
    """Run a small deterministic demonstration and report pass/fail totals."""
    import unittest
    from test_unix_security_auditor import SecurityModelTests
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SecurityModelTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print("\n=== SELF-TEST SUMMARY ===")
    print(f"Passed: {result.testsRun - len(result.failures) - len(result.errors)}/{result.testsRun}")
    print(f"Failed: {len(result.failures) + len(result.errors)}")
    return 0 if result.wasSuccessful() else 1


def prompt_int(label: str) -> int:
    while True:
        value = input(label).strip()
        try:
            parsed = int(value, 10)
            if parsed < 0:
                raise ValueError
            return parsed
        except ValueError:
            print("Enter a non-negative integer.")


def menu() -> int:
    """Interactive menu for live classroom demonstration."""
    while True:
        print("\n" + "=" * 62)
        print(" UNIX / LINUX SECURITY MODELS - INTERACTIVE AUDITOR")
        print("=" * 62)
        print("1. Inspect a real file and check current-process access")
        print("2. Simulate owner/group/other access for a UID and GID set")
        print("3. Audit a directory for risky permission bits")
        print("4. Display a real file's POSIX ACL (getfacl)")
        print("5. Run a POSIX ACL policy simulation")
        print("6. Create a SHA-256 integrity baseline")
        print("7. Verify a file against a SHA-256 baseline")
        print("8. Run automated self-tests")
        print("0. Exit")
        choice = input("Select an option: ").strip()
        if choice == "1":
            inspect_file(Path(input("File path: ").strip()))
        elif choice == "2":
            path = Path(input("File path: ").strip())
            uid = prompt_int("User ID (UID): ")
            gids_text = input("Group IDs, comma-separated (GIDs): ").strip()
            try:
                gids = {int(item.strip()) for item in gids_text.split(",") if item.strip()}
                operation = input("Requested right (r/w/x): ").strip()
                simulate_file_access(path, uid, gids, operation)
            except ValueError as exc:
                print(f"Invalid input: {exc}")
        elif choice == "3":
            folder = Path(input("Directory to scan: ").strip())
            if not folder.is_dir():
                print("ERROR: choose an existing directory")
            else:
                findings = audit_directory(folder)
                print_audit(findings, folder)
                out = input("Export JSON report? (y/N): ").strip().lower()
                if out == "y":
                    destination = Path(input("Output JSON path: ").strip())
                    export_audit_json(findings, destination, folder)
                    print(f"Saved: {destination}")
        elif choice == "4":
            show_acl(Path(input("File path: ").strip()))
        elif choice == "5":
            run_acl_demo()
        elif choice == "6":
            target = Path(input("File to monitor: ").strip())
            baseline = Path(input("Where to save baseline JSON: ").strip())
            try:
                record = create_baseline(target, baseline)
                print(f"Baseline created: {baseline}")
                print(f"SHA-256: {record['sha256']}")
            except (OSError, ValueError) as exc:
                print(f"ERROR: {exc}")
        elif choice == "7":
            target = Path(input("File to verify: ").strip())
            baseline = Path(input("Baseline JSON path: ").strip())
            try:
                same, expected, current = verify_baseline(target, baseline)
                print(f"Expected SHA-256: {expected}")
                print(f"Current  SHA-256: {current}")
                print("INTEGRITY: " + ("UNCHANGED" if same else "CHANGE DETECTED"))
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                print(f"ERROR: {exc}")
        elif choice == "8":
            self_test()
        elif choice == "0":
            print("Exiting. No file permissions were changed by the program.")
            return 0
        else:
            print("Invalid menu option. Choose 0-8.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Unix/Linux file-permission auditor and ACL/integrity teaching simulator")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("menu", help="open the interactive menu")
    sub.add_parser("self-test", help="run automated tests")
    sub.add_parser("acl-demo", help="run a deterministic POSIX ACL policy simulation")
    p = sub.add_parser("inspect", help="inspect metadata and current-process access for a path")
    p.add_argument("path", type=Path)
    p = sub.add_parser("simulate", help="simulate classic mode-bit access for a supplied UID/GID set")
    p.add_argument("path", type=Path)
    p.add_argument("--uid", type=int, required=True)
    p.add_argument("--gids", required=True, help="comma-separated primary and supplementary GIDs")
    p.add_argument("--operation", choices=("r", "w", "x", "read", "write", "execute"), required=True)
    p = sub.add_parser("audit", help="recursively audit a directory for risky permission settings")
    p.add_argument("directory", type=Path)
    p.add_argument("--json-out", type=Path, help="optional path to save findings as JSON")
    p = sub.add_parser("acl", help="show POSIX ACL entries using getfacl, if installed")
    p.add_argument("path", type=Path)
    p = sub.add_parser("baseline", help="create a SHA-256 baseline JSON for a regular file")
    p.add_argument("path", type=Path)
    p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("verify", help="verify a regular file against a saved SHA-256 baseline")
    p.add_argument("path", type=Path)
    p.add_argument("--baseline", type=Path, required=True)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    if os.name != "posix":
        print("This educational implementation requires a POSIX system (Linux/macOS).", file=sys.stderr)
        return 2
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command in (None, "menu"):
        return menu()
    if args.command == "self-test":
        return self_test()
    if args.command == "acl-demo":
        run_acl_demo()
        return 0
    if args.command == "inspect":
        return inspect_file(args.path)
    if args.command == "simulate":
        try:
            gids = {int(part.strip()) for part in args.gids.split(",") if part.strip()}
            return simulate_file_access(args.path, args.uid, gids, args.operation)
        except ValueError as exc:
            parser.error(str(exc))
    if args.command == "audit":
        if not args.directory.is_dir():
            parser.error(f"not a directory: {args.directory}")
        findings = audit_directory(args.directory)
        print_audit(findings, args.directory)
        if args.json_out:
            export_audit_json(findings, args.json_out, args.directory)
            print(f"JSON report saved: {args.json_out}")
        return 0
    if args.command == "acl":
        return show_acl(args.path)
    if args.command == "baseline":
        try:
            record = create_baseline(args.path, args.output)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        print(f"Baseline saved: {args.output}\nSHA-256: {record['sha256']}")
        return 0
    if args.command == "verify":
        try:
            same, expected, current = verify_baseline(args.path, args.baseline)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            parser.error(str(exc))
        print(f"Expected: {expected}\nCurrent : {current}")
        print("INTEGRITY: " + ("UNCHANGED" if same else "CHANGE DETECTED"))
        return 0 if same else 1
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
