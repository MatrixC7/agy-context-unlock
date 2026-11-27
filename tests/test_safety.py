#!/usr/bin/env python3
"""Regression tests for the round-2 safety fixes (no network)."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import agy_context_unlock as unlock  # noqa: E402
import verify_live as verify  # noqa: E402

def _pick_clean_target():
    """First unpatched binary that matches a known build (prefers /usr/bin/agy)."""
    candidates = [Path("/usr/bin/agy")]
    candidates += sorted(Path("/usr/bin").glob("agy.agy-unlock-backup*"))
    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            sha = hashlib.sha256(candidate.read_bytes()).hexdigest()
        except OSError:
            continue
        if unlock.identify_build(sha):
            return candidate
    return None


CLEAN_ANY_BIN = _pick_clean_target()
BIN = CLEAN_ANY_BIN or Path("/usr/bin/agy")
HAS_TARGET = CLEAN_ANY_BIN is not None


class TestCompactionSummary(unittest.TestCase):
    def test_late_compaction_is_not_early(self):
        rows = [
            {"model": "m", "entries": [{"tokens": 300_000, "reason": 0, "max_context": 900_000}]},
            {"model": "m", "entries": [{"tokens": 10_000, "reason": 2, "max_context": 900_000}]},
        ]
        s = verify.summarize(rows)
        self.assertEqual(s["max_tokens"], 300_000)
        self.assertEqual(s["compactions"], [(1, 300_000)])
        self.assertFalse(any(t <= 256_000 for _, t in s["compactions"]))

    def test_early_compaction_is_early(self):
        rows = [
            {"model": "m", "entries": [{"tokens": 200_000, "reason": 0, "max_context": 256_000}]},
            {"model": "m", "entries": [{"tokens": 10_000, "reason": 2, "max_context": 256_000}]},
        ]
        s = verify.summarize(rows)
        self.assertEqual(s["compactions"], [(1, 200_000)])
        self.assertTrue(any(t <= 256_000 for _, t in s["compactions"]))

    def test_multiple_compactions_use_immediately_preceding_row(self):
        rows = [
            {"model": "m", "entries": [{"tokens": 360_000, "reason": 0, "max_context": 256_000}]},
            {"model": "m", "entries": [{"tokens": 15_000, "reason": 2, "max_context": 256_000}]},
            {"model": "m", "entries": [{"tokens": 220_000, "reason": 0, "max_context": 256_000}]},
            {"model": "m", "entries": [{"tokens": 14_000, "reason": 2, "max_context": 256_000}]},
        ]
        s = verify.summarize(rows)
        self.assertEqual(s["compactions"], [(1, 360_000), (3, 220_000)])


class TestVerifierSafety(unittest.TestCase):
    def test_explicit_workdir_is_not_deleted(self):
        with tempfile.TemporaryDirectory() as td:
            marker = Path(td) / "keep.txt"
            marker.write_text("keep")
            r = subprocess.run(
                [sys.executable, str(ROOT / "verify_live.py"),
                 "--binary", "/bin/false", "--mode", "stream",
                 "--turns", "1", "--turn-bytes", "1000",
                 "--workdir", td, "--allow-failure"],
                capture_output=True, text=True, timeout=60,
            )
            self.assertTrue(marker.exists(), "explicit --workdir must not be deleted")
            self.assertTrue(any(Path(td).glob("run-*")))
            # /bin/false has no conversation, so the tool exits non-zero after inspecting.
            self.assertIn(r.returncode, (3, 4))

    def test_no_override_with_launcher_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fake = Path(td) / "agy-unlock"
            fake.write_text("#!/bin/sh\nexit 0\n")
            fake.chmod(0o755)
            r = subprocess.run(
                [sys.executable, str(ROOT / "verify_live.py"),
                 "--binary", str(fake), "--no-override", "--mode", "stream",
                 "--turns", "1", "--turn-bytes", "1000"],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(r.returncode, 2)
            self.assertIn("re-inject", r.stderr)

    def test_invalid_window_rejected(self):
        r = subprocess.run(
            [sys.executable, str(ROOT / "verify_live.py"),
             "--binary", "/bin/false", "--window", "0", "--mode", "stream"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(r.returncode, 2)


@unittest.skipUnless(HAS_TARGET, "target agy not present")
class TestPatcherSafety(unittest.TestCase):
    def test_out_equals_source_requires_yes(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "agy"
            shutil.copy2(BIN, src)
            before = hashlib.sha256(src.read_bytes()).hexdigest()
            r = subprocess.run(
                [sys.executable, str(ROOT / "agy_context_unlock.py"), "patch",
                 "--binary", str(src), "--out", str(src)],
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(r.returncode, 2)
            self.assertIn("resolves to the source", r.stderr)
            self.assertEqual(hashlib.sha256(src.read_bytes()).hexdigest(), before)

    def test_atomic_write_preserves_mode(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "f"
            p.write_text("old")
            os.chmod(p, 0o600)
            unlock._atomic_write(p, b"new", 0o600)
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
            self.assertEqual(p.read_bytes(), b"new")

    def test_stale_backup_is_rotated_before_copy(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "agy"
            src.write_bytes(b"new-binary")
            backup = Path(td) / "agy.agy-unlock-backup"
            backup.write_bytes(b"old-binary")
            old_sha = hashlib.sha256(b"old-binary").hexdigest()
            new_sha = hashlib.sha256(b"new-binary").hexdigest()

            out = unlock._ensure_backup(src, new_sha)

            self.assertEqual(out, backup)
            self.assertEqual(backup.read_bytes(), b"new-binary")
            rotated = Path(td) / f"agy.agy-unlock-backup.{old_sha[:8]}"
            self.assertEqual(rotated.read_bytes(), b"old-binary")

    def test_install_window_validation(self):
        with tempfile.TemporaryDirectory() as td:
            r = subprocess.run(
                [sys.executable, str(ROOT / "agy_context_unlock.py"), "install",
                 "--prefix", td, "--window", "0"],
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(r.returncode, 2)
            self.assertIn("--window", r.stderr)


@unittest.skipUnless(CLEAN_ANY_BIN is not None, "no clean agy build present")
class TestOutputVerdicts(unittest.TestCase):
    """Every command must end with a one-line verdict the user can act on."""

    def _run(self, *args):
        return subprocess.run(
            [sys.executable, str(ROOT / "agy_context_unlock.py"), *args],
            capture_output=True, text=True, timeout=180,
        )

    @staticmethod
    def _last(stream: str) -> str:
        return stream.strip().splitlines()[-1] if stream.strip() else ""

    def _copy(self, td: str) -> Path:
        dst = Path(td) / "agy"
        shutil.copy2(CLEAN_ANY_BIN, dst)
        return dst

    def test_verify_clean_ends_with_not_patched(self):
        r = self._run("verify", "--binary", str(CLEAN_ANY_BIN))
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self._last(r.stdout), "[=] not patched: 0/5 present (run patch)")

    def test_dry_run_ends_with_verdict(self):
        r = self._run("patch", "--binary", str(CLEAN_ANY_BIN), "--dry-run")
        self.assertEqual(r.returncode, 0)
        last = self._last(r.stdout)
        self.assertTrue(last.startswith("[+] dry run ok "), last)
        self.assertIn("no file written", last)

    def test_patch_noop_and_verify_verdicts(self):
        with tempfile.TemporaryDirectory() as td:
            target = self._copy(td)
            r1 = self._run("patch", "--binary", str(target), "--in-place", "--yes")
            self.assertEqual(r1.returncode, 0, r1.stderr)
            first = self._last(r1.stdout)
            self.assertTrue(first.startswith(f"[+] patched {target} "), first)
            self.assertIn("(5 applied, 42 bytes)", first)

            r2 = self._run("verify", "--binary", str(target))
            self.assertEqual(r2.returncode, 0)
            self.assertEqual(self._last(r2.stdout), "[+] verified: 5/5 patched")

            r3 = self._run("patch", "--binary", str(target), "--in-place", "--yes")
            self.assertEqual(r3.returncode, 0)
            self.assertEqual(self._last(r3.stdout), f"[=] unchanged {target} (5 already present, nothing written)")

    def test_partial_state_reports_partial(self):
        with tempfile.TemporaryDirectory() as td:
            target = self._copy(td)
            r1 = self._run("patch", "--binary", str(target), "--in-place", "--yes", "--patches", "ui-selector")
            self.assertEqual(r1.returncode, 0, r1.stderr)
            r2 = self._run("verify", "--binary", str(target))
            self.assertEqual(r2.returncode, 1)
            self.assertEqual(self._last(r2.stdout), "[!] partial: 1/5 patched (restore, then re-patch)")

    def test_failure_ends_with_zero_write_guarantee(self):
        with tempfile.TemporaryDirectory() as td:
            target = self._copy(td)
            before = hashlib.sha256(target.read_bytes()).hexdigest()
            # Corrupt the settings-window signature so the patch aborts in memory.
            u = unlock.Unlocker(target)
            patch = next(p for p in unlock.PATCHES if p.key == "settings-window")
            _state, off, _va, _new = u.inspect_patch(patch)
            raw = bytearray(target.read_bytes())
            raw[off] ^= 0xFF
            target.write_bytes(raw)

            r = self._run("patch", "--binary", str(target), "--in-place", "--yes", "--allow-unknown")
            self.assertEqual(r.returncode, 3)
            self.assertEqual(self._last(r.stderr), f"[-] patch failed {target}; binary not modified")
            self.assertIn("expected bytes not found", r.stderr)
            self.assertNotIn("settings-window: settings-window:", r.stderr)
            self.assertNotEqual(hashlib.sha256(target.read_bytes()).hexdigest(), before)


@unittest.skipUnless(CLEAN_ANY_BIN is not None, "no local agy binary present")
class TestAcpOverrideAndIncrementalBackup(unittest.TestCase):
    def test_acp_override_idempotent_and_order_independent(self):
        assert CLEAN_ANY_BIN is not None
        u1 = unlock.Unlocker(CLEAN_ANY_BIN)
        # Apply acp-override BEFORE model-gate
        by_key = {p.key: p for p in unlock.PATCHES}
        for key in ("acp-override", "model-gate", "ui-selector", "store-gate", "settings-window"):
            r = u1.apply(by_key[key])
            self.assertIn(r.status, ("applied", "already"))
        ok, problems = unlock._verify_patched(bytes(u1.data))
        self.assertTrue(ok, problems)

        # Apply in reverse order (model-gate BEFORE acp-override) -> exact same bytes
        u2 = unlock.Unlocker(CLEAN_ANY_BIN)
        for key in ("ui-selector", "store-gate", "settings-window", "model-gate", "acp-override"):
            u2.apply(by_key[key])
        self.assertEqual(bytes(u1.data), bytes(u2.data))

        # Re-applying all required patches must be a no-op
        for p in [x for x in unlock.PATCHES if not x.optional]:
            self.assertEqual(u2.apply(p).status, "already")

    def test_incremental_repatch_preserves_clean_backup(self):
        assert CLEAN_ANY_BIN is not None
        # Only run if CLEAN_ANY_BIN is genuinely unpatched at all core sites
        probe = unlock.Unlocker(CLEAN_ANY_BIN)
        if any(probe.inspect_patch(p)[0] == "patched" for p in unlock.PATCHES if not p.optional):
            self.skipTest("candidate binary is not clean")
        with tempfile.TemporaryDirectory() as td:
            work_bin = Path(td) / "agy"
            shutil.copy2(CLEAN_ANY_BIN, work_bin)
            clean_sha = hashlib.sha256(work_bin.read_bytes()).hexdigest()

            # Step 1: simulate an older 4-patch in-place install (without acp-override)
            r1 = subprocess.run(
                [sys.executable, str(ROOT / "agy_context_unlock.py"), "patch",
                 "--binary", str(work_bin), "--in-place", "--yes", "--allow-unknown",
                 "--patches", "ui-selector,store-gate,settings-window,model-gate"],
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(r1.returncode, 0, r1.stderr)
            backup = Path(td) / "agy.agy-unlock-backup"
            self.assertEqual(hashlib.sha256(backup.read_bytes()).hexdigest(), clean_sha)

            # Step 2: upgrade in-place to all 5 core patches (adding acp-override)
            r2 = subprocess.run(
                [sys.executable, str(ROOT / "agy_context_unlock.py"), "patch",
                 "--binary", str(work_bin), "--in-place", "--yes", "--allow-unknown"],
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(r2.returncode, 0, r2.stderr)
            self.assertIn("keeping existing clean backup", r2.stdout)
            # Clean backup must NOT have been rotated or overwritten by the 4-patch binary
            self.assertEqual(hashlib.sha256(backup.read_bytes()).hexdigest(), clean_sha)
            self.assertEqual(list(Path(td).glob("agy.agy-unlock-backup.*")), [])

            # Step 3: verify passes
            r3 = subprocess.run(
                [sys.executable, str(ROOT / "agy_context_unlock.py"), "verify",
                 "--binary", str(work_bin)],
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(r3.returncode, 0, r3.stdout + r3.stderr)


if __name__ == "__main__":
    unittest.main()
