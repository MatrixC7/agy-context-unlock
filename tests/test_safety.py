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

BIN = Path("/usr/bin/agy")
HAS_TARGET = BIN.exists() and hashlib.sha256(BIN.read_bytes()).hexdigest().startswith("72738cf044591848")


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

    def test_install_window_validation(self):
        with tempfile.TemporaryDirectory() as td:
            r = subprocess.run(
                [sys.executable, str(ROOT / "agy_context_unlock.py"), "install",
                 "--prefix", td, "--window", "0"],
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(r.returncode, 2)
            self.assertIn("--window", r.stderr)


if __name__ == "__main__":
    unittest.main()
