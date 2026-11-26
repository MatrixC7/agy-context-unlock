#!/usr/bin/env python3
"""Offline tests for the ELF/pclntab parser and the five core patch sites.

Run:  python3 -m unittest discover -s tests -v
They are skipped automatically when /usr/bin/agy is absent or is not one of the
locally verified x86-64 builds (see ``unlock.KNOWN_BUILDS``).
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import agy_context_unlock as unlock  # noqa: E402

BIN = Path("/usr/bin/agy")
HAS_BIN = BIN.exists()
SHA256 = hashlib.sha256(BIN.read_bytes()).hexdigest() if HAS_BIN else ""
BUILD = unlock.identify_build(SHA256) if HAS_BIN else None
IS_TARGET = BUILD is not None


@unittest.skipUnless(IS_TARGET, "no locally verified agy build present")
class TestTargetBinary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = unlock.ELFFile(BIN.read_bytes())
        cls.syms = unlock.GoSymbols(cls.elf)

    def test_elf_shape(self):
        self.assertEqual(self.elf.e_type, 3)  # ET_DYN
        self.assertEqual(self.elf.machine, 0x3E)  # x86-64
        text = self.elf.section(".text")
        self.assertIsNotNone(text)
        self.assertEqual(text.addr, text.offset)
        # Go entry stubs sit 0x80 bytes into .text.
        self.assertEqual(self.syms.text_base, text.addr + 0x80)

    def test_pclntab(self):
        self.assertEqual(self.syms.min_lc, 1)
        self.assertGreater(self.syms.nfunc, 100_000)
        self.assertEqual(len({f.va for f in self.syms.funcs.values()}), len(self.syms.funcs))

    def test_anchor_symbols(self):
        anchors = unlock.ANCHORS_BY_BUILD[SHA256[:16]]
        self.assertTrue(anchors, "anchor table must not be empty")
        for name, va in anchors.items():
            with self.subTest(name=name):
                self.assertEqual(self.syms.find(name).va, va)

    def test_patch_bytes_are_exact_and_unique(self):
        u = unlock.Unlocker(BIN)
        before = bytes(u.data)
        required = [x for x in unlock.PATCHES if not x.optional]
        for p in required:
            state, off, va, new = u.inspect_patch(p)
            self.assertEqual(state, "clean", p.key)
            fn = u._patch_fn(p)
            self.assertTrue(fn.va <= va < fn.end, p.key)
            self.assertNotEqual(before[off:off + len(new)], new, p.key)
        for p in required:
            self.assertEqual(u.apply(p).status, "applied", p.key)
        self.assertTrue(u.is_patched())

    def test_patch_changes_only_expected_bytes(self):
        u = unlock.Unlocker(BIN)
        before = bytes(u.data)
        required = [x for x in unlock.PATCHES if not x.optional]
        expected = set()
        for p in required:
            _state, off, _va, new = u.inspect_patch(p)
            for i, byte in enumerate(new):
                if before[off + i] != byte:
                    expected.add(off + i)
        for p in required:
            u.apply(p)
        after = bytes(u.data)
        diff = {i for i in range(len(before)) if before[i] != after[i]}
        self.assertEqual(diff, expected)
        # 42 bytes total on every 1.5.x layout verified so far.
        self.assertEqual(len(diff), 42)

    def test_cli_locate_json(self):
        r = subprocess.run(
            [sys.executable, str(ROOT / "agy_context_unlock.py"), "locate", "--binary", str(BIN), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f"{self.syms.text_base:#x}", r.stdout)
        self.assertIn("pclntab", r.stdout)

    def test_verify_clean_binary_fails(self):
        r = subprocess.run(
            [sys.executable, str(ROOT / "agy_context_unlock.py"), "verify", "--binary", str(BIN)],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 1)
        self.assertIn("clean", r.stdout)


class TestParserUnits(unittest.TestCase):
    def test_varint_rejects_truncated(self):
        with self.assertRaises(Exception):
            unlock.ELFFile(b"not an elf")

    def test_go_magic_constants(self):
        self.assertIn(0xFFFFFFF1, unlock.GO_MAGICS)


if __name__ == "__main__":
    unittest.main()
