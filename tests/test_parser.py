#!/usr/bin/env python3
"""Offline tests for the ELF/pclntab parser and the three patch sites.

Run:  python3 -m unittest discover -s tests -v
They are skipped automatically when /usr/bin/agy is absent or is not the
verified 1.5.7 x86-64 build.
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
SHA_PREFIX = "5df525a2d6908989"
IS_TARGET = HAS_BIN and hashlib.sha256(BIN.read_bytes()).hexdigest().startswith(SHA_PREFIX)


@unittest.skipUnless(IS_TARGET, "target agy 1.5.7 x86-64 not present")
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
        self.assertEqual(text.addr, 0x6EEF000)
        self.assertEqual(text.offset, 0x6EEF000)

    def test_pclntab_and_text_base(self):
        self.assertEqual(self.syms.pclntab_off, 0x17652A0)
        self.assertEqual(self.syms.min_lc, 1)
        self.assertEqual(self.syms.nfunc, 187711)
        self.assertEqual(self.syms.text_base, 0x6EEF080)

    def test_anchor_symbols(self):
        anchors = {
            "model.SelectorModel.offersContextWindow": 0xA6A03C0,
            "store.(*Store).ContextWindowChoice": 0xA3FDEA0,
            "store.(*Store).ContextWindow": 0xA3FDEE0,
            "backend.(*ServerBackend).buildCascadeConfigInternal": 0xA08C3A0,
            "utils.GetCheckpointConfig": 0x84F5CE0,
        }
        for name, va in anchors.items():
            with self.subTest(name=name):
                self.assertEqual(self.syms.find(name).va, va)

    def test_patch_bytes_are_exact_and_unique(self):
        u = unlock.Unlocker(BIN)
        before = bytes(u.data)
        for p in [x for x in unlock.PATCHES if not x.optional]:
            off, _va = u.locate_patch(p)
            self.assertEqual(before[off:off + len(p.old)], p.old, p.key)

    def test_patch_changes_only_expected_bytes(self):
        u = unlock.Unlocker(BIN)
        before = bytes(u.data)
        for p in [x for x in unlock.PATCHES if not x.optional]:
            u.apply(p)
        after = bytes(u.data)
        diff = {i for i in range(len(before)) if before[i] != after[i]}
        expected = set()
        # exact expected diff: derive from the four known core patch sites (20 bytes total)
        sites = {
            "ui-selector": (0xA6A03C0, range(0, 6)),
            "store-gate": (0xA3FDFA9, (1, 3, 4, 5, 6)),
            "settings-window": (0xA3FE005, (2, 8, 9, 10, 11, 12, 13, 14)),
            "model-gate": (0xA08D0CB, (0,)),
        }
        for name, (base, rels) in sites.items():
            for r in rels:
                expected.add(base + r)
        self.assertEqual(diff, expected)
        self.assertEqual(len(diff), 20)

    def test_cli_locate_json(self):
        r = subprocess.run(
            [sys.executable, str(ROOT / "agy_context_unlock.py"), "locate", "--binary", str(BIN), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("0x6eef080", r.stdout)
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
