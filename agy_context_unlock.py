#!/usr/bin/env python3
"""agy-context-unlock: unlock >256K context window in antigravity-cli (agy).

Verified mechanism (antigravity-cli 1.5.7, Linux x86-64)
--------------------------------------------------------
1. Context auto-compaction (checkpointing) in ``agy`` is triggered **locally by
   the CLI client** (``checkpoint.shouldCheckpoint`` /
   ``checkpoint.MaybeCreateCheckpoint``), not enforced as a 256K hard cap by the
   upstream model API on main generation requests.  When the local token budget
   is reached, ``agy`` sends a separate continuation-summary request, records a
   local ``type=23`` checkpoint step in SQLite, and replaces older history.
2. In unpatched ``agy`` 1.5.7, ``~/.gemini/antigravity-cli/settings.json``'s
   ``"contextWindow": "900K"`` does not take effect on the default path, and
   ``AGY_CLI_AUTO_COMPACT_OVERRIDE`` only works for ``"Gemini 4 Argon"`` due to
   a hardcoded one-model whitelist in ``store.(*Store).ContextWindow``.

What the five core binary patches do (39-42 bytes total; 42 on 1.5.7)
---------------------------------------------------------------------
1. ``ui-selector`` (``model.SelectorModel.offersContextWindow``, 6 bytes):
   Forces ``offersContextWindow()`` to return ``true`` so the Context selector
   (256K / 512K / 900K) is visible in ``/model`` for every model.
2. ``store.(*Store).ContextWindow`` (``store-gate``, 5 bytes):
   Replaces the whitelist-miss ``mov $-1, %rax`` with ``xor %rax, %rax`` + NOPs
   so every native Gemini and enterprise-gateway (``<gateway>/<model>``) custom
   model passes the gate.
3. ``settings-window`` (``store.(*Store).ContextWindow``, 8 bytes):
   Wires the post-env fallback branch to call
   ``store.(*Store).ContextWindowChoice``, which reads and validates
   ``settings.json``'s ``"contextWindow"`` (``"256K"`` / ``"512K"`` /
   ``"900K"``).  With this patch, ``settings.json`` and interactive ``/model``
   selections work directly without requiring environment variables, while
   ``AGY_CLI_AUTO_COMPACT_OVERRIDE`` retains highest priority when set.
   In 1.5.7 the ``featureProvider`` field moved from ``+0xb8`` to ``+0x58``,
   so the 14-byte instruction signature is version-specific (see ``PATCHES``).
4. ``model-gate`` (``backend.(*ServerBackend).buildCascadeConfigInternal``, 1 byte):
   Changes the ``proto.Equal`` conditional jump (``jne`` -> ``jmp``) so any
   non-zero resolved context window is unconditionally written into
   ``CheckpointConfig.MaxTokenLimit`` (offset ``+0xc``, protobuf field 5).
5. ``acp-override`` (``backend.(*ServerBackend).buildCascadeConfigInternal``, 19-22 bytes):
   In headless ACP mode (``agy acp``, e.g. T3 Code), ``store.Manager`` is never
   created and ``ServerBackend.SetContextWindow`` is never called, so
   ``ServerBackend.ContextWindow()`` always returns ``""``.  When that return
   value is empty, this patch falls back to ``store.AutoCompactOverrideSpec()``
   (``strings.TrimSpace(os.Getenv("AGY_CLI_AUTO_COMPACT_OVERRIDE"))``) before
   calling ``backend.ContextWindow.MaxTokenLimit()`` (accepting both ``"900K"``
   and ``"900000"``).  Interactive TUI behavior is unchanged whenever
   ``ServerBackend.ContextWindow()`` is non-empty, and when the env var is unset
   it falls back cleanly to the original empty/default path.

An optional 6th patch (``default-clamp``, enabled via ``--with-default-clamp``)
raises the fallback ``min(x, 256000)`` cap in ``utils.GetCheckpointConfig`` to
``1048576``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import struct
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

PROJECT_VERSION = "2.2.0"
TARGET_VERSION = "1.5.7"
TARGET_SHA256_PREFIX = "5df525a2d6908989"
GO_MAGICS = (0xFFFFFFF1, 0xFFFFFFF0)  # Go 1.18+ primary layout; 0xFFFFFFF0 kept as constant
DEFAULT_WINDOW = 900_000
MAX_WINDOW = 1_000_000

SHF_EXECINSTR = 0x4
PF_X = 0x1


class BinaryError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# ELF
# ---------------------------------------------------------------------------


@dataclass
class Section:
    name: str
    sh_type: int
    flags: int
    addr: int
    offset: int
    size: int


@dataclass
class Segment:
    p_type: int
    flags: int
    offset: int
    vaddr: int
    filesz: int
    memsz: int


class ELFFile:
    """Minimal little-endian ELF64 reader (enough for Go binaries)."""

    def __init__(self, data: bytes):
        if data[:4] != b"\x7fELF":
            raise BinaryError("not an ELF file")
        self.data = data
        self.is64 = data[4] == 2
        self.little = data[5] == 1
        if not (self.is64 and self.little):
            raise BinaryError("only ELF64 little-endian is supported")
        self.e_type = struct.unpack_from("<H", data, 16)[0]
        self.machine = struct.unpack_from("<H", data, 18)[0]
        if self.machine != 0x3E:
            raise BinaryError(f"unsupported ELF machine {self.machine:#x} (want x86-64)")
        self.entry = struct.unpack_from("<Q", data, 24)[0]
        self.phoff = struct.unpack_from("<Q", data, 32)[0]
        self.shoff = struct.unpack_from("<Q", data, 40)[0]
        self.phentsize, self.phnum = struct.unpack_from("<HH", data, 54)
        self.shentsize, self.shnum, self.shstrndx = struct.unpack_from("<HHH", data, 58)
        self.sections: List[Section] = []
        self.segments: List[Segment] = []
        self._read_sections()
        self._read_segments()

    def _read_sections(self) -> None:
        if not self.shoff:
            return
        raw = []
        for i in range(self.shnum):
            base = self.shoff + i * self.shentsize
            nameoff, sh_type = struct.unpack_from("<II", self.data, base)
            flags, addr, offset, size = struct.unpack_from("<QQQQ", self.data, base + 8)
            raw.append((nameoff, sh_type, flags, addr, offset, size))
        strtab_off = raw[self.shstrndx][4] if self.shstrndx < len(raw) else 0
        for nameoff, sh_type, flags, addr, offset, size in raw:
            end = self.data.find(b"\0", strtab_off + nameoff) if strtab_off else -1
            name = self.data[strtab_off + nameoff:end].decode("utf-8", "replace") if end > 0 else ""
            self.sections.append(Section(name, sh_type, flags, addr, offset, size))

    def _read_segments(self) -> None:
        for i in range(self.phnum):
            base = self.phoff + i * self.phentsize
            p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, _align = struct.unpack_from(
                "<IIQQQQQQ", self.data, base
            )
            self.segments.append(Segment(p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz))

    def section(self, name: str) -> Optional[Section]:
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def va_to_off(self, va: int) -> Optional[int]:
        for s in self.sections:
            if s.sh_type != 8 and s.addr and s.addr <= va < s.addr + s.size:
                return s.offset + (va - s.addr)
        for seg in self.segments:
            if seg.p_type == 1 and seg.vaddr <= va < seg.vaddr + seg.filesz:
                return seg.offset + (va - seg.vaddr)
        return None

    def va_to_off_exec(self, va: int) -> Optional[int]:
        """Map VA to file offset only if it lands inside an executable section or segment."""
        for s in self.sections:
            if s.sh_type != 8 and (s.flags & SHF_EXECINSTR) and s.addr and s.addr <= va < s.addr + s.size:
                return s.offset + (va - s.addr)
        for seg in self.segments:
            if seg.p_type == 1 and (seg.flags & PF_X) and seg.vaddr <= va < seg.vaddr + seg.filesz:
                return seg.offset + (va - seg.vaddr)
        return None

    def off_to_va(self, off: int) -> Optional[int]:
        for s in self.sections:
            if s.sh_type != 8 and s.offset <= off < s.offset + s.size:
                return s.addr + (off - s.offset)
        for seg in self.segments:
            if seg.p_type == 1 and seg.offset <= off < seg.offset + seg.filesz:
                return seg.vaddr + (off - seg.offset)
        return None

    def relocations(self) -> Dict[int, int]:
        """Map r_offset -> addend for R_X86_64_RELATIVE entries."""
        out: Dict[int, int] = {}
        for s in self.sections:
            if s.sh_type != 4 or s.size < 24:  # SHT_RELA
                continue
            for i in range(0, s.size - 23, 24):
                r_offset, r_info, r_addend = struct.unpack_from("<QQq", self.data, s.offset + i)
                if (r_info & 0xFFFFFFFF) == 8:  # R_X86_64_RELATIVE
                    out[r_offset] = r_addend
        return out


# ---------------------------------------------------------------------------
# Go pclntab (Go 1.18+ 0xFFFFFFF1 header layout)
# ---------------------------------------------------------------------------


@dataclass
class GoFunc:
    name: str
    entryoff: int
    funcoff: int
    va: int
    end: int


class GoSymbols:
    def __init__(self, elf: ELFFile):
        self.elf = elf
        self.data = elf.data
        self.relocs = elf.relocations()
        self.pclntab_off, self.min_lc, self.nfunc = self._find_pclntab()
        base = self.pclntab_off
        self.funcname_off = base + struct.unpack_from("<Q", self.data, base + 32)[0]
        self.pcln_off = base + struct.unpack_from("<Q", self.data, base + 64)[0]
        self.pclntab_va = elf.off_to_va(self.pclntab_off)
        if self.pclntab_va is None:
            raise BinaryError("cannot map pclntab file offset to a VA")
        self.text_base = self._find_text_base()
        self.funcs = self._build()

    # -- discovery ---------------------------------------------------------
    def _find_pclntab(self) -> Tuple[int, int, int]:
        data = self.data
        candidates = []
        # Header offsets (+8 nfunc, +32 funcnameOffset, +64 pclnOffset) follow Go 1.18+ (0xFFFFFFF1).
        needle = struct.pack("<I", 0xFFFFFFF1) + b"\x00\x00"
        pos = 0
        while True:
            i = data.find(needle, pos)
            if i < 0:
                break
            pos = i + 1
            if i + 72 > len(data):
                continue
            min_lc, ptr_size = data[i + 6], data[i + 7]
            if min_lc not in (1, 2, 4) or ptr_size != 8:
                continue
            nfunc = struct.unpack_from("<Q", data, i + 8)[0]
            if not (1000 < nfunc < 5_000_000):
                continue
            fn_off = struct.unpack_from("<Q", data, i + 32)[0]
            pcln_off = struct.unpack_from("<Q", data, i + 64)[0]
            if not (72 <= fn_off < 1 << 40 and 72 <= pcln_off < 1 << 40):
                continue
            fn = i + fn_off
            head = data[fn:fn + 128].split(b"\0", 1)[0]
            if len(head) < 4 or not all(0x20 <= c < 0x7F for c in head):
                continue
            if i + pcln_off + (nfunc + 1) * 8 > len(data):
                continue
            va = self.elf.off_to_va(i)
            has_moduledata = False
            if va is not None:
                for slot, addend in self.relocs.items():
                    if addend == va:
                        minpc = self.relocs.get(slot + 0xA0)
                        text = self.relocs.get(slot + 0xB0)
                        if minpc and text and minpc == text:
                            has_moduledata = True
                            break
            candidates.append((has_moduledata, nfunc, i, min_lc))
        if not candidates:
            raise BinaryError("Go pclntab not found")
        # Prefer the candidate referenced by a valid moduledata structure, then largest nfunc.
        candidates.sort(key=lambda x: (x[0], x[1]), reverse=True)
        _, nfunc, off, min_lc = candidates[0]
        return off, min_lc, nfunc

    def _find_text_base(self) -> int:
        # 1) preferred: moduledata found through the RELATIVE relocation that
        #    points at pclntab.  moduledata layout: +0 pclntab, +0xa0 minpc, +0xb0 text.
        for slot, addend in self.relocs.items():
            if addend != self.pclntab_va:
                continue
            minpc = self.relocs.get(slot + 0xA0)
            text = self.relocs.get(slot + 0xB0)
            if minpc and text and minpc == text and self._plausible_base(text):
                return text
        # 2) header textStart (non-PIE builds)
        header_text = struct.unpack_from("<Q", self.data, self.pclntab_off + 24)[0]
        if header_text and self._plausible_base(header_text):
            return header_text
        # 3) .text start and .text+0x80
        text_sec = self.elf.section(".text")
        if text_sec:
            for delta in (0x80, 0x0):
                cand = text_sec.addr + delta
                if self._plausible_base(cand):
                    return cand
        raise BinaryError("cannot determine Go text base")

    def _plausible_base(self, base: int) -> bool:
        if self.elf.va_to_off_exec(base) is None:
            return False
        ok = 0
        total = 0
        for i in (1, 2, 10, 100, 1000):
            if i + 1 > self.nfunc:
                continue
            eo, _ = struct.unpack_from("<II", self.data, self.pcln_off + i * 8)
            off = self.elf.va_to_off_exec(base + eo)
            if off is None or off >= len(self.data):
                continue
            total += 1
            if self.data[off] not in (0x00, 0xCC):
                ok += 1
        return total > 0 and ok >= max(1, total - 1)

    def _funcname(self, nameoff: int) -> str:
        start = self.funcname_off + nameoff
        end = self.data.find(b"\0", start, start + 512)
        if end < 0:
            return ""
        return self.data[start:end].decode("utf-8", "replace")

    def _build(self) -> Dict[str, GoFunc]:
        funcs: Dict[str, GoFunc] = {}
        entries: List[Tuple[int, int, str]] = []
        for i in range(self.nfunc):
            eo, fo = struct.unpack_from("<II", self.data, self.pcln_off + i * 8)
            rec = self.pcln_off + fo
            if rec + 8 > len(self.data):
                continue
            nameoff = struct.unpack_from("<i", self.data, rec + 4)[0]
            name = self._funcname(nameoff)
            if not name:
                continue
            entries.append((eo, fo, name))
        entries.sort()
        for idx, (eo, fo, name) in enumerate(entries):
            end = entries[idx + 1][0] if idx + 1 < len(entries) else eo + 0x1000
            va = self.text_base + eo
            prev = funcs.get(name)
            if prev is None or va < prev.va:
                funcs[name] = GoFunc(name, eo, fo, va, self.text_base + end)
        return funcs

    # -- lookup ------------------------------------------------------------
    def find(self, suffix: str) -> GoFunc:
        exact = self.funcs.get(suffix)
        if exact is not None:
            return exact
        matches = [f for n, f in self.funcs.items() if n.endswith("." + suffix) or n.endswith("/" + suffix)]
        if not matches:
            raise BinaryError(f"symbol not found: {suffix}")
        uniq = {(f.entryoff, f.va) for f in matches}
        if len(uniq) > 1:
            names = sorted({f.name for f in matches})[:5]
            raise BinaryError(f"ambiguous symbol {suffix}: {names}")
        return matches[0]


# ---------------------------------------------------------------------------
# Patch definitions
# ---------------------------------------------------------------------------


@dataclass
class Patch:
    key: str
    symbol: str
    old: bytes
    new: bytes
    description: str
    optional: bool = False
    occurrence: int = 0  # 0 = must be exactly one


PATCHES: List[Patch] = [
    Patch(
        key="ui-selector",
        symbol="model.SelectorModel.offersContextWindow",
        old=bytes.fromhex("49 89 e4 49 81 ec"),
        new=bytes.fromhex("b8 01 00 00 00 c3"),
        description="Context chip: offersContextWindow() -> true",
    ),
    Patch(
        key="store-gate",
        symbol="store.(*Store).ContextWindow",
        old=bytes.fromhex("48 c7 c0 ff ff ff ff 48 85 c0 7c"),
        new=bytes.fromhex("48 31 c0 90 90 90 90 48 85 c0 7c"),
        description="Context override: bypass the one-model whitelist gate",
    ),
    Patch(
        key="settings-window",
        symbol="store.(*Store).ContextWindow",
        old=bytes.fromhex("48 8b 8c 24 08 01 00 00 48 8b 49 58"),
        new=bytes.fromhex("48 8b 84 24 08 01 00 00 e8 8e fe ff ff c9 c3"),
        description="Context override: fall back to settings.json contextWindow (ContextWindowChoice)",
    ),
    Patch(
        key="model-gate",
        symbol="backend.(*ServerBackend).buildCascadeConfigInternal",
        # Symbolic anchor: `call proto.Equal` followed by `test %al,%al; jne <exit_stub>`.
        old=bytes.fromhex("84 c0 75 0a"),
        new=bytes.fromhex("84 c0 eb 0a"),
        description="Checkpoint override: drop the selected-model equality gate",
    ),
    Patch(
        key="acp-override",
        symbol="backend.(*ServerBackend).buildCascadeConfigInternal",
        # Symbolic anchor: `call ServerBackend.ContextWindow` followed by
        # `call MaxTokenLimit; test %eax,%eax; jne <exit_stub>; <exit_stub>` (19..22B).
        old=bytes.fromhex("85 c0 75"),
        # Prefix of the dynamically resolved 19..22-byte ACP env fallback sequence:
        #   test %rbx,%rbx; jne +5; call AutoCompactOverrideSpec; call MaxTokenLimit;
        #   test %eax,%eax; je <exit_stub>; [nop...]
        new=bytes.fromhex("48 85 db 75 05"),
        description="ACP fallback: read AGY_CLI_AUTO_COMPACT_OVERRIDE when ServerBackend.ContextWindow() is empty",
    ),
    Patch(
        key="default-clamp",
        symbol="utils.GetCheckpointConfig",
        old=bytes.fromhex("81 fa 00 e8 03 00 be 00 e8 03 00"),
        new=bytes.fromhex("81 fa 00 00 10 00 be 00 00 10 00"),
        description="Default checkpoint cap: 256000 -> 1048576 (opt-in)",
        optional=True,
    ),
]


@dataclass
class PatchResult:
    patch: Patch
    status: str  # applied | already | absent
    va: Optional[int] = None
    file_offset: Optional[int] = None
    detail: str = ""


class Unlocker:
    def __init__(self, path: Path):
        self.path = path
        self.data = bytearray(path.read_bytes())
        self.sha256 = hashlib.sha256(self.data).hexdigest()
        self.is_target = self.sha256.startswith(TARGET_SHA256_PREFIX)
        self.elf = ELFFile(bytes(self.data))
        self.symbols = GoSymbols(self.elf)
        self.text_sec = self.elf.section(".text")
        if self.text_sec is None:
            raise BinaryError(".text section not found")

    @staticmethod
    def _validate_exit_stub(blob: bytes, idx: int, label: str) -> int:
        """Validate `mov disp(%rsp), %rcx; jmp ret` at blob[idx:] and return its byte length."""
        if idx + 7 > len(blob):
            raise BinaryError(f"{label}: truncated exit stub")
        if blob[idx:idx + 4] == b"\x48\x8b\x8c\x24":  # mov disp32(%rsp), %rcx
            mov_len = 8
        elif blob[idx:idx + 4] == b"\x48\x8b\x4c\x24":  # mov disp8(%rsp), %rcx
            mov_len = 5
        else:
            raise BinaryError(f"{label}: unexpected mov instruction in exit stub ({blob[idx:idx + 4].hex()})")
        jmp_off = idx + mov_len
        if jmp_off + 2 > len(blob):
            raise BinaryError(f"{label}: truncated jmp in exit stub")
        if blob[jmp_off] == 0xEB:  # jmp rel8
            jmp_len = 2
        elif blob[jmp_off] == 0xE9 and jmp_off + 5 <= len(blob):  # jmp rel32
            jmp_len = 5
        else:
            raise BinaryError(f"{label}: unexpected jmp opcode in exit stub ({blob[jmp_off]:#x})")
        return mov_len + jmp_len

    def _find_unique_call(self, fn: GoFunc, blob: bytes, target_sym: str, label: str) -> int:
        """Return the unique byte offset within ``blob`` of a `call rel32` to ``target_sym``."""
        target = self.symbols.find(target_sym)
        hits = []
        pos = 0
        while True:
            i = blob.find(b"\xe8", pos)
            if i < 0 or i + 5 > len(blob):
                break
            pos = i + 1
            rel = struct.unpack_from("<i", blob, i + 1)[0]
            if fn.va + i + 5 + rel == target.va:
                hits.append(i)
        if len(hits) != 1:
            raise BinaryError(f"{label}: expected 1 call to {target_sym} in {fn.name}, found {len(hits)}")
        return hits[0]

    def _inspect_model_gate(self, fn: GoFunc, start: int, blob: bytes) -> Tuple[str, int, int, bytes]:
        """Locate `call proto.Equal; test %al,%al; (jne|jmp) <exit_stub>` symbolically."""
        peq_idx = self._find_unique_call(fn, blob, "proto.Equal", "model-gate")
        site_idx = peq_idx + 5
        if site_idx + 4 > len(blob) or blob[site_idx:site_idx + 2] != b"\x84\xc0":
            raise BinaryError(f"model-gate: expected `test %al,%al` after call proto.Equal in {fn.name}")
        op = blob[site_idx + 2]
        if op not in (0x75, 0xEB):
            raise BinaryError(f"model-gate: expected jne/jmp after `test %al,%al` (got {op:#x})")
        j_disp = blob[site_idx + 3]
        stub_len = self._validate_exit_stub(blob, site_idx + 4, "model-gate")
        if j_disp != stub_len:
            raise BinaryError(f"model-gate: jump displacement {j_disp:#x} != exit stub length {stub_len:#x}")
        state = "patched" if op == 0xEB else "clean"
        return state, start + site_idx, fn.va + site_idx, bytes([0x84, 0xC0, 0xEB, j_disp])

    def _build_acp_core(self, site_va: int, exit_stub_va: int) -> bytes:
        acos_fn = self.symbols.find("store.AutoCompactOverrideSpec")
        mtl_fn = self.symbols.find("backend.ContextWindow.MaxTokenLimit")
        rel_acos = acos_fn.va - (site_va + 10)  # +5B test/jne + 5B call
        rel_mtl = mtl_fn.va - (site_va + 15)    # +10B + 5B call
        rel8_exit = exit_stub_va - (site_va + 19)  # +15B + 2B test + 2B je
        if not (-1 << 31 <= rel_acos < 1 << 31):
            raise BinaryError(f"acp-override: AutoCompactOverrideSpec out of rel32 range ({rel_acos:#x})")
        if not (-1 << 31 <= rel_mtl < 1 << 31):
            raise BinaryError(f"acp-override: MaxTokenLimit out of rel32 range ({rel_mtl:#x})")
        if not (-128 <= rel8_exit <= 127):
            raise BinaryError(f"acp-override: exit stub out of rel8 range ({rel8_exit:#x})")
        return (
            bytes.fromhex("48 85 db 75 05")
            + b"\xe8" + struct.pack("<i", rel_acos)
            + b"\xe8" + struct.pack("<i", rel_mtl)
            + bytes.fromhex("85 c0 74") + struct.pack("<b", rel8_exit)
        )

    def _resolve_patch_new_bytes(self, p: Patch, site_va: int) -> bytes:
        """Compute dynamic target-relative machine code for call/branch patches."""
        if p.key == "settings-window":
            choice_fn = self.symbols.find("store.(*Store).ContextWindowChoice")
            call_next_va = site_va + 8 + 5  # mov (8B) + call rel32 (5B)
            rel = choice_fn.va - call_next_va
            if not (-1 << 31 <= rel < 1 << 31):
                raise BinaryError(f"settings-window: ContextWindowChoice out of rel32 range ({rel:#x})")
            return bytes.fromhex("48 8b 84 24 08 01 00 00") + b"\xe8" + struct.pack("<i", rel) + b"\xc9\xc3"
        if p.key in ("model-gate", "acp-override"):
            _state, _off, _va, new_bytes = self.inspect_patch(p)
            return new_bytes
        return p.new

    # -- helpers -----------------------------------------------------------
    def func_bytes(self, fn: GoFunc) -> Tuple[int, int]:
        start = self.elf.va_to_off(fn.va)
        if start is None:
            raise BinaryError(f"cannot map {fn.name} to a file offset")
        end = self.elf.va_to_off(fn.end)
        if end is None or end <= start:
            end = min(len(self.data), start + 0x4000)
        return start, end

    def inspect_patch(self, p: Patch) -> Tuple[str, int, int, bytes]:
        """Return (state, file_offset, va, resolved_new_bytes) with state in {'patched', 'clean'}."""
        fn = self.symbols.find(p.symbol)
        start, end = self.func_bytes(fn)
        blob = bytes(self.data[start:end])

        if p.key == "model-gate":
            return self._inspect_model_gate(fn, start, blob)

        if p.key == "acp-override":
            cw_idx = self._find_unique_call(fn, blob, "backend.(*ServerBackend).ContextWindow", "acp-override")
            site_idx = cw_idx + 5
            site_va = fn.va + site_idx
            _mg_state, _mg_off, mg_va, _mg_new = self._inspect_model_gate(fn, start, blob)
            exit_stub_va = mg_va + 4
            core = self._build_acp_core(site_va, exit_stub_va)

            if site_idx + 19 <= len(blob) and blob[site_idx:site_idx + 19] == core:
                pad = 0
                while pad <= 8 and site_idx + 19 + pad < len(blob) and blob[site_idx + 19 + pad] == 0x90:
                    pad += 1
                if blob[site_idx + 19 + pad:site_idx + 19 + pad + 3] != b"\x89\x44\x24":
                    raise BinaryError(f"acp-override: patched sequence not followed by mov %eax, disp(%rsp)")
                return "patched", start + site_idx, site_va, core + b"\x90" * pad

            mtl_fn = self.symbols.find("backend.ContextWindow.MaxTokenLimit")
            expected_call = b"\xe8" + struct.pack("<i", mtl_fn.va - (site_va + 5))
            if blob[site_idx:site_idx + 5] != expected_call:
                raise BinaryError(
                    f"acp-override: expected call MaxTokenLimit after ContextWindow "
                    f"(got {blob[site_idx:site_idx + 5].hex()}, want {expected_call.hex()})"
                )
            if blob[site_idx + 5:site_idx + 8] != b"\x85\xc0\x75":
                raise BinaryError(f"acp-override: expected `test %eax,%eax; jne` after MaxTokenLimit")
            skip_len = blob[site_idx + 8]
            stub_len = self._validate_exit_stub(blob, site_idx + 9, "acp-override")
            if skip_len != stub_len:
                raise BinaryError(f"acp-override: jne displacement {skip_len:#x} != exit stub length {stub_len:#x}")
            slot_len = 9 + skip_len
            if slot_len < len(core):
                raise BinaryError(f"acp-override: slot too small ({slot_len}B < {len(core)}B)")
            if blob[site_idx + slot_len:site_idx + slot_len + 3] != b"\x89\x44\x24":
                raise BinaryError(f"acp-override: slot not followed by mov %eax, disp(%rsp)")
            new_bytes = core + b"\x90" * (slot_len - len(core))
            return "clean", start + site_idx, site_va, new_bytes

        if p.key == "settings-window":
            prefix = bytes.fromhex("48 8b 84 24 08 01 00 00 e8")
            patched_hits = []
            pos = 0
            while True:
                i = blob.find(prefix, pos)
                if i < 0:
                    break
                pos = i + 1
                if i + 15 <= len(blob):
                    cand = self._resolve_patch_new_bytes(p, fn.va + i)
                    if blob[i:i + 15] == cand:
                        patched_hits.append((i, cand))
            if len(patched_hits) == 1:
                i, cand = patched_hits[0]
                return "patched", start + i, fn.va + i, cand
            if len(patched_hits) > 1:
                raise BinaryError(f"{p.key}: multiple patched sites found in {p.symbol}")

            hits = []
            pos = 0
            while True:
                i = blob.find(p.old, pos)
                if i < 0:
                    break
                hits.append(i)
                pos = i + 1
            if not hits:
                raise BinaryError(f"{p.key}: expected bytes not found in {p.symbol}")
            if p.occurrence == 0 and len(hits) != 1:
                raise BinaryError(
                    f"{p.key}: expected exactly one match of {p.old.hex()} in {p.symbol}, found {len(hits)}"
                )
            if p.occurrence >= len(hits):
                raise BinaryError(f"{p.key}: occurrence {p.occurrence} not found in {p.symbol}")
            i = hits[p.occurrence]
            site_va = fn.va + i
            new_bytes = self._resolve_patch_new_bytes(p, site_va)
            if i + len(new_bytes) > len(blob):
                raise BinaryError(f"{p.key}: replacement exceeds function bounds in {p.symbol}")
            return "clean", start + i, site_va, new_bytes

        if p.new in blob:
            idx = blob.find(p.new)
            return "patched", start + idx, fn.va + idx, p.new
        hits = []
        pos = 0
        while True:
            i = blob.find(p.old, pos)
            if i < 0:
                break
            hits.append(i)
            pos = i + 1
        if not hits:
            raise BinaryError(f"{p.key}: expected bytes not found in {p.symbol}")
        if p.occurrence == 0 and len(hits) != 1:
            raise BinaryError(
                f"{p.key}: expected exactly one match of {p.old.hex()} in {p.symbol}, found {len(hits)}"
            )
        if p.occurrence >= len(hits):
            raise BinaryError(f"{p.key}: occurrence {p.occurrence} not found in {p.symbol}")
        i = hits[p.occurrence]
        return "clean", start + i, fn.va + i, p.new

    def is_patched(self) -> bool:
        for p in [x for x in PATCHES if not x.optional]:
            try:
                state, _off, _va, _new = self.inspect_patch(p)
            except BinaryError:
                return False
            if state != "patched":
                return False
        return True

    def locate_patch(self, p: Patch) -> Tuple[int, int]:
        _state, off, va, _new = self.inspect_patch(p)
        return off, va

    def apply(self, p: Patch) -> PatchResult:
        state, off, site_va, new_bytes = self.inspect_patch(p)
        if state == "patched":
            return PatchResult(p, "already", site_va, off, "already patched")
        self.data[off:off + len(new_bytes)] = new_bytes
        return PatchResult(p, "applied", site_va, off, p.description)


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def _header(path: Path, u: Unlocker) -> None:
    print(f"[i] binary : {path}")
    print(f"[i] sha256 : {u.sha256}")
    print(f"[i] arch   : x86-64 ELF64 (e_type={u.elf.e_type})")
    print(f"[i] text   : va={u.elf.section('.text').addr:#x} "
          f"off={u.elf.section('.text').offset:#x} size={u.elf.section('.text').size:#x}")
    print(f"[i] go     : pclntab_off={u.symbols.pclntab_off:#x} minLC={u.symbols.min_lc} "
          f"nfunc={u.symbols.nfunc} text_base={u.symbols.text_base:#x}")
    print(f"[i] symbols: {len(u.symbols.funcs)}")


def cmd_locate(args: argparse.Namespace) -> int:
    path = Path(args.binary).expanduser().resolve()
    u = Unlocker(path)
    _header(path, u)
    if not u.is_target:
        print(f"[!] warning: SHA256 is not the verified {TARGET_VERSION} build "
              f"({TARGET_SHA256_PREFIX}...); patch signatures may not match")
    print("\n[patch targets]")
    for p in PATCHES:
        try:
            state_key, off, va, _new = u.inspect_patch(p)
            fn = u.symbols.find(p.symbol)
            state = "already patched" if state_key == "patched" else "patchable"
            print(f"  {p.key:16s} {state:15s} {p.symbol} +0x{va - fn.va:x} (va {va:#x}, off {off:#x})")
        except BinaryError as exc:
            print(f"  {p.key:16s} NOT FOUND      {exc}")
    if args.json:
        out = {
            "binary": str(path),
            "sha256": u.sha256,
            "go": {
                "pclntab_offset": u.symbols.pclntab_off,
                "min_lc": u.symbols.min_lc,
                "nfunc": u.symbols.nfunc,
                "text_base": u.symbols.text_base,
            },
            "symbols": {p.symbol: u.symbols.find(p.symbol).va for p in PATCHES},
        }
        print(json.dumps(out, indent=2))
    return 0


def cmd_patch(args: argparse.Namespace) -> int:
    src = Path(args.binary).expanduser().resolve()
    if not src.exists():
        print(f"error: no such file: {src}", file=sys.stderr)
        return 2
    u = Unlocker(src)
    _header(src, u)
    if not (u.is_target or u.is_patched()) and not args.allow_unknown:
        print(f"error: SHA256 {u.sha256} is not the verified {TARGET_VERSION} build "
              f"({TARGET_SHA256_PREFIX}...); use --allow-unknown to override", file=sys.stderr)
        return 2

    selected = [p for p in PATCHES if not p.optional]
    if args.with_default_clamp:
        selected = [p for p in PATCHES]
    if args.patches:
        wanted = {x.strip() for x in args.patches.split(",") if x.strip()}
        unknown = wanted - {p.key for p in PATCHES}
        if unknown:
            print(f"error: unknown patch(es): {sorted(unknown)}", file=sys.stderr)
            return 2
        selected = [p for p in PATCHES if p.key in wanted]

    prior_patched_keys: List[str] = []
    for p in PATCHES:
        try:
            if u.inspect_patch(p)[0] == "patched":
                prior_patched_keys.append(p.key)
        except BinaryError:
            pass

    results: List[PatchResult] = []
    print("\n[applying]")
    for p in selected:
        try:
            r = u.apply(p)
        except BinaryError as exc:
            print(f"  [!] {p.key}: {exc}", file=sys.stderr)
            if p.optional:
                continue
            return 3
        results.append(r)
        print(f"  {'[*]' if r.status == 'applied' else '[=]'} {p.key:16s} {r.detail}")

    changed = any(r.status == "applied" for r in results)
    if not changed:
        print("\n[=] nothing to change (binary already patched)")
        return 0
    if args.dry_run:
        print("\n[*] dry run: no file written")
        return 0

    if args.in_place:
        dst = src
    elif args.out:
        dst = Path(args.out).expanduser().resolve()
    else:
        dst = src.with_name(src.name + ".patched")
    overwrites_source = dst == src or (dst.exists() and src.exists() and os.path.samefile(dst, src))
    if overwrites_source and not args.yes:
        print("error: output resolves to the source binary; pass --in-place --yes (and --allow-system "
              "for a system path) to overwrite it", file=sys.stderr)
        return 2
    if overwrites_source and str(src) in ("/usr/bin/agy", "/usr/local/bin/agy") and not args.allow_system:
        print("error: refusing to overwrite a system binary; pass --allow-system or use install mode", file=sys.stderr)
        return 2
    if overwrites_source:
        if _backup_matches_clean_source(src, u.sha256, prior_patched_keys):
            backup = src.with_name(src.name + ".agy-unlock-backup")
            print(f"[i] keeping existing clean backup: {backup}")
        else:
            _ensure_backup(src, u.sha256)
    _atomic_write(dst, bytes(u.data), src.stat().st_mode)
    print(f"[*] wrote {dst}")
    print(f"    sha256 {u.sha256} -> {hashlib.sha256(u.data).hexdigest()}")
    return 0


def _backup_matches_clean_source(src: Path, source_sha: str, already_keys: List[str]) -> bool:
    """Return True if existing .agy-unlock-backup is provably the clean original of src.

    When upgrading agy-context-unlock itself (e.g. adding a new patch onto an
    already-patched binary), overwriting/rotating .agy-unlock-backup with the
    partially patched binary would lose the clean unpatched backup.  Verify
    cryptographically by re-applying the already-present patches onto the backup
    in memory and checking that the result matches ``source_sha``.
    """
    if not already_keys:
        return False
    backup = src.with_name(src.name + ".agy-unlock-backup")
    if not backup.exists():
        return False
    try:
        if backup.stat().st_size != src.stat().st_size:
            return False
        bu = Unlocker(backup)
        by_key = {p.key: p for p in PATCHES}
        for key in already_keys:
            r = bu.apply(by_key[key])
            if r.status != "applied":
                return False
        return hashlib.sha256(bu.data).hexdigest() == source_sha
    except (BinaryError, OSError):
        return False



def _ensure_backup(src: Path, source_sha: str) -> Path:
    """Keep one backup of the *current* source binary.

    A package upgrade replaces /usr/bin/agy but leaves the old
    ``.agy-unlock-backup`` in place.  Blindly reusing that stale file would make
    ``restore`` downgrade the CLI to a previous version, so rotate a mismatching
    backup to ``<backup>.<old-sha8>`` before copying the current binary.
    """
    backup = src.with_name(src.name + ".agy-unlock-backup")
    if backup.exists():
        old_sha = hashlib.sha256(backup.read_bytes()).hexdigest()
        if old_sha != source_sha:
            rotated = backup.with_name(f"{backup.name}.{old_sha[:8]}")
            if rotated.exists():
                backup.unlink()
            else:
                os.replace(backup, rotated)
            print(f"[i] rotated stale backup: {rotated}")
    if not backup.exists():
        shutil.copy2(src, backup)
        print(f"[i] backup: {backup}")
    return backup


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, stat.S_IMODE(mode))
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _verify_patched(data: bytes) -> Tuple[bool, List[str]]:
    u = object.__new__(Unlocker)
    u.path = Path("<memory>")
    u.data = bytearray(data)
    u.sha256 = hashlib.sha256(data).hexdigest()
    u.is_target = u.sha256.startswith(TARGET_SHA256_PREFIX)
    u.elf = ELFFile(data)
    u.symbols = GoSymbols(u.elf)
    u.text_sec = u.elf.section(".text")
    problems = []
    for p in PATCHES:
        if p.optional:
            continue
        try:
            state, _off, _va, _new = u.inspect_patch(p)
        except BinaryError as exc:
            problems.append(f"{p.key}: {exc}")
            continue
        if state != "patched":
            problems.append(f"{p.key}: patched bytes absent")
    return not problems, problems


def cmd_verify(args: argparse.Namespace) -> int:
    path = Path(args.binary).expanduser().resolve()
    u = Unlocker(path)
    print(f"[i] {path}\n[i] sha256 {u.sha256}")
    print(f"[i] go text_base={u.symbols.text_base:#x} nfunc={u.symbols.nfunc}")
    ok = True
    for p in PATCHES:
        try:
            state_key, _off, _va, _new = u.inspect_patch(p)
            applied = state_key == "patched"
            status = "PATCHED" if applied else "clean"
        except BinaryError:
            applied = False
            status = "UNKNOWN"
        print(f"  {p.key:16s} {status:8s} {p.symbol}")
        if not p.optional and not applied:
            ok = False
    print("[+] verified: required patches are present" if ok else "[-] verification failed")
    return 0 if ok else 1


def cmd_restore(args: argparse.Namespace) -> int:
    path = Path(args.binary).expanduser().resolve()
    backup = Path(args.backup).expanduser().resolve() if args.backup else path.with_name(path.name + ".agy-unlock-backup")
    if not backup.exists():
        print(f"error: backup not found: {backup}", file=sys.stderr)
        return 2
    _atomic_write(path, backup.read_bytes(), backup.stat().st_mode)
    print(f"[*] restored {path} from {backup}")
    return 0


def cmd_self_test(args: argparse.Namespace) -> int:
    path = Path(args.binary).expanduser().resolve()
    data = path.read_bytes()
    elf = ELFFile(data)
    syms = GoSymbols(elf)
    checks = []

    anchors = {
        "model.SelectorModel.offersContextWindow": 0xA6A03C0,
        "store.(*Store).ContextWindowChoice": 0xA3FDEA0,
        "store.(*Store).ContextWindow": 0xA3FDEE0,
        "store.AutoCompactOverrideSpec": 0xA3FDC00,
        "backend.ContextWindow.MaxTokenLimit": 0xA0789E0,
        "backend.(*ServerBackend).buildCascadeConfigInternal": 0xA08C3A0,
        "utils.GetCheckpointConfig": 0x84F5CE0,
    }
    for name, want in anchors.items():
        got = syms.find(name).va
        checks.append((f"symbol {name}", got == want, f"{got:#x} (want {want:#x})"))

    u = Unlocker(path)
    before = bytes(u.data)
    required = [p for p in PATCHES if not p.optional]

    # Count the bytes that each patch would actually change.  We cannot zip
    # p.old/p.new: settings-window matches 14 bytes but writes 15 (the trailing
    # "ret" replaces the byte after the old signature), and acp-override
    # resolves dynamic call/jump displacements over 22 bytes.
    base = bytearray(before)
    expected = 0
    for p in required:
        _state, off, _site_va, new_bytes = u.inspect_patch(p)
        expected += sum(1 for i, b in enumerate(new_bytes) if base[off + i] != b)

    for p in required:
        u.apply(p)
    after = bytes(u.data)
    diff = [i for i in range(len(before)) if before[i] != after[i]]
    checks.append(("patched byte count", len(diff) == expected, f"{len(diff)} bytes (want {expected})"))

    ok = True
    for name, passed, detail in checks:
        print(f"  [{'OK' if passed else 'FAIL'}] {name}: {detail}")
        ok = ok and passed
    print("[+] self-test passed" if ok else "[-] self-test failed")
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# Pacman hook generator (Arch Linux / EndeavourOS)
# ---------------------------------------------------------------------------

PACMAN_HOOK_TEMPLATE = """[Trigger]
Operation = Install
Operation = Upgrade
Type = Package
Target = {package}

[Action]
Description = Patching /usr/bin/agy to unlock context window limit (settings.json & override)...
When = PostTransaction
Exec = /usr/bin/python3 {script_path} patch --binary {binary_path} --in-place --yes --allow-system --allow-unknown
"""


def cmd_pacman_hook(args: argparse.Namespace) -> int:
    script_path = Path(args.script_path).expanduser().resolve() if args.script_path else Path(__file__).resolve()
    binary_path = Path(args.binary).expanduser().resolve()
    content = PACMAN_HOOK_TEMPLATE.format(
        package=args.package,
        script_path=script_path,
        binary_path=binary_path,
    )
    if args.write:
        dst = Path(args.write).expanduser().resolve()
        _atomic_write(dst, content.encode("utf-8"), 0o644)
        print(f"[*] wrote pacman hook: {dst}")
    else:
        sys.stdout.write(content)
    return 0


# ---------------------------------------------------------------------------
# install (optional standalone copy + launcher)
# ---------------------------------------------------------------------------

LAUNCHER = r'''#!/usr/bin/env python3
"""agy-unlock launcher: run agy with an optional context window override."""
import json, os, sys
from pathlib import Path

BIN = Path(os.environ.get("AGY_UNLOCK_BINARY", __BIN__))
WINDOW = os.environ.get("AGY_UNLOCK_WINDOW", "__WINDOW__")
STATE = Path(__file__).resolve().parent.parent / "share" / "agy-context-unlock" / "state.json"
CONFIG = Path.home() / ".gemini" / "antigravity-cli" / "settings.json"
MAX_WINDOW = 1_000_000


def load_json(path, default):
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        return default


def load_settings(value):
    try:
        if value.lstrip().startswith("{"):
            return json.loads(value)
        return load_json(value, {})
    except Exception:
        return {}


def parse_args(argv):
    """Return (model, provider). Never treats post-'--' text as a flag."""
    model = None
    settings = {}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--":
            break
        if a == "--model" and i + 1 < len(argv):
            model = argv[i + 1]; i += 2; continue
        if a.startswith("--model="):
            model = a.split("=", 1)[1]; i += 1; continue
        if a == "--settings" and i + 1 < len(argv):
            settings = load_settings(argv[i + 1]); i += 2; continue
        if a.startswith("--settings="):
            settings = load_settings(a.split("=", 1)[1]); i += 1; continue
        i += 1
    if model is None:
        model = settings.get("model")
    return model, settings.get("modelProvider")


def is_native_gemini(model, provider):
    if not model or "/" in model:
        return False
    if provider and provider not in ("google", "Google", "MODEL_PROVIDER_GOOGLE"):
        return False
    return str(model).lower().startswith(("gemini", "google gemini"))


def main():
    st = load_json(STATE, {})
    if not BIN.exists():
        sys.exit(f"agy-unlock: binary missing: {BIN}")
    try:
        window = int(WINDOW)
        if not 0 < window <= MAX_WINDOW:
            raise ValueError
    except Exception:
        sys.exit(f"agy-unlock: invalid window {WINDOW!r} (want 1..{MAX_WINDOW})")

    cfg = load_json(CONFIG, {})
    model, provider = parse_args(sys.argv[1:])
    if model is None:
        model = cfg.get("model")
    if provider is None:
        provider = cfg.get("modelProvider")

    env = dict(os.environ)
    native = is_native_gemini(model, provider)
    scope = st.get("scope", "native-gemini")
    if (scope == "all") or (scope == "native-gemini" and native):
        env["AGY_CLI_AUTO_COMPACT_OVERRIDE"] = str(window)
    elif os.environ.get("AGY_UNLOCK_KEEP_ENV") != "1":
        env.pop("AGY_CLI_AUTO_COMPACT_OVERRIDE", None)

    if os.environ.get("AGY_UNLOCK_VERBOSE"):
        print(f"agy-unlock: model={model!r} provider={provider!r} native={native} "
              f"scope={scope} override={env.get('AGY_CLI_AUTO_COMPACT_OVERRIDE', '<unset>')}",
              file=sys.stderr)
    os.execve(str(BIN), [str(BIN), *sys.argv[1:]], env)


if __name__ == "__main__":
    main()'''


def cmd_install(args: argparse.Namespace) -> int:
    src = Path(args.binary).expanduser().resolve()
    u = Unlocker(src)
    if not (u.is_target or u.is_patched()) and not args.allow_unknown:
        print(f"error: SHA256 {u.sha256} is not the verified {TARGET_VERSION} build "
              f"({TARGET_SHA256_PREFIX}...); use --allow-unknown to override", file=sys.stderr)
        return 2
    if not 0 < args.window <= MAX_WINDOW:
        print(f"error: --window must be in 1..{MAX_WINDOW}", file=sys.stderr)
        return 2
    root = Path(args.prefix).expanduser().resolve()
    share = root / "share" / "agy-context-unlock"
    bindir = root / "bin"
    share.mkdir(parents=True, exist_ok=True)
    bindir.mkdir(parents=True, exist_ok=True)

    installed = share / "agy"
    if args.patch:
        for p in [q for q in PATCHES if not q.optional]:
            u.apply(p)
        data = bytes(u.data)
        applied = [p.key for p in PATCHES if not p.optional]
        _atomic_write(installed, data, src.stat().st_mode)
        bin_path = str(installed)
        note = " (patched, locked read-only to stop the auto-updater)"
    else:
        applied = []
        bin_path = str(src)
        note = " (launcher only; uses the read-only system binary, so the auto-updater skips it)"

    state = {
        "project_version": PROJECT_VERSION,
        "source_binary": str(src),
        "source_sha256": u.sha256,
        "binary": bin_path,
        "patched": bool(applied),
        "patches": applied,
        "scope": args.scope,
        "window": args.window,
    }
    if not os.access(share, os.W_OK):
        print(f"error: {share} is not writable; chmod u+w it before reinstalling", file=sys.stderr)
        return 2
    _atomic_write(share / "state.json", (json.dumps(state, indent=2) + "\n").encode(), 0o644)
    launcher = bindir / "agy-unlock"
    _atomic_write(
        launcher,
        LAUNCHER.replace("__WINDOW__", str(args.window)).replace("__BIN__", json.dumps(bin_path)).encode(),
        0o755,
    )

    if args.patch:
        installed.chmod(0o555)
        share.chmod(0o555)
    else:
        if installed.exists():
            try:
                installed.unlink()
            except OSError as exc:
                print(f"error: cannot remove old patched copy {installed}: {exc}; "
                      f"chmod u+w {share} and retry", file=sys.stderr)
                return 2

    print(f"[*] installed binary        : {bin_path}{note}")
    print(f"[*] installed launcher      : {launcher}")
    print(f"[*] window                  : {args.window:,} tokens (scope={args.scope})")
    if args.patch:
        print(f"[i] {share} is read-only; 'chmod u+w {share}' before reinstalling/updating")
    if args.shadow:
        shadow = bindir / "agy"
        if shadow.exists() or shadow.is_symlink():
            print(f"[!] {shadow} already exists; not overwriting", file=sys.stderr)
        else:
            import shlex
            shadow.write_text("#!/bin/sh\nexec %s \"$@\"\n" % shlex.quote(str(launcher)))
            shadow.chmod(0o755)
            print(f"[*] shadow launcher         : {shadow} (takes precedence only if {bindir} is before /usr/bin in PATH)")
    print("\nRun: agy-unlock            # or: agy-unlock -p 'hello'")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="agy-context-unlock",
        description="Unlock >256K context window in antigravity-cli (agy 1.5.7 Linux x86-64).",
    )
    ap.add_argument("--version", action="version", version=f"%(prog)s {PROJECT_VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--binary", default="/usr/bin/agy", help="path to agy (default: /usr/bin/agy)")
        p.add_argument("--json", action="store_true", help="machine-readable output where supported")

    p = sub.add_parser("locate", help="parse the binary and print patch sites")
    common(p)
    p.set_defaults(func=cmd_locate)

    p = sub.add_parser("patch", help="write a patched copy (or patch in-place)")
    common(p)
    p.add_argument("--out", help="output path (default: BINARY.patched)")
    p.add_argument("--in-place", action="store_true", help="overwrite BINARY (creates a .agy-unlock-backup)")
    p.add_argument("--yes", action="store_true", help="confirm --in-place")
    p.add_argument("--allow-system", action="store_true", help="allow --in-place on /usr/bin/agy")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--patches", help="comma-separated subset: ui-selector,store-gate,settings-window,model-gate,acp-override,default-clamp")
    p.add_argument("--with-default-clamp", action="store_true", help="also raise the local 256000 fallback cap to 1048576")
    p.add_argument("--allow-unknown", action="store_true", help="allow a binary whose SHA256 is not the verified 1.5.7 build")
    p.set_defaults(func=cmd_patch)

    p = sub.add_parser("verify", help="verify required patches in a binary")
    common(p)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("restore", help="restore an in-place patched binary from its backup")
    common(p)
    p.add_argument("--backup")
    p.set_defaults(func=cmd_restore)

    p = sub.add_parser("self-test", help="offline parser/patch self-test")
    common(p)
    p.set_defaults(func=cmd_self_test)

    p = sub.add_parser("pacman-hook", help="print or write an Arch/EndeavourOS Pacman PostTransaction hook")
    common(p)
    p.add_argument("--package", default="antigravity-cli", help="Pacman package name (default: antigravity-cli)")
    p.add_argument("--script-path", help="path to agy_context_unlock.py in the hook (default: this script's path)")
    p.add_argument("--write", help="write hook to file (e.g. /etc/pacman.d/hooks/99-agy-context-unlock.hook)")
    p.set_defaults(func=cmd_pacman_hook)

    p = sub.add_parser("install", help="install a standalone patched copy and the agy-unlock launcher")
    common(p)
    p.add_argument("--prefix", default=str(Path.home() / ".local"), help="install prefix (default: ~/.local)")
    p.add_argument("--window", type=int, default=DEFAULT_WINDOW, help="token window for launcher override (default: 900000)")
    p.add_argument("--scope", default="native-gemini", choices=["native-gemini", "all"], help="who gets the launcher env override")
    p.add_argument("--shadow", action="store_true", help="also create PREFIX/bin/agy wrapper")
    p.add_argument("--patch", action="store_true", help="also apply the binary patches to the installed copy")
    p.add_argument("--allow-unknown", action="store_true", help="allow a binary whose SHA256 is not the verified 1.5.7 build")
    p.set_defaults(func=cmd_install)
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except BinaryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
