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

What the four core binary patches do (20 bytes total)
-----------------------------------------------------
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

An optional 5th patch (``default-clamp``, enabled via ``--with-default-clamp``)
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

PROJECT_VERSION = "2.1.0"
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
        old=bytes.fromhex("84 c0 75 0a 48 8b 8c 24 b0 00 00 00"),
        new=bytes.fromhex("84 c0 eb 0a 48 8b 8c 24 b0 00 00 00"),
        description="Checkpoint override: drop the selected-model equality gate",
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

    def _resolve_patch_new_bytes(self, p: Patch, site_va: int) -> bytes:
        """For settings-window, dynamically verify/compute the relative call to ContextWindowChoice."""
        if p.key != "settings-window":
            return p.new
        choice_fn = self.symbols.find("store.(*Store).ContextWindowChoice")
        call_next_va = site_va + 8 + 5  # mov (8B) + call rel32 (5B)
        rel = choice_fn.va - call_next_va
        if not (-1 << 31 <= rel < 1 << 31):
            raise BinaryError(f"settings-window: ContextWindowChoice out of rel32 range ({rel:#x})")
        return bytes.fromhex("48 8b 84 24 08 01 00 00") + b"\xe8" + struct.pack("<i", rel) + b"\xc9\xc3"

    # -- helpers -----------------------------------------------------------
    def func_bytes(self, fn: GoFunc) -> Tuple[int, int]:
        start = self.elf.va_to_off(fn.va)
        if start is None:
            raise BinaryError(f"cannot map {fn.name} to a file offset")
        end = self.elf.va_to_off(fn.end)
        if end is None or end <= start:
            end = min(len(self.data), start + 0x4000)
        return start, end

    def is_patched(self) -> bool:
        for p in [x for x in PATCHES if not x.optional]:
            fn = self.symbols.find(p.symbol)
            start, end = self.func_bytes(fn)
            if p.new not in bytes(self.data[start:end]):
                return False
        return True

    def locate_patch(self, p: Patch) -> Tuple[int, int]:
        fn = self.symbols.find(p.symbol)
        start, end = self.func_bytes(fn)
        blob = bytes(self.data[start:end])
        hits = []
        pos = 0
        while True:
            i = blob.find(p.old, pos)
            if i < 0:
                break
            hits.append(i)
            pos = i + 1
        if p.new in blob:
            idx = blob.find(p.new)
            return start + idx, fn.va + idx
        if p.occurrence == 0:
            if len(hits) != 1:
                raise BinaryError(
                    f"{p.key}: expected exactly one match of {p.old.hex()} in "
                    f"{p.symbol}, found {len(hits)}"
                )
            i = hits[0]
        else:
            if len(hits) <= p.occurrence:
                raise BinaryError(f"{p.key}: occurrence {p.occurrence} not found in {p.symbol}")
            i = hits[p.occurrence]
        return start + i, fn.va + i

    def apply(self, p: Patch) -> PatchResult:
        fn = self.symbols.find(p.symbol)
        start, end = self.func_bytes(fn)
        blob = bytes(self.data[start:end])
        if p.new in blob:
            off = start + blob.find(p.new)
            return PatchResult(p, "already", fn.va + blob.find(p.new), off, "already patched")
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
            raise BinaryError(f"{p.key}: expected one match in {p.symbol}, found {len(hits)}")
        if p.occurrence >= len(hits):
            raise BinaryError(f"{p.key}: occurrence {p.occurrence} missing in {p.symbol}")
        i = hits[p.occurrence]
        site_va = fn.va + i
        new_bytes = self._resolve_patch_new_bytes(p, site_va)
        self.data[start + i:start + i + len(new_bytes)] = new_bytes
        return PatchResult(p, "applied", site_va, start + i, p.description)


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
            off, va = u.locate_patch(p)
            fn = u.symbols.find(p.symbol)
            state = "already patched" if p.new in bytes(u.data[off:off + len(p.new)]) else "patchable"
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
        backup = src.with_name(src.name + ".agy-unlock-backup")
        if not backup.exists():
            shutil.copy2(src, backup)
            print(f"[i] backup: {backup}")
    _atomic_write(dst, bytes(u.data), src.stat().st_mode)
    print(f"[*] wrote {dst}")
    print(f"    sha256 {u.sha256} -> {hashlib.sha256(u.data).hexdigest()}")
    return 0


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
    elf = ELFFile(data)
    syms = GoSymbols(elf)
    problems = []
    for p in PATCHES:
        if p.optional:
            continue
        fn = syms.find(p.symbol)
        start = elf.va_to_off(fn.va)
        end = elf.va_to_off(fn.end) or start + 0x4000
        if p.new not in data[start:end]:
            problems.append(f"{p.key}: patched bytes absent")
    return not problems, problems


def cmd_verify(args: argparse.Namespace) -> int:
    path = Path(args.binary).expanduser().resolve()
    data = path.read_bytes()
    elf = ELFFile(data)
    syms = GoSymbols(elf)
    print(f"[i] {path}\n[i] sha256 {hashlib.sha256(data).hexdigest()}")
    print(f"[i] go text_base={syms.text_base:#x} nfunc={syms.nfunc}")
    ok = True
    for p in PATCHES:
        fn = syms.find(p.symbol)
        start = elf.va_to_off(fn.va)
        end = elf.va_to_off(fn.end) or start + 0x4000
        applied = p.new in data[start:end]
        status = "PATCHED" if applied else ("clean" if p.old in data[start:end] else "UNKNOWN")
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
    # "ret" replaces the byte after the old signature).
    base = bytearray(before)
    expected = 0
    for p in required:
        off, site_va = u.locate_patch(p)
        new_bytes = u._resolve_patch_new_bytes(p, site_va)
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
    p.add_argument("--patches", help="comma-separated subset: ui-selector,store-gate,settings-window,model-gate,default-clamp")
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
