#!/usr/bin/env python3
"""End-to-end verifier: prove that agy actually crosses 256K without compacting.

It generates filler files, asks the agent to read all of them (so the context
grows past 256K tokens), runs agy, then decodes the session's gen_metadata
rows and reports the highest token count and every MAX_TOKEN_LIMIT checkpoint.

Only numeric metadata is read; conversation text is never printed.

Example (patched binary, native Gemini Flash):
    python3 verify_live.py --binary ~/.local/share/agy-context-unlock/agy \
        --model "Gemini 3.8 Flash (High)" --files 6 --window 900000 \
        --proxy http://127.0.0.1:2080

Negative control (unpatched binary; expected to compact near 256K):
    python3 verify_live.py --binary /usr/bin/agy --no-override \
        --model "Gemini 3.8 Flash (High)" --files 4
"""

from __future__ import annotations

import argparse
import hashlib
import os
import random
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

HOME = Path.home()
CONV_DIR = HOME / ".gemini" / "antigravity-cli" / "conversations"
WORDS = (
    "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima "
    "mike november oscar papa quebec romeo sierra tango"
).split()


# ---------------------------------------------------------------------------
# protobuf wire decoder (only ContextWindowMetadata is needed)
# ---------------------------------------------------------------------------


def _varint(b: bytes, p: int) -> Tuple[int, int]:
    v = 0
    for n in range(10):
        if p >= len(b):
            raise ValueError("truncated varint")
        x = b[p]
        p += 1
        v |= (x & 0x7F) << (7 * n)
        if x < 0x80:
            return v, p
    raise ValueError("varint overflow")


def _wire(b: bytes) -> List[Tuple[int, int, object]]:
    p = 0
    out = []
    while p < len(b):
        key, p = _varint(b, p)
        f, w = key >> 3, key & 7
        if not f:
            raise ValueError("field 0")
        if w == 0:
            v, p = _varint(b, p)
        elif w == 1:
            v = b[p:p + 8]
            p += 8
        elif w == 2:
            n, p = _varint(b, p)
            v = b[p:p + n]
            p += n
        elif w == 5:
            v = b[p:p + 4]
            p += 4
        else:
            raise ValueError(f"wire {w}")
        out.append((f, w, v))
    return out


def _last(fields, f, w, default=None):
    vals = [v for ff, ww, v in fields if ff == f and ww == w]
    return vals[-1] if vals else default


def decode_row(blob: bytes) -> Dict[str, object]:
    root = _wire(blob)
    chat = _wire(_last(root, 1, 2, b""))
    model = _last(chat, 19, 2, b"").decode("utf-8", "replace")
    entries = []
    ctx = _wire(_last(chat, 9, 2, b""))
    for raw in [v for f, w, v in ctx if f == 10 and w == 2]:
        f = _wire(raw)
        entries.append(
            {
                "tokens": _last(f, 1, 0, 0),
                "reason": _last(f, 2, 0, 0),
                "max_context": _last(f, 4, 0, 0),
            }
        )
    return {"model": model, "entries": entries}


def read_session(db: Path) -> List[Dict[str, object]]:
    if not db.exists():
        return []
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.execute("PRAGMA query_only=ON")
    try:
        rows = con.execute("SELECT idx,data FROM gen_metadata ORDER BY idx").fetchall()
    finally:
        con.close()
    out = []
    for idx, data in rows:
        try:
            d = decode_row(data)
        except Exception:
            continue
        d["idx"] = idx
        out.append(d)
    return out


# ---------------------------------------------------------------------------
# test data and run
# ---------------------------------------------------------------------------


def make_chunks(work: Path, count: int, bytes_each: int = 400_000) -> List[Path]:
    work.mkdir(parents=True, exist_ok=True)
    paths = []
    rng = random.Random(11)
    for i in range(1, count + 1):
        p = work / f"part{i:02d}.txt"
        if p.exists() and p.stat().st_size >= bytes_each * 0.9:
            paths.append(p)
            continue
        buf, n = [], 0
        while n < bytes_each:
            line = " ".join(rng.choice(WORDS) for _ in range(40))
            buf.append(line)
            n += len(line) + 1
        p.write_text("\n".join(buf))
        paths.append(p)
    return paths


def filler(rng: random.Random, size: int) -> str:
    buf, n = [], 0
    while n < size:
        line = " ".join(rng.choice(WORDS) for _ in range(40))
        buf.append(line)
        n += len(line) + 1
    return "\n".join(buf)


def run_stream(binary: Path, model: str, turns: int, bytes_each: int, log: Path,
               proxy: Optional[str], override: Optional[int], timeout: int,
               work: Path) -> Optional[str]:
    import json
    rng = random.Random(31)
    msgs = []
    for k in range(turns):
        text = f"Ignore the filler. Reply with exactly: V{k}_OK\n\n" + filler(rng, bytes_each)
        msgs.append({"event": "user", "message": {"role": "user",
                                                  "content": [{"type": "text", "text": text}]}})
    nd = work / "stream.ndjson"
    with nd.open("w") as fh:
        for m in msgs:
            fh.write(json.dumps(m) + "\n")
    env = dict(os.environ)
    if proxy:
        env["HTTPS_PROXY"] = proxy
        env["HTTP_PROXY"] = proxy
    if override:
        env["AGY_CLI_AUTO_COMPACT_OVERRIDE"] = str(override)
    else:
        env.pop("AGY_CLI_AUTO_COMPACT_OVERRIDE", None)
    cmd = [str(binary), "--print=", "--input-format", "stream-json",
           "--output-format", "stream-json", "--model", model,
           "--dangerously-skip-permissions", "--log-file", str(log)]
    print(f"[i] running stream: {turns} turns x ~{bytes_each // 4} tokens (override={override})")
    t0 = time.time()
    with nd.open("rb") as fin:
        p = subprocess.run(cmd, env=env, stdin=fin, capture_output=True, timeout=timeout)
    print(f"[i] rc={p.returncode} elapsed={time.time() - t0:.1f}s "
          f"(stdout={len(p.stdout)}B stderr={len(p.stderr)}B; content not printed)")
    out = p.stdout.decode("utf-8", "replace")
    ids = re.findall(r'"conversation_id":"([0-9a-f-]{36})"', out)
    return (ids[0] if ids else None), p.returncode


def run_agy(binary: Path, model: str, files: List[Path], log: Path,
            proxy: Optional[str], override: Optional[int], timeout: int) -> int:
    prompt = (
        "Use your file-reading tool to read each of these files completely, one after another, "
        "in this order:\n"
        + "\n".join(str(p) for p in files)
        + "\nRead every file in full before moving on. "
        "After all files are read, reply with exactly: ALL_READ"
    )
    env = dict(os.environ)
    if proxy:
        env["HTTPS_PROXY"] = proxy
        env["HTTP_PROXY"] = proxy
    if override:
        env["AGY_CLI_AUTO_COMPACT_OVERRIDE"] = str(override)
    else:
        env.pop("AGY_CLI_AUTO_COMPACT_OVERRIDE", None)
    cmd = [str(binary), "-p", prompt, "--model", model,
           "--dangerously-skip-permissions", "--log-file", str(log)]
    print(f"[i] running: {binary} --model {model!r} (override={override})")
    t0 = time.time()
    p = subprocess.run(cmd, env=env, text=True, capture_output=True, timeout=timeout)
    print(f"[i] rc={p.returncode} elapsed={time.time() - t0:.1f}s "
          f"(stdout={len(p.stdout)}B stderr={len(p.stderr)}B; content not printed)")
    return p.returncode


def conversation_id(log: Path) -> Optional[str]:
    try:
        text = log.read_text(errors="replace")
    except Exception:
        return None
    ids = re.findall(r"conversation=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", text)
    return ids[-1] if ids else None


def summarize(rows: List[Dict[str, object]]) -> Dict[str, object]:
    if not rows:
        return {"rows": 0, "max_tokens": 0, "compactions": [], "over_256k": 0, "models": {}}
    max_tokens = 0
    over = 0
    compactions = []
    models: Dict[str, int] = {}
    prev_max = 0
    for pos, r in enumerate(rows):
        name = r["model"] or "<unknown>"
        models[name] = models.get(name, 0) + 1
        row_max = 0
        for e in r["entries"]:
            # reason=2 marks the post-compaction row: the meaningful "before"
            # value is the immediately preceding row's maximum.
            if e["reason"] == 2:
                compactions.append((r.get("idx", pos), prev_max))
            max_tokens = max(max_tokens, e["tokens"])
            row_max = max(row_max, e["tokens"])
            if e["tokens"] > 256_000:
                over += 1
        prev_max = row_max
    return {
        "rows": len(rows),
        "max_tokens": max_tokens,
        "over_256k": over,
        "compactions": compactions,
        "models": models,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", default="/usr/bin/agy")
    ap.add_argument("--model", default="Gemini 3.8 Flash (High)")
    ap.add_argument("--mode", choices=["files", "stream"], default="files",
                    help="files: ask the agent to read filler files; stream: send N NDJSON user turns")
    ap.add_argument("--files", type=int, default=6, help="number of 400KB filler files (default 6 ~= 450K tokens)")
    ap.add_argument("--turns", type=int, default=30, help="stream mode: number of user turns (default 30)")
    ap.add_argument("--turn-bytes", type=int, default=60_000, help="stream mode: filler bytes per turn")
    ap.add_argument("--window", type=int, default=900_000, help="override passed to agy (default 900000)")
    ap.add_argument("--no-override", action="store_true", help="negative control: do not set the env override")
    ap.add_argument("--proxy", default=os.environ.get("HTTPS_PROXY", ""), help="HTTPS proxy for the model API")
    ap.add_argument("--timeout", type=int, default=2400)
    ap.add_argument("--workdir", default="", help="parent dir for a new run-<timestamp> subdir; never deleted if given")
    ap.add_argument("--keep", action="store_true", help="keep the auto-created temp dir")
    ap.add_argument("--allow-failure", action="store_true", help="still inspect the session if agy rc != 0")
    args = ap.parse_args()

    binary = Path(args.binary).expanduser().resolve()
    if not binary.exists():
        print(f"error: binary not found: {binary}", file=sys.stderr)
        return 2
    if not 0 < args.window <= 1_000_000:
        print("error: --window must be in 1..1000000", file=sys.stderr)
        return 2
    if args.no_override and "unlock" in binary.name:
        print("error: --no-override with an agy-unlock launcher will re-inject the override; "
              "point --binary at the underlying agy binary", file=sys.stderr)
        return 2
    auto_cleanup = not bool(args.workdir)
    if args.workdir:
        parent = Path(args.workdir).expanduser().resolve()
        work = parent / f"run-{time.strftime('%Y%m%d-%H%M%S')}"
        work.mkdir(parents=True, exist_ok=False)
    else:
        work = Path(tempfile.mkdtemp(prefix="agy-unlock-verify-"))
    log = work / "run.log"
    try:
        override = None if args.no_override else args.window
        rc = 0
        if args.mode == "stream":
            cid, rc = run_stream(binary, args.model, args.turns, args.turn_bytes, log,
                                 args.proxy or None, override, args.timeout, work)
        else:
            files = make_chunks(work, args.files)
            print(f"[i] filler: {len(files)} files x ~400KB in {work}")
            rc = run_agy(binary, args.model, files, log, args.proxy or None, override, args.timeout)
            cid = conversation_id(log)
        if rc != 0 and not args.allow_failure:
            print(f"error: agy exited rc={rc}; use --allow-failure to inspect anyway", file=sys.stderr)
            return 4
        if not cid:
            print("error: could not find conversation id in the log", file=sys.stderr)
            return 3
        db = CONV_DIR / f"{cid}.db"
        print(f"[i] conversation: {cid}")
        rows = read_session(db)
        s = summarize(rows)
        print("\n[result]")
        print(f"  rows              : {s['rows']}")
        print(f"  models            : {s['models']}")
        print(f"  max estimated     : {s['max_tokens']:,} tokens")
        print(f"  entries > 256000  : {s['over_256k']}")
        print(f"  MAX_TOKEN_LIMIT   : {s['compactions'] or 'none'}")
        passed = s["max_tokens"] > 256_000 and not any(t <= 256_000 for _, t in s["compactions"])
        early = [c for c in s["compactions"] if c[1] <= 256_000]
        print(f"  early (<=256K)    : {early or 'none'}")
        print(f"  verdict           : {'PASS (>256K reached, no early compaction)' if passed else 'FAIL'}")
        if not auto_cleanup:
            print(f"[i] workdir kept: {work}")
        elif args.keep:
            print(f"[i] kept temp workdir: {work}")
        return 0 if passed else 1
    finally:
        # Only remove a directory this tool created itself.
        if auto_cleanup and not args.keep:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
