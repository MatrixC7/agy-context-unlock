#!/usr/bin/env python3
"""Zero-token GDB verification for agy context window resolution.

Starts agy under GDB, records the resolved context window registers inside
backend.(*ServerBackend).buildCascadeConfigInternal, and kills the process just
before the config function returns -- BEFORE any generation request is sent
(0 token cost).

The five breakpoint offsets are derived from the model-gate patch signature, so
the tool does not embed absolute build addresses and keeps working when a minor
agy release shifts the function.

Usage:
  python3 tools/gdb_verify.py --binary /usr/bin/agy
  python3 tools/gdb_verify.py --binary /path/to/agy.patched
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agy_context_unlock as unlock  # noqa: E402

GDB_INNER_SCRIPT = r"""
import gdb, json, os, shlex

out = os.environ['GDB_VERIFY_OUT']
bin_real = os.path.realpath(os.environ['GDB_VERIFY_BIN'])
res = {'events': [], 'status': 'not_started'}

OFF_STRING_LEN = int(os.environ['GDB_VERIFY_OFF_STRING_LEN'], 0)
OFF_LIMIT = int(os.environ['GDB_VERIFY_OFF_LIMIT'], 0)
OFF_PROTO = int(os.environ['GDB_VERIFY_OFF_PROTO'], 0)
OFF_WRITE = int(os.environ['GDB_VERIFY_OFF_WRITE'], 0)
OFF_RETURN = int(os.environ['GDB_VERIFY_OFF_RETURN'], 0)

for c in (
    'set pagination off',
    'set confirm off',
    'set print thread-events off',
    'set auto-load off',
    'handle SIGURG nostop noprint pass',
):
    gdb.execute(c, to_string=True)

args = ['-p', 'Reply OK', '--model', os.environ['GDB_VERIFY_MODEL'], '--log-file', '/dev/null']
gdb.execute('starti ' + shlex.join(args) + ' > /dev/null 2>&1', to_string=True)
pid = gdb.selected_inferior().pid
base = None
with open(f'/proc/{pid}/maps') as f:
    for line in f:
        p = line.split()
        if len(p) >= 6 and p[-1] == bin_real and int(p[2], 16) == 0:
            base = int(p[0].split('-')[0], 16)
            break

if base is None:
    res['status'] = 'no_pie_base'
else:
    res['pie_base'] = hex(base)
    points = {}
    for off in (OFF_STRING_LEN, OFF_LIMIT, OFF_PROTO, OFF_WRITE, OFF_RETURN):
        bp = gdb.Breakpoint(f'*{base + off:#x}', internal=True)
        bp.silent = True
        points[base + off] = off
    while True:
        gdb.execute('continue', to_string=True)
        if not gdb.selected_inferior().pid:
            res['status'] = 'exited_before_config'
            break
        off = points.get(int(gdb.parse_and_eval('$pc')))
        if off == OFF_STRING_LEN:
            res['events'].append({'name': 'CTXWINDOW_STRING_LEN', 'value': int(gdb.parse_and_eval('$rbx'))})
        elif off == OFF_LIMIT:
            res['events'].append({'name': 'CTXWINDOW_LIMIT', 'value': int(gdb.parse_and_eval('$eax'))})
        elif off == OFF_PROTO:
            res['events'].append({'name': 'PROTO_EQUAL', 'value': int(gdb.parse_and_eval('$al'))})
        elif off == OFF_WRITE:
            res['events'].append({'name': 'WRITE_MAXTOKEN', 'value': int(gdb.parse_and_eval('$ecx'))})
        elif off == OFF_RETURN:
            res['events'].append({'name': 'CONFIG_RETURN_BEFORE_REQUEST', 'value': 1})
            gdb.execute('kill', to_string=True)
            res['status'] = 'killed_before_config_return'
            break

with open(out, 'w') as f:
    json.dump(res, f, indent=2)
"""


def main() -> int:
    ap = argparse.ArgumentParser(description="Zero-token GDB verifier for agy context window resolution.")
    ap.add_argument("--binary", default="/usr/bin/agy", help="path to agy binary to test")
    ap.add_argument(
        "--models",
        default="Gemini 4 Argon (High),Gemini 3.8 Flash (High)",
        help="comma-separated model names to test",
    )
    ap.add_argument("--proxy", default=os.environ.get("HTTPS_PROXY", "http://127.0.0.1:2080"))
    ap.add_argument("--override", default="", help="optional AGY_CLI_AUTO_COMPACT_OVERRIDE value (default: unset)")
    args = ap.parse_args()

    binary = Path(args.binary).expanduser().resolve()
    if not binary.exists():
        print(f"error: binary not found: {binary}", file=sys.stderr)
        return 2

    # Locate the model-gate site dynamically.  The other four breakpoints keep a
    # stable relative layout inside buildCascadeConfigInternal:
    #   context-window string length  = site - 0x41
    #   parsed MaxTokenLimit          = site - 0x3c
    #   proto.Equal result            = site
    #   CheckpointConfig write        = site + 0x20
    #   function return point         = site + 0x52
    try:
        u = unlock.Unlocker(binary)
        gate = next(p for p in unlock.PATCHES if p.key == "model-gate")
        _gate_off, gate_va = u.locate_patch(gate)
    except Exception as exc:  # BinaryError, OSError, StopIteration
        print(f"error: cannot locate model-gate in {binary}: {exc}", file=sys.stderr)
        return 2
    offsets = {
        "GDB_VERIFY_OFF_STRING_LEN": gate_va - 0x41,
        "GDB_VERIFY_OFF_LIMIT": gate_va - 0x3c,
        "GDB_VERIFY_OFF_PROTO": gate_va,
        "GDB_VERIFY_OFF_WRITE": gate_va + 0x20,
        "GDB_VERIFY_OFF_RETURN": gate_va + 0x52,
    }

    models = [m.strip() for m in args.models.split(",") if m.strip()]
    with tempfile.TemporaryDirectory(prefix="agy-gdb-verify-") as work:
        script_path = Path(work) / "gdb_inner.py"
        script_path.write_text(GDB_INNER_SCRIPT)

        for model in models:
            out_path = Path(work) / "result.json"
            env = dict(os.environ)
            if args.override:
                env["AGY_CLI_AUTO_COMPACT_OVERRIDE"] = str(args.override)
            else:
                env.pop("AGY_CLI_AUTO_COMPACT_OVERRIDE", None)
            if args.proxy:
                env["HTTPS_PROXY"] = env["HTTP_PROXY"] = args.proxy
                env["https_proxy"] = env["http_proxy"] = args.proxy
            env["GDB_VERIFY_OUT"] = str(out_path)
            env["GDB_VERIFY_BIN"] = str(binary)
            env["GDB_VERIFY_MODEL"] = model
            for key, value in offsets.items():
                env[key] = hex(value)

            subprocess.run(
                [
                    "gdb", "-q", "-nx", "-nh", "-batch",
                    "-ex", f"python import runpy; runpy.run_path({str(script_path)!r})",
                    "--args", str(binary),
                ],
                cwd=work,
                env=env,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            data = json.loads(out_path.read_text())
            print(f"== {model} ==")
            for ev in data.get("events", []):
                print(f"  {ev['name']}={ev['value']}")
            print(f"  status={data.get('status')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
