"""Redacting mitmproxy addon: capture only request/response *shape*, key trees, and token usage.

Never writes message text, tool output, file content, or auth headers.
Performs full-depth recursive key scanning and normalizes string-typed numeric policy values.
"""
import json
import os
import re
import time

from mitmproxy import http

OUT = os.environ.get("CAPTURE_OUT", "/tmp/agy-tls-capture.jsonl")
ALLOW = ("streamGenerateContent", "generateContent", "fetchAvailableModels")
MAX_NODES = 500000

CONFIG_TARGET_NORM = {
    "checkpointconfig",
    "cascadeconfig",
    "maxtokenlimit",
    "contextwindow",
    "maxcontexttokens",
    "autocompact",
    "contextwindowcompression",
}


def _norm_key(k: str) -> str:
    return re.sub(r"[^a-z0-9]", "", k.lower())


def _coerce_num(v):
    if isinstance(v, (int, float, bool)):
        return v
    if isinstance(v, str):
        s = v.strip()
        if re.fullmatch(r"-?\d+", s):
            return int(s)
        if re.fullmatch(r"-?\d+\.\d+", s):
            return float(s)
    return None


def _write(rec):
    parent = os.path.dirname(os.path.abspath(OUT))
    if parent:
        os.makedirs(parent, exist_ok=True)
    line = json.dumps(rec, ensure_ascii=False, sort_keys=True)
    with open(OUT, "a") as fh:
        fh.write(line + "\n")
    os.chmod(OUT, 0o600)


def _find_full(obj, path="", out=None, budget=None):
    """Full-depth, full-array scan for any checkpoint/context-window config key."""
    if out is None:
        out = []
    if budget is None:
        budget = [MAX_NODES]
    budget[0] -= 1
    if budget[0] <= 0:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}" if path else k
            if _norm_key(k) in CONFIG_TARGET_NORM:
                num = _coerce_num(v)
                out.append({
                    "path": p,
                    "key": k,
                    "value": num if num is not None else f"<{type(v).__name__}>",
                })
            if isinstance(v, (dict, list)):
                _find_full(v, p, out, budget)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, (dict, list)):
                _find_full(v, f"{path}[{i}]", out, budget)
    return out


def _key_tree_full(obj, out=None, budget=None):
    """Collect all dict key names across the entire JSON tree (no depth/array truncation)."""
    if out is None:
        out = set()
    if budget is None:
        budget = [MAX_NODES]
    budget[0] -= 1
    if budget[0] <= 0:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.add(k)
            if isinstance(v, (dict, list)):
                _key_tree_full(v, out, budget)
    elif isinstance(obj, list):
        for v in obj:
            if isinstance(v, (dict, list)):
                _key_tree_full(v, out, budget)
    return out


def _summarize_models(obj):
    models = obj.get("models") if isinstance(obj, dict) else None
    if not isinstance(models, dict):
        return None
    out = []
    for mid, v in models.items():
        mi = v.get("modelInfo", v) if isinstance(v, dict) else {}
        ex = (mi.get("modelExperiments") or {}).get("experiments") or {}
        cp = None
        for k, e in ex.items():
            if k.startswith("CASCADE_USE_EXPERIMENT_CHECKPOINTER") and isinstance(e, dict):
                sv = e.get("stringValue")
                if isinstance(sv, str):
                    try:
                        raw_cp = json.loads(sv)
                        cp = {ck: _coerce_num(cv) for ck, cv in raw_cp.items() if _coerce_num(cv) is not None}
                    except Exception:
                        cp = "<unparseable>"
        out.append({
            "id": mid,
            "displayName": mi.get("displayName"),
            "maxTokens": _coerce_num(mi.get("maxTokens")),
            "maxOutputTokens": _coerce_num(mi.get("maxOutputTokens")),
            "checkpoint_policy_numeric": cp,
        })
    return out


def response(flow: http.HTTPFlow):
    if not any(a in flow.request.path for a in ALLOW):
        return
    req_bytes = flow.request.raw_content or b""
    rec = {
        "ts": time.time(),
        "method": flow.request.method,
        "path": flow.request.path,
        "request_bytes": len(req_bytes),
        "status": flow.response.status_code if flow.response else None,
    }
    if req_bytes:
        try:
            req_obj = json.loads(req_bytes)
            if isinstance(req_obj, dict):
                rec["top_keys"] = list(req_obj.keys())
                rec["key_tree"] = sorted(_key_tree_full(req_obj))
                rec["config_matches"] = _find_full(req_obj)
                inner = req_obj.get("request", req_obj)
                if isinstance(inner, dict) and isinstance(inner.get("contents"), list):
                    rec["contents_count"] = len(inner["contents"])
        except Exception:
            rec["request_json_parsed"] = False

    if "fetchAvailableModels" in flow.request.path and flow.response and flow.response.content:
        try:
            m_obj = json.loads(flow.response.content)
            rec["models"] = _summarize_models(m_obj)
        except Exception:
            pass
    _write(rec)
