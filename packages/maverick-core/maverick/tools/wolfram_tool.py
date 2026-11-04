"""Wolfram Alpha tool — computational knowledge queries.

Auth: ``WOLFRAM_APP_ID`` (developer.wolframalpha.com).

ops:
  - short(query)        — Short Answers API (one-line result)
  - full(query)         — Full Results API (pods, flattened to text)
  - spoken(query)       — Spoken Results API (conversational phrasing)
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..governed_http import guarded_redirect_get
from ..governed_http import guarded_sender as _governed_sender
from . import Tool

log = logging.getLogger(__name__)


_WA_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["short", "full", "spoken"]},
        "query": {"type": "string"},
    },
    "required": ["op", "query"],
}


def _app_id() -> str:
    a = os.environ.get("WOLFRAM_APP_ID", "").strip()
    if not a:
        raise RuntimeError("Wolfram Alpha requires WOLFRAM_APP_ID.")
    return a


def _get_text(url: str, params: dict) -> tuple[int, str]:
    import httpx
    r = guarded_redirect_get(httpx.get)(url, params={**params, "appid": _app_id()},
                                       timeout=30.0, follow_redirects=True)
    return r.status_code, r.text


def _op_short(query: str) -> str:
    code, text = _get_text("https://api.wolframalpha.com/v1/result",
                           {"i": query})
    if code == 501:
        return "no short answer available (try op=full)"
    if code >= 400:
        return f"ERROR: short ({code}): {text[:200]}"
    return text.strip()


def _op_spoken(query: str) -> str:
    code, text = _get_text("https://api.wolframalpha.com/v1/spoken",
                           {"i": query})
    if code == 501:
        return "no spoken answer available"
    if code >= 400:
        return f"ERROR: spoken ({code}): {text[:200]}"
    return text.strip()


def _op_full(query: str) -> str:
    import httpx
    r = _governed_sender(httpx.get)(
        "https://api.wolframalpha.com/v2/query",
        params={"input": query, "appid": _app_id(), "output": "json"},
        timeout=30.0,
    )
    if r.status_code >= 400:
        return f"ERROR: full ({r.status_code}): {r.text[:200]}"
    try:
        data = r.json()
    except ValueError:
        return r.text[:1000]
    qr = data.get("queryresult") or {}
    if not qr.get("success"):
        return "no result (query not understood)"
    pods = qr.get("pods") or []
    out = []
    for pod in pods:
        title = pod.get("title", "?")
        subs = pod.get("subpods") or []
        texts = [s.get("plaintext", "") for s in subs if s.get("plaintext")]
        if texts:
            out.append(f"  [{title}] " + " | ".join(texts)[:200])
    return "\n".join(out) or "(no textual pods)"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    query = (args.get("query") or "").strip()
    if not query:
        return "ERROR: query is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed."
    try:
        if op == "short":
            return _op_short(query)
        if op == "spoken":
            return _op_spoken(query)
        if op == "full":
            return _op_full(query)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Wolfram request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def wolfram_tool() -> Tool:
    return Tool(
        name="wolfram",
        description=(
            "Wolfram Alpha computational knowledge. ops: short "
            "(one-line answer), full (all result pods), spoken "
            "(conversational phrasing). Auth: WOLFRAM_APP_ID."
        ),
        input_schema=_WA_SCHEMA,
        fn=_run,
    )
