"""Replicate tool — run hosted ML models (image/video/audio gen).

Auth: ``REPLICATE_API_TOKEN``.

ops:
  - run(model, input, wait)            — create a prediction; wait polls to completion
  - predict_get(prediction_id)
  - cancel(prediction_id, confirm)
  - models(query)                      — search the model catalog

``model`` is "owner/name" or "owner/name:version". When no version is
given we resolve the latest version automatically.
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool, safe_path_segment

log = logging.getLogger(__name__)


_RP_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["run", "predict_get", "cancel", "models"]},
        "model": {"type": "string"},
        "input": {"type": "object"},
        "wait": {"type": "boolean", "description": "Poll until terminal (run op)."},
        "prediction_id": {"type": "string"},
        "query": {"type": "string"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


_API = "https://api.replicate.com/v1"


def _token() -> str:
    t = os.environ.get("REPLICATE_API_TOKEN", "").strip()
    if not t:
        raise RuntimeError("Replicate requires REPLICATE_API_TOKEN.")
    return t


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {_token()}",
            "Content-Type": "application/json"}


def _get(path: str, params: dict | None = None) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.get)(f"{_API}{path}", headers=_headers(),
                  params=params or {}, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _post(path: str, body: dict) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.post)(f"{_API}{path}", headers=_headers(), json=body, timeout=60.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _resolve_version(model: str) -> str | None:
    if ":" in model:
        return model.split(":", 1)[1]
    code, data = _get(f"/models/{model}")
    if code >= 400 or not isinstance(data, dict):
        return None
    vid = (data.get("latest_version") or {}).get("id")
    if vid:
        return vid
    # Some models don't expose latest_version on the model object;
    # fall back to the /versions list and take the most recent.
    c2, d2 = _get(f"/models/{model}/versions")
    if c2 >= 400 or not isinstance(d2, dict):
        return None
    results = d2.get("results") or []
    return results[0].get("id") if results else None


def _fmt_prediction(p: dict) -> str:
    out = p.get("output")
    out_str = json.dumps(out, default=str)[:1500] if out is not None else "(none)"
    return (
        f"id:     {p.get('id')}\n"
        f"status: {p.get('status')}\n"
        f"error:  {p.get('error') or '(none)'}\n"
        f"output: {out_str}"
    )


def _op_run(args: dict) -> str:
    model = (args.get("model") or "").strip()
    if not model:
        return "ERROR: run requires model"
    # owner/name[:version] -- reject anything that could traverse to a
    # different API path (model is interpolated into /models/{model}).
    owner_name = model.split(":", 1)[0]
    parts = owner_name.split("/")
    if (len(parts) != 2 or not all(parts) or ".." in owner_name
            or not all(c.isalnum() or c in "_.-" for p in parts for c in p)):
        return f"ERROR: invalid model {model!r} (expected owner/name[:version])"
    inp = args.get("input") if isinstance(args.get("input"), dict) else {}
    version = _resolve_version(model)
    if not version:
        return f"ERROR: could not resolve version for model {model!r}"
    code, data = _post("/predictions", {"version": version, "input": inp})
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: run ({code}): {data}"
    pid = data.get("id")
    if not args.get("wait"):
        return f"created prediction {pid} (status={data.get('status')})"
    # Poll up to ~90s.
    deadline = time.time() + 90
    while time.time() < deadline:
        c2, p2 = _get(f"/predictions/{pid}")
        if c2 >= 400 or not isinstance(p2, dict):
            return f"ERROR: poll ({c2}): {p2}"
        if p2.get("status") in ("succeeded", "failed", "canceled"):
            return _fmt_prediction(p2)
        time.sleep(2)
    return f"prediction {pid} still running after 90s; use predict_get to poll"


def _op_predict_get(args: dict) -> str:
    pid = (args.get("prediction_id") or "").strip()
    if not pid:
        return "ERROR: predict_get requires prediction_id"
    seg = safe_path_segment(pid)
    if seg is None:
        return "ERROR: predict_get requires a valid prediction_id"
    code, data = _get(f"/predictions/{seg}")
    if code == 404:
        return f"prediction {pid} not found"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: predict_get ({code}): {data}"
    return _fmt_prediction(data)


def _op_cancel(args: dict) -> str:
    pid = (args.get("prediction_id") or "").strip()
    if not pid:
        return "ERROR: cancel requires prediction_id"
    seg = safe_path_segment(pid)
    if seg is None:
        return "ERROR: cancel requires a valid prediction_id"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would cancel {pid}. Re-run with confirm=true."
    code, data = _post(f"/predictions/{seg}/cancel", {})
    if code >= 400:
        return f"ERROR: cancel ({code}): {data}"
    return f"cancelled {pid}"


def _op_models(args: dict) -> str:
    import httpx
    q = (args.get("query") or "").strip()
    if not q:
        return "ERROR: models requires query"
    # Replicate's catalog search is the HTTP QUERY method with the
    # plaintext search string as the body — GET /models is the
    # (unfiltered) list endpoint and ignores any query param, so it
    # would silently return the whole catalog instead of matches.
    r = httpx.request(
        "QUERY", f"{_API}/models",
        headers={"Authorization": f"Bearer {_token()}",
                 "Content-Type": "text/plain"},
        content=q, timeout=30.0,
    )
    code = r.status_code
    try:
        data = r.json()
    except ValueError:
        data = r.text[:300]
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: models ({code}): {data}"
    rows = data.get("results") or []
    if not rows:
        return "no models"
    return "\n".join(
        f"  {m.get('owner')}/{m.get('name')}  "
        f"{(m.get('description') or '')[:60]}"
        for m in rows[:25]
    )


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed."
    try:
        return {
            "run":         _op_run,
            "predict_get": _op_predict_get,
            "cancel":      _op_cancel,
            "models":      _op_models,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Replicate request failed: {type(e).__name__}: {e}"


def replicate_tool() -> Tool:
    return Tool(
        name="replicate",
        description=(
            "Replicate hosted ML models. ops: run (model + input "
            "[+wait to poll]), predict_get, cancel (confirm=true), "
            "models (catalog search). model = 'owner/name[:version]'. "
            "Auth: REPLICATE_API_TOKEN."
        ),
        input_schema=_RP_SCHEMA,
        fn=_run,
    )
