"""Datadog tool — events, metrics, monitor status.

Auth:
  - ``DATADOG_API_KEY`` (required for all ops)
  - ``DATADOG_APP_KEY`` (required for read ops: monitors, slos)
  - ``DATADOG_SITE`` (default ``datadoghq.com``; use ``datadoghq.eu``
    or other regional sites as needed)

ops:
  - submit_event(title, text, alert_type, tags)
  - submit_metric(metric, value, tags)
  - monitors(limit, name)
  - monitor_get(monitor_id)
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool

log = logging.getLogger(__name__)


_DD_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["submit_event", "submit_metric",
                     "monitors", "monitor_get"],
        },
        "title": {"type": "string"},
        "text": {"type": "string"},
        "alert_type": {"type": "string", "enum": ["info", "warning", "error", "success"]},
        "tags": {"type": "array", "items": {"type": "string"}},
        "metric": {"type": "string"},
        "value": {"type": "number"},
        "limit": {"type": "integer"},
        "name": {"type": "string"},
        "monitor_id": {"type": "integer"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


def _site() -> str:
    return os.environ.get("DATADOG_SITE", "datadoghq.com").strip()


def _api_key() -> str:
    k = os.environ.get("DATADOG_API_KEY", "").strip()
    if not k:
        raise RuntimeError("Datadog requires DATADOG_API_KEY.")
    return k


def _app_key() -> str:
    k = os.environ.get("DATADOG_APP_KEY", "").strip()
    if not k:
        raise RuntimeError("Read ops require DATADOG_APP_KEY (in addition to DATADOG_API_KEY).")
    return k


def _post(path: str, body: dict, app: bool = False) -> tuple[int, Any]:
    import httpx
    headers = {"DD-API-KEY": _api_key(), "Content-Type": "application/json"}
    if app:
        headers["DD-APPLICATION-KEY"] = _app_key()
    r = _governed_sender(httpx.post)(f"https://api.{_site()}{path}", headers=headers,
                   json=body, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _get(path: str, params: dict | None = None) -> tuple[int, Any]:
    import httpx
    headers = {"DD-API-KEY": _api_key(), "DD-APPLICATION-KEY": _app_key()}
    r = _governed_sender(httpx.get)(f"https://api.{_site()}{path}", headers=headers,
                  params=params or {}, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _op_submit_event(args: dict) -> str:
    title = (args.get("title") or "").strip()
    text = (args.get("text") or "").strip()
    if not title or not text:
        return "ERROR: submit_event requires title and text"
    if not as_bool(args.get("confirm")):
        return "DRY RUN: would submit Datadog event. Re-run with confirm=true."
    body = {
        "title": title,
        "text": text,
        "alert_type": (args.get("alert_type") or "info").lower(),
        "tags": [str(t) for t in (args.get("tags") or [])],
    }
    code, data = _post("/api/v1/events", body)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: submit_event ({code}): {data}"
    return f"event id={data.get('event', {}).get('id') or data.get('id', '?')}"


def _op_submit_metric(args: dict) -> str:
    metric = (args.get("metric") or "").strip()
    if not metric or "value" not in args:
        return "ERROR: submit_metric requires metric and value"
    if not as_bool(args.get("confirm")):
        return "DRY RUN: would submit Datadog metric. Re-run with confirm=true."
    body = {"series": [{
        "metric": metric,
        "type": 3,  # gauge
        # v2 /api/v2/series requires point objects, not the v1 [ts, val]
        # array form -- the array shape 400s against the v2 endpoint.
        "points": [{
            "timestamp": int(time.time()),
            "value": float(args.get("value")),
        }],
        "tags": [str(t) for t in (args.get("tags") or [])],
    }]}
    code, data = _post("/api/v2/series", body)
    if code >= 400:
        return f"ERROR: submit_metric ({code}): {data}"
    return f"submitted {metric}"


def _op_monitors(args: dict) -> str:
    limit = max(1, min(int(args.get("limit") or 25), 100))
    name = (args.get("name") or "").strip()
    if name:
        # /api/v1/monitor has no `name` filter -- it'd be silently ignored,
        # returning every monitor. /api/v1/monitor/search supports
        # `query=name:...` and returns the matches under a `monitors` key
        # (a dict) rather than the bare list the plain list endpoint returns.
        code, data = _get(
            "/api/v1/monitor/search",
            {"query": f"name:{name}", "per_page": limit},
        )
        if code >= 400 or not isinstance(data, dict):
            return f"ERROR: monitors ({code}): {data}"
        monitors = data.get("monitors") or []
    else:
        code, data = _get("/api/v1/monitor", {"page_size": limit})
        if code >= 400 or not isinstance(data, list):
            return f"ERROR: monitors ({code}): {data}"
        monitors = data
    if not monitors:
        return "no monitors"
    return "\n".join(
        f"  {m.get('id') or '?'!s:>10}  [{m.get('overall_state', '?'):>4}]  "
        f"{(m.get('name') or '')[:80]}"
        for m in monitors
    )


def _op_monitor_get(args: dict) -> str:
    mid = int(args.get("monitor_id") or 0)
    if not mid:
        return "ERROR: monitor_get requires monitor_id"
    code, data = _get(f"/api/v1/monitor/{mid}")
    if code == 404:
        return f"monitor {mid} not found"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: monitor_get ({code}): {data}"
    return (
        f"#{data.get('id')}  state={data.get('overall_state')}\n"
        f"  name:    {data.get('name')}\n"
        f"  type:    {data.get('type')}\n"
        f"  message: {(data.get('message') or '')[:300]}\n"
        f"  tags:    {data.get('tags')}\n"
        f"  query:   {(data.get('query') or '')[:300]}"
    )


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    try:
        if op == "submit_event":
            return _op_submit_event(args)
        if op == "submit_metric":
            return _op_submit_metric(args)
        if op == "monitors":
            return _op_monitors(args)
        if op == "monitor_get":
            return _op_monitor_get(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Datadog request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def datadog_tool() -> Tool:
    return Tool(
        name="datadog",
        description=(
            "Datadog events + metrics + monitors. ops: submit_event "
            "(title + text + alert_type + tags, confirm=true), submit_metric "
            "(metric + value + tags, confirm=true), monitors (list), monitor_get. "
            "Auth: DATADOG_API_KEY (+ DATADOG_APP_KEY for reads). "
            "DATADOG_SITE overrides region."
        ),
        input_schema=_DD_SCHEMA,
        fn=_run,
    )
