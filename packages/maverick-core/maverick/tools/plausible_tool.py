"""Plausible Analytics tool — privacy-first events + reads.

Auth:
  - ``PLAUSIBLE_API_KEY`` (read-only Stats API token)
  - ``PLAUSIBLE_SITE_ID`` default site (overridable per-call)
  - ``PLAUSIBLE_HOST`` optional self-hosted host (default plausible.io)

ops:
  - event(site_id, name, url, props)         — send a custom event (no key needed)
  - aggregate(site_id, period, metrics)
  - timeseries(site_id, period)
  - breakdown(site_id, property, period, limit)
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool

log = logging.getLogger(__name__)


_PL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["event", "aggregate", "timeseries", "breakdown"],
        },
        "site_id": {"type": "string"},
        "name": {"type": "string"},
        "url": {"type": "string"},
        "props": {"type": "object"},
        "period": {
            "type": "string",
            "description": "12mo / 6mo / month / 7d / 30d / day / realtime",
        },
        "metrics": {
            "type": "array", "items": {"type": "string"},
            "description": "visitors, pageviews, bounce_rate, visit_duration, ...",
        },
        "property": {"type": "string", "description": "e.g. event:page, visit:source"},
        "limit": {"type": "integer"},
    },
    "required": ["op"],
}


def _host() -> str:
    return os.environ.get("PLAUSIBLE_HOST", "https://plausible.io").rstrip("/")


def _site(arg: str) -> str:
    return (arg or os.environ.get("PLAUSIBLE_SITE_ID") or "").strip()


def _read_key() -> str:
    k = os.environ.get("PLAUSIBLE_API_KEY", "").strip()
    if not k:
        raise RuntimeError("Read ops require PLAUSIBLE_API_KEY.")
    return k


def _op_event(args: dict) -> str:
    import httpx
    site = _site(args.get("site_id") or "")
    if not site:
        return "ERROR: event requires site_id or PLAUSIBLE_SITE_ID"
    name = (args.get("name") or "").strip()
    if not name:
        return "ERROR: event requires name"
    body = {
        "name": name,
        "url": args.get("url") or f"https://{site}/",
        "domain": site,
    }
    if args.get("props"):
        body["props"] = args["props"]
    r = _governed_sender(httpx.post)(f"{_host()}/api/event", json=body,
                   headers={"User-Agent": "maverick-agent"},
                   timeout=15.0)
    if r.status_code >= 400:
        return f"ERROR: event ({r.status_code}): {r.text[:300]}"
    return f"event {name!r} accepted for {site}"


def _stats_get(path: str, params: dict) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.get)(f"{_host()}/api/v1/stats{path}",
                  headers={"Authorization": f"Bearer {_read_key()}"},
                  params=params, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _op_aggregate(args: dict) -> str:
    site = _site(args.get("site_id") or "")
    if not site:
        return "ERROR: aggregate requires site_id"
    metrics = args.get("metrics") or ["visitors", "pageviews"]
    code, data = _stats_get("/aggregate", {
        "site_id": site,
        "period": args.get("period") or "7d",
        "metrics": ",".join(metrics),
    })
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: aggregate ({code}): {data}"
    results = data.get("results") or {}
    return "\n".join(
        f"  {k}: {(v or {}).get('value', '?')}" for k, v in results.items()
    )


def _op_timeseries(args: dict) -> str:
    site = _site(args.get("site_id") or "")
    if not site:
        return "ERROR: timeseries requires site_id"
    code, data = _stats_get("/timeseries", {
        "site_id": site, "period": args.get("period") or "30d",
    })
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: timeseries ({code}): {data}"
    rows = data.get("results") or []
    if not rows:
        return "no data"
    return "\n".join(
        f"  {r.get('date')}  visitors={r.get('visitors')}" for r in rows
    )


def _op_breakdown(args: dict) -> str:
    site = _site(args.get("site_id") or "")
    if not site:
        return "ERROR: breakdown requires site_id"
    prop = (args.get("property") or "event:page").strip()
    code, data = _stats_get("/breakdown", {
        "site_id": site, "period": args.get("period") or "7d",
        "property": prop,
        "limit": max(1, min(int(args.get("limit") or 25), 100)),
    })
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: breakdown ({code}): {data}"
    rows = data.get("results") or []
    if not rows:
        return "no data"
    # Plausible v1 breakdown keys each row by the SHORT property name
    # (e.g. 'page', 'source'), not the full 'event:page' / 'visit:source'
    # passed in the request. Look up the short name or the dimension column
    # is always '?'.
    dim = prop.split(":", 1)[-1]
    return "\n".join(
        f"  visitors={r.get('visitors', '?')!s:>8}  {str(r.get(dim) or '?')[:80]}"
        for r in rows
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
        return {
            "event":      _op_event,
            "aggregate":  _op_aggregate,
            "timeseries": _op_timeseries,
            "breakdown":  _op_breakdown,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Plausible request failed: {type(e).__name__}: {e}"


def plausible_tool() -> Tool:
    return Tool(
        name="plausible",
        description=(
            "Plausible Analytics. ops: event (custom event POST, no "
            "key needed), aggregate, timeseries, breakdown (all read "
            "ops require PLAUSIBLE_API_KEY). PLAUSIBLE_SITE_ID / "
            "PLAUSIBLE_HOST configure default site + self-hosted host."
        ),
        input_schema=_PL_SCHEMA,
        fn=_run,
    )
