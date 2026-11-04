"""Google Analytics 4 tool — Data API + Measurement Protocol.

Read ops use the Data API v1 (service-account access token, refreshed
externally — same pattern as Salesforce / Spotify).
Write op uses the Measurement Protocol (event ingestion, no OAuth).

Auth:
  - Read: ``GA4_ACCESS_TOKEN`` + ``GA4_PROPERTY_ID``
  - Write: ``GA4_MEASUREMENT_ID`` + ``GA4_API_SECRET``

ops:
  - run_report(start_date, end_date, dimensions, metrics)
  - realtime(metrics)
  - send_event(client_id, name, params)
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool

log = logging.getLogger(__name__)


_GA4_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["run_report", "realtime", "send_event"]},
        "start_date": {"type": "string"},
        "end_date": {"type": "string"},
        "dimensions": {"type": "array", "items": {"type": "string"}},
        "metrics": {"type": "array", "items": {"type": "string"}},
        "client_id": {"type": "string"},
        "name": {"type": "string"},
        "params": {"type": "object"},
    },
    "required": ["op"],
}


def _read_config() -> tuple[str, str]:
    tok = os.environ.get("GA4_ACCESS_TOKEN", "").strip()
    pid = os.environ.get("GA4_PROPERTY_ID", "").strip()
    if not tok or not pid:
        raise RuntimeError(
            "GA4 read ops require GA4_ACCESS_TOKEN + GA4_PROPERTY_ID."
        )
    return tok, pid


def _measurement_config() -> tuple[str, str]:
    mid = os.environ.get("GA4_MEASUREMENT_ID", "").strip()
    sec = os.environ.get("GA4_API_SECRET", "").strip()
    if not mid or not sec:
        raise RuntimeError(
            "GA4 send_event requires GA4_MEASUREMENT_ID + GA4_API_SECRET."
        )
    return mid, sec


def _op_run_report(args: dict) -> str:
    import httpx
    tok, pid = _read_config()
    body = {
        "dateRanges": [{
            "startDate": args.get("start_date") or "7daysAgo",
            "endDate":   args.get("end_date") or "today",
        }],
        "dimensions": [{"name": d} for d in (args.get("dimensions") or ["country"])],
        "metrics":    [{"name": m} for m in (args.get("metrics") or ["activeUsers"])],
    }
    r = _governed_sender(httpx.post)(
        f"https://analyticsdata.googleapis.com/v1beta/properties/{pid}:runReport",
        headers={"Authorization": f"Bearer {tok}",
                 "Content-Type": "application/json"},
        json=body, timeout=30.0,
    )
    if r.status_code >= 400:
        return f"ERROR: run_report ({r.status_code}): {r.text[:300]}"
    try:
        data = r.json()
    except ValueError:
        return f"ERROR: run_report: non-JSON response: {r.text[:300]}"
    rows = data.get("rows") or []
    if not rows:
        return "no rows"
    out = []
    for row in rows[:50]:
        dims = [d.get("value", "?") for d in (row.get("dimensionValues") or [])]
        mets = [m.get("value", "?") for m in (row.get("metricValues") or [])]
        out.append(f"  {' / '.join(dims)}  -> {' '.join(mets)}")
    return "\n".join(out)


def _op_realtime(args: dict) -> str:
    import httpx
    tok, pid = _read_config()
    body = {
        "metrics": [{"name": m} for m in (args.get("metrics") or ["activeUsers"])],
    }
    r = _governed_sender(httpx.post)(
        f"https://analyticsdata.googleapis.com/v1beta/properties/{pid}:runRealtimeReport",
        headers={"Authorization": f"Bearer {tok}",
                 "Content-Type": "application/json"},
        json=body, timeout=15.0,
    )
    if r.status_code >= 400:
        return f"ERROR: realtime ({r.status_code}): {r.text[:300]}"
    try:
        data = r.json()
    except ValueError:
        return f"ERROR: realtime: non-JSON response: {r.text[:300]}"
    rows = data.get("rows") or []
    if not rows:
        return "no realtime users"
    return "\n".join(
        " ".join(m.get("value", "?") for m in (row.get("metricValues") or []))
        for row in rows
    )


def _op_send_event(args: dict) -> str:
    import httpx
    mid, sec = _measurement_config()
    client_id = (args.get("client_id") or "").strip()
    name = (args.get("name") or "").strip()
    if not client_id or not name:
        return "ERROR: send_event requires client_id and name"
    body = {
        "client_id": client_id,
        "events": [{
            "name": name,
            "params": args.get("params") if isinstance(args.get("params"), dict) else {},
        }],
    }
    r = _governed_sender(httpx.post)(
        "https://www.google-analytics.com/mp/collect",
        params={"measurement_id": mid, "api_secret": sec},
        json=body, timeout=15.0,
    )
    if r.status_code >= 400:
        return f"ERROR: send_event ({r.status_code}): {r.text[:300]}"
    return f"event {name!r} accepted for client {client_id}"


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
            "run_report": _op_run_report,
            "realtime":   _op_realtime,
            "send_event": _op_send_event,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: GA4 request failed: {type(e).__name__}: {e}"


def ga4_tool() -> Tool:
    return Tool(
        name="ga4",
        description=(
            "Google Analytics 4. ops: run_report (dimensions + "
            "metrics + date range), realtime (active-users style), "
            "send_event (Measurement Protocol). Read auth: "
            "GA4_ACCESS_TOKEN + GA4_PROPERTY_ID. Write auth: "
            "GA4_MEASUREMENT_ID + GA4_API_SECRET."
        ),
        input_schema=_GA4_SCHEMA,
        fn=_run,
    )
