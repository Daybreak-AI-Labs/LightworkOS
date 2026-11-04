"""Home Assistant tool — IoT control.

Talks to a Home Assistant instance over its REST API.

Auth:
  - ``HASS_URL`` (e.g. http://homeassistant.local:8123)
  - ``HASS_TOKEN`` (long-lived access token, Profile → Security)

ops:
  - states(domain)                          — list entity states (optional domain filter)
  - state_get(entity_id)
  - call_service(domain, service, data, confirm)
  - history(entity_id, hours)
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool

log = logging.getLogger(__name__)


_HASS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["states", "state_get", "call_service", "history"],
        },
        "domain": {"type": "string"},
        "service": {"type": "string"},
        "data": {"type": "object"},
        "entity_id": {"type": "string"},
        "hours": {"type": "number"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


def _config() -> tuple[str, str]:
    url = os.environ.get("HASS_URL", "").strip().rstrip("/")
    tok = os.environ.get("HASS_TOKEN", "").strip()
    if not url or not tok:
        raise RuntimeError("Home Assistant requires HASS_URL + HASS_TOKEN.")
    return url, tok


def _headers() -> dict[str, str]:
    _u, tok = _config()
    return {"Authorization": f"Bearer {tok}",
            "Content-Type": "application/json"}


def _get(path: str) -> tuple[int, Any]:
    import httpx
    url, _ = _config()
    r = _governed_sender(httpx.get)(f"{url}{path}", headers=_headers(), timeout=15.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _post(path: str, body: dict) -> tuple[int, Any]:
    import httpx
    url, _ = _config()
    r = _governed_sender(httpx.post)(f"{url}{path}", headers=_headers(),
                   json=body, timeout=15.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _op_states(args: dict) -> str:
    code, data = _get("/api/states")
    if code >= 400 or not isinstance(data, list):
        return f"ERROR: states ({code}): {data}"
    domain = (args.get("domain") or "").strip()
    rows = [d for d in data if not domain or d.get("entity_id", "").startswith(domain + ".")]
    if not rows:
        return f"no entities (domain={domain or '*'})"
    return "\n".join(
        f"  {e.get('entity_id'):<40}  {e.get('state', '?'):<12}  "
        f"{(e.get('attributes') or {}).get('friendly_name', '')[:40]}"
        for e in rows[:200]
    )


def _safe_seg(s: str) -> bool:
    """HA entity_ids / domains / services are [A-Za-z0-9_.-]; reject slashes
    and '..' so a value can't traverse the REST API path."""
    return bool(s) and ".." not in s and all(c.isalnum() or c in "_.-" for c in s)


def _op_state_get(args: dict) -> str:
    eid = (args.get("entity_id") or "").strip()
    if not _safe_seg(eid):
        return "ERROR: state_get requires a valid entity_id"
    code, data = _get(f"/api/states/{eid}")
    if code == 404:
        return f"entity {eid} not found"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: state_get ({code}): {data}"
    attrs = data.get("attributes") or {}
    return (
        f"{data.get('entity_id')}  state={data.get('state')}\n"
        f"  last_changed:  {data.get('last_changed')}\n"
        f"  last_updated:  {data.get('last_updated')}\n"
        f"  attributes:    {json.dumps(attrs, default=str)[:500]}"
    )


def _op_call_service(args: dict) -> str:
    domain = (args.get("domain") or "").strip()
    service = (args.get("service") or "").strip()
    if not _safe_seg(domain) or not _safe_seg(service):
        return "ERROR: call_service requires a valid domain and service"
    if not as_bool(args.get("confirm")):
        return (
            f"DRY RUN: would call {domain}.{service}. "
            "Re-run with confirm=true."
        )
    data = args.get("data") if isinstance(args.get("data"), dict) else {}
    code, body = _post(f"/api/services/{domain}/{service}", data)
    if code >= 400:
        return f"ERROR: call_service ({code}): {body}"
    affected = body if isinstance(body, list) else [body]
    return f"called {domain}.{service} ({len(affected)} state(s) changed)"


def _op_history(args: dict) -> str:
    eid = (args.get("entity_id") or "").strip()
    if not _safe_seg(eid):
        return "ERROR: history requires a valid entity_id"
    # Honor the advertised ``hours`` window: HA takes the window START as a path
    # timestamp (it otherwise defaults to the last 24h), so the documented
    # parameter takes effect.
    try:
        hours = max(1, int(args.get("hours") or 24))
    except (TypeError, ValueError):
        hours = 24
    from datetime import datetime, timedelta, timezone
    from urllib.parse import quote
    start = quote(
        (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat())
    code, data = _get(f"/api/history/period/{start}?filter_entity_id={eid}")
    if code >= 400 or not isinstance(data, list):
        return f"ERROR: history ({code}): {data}"
    series = data[0] if data else []
    if not series:
        return "no history"
    return "\n".join(
        f"  {s.get('last_changed')}  {s.get('state', '?')}"
        for s in series[-min(len(series), 100):]
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
            "states":       _op_states,
            "state_get":    _op_state_get,
            "call_service": _op_call_service,
            "history":      _op_history,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Home Assistant request failed: {type(e).__name__}: {e}"


def home_assistant_tool() -> Tool:
    return Tool(
        name="home_assistant",
        description=(
            "Home Assistant IoT. ops: states (optional domain "
            "filter), state_get, call_service (domain + service + "
            "data; confirm=true required), history. Auth: HASS_URL "
            "+ HASS_TOKEN."
        ),
        input_schema=_HASS_SCHEMA,
        fn=_run,
    )
