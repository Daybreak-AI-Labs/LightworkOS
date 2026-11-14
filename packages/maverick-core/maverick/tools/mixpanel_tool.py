"""Mixpanel tool — track + people + read API.

Auth:
  - ``MIXPANEL_PROJECT_TOKEN`` (for `/track` / `/engage` — safe in clients)
  - ``MIXPANEL_SERVICE_USERNAME`` + ``MIXPANEL_SERVICE_SECRET`` (for read API)
  - ``MIXPANEL_PROJECT_ID`` for read API URLs

ops:
  - track(event, distinct_id, properties)
  - people_set(distinct_id, properties)
  - segmentation(event, from_date, to_date, unit)
"""
from __future__ import annotations

import base64
import json
import logging
import os
from typing import Any

from ..fastjson import dumps_compact
from ..governed_http import guarded_sender as _governed_sender
from . import Tool

log = logging.getLogger(__name__)


_MP_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["track", "people_set", "segmentation"],
        },
        "event": {"type": "string"},
        "distinct_id": {"type": "string"},
        "properties": {"type": "object"},
        "from_date": {"type": "string", "description": "YYYY-MM-DD"},
        "to_date": {"type": "string"},
        "unit": {"type": "string", "enum": ["minute", "hour", "day", "week", "month"]},
    },
    "required": ["op"],
}


def _token() -> str:
    t = os.environ.get("MIXPANEL_PROJECT_TOKEN", "").strip()
    if not t:
        raise RuntimeError("Mixpanel track/engage require MIXPANEL_PROJECT_TOKEN.")
    return t


def _service_auth() -> dict[str, str]:
    user = os.environ.get("MIXPANEL_SERVICE_USERNAME", "").strip()
    secret = os.environ.get("MIXPANEL_SERVICE_SECRET", "").strip()
    pid = os.environ.get("MIXPANEL_PROJECT_ID", "").strip()
    if not user or not secret or not pid:
        raise RuntimeError(
            "Read ops require MIXPANEL_SERVICE_USERNAME + "
            "MIXPANEL_SERVICE_SECRET + MIXPANEL_PROJECT_ID."
        )
    raw = f"{user}:{secret}".encode("ascii")
    return {
        "Authorization": "Basic " + base64.b64encode(raw).decode("ascii"),
        "Accept": "application/json",
    }


def _op_track(args: dict) -> str:
    import httpx
    event = (args.get("event") or "").strip()
    did = (args.get("distinct_id") or "").strip()
    if not event or not did:
        return "ERROR: track requires event and distinct_id"
    payload = {
        "event": event,
        # The project token and distinct_id are applied last so caller
        # properties cannot redirect the event to another project or person.
        "properties": {
            **(args.get("properties") or {}),
            "token": _token(),
            "distinct_id": did,
        },
    }
    r = _governed_sender(httpx.post)(
        "https://api.mixpanel.com/track",
        data={"data": base64.b64encode(json.dumps(payload).encode()).decode()},
        timeout=15.0,
    )
    if r.status_code >= 400:
        return f"ERROR: track ({r.status_code}): {r.text[:300]}"
    return f"tracked {event!r} for {did} ({r.text})"


def _op_people_set(args: dict) -> str:
    import httpx
    did = (args.get("distinct_id") or "").strip()
    props = args.get("properties") if isinstance(args.get("properties"), dict) else None
    if not did or not props:
        return "ERROR: people_set requires distinct_id and properties"
    payload = {
        "$token": _token(),
        "$distinct_id": did,
        "$set": props,
    }
    r = _governed_sender(httpx.post)(
        "https://api.mixpanel.com/engage",
        data={"data": base64.b64encode(json.dumps(payload).encode()).decode()},
        timeout=15.0,
    )
    if r.status_code >= 400:
        return f"ERROR: people_set ({r.status_code}): {r.text[:300]}"
    return f"people.set for {did}"


def _op_segmentation(args: dict) -> str:
    import httpx
    event = (args.get("event") or "").strip()
    fd = (args.get("from_date") or "").strip()
    td = (args.get("to_date") or "").strip()
    if not event or not fd or not td:
        return "ERROR: segmentation requires event, from_date, to_date"
    pid = os.environ.get("MIXPANEL_PROJECT_ID", "").strip()
    r = _governed_sender(httpx.get)(
        "https://mixpanel.com/api/2.0/segmentation",
        headers=_service_auth(),
        params={
            "project_id": pid, "event": event,
            "from_date": fd, "to_date": td,
            "unit": args.get("unit") or "day",
        }, timeout=30.0,
    )
    if r.status_code >= 400:
        return f"ERROR: segmentation ({r.status_code}): {r.text[:300]}"
    try:
        data = r.json()
    except ValueError:
        return r.text[:1000]
    return dumps_compact(data)[:3000]


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
            "track":         _op_track,
            "people_set":    _op_people_set,
            "segmentation":  _op_segmentation,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Mixpanel request failed: {type(e).__name__}: {e}"


def mixpanel_tool() -> Tool:
    return Tool(
        name="mixpanel",
        description=(
            "Mixpanel events + people + segmentation. ops: track "
            "(event + distinct_id + properties; needs "
            "MIXPANEL_PROJECT_TOKEN), people_set (distinct_id + "
            "properties), segmentation (read; needs service "
            "account + project id). "
        ),
        input_schema=_MP_SCHEMA,
        fn=_run,
    )
