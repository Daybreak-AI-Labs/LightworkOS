"""PostHog tool — product analytics events + insights.

Lets the agent capture analytics events ("user X completed task Y"),
identify users, and query stored insights. Useful for:

  - logging from inside a workflow ("ran goal #42 — capture as
    posthog event 'goal_completed' with cost+duration props")
  - reading dashboard insights to inform decisions

ops:
  - capture(event, distinct_id, properties)        — fire an event
  - identify(distinct_id, properties)              — set person props
  - insights(limit)                                — list dashboard insights
  - insight_get(insight_id)                        — fetch one insight + values

Auth:
  - capture / identify use ``POSTHOG_API_KEY`` (project-write key,
    safe in clients).
  - insights / insight_get use ``POSTHOG_PERSONAL_API_KEY`` (read
    scope) + ``POSTHOG_PROJECT_ID``.
  - Self-hosted: ``POSTHOG_HOST`` (default https://us.posthog.com) sets the
    API host; events ingest on the derived ``*.i.posthog.com`` host (override
    with ``POSTHOG_INGESTION_HOST``).
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool

log = logging.getLogger(__name__)


_PH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["capture", "identify", "insights", "insight_get"],
        },
        "event": {"type": "string"},
        "distinct_id": {"type": "string"},
        "properties": {"type": "object"},
        "limit": {"type": "integer"},
        "insight_id": {"type": "integer"},
    },
    "required": ["op"],
}


def _host() -> str:
    """API host (insights/read endpoints): the app host, e.g. us.posthog.com."""
    return os.environ.get("POSTHOG_HOST", "https://us.posthog.com").rstrip("/")


def _ingestion_host() -> str:
    """Event-ingestion host for /capture/.

    PostHog ingests events on a dedicated host (``us.i.posthog.com`` /
    ``eu.i.posthog.com``), distinct from the app/API host. Posting events to
    the app host is the documented wrong endpoint and silently drops them on
    some deployments. Honour an explicit ``POSTHOG_INGESTION_HOST`` first;
    otherwise derive the ingestion host from ``POSTHOG_HOST`` by inserting the
    ``i`` subdomain for the standard cloud regions, falling back to the app
    host itself for self-hosted instances (which ingest on the same host).
    """
    explicit = os.environ.get("POSTHOG_INGESTION_HOST", "").strip()
    if explicit:
        return explicit.rstrip("/")
    host = _host()
    # Legacy single-region cloud host -> US ingestion.
    if host == "https://app.posthog.com":
        return "https://us.i.posthog.com"
    for region in ("us", "eu"):
        if host == f"https://{region}.posthog.com":
            return f"https://{region}.i.posthog.com"
    # Self-hosted: ingest on the same host (no i-subdomain split).
    return host


def _project_key() -> str:
    return os.environ.get("POSTHOG_API_KEY", "").strip()


def _personal_key() -> str:
    return os.environ.get("POSTHOG_PERSONAL_API_KEY", "").strip()


def _project_id() -> str:
    return os.environ.get("POSTHOG_PROJECT_ID", "").strip()


def _op_capture(event: str, distinct_id: str, properties: dict) -> str:
    import httpx
    key = _project_key()
    if not key:
        return "ERROR: capture requires POSTHOG_API_KEY"
    payload = {
        "api_key": key,
        "event": event,
        "distinct_id": distinct_id,
        "properties": properties or {},
    }
    r = _governed_sender(httpx.post)(
        f"{_ingestion_host()}/capture/",
        # follow_redirects=False: don't replay the project API key to another
        # host on a cross-origin 30x off the ingestion endpoint.
        json=payload, timeout=15.0, follow_redirects=False,
    )
    if r.status_code >= 400:
        return f"ERROR: capture ({r.status_code}): {r.text[:300]}"
    return f"captured {event!r} for {distinct_id}"


def _op_identify(distinct_id: str, properties: dict) -> str:
    """PostHog's `$identify` is a capture with a special event name."""
    return _op_capture(
        "$identify", distinct_id,
        {"$set": properties or {}},
    )


def _op_insights(limit: int) -> str:
    import httpx
    pkey = _personal_key()
    pid = _project_id()
    if not pkey or not pid:
        return "ERROR: insights requires POSTHOG_PERSONAL_API_KEY + POSTHOG_PROJECT_ID"
    r = _governed_sender(httpx.get)(
        f"{_host()}/api/projects/{pid}/insights/",
        headers={"Authorization": f"Bearer {pkey}"},
        params={"limit": limit}, timeout=30.0,
    )
    if r.status_code >= 400:
        return f"ERROR: insights ({r.status_code}): {r.text[:300]}"
    data = r.json()
    rows = data.get("results") or []
    if not rows:
        return "no insights"
    return "\n".join(
        # Coerce present-but-null id/name (dict.get default only applies to
        # missing keys) so a JSON null doesn't crash the whole listing.
        f"  {it.get('id') or '':>6}  {(it.get('name') or '')[:80]}  "
        f"({it.get('filters', {}).get('insight', '?')})"
        for it in rows
    )


def _op_insight_get(insight_id: int) -> str:
    import httpx
    pkey = _personal_key()
    pid = _project_id()
    if not pkey or not pid:
        return "ERROR: insight_get requires POSTHOG_PERSONAL_API_KEY + POSTHOG_PROJECT_ID"
    r = _governed_sender(httpx.get)(
        f"{_host()}/api/projects/{pid}/insights/{insight_id}/",
        headers={"Authorization": f"Bearer {pkey}"},
        timeout=30.0,
    )
    if r.status_code == 404:
        return f"insight {insight_id} not found"
    if r.status_code >= 400:
        return f"ERROR: insight_get ({r.status_code}): {r.text[:300]}"
    data = r.json()
    result = data.get("result")
    summary = (
        f"#{data.get('id')}  {data.get('name', '')}\n"
        f"  description: {(data.get('description') or '')[:200]}\n"
        f"  filters: {str(data.get('filters') or {})[:300]}\n"
        f"  last_refresh: {data.get('last_refresh')}\n"
    )
    if isinstance(result, list) and result:
        first = result[0]
        if isinstance(first, dict):
            label = first.get("label") or first.get("breakdown_value") or "?"
            data_pts = first.get("data") or []
            summary += f"  series[0]: {label}  points={len(data_pts)}"
    return summary


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    properties = args.get("properties") if isinstance(args.get("properties"), dict) else {}
    try:
        if op == "capture":
            event = (args.get("event") or "").strip()
            did = (args.get("distinct_id") or "").strip()
            if not event or not did:
                return "ERROR: capture requires event and distinct_id"
            return _op_capture(event, did, properties)
        if op == "identify":
            did = (args.get("distinct_id") or "").strip()
            if not did:
                return "ERROR: identify requires distinct_id"
            return _op_identify(did, properties)
        if op == "insights":
            return _op_insights(max(1, min(int(args.get("limit") or 20), 100)))
        if op == "insight_get":
            iid = int(args.get("insight_id") or 0)
            if not iid:
                return "ERROR: insight_get requires insight_id"
            return _op_insight_get(iid)
    except Exception as e:
        return f"ERROR: posthog failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def posthog_tool() -> Tool:
    return Tool(
        name="posthog",
        description=(
            "PostHog analytics. ops: capture (event + distinct_id + "
            "properties; needs POSTHOG_API_KEY), identify (distinct_id + "
            "person props), insights (list), insight_get (id). Reads "
            "need POSTHOG_PERSONAL_API_KEY + POSTHOG_PROJECT_ID. "
            "POSTHOG_HOST overrides for self-hosted."
        ),
        input_schema=_PH_SCHEMA,
        fn=_run,
    )
