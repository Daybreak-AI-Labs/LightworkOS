"""Web archive (Wayback Machine) tool.

Look up the closest archived snapshot of a URL via the archive.org
availability API, or build the "Save Page Now" endpoint for a URL.

ops:
  - snapshot(url, timestamp)  — query availability and return the closest
    snapshot URL + timestamp.
  - save(url)                 — return the Save Page Now endpoint URL (does
    not fetch it).

No auth required. Stdlib only (urllib.request + json). The network layer is
a single small helper; URL building and response parsing are pure helpers
tested without any network access.
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Any

from . import Tool

_AVAIL = "https://archive.org/wayback/available"
_SAVE = "https://web.archive.org/save"


def _avail_url(url: str, timestamp: str = "") -> str:
    """Build the archive.org availability API URL for ``url``."""
    params = {"url": url}
    if timestamp:
        params["timestamp"] = timestamp
    return f"{_AVAIL}?{urllib.parse.urlencode(params)}"


def _save_url(url: str) -> str:
    """Build the Save Page Now endpoint URL for ``url``."""
    return f"{_SAVE}/{url}"


def _parse_availability(data: dict) -> str:
    """Parse an availability-API JSON dict into a snapshot summary."""
    closest = ((data.get("archived_snapshots") or {}).get("closest") or {})
    if not closest or not closest.get("available"):
        return "no snapshot found"
    snap_url = closest.get("url", "?")
    ts = closest.get("timestamp", "?")
    status = closest.get("status", "?")
    return f"snapshot: {snap_url}\n  timestamp: {ts}\n  status: {status}"


def _http_get_json(url: str) -> tuple[int, Any]:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "maverick-web-archive"},
        method="GET",
    )
    # Route through the SSRF-guarded opener (host allow-list + IP-pin + per-hop
    # redirect revalidation), like the http_fetch tool. A raw urlopen here
    # followed redirects from the archive host straight to an internal address
    # with no re-check; guarded_urlopen revalidates every hop.
    from .http_fetch import guarded_urlopen
    try:
        with guarded_urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return getattr(resp, "status", 200), json.loads(raw)
    except urllib.error.HTTPError as e:  # type: ignore[attr-defined]
        body = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(body)
        except ValueError:
            return e.code, body[:300]
    except Exception as e:  # SSRF block / network error -> surface as a clean code
        return 0, f"blocked or unreachable: {type(e).__name__}: {e}"


def _op_snapshot(args: dict) -> str:
    url = (args.get("url") or "").strip()
    if not url:
        return "ERROR: url is required"
    timestamp = (args.get("timestamp") or "").strip()
    code, data = _http_get_json(_avail_url(url, timestamp))
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: availability ({code}): {data}"
    return _parse_availability(data)


def _op_save(args: dict) -> str:
    url = (args.get("url") or "").strip()
    if not url:
        return "ERROR: url is required"
    return f"save endpoint: {_save_url(url)}"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op") or "snapshot"
    if op not in ("snapshot", "save"):
        return f"ERROR: unknown op {op!r}"
    try:
        return _op_snapshot(args) if op == "snapshot" else _op_save(args)
    except Exception as e:
        return f"ERROR: web archive request failed: {type(e).__name__}: {e}"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["snapshot", "save"]},
        "url": {"type": "string", "description": "The URL to look up / save."},
        "timestamp": {
            "type": "string",
            "description": "Target timestamp YYYYMMDDhhmmss (snapshot).",
        },
    },
    "required": ["url"],
}


def web_archive() -> Tool:
    return Tool(
        name="web_archive",
        description=(
            "Wayback Machine / web archive. ops: snapshot (query "
            "archive.org for the closest archived copy of a URL, "
            "optionally near a timestamp) and save (return the Save "
            "Page Now endpoint URL). No auth required."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
