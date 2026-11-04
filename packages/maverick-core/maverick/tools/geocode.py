"""Geocoding tool — places <-> coordinates.

Uses OpenStreetMap's Nominatim service (no API key required). Respects
the OSM usage policy: max 1 req/sec, identifying User-Agent, optional
``NOMINATIM_URL`` env to point at a self-hosted instance.

ops:
  - forward(query, limit)              — text address -> lat/lon
  - reverse(lat, lon)                  — coords -> nearest address
"""
from __future__ import annotations

import logging
import os
from typing import Any

from . import Tool

log = logging.getLogger(__name__)


_GEO_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["forward", "reverse"]},
        "query": {"type": "string", "description": "Address / place name."},
        "lat": {"type": "number"},
        "lon": {"type": "number"},
        "limit": {"type": "integer"},
    },
    "required": ["op"],
}


def _base() -> str:
    return os.environ.get("NOMINATIM_URL", "https://nominatim.openstreetmap.org").rstrip("/")


def _ua() -> str:
    # OSM ToS requires identifying UA + contact. Users should override
    # via env in real deployments.
    return os.environ.get(
        "NOMINATIM_USER_AGENT",
        "maverick-agent (https://github.com/Daybreak-AI-Labs/LightworkOS; contact: user)",
    )


def _get(path: str, params: dict) -> tuple[int, Any]:
    # Route through the SSRF-safe client (resolve-once + IP-pin + redirects OFF),
    # exactly like the sibling URL tools (currency._fetch). NOMINATIM_URL is
    # operator-set, but a self-hosted/compromised Nominatim could 302 -> an
    # internal address (e.g. cloud metadata at 169.254.169.254); a raw
    # httpx.get(follow_redirects=True) would chase it with no per-hop check.
    from ._ssrf import BlockedHost, safe_get
    params = {**params, "format": "json"}
    try:
        r = safe_get(
            f"{_base()}{path}",
            headers={"User-Agent": _ua(), "Accept": "application/json"},
            params=params, timeout=20.0,
        )
    except BlockedHost as e:
        return 0, f"blocked host (SSRF guard): {e}"
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:500]


def _op_forward(query: str, limit: int) -> str:
    if not query.strip():
        return "ERROR: forward requires query"
    code, data = _get("/search", {"q": query, "limit": limit, "addressdetails": 1})
    if code >= 400 or not isinstance(data, list):
        return f"ERROR: forward ({code}): {data}"
    if not data:
        return "no matches"
    rows = []
    for d in data:
        rows.append(
            f"  ({d.get('lat')}, {d.get('lon')})  "
            f"{(d.get('display_name') or '')[:160]}"
        )
    return "\n".join(rows)


def _op_reverse(lat: float, lon: float) -> str:
    code, data = _get("/reverse", {"lat": lat, "lon": lon,
                                    "addressdetails": 1, "zoom": 18})
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: reverse ({code}): {data}"
    display = data.get("display_name") or "(no display name)"
    addr = data.get("address") or {}
    if not addr:
        return display
    keys = ("road", "house_number", "suburb", "city", "town", "village",
            "state", "postcode", "country")
    parts = [f"  {k}: {addr[k]}" for k in keys if k in addr]
    return display + "\n" + "\n".join(parts)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    try:
        if op == "forward":
            return _op_forward(
                args.get("query") or "",
                max(1, min(int(args.get("limit") or 5), 25)),
            )
        if op == "reverse":
            lat = args.get("lat")
            lon = args.get("lon")
            if lat is None or lon is None:
                return "ERROR: reverse requires lat and lon"
            return _op_reverse(float(lat), float(lon))
    except Exception as e:
        return f"ERROR: geocode failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def geocode() -> Tool:
    return Tool(
        name="geocode",
        description=(
            "Geocoding via OpenStreetMap Nominatim. ops: forward "
            "(address -> lat/lon), reverse (lat/lon -> address). "
            "No API key. NOMINATIM_URL to point at a self-hosted "
            "instance. Respects OSM usage policy (UA + low rate)."
        ),
        input_schema=_GEO_SCHEMA,
        fn=_run,
    )
