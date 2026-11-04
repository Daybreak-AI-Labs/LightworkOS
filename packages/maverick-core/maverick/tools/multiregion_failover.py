"""Multi-region failover.

Pick the region to serve a client from and the ordered fallback list behind it.
Deterministic and offline: the caller supplies the candidate regions (each
``{name, healthy, rtt_ms, capacity_left}``) and the client's region; this
resolves the selection.

A region is eligible when it is healthy AND has capacity left (``> 0``).
Eligible regions are ordered nearest-first by (rtt_ms, name); the client's own
region, when eligible, is preferred to the front (rtt 0 to itself). The first is
the chosen region, the rest are the ordered fallback list.

ops:
  - select(regions, client_region)  — chosen region + ordered fallbacks (or NONE).
"""
from __future__ import annotations

from typing import Any

from . import Tool


def _parse_region(r: Any, idx: int) -> tuple[dict[str, Any] | None, str]:
    if not isinstance(r, dict):
        return None, f"ERROR: region #{idx} must be an object"
    name = r.get("name")
    if not isinstance(name, str) or not name.strip():
        return None, f"ERROR: region #{idx} needs a non-empty name"
    try:
        rtt = float(r.get("rtt_ms"))
        capacity = float(r.get("capacity_left"))
    except (TypeError, ValueError):
        return None, f"ERROR: region {name!r} needs numeric rtt_ms and capacity_left"
    if rtt < 0:
        return None, f"ERROR: region {name!r} rtt_ms must be >= 0"
    return {
        "name": name,
        "healthy": bool(r.get("healthy", False)),
        "rtt_ms": rtt,
        "capacity_left": capacity,
    }, ""


def _select(regions: list, client_region: str) -> str:
    parsed: list[dict[str, Any]] = []
    for i, r in enumerate(regions):
        reg, err = _parse_region(r, i)
        if err:
            return err
        parsed.append(reg)

    eligible = [r for r in parsed if r["healthy"] and r["capacity_left"] > 0]

    def sort_key(r: dict[str, Any]) -> tuple[int, float, str]:
        # Client's own region sorts ahead of all others (local hop wins),
        # then nearest rtt, then name for stability.
        local = 0 if r["name"] == client_region else 1
        return (local, r["rtt_ms"], r["name"])

    eligible.sort(key=sort_key)

    if not eligible:
        return (
            f"NONE no healthy region with capacity (client={client_region}; "
            f"evaluated {len(parsed)})"
        )

    chosen = eligible[0]["name"]
    fallbacks = [r["name"] for r in eligible[1:]]
    fb = ", ".join(fallbacks) if fallbacks else "(none)"
    return (
        f"SELECT {chosen} for client {client_region} "
        f"(rtt={eligible[0]['rtt_ms']:g}ms, capacity_left={eligible[0]['capacity_left']:g})\n"
        f"  fallbacks: [{fb}]"
    )


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "select"):
        return f"ERROR: unknown op {args.get('op')!r}"
    regions = args.get("regions")
    if not isinstance(regions, list) or not regions:
        return "ERROR: regions (non-empty list of {name, healthy, rtt_ms, capacity_left}) is required"
    client_region = args.get("client_region")
    if not isinstance(client_region, str) or not client_region.strip():
        return "ERROR: client_region (string) is required"
    return _select(regions, client_region)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["select"]},
        "regions": {
            "type": "array",
            "description": "Regions: {name, healthy, rtt_ms, capacity_left}",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "healthy": {"type": "boolean"},
                    "rtt_ms": {"type": "number", "minimum": 0},
                    "capacity_left": {"type": "number"},
                },
                "required": ["name", "rtt_ms", "capacity_left"],
            },
        },
        "client_region": {
            "type": "string",
            "description": "The region the client is in, e.g. 'us-east-1'",
        },
    },
    "required": ["regions", "client_region"],
}


def multiregion_failover() -> Tool:
    return Tool(
        name="multiregion_failover",
        description=(
            "Multi-region failover. op=select with 'regions' (each {name, "
            "healthy, rtt_ms, capacity_left}) and the 'client_region'. Returns "
            "the nearest healthy region with capacity left and an ordered "
            "fallback list (client's own region preferred, then by rtt). Returns "
            "NONE if no region is healthy with capacity. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
