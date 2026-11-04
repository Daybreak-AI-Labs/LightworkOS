"""Per-jurisdiction data residency routing.

Decide where a data subject's data may be stored. The caller supplies the
subject's region and a policy mapping each region to its allowed storage
regions; this resolves the permitted storage region(s), expanding named groups
(EU/EEA) on both sides. If the subject's region has no policy entry, or the
entry permits nothing, the result is DENY. Deterministic and offline. No disk.

ops:
  - route(region, policy)

A storage region is permitted when it appears (directly, or via a group it
belongs to / expands to) in the policy entry for the subject's region.
"""
from __future__ import annotations

from typing import Any

from . import Tool

# Named region groups -> member codes. A group used as a *storage* target
# expands to all its members; a member matches a group target it belongs to.
_GROUPS: dict[str, set[str]] = {
    "EU": {"AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE",
           "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT",
           "RO", "SK", "SI", "ES", "SE"},
    "EEA": set(),  # filled below = EU + EFTA
}
_GROUPS["EEA"] = _GROUPS["EU"] | {"IS", "LI", "NO"}


def _expand(entries: Any) -> list[str]:
    """Resolve codes/group-names into a flat, de-duplicated, sorted list."""
    out: set[str] = set()
    for e in entries or []:
        token = str(e).strip().upper()
        if not token:
            continue
        if token in _GROUPS:
            out |= _GROUPS[token]
        else:
            out.add(token)
    return sorted(out)


def _route(region: str, policy: dict) -> str:
    code = region.strip().upper()
    if not code:
        return "ERROR: region is required"

    # Find the policy entry for this subject region: a direct key, or a group
    # key whose membership includes the code.
    entry: Any = None
    matched_key: str | None = None
    norm = {str(k).strip().upper(): v for k, v in policy.items()}
    if code in norm:
        entry, matched_key = norm[code], code
    else:
        for key, val in norm.items():
            if key in _GROUPS and code in _GROUPS[key]:
                entry, matched_key = val, key
                break

    if entry is None:
        return f"DENY {code}: no residency policy for this region"
    permitted = _expand(entry)
    if not permitted:
        return f"DENY {code}: policy permits no storage region (matched {matched_key})"
    return (
        f"ALLOW {code}: permitted storage region(s): {', '.join(permitted)} "
        f"(matched {matched_key})"
    )


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "route"):
        return f"ERROR: unknown op {args.get('op')!r} (expected route)"
    region = args.get("region")
    policy = args.get("policy")
    if not isinstance(region, str) or not region.strip():
        return "ERROR: region (subject's region code or group) is required"
    if not isinstance(policy, dict) or not policy:
        return "ERROR: policy (non-empty {region: [allowed storage regions]}) is required"
    return _route(region, policy)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["route"]},
        "region": {
            "type": "string",
            "description": "data subject's region (ISO code or group EU/EEA)",
        },
        "policy": {
            "type": "object",
            "description": "{region: [allowed storage regions]}; keys/values may be groups",
            "additionalProperties": {"type": "array", "items": {"type": "string"}},
        },
    },
    "required": ["region", "policy"],
}


def data_residency() -> Tool:
    return Tool(
        name="data_residency",
        description=(
            "Per-jurisdiction data residency routing. op=route with 'region' (the "
            "data subject's region) and 'policy' ({region: [allowed storage "
            "regions]}). Expands groups (EU/EEA) on both sides; returns ALLOW with "
            "the permitted storage region(s) or DENY when none apply. "
            "Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
