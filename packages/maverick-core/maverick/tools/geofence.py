"""Geofence policy tool.

Decide whether an operation is permitted from a given region against an
allow/deny policy — the building block for "this workload may only run in the
EU" or "deny these sanctioned jurisdictions". Deterministic and offline: the
caller supplies the region (an ISO 3166-1 alpha-2 country code, or a named
group like ``EU``) and the policy; this resolves the decision. Deny always wins
over allow; with no allow-list, the decision falls through to ``default``,
which itself defaults to ``deny`` (deny-by-default — safe for a geofence).

ops:
  - check(region, policy)  — ALLOW / DENY with the reason.

Policy: ``{"allow": [...], "deny": [...], "default": "allow"|"deny"}`` where
entries are country codes or group names.
"""
from __future__ import annotations

from typing import Any

from . import Tool

# Named region groups -> member ISO 3166-1 alpha-2 codes.
_GROUPS: dict[str, set[str]] = {
    "EU": {"AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE",
           "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT",
           "RO", "SK", "SI", "ES", "SE"},
    "EEA": set(),  # filled below = EU + EFTA
    "FIVE_EYES": {"US", "GB", "CA", "AU", "NZ"},
}
_GROUPS["EEA"] = _GROUPS["EU"] | {"IS", "LI", "NO"}


def _expand(entries: Any) -> set[str]:
    """Resolve a list of codes/group-names into a flat set of country codes."""
    out: set[str] = set()
    for e in entries or []:
        token = str(e).strip().upper()
        if not token:
            continue
        if token in _GROUPS:
            out |= _GROUPS[token]
        else:
            out.add(token)
    return out


def _check(region: str, policy: dict) -> str:
    code = region.strip().upper()
    if not code:
        return "ERROR: region is required"
    if code not in _GROUPS and not (len(code) == 2 and code.isalpha()):
        # "Germany" would match no list entry and fall to an allow default.
        return f"ERROR: region {region!r} is not an ISO 3166-1 alpha-2 code or a group"
    allow = _expand(policy.get("allow"))
    deny = _expand(policy.get("deny"))
    default = str(policy.get("default", "deny")).strip().lower()
    if default not in ("allow", "deny"):
        default = "deny"

    # The region may itself be a GROUP name (e.g. "EU"), which the docstring
    # supports. Expand it and match by membership: a bare country code expands
    # to itself (unchanged behaviour), while a group region matches a list entry
    # only when EVERY country it covers is on that list. Without this a group
    # region never matched the expanded lists, so a `deny: ["EU"]` was silently
    # bypassed (fail-open) and an `allow: ["EU"]` wrongly denied. Deny wins:
    # a group region is denied when ANY country it covers is on the deny-list
    # (EU with deny DE must not come back ALLOW).
    region_codes = _expand([code])

    if region_codes & deny:
        return f"DENY {code}: in deny-list"
    if allow:
        if region_codes and region_codes <= allow:
            return f"ALLOW {code}: in allow-list"
        return f"DENY {code}: not in allow-list"
    # No allow-list -> anything not explicitly denied falls to the default.
    return f"{default.upper()} {code}: default policy ({default})"


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "check"):
        return f"ERROR: unknown op {args.get('op')!r}"
    region = args.get("region")
    policy = args.get("policy")
    if not isinstance(region, str) or not region.strip():
        return "ERROR: region (country code or group) is required"
    if not isinstance(policy, dict):
        return "ERROR: policy (object with allow/deny/default) is required"
    return _check(region, policy)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["check"]},
        "region": {"type": "string", "description": "ISO 3166-1 alpha-2 code, e.g. DE"},
        "policy": {
            "type": "object",
            "description": "allow/deny lists (codes or groups EU/EEA/FIVE_EYES) + default",
            "properties": {
                "allow": {"type": "array", "items": {"type": "string"}},
                "deny": {"type": "array", "items": {"type": "string"}},
                "default": {"type": "string", "enum": ["allow", "deny"]},
            },
        },
    },
    "required": ["region", "policy"],
}


def geofence() -> Tool:
    return Tool(
        name="geofence",
        description=(
            "Decide if a region is permitted by an allow/deny geofence policy. "
            "op=check with 'region' (ISO 3166-1 alpha-2 code or a group: EU, "
            "EEA, FIVE_EYES) and 'policy' (allow/deny lists + default). Deny "
            "wins over allow (a group is denied if any member is denied). "
            "Without an allow-list the 'default' decides, and it is deny "
            "unless the policy sets default=allow. "
            "Returns ALLOW/DENY with the reason."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
