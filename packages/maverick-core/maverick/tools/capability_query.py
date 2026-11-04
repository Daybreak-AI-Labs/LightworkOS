"""Capability self-report tool: what is this run allowed to do?

Surfaces the current principal's :class:`~maverick.capability.Capability` — the
attenuating grant that bounds which tools (up to what risk) the run may use — so
an agent can introspect its own permissions instead of discovering them by
hitting a wall. Ops:

  - ``list``: the effective grant (allow/deny tool sets, max risk, expiry, path
    + host scopes) plus whether enforcement is on.
  - ``check``: is a specific tool permitted right now? (with the reason).
  - ``enforced``: is capability enforcement active?

Read-only; builds the grant from config via ``capability_from_config`` (same
[security]/RBAC source the ACL uses).
"""
from __future__ import annotations

from ..fastjson import dumps_compact
from . import Tool

_SCHEMA = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["list", "check", "enforced"]},
        "tool": {"type": "string", "description": "tool name to check (check op)"},
    },
    "required": ["op"],
}


def _grant(principal: str):
    from ..capability import capability_from_config
    return capability_from_config(principal)


def _run(args: dict, user_id: str | None) -> str:
    op = args.get("op")
    from ..capability import capability_enforced
    principal = user_id or "self"
    if op == "enforced":
        on = capability_enforced()
        return f"capability enforcement: {'ON' if on else 'OFF (default-open)'}"
    if op == "list":
        cap = _grant(principal)
        return dumps_compact({
            "principal": cap.principal,
            "enforced": capability_enforced(),
            "allow_tools": sorted(cap.allow_tools) or "(all)",
            "deny_tools": sorted(cap.deny_tools),
            "max_risk": cap.max_risk or "(none)",
            "expires_at": cap.expires_at,
            "allow_paths": sorted(cap.allow_paths) or "(all)",
            "allow_hosts": sorted(cap.allow_hosts) or "(all)",
        })
    if op == "check":
        name = str(args.get("tool") or "").strip()
        if not name:
            return "ERROR: check requires a tool name"
        cap = _grant(principal)
        permitted = cap.permits(name)
        enforced = capability_enforced()
        verdict = "permitted" if permitted else "denied"
        note = "" if enforced else " (enforcement OFF — advisory only)"
        return f"{name}: {verdict}{note}"
    return f"ERROR: unknown op {op!r}"


def capability_query(user_id: str | None = None) -> Tool:
    return Tool(
        name="self_capability",
        description=(
            "Report what the current run is allowed to do. ops: list (effective "
            "capability grant — allowed/denied tools, max risk, path/host scopes), "
            "check (is a named tool permitted?), enforced (is enforcement on?)."
        ),
        input_schema=_SCHEMA,
        fn=lambda args: _run(args, user_id),
        parallel_safe=True,
    )


__all__ = ["capability_query"]
