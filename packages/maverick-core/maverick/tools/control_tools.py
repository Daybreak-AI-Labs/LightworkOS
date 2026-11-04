"""find_controls -- a read-only tool that maps a risk to authoritative controls.

The privacy/security analyst agents call this to ground a finding in the specific
control that closes it, with citations across GDPR / EU AI Act / ISO 27001 /
SOC 2 / NIST / HIPAA -- instead of recalling controls from memory. Stateless and
read-only, so it is registered in the base tool set and any agent can use it.
"""
from __future__ import annotations

from . import Tool


def find_controls_tool() -> Tool:
    async def _find(args: dict) -> str:
        from ..controls import find_controls, render_control

        query = str(args.get("query", "")).strip()
        if not query:
            return "ERROR: 'query' is required (the risk or topic to find controls for)."
        try:                                   # a model may emit a non-int limit
            limit = max(1, int(args.get("limit", 5)))
        except (TypeError, ValueError):
            limit = 5
        hits = find_controls(query, limit=limit)
        if not hits:
            return f"No catalog controls matched {query!r}."
        return "\n".join(render_control(c) for c in hits)

    return Tool(
        name="find_controls",
        description="Find the privacy/security control(s) that address a risk or "
                    "topic, with framework citations (GDPR, EU AI Act, ISO 27001, "
                    "SOC 2, NIST, HIPAA). Use it to ground a recommendation.",
        input_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string",
                          "description": "the risk / topic, e.g. 'vendor has no DPA' "
                                         "or 'data at rest encryption'"},
                "limit": {"type": "integer", "description": "max controls (default 5)"},
            },
            "required": ["query"],
        },
        fn=_find,
    )


__all__ = ["find_controls_tool"]
