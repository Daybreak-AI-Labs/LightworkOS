"""Posture tools -- the compliance auditor's evidence source.

A read-only window onto this deployment's live control state (from
:func:`maverick.compliance.compliance_report`), so the auditor can answer a
framework's control questions from what the system *actually* enforces rather
than guessing.
"""
from __future__ import annotations

from . import Tool


def posture_tools() -> list[Tool]:
    async def _run(args: dict) -> str:
        from ..compliance import compliance_report
        try:
            checks = compliance_report()
        except Exception as e:  # never crash the agent on a probe error
            return f"could not read deployment posture: {type(e).__name__}: {e}"
        if not checks:
            return "No deployment control posture available."
        lines = ["Live deployment control posture (this system's actual state):"]
        for c in checks:
            lines.append(f"  [{c.status}] {c.control} ({c.regulation}) -- {c.detail}")
        return "\n".join(lines)

    return [
        Tool(
            name="deployment_posture",
            description="Report this deployment's live compliance control state "
                        "(active / available / action_needed) as audit evidence "
                        "when assessing the system itself. Read-only.",
            input_schema={"type": "object", "properties": {}},
            fn=_run,
        ),
    ]


__all__ = ["posture_tools"]
