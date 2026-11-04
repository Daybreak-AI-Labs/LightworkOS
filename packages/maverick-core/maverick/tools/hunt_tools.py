"""Hunt tools -- the threat-hunter agent's hands.

A thin layer over :mod:`maverick.threat_hunt`: the agent runs the sweep, then
triages the risk-ranked findings (with their metadata samples) into "real attack"
vs "benign control firing." Read-only over the audit log; the agent surfaces and
prioritises, it never remediates.
"""
from __future__ import annotations

from . import Tool


def hunt_tools() -> list[Tool]:
    async def _run(args: dict) -> str:
        from ..threat_hunt import hunt, render_report_text

        since = (str(args.get("since") or "")).strip() or None
        until = (str(args.get("until") or "")).strip() or None
        report = hunt(all_days=True, since=since, until=until)
        if not report.findings:
            return (
                f"No attack signals in the audit trail ({report.events_scanned} "
                "event(s) scanned). Nothing to investigate."
            )
        lines = [render_report_text(report), "", "Evidence samples (metadata) to triage:"]
        for f in report.findings:
            lines.append(f"- {f.kind} [{f.severity}] x{f.count}; agents={f.agents}")
            for s in f.samples:
                lines.append(f"    {s}")
        return "\n".join(lines)

    return [
        Tool(
            name="run_threat_hunt",
            description="Sweep the audit trail for attack signals (blocked egress, "
                        "shield blocks, capability/governance denials, the kill "
                        "switch) and return the risk-ranked findings with evidence "
                        "samples to triage. Optional since/until (UTC YYYY-MM-DD).",
            input_schema={
                "type": "object",
                "properties": {
                    "since": {"type": "string", "description": "UTC YYYY-MM-DD"},
                    "until": {"type": "string", "description": "UTC YYYY-MM-DD"},
                },
            },
            fn=_run,
        ),
    ]


__all__ = ["hunt_tools"]
