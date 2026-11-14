"""Misuse leaderboard removal.

Given a public leaderboard of entries (id, score, flagged?), remove the entries
flagged for misuse, emit a tombstone for each removal (id + reason), and return
the cleaned board re-ranked by score. Deterministic and offline so the same
board always cleans to the same result — important for an auditable takedown.

ops:
  - apply(entries)  — entries: [{id, score, flagged?, reason?}].
"""
from __future__ import annotations

from typing import Any

from . import Tool, as_bool


def _apply(entries: list[Any]) -> str:
    kept: list[tuple[str, float]] = []
    tombstones: list[tuple[str, str]] = []
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            return f"ERROR: entry #{i} must be an object {{id,score,flagged?}}"
        eid = str(e.get("id", "")).strip()
        if not eid:
            return f"ERROR: entry #{i} is missing 'id'"
        try:
            score = float(e.get("score", 0))
        except (TypeError, ValueError):
            score = 0.0
        if as_bool(e.get("flagged", False)):
            reason = str(e.get("reason", "")).strip() or "flagged for misuse"
            tombstones.append((eid, reason))
        else:
            kept.append((eid, score))

    # Stable rank: highest score first; ties keep original (insertion) order.
    ranked = sorted(kept, key=lambda kv: -kv[1])

    board_lines = [f"{rank}. {eid} (score={score:g})"
                   for rank, (eid, score) in enumerate(ranked, start=1)]
    tomb_lines = [f"{eid}: {reason}" for eid, reason in tombstones]

    out = [f"CLEANED: removed {len(tombstones)}, kept {len(ranked)}"]
    out.append("ranking:")
    out.extend("- " + line for line in board_lines) if board_lines else out.append("- (empty)")
    if tomb_lines:
        out.append("tombstones:")
        out.extend("- " + line for line in tomb_lines)
    return "\n".join(out)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "apply"):
        return f"ERROR: unknown op {args.get('op')!r}"
    entries = args.get("entries")
    if not isinstance(entries, list):
        return "ERROR: entries (list of {id,score,flagged?}) is required"
    return _apply(entries)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["apply"]},
        "entries": {
            "type": "array",
            "description": "Leaderboard entries: {id, score, flagged?, reason?}",
            "items": {"type": "object"},
        },
    },
    "required": ["entries"],
}


def misuse_removal() -> Tool:
    return Tool(
        name="misuse_removal",
        description=(
            "Remove misuse-flagged leaderboard entries and re-rank. op=apply "
            "with 'entries' ([{id,score,flagged?,reason?}]) drops every flagged "
            "entry, emits a tombstone (id + reason) for each removal, and "
            "returns the cleaned board ranked by score (ties stable). "
            "Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
