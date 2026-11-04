"""Replay annotation export.

Trace annotations (``maverick.ux_store`` — human notes pinned to replay-trace
steps by ``seq``) stay locked inside the dashboard JSON store. This module
exports a run's annotations to two portable formats:

* **markdown** — a review document (one section per note, with the annotated
  event's excerpt for context), pasteable into a PR or incident doc;
* **srt** — an SRT-style timed caption track (cue times relative to the run
  start), so notes overlay a replay video (``maverick.replay.video``) or any
  player that takes ``.srt``.

``seq`` indexes the goal's ordered event list (the replay steps the trajectory
page shows); a seq with no matching event still exports, anchored at the run
start. Deterministic + offline: pure functions over Goal/GoalEvent rows and
the annotation dicts. CLI: ``python -m maverick.annotation_export <goal_id>``.
"""
from __future__ import annotations

from collections.abc import Sequence

from .world_model_contracts import GoalEventReader, GoalEventRecord

_SRT_CUE_SECONDS = 3.0  # each note is shown for 3s, the subtitle convention
_EXCERPT_CHARS = 160


def _ordered_events(world: GoalEventReader, goal_id: int) -> Sequence[GoalEventRecord]:
    return world.goal_events(goal_id, limit=10_000)


def _event_for_seq(events: list, seq: int):
    """The replay step a note is pinned to: ``seq`` is the 0-based index into
    the ordered event list; out-of-range pins anchor to no event."""
    if 0 <= int(seq) < len(events):
        return events[int(seq)]
    return None


def _run_base_ts(goal, events: list) -> float:
    """The replay clock's zero: run creation (or the first event if earlier)."""
    base = float(goal.created_at or 0.0)
    if events:
        base = min(base, float(events[0].ts)) if base else float(events[0].ts)
    return base


def _offset_seconds(goal, events: list, seq: int) -> float:
    ev = _event_for_seq(events, seq)
    if ev is None:
        return 0.0
    return max(0.0, float(ev.ts) - _run_base_ts(goal, events))


def _fmt_clock(seconds: float) -> str:
    s = max(0, int(seconds))
    return f"{s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d}"


def _fmt_srt_time(seconds: float) -> str:
    ms = max(0, int(round(float(seconds) * 1000)))
    s, ms = divmod(ms, 1000)
    h, rem = divmod(s, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d},{ms:03d}"


def to_markdown(goal, events: list, annotations: list[dict]) -> str:
    """Render a run's annotations as a markdown review document."""
    lines = [
        f"# Trace annotations — goal #{goal.id}: {goal.title or '(untitled)'}",
        "",
        f"{len(annotations)} annotation(s) over {len(events)} replay step(s).",
        "",
    ]
    for note in annotations:
        seq = int(note.get("seq", 0))
        ev = _event_for_seq(events, seq)
        offset = _fmt_clock(_offset_seconds(goal, events, seq))
        where = f"step {seq}" + (f" · {ev.kind}" if ev is not None else " · (no such step)")
        lines.append(f"## [{offset}] {where} — {note.get('author') or '_anon'}")
        lines.append("")
        lines.append(str(note.get("note") or "").strip())
        if ev is not None and (ev.content or "").strip():
            excerpt = " ".join((ev.content or "").split())[:_EXCERPT_CHARS]
            lines.append("")
            lines.append(f"> {excerpt}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def to_srt(goal, events: list, annotations: list[dict]) -> str:
    """Render a run's annotations as an SRT-style timed caption track."""
    cues: list[str] = []
    for i, note in enumerate(annotations, start=1):
        start = _offset_seconds(goal, events, int(note.get("seq", 0)))
        end = start + _SRT_CUE_SECONDS
        text = " ".join(str(note.get("note") or "").split())
        author = note.get("author") or "_anon"
        cues.append(
            f"{i}\n{_fmt_srt_time(start)} --> {_fmt_srt_time(end)}\n[{author}] {text}\n"
        )
    return "\n".join(cues)


def export_annotations(
    world, goal_id: int, fmt: str = "markdown", *, annotations: list[dict] | None = None
) -> str:
    """Export goal ``goal_id``'s trace annotations as ``markdown`` or ``srt``.

    ``annotations=None`` reads the shared dashboard UX store (the same ledger
    the ``/api/v1/goals/{id}/annotations`` endpoints write); pass an explicit
    list to export from elsewhere. Raises ``ValueError`` on an unknown goal or
    format.
    """
    if fmt not in ("markdown", "srt"):
        raise ValueError(f"unknown format {fmt!r}; use 'markdown' or 'srt'")
    goal = world.get_goal(goal_id)
    if goal is None:
        raise ValueError(f"no such goal: {goal_id}")
    if annotations is None:
        from .ux_store import shared
        annotations = shared().annotations(goal_id)
    events = _ordered_events(world, goal_id)
    render = to_markdown if fmt == "markdown" else to_srt
    return render(goal, events, annotations)


def main(argv: list[str] | None = None) -> int:
    """CLI: print a goal's annotation export to stdout."""
    import argparse
    from pathlib import Path

    p = argparse.ArgumentParser(
        prog="maverick.annotation_export",
        description="Export a run's trace annotations to markdown or SRT.",
    )
    p.add_argument("goal_id", type=int)
    p.add_argument("--format", choices=("markdown", "srt"), default="markdown")
    p.add_argument("--db", default=None, help="world DB path (default: ~/.maverick/world.db)")
    args = p.parse_args(argv)

    from .world_model import close_world_if_owned, open_world
    world = open_world(Path(args.db)) if args.db else open_world()
    try:
        try:
            print(export_annotations(world, args.goal_id, fmt=args.format), end="")
        except ValueError as e:
            print(f"error: {e}")
            return 2
        return 0
    finally:
        close_world_if_owned(world)


__all__ = ["to_markdown", "to_srt", "export_annotations", "main"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
