"""Tiny shared helpers for the append-only NDJSON telemetry stores.

Several subsystems keep a best-effort, append-only log (0600, bounded tail) of
JSON rows -- the consequence store, trigger firing history, goal feedback, flow
node outcomes. They all want the same two primitives; this is that shared core so
a new store doesn't re-copy the append idiom and the tail reader.
"""
from __future__ import annotations

import json
import os


def append_row(path, row: dict) -> bool:
    """Append one JSON row to ``path`` (0600, atomic append). Never raises;
    returns whether the write succeeded."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(path), os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
        return True
    except Exception:  # pragma: no cover -- telemetry is best-effort
        return False


def tail_rows(path, max_rows: int) -> list[dict]:
    """The last ``max_rows`` JSON-object rows of ``path`` (in file order).
    Missing file / unreadable lines degrade to fewer rows, never an error."""
    if not path.exists():
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    out: list[dict] = []
    for raw in lines[-max_rows:]:
        try:
            d = json.loads(raw)
            if isinstance(d, dict):
                out.append(d)
        except (ValueError, TypeError):
            continue
    return out


def clamp01(value) -> float:
    """Clamp to [0, 1]; non-numeric -> 0.0."""
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


__all__ = ["append_row", "tail_rows", "clamp01"]
