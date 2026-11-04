"""Streaming reasoning-trace channel formatter.

Render a stream of reasoning-trace events (each a phase, a chunk of text, and a
timestamp) into a single ordered, redaction-aware view, or summarise the stream
into per-phase counts and a wall-clock duration. Deterministic and offline: the
caller supplies the events; this orders them by timestamp and strips anything
wrapped in ``<secret>...</secret>`` so a leaked credential in a thought never
reaches the rendered channel.

ops:
  - format(events)     — ordered, redacted trace rendering ("[ts] phase: text").
  - summarize(events)  — phase counts + total duration (max ts - min ts).

Each event is ``{"phase": str, "text": str, "ts": number}``. Events with a
non-numeric ``ts`` sort last (stable) so a malformed timestamp never crashes
the render.
"""
from __future__ import annotations

import re
from typing import Any

from . import Tool

_SECRET_RE = re.compile(r"<secret>.*?</secret>", re.IGNORECASE | re.DOTALL)


def _redact(text: str) -> str:
    """Replace every <secret>...</secret> span with a fixed marker."""
    text = _SECRET_RE.sub("[REDACTED]", text)
    # Also strip a trailing UNCLOSED <secret> tag: a secret split across events
    # (or whose closing tag hasn't streamed yet) would otherwise leak its body
    # verbatim, since the closed-span regex above can't match it.
    return re.sub(r"<secret>.*", "[REDACTED]", text, flags=re.IGNORECASE | re.DOTALL)


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _ordered(events: list) -> list[dict]:
    """Return the event dicts sorted by ts (non-numeric ts sorts last, stable)."""
    indexed = [
        (i, e) for i, e in enumerate(events) if isinstance(e, dict)
    ]

    def _key(pair: tuple[int, dict]) -> tuple[int, float, int]:
        i, e = pair
        ts = _as_float(e.get("ts"))
        if ts is None:
            return (1, 0.0, i)  # bucket malformed timestamps after valid ones
        return (0, ts, i)

    return [e for _, e in sorted(indexed, key=_key)]


def _format(events: list) -> str:
    rows = []
    for e in _ordered(events):
        phase = str(e.get("phase") or "?")
        text = _redact(str(e.get("text") or ""))
        ts = e.get("ts")
        ts_str = ts if _as_float(ts) is not None else "?"
        rows.append(f"[{ts_str}] {phase}: {text}")
    if not rows:
        return "TRACE: (empty)"
    return "TRACE:\n" + "\n".join(rows)


def _summarize(events: list) -> str:
    counts: dict[str, int] = {}
    stamps: list[float] = []
    for e in events:
        if not isinstance(e, dict):
            continue
        phase = str(e.get("phase") or "?")
        counts[phase] = counts.get(phase, 0) + 1
        ts = _as_float(e.get("ts"))
        if ts is not None:
            stamps.append(ts)
    total = sum(counts.values())
    if not total:
        return "SUMMARY: 0 event(s)"
    duration = (max(stamps) - min(stamps)) if len(stamps) >= 2 else 0.0
    parts = [f"{p}={counts[p]}" for p in sorted(counts)]
    return (
        f"SUMMARY: {total} event(s), duration {duration:g}\n"
        + "\n".join(f"- {p}" for p in parts)
    )


def _run(args: dict[str, Any]) -> str:
    op = args.get("op") or "format"
    if op not in ("format", "summarize"):
        return f"ERROR: unknown op {op!r}"
    events = args.get("events")
    if not isinstance(events, list):
        return "ERROR: events (array of {phase, text, ts}) is required"
    return _format(events) if op == "format" else _summarize(events)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["format", "summarize"]},
        "events": {
            "type": "array",
            "description": "reasoning-trace events; each {phase, text, ts}",
            "items": {
                "type": "object",
                "properties": {
                    "phase": {"type": "string"},
                    "text": {"type": "string"},
                    "ts": {"type": "number"},
                },
            },
        },
    },
    "required": ["events"],
}


def streaming_reasoning_trace() -> Tool:
    return Tool(
        name="streaming_reasoning_trace",
        description=(
            "Render a streaming reasoning-trace channel. op=format orders events "
            "(each {phase, text, ts}) by timestamp into a redaction-aware view "
            "(anything between <secret>...</secret> is stripped); op=summarize "
            "returns per-phase counts and the total duration. Deterministic, "
            "offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
