"""OpenMetrics exposition renderer.

Render a list of metric samples into a valid OpenMetrics / Prometheus text
exposition: ``# TYPE`` and ``# HELP`` lines per metric family, escaped labels,
the sample lines, and a closing ``# EOF`` marker. Deterministic and offline:
this only formats — it does not scrape or expose a port.

Metric names must match ``[a-zA-Z_:][a-zA-Z0-9_:]*`` and label names
``[a-zA-Z_][a-zA-Z0-9_]*``. HELP text escapes ``\\`` and newlines; label values
escape ``\\``, ``"`` and newlines (the OpenMetrics rules).

ops:
  - render(metrics)  — the exposition text (ends with ``# EOF``).

Metrics: ``[{"name", "type", "value", "labels"?, "help"?}]``.
``type`` is one of counter/gauge/histogram/summary/info/untyped.
"""
from __future__ import annotations

import re
from typing import Any

from . import Tool

_NAME_RE = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")
_LABEL_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
_TYPES = {"counter", "gauge", "histogram", "summary", "info", "untyped"}


def _esc_help(text: str) -> str:
    # HELP: escape backslash and newline only.
    return text.replace("\\", "\\\\").replace("\n", "\\n")


def _esc_label_value(text: str) -> str:
    # Label value: escape backslash, double-quote, newline.
    return (
        text.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
    )


def _fmt_value(v: Any) -> str | None:
    if isinstance(v, bool):  # bool is an int subclass — reject explicitly
        return None
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    return None


def _render_labels(labels: Any) -> str | None:
    if not labels:
        return ""
    if not isinstance(labels, dict):
        return None
    parts: list[str] = []
    for k in labels:
        if not isinstance(k, str) or not _LABEL_RE.match(k):
            return None
    for k in sorted(labels):  # deterministic ordering
        parts.append(f'{k}="{_esc_label_value(str(labels[k]))}"')
    return "{" + ",".join(parts) + "}"


def _render(metrics: list) -> str:
    lines: list[str] = []
    # OpenMetrics/Prometheus require exactly one # TYPE (and at most one # HELP)
    # per metric FAMILY, not per sample. Emitting them for every sample produced
    # invalid, parser-rejected exposition whenever a metric name recurred with a
    # different label set. Emit metadata only the first time each name is seen.
    seen: set[str] = set()
    for m in metrics:
        if not isinstance(m, dict):
            return "ERROR: each metric must be an object"
        name = m.get("name")
        if not isinstance(name, str) or not _NAME_RE.match(name):
            return f"ERROR: invalid metric name {name!r}"
        mtype = str(m.get("type", "untyped")).strip().lower()
        if mtype not in _TYPES:
            return f"ERROR: invalid metric type {mtype!r}"
        value = _fmt_value(m.get("value"))
        if value is None:
            return f"ERROR: metric {name!r} needs a numeric value"
        labels = _render_labels(m.get("labels"))
        if labels is None:
            return f"ERROR: metric {name!r} has invalid labels"

        if name not in seen:
            help_text = m.get("help")
            if help_text is not None:
                lines.append(f"# HELP {name} {_esc_help(str(help_text))}")
            lines.append(f"# TYPE {name} {mtype}")
            seen.add(name)
        lines.append(f"{name}{labels} {value}")

    lines.append("# EOF")
    return "\n".join(lines) + "\n"


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "render"):
        return f"ERROR: unknown op {args.get('op')!r}"
    metrics = args.get("metrics")
    if not isinstance(metrics, list) or not metrics:
        return "ERROR: metrics (non-empty list of {name, type, value, labels?, help?}) is required"
    return _render(metrics)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["render"]},
        "metrics": {
            "type": "array",
            "description": "Metric samples: {name, type, value, labels?, help?}",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "type": {
                        "type": "string",
                        "enum": sorted(_TYPES),
                    },
                    "value": {"type": "number"},
                    "labels": {"type": "object"},
                    "help": {"type": "string"},
                },
                "required": ["name", "type", "value"],
            },
        },
    },
    "required": ["metrics"],
}


def openmetrics() -> Tool:
    return Tool(
        name="openmetrics",
        description=(
            "OpenMetrics/Prometheus text exposition renderer. op=render with "
            "'metrics' ({name, type, value, labels?, help?}). Emits # HELP / "
            "# TYPE lines, escaped label values, the sample lines, and a closing "
            "# EOF. Validates metric and label name regexes. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
