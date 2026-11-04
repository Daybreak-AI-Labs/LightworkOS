"""Error pattern recognizer tool.

Collapses a pile of error lines into a ranked set of *patterns*: it normalises
the variable parts (numbers, hex/pointers, UUIDs, IPs, quoted paths,
timestamps) so "connection to 10.0.0.4:5432 failed" and "connection to
10.0.0.9:5454 failed" land in the same bucket, then ranks buckets by frequency
with a representative example. Turns a noisy log into "these 4 things actually
broke, N times each."

ops:
  - analyze(errors | text[, top])  — cluster and rank. ``errors`` is a list of
    strings, or ``text`` is a blob split into non-empty lines.
"""
from __future__ import annotations

import re
from typing import Any

from . import Tool

# Order matters: most-specific first so a UUID isn't half-eaten by the hex rule.
_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<uuid>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<ts>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<ip>"),
    (re.compile(r"0x[0-9a-fA-F]+"), "<addr>"),
    (re.compile(r"\b[0-9a-fA-F]{12,}\b"), "<hex>"),
    (re.compile(r"(['\"])(?:/[^'\"]*|[A-Za-z]:\\[^'\"]*)\1"), r"\1<path>\1"),
    (re.compile(r"(?<![\w.])/(?:[\w.\-]+/)*[\w.\-]+"), "<path>"),
    # Any remaining digit run (incl. ones glued to letters like "30s"). Safe
    # because earlier rules already replaced their matches with digit-free
    # placeholders (<ip>/<ts>/<uuid>/...).
    (re.compile(r"\d+"), "<n>"),
]


def _normalize(line: str) -> str:
    s = line.strip()
    for pat, repl in _RULES:
        s = pat.sub(repl, s)
    return re.sub(r"\s+", " ", s).strip()


def _analyze(lines: list[str], top: int) -> str:
    buckets: dict[str, list] = {}  # signature -> [count, first_example]
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        sig = _normalize(line)
        if sig not in buckets:
            buckets[sig] = [0, line]
        buckets[sig][0] += 1

    if not buckets:
        return "no error lines to analyze"
    ranked = sorted(buckets.items(), key=lambda kv: (-kv[1][0], kv[0]))
    total = sum(c for _, (c, _) in ranked)
    out = [f"{len(ranked)} distinct pattern(s) across {total} line(s):"]
    for sig, (count, example) in ranked[:top]:
        out.append(f"\n{count}x  {sig}")
        if example.strip() != sig:
            out.append(f"    e.g. {example[:160]}")
    return "\n".join(out)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "analyze"):
        return f"ERROR: unknown op {args.get('op')!r}"
    errors = args.get("errors")
    text = args.get("text")
    if isinstance(errors, list) and errors:
        lines = [str(e) for e in errors]
    elif isinstance(text, str) and text.strip():
        lines = text.splitlines()
    else:
        return "ERROR: provide 'errors' (array) or 'text' (string)"
    try:
        top = int(args.get("top", 10))
    except (TypeError, ValueError):
        top = 10
    return _analyze(lines, max(1, min(top, 50)))


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["analyze"]},
        "errors": {"type": "array", "items": {"type": "string"},
                   "description": "error/log lines to cluster"},
        "text": {"type": "string", "description": "a log blob (split into lines)"},
        "top": {"type": "integer", "description": "max patterns to return (default 10)"},
    },
}


def error_patterns() -> Tool:
    return Tool(
        name="error_patterns",
        description=(
            "Cluster noisy error/log lines into ranked patterns. Normalises the "
            "variable parts (numbers, hex/pointers, UUIDs, IPs, quoted paths, "
            "timestamps) so near-identical errors group, then ranks by frequency "
            "with an example. op=analyze with 'errors' (array) or 'text' (blob)."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
