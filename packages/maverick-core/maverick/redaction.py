"""Deterministic text redaction over the content classifier's findings.

The DSAR path needs to remove OTHER people's data before a response
ships, and evidence surfaces need to quote documents without leaking the
identifiers inside them. This module replaces every validated content
finding with a typed placeholder (``[REDACTED:email]``), working from the
byte-exact spans :mod:`maverick.content_classifier` produced — so the
redaction is reproducible, reviewable, and reversible only by someone
holding the original.

Text only, by design: no OCR, no image or PDF rasterization (both would
need new dependencies, which is a decision, not a drive-by). A second
pass over redacted output is a no-op, so pipelines can redact defensively.
"""
from __future__ import annotations

from typing import Any

from .content_classifier import MAX_TEXT_CHARS, classify_text

REDACTION_TEMPLATE = "[REDACTED:{category}]"


# Filler for collected findings in a working copy: same length, so offsets
# stay those of the original text, and never part of any classifier match.
_FILLER = "\x00"


def _merge_spans(spans: list[tuple[int, int, str]]) -> list[list[Any]]:
    """Merge overlapping or nested spans into their union, labelled with the
    earliest (outermost) finding, so no part of an enclosing identifier stays
    visible around a nested hit."""
    merged: list[list[Any]] = []
    for start, end, category in sorted(spans, key=lambda span: (span[0], -span[1])):
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
            continue
        merged.append([start, end, category])
    return merged


# Window size and context margin for text with more findings than the
# classifier collects in one pass. A finding longer than the margin, or whose
# context lies further back than it, is not expected.
_WINDOW = 20_000
_MARGIN = 1_024


def _collect(text: str, roster: list[str] | None, wanted: set[str] | None,
             *, complete: bool = False) -> tuple[list[tuple[int, int, str]], bool]:
    """Wanted findings in ``text`` and whether the first pass was truncated.
    With ``complete``, collected findings are blanked in a same-length working
    copy and the text classified again until a pass is not truncated."""
    spans: list[tuple[int, int, str]] = []
    work = text
    while True:
        report = classify_text(work, roster=roster)
        spans += [(row["start"], row["end"], row["category"]) for row in report["findings"]
                  if wanted is None or row["category"] in wanted]
        if not report.get("truncated") or not complete:
            return spans, bool(report.get("truncated"))
        if not report["findings"]:
            raise ValueError("text holds findings that could not be redacted")
        chars = list(work)
        for row in report["findings"]:
            chars[row["start"]:row["end"]] = _FILLER * (row["end"] - row["start"])
        work = "".join(chars)


def _collect_window(text: str, low: int, roster: list[str] | None,
                    wanted: set[str] | None) -> list[tuple[int, int, str]]:
    """Every wanted finding that starts in ``[low, low + _WINDOW)``, found in a
    slice with ``_MARGIN`` characters of context on each side."""
    start = max(0, low - _MARGIN)
    piece = text[start:low + _WINDOW + _MARGIN]
    spans, _ = _collect(piece, roster, wanted, complete=True)
    return [(start + a, start + b, category) for a, b, category in spans
            if low <= start + a < low + _WINDOW]


def redact_text(
    text: object,
    *,
    categories: list[str] | None = None,
    roster: list[str] | None = None,
) -> dict[str, Any]:
    """Replace validated findings with typed placeholders.

    ``categories`` limits redaction to those categories; ``None`` redacts
    every finding. ``roster`` adds deterministic name matches (category
    ``name``). Returns ``{"text", "redactions", "counts"}`` where
    ``counts`` maps category -> replacements made. Overlapping findings are
    replaced as one span. Text with more findings than the classifier
    collects in one pass is redacted over several passes.
    """

    sample = str(text or "")
    if len(sample) > MAX_TEXT_CHARS:
        raise ValueError(f"text must be at most {MAX_TEXT_CHARS} characters")
    wanted = None if categories is None else {str(c) for c in categories}
    counts: dict[str, int] = {}
    spans, truncated = _collect(sample, roster, wanted)
    if truncated:
        # More findings than one pass collects: scan bounded windows (with
        # context margins) instead, so each window costs one or two passes.
        spans = []
        for low in range(0, len(sample), _WINDOW):
            spans += _collect_window(sample, low, roster, wanted)
    # Build the redacted text once, from the original.
    pieces: list[str] = []
    pos = 0
    for start, end, category in _merge_spans(spans):
        pieces += [sample[pos:start], REDACTION_TEMPLATE.format(category=category)]
        pos = end
        counts[category] = counts.get(category, 0) + 1
    out = "".join(pieces) + sample[pos:]
    return {
        "text": out,
        "redactions": sum(counts.values()),
        "counts": counts,
    }


#: Bound on nodes walked by :func:`redact_structured`.
MAX_STRUCTURED_NODES = 200_000


def redact_structured(
    value: Any,
    *,
    categories: list[str] | None = None,
    roster: list[str] | None = None,
) -> dict[str, Any]:
    """Field-aware redaction over JSON-shaped data (dict/list/str trees).

    Walks the structure and redacts each STRING leaf individually — no
    serialize-redact-reparse round trip, so placeholders can never break
    quoting and non-string leaves (numbers, booleans) pass through
    untouched. Dict keys are left as-is: keys are schema, values are
    data. Returns ``{"value", "redactions", "counts"}``.
    """

    counts: dict[str, int] = {}
    nodes = 0

    def walk(node: Any) -> Any:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_STRUCTURED_NODES:
            raise ValueError(
                f"structure exceeds {MAX_STRUCTURED_NODES} nodes")
        if isinstance(node, str):
            result = redact_text(node, categories=categories, roster=roster)
            for category, count in result["counts"].items():
                counts[category] = counts.get(category, 0) + count
            return result["text"]
        if isinstance(node, dict):
            return {key: walk(item) for key, item in node.items()}
        if isinstance(node, list):
            return [walk(item) for item in node]
        return node

    out = walk(value)
    return {"value": out, "redactions": sum(counts.values()),
            "counts": counts}


__all__ = [
    "MAX_STRUCTURED_NODES",
    "REDACTION_TEMPLATE",
    "redact_structured",
    "redact_text",
]
