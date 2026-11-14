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


def _replace_spans(text: str, work: str, findings: list[dict[str, Any]],
                   wanted: set[str] | None, counts: dict[str, int]) -> tuple[str, str, int]:
    """Replace the ``wanted`` findings in ``text`` and in its working copy
    ``work`` (same offsets), and blank the other findings in ``work`` only so a
    later pass does not collect them again. Returns both strings and how many
    spans were handled, adding replacements to ``counts``."""
    # Unwanted findings: blank them in the working copy only (same length).
    kept = [row for row in findings if wanted is not None and row["category"] not in wanted]
    if kept:
        chars = list(work)
        for row in kept:
            chars[row["start"]:row["end"]] = "\x00" * (row["end"] - row["start"])
        work = "".join(chars)
    # Merge overlapping or nested wanted spans into their union, labelled with
    # the earliest (outermost) finding, so no part of an enclosing identifier
    # stays visible around a nested hit.
    merged: list[list[Any]] = []
    for row in sorted((row for row in findings if wanted is None or row["category"] in wanted),
                      key=lambda row: (row["start"], -row["end"])):
        if merged and row["start"] < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], row["end"])
            continue
        merged.append([row["start"], row["end"], row["category"]])
    # Rebuild both strings in one forward pass (offsets refer to the input).
    out_text: list[str] = []
    out_work: list[str] = []
    pos = 0
    for start, end, category in merged:
        placeholder = REDACTION_TEMPLATE.format(category=category)
        out_text += [text[pos:start], placeholder]
        out_work += [work[pos:start], placeholder]
        pos = end
        counts[category] = counts.get(category, 0) + 1
    text = "".join(out_text) + text[pos:]
    work = "".join(out_work) + work[pos:]
    return text, work, len(merged) + len(kept)


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
    out = work = sample
    counts: dict[str, int] = {}
    # The classifier stops collecting at its findings cap. Redact what it
    # collected, then classify the redacted text again (placeholders are never
    # findings) until a pass is complete, so every finding is redacted however
    # many there are. Each truncated pass handles at least one span.
    while True:
        report = classify_text(work, roster=roster)
        out, work, handled = _replace_spans(out, work, report["findings"], wanted, counts)
        if not report.get("truncated"):
            break
        if not handled:
            raise ValueError("text holds findings that could not be redacted")
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
