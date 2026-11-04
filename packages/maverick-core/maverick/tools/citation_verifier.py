"""Citation verifier tool.

Checks that each cited quote actually appears in the source it is attributed
to — the cheap guard against fabricated or drifted citations in agent output.
Stateless: the caller passes the claim/quote/source triples on each call.

For each item it reports SUPPORTED (the quote is found in the source, exactly
or after whitespace/case normalisation), PARTIAL (high token overlap but not a
clean match — likely paraphrased or lightly edited), or UNSUPPORTED. No
network, no LLM — pure string work, so it is deterministic and fast.
"""
from __future__ import annotations

import re
from typing import Any

from . import Tool

_WORD = re.compile(r"\w+")


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").lower()).strip()


def _tokens(s: str) -> list[str]:
    return _WORD.findall((s or "").lower())


def _overlap(quote: str, source: str) -> float:
    """Fraction of the quote's tokens (with multiplicity) covered by the source."""
    q = _tokens(quote)
    if not q:
        return 0.0
    src = set(_tokens(source))
    return sum(1 for t in q if t in src) / len(q)


def _verify_one(quote: str, source: str, partial_threshold: float) -> tuple[str, float]:
    if not quote.strip():
        return "UNSUPPORTED", 0.0
    if _norm(quote) in _norm(source):
        return "SUPPORTED", 1.0
    ov = _overlap(quote, source)
    if ov >= partial_threshold:
        return "PARTIAL", ov
    return "UNSUPPORTED", ov


def _run(args: dict[str, Any]) -> str:
    items = args.get("items")
    if not isinstance(items, list) or not items:
        return "ERROR: items must be a non-empty array of {quote, source[, claim]}"
    try:
        threshold = float(args.get("partial_threshold", 0.8))
    except (TypeError, ValueError):
        threshold = 0.8
    threshold = min(max(threshold, 0.0), 1.0)

    rows: list[str] = []
    counts = {"SUPPORTED": 0, "PARTIAL": 0, "UNSUPPORTED": 0}
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            rows.append(f"[{i}] ERROR: item is not an object")
            continue
        quote = str(item.get("quote") or "")
        source = str(item.get("source") or "")
        verdict, score = _verify_one(quote, source, threshold)
        counts[verdict] += 1
        label = str(item.get("claim") or quote)[:80]
        rows.append(f"[{i}] {verdict} ({score:.2f}) — {label}")

    summary = (
        f"{counts['SUPPORTED']} supported, {counts['PARTIAL']} partial, "
        f"{counts['UNSUPPORTED']} unsupported of {len(items)}"
    )
    return summary + "\n" + "\n".join(rows)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "items": {
            "type": "array",
            "description": "claims to check; each {quote, source, claim?}",
            "items": {
                "type": "object",
                "properties": {
                    "claim": {"type": "string"},
                    "quote": {"type": "string", "description": "the quoted span to verify"},
                    "source": {"type": "string", "description": "the source text it's attributed to"},
                },
                "required": ["quote", "source"],
            },
        },
        "partial_threshold": {
            "type": "number",
            "description": "token-overlap fraction for a PARTIAL verdict (default 0.8)",
        },
    },
    "required": ["items"],
}


def citation_verifier() -> Tool:
    return Tool(
        name="citation_verifier",
        description=(
            "Verify cited quotes against their source text. For each "
            "{quote, source} item returns SUPPORTED (quote found, exact or "
            "whitespace/case-normalised), PARTIAL (high token overlap — likely "
            "paraphrased), or UNSUPPORTED. Deterministic; no network or LLM. "
            "Use to catch fabricated/drifted citations before they ship."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
