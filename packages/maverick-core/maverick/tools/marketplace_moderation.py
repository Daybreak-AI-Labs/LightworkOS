"""Marketplace listing moderation.

Scan a marketplace listing and return a moderation decision —
``APPROVE`` / ``REVIEW`` / ``REJECT`` — by checking for banned terms, missing
required fields, and spam signals (repeated characters, excessive caps). Pure,
deterministic heuristics: no network, no model call. A banned term is an
automatic REJECT; missing fields or spam signals escalate to REVIEW.

ops:
  - scan(listing={title, description, tags})

Stdlib only (re). No network access anywhere in this tool.
"""
from __future__ import annotations

import re
from typing import Any

from . import Tool

# Prohibited goods/claims — a hit is an automatic reject. Matched as whole
# words, case-insensitively.
_BANNED = frozenset({
    "weapon", "weapons", "gun", "guns", "ammo", "ammunition",
    "drugs", "cocaine", "heroin", "counterfeit", "replica",
    "ivory", "stolen", "endangered",
})

# Promo/spam phrases that don't ban a listing on their own but raise suspicion.
_SPAM_PHRASES = ("act now", "limited time", "100% free", "click here",
                 "money back", "risk free", "guaranteed")


def _words(text: str) -> list[str]:
    return re.findall(r"[a-z0-9']+", text.lower())


def _banned_hits(text: str) -> list[str]:
    return sorted({w for w in _words(text) if w in _BANNED})


def _has_repeated_chars(text: str) -> bool:
    # Same character 4+ times in a row (e.g. "saaaale", "!!!!").
    return re.search(r"(.)\1{3,}", text) is not None


def _caps_ratio(text: str) -> float:
    letters = [c for c in text if c.isalpha()]
    if len(letters) < 8:
        return 0.0
    upper = sum(1 for c in letters if c.isupper())
    return upper / len(letters)


def _spam_signals(title: str, description: str) -> list[str]:
    signals: list[str] = []
    blob = f"{title}\n{description}"
    low = blob.lower()
    if _has_repeated_chars(blob):
        signals.append("repeated characters")
    if _caps_ratio(blob) > 0.6:
        signals.append("excessive caps")
    hits = [p for p in _SPAM_PHRASES if p in low]
    if hits:
        signals.append("promo phrases: " + ", ".join(hits))
    return signals


def _scan(listing: dict) -> dict[str, Any]:
    """Return {decision, reasons} for a listing. Pure."""
    title = str(listing.get("title", "")).strip()
    description = str(listing.get("description", "")).strip()
    raw_tags = listing.get("tags") or []
    tags = [str(t) for t in raw_tags] if isinstance(raw_tags, list) else []

    reasons: list[str] = []

    banned = _banned_hits(" ".join([title, description, " ".join(tags)]))
    missing = [f for f, v in (("title", title), ("description", description))
               if not v]
    if not tags:
        missing.append("tags")
    spam = _spam_signals(title, description)

    if banned:
        decision = "REJECT"
        reasons.append("banned terms: " + ", ".join(banned))
    elif missing or spam:
        decision = "REVIEW"
        if missing:
            reasons.append("missing fields: " + ", ".join(missing))
        reasons.extend(spam)
    else:
        decision = "APPROVE"
        reasons.append("no issues found")
    return {"decision": decision, "reasons": reasons}


def _op_scan(args: dict) -> str:
    listing = args.get("listing")
    if not isinstance(listing, dict):
        return "ERROR: scan requires listing (object with title/description/tags)"
    res = _scan(listing)
    return f"{res['decision']}: " + "; ".join(res["reasons"])


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op not in (None, "scan"):
        return f"ERROR: unknown op {op!r}"
    return _op_scan(args)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["scan"]},
        "listing": {
            "type": "object",
            "description": "The listing to moderate.",
            "properties": {
                "title": {"type": "string"},
                "description": {"type": "string"},
                "tags": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
    "required": ["listing"],
}


def marketplace_moderation() -> Tool:
    return Tool(
        name="marketplace_moderation",
        description=(
            "Moderate a marketplace listing. op=scan with 'listing' "
            "({title, description, tags}) -> APPROVE / REVIEW / REJECT by "
            "checking banned terms (reject), missing fields, and spam signals "
            "(repeated chars, excessive caps, promo phrases). Pure heuristics."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
