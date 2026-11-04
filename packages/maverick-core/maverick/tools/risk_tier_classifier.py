"""Goal risk-tier auto-classifier.

Score a proposed goal/action as LOW / MEDIUM / HIGH risk from a small set of
boolean *signals* about what it does — is it irreversible, does it move money,
does it touch PII, does it egress over the network, does it have a wide blast
radius? Distinct from ``ai_act_classifier`` (which screens EU AI Act tiers from
a free-text description): this is a general, weighted, signal-driven scorer for
gating how much oversight a step needs. Deterministic weighted sum with
documented weights and thresholds.

ops:
  - score(signals)  — LOW/MEDIUM/HIGH + contributing factors + numeric score.

Signals (all optional booleans; missing = absent):
  irreversible?, moves_money?, touches_pii?, network_egress?, affects_many?
A numeric ``custom_weight`` may be added on top of the matched factor weights.

Weights (points) and thresholds are fixed so the same signals always map to the
same tier: HIGH at >= 6, MEDIUM at >= 3, else LOW.
"""
from __future__ import annotations

from typing import Any

from . import Tool

# Signal key -> (points, human-readable factor label). Irreversibility and
# money movement dominate; data sensitivity / egress / blast-radius are
# additive contributors.
_WEIGHTS: dict[str, tuple[int, str]] = {
    "irreversible?": (4, "irreversible action"),
    "moves_money?": (4, "moves money"),
    "touches_pii?": (3, "touches sensitive data (PII)"),
    "network_egress?": (2, "network egress"),
    "affects_many?": (3, "wide blast radius (affects many)"),
}

_HIGH_AT = 6
_MEDIUM_AT = 3


def _tier(score: int) -> str:
    if score >= _HIGH_AT:
        return "HIGH"
    if score >= _MEDIUM_AT:
        return "MEDIUM"
    return "LOW"


def _score(signals: dict[str, Any]) -> str:
    total = 0
    factors: list[str] = []
    for key, (points, label) in _WEIGHTS.items():
        if signals.get(key) is True:
            total += points
            factors.append(f"{label} (+{points})")

    if "custom_weight" in signals:
        try:
            extra = int(signals["custom_weight"])
        except (TypeError, ValueError, OverflowError):
            return "ERROR: custom_weight must be an integer"
        if extra:
            total += extra
            sign = "+" if extra >= 0 else ""
            factors.append(f"custom adjustment ({sign}{extra})")

    tier = _tier(total)
    out = f"tier: {tier}\nscore: {total}"
    if factors:
        out += "\nfactors:\n" + "\n".join(f"- {f}" for f in factors)
    else:
        out += "\nfactors: none (no risk signals set)"
    out += f"\nthresholds: HIGH>={_HIGH_AT}, MEDIUM>={_MEDIUM_AT}, else LOW"
    return out


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "score"):
        return f"ERROR: unknown op {args.get('op')!r} (expected score)"
    signals = args.get("signals")
    if not isinstance(signals, dict):
        return "ERROR: signals (object of boolean risk flags) is required"
    return _score(signals)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["score"]},
        "signals": {
            "type": "object",
            "description": "boolean risk flags; numeric custom_weight optional",
            "properties": {
                "irreversible?": {"type": "boolean"},
                "moves_money?": {"type": "boolean"},
                "touches_pii?": {"type": "boolean"},
                "network_egress?": {"type": "boolean"},
                "affects_many?": {"type": "boolean"},
                "custom_weight": {"type": "integer"},
            },
        },
    },
    "required": ["signals"],
}


def risk_tier_classifier() -> Tool:
    return Tool(
        name="risk_tier_classifier",
        description=(
            "Score a goal/action as LOW/MEDIUM/HIGH risk from boolean signals. "
            "op=score with 'signals' ({irreversible?, moves_money?, touches_pii?, "
            "network_egress?, affects_many?} + optional integer custom_weight). "
            "Deterministic weighted sum (irreversible/money +4, PII/blast +3, "
            "egress +2); HIGH>=6, MEDIUM>=3, else LOW. Returns the tier, the "
            "numeric score, and the contributing factors. General goal-risk "
            "scorer, NOT EU AI Act tiers."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
