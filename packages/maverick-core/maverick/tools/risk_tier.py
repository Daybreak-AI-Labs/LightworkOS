"""Operational risk-tier scorer for agent goals.

Scores a goal/task into LOW / MEDIUM / HIGH from explicit operational risk
signals (shell, network, secrets, PII, spend, irreversibility, production,
external send) so the agent loop can gate the risky ones — extra approval,
containment, or a budget cap. This is operational triage, distinct from
``ai_act_classifier`` (EU AI Act regulatory tiers). Transparent additive
scoring — deterministic and offline.

ops:
  - score(signals, [spend_usd])  — TIER + numeric score + the contributing
    factors. ``signals`` is ``{name: bool}`` over the known risk signals;
    ``spend_usd`` adds weight by magnitude.
"""
from __future__ import annotations

from typing import Any

from . import Tool

# Transparent additive weights. Higher = more dangerous if uncontrolled.
_WEIGHTS: dict[str, int] = {
    "shell": 2,            # arbitrary code execution
    "secrets": 2,          # reads/handles credentials
    "pii": 2,              # processes personal data
    "irreversible": 2,     # deletes/overwrites; no undo
    "production": 2,       # touches live/prod systems
    "external_send": 2,    # sends data to outside recipients
    "network": 1,          # makes outbound network calls
    "filesystem_write": 1, # writes to the local filesystem
}
_HIGH = 5
_MEDIUM = 2


def _spend_weight(spend: float) -> int:
    if spend >= 100:
        return 2
    if spend > 0:
        return 1
    return 0


def _score(signals: dict, spend: float) -> str:
    unknown = [k for k in signals if k not in _WEIGHTS]
    if unknown:
        return f"ERROR: unknown signal(s): {', '.join(sorted(unknown))}"

    total = 0
    factors: list[str] = []
    for name in _WEIGHTS:  # stable, weight-declared order
        if signals.get(name):
            total += _WEIGHTS[name]
            factors.append(name)

    sw = _spend_weight(spend)
    if sw:
        total += sw
        factors.append(f"spend=${spend:g}")

    tier = "HIGH" if total >= _HIGH else "MEDIUM" if total >= _MEDIUM else "LOW"
    detail = ", ".join(factors) if factors else "no elevated risk signals"
    return f"{tier} (score {total}): {detail}"


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "score"):
        return f"ERROR: unknown op {args.get('op')!r}"
    signals = args.get("signals", {})
    if not isinstance(signals, dict):
        return "ERROR: signals must be an object {name: bool}"
    spend = args.get("spend_usd", 0)
    try:
        spend = float(spend)
    except (TypeError, ValueError):
        return "ERROR: spend_usd must be a number"
    if spend < 0:
        return "ERROR: spend_usd must be non-negative"
    return _score(signals, spend)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["score"]},
        "signals": {
            "type": "object",
            "description": (
                "boolean risk signals; known: " + ", ".join(_WEIGHTS) + ""
            ),
        },
        "spend_usd": {
            "type": "number",
            "description": "estimated spend; >0 adds 1, >=100 adds 2",
        },
    },
    "required": ["signals"],
}


def risk_tier() -> Tool:
    return Tool(
        name="risk_tier",
        description=(
            "Score an agent goal into LOW/MEDIUM/HIGH operational risk for "
            "gating. op=score with 'signals' ({name: bool}; known: "
            + ", ".join(_WEIGHTS) + ") and optional 'spend_usd'. Transparent "
            "additive weights; reports the tier, numeric score, and contributing "
            "factors. Operational triage (not EU AI Act). Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
