"""Additive-decision explainer.

For an automated decision driven by a linear scorecard (score = sum of
weight x value, plus an intercept), this produces the per-factor contribution
breakdown a data subject is owed under GDPR Art. 22 / "right to explanation":
which factors pushed the decision which way, and by how much. Given a decision
threshold it also reports the outcome and the margin to that threshold. Pure
arithmetic — deterministic and offline; only explains additive models.
(It does not yet compute counterfactual recourse — the minimal factor change
that would flip the outcome.)

ops:
  - explain(factors, [intercept], [threshold])  — ``factors`` is
    ``{name: {weight, value}}``. Reports the total score, each factor's signed
    contribution (ranked by magnitude), and — when ``threshold`` is given — the
    APPROVED/DENIED outcome and the margin to the threshold.
"""
from __future__ import annotations

from typing import Any

from . import Tool


def _explain(factors: dict, intercept: float, threshold: float | None) -> str:
    contribs: list[tuple[str, float]] = []
    for name, f in factors.items():
        if not isinstance(f, dict) or "weight" not in f or "value" not in f:
            return f"ERROR: factor {name!r} needs 'weight' and 'value'"
        try:
            weight = float(f["weight"])
            value = float(f["value"])
        except (TypeError, ValueError):
            return f"ERROR: factor {name!r} weight/value must be numbers"
        contribs.append((str(name), weight * value))

    score = intercept + sum(c for _, c in contribs)
    # Rank by magnitude (largest driver first); ties broken by name for determinism.
    ranked = sorted(contribs, key=lambda x: (-abs(x[1]), x[0]))

    lines = [f"score: {score:.4g}" + (f" (intercept {intercept:g})" if intercept else "")]
    if threshold is not None:
        outcome = "APPROVED" if score >= threshold else "DENIED"
        margin = score - threshold
        lines[0] = (
            f"{outcome}: score {score:.4g} "
            f"{'>=' if margin >= 0 else '<'} threshold {threshold:g} "
            f"(margin {margin:+.4g})"
        )
    lines.append("factors by contribution:")
    for name, c in ranked:
        lines.append(f"  {c:+.4g} {name}")
    return "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "explain"):
        return f"ERROR: unknown op {args.get('op')!r}"
    factors = args.get("factors")
    if not isinstance(factors, dict) or not factors:
        return "ERROR: factors must be a non-empty object {name: {weight, value}}"
    intercept = args.get("intercept", 0)
    try:
        intercept = float(intercept)
    except (TypeError, ValueError):
        return "ERROR: intercept must be a number"
    threshold = args.get("threshold")
    if threshold is not None:
        try:
            threshold = float(threshold)
        except (TypeError, ValueError):
            return "ERROR: threshold must be a number"
    return _explain(factors, intercept, threshold)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["explain"]},
        "factors": {
            "type": "object",
            "description": "factor name -> {weight, value}; contribution = weight x value",
        },
        "intercept": {"type": "number", "description": "constant added to the score (default 0)"},
        "threshold": {
            "type": "number",
            "description": "decision boundary; if set, reports APPROVED/DENIED and the margin",
        },
    },
    "required": ["factors"],
}


def decision_explainer() -> Tool:
    return Tool(
        name="decision_explainer",
        description=(
            "Explain an additive/scorecard decision (right-to-explanation). "
            "op=explain with 'factors' ({name: {weight, value}}), optional "
            "'intercept' and 'threshold'. Reports the total score, each factor's "
            "signed contribution ranked by magnitude, and — with a threshold — the "
            "APPROVED/DENIED outcome and margin. Explains additive models only. "
            "Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
