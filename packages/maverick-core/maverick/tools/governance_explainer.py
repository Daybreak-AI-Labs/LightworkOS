"""Right-to-explanation for governance decisions.

GDPR Art. 22 / EU AI Act Art. 14: a person subject to an automated decision is
owed a *meaningful explanation*. Lightwork's governance engine
(:func:`maverick.governance.evaluate`) already records which clause fired and
why; this tool turns that into the human-facing explanation — the decision,
the rule that produced it, the plain-language reason, and the **counterfactual**
("it would have been ALLOWED if ..."), which is the part an affected person
actually needs.

Distinct from the ``decision_explainer`` tool (which breaks down an additive
*scorecard*): this explains the deterministic policy decisions Lightwork itself
makes about whether an action may run. Deterministic, offline — it re-runs the
real evaluator over the supplied policy/action/context.

ops:
  - explain(action[, risk, amount, currency, policy])  — policy is the
    governance Policy as a config-shaped dict (deny_actions,
    require_human_actions, deny_min_risk, require_human_min_risk, deny_above,
    require_human_above). Reports decision + rule + reason + counterfactual.
"""
from __future__ import annotations

from typing import Any

from . import Tool

# Plain-language gloss + the counterfactual for each rule the evaluator can
# cite. Keyed by Verdict.rule.
_RULES = {
    "capability": "the run's capability grant does not include this action",
    "deny_actions": "this action is on the org's hard-deny list",
    "deny_min_risk": "the action's risk meets the org's deny-by-risk floor",
    "deny_above": "the amount exceeds the org's deny ceiling for this action",
    "require_human_actions": "this action always requires a human approver",
    "require_human_min_risk": "the action's risk meets the human-approval risk floor",
    "require_human_above": "the amount exceeds the human-approval threshold",
    "default": "no deny or human-approval rule matched",
}

_COUNTERFACTUAL = {
    "capability": "It would be ALLOWED if the run were granted this capability.",
    "deny_actions": "It would be ALLOWED if this action were removed from "
                    "[governance] deny_actions.",
    "deny_min_risk": "It would be ALLOWED if the deny-risk floor were raised "
                     "above this action's risk, or the action reclassified lower.",
    "deny_above": "It would be ALLOWED below the deny ceiling, or if the ceiling "
                  "were raised.",
    "require_human_actions": "It would run automatically if removed from "
                             "[governance] require_human_actions — or proceeds now "
                             "with a human approval.",
    "require_human_min_risk": "It would run automatically if the human-approval "
                              "risk floor were raised — or proceeds with approval.",
    "require_human_above": "It would run automatically below the approval "
                           "threshold — or proceeds with a human approval.",
    "default": "",
}


def _policy_from_dict(raw: Any):
    from ..governance import Policy, _amount_table, _risk_level

    if not isinstance(raw, dict):
        return Policy()

    def _names(key: str) -> frozenset[str]:
        v = raw.get(key)
        return frozenset(str(x) for x in v if str(x)) if isinstance(v, (list, tuple, set)) else frozenset()

    return Policy(
        deny_actions=_names("deny_actions"),
        require_human_actions=_names("require_human_actions"),
        deny_min_risk=_risk_level(raw.get("deny_min_risk")),
        require_human_min_risk=_risk_level(raw.get("require_human_min_risk")),
        deny_above=_amount_table(raw.get("deny_above")),
        require_human_above=_amount_table(raw.get("require_human_above")),
    )


def _explain(args: dict[str, Any]) -> str:
    action = str(args.get("action") or "").strip()
    if not action:
        return "ERROR: action is required"
    from ..governance import evaluate

    amount = args.get("amount")
    if amount is not None:
        if isinstance(amount, bool) or not isinstance(amount, (int, float)):
            return "ERROR: amount must be a number"
        amount = float(amount)
    risk = args.get("risk")
    # Never pass policy=None here: evaluate(..., policy=None) loads the live
    # [governance] configuration, which would let ordinary tool callers probe
    # deployed deny/approval gates.  This explainer is safe for agent exposure
    # only when it evaluates an explicitly supplied policy snapshot (or the
    # empty default policy when omitted). When ``risk`` is omitted,
    # evaluate() still rates the action with tool_risk(), which applies the
    # deployment's [security.tool_risk] overrides.
    policy = _policy_from_dict(args.get("policy"))

    verdict = evaluate(action, risk=str(risk) if risk else None, amount=amount,
                       currency=str(args.get("currency") or ""), policy=policy)

    lines = [
        f"action: {action}",
        f"decision: {verdict.decision.value.upper()}",
        f"rule: {verdict.rule} — {_RULES.get(verdict.rule, verdict.rule)}",
        f"reason: {verdict.reason}",
    ]
    cf = _COUNTERFACTUAL.get(verdict.rule, "")
    if cf:
        lines.append(f"counterfactual: {cf}")
    return "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op", "explain")
    if op != "explain":
        return f"ERROR: unknown op {op!r}"
    return _explain(args)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["explain"]},
        "action": {"type": "string", "description": "the action/tool name to evaluate"},
        "risk": {"type": "string", "description": "override risk (low/medium/high/critical)"},
        "amount": {"type": "number", "description": "transaction amount (for dollar tiers)"},
        "currency": {"type": "string"},
        "policy": {
            "type": "object",
            "description": "governance Policy as config dict (deny_actions, "
                           "require_human_actions, *_min_risk, *_above); omit for "
                           "an empty policy (never loads the live [governance] "
                           "policy; when 'risk' is omitted the action's risk "
                           "comes from tool_risk, which honours "
                           "[security.tool_risk] overrides)",
        },
    },
    "required": ["action"],
}


def governance_explainer() -> Tool:
    return Tool(
        name="governance_explainer",
        description=(
            "Explain a governance decision (right-to-explanation, GDPR Art. 22 "
            "/ AI Act Art. 14). op=explain re-runs the real policy evaluator "
            "over 'action' (+ optional risk/amount/policy) and reports the "
            "decision (ALLOW/DENY/REQUIRE_HUMAN), the rule that fired, a "
            "plain-language reason, and the counterfactual that would change "
            "it. Deterministic; complements decision_explainer (scorecards)."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
