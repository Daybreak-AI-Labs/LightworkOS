"""Retry and unknown-effect policy for workflow work-node transitions."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .ir import NODE_ACTION, NODE_AGENT, Flow, FlowNode


def agent_error_route_errors(flow: Flow) -> list[str]:
    """Authoring refusals only; existing saved releases remain loadable."""
    errors = []
    for node in flow.nodes.values():
        if node.kind == NODE_AGENT and node.on_error:
            errors.append(f"agent node {node.id!r}: on_error is not supported; "
                          "failed agent work requires reconciliation before continuing")
        if node.body is not None:
            errors.extend(agent_error_route_errors(node.body))
        for branch in node.branches:
            errors.extend(agent_error_route_errors(branch))
    return errors


@dataclass(frozen=True)
class WorkPolicy:
    """Pre-dispatch retry limits and the effect boundaries they protect."""

    retries: int
    high_risk_action: bool
    ambiguous_agent: bool


def work_policy(node: FlowNode, *, max_retries: int) -> WorkPolicy:
    retries = min(max(0, node.retries), max_retries)
    high_risk = False
    ambiguous_agent = node.kind == NODE_AGENT and node.learned_fallback is not False
    if node.kind == NODE_AGENT:
        # An agent trajectory may have performed effects before failing.
        retries = 0
    elif node.kind == NODE_ACTION:
        from ..tool_reliability import is_retry_safe

        high_risk = not is_retry_safe(node.tool)
        if high_risk:
            retries = 0
    return WorkPolicy(retries, high_risk, ambiguous_agent)


def explicit_unknown(node: FlowNode, result: Any, outcome: float | None) -> bool:
    """An unknown action effect must never be retried, even for a read tool."""
    if node.kind != NODE_ACTION or outcome != 0.0:
        return False
    from ..tool_results import ToolResultState, classify_tool_result

    return classify_tool_result(result) is ToolResultState.INDETERMINATE


def needs_reconciliation(
    policy: WorkPolicy, *, result: Any, outcome: float | None,
    error: Exception | None, unknown: bool,
) -> bool:
    """Keep ambiguous effects quarantined while preserving definite refusals."""
    definitive_no_effect = False
    if policy.high_risk_action and error is None and outcome == 0.0:
        from ..tool_results import ToolResultState, classify_tool_result

        definitive_no_effect = classify_tool_result(result) in {
            ToolResultState.PREVIEW, ToolResultState.REFUSED,
        }
    return bool(
        unknown or ((policy.high_risk_action or policy.ambiguous_agent)
                    and not definitive_no_effect and (error is not None or outcome == 0.0))
    )
