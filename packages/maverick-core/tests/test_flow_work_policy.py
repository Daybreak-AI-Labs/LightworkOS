"""Workflow retry policy never repeats an effect with unknown outcome."""
from maverick.flow.ir import NODE_ACTION, NODE_AGENT, FlowNode
from maverick.flow.work_policy import explicit_unknown, needs_reconciliation, work_policy
from maverick.tool_results import ToolResultState, ToolResultText


def test_work_policy_limits_retries_by_effect_boundary(monkeypatch):
    monkeypatch.setattr("maverick.tool_reliability.is_retry_safe", lambda tool: tool == "read")
    read = work_policy(FlowNode(id="r", kind=NODE_ACTION, tool="read", retries=4), max_retries=3)
    write = work_policy(FlowNode(id="w", kind=NODE_ACTION, tool="write", retries=4), max_retries=3)
    agent = work_policy(FlowNode(id="a", kind=NODE_AGENT, retries=4), max_retries=3)
    assert read.retries == 3 and read.high_risk_action is False
    assert write.retries == 0 and write.high_risk_action is True
    assert agent.retries == 0 and agent.ambiguous_agent is True


def test_unknown_result_requires_reconciliation_even_for_safe_tool(monkeypatch):
    monkeypatch.setattr("maverick.tool_reliability.is_retry_safe", lambda _tool: True)
    node = FlowNode(id="r", kind=NODE_ACTION, tool="read", retries=3)
    policy = work_policy(node, max_retries=3)
    result = ToolResultText("ERROR: connection lost", ToolResultState.INDETERMINATE)
    unknown = explicit_unknown(node, result, 0.0)
    assert unknown is True
    assert needs_reconciliation(policy, result=result, outcome=0.0, error=None, unknown=unknown)


def test_definitive_refusal_does_not_claim_an_unknown_write(monkeypatch):
    monkeypatch.setattr("maverick.tool_reliability.is_retry_safe", lambda _tool: False)
    node = FlowNode(id="w", kind=NODE_ACTION, tool="write", retries=3)
    policy = work_policy(node, max_retries=3)
    refused = ToolResultText("human denied", ToolResultState.REFUSED)
    assert not needs_reconciliation(policy, result=refused, outcome=0.0, error=None, unknown=False)
    assert needs_reconciliation(policy, result="ERROR: timeout", outcome=0.0, error=None, unknown=False)
