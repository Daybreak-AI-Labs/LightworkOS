"""Native execution of automatically built graphs retains inputs and approvals."""
import pytest
from maverick.flow.runner import STATUS_COMPLETED, STATUS_PAUSED_APPROVAL, run_flow
from maverick.work_discovery_factory import build_task_flow, review_for_task


@pytest.mark.parametrize("intent", ["invoice.reconcile", "financial_report.draft", "contract.review", "rfp.draft"])
def test_built_workflow_passes_material_through_agents_and_pauses_for_review(intent):
    from maverick.intent_value.taxonomy import definition

    review = review_for_task(definition(intent)["label"], intent)
    flow = build_task_flow(review, identifier="test-built-work")
    assert flow.validate() == []
    assert flow.schedule == "" and flow.max_dollars > 0 and flow.max_seconds > 0
    calls = []

    def agent(node, brief, data):
        calls.append(node.id)
        assert "Authorized example source" in brief
        assert "Check every figure" in brief
        if node.id == "produce":
            assert "prepared source" in brief
        if node.id == "check":
            assert "produced draft" in brief
        return {"prepare": "prepared source", "produce": "produced draft", "check": "checked result"}[node.id], 0.9

    def action(*args):
        pytest.fail("The generated draft must not perform an external action")

    first = run_flow(flow.copy(), agent_fn=agent, action_fn=action)
    assert first.status == STATUS_PAUSED_APPROVAL and calls == []
    data = {**first.data, "source_material": "Authorized example source", "requirements": "Check every figure"}
    second = run_flow(flow.copy(), agent_fn=agent, action_fn=action, resume={"node_id": first.cursor, "data": data, "decision": "approved"})
    assert second.status == STATUS_PAUSED_APPROVAL and second.cursor == "review"
    assert calls == ["prepare", "produce", "check"]
    assert second.data["checked_result"] == "checked result"
    final = run_flow(flow.copy(), agent_fn=agent, action_fn=action, resume={"node_id": second.cursor, "data": second.data, "decision": "approved"})
    assert final.status == STATUS_COMPLETED
