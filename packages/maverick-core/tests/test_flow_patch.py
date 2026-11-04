"""Patch vocabulary: validated, copy-on-write edits to a Flow."""
from __future__ import annotations

import pytest
from maverick.flow.ir import (
    Flow,
    FlowNode,
    ensure_high_risk_approvals,
    partition_draft_validation_errors,
)
from maverick.flow.patch import PatchError, apply_patches, describe_patch


def _flow() -> Flow:
    return Flow.from_dict({
        "id": "f1", "name": "Triage", "start": "n0",
        "nodes": [
            {"id": "n0", "kind": "agent", "brief": "triage {{issue}}", "next": "n1", "output": "summary"},
            {"id": "n1", "kind": "approval", "prompt": "post it?", "next": "n2"},
            {"id": "n2", "kind": "action", "tool": "web_search",
             "params": {"query": "{{summary}}"}},
        ],
    })


def test_add_node_splices_into_chain():
    out = apply_patches(_flow(), [
        {"op": "add_node", "after": "n0",
         "node": {"id": "n05", "kind": "delay", "seconds": 5}},
    ])
    assert out.nodes["n0"].next == "n05"
    assert out.nodes["n05"].next == "n1"
    assert out.validate() == []


def test_add_node_duplicate_id_rejected():
    with pytest.raises(PatchError, match="already exists"):
        apply_patches(_flow(), [
            {"op": "add_node", "node": {"id": "n1", "kind": "delay", "seconds": 1}},
        ])


def test_remove_node_heals_routing_and_start():
    out = apply_patches(_flow(), [{"op": "remove_node", "id": "n1"}])
    assert "n1" not in out.nodes
    assert out.nodes["n0"].next == "n2"
    out2 = apply_patches(out, [{"op": "remove_node", "id": "n0"}])
    assert out2.start == "n2"


def test_set_field_and_flow_field():
    out = apply_patches(_flow(), [
        {"op": "set_field", "id": "n0", "field": "brief", "value": "summarize {{issue}}"},
        {"op": "set_flow_field", "field": "max_dollars", "value": 3},
        {"op": "set_flow_field", "field": "name", "value": "Issue triage"},
    ])
    assert out.nodes["n0"].brief == "summarize {{issue}}"
    assert out.max_dollars == 3.0
    assert out.name == "Issue triage"


def test_set_field_accepts_rich_human_task_fields():
    # the copilot's schema documents these approval fields, so set_field must
    # accept them (else "make it expire after a day and escalate to n2" fails).
    out = apply_patches(_flow(), [
        {"op": "set_field", "id": "n1", "field": "expires_after", "value": 86400},
        {"op": "set_field", "id": "n1", "field": "on_expire", "value": "n2"},
        {"op": "set_field", "id": "n1", "field": "assignee", "value": "ops"},
        {"op": "set_field", "id": "n1", "field": "form",
         "value": [{"name": "note", "label": "Why?"}]},
    ])
    assert out.nodes["n1"].expires_after == 86400.0
    assert out.nodes["n1"].on_expire == "n2" and out.nodes["n1"].assignee == "ops"
    assert out.validate() == []


def test_copilot_can_set_run_questions_timezone_and_concurrency():
    original = _flow()
    out = apply_patches(original, [
        {"op": "set_flow_field", "field": "inputs", "value": [
            {"key": "issue", "label": "What issue should we triage?", "type": "text", "required": True},
        ]},
        {"op": "set_flow_field", "field": "timezone", "value": "America/New_York"},
        {"op": "set_flow_field", "field": "max_concurrent", "value": 3},
    ])
    assert out.inputs == [{
        "key": "issue", "label": "What issue should we triage?", "type": "text", "required": True,
    }]
    assert out.timezone == "America/New_York" and out.max_concurrent == 3
    assert original.inputs == [] and original.timezone == "" and original.max_concurrent == 0


@pytest.mark.parametrize("field,value", [
    ("inputs", [{"key": "a", "type": "text"}, {"key": "a", "type": "text"}]),
    ("inputs", [{"key": "bad key", "type": "text"}]),
    ("timezone", "Nowhere/Invalid"),
    ("max_concurrent", 33),
    ("max_concurrent", True),
])
def test_copilot_rejects_invalid_run_settings(field, value):
    with pytest.raises(PatchError):
        apply_patches(_flow(), [{"op": "set_flow_field", "field": field, "value": value}])


def test_removing_escalation_step_heals_approval_expiry_route():
    flow = Flow.from_dict({
        "id": "f2", "name": "Review", "start": "approve",
        "nodes": [
            {"id": "approve", "kind": "approval", "prompt": "Approve?", "next": "done",
             "on_expire": "escalate"},
            {"id": "escalate", "kind": "agent", "brief": "Tell the owner", "next": "done"},
            {"id": "done", "kind": "agent", "brief": "Finish"},
        ],
    })
    out = apply_patches(flow, [{"op": "remove_node", "id": "escalate"}])
    assert out.nodes["approve"].on_expire == "done"
    assert out.validate() == []


def test_removing_switch_target_heals_case_route():
    flow = Flow.from_dict({
        "id": "f3", "name": "Sort", "start": "sort",
        "nodes": [
            {"id": "sort", "kind": "switch", "condition": "priority",
             "cases": [{"value": "high", "to": "urgent"}], "next": "done"},
            {"id": "urgent", "kind": "agent", "brief": "Handle urgent", "next": "done"},
            {"id": "done", "kind": "agent", "brief": "Finish"},
        ],
    })
    out = apply_patches(flow, [{"op": "remove_node", "id": "urgent"}])
    assert out.nodes["sort"].cases[0]["to"] == "done"
    assert out.validate() == []


def test_set_field_rejects_id_and_unknown_fields():
    with pytest.raises(PatchError, match="not editable"):
        apply_patches(_flow(), [{"op": "set_field", "id": "n0", "field": "id", "value": "zz"}])


def test_rewire_edge_and_clear():
    out = apply_patches(_flow(), [
        {"op": "rewire", "id": "n1", "field": "next", "to": None},
    ])
    assert out.nodes["n1"].next is None
    with pytest.raises(PatchError, match="unknown node"):
        apply_patches(_flow(), [{"op": "rewire", "id": "n1", "field": "next", "to": "nope"}])


def test_invalid_result_rejected_and_original_untouched():
    flow = _flow()
    # emptying an agent brief makes the flow structurally invalid
    with pytest.raises(PatchError, match="invalid"):
        apply_patches(flow, [{"op": "set_field", "id": "n0", "field": "brief", "value": ""}])
    assert flow.nodes["n0"].brief == "triage {{issue}}"


def test_draft_policy_partition_does_not_trust_forgeable_error_text():
    forged = "action node 'x' uses unclassified direct action tool 'fake'"

    blocking, policy = partition_draft_validation_errors([forged])

    assert blocking == [forged]
    assert policy == []


def test_nested_unclassified_action_keeps_typed_draft_provenance():
    body = Flow(id="body", name="body", start="send", nodes={
        "send": FlowNode(id="send", kind="action", tool="slack_post"),
    })
    flow = ensure_high_risk_approvals(Flow(
        id="outer", name="outer", start="loop", nodes={
            "loop": FlowNode(id="loop", kind="foreach", items="rows", body=body),
        },
    ))

    blocking, policy = partition_draft_validation_errors(flow.validate())

    assert blocking == []
    assert len(policy) == 1
    assert "foreach 'loop' body" in policy[0]


def test_unknown_op_and_empty_list():
    with pytest.raises(PatchError, match="unknown op"):
        apply_patches(_flow(), [{"op": "transmogrify"}])
    with pytest.raises(PatchError, match="no patches"):
        apply_patches(_flow(), [])


def test_describe_patch_lines():
    assert describe_patch(
        {"op": "add_node", "node": {"id": "d1", "kind": "delay"}, "after": "n0"}) == "add delay node d1 after n0"
    assert describe_patch({"op": "rewire", "id": "a", "field": "next", "to": "b"}) == "rewire a.next -> b"
