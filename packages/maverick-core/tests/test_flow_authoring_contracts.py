"""Authoring contracts reject malformed or misleading workflow changes."""
from __future__ import annotations

import base64
import hashlib
import hmac
import importlib
import json
from types import SimpleNamespace

import pytest
from maverick.budget import BudgetExceeded
from maverick.flow import action_recipe, approvals, execution, store
from maverick.flow.draft import draft_flow
from maverick.flow.ir import Flow, FlowNode, ensure_high_risk_approvals
from maverick.flow.patch import PatchError, apply_patches
from maverick.flow.runner import run_flow
from maverick.killswitch import Halted


def _flow(*nodes, flow_id="authoring"):
    return Flow(id=flow_id, name=flow_id, start=nodes[0].id,
                nodes={node.id: node for node in nodes})


@pytest.mark.parametrize("character", ["p", "界"])
def test_approval_links_bind_full_pause_and_approver_values(monkeypatch, tmp_path, character):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    app = importlib.import_module("maverick_dashboard.app")
    from maverick import approval_cards
    from maverick_dashboard import automation_queue

    monkeypatch.setattr(approvals, "_secret_for_tenant", lambda _tenant: "approval-fixture-secret")
    binding = "b" * 64
    run = SimpleNamespace(
        run_id="long-approval", status="paused_approval", cursor=character * 300,
        prompt=character * 2500, updated=123.0, owner=character * 600,
        human={"assignee": character * 600, "approval_card": {}},
    )
    monkeypatch.setattr(store, "load_run", lambda _rid: run)
    monkeypatch.setattr(automation_queue, "flow_approval_binding", lambda _run: binding)
    monkeypatch.setattr(approval_cards, "require_current_approval_card", lambda _card: None)
    token = approvals.mint_token(
        run.run_id, "approved", cursor=run.cursor, prompt=run.prompt,
        updated=run.updated, owner=run.owner, assignee=run.human["assignee"],
        binding_sha256=binding, tenant="",
    )
    assert app._load_paused_approval_run(token)[0] is run
    for field in ("cursor", "prompt", "owner", "assignee"):
        container = run.human if field == "assignee" else vars(run)
        saved = container[field]
        container[field] = saved[:-1] + "z"
        assert app._load_paused_approval_run(token)[0] is None
        container[field] = saved
    # Pre-digest short links still bind their exact values.
    run.cursor, run.prompt, run.owner, run.human["assignee"] = "gate", "Approve?", "alice", "alice"
    body = base64.urlsafe_b64encode(json.dumps({
        "r": run.run_id, "d": "approved", "e": 9_999_999_999,
        "c": run.cursor, "p": run.prompt, "u": run.updated,
        "a": "alice", "o": "alice", "t": "", "b": binding,
    }).encode()).decode().rstrip("=")
    signature = hmac.new(b"approval-fixture-secret", body.encode(), hashlib.sha256).hexdigest()
    assert app._load_paused_approval_run(f"{body}.{signature}")[0] is run


@pytest.mark.parametrize("patch", [
    {"op": "add_node", "node": {"id": "b", "kind": "scope", "body": "oops"}},
    {"op": "add_node", "node": {"id": "b", "kind": "delay", "seconds": None}},
    {"op": "add_node", "node": {"id": "b", "kind": "switch", "cases": 5}},
    {"op": "set_field", "id": "a", "field": "body", "value": "oops"},
    {"op": "add_node", "node": "oops"},
    {"op": []},
])
def test_malformed_node_edits_always_raise_patch_error(patch):
    flow = _flow(FlowNode(id="a", kind="agent", brief="work"))
    before = flow.to_dict()
    with pytest.raises(PatchError):
        apply_patches(flow, [patch])
    assert flow.to_dict() == before


@pytest.mark.parametrize("container", [None, "scope", "parallel"])
def test_duplicate_node_ids_are_reported_even_after_authoring_copy(container):
    raw = {"id": "child", "name": "child", "start": "a", "nodes": [
        {"id": "a", "kind": "approval", "prompt": "Approve?"},
        {"id": "a", "kind": "agent", "brief": "work"},
    ]}
    if container:
        nested = {"id": "nested", "kind": container}
        nested["body" if container == "scope" else "branches"] = raw if container == "scope" else [raw]
        raw = {"id": "outer", "name": "outer", "start": "nested", "nodes": [nested]}
    flow = Flow.from_dict(raw)
    assert any("duplicate node id 'a'" in error for error in flow.validate())
    assert any("duplicate node id 'a'" in error for error in flow.copy().validate())
    assert any("duplicate node id 'a'" in error for error in ensure_high_risk_approvals(flow).validate())
    # Existing saved definitions contain the collapsed dict form, not duplicates.
    assert Flow.from_dict(flow.to_dict()).validate() == []


@pytest.mark.parametrize("container", ["scope", "parallel"])
@pytest.mark.parametrize("existing", [False, True])
def test_node_field_edit_preserves_unchanged_nested_duplicate_diagnostics(container, existing):
    child = {"id": "child", "name": "child", "start": "a", "nodes": [
        {"id": "a", "kind": "agent", "brief": "first"},
        {"id": "a", "kind": "agent", "brief": "second"},
    ]}
    field = "body" if container == "scope" else "branches"
    nested = {"id": "nested", "kind": container, field: child if field == "body" else [child]}
    flow = _flow(FlowNode(id="start", kind="agent", brief="start"))
    prefix = [{"op": "add_node", "after": "start", "node": nested}]
    if existing:
        flow.nodes["start"].next = "nested"
        flow.nodes["nested"] = FlowNode.from_dict(nested)
        prefix = []
    label = {"op": "set_field", "id": "nested", "field": "label", "value": "Edited label"}
    with pytest.raises(PatchError, match="duplicate node id 'a'"):
        apply_patches(flow, [*prefix, label])

    # Explicit replacement or removal is still a valid repair in the same batch.
    repaired_child = _flow(FlowNode(id="a", kind="agent", brief="replacement")).to_dict()
    replacement = {"op": "set_field", "id": "nested", "field": field,
                   "value": repaired_child if field == "body" else [repaired_child]}
    repaired = apply_patches(flow, [*prefix, label, replacement])
    assert repaired.validate() == [] and repaired.nodes["nested"].label == "Edited label"
    removed = apply_patches(flow, [*prefix, label, {"op": "remove_node", "id": "nested"}])
    assert removed.validate() == [] and "nested" not in removed.nodes


def test_choice_approval_gets_a_binary_gate_before_high_risk_work():
    flow = _flow(
        FlowNode(id="choice", kind="approval", prompt="Choose", choices=["go", "hold"], next="pay"),
        FlowNode(id="pay", kind="action", tool="wire_transfer"),
    )
    governed = ensure_high_risk_approvals(flow)
    assert governed.validate() == []
    gate = governed.nodes[governed.nodes["choice"].next]
    assert gate.kind == "approval" and not gate.choices and gate.next == "pay"
    assert ensure_high_risk_approvals(governed).to_dict() == governed.to_dict()
    calls = []
    result = run_flow(
        governed, agent_fn=lambda *_args: ("unused", 1.0),
        action_fn=lambda *_args: (calls.append("payment") or "sent", 1.0),
        approve_fn=lambda node, _data: "hold" if node.id == "choice" else "pending",
    )
    assert result.status == "paused_approval" and result.cursor == gate.id
    assert calls == []


@pytest.mark.parametrize("cap", [0.0, 1.0])
def test_budget_wrappers_keep_injected_agent_wall_contract(monkeypatch, tmp_path, cap):
    monkeypatch.setattr("maverick.paths.data_dir", lambda *parts, **kwargs: tmp_path.joinpath(*parts))
    flow = _flow(FlowNode(id="a", kind="agent", brief="work", timeout=2.0))
    flow.max_dollars = cap
    calls = []

    def legacy(brief, data):
        calls.append((brief, None))
        return "done", 1.0

    result = execution.execute(
        flow, agent_runner=legacy, action_runner=lambda *_args: ("unused", 1.0),
        agent_budget_dollars=0.25, record_outcomes=True,
    )
    assert result.status == "completed"
    assert calls == [("work", None)] and result.cost_dollars == 0.25

    def bounded(brief, data, *, wall=None):
        calls.append((brief, wall))
        return "done", 1.0

    result = execution.execute(
        flow, agent_runner=bounded, action_runner=lambda *_args: ("unused", 1.0),
        agent_budget_dollars=0.25, record_outcomes=True,
    )
    assert result.status == "completed" and calls[-1] == ("work", 2.0)


@pytest.mark.parametrize("stop", [Halted("operator stop", "test"), BudgetExceeded("draft cap")])
def test_draft_control_stop_never_returns_runnable_fallback(stop):
    def complete(*args, **kwargs):
        raise stop

    with pytest.raises(type(stop)):
        draft_flow("draft a weekly report", complete=complete)


@pytest.mark.parametrize("schema", [[], {}, None, 17])
def test_malformed_recipe_schema_abstains(schema):
    decision = action_recipe.resolve_step({"schema": schema}, 0, {}, [])
    assert not decision.applied and decision.reason == "invalid_artifact"


@pytest.mark.parametrize("nested", [False, True])
def test_patch_refuses_agent_error_route_without_invalidating_saved_graph(nested):
    body = _flow(
        FlowNode(id="a", kind="agent", brief="work", on_error="recover"),
        FlowNode(id="recover", kind="agent", brief="recover"),
    )
    assert body.validate() == []
    result = run_flow(body, agent_fn=lambda *_args: ("failed", 0.0),
                      action_fn=lambda *_args: ("unused", 1.0))
    assert result.status == "indeterminate"
    flow = _flow(FlowNode(id="scope", kind="scope", body=body)) if nested else body
    with pytest.raises(PatchError, match="agent.*on_error|on_error.*agent"):
        apply_patches(flow, [{"op": "set_flow_field", "field": "name", "value": "Edit"}])
    if not nested:
        repaired = apply_patches(flow, [{"op": "set_field", "id": "a", "field": "on_error", "value": None}])
        assert repaired.nodes["a"].on_error is None and repaired.validate() == []
