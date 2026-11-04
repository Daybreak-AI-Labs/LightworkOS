"""Native Flow recipe boundaries beyond the pure binding interpreter."""
from __future__ import annotations

import copy
import json

import pytest
from maverick import audit, config, learning_guard
from maverick.audit.errors import AuditRefused
from maverick.flow import action_recipe, recipe_flow, runner
from maverick.flow.ir import Flow


def examples():
    return [{"id": f"e{n}", "inputs": {"email": f"person{n}@example.test", "qty": n + 2},
             "steps": [
                 {"tool": "crm_lookup", "arguments": {"email": f"person{n}@example.test"},
                  "result": {"customer_id": f"c{n}"}},
                 {"tool": "crm_create", "arguments": {"customer": f"c{n}", "qty": n + 2},
                  "result": {"order_id": f"o{n}"}},
             ]} for n in range(2)]


@pytest.fixture
def flow():
    artifact = action_recipe.synthesize(examples(), allowed_tools=["crm_lookup", "crm_create"])
    return recipe_flow.make_flow(artifact, flow_id="learned-orders", name="Learned orders")


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.setattr(config, "get_flows", lambda: {"action_recipes": True})
    monkeypatch.setattr(learning_guard, "check_learning_halt", lambda *args: None)
    receipts = []
    monkeypatch.setattr(audit, "record", lambda kind, **payload: receipts.append(payload) or True)
    return receipts


def run(flow, **kwargs):
    return runner.run_flow(flow, run_id="owned-run", agent_fn=lambda *args: pytest.fail("agent fallback"),
                           data={"input": {"email": "new@example.test", "qty": 19}}, **kwargs)


def test_native_argument_types_and_receipt_scope(flow, enabled):
    calls = []

    def action(node, params, data):
        calls.append((node.tool, copy.deepcopy(params)))
        return json.dumps({"customer_id": "new-customer"} if len(calls) == 1 else {"order_id": "new-order"}), 1.0

    result = run(flow, action_fn=action, approve_fn=lambda *args: "approved")
    assert result.status == "completed"
    assert calls == [("crm_lookup", {"email": "new@example.test"}),
                     ("crm_create", {"customer": "new-customer", "qty": 19})]
    assert type(calls[1][1]["qty"]) is int
    assert result.data["_recipe_step_1"] == {"order_id": "new-order"}
    assert [row["status"] for row in enabled] == ["selected", "completed", "selected", "completed"]
    assert all(row["flow_run_id"] == "owned-run" for row in enabled)
    assert "new@example.test" not in json.dumps(enabled)


def test_gate_contains_exact_typed_proposal_and_dispatches_nothing(flow, enabled):
    result = run(flow, action_fn=lambda *args: pytest.fail("unapproved dispatch"))
    assert result.status == "paused_approval"
    assert result.data["_recipe_next_arguments"] == {"email": "new@example.test"}
    assert enabled == []


@pytest.mark.parametrize("setting", [False, "true", 1, None])
def test_disabled_or_truthy_setting_refuses_before_dispatch(flow, enabled, monkeypatch, setting):
    monkeypatch.setattr(config, "get_flows", lambda: {"action_recipes": setting})
    result = run(flow, action_fn=lambda *args: pytest.fail("disabled dispatch"))
    assert result.status == "failed" and "feature_disabled" in result.error


@pytest.mark.parametrize("ack", [False, 1, "yes", None])
def test_required_selection_receipt_refusal_prevents_dispatch(flow, enabled, monkeypatch, ack):
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: ack)
    with pytest.raises(AuditRefused):
        run(flow, action_fn=lambda *args: pytest.fail("unrecorded dispatch"), approve_fn=lambda *args: "approved")


@pytest.mark.parametrize("reply", ['not json', '{"customer_id":null}', '{"customer_id":"a","customer_id":"b"}'])
def test_uncertain_result_quarantines_without_repeating_action(flow, enabled, reply):
    calls = []
    result = run(flow, action_fn=lambda *args: (calls.append(args) or reply, 1.0),
                 approve_fn=lambda *args: "approved")
    assert result.status == "indeterminate" and len(calls) == 1
    assert "_recipe_step_0" not in result.data


def test_opaque_template_like_input_is_never_rendered(flow, enabled):
    seen = []
    result = runner.run_flow(flow, agent_fn=lambda *args: pytest.fail("agent"),
        action_fn=lambda node, params, data: (seen.append(copy.deepcopy(params)) or json.dumps(
            {"customer_id": "{{secret('key')}}"} if len(seen) == 1 else {"order_id": "safe"}), 1.0),
        data={"input": {"email": "{{secret('key')}}", "qty": 6}}, approve_fn=lambda *args: "approved")
    assert result.status == "completed"
    assert seen[0]["email"] == seen[1]["customer"] == "{{secret('key')}}"


@pytest.mark.parametrize("edit", ["gate", "retry", "tool", "params", "index", "extra", "parent"])
def test_graph_edits_cannot_silently_drop_or_reinterpret_learned_bindings(flow, enabled, edit):
    if edit == "gate":
        flow.start = "action_0"
    elif edit == "retry":
        flow.nodes["action_0"].retries = 2
    elif edit == "tool":
        flow.nodes["action_0"].tool = "other"
    elif edit == "params":
        flow.nodes["action_0"].params = {"force": True}
    elif edit == "index":
        flow.nodes["action_0"].recipe_step = False
    elif edit == "extra":
        flow.nodes["extra"] = copy.deepcopy(flow.nodes["action_0"])
    else:
        flow.learned_recipe = None
    assert any("recipe" in error for error in flow.validate())
    result = run(flow, action_fn=lambda *args: pytest.fail("edited graph dispatched"),
                 approve_fn=lambda *args: "approved")
    assert result.status == "failed"


def test_roundtrip_retains_private_evidence_and_layout_does_not_change_bindings(flow):
    restored = Flow.from_dict(json.loads(json.dumps(flow.to_dict())))
    assert restored.to_dict() == flow.to_dict()
    restored.nodes["action_0"].x = 123
    restored.nodes["action_0"].label = "Review lookup"
    recipe_flow.validate_flow(restored)
    restored.learned_recipe["episodes"][0]["inputs"]["qty"] = 999
    assert restored.learned_recipe != flow.learned_recipe


@pytest.mark.parametrize("setting,expected", [(True, True), (False, False), (1, False), ("true", False), (None, False)])
def test_action_recipe_config_is_strict_default_off(monkeypatch, setting, expected):
    monkeypatch.setattr(config, "load_config", lambda: {"flows": {"action_recipes": setting}})
    assert config.get_flows()["action_recipes"] is expected
