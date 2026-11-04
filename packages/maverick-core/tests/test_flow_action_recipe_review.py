"""Independent native tests for recipe approval, state and source immutability."""
from __future__ import annotations

import copy
import hashlib
import json

import pytest
from maverick import audit, config
from maverick.flow import action_recipe, execution, recipe_flow, store
from maverick.tools import Tool, ToolRegistry

_LOOKUP = "review_customer_lookup"
_CREATE = "review_order_create"
_OTHER = "review_other_mutation"


def _artifact():
    episodes = []
    for index in range(2):
        episodes.append({"id": f"reviewed-{index}",
                         "inputs": {"lookup_ref": f"ref-{index}", "quantity": index + 2},
                         "steps": [
                             {"tool": _LOOKUP, "arguments": {"query": f"ref-{index}"},
                              "result": {"customer_id": f"customer-{index}"}},
                             {"tool": _CREATE, "arguments": {"customer_id": f"customer-{index}",
                                                               "quantity": index + 2},
                              "result": {"order_id": f"order-{index}"}},
                         ]})
    return action_recipe.synthesize(episodes, allowed_tools=[_LOOKUP, _CREATE])


@pytest.fixture
def native(tmp_path, monkeypatch):
    path = tmp_path / "review-config.toml"
    path.write_text('[flows]\nenable=true\naction_recipes=true\n'
                    '[security.tool_risk]\nreview_customer_lookup="low"\n'
                    'review_order_create="high"\nreview_other_mutation="high"\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    # The receipts these tests verify are signed; pin signing so they hold under
    # the suite's ordinary posture as well as the secure one.
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_TOOL_CACHE", "0")
    monkeypatch.delenv("MAVERICK_CONFIG_OVERLAY", raising=False)
    config.reset_config_cache()
    calls = []
    registry = ToolRegistry(principal="reviewer")

    def call(name, args):
        calls.append((name, copy.deepcopy(args)))
        return json.dumps({"customer_id": "runtime-customer"} if name == _LOOKUP
                          else {"order_id": "runtime-order"})

    for name in (_LOOKUP, _CREATE, _OTHER):
        registry.register(Tool(name=name, description="Local review fixture",
                               input_schema={"type": "object"},
                               fn=lambda args, tool=name: call(tool, args)))
    monkeypatch.setattr("maverick.tools.base_registry", lambda *args, **kwargs: registry)
    return execution.default_action_runner(world=None, user_id="reviewer"), calls


def _flow():
    result = recipe_flow.make_flow(_artifact(), flow_id="reviewed-action-flow", name="Reviewed actions")
    result.owner = "reviewer"
    return result


def _execute(flow, native, data, approve, run_id="review-run"):
    action, calls = native
    result = execution.execute(flow, owner="reviewer", run_id=run_id, data=data,
                               action_runner=action, agent_runner=lambda *args: pytest.fail("agent fallback"),
                               approve_fn=approve)
    assert store.load_run(run_id).status == result.status
    return result, calls


def test_original_input_mutation_cannot_change_arguments_already_shown_for_approval(native):
    supplied = {"input": {"lookup_ref": "new-ref", "quantity": 19}}
    reviewed = []

    def approve(node, data):
        reviewed.append((node.id, copy.deepcopy(data["_recipe_next_arguments"])))
        if node.id == "approval_1":
            # Simulate the original caller updating its own input object while
            # a review is outstanding; the reviewer approved the earlier copy.
            supplied["input"]["quantity"] = 9000
        return "approved"

    result, calls = _execute(_flow(), native, supplied, approve)
    assert reviewed[-1] == ("approval_1", {"customer_id": "runtime-customer", "quantity": 19})
    writes = [arguments for name, arguments in calls if name == _CREATE]
    assert not writes or writes == [{"customer_id": "runtime-customer", "quantity": 19}]
    assert result.status in {"completed", "failed", "indeterminate"}


def test_original_flow_mutation_cannot_replace_reviewed_tool_after_validation(native):
    flow = _flow()

    def approve(node, data):
        if node.id == "approval_1":
            # The registry and organization may allow both tools, but only the
            # original tool is in this recipe and the reviewed graph snapshot.
            flow.nodes["action_1"].tool = _OTHER
        return "approved"

    result, calls = _execute(flow, native, {"input": {"lookup_ref": "new-ref", "quantity": 19}}, approve)
    assert _OTHER not in [name for name, _arguments in calls]
    assert result.status in {"completed", "failed", "indeterminate"}


def test_supplied_prior_result_cannot_replace_the_result_of_the_actual_prefix(native):
    result, calls = _execute(_flow(), native,
                             {"input": {"lookup_ref": "new-ref", "quantity": 19},
                              "_recipe_step_0": {"customer_id": "forged-customer"},
                              "_recipe_next_arguments": {"customer_id": "forged-customer", "quantity": 1}},
                             lambda *args: "approved")
    assert result.status == "completed"
    assert calls == [(_LOOKUP, {"query": "new-ref"}),
                     (_CREATE, {"customer_id": "runtime-customer", "quantity": 19})]


def test_native_pause_has_no_effect_and_roundtrip_keeps_complete_recipe(native):
    flow = _flow()
    restored = type(flow).from_dict(json.loads(json.dumps(flow.to_dict())))
    assert restored.to_dict() == flow.to_dict()
    result, calls = _execute(restored, native, {"input": {"lookup_ref": "new-ref", "quantity": 19}},
                             lambda *args: "pending")
    assert result.status == "paused_approval" and result.cursor == "approval_0" and calls == []
    assert result.data["_recipe_next_arguments"] == {"query": "new-ref"}
    saved = store.load_flow_snapshot(store.load_run(result.run_id).definition_digest)
    assert saved.learned_recipe == flow.learned_recipe
    assert saved.nodes["action_0"].recipe_step == 0


def test_all_prior_shapes_are_checked_even_if_later_argument_does_not_reference_them():
    artifact = _artifact()
    decision = action_recipe.resolve_step(artifact, 1, {"lookup_ref": "new", "quantity": 9},
                                          [{"customer_id": "actual", "unreviewed": True}])
    assert decision.applied is False and decision.reason == "outside_domain"


def test_stripped_parent_recipe_never_becomes_ordinary_action_dispatch(native):
    flow = _flow()
    flow.learned_recipe = None
    with pytest.raises(ValueError, match="recipe"):
        _execute(flow, native, {"input": {"lookup_ref": "new", "quantity": 9}}, lambda *args: "approved")
    assert native[1] == []


def test_durable_resume_cannot_accept_a_caller_invented_checkpoint(native):
    action, calls = native
    data = {"input": {"lookup_ref": "new", "quantity": 9},
            "_recipe_step_0": {"customer_id": "caller-supplied"}}
    with pytest.raises(ValueError, match="no such flow run"):
        execution.execute(_flow(), resume_run_id="invented-unpersisted-run", data=data,
                          decision="approved", decided_by="reviewer", action_runner=action,
                          agent_runner=lambda *args: pytest.fail("agent"))
    assert calls == []


def test_approval_callback_mutating_its_node_and_data_cannot_rewrite_the_run(native):
    flow = _flow()

    def approve(node, data):
        node.next = None
        node.kind = "action"
        data["input"]["quantity"] = 9000
        data["_recipe_next_arguments"] = {"customer_id": "not-reviewed", "quantity": 9000}
        data["_recipe_step_0"] = {"customer_id": "forged-customer"}
        return "approved"

    result, calls = _execute(flow, native, {"input": {"lookup_ref": "new-ref", "quantity": 19}}, approve)
    assert result.status == "completed"
    assert calls == [(_LOOKUP, {"query": "new-ref"}),
                     (_CREATE, {"customer_id": "runtime-customer", "quantity": 19})]
    assert result.data["input"] == {"lookup_ref": "new-ref", "quantity": 19}
    assert result.data["_recipe_step_0"] == {"customer_id": "runtime-customer"}
    assert flow.nodes["approval_0"].kind == "approval" and flow.nodes["approval_0"].next == "action_0"


def test_executor_mutation_after_dispatch_cannot_change_later_bindings_or_receipt(native):
    original, calls = native

    def executor(tool, params, data):
        result = original(tool, params, data)
        params.clear()
        params["unreviewed"] = 9000
        data["input"]["quantity"] = 9000
        data["_recipe_step_0"] = {"customer_id": "forged-customer"}
        return result

    flow = _flow()
    result, _ = _execute(flow, (executor, calls), {"input": {"lookup_ref": "new-ref", "quantity": 19}},
                         lambda *args: "approved")
    assert result.status == "completed"
    assert calls == [(_LOOKUP, {"query": "new-ref"}),
                     (_CREATE, {"customer_id": "runtime-customer", "quantity": 19})]
    assert result.data["input"]["quantity"] == 19
    assert store.load_run(result.run_id).data["_recipe_step_0"] == {"customer_id": "runtime-customer"}
    events = list(audit.iter_events(all_days=True, strict=True, verify=True))
    decisions = [event for event in events if event["kind"] == audit.EventKind.FLOW_ACTION_RECIPE_DECISION]
    assert len(decisions) == 4
    for event in decisions:
        arguments = calls[event["step_index"]][1]
        canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        assert event["arguments_sha256"] == hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        assert event["flow_run_id"] == result.run_id and event["sig"]


def _resume_attestation(run, submitted_inputs):
    from maverick.flow.approvals import flow_decision_attestation_material, paused_operation_binding
    from maverick_dashboard.approval_authority import issue_flow_decision_attestation

    current = store.load_run(run.run_id)
    binding = paused_operation_binding(current, inputs=submitted_inputs)
    material = flow_decision_attestation_material(
        current, inputs=submitted_inputs, operation_binding_sha256=binding,
        authority_binding_sha256="", decision="approved", decided_by="system:direct")
    token = issue_flow_decision_attestation(None, material=material,
                                           expires_at=float(current.human["approval_card"]["expires_at"]))
    return binding, token


@pytest.mark.parametrize("injection", ["input", "prior_result"])
def test_signed_durable_resume_cannot_overwrite_reviewed_inputs_or_completed_result(native, injection):
    flow = _flow()
    data = {"input": {"lookup_ref": "new-ref", "quantity": 19}}
    paused, calls = _execute(flow, native, data,
                             lambda node, _data: "approved" if node.id == "approval_0" else "pending")
    assert paused.status == "paused_approval" and paused.cursor == "approval_1"
    assert calls == [(_LOOKUP, {"query": "new-ref"})]
    submitted = ({"input": {"lookup_ref": "other", "quantity": 9000}} if injection == "input"
                 else {"_recipe_step_0": {"customer_id": "forged-customer"}})
    binding, token = _resume_attestation(paused, submitted)
    resumed = execution.execute(flow, resume_run_id=paused.run_id, inputs=submitted,
                                decision="approved", decided_by="system:direct",
                                approval_binding_sha256=binding, approval_decision_attestation=token,
                                action_runner=native[0], agent_runner=lambda *args: pytest.fail("agent"))
    assert resumed.status == "completed", resumed.error
    assert calls == [(_LOOKUP, {"query": "new-ref"}),
                     (_CREATE, {"customer_id": "runtime-customer", "quantity": 19})]
    assert resumed.data["input"] == data["input"]
    assert resumed.data["_recipe_step_0"] == {"customer_id": "runtime-customer"}
