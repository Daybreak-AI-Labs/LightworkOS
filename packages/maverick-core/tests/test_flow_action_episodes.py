"""Native local dispatch capture; fixtures perform no external connector calls."""
from __future__ import annotations

import copy
import importlib
import json

import pytest
from maverick import audit, config, tools, world_model
from maverick.flow import Flow, FlowNode, execution, store
from maverick.flow.action_episodes import ActionEpisodeCapture
from maverick.paths import tenant_scope

INPUTS = {"customer": "ACME", "quantity": 3}


@pytest.fixture
def native(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.setattr(config, "get_flows", lambda: {"enable": True, "action_recipes": True})
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "capture-world.db")
    risk_module = importlib.import_module("maverick.safety.tool_risk")
    monkeypatch.setattr(risk_module, "_load_overrides", lambda: {
        "episode_lookup": "low", "episode_update": "high",
    })
    calls = []
    outputs = {"episode_lookup": '{"customer_id":"C42","active":true}',
               "episode_update": '{"updated":true,"revision":2}'}
    registry = tools.ToolRegistry(principal="reviewer")

    def perform(name, args):
        calls.append((name, copy.deepcopy(args)))
        value = outputs[name]
        return value(args) if callable(value) else value

    for name in outputs:
        registry.register(tools.Tool(
            name=name, description="Local bounded capture fixture", input_schema={
                "type": "object", "properties": {"query": {"type": "string"}},
            }, fn=lambda args, name=name: perform(name, args),
        ))
    monkeypatch.setattr(tools, "base_registry", lambda *args, **kwargs: registry)
    return calls, outputs, registry


def flow(*, one_step=False, save=True, owner="reviewer", retries=0):
    result = Flow(id="captured-actions", name="Captured actions", owner=owner, start="review", nodes={
        "review": FlowNode(id="review", kind="approval", prompt="Review local fixture changes", next="lookup"),
        "lookup": FlowNode(id="lookup", kind="action", tool="episode_lookup", output="found",
                           params={"query": "{{input.customer}}", "limit": 3}, retries=retries,
                           next=None if one_step else "review_update"),
    })
    if not one_step:
        result.nodes["review_update"] = FlowNode(
            id="review_update", kind="approval", prompt="Review exact fixture update", next="update",
        )
        result.nodes["update"] = FlowNode(
            id="update", kind="action", tool="episode_update", output="changed",
            params={"customer_id": "C42", "quantity": 3, "confirm": True},
        )
    if save:
        store.save_flow(result)
    return result


def capture(*, inputs=None, allowed=None, max_steps=8):
    return ActionEpisodeCapture(
        input_data=INPUTS if inputs is None else inputs,
        allowed_tools=["episode_lookup", "episode_update"] if allowed is None else allowed,
        max_steps=max_steps,
    )


def run(source, collector, *, data=None, action_runner=None, approve=True, record_outcomes=True):
    def no_agent(*args, **kwargs):
        pytest.fail("the admitted action episode cannot dispatch an agent")

    return execution.execute(
        source, owner=source.owner,
        data={"input": copy.deepcopy(INPUTS)} if data is None else data,
        action_runner=(execution.default_action_runner(None, user_id="reviewer")
                       if action_runner is None else action_runner),
        agent_runner=no_agent, approve_fn=(lambda *args: "approved") if approve else None,
        episode_capture=collector, record_outcomes=record_outcomes,
    )


def exported(collector):
    return collector.export(reviewed=True, rationale="Reviewed the actual local fixture steps.")


def test_native_governed_actions_export_typed_data_and_signed_call_provenance(native):
    source, collector = flow(), capture()
    result = run(source, collector)
    assert result.status == "completed"
    assert collector.status == "complete"
    bundle = exported(collector)
    assert bundle["episode"] == {
        "id": result.run_id, "inputs": INPUTS,
        "steps": [
            {"tool": "episode_lookup", "arguments": {"query": "ACME", "limit": 3},
             "result": {"customer_id": "C42", "active": True}},
            {"tool": "episode_update", "arguments": {"customer_id": "C42", "quantity": 3, "confirm": True},
             "result": {"updated": True, "revision": 2}},
        ],
    }
    assert type(bundle["episode"]["steps"][0]["arguments"]["limit"]) is int
    provenance = bundle["provenance"]
    assert provenance["family"] == "native_governed_flow_actions_v1"
    assert provenance["run_id"] == result.run_id
    assert provenance["flow_id"] == source.id
    assert provenance["owner"] == source.owner
    assert provenance["definition_digest"] == result.definition_digest
    assert provenance["definition_version"] == source.version
    assert provenance["definition_revision"] == source.revision
    assert [step["node_id"] for step in provenance["steps"]] == ["lookup", "update"]
    assert all(len(step["step_sha256"]) == 64 and len(step["tool_schema_sha256"]) == 64
               for step in provenance["steps"])
    assert bundle["review"]["authenticated"] is False
    assert bundle["review"]["authority"] == "local_caller_assertion"
    events = list(audit.iter_events(all_days=True, strict=True, verify=True))
    call_ids = [step["call_id"] for step in provenance["steps"]]
    assert len(set(call_ids)) == 2
    for call_id in call_ids:
        pair = [event for event in events if event.get("call_id") == call_id]
        assert [event["kind"] for event in pair] == ["tool_call", "tool_result"]
        assert all(event["sig"] for event in pair)
        assert pair[1]["status"] == "ok" and pair[1]["disposition"] == "completed"
    assert len(native[0]) == 2
    assert store.load_run(result.run_id, owner=source.owner).status == "completed"


def test_export_and_initial_inputs_are_independent_copies(native):
    inputs = copy.deepcopy(INPUTS)
    collector = capture(inputs=inputs)
    inputs["customer"] = "caller-changed"
    leaked_copy = collector.input_data
    leaked_copy["customer"] = "caller-changed-again"
    run(flow(), collector)
    first = exported(collector)
    first["episode"]["steps"][0]["arguments"]["query"] = "altered"
    assert exported(collector)["episode"]["steps"][0]["arguments"]["query"] == "ACME"


@pytest.mark.parametrize("value", [False, None, 1, "true"])
def test_feature_requires_literal_true_and_does_not_change_execution(native, monkeypatch, value):
    monkeypatch.setattr(config, "get_flows", lambda: {"action_recipes": value})
    collector = capture()
    assert run(flow(), collector).status == "completed"
    assert len(native[0]) == 2 and collector.status == "unusable"
    with pytest.raises(ValueError, match="complete exportable"):
        exported(collector)


def test_successful_injected_runner_cannot_attest_native_capture(native):
    collector = capture()
    calls = []

    def injected(name, params, data):
        calls.append(name)
        return '{"ok":true}', 1.0

    assert run(flow(), collector, action_runner=injected).status == "completed"
    assert calls == ["episode_lookup", "episode_update"]
    assert native[0] == [] and collector.status == "unusable"
    with pytest.raises(ValueError):
        exported(collector)


@pytest.mark.parametrize("source_kind", ["unsaved", "ownerless", "retry", "unselected", "step_limit"])
def test_ineligible_sources_never_change_the_native_action_result(native, source_kind):
    source = flow(save=source_kind != "unsaved", owner="" if source_kind == "ownerless" else "reviewer",
                  retries=1 if source_kind == "retry" else 0)
    collector = capture(allowed=["episode_lookup"] if source_kind == "unselected" else None,
                        max_steps=1 if source_kind == "step_limit" else 8)
    result = run(source, collector)
    assert result.status == "completed" and len(native[0]) == 2
    assert collector.status == "unusable"


def test_saved_definition_must_exactly_match_the_executed_snapshot(native):
    source = flow()
    source.nodes["lookup"].params["limit"] = 9
    collector = capture()
    assert run(source, collector).status == "completed"
    assert native[0][0][1]["limit"] == 9
    assert collector.status == "unusable"


@pytest.mark.parametrize("inputs", [
    {"customer": "DIFFERENT", "quantity": 3}, {"customer": "ACME"},
    {"customer": "ACME", "quantity": True},
])
def test_selected_inputs_must_match_the_actual_complete_input_object(native, inputs):
    collector = capture(inputs=inputs)
    assert run(flow(), collector).status == "completed"
    assert collector.status == "unusable"


def test_complete_top_level_initial_data_can_be_used_without_input_wrapper(native):
    source = flow(one_step=True)
    source.nodes["lookup"].params["query"] = "{{customer}}"
    store.save_flow(source)
    collector = capture()
    assert run(source, collector, data=copy.deepcopy(INPUTS)).status == "completed"
    assert exported(collector)["episode"]["inputs"] == INPUTS


@pytest.mark.parametrize("payload", [
    "not JSON", "[1,2]", '{"x":1,"x":2}', '{"value":NaN}',
    '{"truncated":true,"preview":"partial"}', '{"pending":true,"body":{"id":"A"}}',
    '{"nested":{"complete":false}}', '{"dry_run":true}',
    '{"password":"ordinary"}', '{"value":"***redacted***"}',  # pragma: allowlist secret
    json.dumps({"value": "x" * 17000}),
], ids=["text", "array", "duplicate", "nan", "truncated", "pending", "incomplete",
        "preview", "credential", "redacted", "oversized"])
def test_incomplete_or_private_results_are_unusable_without_replaying_success(native, payload):
    native[1]["episode_lookup"] = payload
    collector = capture()
    result = run(flow(one_step=True), collector)
    assert result.status == "completed"
    assert result.data["found"] == payload
    assert len(native[0]) == 1 and collector.status == "unusable"


@pytest.mark.parametrize("payload", ["ERROR: failed", "REFUSED: denied", "DRY RUN: preview", "INDETERMINATE: reconcile"])
def test_failed_refused_preview_and_uncertain_results_are_not_examples(native, payload):
    native[1]["episode_lookup"] = payload
    collector = capture()
    result = run(flow(one_step=True), collector)
    assert result.status != "completed"
    assert len(native[0]) == 1 and collector.status == "unusable"


def test_terminal_audit_failure_after_effect_remains_indeterminate_and_not_replayed(native, monkeypatch):
    original = audit.audit_event

    def refuse_terminal(kind, **kwargs):
        return False if kind == audit.EventKind.TOOL_RESULT else original(kind, **kwargs)

    monkeypatch.setattr(audit, "audit_event", refuse_terminal)
    collector = capture()
    result = run(flow(one_step=True), collector)
    assert result.status == "indeterminate"
    assert len(native[0]) == 1 and collector.status == "unusable"


def test_native_authorization_denial_produces_no_observation_or_effect(native, monkeypatch):
    from maverick import tool_authz

    monkeypatch.setattr(tool_authz, "authorize", lambda *args, **kwargs: "REFUSED: current policy")
    collector = capture()
    assert run(flow(one_step=True), collector).status != "completed"
    assert native[0] == [] and collector.status == "unusable"


def test_legacy_secret_expressions_refuse_before_capture_or_effect(native, monkeypatch):
    from maverick import secret_provider

    monkeypatch.setattr(secret_provider, "get_secret", lambda name: pytest.fail("Flow must not read deployment secrets"))
    source = flow(one_step=True)
    source.nodes["lookup"].params["query"] = "{{secret('CAPTURE_TEST')}}"
    store.save_flow(source)
    collector = capture()
    result = run(source, collector)
    assert result.status == "failed" and "Connections" in result.error
    assert native[0] == []
    assert collector.status == "unusable"


def test_optional_post_effect_capture_failure_preserves_success_without_repeat(native, monkeypatch):
    from maverick.flow import action_episodes

    def failure(_value):
        raise OSError("local evidence serialization unavailable")

    monkeypatch.setattr(action_episodes, "_result_object", failure)
    collector = capture()
    assert run(flow(), collector).status == "completed"
    assert len(native[0]) == 2 and collector.status == "unusable"


def test_arguments_are_copied_before_a_tool_mutates_them(native):
    def mutate(args):
        args["query"] = "changed inside fixture"
        return '{"ok":true}'

    native[1]["episode_lookup"] = mutate
    collector = capture()
    assert run(flow(one_step=True), collector).status == "completed"
    assert exported(collector)["episode"]["steps"][0]["arguments"]["query"] == "ACME"


def test_paused_and_dry_runs_cannot_be_exported(native):
    source = flow()
    paused_capture = capture()
    assert run(source, paused_capture, approve=False).status == "paused_approval"
    assert paused_capture.status == "unusable" and native[0] == []
    dry_capture = capture()
    assert run(source, dry_capture, record_outcomes=False).status == "completed"
    assert dry_capture.status == "unusable"


def test_collector_cannot_be_reused_for_another_run(native):
    source, collector = flow(), capture()
    assert run(source, collector).status == "completed"
    assert collector.status == "complete"
    assert run(source, collector).status == "completed"
    assert collector.status == "unusable" and len(native[0]) == 4


@pytest.mark.parametrize("reviewed,rationale", [(False, "reviewed"), (1, "reviewed"), (True, ""), (True, "   ")])
def test_export_requires_explicit_local_review(native, reviewed, rationale):
    collector = capture()
    run(flow(one_step=True), collector)
    with pytest.raises(ValueError, match="explicit local review"):
        collector.export(reviewed=reviewed, rationale=rationale)


def test_export_cannot_change_tenant(native):
    with tenant_scope(tenant="capture-tenant"):
        collector = capture()
        assert run(flow(one_step=True), collector).status == "completed"
        assert exported(collector)["provenance"]["tenant"] == "capture-tenant"
    with tenant_scope(tenant="other-tenant"):
        with pytest.raises(ValueError, match="another tenant"):
            exported(collector)


@pytest.mark.parametrize("inputs", [{"api_token": "example"}, {"customer": "{{secret('NAME')}}"},
                                   {"customer": object()}, {"customer": float("inf")}])
def test_input_contract_rejects_secrets_non_json_and_nonfinite_values(inputs):
    with pytest.raises(ValueError):
        capture(inputs=inputs)


def test_native_capture_to_learned_recipe_executes_new_live_result_bindings(native):
    from maverick.flow import action_recipe, recipe_flow

    # These are source executions with reviewed concrete arguments, not hand-
    # assembled learner steps. The native runner records all training steps.
    customer_ids = {"ACME": "C42", "BRAVO": "C93", "CHARLIE": "NEW-LIVE-C117"}
    native[1]["episode_lookup"] = lambda args: json.dumps({
        "customer_id": customer_ids[args["query"]], "active": True,
    })
    bundles = []
    for index, (customer, quantity) in enumerate((("ACME", 3), ("BRAVO", 7))):
        business_inputs = {"customer": customer, "quantity": quantity}
        source = flow(save=False)
        source.id = f"reviewed-source-{index}"
        source.nodes["update"].params.update(
            customer_id=customer_ids[customer], quantity=quantity,
        )
        store.save_flow(source)
        collector = capture(inputs=business_inputs)
        observed_run = run(source, collector, data={"input": business_inputs})
        assert observed_run.status == "completed"
        bundle = exported(collector)
        assert bundle["provenance"]["run_id"] == observed_run.run_id
        assert bundle["review"]["reviewed"] is True
        bundles.append(bundle)
    assert len(native[0]) == 4
    artifact = action_recipe.synthesize(
        [bundle["episode"] for bundle in bundles],
        allowed_tools=["episode_lookup", "episode_update"],
    )
    learned = recipe_flow.make_flow(
        artifact, flow_id="learned-from-native-runs", name="Reviewed captured work",
    )
    learned.owner = "reviewer"
    store.save_flow(learned)
    new_inputs = {"customer": "CHARLIE", "quantity": 11}
    completed = run(learned, None, data={"input": new_inputs})
    assert completed.status == "completed", completed.error
    assert native[0][4:] == [
        ("episode_lookup", {"query": "CHARLIE", "limit": 3}),
        ("episode_update", {"customer_id": "NEW-LIVE-C117", "quantity": 11, "confirm": True}),
    ]
    assert completed.data["_recipe_step_0"]["customer_id"] == "NEW-LIVE-C117"
    assert completed.data["_recipe_step_1"] == {"updated": True, "revision": 2}
    assert store.load_run(completed.run_id, owner="reviewer").status == "completed"
    pinned = store.load_flow_snapshot(completed.definition_digest)
    assert pinned.learned_recipe == artifact
