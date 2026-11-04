"""Independent execution-policy boundaries; signed source services tested separately."""
from __future__ import annotations

import copy

import pytest
from maverick import audit, config, learning_guard
from maverick.audit.errors import AuditRefused
from maverick.flow import action_recipe, recipe_flow, recipe_lineage, runner, store
from maverick.flow.ir import Flow, FlowNode


@pytest.fixture
def setup(monkeypatch):
    episodes = [{"id": f"e{n}", "inputs": {"code": f"sku{n}"}, "steps": [
        {"tool": "crm_lookup", "arguments": {"code": f"sku{n}"}, "result": {"id": f"item{n}"}},
        {"tool": "crm_create", "arguments": {"id": f"item{n}"}, "result": {"id": f"order{n}"}},
    ]} for n in range(2)]
    artifact = action_recipe.synthesize(episodes, allowed_tools=["crm_lookup", "crm_create"])
    flow = recipe_flow.make_flow(artifact, flow_id="lineage-runtime", name="Governed")
    flow.owner = "owner"
    flow.recipe_lineage = {"schema": recipe_lineage.REFERENCE_SCHEMA, "id": "LRA-" + "1" * 32,
                           "package_sha256": "2" * 64, "artifact_sha256": artifact["artifact_sha256"]}
    settings = {"action_recipes": True, "action_recipe_lineage": True, "require_action_recipe_lineage": True}
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.setattr(config, "get_flows", lambda: settings)
    monkeypatch.setattr(learning_guard, "check_learning_halt", lambda *args: None)
    receipts, checks, calls = [], [], []
    monkeypatch.setattr(audit, "record", lambda kind, **payload: receipts.append(payload) or True)

    def current(reference, artifact, *, owner):
        checks.append((copy.deepcopy(reference), artifact["artifact_sha256"], owner))
        return {"id": reference["id"], "package_sha256": reference["package_sha256"],
                "artifact_sha256": artifact["artifact_sha256"], "checked_at": len(checks),
                "use_until": 9999999999, "current_eligibility": "accepted"}

    monkeypatch.setattr(recipe_lineage, "runtime_reference", current)

    def action(node, params, data):
        calls.append((node.tool, params))
        return {"id": "live-item" if len(calls) == 1 else "live-order"}, 1.0

    def run(**kwargs):
        return runner.run_flow(flow, run_id="durable-run", data={"input": {"code": "new"}},
                               action_fn=action, agent_fn=lambda *args: pytest.fail("fallback"),
                               approve_fn=kwargs.pop("approve_fn", lambda *args: "approved"), **kwargs)

    return flow, settings, receipts, checks, calls, run


def test_checks_before_proposal_and_each_dispatch_and_attributes_receipts(setup):
    flow, _, receipts, checks, calls, run = setup
    assert run().status == "completed"
    # Proposal, pre-receipt selection and final post-receipt dispatch check.
    assert len(calls) == 2 and len(checks) == 6
    assert all(row[2] == flow.owner for row in checks)
    assert all(row["recipe_lineage"]["id"] == flow.recipe_lineage["id"] for row in receipts)
    assert [r["recipe_lineage"]["checked_at"] for r in receipts] == [2, 3, 5, 6]
    assert all(row["flow_run_id"] == "durable-run" for row in receipts)


@pytest.mark.parametrize("exception", [ValueError, PermissionError, LookupError, RuntimeError, OSError])
def test_unavailable_evidence_after_prefix_stops_preserving_completed_work(setup, monkeypatch, exception):
    _, _, receipts, _, calls, run = setup
    original = recipe_lineage.runtime_reference

    def current(*args, **kwargs):
        if calls:
            raise exception("withdrawn, expired, revoked or unavailable")
        return original(*args, **kwargs)

    monkeypatch.setattr(recipe_lineage, "runtime_reference", current)
    result = run()
    assert result.status == "indeterminate" and len(calls) == 1
    assert result.data["_recipe_step_0"] == {"id": "live-item"}
    assert "evidence_ineligible" in result.error
    assert receipts[-1]["status"] == "blocked" and "recipe_lineage" not in receipts[-1]


def test_withdrawal_during_approval_is_rechecked_before_dispatch(setup):
    _, settings, _, _, calls, run = setup

    def approve(*args):
        settings["action_recipe_lineage"] = False
        return "approved"

    # The existing high-risk dispatch boundary conservatively quarantines a
    # rejected attempt; the receipt still identifies that selection was blocked.
    assert run(approve_fn=approve).status == "indeterminate"
    assert calls == []


def test_pending_audit_is_control_stop_without_dispatch(setup, monkeypatch):
    _, _, _, _, calls, run = setup

    def pending(*args, **kwargs):
        raise recipe_lineage.RecipeLineageAuditPending("pending")

    monkeypatch.setattr(recipe_lineage, "runtime_reference", pending)
    with pytest.raises(AuditRefused):
        run()
    assert calls == []


def test_required_policy_refuses_stripped_reference_without_trusting_caller_data(setup):
    flow, _, _, checks, calls, run = setup
    flow.recipe_lineage = None
    result = run()
    assert result.status == "failed" and calls == checks == []


def test_data_and_approval_callbacks_cannot_replace_definition_evidence(setup):
    flow, _, _, checks, calls, run = setup
    original = copy.deepcopy(flow.recipe_lineage)

    def approve(node, data):
        data["recipe_lineage"] = {"id": "forged", "owner": "victim"}
        data["_recipe_lineage_check"] = {"current_eligibility": "accepted"}
        flow.recipe_lineage["id"] = "LRA-" + "9" * 32
        flow.owner = "victim"
        return "approved"

    assert run(approve_fn=approve).status == "completed" and len(calls) == 2
    assert all(row[0] == original and row[2] == "owner" for row in checks)


def test_structural_reference_edit_and_orphan_are_rejected(setup):
    flow, _, _, _, calls, run = setup
    flow.recipe_lineage["artifact_sha256"] = "0" * 64
    assert flow.validate() and run().status == "failed" and not calls
    flow.learned_recipe = None
    assert any("lineage" in error for error in flow.validate())


def test_roundtrip_and_nested_persistence_enforce_required_policy(setup, tmp_path, monkeypatch):
    flow, _, _, _, _, _ = setup
    restored = Flow.from_dict(flow.to_dict())
    assert restored.recipe_lineage == flow.recipe_lineage
    restored.recipe_lineage["id"] = "different"
    assert flow.recipe_lineage["id"] != "different"
    monkeypatch.setattr(store, "_flows_dir", lambda: tmp_path)
    flow.recipe_lineage = None
    parent = Flow("parent", "Parent", "scope", nodes={"scope": FlowNode("scope", "scope", body=flow)})
    with pytest.raises(ValueError, match="admitted signed evidence"):
        store.save_flow(parent)
    assert not (tmp_path / "parent.json").exists()
    with pytest.raises(ValueError, match="admitted signed evidence"):
        store.snapshot_flow_bundle(parent)


def test_raw_operator_assertion_still_runs_when_policy_explicitly_allows(setup):
    flow, settings, receipts, checks, calls, run = setup
    flow.recipe_lineage = None
    settings["require_action_recipe_lineage"] = False
    settings["action_recipe_lineage"] = False
    assert run().status == "completed" and len(calls) == 2 and checks == []
    assert all("recipe_lineage" not in row for row in receipts)


@pytest.mark.parametrize("capture,lineage,required,blocked", [
    (True, False, False, True),
    (False, True, False, True),
    (True, True, False, True),
    (False, False, True, True),
    (False, False, False, False),
])
def test_customer_learning_flags_require_signed_lineage_even_when_explicit_toggle_is_off(
    setup, capture, lineage, required, blocked,
):
    flow, settings, _, checks, calls, run = setup
    flow.recipe_lineage = None
    settings.update(action_episode_capture=capture, action_recipe_lineage=lineage,
                    require_action_recipe_lineage=required)
    if blocked:
        with pytest.raises(ValueError, match="admitted signed evidence"):
            recipe_flow.check_persisted_lineage(flow)
        assert run().status == "failed" and calls == checks == []
    else:
        recipe_flow.check_persisted_lineage(flow)
        assert run().status == "completed" and len(calls) == 2


@pytest.mark.parametrize("container", ["root", "scope", "subflow"])
def test_denied_snapshot_writes_no_content_addressed_objects(setup, monkeypatch, container):
    child, _, _, _, _, _ = setup
    child.recipe_lineage = None
    if container == "root":
        parent = child
    else:
        node = FlowNode("nested", container)
        if container == "scope":
            node.body = child
        else:
            node.flow_ref = child.id
        parent = Flow("parent", "Parent", node.id, nodes={node.id: node}, owner="owner")
    monkeypatch.setattr(store, "load_flow", lambda identity: child if identity == child.id else None)
    written = []
    monkeypatch.setattr(store, "_store_flow_object", lambda raw: written.append(raw) or "digest")
    with pytest.raises(ValueError, match="admitted signed evidence"):
        store.snapshot_flow_bundle(parent)
    assert written == []


@pytest.mark.parametrize("container", ["scope", "parallel", "subflow"])
@pytest.mark.parametrize("child_owner", ["", "owner", "foreign-owner"])
def test_nested_recipe_evidence_uses_root_authority(setup, container, child_owner):
    child, _, _, checks, _, _ = setup
    child.owner = child_owner
    node = FlowNode("container", container)
    if container == "parallel":
        node.branches = [child]
    elif container == "subflow":
        node.flow_ref = child.id
    else:
        node.body = child
    parent = Flow("outer", "Outer", node.id, nodes={node.id: node}, owner="owner")
    calls = []

    def action(node, params, data):
        calls.append(params)
        return {"id": "fresh"}, 1.0

    result = runner.run_flow(parent, action_fn=action, agent_fn=lambda *args: pytest.fail("agent"),
        approve_fn=lambda *args: "approved", data={"input": {"code": "fresh"}},
        resolve_flow=lambda identity: child if identity == child.id else None)
    if child_owner == "foreign-owner":
        assert result.status != "completed" and calls == checks == []
        if container != "subflow":
            with pytest.raises(ValueError, match="authoritative execution owner"):
                recipe_flow.check_persisted_lineage(parent)
    else:
        assert result.status == "completed" and len(calls) == 2
        assert len(checks) == 6 and all(row[2] == "owner" for row in checks)


@pytest.mark.parametrize("value,enabled,required", [
    (True, True, True), (False, False, False), ("false", False, True), (None, False, True), (0, False, True),
])
def test_config_is_strict_and_malformed_restriction_fails_closed(monkeypatch, value, enabled, required):
    monkeypatch.setattr(config, "load_config", lambda: {"flows": {
        "action_recipe_lineage": value, "require_action_recipe_lineage": value,
        "action_evidence_issuer": 42, "action_evidence_revoked_keys": "invalid"}})
    settings = config.get_flows()
    assert settings["action_recipe_lineage"] is enabled
    assert settings["require_action_recipe_lineage"] is required
    assert settings["action_evidence_issuer"] == 42
    assert settings["action_evidence_revoked_keys"] == "invalid"
