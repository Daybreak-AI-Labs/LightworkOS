"""Learned workflows cannot downgrade required receipts to unsigned events."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest
from maverick import audit, audit_contract
from maverick.audit.errors import AuditRefused
from maverick.flow import action_recipe, execution, recipe_flow, store, workflow_recipe_flow

from test_support.action_episode_native import native as native
from test_support.workflow_memory_native import decide, redeliver
from test_support.workflow_memory_native import memory_native as memory_native
from test_support.workflow_transducer_native import workflow_native as workflow_native


@pytest.mark.parametrize("schema,required", [
    (action_recipe.SCHEMA, False), (action_recipe.CHOICE_SCHEMA, False),
    (action_recipe.WORKFLOW_SCHEMA, True), (action_recipe.MEMORY_SCHEMA, True),
])
def test_workflow_receipt_selects_strict_sink_without_changing_older_recipes(monkeypatch, schema, required):
    events = []

    def record(*args, **kwargs):
        events.append((args, kwargs))
        return True

    monkeypatch.setattr(audit, "record", record)
    recipe_flow.record_decision({"schema": schema, "artifact_sha256": "a" * 64}, flow_id="flow",
        run_id="run", node_id="decision_0", index=0, status="workflow_selected", reason="agreement",
        arguments={"private_value": "never include in the receipt"})
    assert len(events) == 1
    args, payload = events[0]
    assert args == (audit.EventKind.FLOW_ACTION_RECIPE_DECISION,)
    assert payload["_require_signed"] is required
    assert "private_value" not in str(payload) and len(payload["arguments_sha256"]) == 64


def test_recipe_receipt_is_covered_by_the_refusal_contract_scanner():
    path = Path(recipe_flow.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    assert audit_contract._imports_audit_writer(tree)
    assert audit_contract._audit_calls(tree)
    assert audit_contract.scan_file(path) == []


@pytest.fixture(params=["workflow_native", "memory_native"])
def learned_native(request):
    harness = request.getfixturevalue(request.param)

    def start(flow):
        if request.param == "memory_native":
            return harness.start(flow, 5, [2, 3])
        return harness.start(flow, {"customer": "held-out", "quantity": 5, "repeat": False})

    return harness, start


def test_disabled_signing_refuses_initial_selection_without_dispatch(learned_native, monkeypatch):
    harness, start = learned_native
    flow = harness.draft("unsigned-workflow-start")
    before = harness.counts()
    sink = audit.default_audit_log()
    monkeypatch.setattr(sink, "_signing_enabled", False)
    with pytest.raises(AuditRefused):
        start(flow)
    assert harness.counts() == before
    assert sink._signing_enabled is False  # No implicit policy change.


def test_disabled_signing_refuses_approved_action_before_effect(learned_native, monkeypatch):
    harness, start = learned_native
    run = start(harness.draft("unsigned-workflow-resume"))
    assert run.status == "paused_approval", run.error
    before = harness.counts()
    sink = audit.default_audit_log()
    monkeypatch.setattr(sink, "_signing_enabled", False)
    with pytest.raises(AuditRefused):
        decide(run.run_id)
    assert harness.counts() == before
    saved = store.load_run(run.run_id)
    assert saved.status == "paused_approval"
    assert saved.data[workflow_recipe_flow.HISTORY] == []


def test_signing_loss_after_effect_quarantines_without_history_or_replay(learned_native, monkeypatch):
    harness, start = learned_native
    run = start(harness.draft("unsigned-workflow-completion"))
    before = harness.counts()
    action = execution.default_action_runner(None, user_id="reviewer")
    sink = audit.default_audit_log()

    def lose_signing_after_action(node, params, data):
        result = action(node, params, data)
        monkeypatch.setattr(sink, "_signing_enabled", False)
        return result

    with pytest.raises(AuditRefused):
        decide(run.run_id, action_runner=lose_signing_after_action)
    assert harness.counts() == before + 1
    saved = store.load_run(run.run_id)
    assert saved.status == "indeterminate"
    assert saved.data[workflow_recipe_flow.HISTORY] == []
    assert redeliver(run.run_id).status == "indeterminate"
    assert harness.counts() == before + 1


def test_signing_withdrawal_after_selection_stops_before_dispatch(learned_native, monkeypatch):
    harness, start = learned_native
    run = start(harness.draft("signing-withdrawn-at-selected-receipt"))
    before, original = harness.counts(), audit.record
    sink, seen = audit.default_audit_log(), []

    def disable_after_receipt(*args, **kwargs):
        result = original(*args, **kwargs)
        if (args and args[0] == audit.EventKind.FLOW_ACTION_RECIPE_DECISION
                and kwargs.get("flow_run_id") == run.run_id and kwargs.get("status") == "selected"):
            assert result is True and kwargs.get("_require_signed") is True
            monkeypatch.setattr(sink, "_signing_enabled", False)
            seen.append(True)
        return result

    monkeypatch.setattr(audit, "record", disable_after_receipt)
    with pytest.raises(AuditRefused):
        decide(run.run_id)
    assert seen
    assert harness.counts() == before
    saved = store.load_run(run.run_id)
    assert saved.status == "paused_approval"
    assert saved.data[workflow_recipe_flow.HISTORY] == []
