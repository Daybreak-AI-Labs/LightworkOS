"""Authority and receipt boundaries for inferred native history computations."""
from __future__ import annotations

import copy

import pytest
from maverick import audit
from maverick.audit.errors import AuditRefused
from maverick.flow import action_recipe, execution, recipe_flow, store, workflow_recipe_flow

from test_support.workflow_memory_native import decide, redeliver
from test_support.workflow_memory_native import memory_native as memory_native
from test_support.workflow_memory_native import native as native


def test_memory_adapters_require_history_and_exact_admitted_graph(memory_native, monkeypatch):
    h = memory_native
    artifact = h.package["artifact"]
    action_recipe.validate_artifact(artifact)
    assert artifact["schema"] == action_recipe.MEMORY_SCHEMA
    assert action_recipe.resolve_step(artifact, 0, {"target": 5}, []).reason == "workflow_history_required"
    action_recipe.validate_result(artifact, 0, {"quantity": 2}, tool="memory_receipt")
    with pytest.raises(ValueError):
        action_recipe.validate_result(artifact, 0, {"quantity": True}, tool="memory_receipt")
    raw = recipe_flow.make_flow(artifact, flow_id="memory-unadmitted", name="Unadmitted")
    raw.owner = h.context.resource_owner
    with pytest.raises(ValueError, match="admitted signed evidence"):
        store.save_flow(raw)
    flow = h.draft("memory-exact")
    for mutate in (lambda f: setattr(f.nodes["action_0_0"], "next", None),
                   lambda f: setattr(f.nodes["action_0_0"], "retries", 1),
                   lambda f: setattr(f, "start", "action_0_0")):
        changed = copy.deepcopy(flow)
        mutate(changed)
        with pytest.raises(ValueError, match="graph changed|nodes changed"):
            store.save_flow(changed)
    with monkeypatch.context() as smaller_storage:
        smaller_storage.setattr(store, "_MAX_FLOW_DEFINITION_BYTES", 1)
        with pytest.raises(ValueError, match="storage limit"):
            recipe_flow.make_flow(artifact, flow_id="memory-oversized", name="Too large")
        with pytest.raises(ValueError, match="storage limit"):
            h.lineage.draft(h.context, h.admission["id"], flow_id="memory-oversized", name="Too large")


def test_memory_flag_is_strict_at_admission_draft_and_dispatch(memory_native):
    h = memory_native
    flow = h.draft("memory-strict-flag")
    before = h.counts()
    for value in (False, 1, "true", None):
        h.flags["action_workflow_memory_learning"] = value
        with pytest.raises(PermissionError, match="memory"):
            h.lineage.admit(h.context, h.package)
        with pytest.raises(ValueError, match="memory"):
            store.save_flow(flow)
        with pytest.raises(ValueError, match="memory"):
            h.start(flow, 5, [2, 3])
        assert h.counts() == before
    h.flags["action_workflow_memory_learning"] = True


def test_memory_receipt_binds_every_summary_and_rejects_changed_digest(memory_native):
    h = memory_native
    artifact = h.package["artifact"]
    run = h.start(h.draft("memory-summary-binding"), 5, [2, 3])
    assert run.status == "paused_approval", run.error
    selection = run.data[workflow_recipe_flow.SELECTION]
    assert selection["schema"] == "lightwork.workflow-memory-selection.v1"
    assert selection["memory_model_count"] == len(artifact["models"])
    assert len(selection["memory_models_sha256"]) == 64
    assert workflow_recipe_flow.selected_binding(artifact, run.data, 0, "memory_receipt") == selection
    for field, replacement in (("memory_models_sha256", "0" * 64), ("memory_model_count", 0)):
        changed = copy.deepcopy(run.data)
        changed[workflow_recipe_flow.SELECTION][field] = replacement
        with pytest.raises(ValueError, match="actual history"):
            workflow_recipe_flow.selected_binding(artifact, changed, 0, "memory_receipt")
    events = [event for event in audit.iter_events(all_days=True, strict=True, verify=True)
              if event.get("flow_run_id") == run.run_id
              and event["kind"] == audit.EventKind.FLOW_ACTION_RECIPE_DECISION]
    assert events and all(event.get("sig") for event in events)
    assert events[-1]["recipe_workflow"] == selection
    assert not {"models", "summary", "quantity", "target"}.intersection(events[-1]["recipe_workflow"])


def test_memory_disable_during_receipt_stops_dispatch_and_completion(memory_native, monkeypatch):
    h = memory_native
    for ordinal, (status, index) in enumerate((("workflow_selected", 1), ("selected", 1),
                                              ("workflow_selected", 2))):
        h.flags["action_workflow_memory_learning"] = True
        run = h.start(h.draft("memory-boundary-" + str(ordinal)), 5, [2, 3])
        if status == "selected" or index == 2:
            run = decide(run.run_id)
        assert run.status == "paused_approval", run.error
        before = h.counts()
        original, seen = audit.record, []

        def record(*args, _write=original, _run_id=run.run_id, _status=status, _index=index, _seen=seen, **kwargs):
            receipt = _write(*args, **kwargs)
            if (args and args[0] == audit.EventKind.FLOW_ACTION_RECIPE_DECISION
                    and kwargs.get("flow_run_id") == _run_id
                    and kwargs.get("status") == _status and kwargs.get("step_index") == _index):
                h.flags["action_workflow_memory_learning"] = False
                _seen.append(True)
            return receipt

        with monkeypatch.context() as boundary:
            boundary.setattr(audit, "record", record)
            stopped = decide(run.run_id)
        assert seen and stopped.status in {"failed", "indeterminate"}, stopped.error
        assert h.counts() == before + (status == "workflow_selected")
        assert len(stopped.data[workflow_recipe_flow.HISTORY]) == index
        assert redeliver(run.run_id).status == stopped.status
        assert h.counts() == before + (status == "workflow_selected")
    h.flags["action_workflow_memory_learning"] = True


def test_memory_lost_receipt_or_result_never_replays_completed_work(memory_native, monkeypatch):
    h = memory_native
    run = h.start(h.draft("memory-lost-receipt"), 5, [2, 3])
    before, original = h.counts(), audit.record

    def record(*args, **kwargs):
        receipt = original(*args, **kwargs)
        if (args and args[0] == audit.EventKind.FLOW_ACTION_RECIPE_DECISION
                and kwargs.get("flow_run_id") == run.run_id and kwargs.get("status") == "completed"):
            return 1  # An integer acknowledgement is not literal success.
        return receipt

    with monkeypatch.context() as boundary:
        boundary.setattr(audit, "record", record)
        with pytest.raises(AuditRefused):
            decide(run.run_id)
    assert h.counts() == before + 1
    assert store.load_run(run.run_id).status == "indeterminate"
    assert redeliver(run.run_id).status == "indeterminate" and h.counts() == before + 1
    run = h.start(h.draft("memory-lost-result"), 5, [1, 3, 1])
    run = decide(run.run_id)
    before = h.counts()
    action = execution.default_action_runner(None, user_id="reviewer")

    def lose_response(node, params, data):
        action(node, params, data)
        raise ConnectionError("lost receipt observation after native journal write")

    run = decide(run.run_id, action_runner=lose_response)
    assert run.status == "indeterminate" and h.counts() == before + 1, run.error
    assert len(run.data[workflow_recipe_flow.HISTORY]) == 1
    assert redeliver(run.run_id).status == "indeterminate" and h.counts() == before + 1
