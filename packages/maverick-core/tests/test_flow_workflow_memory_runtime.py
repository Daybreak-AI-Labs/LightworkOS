"""Real local receipt effects, signed teachers, and durable learned-memory runs."""
from __future__ import annotations

import copy
import multiprocessing

import pytest
from maverick import audit, world_model
from maverick.flow import action_recipe_transforms, store
from maverick.flow.workflow_recipe_flow import HISTORY, SELECTION

from test_support.action_episode_native import native as native
from test_support.audit_child_process import audit_signing_target
from test_support.workflow_memory_native import TOOL, child_resume, decide, redeliver
from test_support.workflow_memory_native import memory_native as memory_native


@pytest.mark.parametrize("target,quantities", [(5, [2, 3]), (5, [1, 3, 1]), (9, [1, 2, 3, 3])])
def test_actual_receipts_choose_next_call_or_end_from_cumulative_history(memory_native, target, quantities):
    h = memory_native
    baseline = h.counts()
    flow = h.draft("native-memory-procedure")
    run = h.start(flow, target, quantities)
    assert run.status == "paused_approval" and h.counts() == baseline, run.error
    artifact = h.package["artifact"]
    summaries = action_recipe_transforms._digest([model["summary"] for model in artifact["models"]])
    previous = []
    for index, quantity in enumerate(quantities):
        assert run.cursor == f"approval_{index}_0"
        assert run.data["_recipe_next_arguments"] == {"target": target}
        selection = run.data[SELECTION]
        assert selection["schema"] == "lightwork.workflow-memory-selection.v1"
        assert selection["memory_models_sha256"] == summaries
        assert selection["memory_model_count"] == artifact["model_count"]
        assert selection["history_sha256"] == action_recipe_transforms._digest(
            {"input": {"target": target}, "steps": previous})
        assert run.data[HISTORY] == previous
        run = decide(run.run_id)
        saved = store.load_run(run.run_id, owner="reviewer")
        expected = {"tool": TOOL, "arguments": {"target": target}, "result": {"quantity": quantity}}
        previous.append(expected)
        assert h.counts() == baseline + index + 1
        assert saved.data[HISTORY] == previous
        assert saved.data[f"_recipe_step_{index}"] == expected["result"]
        assert run.status == ("completed" if index + 1 == len(quantities) else "paused_approval"), run.error
        assert (sum(quantities[:index + 1]) >= target) == (run.status == "completed")
    assert run.data[SELECTION]["kind"] == "complete" and "_recipe_next_arguments" not in run.data
    actual = h.calls()[baseline:]
    assert [call["result"]["quantity"] for call in actual] == quantities
    assert all(call["arguments"] == {"target": target} for call in actual)
    assert len({call["ordinal"] for call in actual}) == len(quantities)
    assert redeliver(run.run_id).status == "completed" and h.counts() == baseline + len(quantities)
    events = [event for event in audit.iter_events(all_days=True, strict=True, verify=True)
              if event.get("flow_run_id") == run.run_id
              and event["kind"] == audit.EventKind.FLOW_ACTION_RECIPE_DECISION]
    selected = [event for event in events if event.get("status") == "workflow_selected"]
    completed = [event for event in events if event.get("status") == "completed"]
    assert len(selected) == len(quantities) + 1 and len(completed) == len(quantities)
    assert all(event.get("sig") and event["recipe_workflow"]["memory_models_sha256"] == summaries for event in events)
    assert selected[-1]["recipe_workflow"]["kind"] == "complete"
    for index, event in enumerate(completed):
        binding = event["recipe_workflow"]
        assert event["step_index"] == index
        assert binding["schema"] == "lightwork.workflow-memory-completion.v1"
        assert binding["history_sha256"] == action_recipe_transforms._digest(
            {"input": {"target": target}, "steps": previous[:index]})
        assert binding["result_sha256"] == action_recipe_transforms._digest(previous[index]["result"])
        assert binding["completed_history_sha256"] == action_recipe_transforms._digest(
            {"input": {"target": target}, "steps": previous[:index + 1]})
    assert all("quantity" not in event and "arguments" not in event for event in events)


def test_fresh_worker_reconstructs_accumulator_from_retained_native_receipts(memory_native):
    h = memory_native
    baseline = h.counts()
    run = h.start(h.draft("memory-restart"), 7, [1, 3, 2, 1])
    run = decide(run.run_id)
    assert run.status == "paused_approval" and len(run.data[HISTORY]) == 1
    preserved = copy.deepcopy(run.data[HISTORY])
    process = multiprocessing.get_context("spawn").Process(target=audit_signing_target(child_resume),
        args=(run.run_id, str(h.journal), str(h.schedule), str(world_model.DEFAULT_DB), copy.deepcopy(h.flags)))
    process.start()
    process.join(60)
    if process.is_alive():
        process.terminate()
        process.join(5)
        pytest.fail("fresh worker did not finish one authenticated native memory continuation")
    assert process.exitcode == 0
    run = store.load_run(run.run_id, owner="reviewer")
    assert run.status == "paused_approval" and len(run.data[HISTORY]) == 2
    assert run.data[HISTORY][:1] == preserved and h.counts() == baseline + 2
    run = decide(run.run_id)
    assert run.status == "paused_approval" and h.counts() == baseline + 3
    run = decide(run.run_id)
    assert run.status == "completed" and h.counts() == baseline + 4, run.error
    assert [step["result"]["quantity"] for step in run.data[HISTORY]] == [1, 3, 2, 1]
