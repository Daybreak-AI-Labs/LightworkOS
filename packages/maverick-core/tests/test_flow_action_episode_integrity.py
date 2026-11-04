"""Independent native-path checks of durable evidence admission and recovery."""
from __future__ import annotations

import copy
import json
import time

import pytest
from maverick import config, tools
from maverick.flow import execution, store
from maverick.flow.approvals import paused_operation_binding

from test_support.action_episode_native import (
    ALLOWED,
    FLAGS,
    INPUTS,
    TOOL_SCHEMAS,
    _calls,
    _context,
    _enroll,
    _no_agent,
    _resume,
    _row,
    _schema,
    _service,
    _source,
    _start,
)
from test_support.action_episode_native import (
    native as native,
)


def _accept(source, run):
    row = _row(source, run)
    assert row["status"] == "awaiting_review"
    _service().review(
        _context(), source.id, run.run_id, expected_revision=row["revision"],
        expected_episode_sha256=row["episode_sha256"], accepted=True,
        rationale="Reviewed the exact native execution evidence.",
    )
    return _service().export(_context(), source.id, run.run_id)


@pytest.mark.parametrize("depth", [1, 2])
def test_admitted_nested_business_result_survives_encryption_and_native_resume(native, monkeypatch, depth):
    nested = {"customer_id": "C42", "active": True}
    for _ in range(depth):
        nested = {"customer": nested}
    schemas = copy.deepcopy(TOOL_SCHEMAS)
    schemas["episode_lookup"]["result"] = _schema(nested)
    tool = tools.base_registry().get("episode_lookup")
    original = tool.fn

    def lookup(args):
        original(args)
        return json.dumps(nested)

    monkeypatch.setattr(tool, "fn", lookup)
    source, run = _start()
    _service().enroll(
        _context(), source.id, run.run_id,
        expected_pause_binding=paused_operation_binding(store.load_run(run.run_id)),
        allowed_tools=ALLOWED, input_schema=_schema(INPUTS), tool_data_schemas=schemas,
        retain_until=time.time() + 3600,
    )
    assert _resume(run.run_id).status == "paused_approval"
    final = _resume(run.run_id)
    bundle = _accept(source, final)
    assert bundle["episode"]["steps"][0]["result"] == nested
    assert len(_calls(native)) == 2


@pytest.mark.parametrize("depth", [5, 6, 7, 8])
def test_native_tool_schema_depth_does_not_reduce_the_business_value_depth_limit(native, monkeypatch, depth):
    nested = {"value": 7}
    for _ in range(depth - 2):
        nested = {"group": nested}
    arguments = {"query": nested}
    schemas = copy.deepcopy(TOOL_SCHEMAS)
    schemas["episode_lookup"]["arguments"] = _schema(arguments)
    tool = tools.base_registry().get("episode_lookup")
    monkeypatch.setattr(tool, "input_schema", copy.deepcopy(schemas["episode_lookup"]["arguments"]))
    source = _source()
    source.nodes["lookup"].params = arguments
    store.save_flow(source)
    run = execution.execute(
        source, owner="reviewer", data={"input": copy.deepcopy(INPUTS)}, agent_runner=_no_agent,
        action_runner=execution.default_action_runner(None, user_id="reviewer"),
    )
    _service().enroll(
        _context(), source.id, run.run_id,
        expected_pause_binding=paused_operation_binding(store.load_run(run.run_id)),
        allowed_tools=ALLOWED, input_schema=_schema(INPUTS), tool_data_schemas=schemas,
        retain_until=time.time() + 3600,
    )
    assert _resume(run.run_id).status == "paused_approval"
    final = _resume(run.run_id)
    bundle = _accept(source, final)
    assert bundle["episode"]["steps"][0]["arguments"] == arguments
    assert len(_calls(native)) == 2


def test_business_argument_depth_above_eight_is_still_refused_before_retention(native):
    from maverick.flow.action_episodes import _object

    nested = {"value": 7}
    for _ in range(7):
        nested = {"group": nested}
    arguments = {"query": nested}
    with pytest.raises(ValueError, match="depth limit"):
        _object(arguments)
    source = _source()
    source.nodes["lookup"].params = arguments
    store.save_flow(source)
    run = execution.execute(
        source, owner="reviewer", data={"input": copy.deepcopy(INPUTS)}, agent_runner=_no_agent,
        action_runner=execution.default_action_runner(None, user_id="reviewer"),
    )
    with pytest.raises(ValueError, match="depth limit"):
        _enroll(source, run)
    assert run.status == "paused_approval" and _calls(native) == []


def test_mid_action_capture_disable_cannot_be_recovered_as_complete_evidence(native, monkeypatch):
    from maverick.flow.action_episode_review import ActionEpisodeConflict

    source, run = _start()
    _enroll(source, run)
    state = dict(FLAGS)
    monkeypatch.setattr(config, "get_flows", lambda: dict(state))
    tool = tools.base_registry().get("episode_lookup")
    original = tool.fn

    def lookup(args):
        result = original(args)
        state["action_episode_capture"] = False
        return result

    monkeypatch.setattr(tool, "fn", lookup)
    assert _resume(run.run_id).status == "paused_approval"
    state["action_episode_capture"] = True
    final = _resume(run.run_id)
    assert final.status == "completed" and len(_calls(native)) == 2
    assert _row(source, final)["status"] == "unusable"
    with pytest.raises(ActionEpisodeConflict):
        _service().export(_context(), source.id, run.run_id)


def test_missing_completed_observation_is_not_reconstructed_from_successful_run(native, monkeypatch):
    from maverick.flow.action_episode_review import DurableActionEpisodeCapture

    source, run = _start()
    _enroll(source, run)
    with monkeypatch.context() as scoped:
        # Model a lost capture write after a real native tool/audit success.
        # No result bytes are supplied to the evidence service.
        scoped.setattr(DurableActionEpisodeCapture, "complete", lambda *args, **kwargs: None)
        first = _resume(run.run_id)
    assert first.status == "paused_approval"
    final = _resume(run.run_id)
    assert final.status == "completed" and len(_calls(native)) == 2
    assert _row(source, final)["status"] == "unusable"


def test_tool_mutation_cannot_rewrite_the_prepared_argument_snapshot(native, monkeypatch):
    source, run = _start()
    _enroll(source, run)
    tool = tools.base_registry().get("episode_lookup")
    original = tool.fn

    def lookup(args):
        result = original(args)
        args["query"] = "changed inside tool after dispatch"
        return result

    monkeypatch.setattr(tool, "fn", lookup)
    assert _resume(run.run_id).status == "paused_approval"
    final = _resume(run.run_id)
    bundle = _accept(source, final)
    assert bundle["episode"]["steps"][0]["arguments"] == {"query": "ACME"}
    assert len(_calls(native)) == 2


def test_accepted_evidence_cannot_migrate_to_recreated_same_owner_flow(native):
    from maverick.flow.action_episode_review import ActionEpisodeConflict

    source, run = _start()
    _enroll(source, run)
    assert _resume(run.run_id).status == "paused_approval"
    final = _resume(run.run_id)
    _accept(source, final)
    assert store.delete_flow(source.id, expected_version=source.version, expected_revision=source.revision)
    replacement = copy.deepcopy(source)
    store.save_flow(replacement)
    assert replacement.version == source.version
    assert replacement.owner == source.owner and replacement.revision != source.revision
    with pytest.raises(ActionEpisodeConflict, match="generation changed"):
        _service().export(_context(), source.id, run.run_id)
