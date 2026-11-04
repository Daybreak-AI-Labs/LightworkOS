"""Persisted native action capture across real approval pauses; no providers."""
from __future__ import annotations

import multiprocessing

import pytest
from maverick import audit
from maverick.flow import execution, store

from test_support.action_episode_native import (
    ALLOWED,
    INPUTS,
    _calls,
    _child_resume,
    _context,
    _enroll,
    _no_agent,
    _resume,
    _row,
    _service,
    _start,
)
from test_support.action_episode_native import (
    native as native,
)
from test_support.audit_child_process import audit_signing_target


def test_durable_native_capture_survives_two_fresh_process_approval_resumes(native, tmp_path):
    source, run = _start()
    _enroll(source, run)
    assert _calls(native) == []
    # Each segment is a genuinely fresh interpreter and reopens the same
    # encrypted persisted evidence. No in-memory collector is handed across.
    for expected_status, count in (("paused_approval", 1), ("completed", 2)):
        process = multiprocessing.get_context("spawn").Process(
            target=audit_signing_target(_child_resume), args=(run.run_id, str(native), str(tmp_path / "native-resume.db")),
        )
        process.start()
        process.join(45)
        if process.is_alive():
            process.terminate()
            process.join(5)
            pytest.fail("native local resume worker timed out")
        assert process.exitcode == 0
        run = store.load_run(run.run_id, owner="reviewer", flow_id=source.id)
        assert run.status == expected_status
        assert len(_calls(native)) == count
    row = _row(source, run)
    assert row["status"] == "awaiting_review"
    accepted = _service().review(
        _context(), source.id, run.run_id, expected_revision=row["revision"],
        expected_episode_sha256=row["episode_sha256"], accepted=True,
        rationale="Reviewed both persisted native fixture steps and their business inputs.",
    )
    assert accepted["status"] == "accepted"
    bundle = _service().export(_context(), source.id, run.run_id)
    assert bundle["episode"]["inputs"] == INPUTS
    assert [step["tool"] for step in bundle["episode"]["steps"]] == ALLOWED
    assert bundle["episode"]["steps"][1]["arguments"]["quantity"] == 3
    assert type(bundle["episode"]["steps"][1]["arguments"]["quantity"]) is int
    assert bundle["review"]["authenticated"] is True
    receipts = bundle["provenance"]["steps"]
    assert len({receipt["call_id"] for receipt in receipts}) == 2
    events = list(audit.iter_events(all_days=True, strict=True, verify=True))
    for receipt in receipts:
        pair = [event for event in events if event.get("call_id") == receipt["call_id"]]
        assert [event["kind"] for event in pair] == ["tool_call", "tool_result"]
        assert pair[1]["disposition"] == "completed"
    with pytest.raises(execution.FlowNotResumable):
        execution.execute(
            source, owner="reviewer", resume_run_id=run.run_id, decision="approved", decided_by="reviewer",
            agent_runner=_no_agent, action_runner=execution.default_action_runner(None, user_id="reviewer"),
        )
    assert len(_calls(native)) == 2


@pytest.mark.parametrize("method", ["prepare", "complete", "finish"])
def test_optional_capture_storage_failure_never_repeats_native_effects(native, monkeypatch, method):
    from maverick.flow.action_episode_review import (
        ActionEpisodeConflict,
        DurableActionEpisodeCapture,
    )

    source, run = _start()
    _enroll(source, run)

    def unavailable(*args, **kwargs):
        raise OSError("local capture storage unavailable")

    with monkeypatch.context() as scoped:
        scoped.setattr(DurableActionEpisodeCapture, method, unavailable)
        first = _resume(run.run_id)
    assert first.status == "paused_approval"
    final = _resume(run.run_id)
    assert final.status == "completed"
    assert [item["tool"] for item in _calls(native)] == ALLOWED
    assert _row(source, final)["status"] == "unusable"
    with pytest.raises(ActionEpisodeConflict, match="no accepted unexpired review"):
        _service().export(_context(), source.id, final.run_id)


def test_injected_action_runner_cannot_create_durable_native_evidence(native):
    source, run = _start()
    _enroll(source, run)
    first = _resume(run.run_id, action_runner=lambda *args: ('{"customer_id":"C42","active":true}', 1.0))
    assert first.status == "paused_approval" and _calls(native) == []
    assert _row(source, first)["status"] == "unusable"


def test_terminal_audit_failure_does_not_certify_or_repeat_an_effect(native, monkeypatch):
    source, run = _start()
    _enroll(source, run)
    original = audit.audit_event

    def refuse_terminal(kind, **kwargs):
        return False if kind == audit.EventKind.TOOL_RESULT else original(kind, **kwargs)

    monkeypatch.setattr(audit, "audit_event", refuse_terminal)
    result = _resume(run.run_id)
    assert result.status == "indeterminate"
    assert len(_calls(native)) == 1
    assert _row(source, result)["status"] == "unusable"
    with pytest.raises(execution.FlowNotResumable):
        execution.execute(
            source, owner="reviewer", resume_run_id=run.run_id, decision="approved", decided_by="reviewer",
            agent_runner=_no_agent, action_runner=execution.default_action_runner(None, user_id="reviewer"),
        )
    assert len(_calls(native)) == 1


def test_approval_submitted_inputs_invalidate_capture_without_blocking_business_run(native):
    source, run = _start()
    _enroll(source, run)
    first = _resume(run.run_id, inputs={"note": "a newly supplied form value"})
    assert first.status == "paused_approval" and len(_calls(native)) == 1
    assert _row(source, first)["status"] == "unusable"


def test_invalid_native_approval_never_reaches_capture_factory(native, monkeypatch):
    source, run = _start()
    _enroll(source, run)
    factory_calls = []
    monkeypatch.setattr(execution, "resume_capture", lambda *args, **kwargs: factory_calls.append(kwargs))
    with pytest.raises((ValueError, PermissionError)):
        execution.execute(
            source, owner="reviewer", resume_run_id=run.run_id, decision="approved", decided_by="reviewer",
            approval_binding_sha256="changed-binding", agent_runner=_no_agent,
            action_runner=execution.default_action_runner(None, user_id="reviewer"),
        )
    assert factory_calls == [] and _calls(native) == []
    assert store.load_run(run.run_id).status == "paused_approval"


def test_historical_draft_edit_cannot_change_captured_pinned_arguments(native):
    source, run = _start()
    _enroll(source, run)
    changed = store.load_flow(source.id)
    changed.nodes["update"].params["quantity"] = 99
    store.save_flow(changed)
    assert _resume(run.run_id).status == "paused_approval"
    final = _resume(run.run_id)
    assert final.status == "completed" and _calls(native)[1]["arguments"]["quantity"] == 3
    assert _row(source, final)["status"] == "awaiting_review"
