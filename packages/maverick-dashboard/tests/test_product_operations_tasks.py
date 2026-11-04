"""Copilot task handlers use native receipts and current owner authority."""
import pytest
from fastapi import HTTPException
from maverick.world_model import WorldModel
from maverick_dashboard import api, app, auth, clarification_submission, draft_api
from maverick_dashboard import product_operations_tasks as actions
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(auth, "require_permission", lambda *args: None)
    monkeypatch.setattr(auth, "assert_goal_access", lambda *args: None)
    monkeypatch.setattr(auth, "caller_principal", lambda *args: "user:owner")
    monkeypatch.setattr(api, "require_permission", lambda *args: None)
    monkeypatch.setattr(api, "assert_goal_access", lambda *args: None)
    monkeypatch.setattr(api, "caller_principal", lambda *args: "user:owner")
    monkeypatch.setattr(api, "_ground_outcome", lambda *args, **kwargs: False)
    monkeypatch.setattr(clarification_submission, "require_permission", lambda *args: None)
    monkeypatch.setattr(clarification_submission, "caller_principal", lambda *args: "user:owner")
    monkeypatch.setattr(draft_api, "context_for", lambda *args: "context-for-test")
    monkeypatch.setattr(api, "_require_goal_restart_admission", lambda *args: None)
    with WorldModel(tmp_path / "world.db") as world:
        monkeypatch.setattr(app, "_world", lambda: world)
        monkeypatch.setattr(api, "_world", lambda: world)
        goal_id = world.create_goal("Reviewed work", owner="user:owner")
        request = Request({"type": "http", "method": "POST", "scheme": "http",
                           "path": "/api/v1/copilot/product-operations/execute",
                           "headers": [(b"host", b"127.0.0.1"), (b"origin", b"http://127.0.0.1")]})
        yield world, goal_id, request, {"kind": "goal", "id": goal_id}


@pytest.mark.asyncio
async def test_answer_uses_native_receipt_and_recovery_never_dispatches_twice(setup, monkeypatch):
    world, goal_id, request, selection = setup
    question = world.ask("Which period?", goal_id=goal_id)
    world.set_goal_status(goal_id, "blocked")
    dispatched = []
    monkeypatch.setattr(api, "_dispatch_requeued_goal", lambda *args, **kwargs: dispatched.append(goal_id))
    args = {"question": str(question), "answer": "Use September."}
    preview = actions.answer_preview(request, selection, args)
    first = await run_in_threadpool(actions.answer_execute, request, selection, args, preview.native, "answer-operation-one")
    recovered = actions.answer_recover(request, selection, args, preview.native, "answer-operation-one")
    assert first.status == "queued" and recovered.status == "replayed"
    assert dispatched == [goal_id] and not world.open_questions(goal_id=goal_id)
    assert not world.list_attachments(goal_id)


def test_text_answer_effect_stays_on_authority_fence_owner_thread(setup, monkeypatch):
    import threading

    world, goal_id, request, selection = setup
    question = world.ask("Which period?", goal_id=goal_id)
    world.set_goal_status(goal_id, "blocked")
    monkeypatch.setattr(api, "_dispatch_requeued_goal", lambda *args, **kwargs: None)
    original = clarification_submission._accept
    owner_thread = threading.get_ident()
    def accept(*args, **kwargs):
        assert threading.get_ident() == owner_thread
        return original(*args, **kwargs)
    monkeypatch.setattr(clarification_submission, "_accept", accept)
    args = {"question": str(question), "answer": "Use September."}
    preview = actions.answer_preview(request, selection, args)
    result = actions.answer_execute(request, selection, args, preview.native, "same-thread-operation")
    assert result.status == "queued"


def test_edit_uses_native_cas_and_exact_receipt_after_later_revision(setup):
    world, goal_id, request, selection = setup
    world.set_goal_status(goal_id, "done", result="First result")
    args = {"text": "Reviewed result"}
    native = actions.edit_preview(request, selection, args).native
    first = actions.edit_execute(request, selection, args, native, "edit-operation-one")
    world.set_goal_status(goal_id, "done", result="A later human edit")
    recovered = actions.edit_recover(request, selection, args, native, "edit-operation-one")
    assert first.status == "confirmed" and recovered.status == "replayed"
    assert world.get_goal(goal_id).result == "A later human edit"
    assert recovered.details["training_completed"] is False


def test_edit_rejects_stale_review_without_overwriting_result(setup):
    world, goal_id, request, selection = setup
    world.set_goal_status(goal_id, "done", result="First result")
    args = {"text": "Old reviewed draft"}
    native = actions.edit_preview(request, selection, args).native
    world.set_goal_status(goal_id, "done", result="A newer edit")
    with pytest.raises(HTTPException) as conflict:
        actions.edit_execute(request, selection, args, native, "edit-operation-two")
    assert conflict.value.status_code == 409
    assert world.get_goal(goal_id).result == "A newer edit"


def test_content_grant_does_not_grant_edit_or_question_authority(setup, monkeypatch):
    world, goal_id, request, selection = setup
    world.set_goal_status(goal_id, "done", result="Private result")
    monkeypatch.setattr(auth, "caller_principal", lambda *args: "user:reviewer")
    for operation in (actions.edit_snapshot, actions.answer_snapshot):
        with pytest.raises(HTTPException) as denied:
            operation(request, selection)
        assert denied.value.status_code == 403


def test_review_choices_never_offer_owner_self_approval_or_stale_decision():
    row = {"owner": "user:owner", "reviewer": "user:reviewer", "status": "pending", "stale": False}
    assert {item["value"] for item in actions._review_choices(row, "user:owner")} == {"comment", "cancel"}
    assert "approve" in {item["value"] for item in actions._review_choices(row, "user:reviewer")}
    row["stale"] = True
    assert actions._review_choices(row, "user:reviewer") == [{"value": "comment", "label": "Add comment"}]
