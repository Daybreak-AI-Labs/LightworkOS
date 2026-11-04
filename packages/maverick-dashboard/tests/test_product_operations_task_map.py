"""Task-map Copilot uses the same native CAS, ownership and durable receipts."""
import pytest
from fastapi import HTTPException
from maverick import goal_mutations
from maverick.world_model import WorldModel
from maverick_dashboard import api, app, auth
from maverick_dashboard import product_operations_task_map as actions
from maverick_dashboard.api_schemas import ReparentIn, RetitleIn
from starlette.requests import Request


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(auth, "require_permission", lambda *args: None)
    monkeypatch.setattr(api, "require_permission", lambda *args: None)
    monkeypatch.setattr(auth, "caller_principal", lambda *args: "user:owner")
    monkeypatch.setattr(api, "caller_principal", lambda *args: "user:owner")
    with WorldModel(tmp_path / "world.db") as world:
        monkeypatch.setattr(app, "_world", lambda: world)
        monkeypatch.setattr(api, "_world", lambda: world)
        goal_id = world.create_goal("Reviewed task", owner="user:owner")
        request = Request({"type": "http", "method": "POST", "scheme": "http",
                           "path": "/api/v1/copilot/product-operations/execute",
                           "headers": [(b"host", b"127.0.0.1"), (b"origin", b"http://127.0.0.1")]})
        yield world, goal_id, request, {"kind": "goal", "id": goal_id}


def test_rename_native_and_copilot_share_stale_revision_guard(setup):
    world, goal_id, request, selection = setup
    args = {"title": "Reviewed rename"}
    native = actions.rename_preview(request, selection, args).native
    api.retitle_goal(request, goal_id, RetitleIn(title="A newer native rename",
                     expected_updated_at=world.get_goal(goal_id).updated_at))
    with pytest.raises(HTTPException) as stale:
        actions.execute(request, selection, args, native, "stale-map-operation")
    assert stale.value.status_code == 409
    assert world.get_goal(goal_id).title == "A newer native rename"


def test_lost_ack_receipt_preserves_later_title_and_rejects_changed_payload(setup):
    world, goal_id, request, selection = setup
    world.set_goal_status(goal_id, "done", result="Original result")
    args = {"title": "Saved title"}
    native = actions.rename_preview(request, selection, args).native
    saved = actions.execute(request, selection, args, native, "rename-map-operation")
    assert saved.status == "confirmed" and saved.details["title"] == "Saved title"
    later = world.get_goal(goal_id)
    api.retitle_goal(request, goal_id, RetitleIn(title="Later title", expected_updated_at=later.updated_at))
    recovered = actions.recover(request, selection, args, native, "rename-map-operation")
    assert recovered.status == "replayed" and recovered.details["revision"] == saved.details["revision"]
    assert world.get_goal(goal_id).title == "Later title"
    assert world.get_goal(goal_id).status == "done" and world.get_goal(goal_id).result == "Original result"
    with pytest.raises(HTTPException) as conflict:
        actions.recover(request, selection, args, {**native, "title": "Changed"}, "rename-map-operation")
    assert conflict.value.status_code == 409


def test_parent_choices_are_owned_cycle_safe_and_current(setup):
    world, goal_id, request, selection = setup
    parent = world.create_goal("Available parent", owner="user:owner")
    descendant = world.create_goal("Own child", parent_id=goal_id, owner="user:owner")
    other = world.create_goal("Private other parent", owner="user:other")
    state = actions.move_snapshot(request, selection)
    assert {row["id"] for row in state.details["parents"]} == {parent}
    assert str(descendant) not in {row["value"] for row in state.fields[0]["choices"]}
    with pytest.raises(HTTPException):
        actions.move_preview(request, selection, {"parent": str(other)})
    native = actions.move_preview(request, selection, {"parent": str(parent)}).native
    moved = actions.execute(request, selection, {"parent": str(parent)}, native, "move-map-operation")
    assert moved.status == "confirmed" and world.get_goal(goal_id).parent_id == parent
    assert actions.recover(request, selection, {}, native, "move-map-operation").status == "replayed"


def test_native_new_cycle_after_review_is_refused_atomically(setup):
    world, goal_id, request, selection = setup
    parent = world.create_goal("Parent candidate", owner="user:owner")
    native = actions.move_preview(request, selection, {"parent": str(parent)}).native
    api.reparent_goal(request, parent, ReparentIn(parent_id=goal_id,
                      expected_updated_at=world.get_goal(parent).updated_at))
    with pytest.raises(HTTPException) as conflict:
        actions.execute(request, selection, {}, native, "cycle-map-operation")
    assert conflict.value.status_code in {400, 409}
    assert world.get_goal(goal_id).parent_id is None


def test_read_grant_and_global_role_never_grant_another_owners_map_mutation(setup, monkeypatch):
    from maverick_dashboard import content_access

    world, goal_id, request, selection = setup
    monkeypatch.setattr(auth, "caller_principal", lambda *args: "user:reviewer")
    monkeypatch.setattr(content_access, "may_read_employee_content", lambda *args, **kwargs: True)
    with pytest.raises(HTTPException) as denied:
        actions.rename_snapshot(request, selection)
    assert denied.value.status_code in {403, 404}
    with pytest.raises(HTTPException) as denied:
        api.retitle_goal(request, goal_id, RetitleIn(title="Forbidden",
                         expected_updated_at=world.get_goal(goal_id).updated_at))
    assert denied.value.status_code == 404
    assert world.get_goal(goal_id).title == "Reviewed task"


def test_handoff_closure_blocks_new_edits_but_keeps_original_receipt_readable(setup):
    world, goal_id, request, selection = setup
    args = {"title": "Before handoff"}
    native = actions.rename_preview(request, selection, args).native
    actions.execute(request, selection, args, native, "before-handoff-map")
    with goal_mutations._transaction(world, goal_id) as (execute, seal, _decode, _postgres, _tenant):
        goal_mutations._record(execute, seal, goal_id, "handoff_closed", "handoff-map-receipt", "user:owner",
                               "closure", {"successor_goal_id": 999})
    assert actions.rename_snapshot(request, selection).blocked
    assert actions.recover(request, selection, args, native, "before-handoff-map").status == "replayed"
    with pytest.raises(HTTPException) as closed:
        api.retitle_goal(request, goal_id, RetitleIn(title="Cannot reopen",
                         expected_updated_at=world.get_goal(goal_id).updated_at))
    assert closed.value.status_code == 409
    with pytest.raises(goal_mutations.GoalMutationConflict):
        goal_mutations.create_child(world, goal_id, title="Cannot extend", description="", owner="user:owner",
                                    actor="user:owner", operation_id="closed-child-map")


def test_map_move_cannot_escape_or_replace_an_inherited_handoff_budget(setup):
    world, goal_id, request, _selection = setup
    child = world.create_goal("Governed child", parent_id=goal_id, owner="user:owner")
    outside = world.create_goal("Other work", owner="user:owner")
    with goal_mutations._transaction(world, goal_id) as (execute, seal, _decode, _postgres, _tenant):
        goal_mutations._record(execute, seal, goal_id, "handoff_lineage", "governed-source", "user:owner",
                               "ceiling", {"max_dollars": 3, "max_seconds": 60})
    selection = {"kind": "goal", "id": child}
    state = actions.move_snapshot(request, selection)
    choices = {row["value"] for row in state.fields[0]["choices"]}
    assert "root" not in choices and str(outside) not in choices and str(goal_id) in choices
    with pytest.raises(HTTPException):
        actions.move_preview(request, selection, {"parent": "root"})
    with pytest.raises(HTTPException) as refused:
        api.reparent_goal(request, child, ReparentIn(parent_id=None,
                          expected_updated_at=world.get_goal(child).updated_at))
    assert refused.value.status_code == 409 and world.get_goal(child).parent_id == goal_id
