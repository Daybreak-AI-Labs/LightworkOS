"""Atomic reviewed result, child creation and task-map mutation regressions."""
import pytest
from maverick.goal_mutations import GoalMutationConflict, create_child, edit_result, edit_structure
from maverick.world_model import WorldModel


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    store = WorldModel(tmp_path / "world.db")
    yield store
    store.close()


def test_result_compare_and_swap_preserves_revision_and_revokes_signoff(world):
    goal = world.create_goal("Review")
    world.set_goal_status(goal, "done", result="Original")
    before = world.get_goal(goal).updated_at
    world.record_signoff(goal, "approved", expected_updated_at=before)
    saved = edit_result(world, goal, text="Reviewed", expected_updated_at=before,
                        operation_id="operation_one_001", actor="user:alice")
    assert saved["revision"] > before
    assert world.signoff_for(goal) is None
    assert [a["content"] for a in world.artifacts_for_goal(goal)] == ["Original", "Reviewed"]
    with pytest.raises(GoalMutationConflict):
        edit_result(world, goal, text="Stale", expected_updated_at=before,
                    operation_id="operation_two_002", actor="user:bob")
    assert world.get_goal(goal).result == "Reviewed"
    replay = edit_result(world, goal, text="Reviewed", expected_updated_at=before,
                         operation_id="operation_one_001", actor="user:alice")
    assert replay["revision"] == saved["revision"]
    assert replay["replayed"] is True
    assert len(world.artifacts_for_goal(goal)) == 2


def test_edit_cannot_restore_obsolete_running_state(world):
    goal = world.create_goal("Running")
    world.set_goal_status(goal, "done", result="First")
    before = world.get_goal(goal).updated_at
    world.set_goal_status(goal, "running", result="New agent result")
    with pytest.raises(GoalMutationConflict):
        edit_result(world, goal, text="Stale", expected_updated_at=before,
                    operation_id="operation_one_001", actor="user:alice")
    assert world.get_goal(goal).status == "running"
    assert world.get_goal(goal).result == "New agent result"


def test_child_retry_is_durable_and_different_payload_is_refused(world):
    parent = world.create_goal("Parent")
    args = dict(title="Child", description="", owner="user:alice",
                actor="user:alice", operation_id="operation_one_001")
    first = create_child(world, parent, **args)
    second = create_child(world, parent, **args)
    assert first["child_id"] == second["child_id"]
    assert len(world.list_goals()) == 2
    with pytest.raises(GoalMutationConflict):
        create_child(world, parent, **{**args, "title": "Different"})


def test_task_map_stale_rename_and_cycle_are_refused(world):
    parent = world.create_goal("Parent")
    child = world.create_goal("Child", parent_id=parent)
    before = world.get_goal(parent).updated_at
    edit_structure(world, parent, title="Renamed", expected_updated_at=before)
    with pytest.raises(GoalMutationConflict):
        edit_structure(world, parent, title="Stale", expected_updated_at=before)
    with pytest.raises(GoalMutationConflict):
        edit_structure(world, parent, move=True, parent_id=child,
                       expected_updated_at=world.get_goal(parent).updated_at)
    assert world.get_goal(parent).parent_id is None
