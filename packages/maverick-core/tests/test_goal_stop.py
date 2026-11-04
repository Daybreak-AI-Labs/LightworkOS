"""Local database coverage for Stop's revision and receipt boundary."""
import pytest
from maverick import goal_mutations, goal_stop
from maverick.world_model import WorldModel


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    store = WorldModel(tmp_path / "world.db")
    # The service assumes the shared mutation-receipt schema. Keep the unit
    # fixture explicit; migration compatibility has separate integration tests.
    with store._writing() as connection:
        connection.execute(goal_mutations.SCHEMA)
    yield store
    store.close()


def task(world):
    identifier = world.create_goal("Keep my partial result", owner="user:alice")
    world.set_goal_status(identifier, "running", result="Partial evidence")
    before = world.get_goal(identifier)
    return identifier, dict(actor="user:alice", operation_id="a" * 32,
                            expected_updated_at=float(before.updated_at), expected_owner="user:alice")


def test_stop_preserves_partial_result_and_exact_retry_does_not_mutate_again(world):
    identifier, args = task(world)
    first = goal_stop.stop(world, identifier, **args)
    saved = world.get_goal(identifier)
    assert saved.status == "cancelled"
    assert saved.result == "Partial evidence"
    assert first["stop_requested"] and not first["cleanup_confirmed"]
    assert not first["external_effects_reversed"]
    assert goal_stop.stop(world, identifier, **args)["replayed"]
    assert goal_stop.receipt(world, identifier, **args)["replayed"]
    assert world.get_goal(identifier).updated_at == saved.updated_at


@pytest.mark.parametrize("change", ["finished", "updated", "transferred"])
def test_changed_task_rejects_stale_stop_without_overwriting(world, change):
    identifier, args = task(world)
    if change == "finished":
        world.set_goal_status(identifier, "done", result="Final evidence")
    elif change == "updated":
        world.set_goal_status(identifier, "running", result="New partial evidence")
    else:
        with world._writing() as connection:
            connection.execute("UPDATE goals SET owner=? WHERE id=?", ("user:bob", identifier))
    before = world.get_goal(identifier)
    with pytest.raises(goal_stop.GoalMutationConflict):
        goal_stop.stop(world, identifier, **args)
    after = world.get_goal(identifier)
    assert (after.status, after.result, after.updated_at, after.owner) == (before.status, before.result, before.updated_at, before.owner)


def test_receipt_cannot_be_reused_for_a_different_review(world):
    identifier, args = task(world)
    goal_stop.stop(world, identifier, **args)
    with pytest.raises(goal_stop.GoalMutationConflict):
        goal_stop.stop(world, identifier, **{**args, "expected_updated_at": args["expected_updated_at"] + 1})
