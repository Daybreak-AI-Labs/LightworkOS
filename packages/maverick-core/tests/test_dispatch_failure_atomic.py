"""A dispatcher failure must not overwrite a concurrent execution claim."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest


@pytest.fixture(params=["sqlite", "postgres"])
def world_pair(request, tmp_path):
    if request.param == "postgres":
        dsn = request.getfixturevalue("postgres_test_dsn")
        from maverick.world_model_backends.postgres import PostgresWorldModel

        first, second = PostgresWorldModel(dsn=dsn), PostgresWorldModel(dsn=dsn)
    else:
        from maverick.world_model import WorldModel

        first, second = WorldModel(tmp_path / "world.db"), WorldModel(tmp_path / "world.db")
    try:
        yield first, second
    finally:
        first.close()
        second.close()


def test_pending_failure_and_execution_claim_are_mutually_exclusive(world_pair):
    first, second = world_pair
    with ThreadPoolExecutor(max_workers=2) as executor:
        for _ in range(20):
            goal_id = first.create_goal("race")
            ready = threading.Barrier(2)

            def claim(barrier, current_goal):
                barrier.wait(timeout=5)
                return first.claim_goal_for_run(current_goal)

            def block(barrier, current_goal):
                barrier.wait(timeout=5)
                return second.block_pending_goal(current_goal, result="dispatch failed")

            claim_future = executor.submit(claim, ready, goal_id)
            block_future = executor.submit(block, ready, goal_id)
            claimed, blocked = claim_future.result(timeout=10), block_future.result(timeout=10)
            assert claimed != blocked
            goal = first.get_goal(goal_id)
            assert goal.status == ("active" if claimed else "blocked")
            if blocked:
                assert goal.result == "dispatch failed"


@pytest.mark.parametrize("status", ["active", "running", "done", "blocked", "error"])
def test_failure_repair_preserves_existing_status(world_pair, status):
    world, _ = world_pair
    goal_id = world.create_goal("existing status")
    world.set_goal_status(goal_id, status, result="existing result")
    assert not world.block_pending_goal(goal_id, result="dispatch failed")
    goal = world.get_goal(goal_id)
    assert (goal.status, goal.result) == (status, "existing result")


def test_postgres_failure_repair_obeys_tenant_scope(postgres_test_dsn):
    from maverick.paths import tenant_scope
    from maverick.world_model_backends.postgres import PostgresWorldModel

    world = PostgresWorldModel(dsn=postgres_test_dsn)
    try:
        with tenant_scope(tenant="tenant-a"):
            goal_id = world.create_goal("tenant-a task")
        with tenant_scope(tenant="tenant-b"):
            assert not world.block_pending_goal(goal_id, result="wrong tenant")
        with tenant_scope(tenant="tenant-a"):
            assert world.get_goal(goal_id).status == "pending"
            assert world.block_pending_goal(goal_id, result="dispatch failed")
            assert world.get_goal(goal_id).result == "dispatch failed"
    finally:
        world.close()
