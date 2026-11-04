"""Durable execution: rewind/fork of a checkpointed run.

Exercises the checkpoint-manipulation mechanics directly against the world model
(no LLM): the continuation itself reuses the crash-resume path.
"""
from __future__ import annotations

from maverick import checkpoint as ckpt_mod
from maverick.budget import Budget
from maverick.world_model import WorldModel


def _seed(world, goal_id, *, agent_id="orchestrator-0", episode_id=0, steps=5):
    ck = ckpt_mod.Checkpointer(world)
    for step in range(steps):
        ck.save(goal_id=goal_id, agent_id=agent_id, episode_id=episode_id,
                step_seq=step, messages=[{"role": "user", "content": f"s{step}"}],
                budget=Budget(max_dollars=5.0), meta={"role": "orchestrator"})
    return ck


def test_checkpoint_query_helpers(tmp_path):
    world = WorldModel(tmp_path / "world.db")
    gid = world.create_goal("a goal")
    ck = _seed(world, gid, steps=5)
    assert ck.orchestrator_for(gid) == ("orchestrator-0", 0)
    assert ck.list_steps(gid, "orchestrator-0") == [0, 1, 2, 3, 4]
    assert ck.at_or_before_step(gid, "orchestrator-0", 2).step_seq == 2
    assert ck.at_or_before_step(gid, "orchestrator-0", 99).step_seq == 4  # clamps to newest
    assert ck.at_or_before_step(gid, "orchestrator-0", -1) is None
    world.close()


def test_rewind_in_place_truncates_and_reblocks(tmp_path):
    world = WorldModel(tmp_path / "world.db")
    gid = world.create_goal("a goal")
    world.set_goal_status(gid, "done")
    ck = _seed(world, gid, steps=5)

    res = ckpt_mod.rewind(world, gid, 2)
    assert res.ok and res.target_step == 2 and res.forked_goal_id is None
    # Checkpoints after step 2 are dropped; the latest is now step 2.
    assert ck.list_steps(gid, "orchestrator-0") == [0, 1, 2]
    assert ck.latest(gid, "orchestrator-0").step_seq == 2
    # The goal is re-blocked so `maverick resume` picks it up.
    assert world.get_goal(gid).status == "blocked"
    world.close()


def test_rewind_fork_creates_child_and_preserves_original(tmp_path):
    world = WorldModel(tmp_path / "world.db")
    gid = world.create_goal("finance close", domain="finance_ap")
    ck = _seed(world, gid, agent_id="finance_ap-0", steps=5)

    res = ckpt_mod.rewind(world, gid, 3, fork=True)
    assert res.ok and res.forked_goal_id is not None
    new = res.forked_goal_id

    # The original is untouched (all five steps remain).
    assert ck.list_steps(gid, "finance_ap-0") == [0, 1, 2, 3, 4]
    # The fork carries only the copied checkpoint at the target step...
    assert ck.list_steps(new, "finance_ap-0") == [3]
    # ...and inherits the parent + department so the resumed role still keys the
    # same checkpoint_id ("finance_ap-0").
    fg = world.get_goal(new)
    assert fg.parent_id == gid
    assert fg.domain == "finance_ap"
    assert fg.status == "blocked"
    world.close()


def test_rewind_without_checkpoints_is_honest(tmp_path):
    world = WorldModel(tmp_path / "world.db")
    gid = world.create_goal("never run with durable on")
    res = ckpt_mod.rewind(world, gid, 1)
    assert not res.ok and "no checkpoints" in res.detail
    world.close()


def test_rewind_step_too_early_lists_available(tmp_path):
    world = WorldModel(tmp_path / "world.db")
    gid = world.create_goal("a goal")
    _seed(world, gid, steps=3)  # steps 0, 1, 2
    res = ckpt_mod.rewind(world, gid, -5)
    assert not res.ok and "available steps" in res.detail
    world.close()
