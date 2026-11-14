"""Durable execution: crash-resume tests.

Covers checkpoint.py (the store + budget round-trip) and the Agent.run()
integration: a run checkpointed mid-loop resumes from the last committed step
instead of step 0, with spent budget preserved. Off-by-default is also asserted.

Configuration: `[durable]` in docs/configuration.md.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from maverick import checkpoint as ckpt_mod
from maverick.agent import Agent
from maverick.blackboard import Blackboard
from maverick.budget import Budget
from maverick.llm import LLMResponse, ToolCall
from maverick.orchestrator import run_goal
from maverick.sandbox import LocalBackend
from maverick.swarm import SwarmContext
from maverick.world_model import WorldModel


def _resp(text="", tool_calls=None, stop_reason="end_turn") -> LLMResponse:
    return LLMResponse(text=text, thinking=None,
                       tool_calls=tool_calls or [], stop_reason=stop_reason)


# ---------- store unit tests ----------

def test_checkpointer_save_and_latest(tmp_path: Path):
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    cp = ckpt_mod.Checkpointer(world)
    b = Budget(max_dollars=2.0)
    b.tool_calls = 3
    b.dollars = 0.42

    assert cp.save(goal_id=gid, agent_id="orchestrator-0-abc", step_seq=2,
                   messages=[{"role": "user", "content": "hi"}], budget=b)
    got = cp.latest(gid, "orchestrator-0-abc")
    assert got is not None
    assert got.step_seq == 2
    assert got.messages == [{"role": "user", "content": "hi"}]
    assert got.budget["tool_calls"] == 3
    assert abs(got.budget["dollars"] - 0.42) < 1e-9


def test_checkpoint_transcript_is_sealed_at_rest(tmp_path: Path, monkeypatch):
    import sqlite3

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    cp = ckpt_mod.Checkpointer(world)
    messages = [{"role": "user", "content": "private prompt text"}]
    assert cp.save(goal_id=gid, agent_id="a", step_seq=1, messages=messages, budget=Budget())
    with sqlite3.connect(tmp_path / "w.db") as conn:
        raw = conn.execute("SELECT messages FROM checkpoints").fetchone()[0]
    assert "private prompt text" not in raw
    assert cp.latest(gid, "a").messages == messages
    assert cp.at_or_before_step(gid, "a", 1).messages == messages


def test_pre_upgrade_plaintext_checkpoint_resumes_under_strict_reads(tmp_path: Path, monkeypatch):
    import json
    import sqlite3

    from maverick import crypto_at_rest

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setattr(crypto_at_rest, "strict_at_rest", lambda: True)
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    cp = ckpt_mod.Checkpointer(world)
    messages = [{"role": "user", "content": "written before sealing"}]
    assert cp.save(goal_id=gid, agent_id="a", step_seq=1, messages=messages, budget=Budget())
    with sqlite3.connect(tmp_path / "w.db") as conn:
        conn.execute("UPDATE checkpoints SET messages = ?", (json.dumps(messages),))
    assert cp.latest(gid, "a", required=True).messages == messages


def test_checkpointer_latest_returns_highest_step(tmp_path: Path):
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    cp = ckpt_mod.Checkpointer(world)
    for step in range(4):
        cp.save(goal_id=gid, agent_id="a", step_seq=step,
                messages=[{"role": "user", "content": str(step)}], budget=Budget())
    got = cp.latest(gid, "a")
    assert got.step_seq == 3
    assert got.messages[0]["content"] == "3"


def test_checkpointer_clear(tmp_path: Path):
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    cp = ckpt_mod.Checkpointer(world)
    cp.save(goal_id=gid, agent_id="a", step_seq=0, messages=[{"x": 1}], budget=Budget())
    cp.clear(gid)
    assert cp.latest(gid, "a") is None


def test_budget_snapshot_restore_round_trip():
    import time

    b = Budget(max_dollars=7.0, max_tool_calls=99)
    b.input_tokens = 1234
    b.output_tokens = 567
    b.dollars = 1.25
    b.tool_calls = 8
    # Simulate ~40s of wall time already spent. Budget.elapsed() reads
    # _started_monotonic, so back-date it (a fresh Budget has ~0 elapsed, which
    # made the old `>= _elapsed - 1.0` assertion vacuous and hid the resume bug).
    b._started_monotonic = time.monotonic() - 40.0
    snap = ckpt_mod.snapshot_budget(b)
    assert snap["_elapsed"] >= 39.0
    r = ckpt_mod.restore_budget(snap)
    assert r.max_dollars == 7.0
    assert r.max_tool_calls == 99
    assert r.input_tokens == 1234
    assert r.output_tokens == 567
    assert r.dollars == 1.25
    assert r.tool_calls == 8
    # Regression: the wall-clock cap must NOT reset on resume -- elapsed()
    # continues from the snapshot rather than ~0 (restore must back-date the
    # monotonic baseline that elapsed() actually reads, not just started_at).
    assert r.elapsed() >= 39.0


def test_enabled_env_overrides(monkeypatch):
    monkeypatch.setenv("MAVERICK_DURABLE", "0")
    assert ckpt_mod.enabled() is False
    monkeypatch.setenv("MAVERICK_DURABLE", "1")
    assert ckpt_mod.enabled() is True


def test_enabled_default_off_without_env_or_config(monkeypatch, tmp_path):
    # No env and an empty config file -> off (the default posture).
    monkeypatch.delenv("MAVERICK_DURABLE", raising=False)
    cfg = tmp_path / "config.toml"
    cfg.write_text("")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    assert ckpt_mod.enabled() is False


def test_enabled_via_config(monkeypatch, tmp_path):
    monkeypatch.delenv("MAVERICK_DURABLE", raising=False)
    cfg = tmp_path / "config.toml"
    cfg.write_text("[durable]\nenabled = true\n")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    assert ckpt_mod.enabled() is True


# ---------- Agent.run() integration ----------

def _mk_ctx(tmp_path, llm):
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("durable test", "")
    ctx = SwarmContext(
        llm=llm, world=world, budget=Budget(max_dollars=1.0),
        blackboard=Blackboard(), sandbox=LocalBackend(workdir=tmp_path),
        goal_id=gid, max_depth=1, use_skills=False,
    )
    return ctx, world, gid


class _ScriptedLLM:
    """Returns queued responses; raises if it runs past the script (so a
    'crash' is simply running out of scripted turns at a known step)."""
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0
        self.kwargs = []

    async def complete_async(self, **kwargs):
        self.kwargs.append(kwargs)
        if self.calls >= len(self._responses):
            raise RuntimeError("scripted-crash: ran past the script")
        resp = self._responses[self.calls]
        self.calls += 1
        return resp


@pytest.mark.asyncio
async def test_run_checkpoints_each_step(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_DURABLE", "1")
    # Two tool turns then crash (script exhausted on the 3rd call).
    llm = _ScriptedLLM([
        _resp(tool_calls=[ToolCall(id="t1", name="shell", input={"cmd": "echo a"})], stop_reason="tool_use"),
        _resp(tool_calls=[ToolCall(id="t2", name="shell", input={"cmd": "echo b"})], stop_reason="tool_use"),
    ])
    ctx, world, gid = _mk_ctx(tmp_path, llm)
    agent = Agent(ctx=ctx, role="researcher", brief="do it", depth=0)

    with pytest.raises(RuntimeError, match="scripted-crash"):
        await agent.run()

    # A checkpoint was committed at the turn boundary under the STABLE id
    # (not the random agent.name), keyed by the context's episode_id.
    cp = ckpt_mod.Checkpointer(world)
    saved = cp.latest(gid, agent.checkpoint_id, episode_id=ctx.episode_id)
    assert saved is not None
    assert saved.step_seq >= 1, "expected a mid-run checkpoint past step 0"


@pytest.mark.asyncio
async def test_resume_works_without_pinning_name(tmp_path, monkeypatch):
    """Production-shape resume: a FRESH agent (new random name) must resume
    from the prior checkpoint via the stable checkpoint_id — this is the bug
    Phase-1 keying had (it only worked when the test pinned agent.name)."""
    monkeypatch.setenv("MAVERICK_DURABLE", "1")
    ctx, world, gid = _mk_ctx(tmp_path, _ScriptedLLM([]))

    # Seed a checkpoint under the stable id a depth-0 researcher would use.
    b = Budget(max_dollars=1.0)
    b.tool_calls = 5
    b.dollars = 0.30
    cp = ckpt_mod.Checkpointer(world)
    cp.save(goal_id=gid, agent_id="researcher-0", episode_id=ctx.episode_id,
            step_seq=5, messages=[{"role": "user", "content": "prior work"}],
            budget=b)

    # Fresh agent — random name, NOT pinned. Resume must still match.
    llm = _ScriptedLLM([_resp(text="FINAL: resumed and done")])
    ctx.llm = llm
    agent = Agent(ctx=ctx, role="researcher", brief="do it", depth=0)
    assert agent.name != "researcher-0"  # random suffix differs

    result = await agent.run()
    assert result.final and "resumed and done" in result.final
    assert llm.calls == 1  # continued, didn't redo the 5 prior steps
    assert ctx.budget.tool_calls >= 5  # budget restored


@pytest.mark.asyncio
async def test_run_goal_resume_reuses_checkpoint_episode(
    tmp_path, monkeypatch, fresh_human_decision,
):
    """A fresh run_goal() resume must look up checkpoints in the crashed
    episode, not in a brand-new episode created for the resume invocation."""
    monkeypatch.setenv("MAVERICK_DURABLE", "1")
    # The scripted shell call must actually run so its output lands in the
    # checkpoint; the shared fixture supplies the fresh human decision the
    # shell permit requires (auto-approve would deny it).
    world_path = tmp_path / "w.db"
    world = WorldModel(world_path)
    gid = world.create_goal("durable run_goal", "")

    first_llm = _ScriptedLLM([
        _resp(
            tool_calls=[ToolCall(id="t1", name="shell", input={"cmd": "echo prior"})],
            stop_reason="tool_use",
        ),
    ])
    with pytest.raises(RuntimeError, match="scripted-crash"):
        await run_goal(
            first_llm, world, Budget(max_dollars=1.0), gid,
            sandbox=LocalBackend(workdir=tmp_path), max_depth=1,
        )

    cp = ckpt_mod.Checkpointer(world)
    checkpoint_episode_id = cp.latest_episode_id(gid, "orchestrator-0")
    assert checkpoint_episode_id is not None

    resumed_llm = _ScriptedLLM([
        _resp(text="FINAL: resumed"),
        _resp(text='{ "confidence": 0.95, "accepts": true, "critique": "ok", "issues": [] }'),
        _resp(text="FINAL: (no skill)"),
    ])
    out = await run_goal(
        resumed_llm, world, Budget(max_dollars=1.0), gid,
        sandbox=LocalBackend(workdir=tmp_path), max_depth=1, resume=True,
    )

    assert "resumed" in out
    first_resume_messages = resumed_llm.kwargs[0]["messages"]
    assert any(
        block.get("type") == "tool_result" and "prior" in block.get("content", "")
        for msg in first_resume_messages
        for block in (msg.get("content") if isinstance(msg.get("content"), list) else [])
    )
    assert world.list_episodes(goal_id=gid)[0].id == checkpoint_episode_id


@pytest.mark.asyncio
async def test_episode_scoping_no_cross_resume(tmp_path, monkeypatch):
    """A checkpoint under episode 1 must NOT be picked up when resuming
    episode 2 (the best-of-N safety property: same goal_id, distinct episodes)."""
    monkeypatch.setenv("MAVERICK_DURABLE", "1")
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    cp = ckpt_mod.Checkpointer(world)
    cp.save(goal_id=gid, agent_id="orchestrator-0", episode_id=1, step_seq=7,
            messages=[{"role": "user", "content": "attempt-1"}], budget=Budget())

    # Episode 2 has no checkpoint -> latest() returns None (no cross-resume).
    assert cp.latest(gid, "orchestrator-0", episode_id=2) is None
    # Episode 1 still resolves.
    got = cp.latest(gid, "orchestrator-0", episode_id=1)
    assert got is not None and got.step_seq == 7


@pytest.mark.asyncio
async def test_disabled_does_not_checkpoint(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_DURABLE", "0")
    llm = _ScriptedLLM([
        _resp(text="FINAL: done"),
    ])
    ctx, world, gid = _mk_ctx(tmp_path, llm)
    agent = Agent(ctx=ctx, role="researcher", brief="x", depth=0)
    result = await agent.run()
    assert result.final and "done" in result.final
    # No checkpoints table writes when disabled.
    cp = ckpt_mod.Checkpointer(world)
    assert cp.latest(gid, agent.checkpoint_id, episode_id=ctx.episode_id) is None


# ---------- CheckpointManager extraction (direct method tests) ----------
# _run_inner's resume/save blocks were lifted into _resume_from_checkpoint /
# _save_checkpoint. These pin the extracted methods directly; the Agent.run()
# integration tests above remain the byte-identical safety net through the loop.

def test_resume_from_checkpoint_restores_state(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_DURABLE", "1")
    ctx, world, gid = _mk_ctx(tmp_path, _ScriptedLLM([]))
    agent = Agent(ctx=ctx, role="researcher", brief="do it", depth=0)
    b = Budget(max_dollars=1.0)
    b.tool_calls = 4
    b.dollars = 0.25
    cp = ckpt_mod.Checkpointer(world)
    cp.save(goal_id=gid, agent_id=agent.checkpoint_id, episode_id=ctx.episode_id,
            step_seq=7, messages=[{"role": "user", "content": "prior"}], budget=b)

    ckpt, start_step, messages = agent._resume_from_checkpoint(
        [{"role": "user", "content": "fresh"}], ctx.blackboard, ctx.episode_id)
    assert ckpt is not None
    assert start_step == 7
    # Index 0 is the freshly-built brief passed in by the caller, not
    # the checkpoint's stale one -- see
    # test_resume_from_checkpoint_refreshes_brief_but_keeps_history below for
    # why (a new `ask_user` answer only ever reaches the model through it).
    assert messages == [{"role": "user", "content": "fresh"}]
    assert agent.ctx.budget.tool_calls == 4  # snapshot restored onto ctx


def test_resume_from_checkpoint_refreshes_brief_but_keeps_history(tmp_path, monkeypatch):
    # Run_goal bakes a newly-answered `ask_user` question into the
    # brief it builds for the resumed root Agent (orchestrator.py's
    # `qa_block`), which lands in `messages[0]` before `_resume_from_checkpoint`
    # is called. Wholesale-replacing `messages` with the checkpoint discarded
    # that fresh brief and put the model right back where it was when it
    # asked -- the resumed run just re-asked the same question forever. The
    # fix must swap in the fresh brief at index 0 while still carrying the
    # rest of the crashed run's history (here: a completed tool exchange)
    # forward, so the resumed loop doesn't repeat work already done.
    monkeypatch.setenv("MAVERICK_DURABLE", "1")
    ctx, world, gid = _mk_ctx(tmp_path, _ScriptedLLM([]))
    agent = Agent(ctx=ctx, role="orchestrator", brief="stale brief", depth=0)
    cp = ckpt_mod.Checkpointer(world)
    prior_history = [
        {"role": "user", "content": "Sub-goal: stale brief"},
        {"role": "assistant", "content": [
            {"type": "tool_use", "id": "t1", "name": "shell",
             "input": {"cmd": "echo prior"}},
        ]},
        {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": "prior"},
        ]},
    ]
    cp.save(goal_id=gid, agent_id=agent.checkpoint_id, episode_id=ctx.episode_id,
            step_seq=2, messages=prior_history, budget=Budget(max_dollars=1.0))

    fresh_brief = {
        "role": "user",
        "content": "Sub-goal: stale brief\n\nQ: lang?\nA: BLUEPYTHON",
    }
    ckpt, start_step, messages = agent._resume_from_checkpoint(
        [fresh_brief], ctx.blackboard, ctx.episode_id)

    assert ckpt is not None
    assert start_step == 2
    # The fresh brief (carrying the newly-answered question) replaces the
    # stale index-0 entry...
    assert messages[0] == fresh_brief
    assert "BLUEPYTHON" in messages[0]["content"]
    # ...but the rest of the crashed run's history -- including the tool_use
    # / tool_result pair, which must stay adjacent or Anthropic 400s the next
    # call -- carries over untouched.
    assert messages[1:] == prior_history[1:]


def test_resume_from_checkpoint_noop_when_disabled(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_DURABLE", raising=False)
    ctx, world, gid = _mk_ctx(tmp_path, _ScriptedLLM([]))
    agent = Agent(ctx=ctx, role="researcher", brief="x", depth=0)
    orig = [{"role": "user", "content": "fresh"}]
    ckpt, start_step, messages = agent._resume_from_checkpoint(orig, ctx.blackboard, 0)
    assert ckpt is None
    assert start_step == 0
    assert messages is orig  # untouched -> today's warm-restart behavior


def test_resume_from_checkpoint_noop_for_deep_worker(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_DURABLE", "1")
    ctx, world, gid = _mk_ctx(tmp_path, _ScriptedLLM([]))
    # depth > 0: durable resume is scoped to the root agent.
    agent = Agent(ctx=ctx, role="researcher", brief="x", depth=1)
    orig = [{"role": "user", "content": "fresh"}]
    ckpt, start_step, messages = agent._resume_from_checkpoint(orig, ctx.blackboard, 0)
    assert (ckpt, start_step) == (None, 0)
    assert messages is orig


def test_save_checkpoint_persists_and_noop_when_none(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_DURABLE", "1")
    ctx, world, gid = _mk_ctx(tmp_path, _ScriptedLLM([]))
    agent = Agent(ctx=ctx, role="researcher", brief="x", depth=0)
    cp = ckpt_mod.Checkpointer(world)
    msgs = [{"role": "user", "content": "x"}]
    # ckpt is None -> fail-open no-op, nothing persisted.
    agent._save_checkpoint(None, step=3, messages=msgs, ep_id=ctx.episode_id)
    assert cp.latest(gid, agent.checkpoint_id, episode_id=ctx.episode_id) is None
    # Real checkpointer -> state persisted at the given step.
    agent._save_checkpoint(cp, step=3, messages=msgs, ep_id=ctx.episode_id)
    saved = cp.latest(gid, agent.checkpoint_id, episode_id=ctx.episode_id)
    assert saved is not None and saved.step_seq == 3
