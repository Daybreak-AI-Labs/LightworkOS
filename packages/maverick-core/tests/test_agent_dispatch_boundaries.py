"""Agent boundary regressions: verifier, checkpoint and post-effect paths."""
from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest
from maverick.agent import Agent, _RunState
from maverick.blackboard import Blackboard
from maverick.budget import Budget
from maverick.capability import Capability
from maverick.coding_mode import CodingModeConfig
from maverick.llm import LLMResponse, ToolCall
from maverick.sandbox import LocalBackend
from maverick.swarm import SwarmContext
from maverick.tools import Tool
from maverick.world_model import WorldModel


@pytest.fixture
def agent(tmp_path, fake_llm, monkeypatch):
    monkeypatch.setenv("MAVERICK_REHEARSAL", "0")
    world = WorldModel(tmp_path / "world.db")
    workspace = tmp_path / "work"
    workspace.mkdir()
    ctx = SwarmContext(
        llm=fake_llm, world=world, budget=Budget(max_dollars=1),
        blackboard=Blackboard(), sandbox=LocalBackend(workdir=workspace),
        goal_id=world.create_goal("boundary check", ""), use_skills=False,
    )
    value = Agent(ctx=ctx, role="orchestrator", brief="check boundaries")
    yield value
    world.close()


def _state(agent):
    return _RunState(messages=[{"role": "user", "content": "task"}],
                     bb=agent.ctx.blackboard, ep_id=0, ckpt=None, start_step=0)


@pytest.mark.asyncio
@pytest.mark.parametrize("entry", ["final", "calibration"])
async def test_verifier_uses_guarded_completion(agent, monkeypatch, entry):
    calls = []
    async def guarded(**kwargs):
        calls.append("guarded")
        return SimpleNamespace()
    async def judge(_brief, _final, llm, _budget, **kwargs):
        await llm.complete_async()
        return SimpleNamespace(confidence=1.0, accepts=True)
    monkeypatch.setattr(agent, "_complete_guarded", guarded)
    monkeypatch.setattr("maverick.verifier.verify_final", judge)
    monkeypatch.setattr("maverick.verifier.verify_proposal", judge)
    monkeypatch.setattr("maverick.calibration.collect_from_coding_enabled", lambda: True)
    monkeypatch.setattr("maverick.calibration.record_sample", lambda *a, **k: None)
    monkeypatch.setattr("maverick.agent._risk_proportional_verify_enabled", lambda: False)
    if entry == "final":
        await agent._judge_final(_state(agent), "answer", None)
    else:
        await agent._record_calibration_sample("answer", SimpleNamespace(all_pass=True))
    assert calls == ["guarded"]


@pytest.mark.asyncio
@pytest.mark.parametrize("interrupted", [False, True, "cancel"])
async def test_completed_tool_turn_is_checkpointed_before_background_work(agent, monkeypatch, interrupted):
    from maverick.checkpoint import Checkpointer
    from maverick.killswitch import Halted
    from maverick.run_outcome import GoalCancelled
    st = _state(agent)
    st.ckpt = Checkpointer(agent.ctx.world)
    response = LLMResponse(text="", thinking=None, stop_reason="tool_use",
                           tool_calls=[ToolCall(id="call", name="write_file", input={})])
    if interrupted:
        response.tool_calls.append(ToolCall(id="second", name="write_file", input={"stop": True}))
    agent._record_assistant_turn(st, response)
    async def run(_name, args):
        if args.get("stop"):
            if interrupted == "cancel":
                stopped = GoalCancelled("cancelled after dispatch")
                stopped.tool_execution_unknown = True
                raise stopped
            raise Halted("after the first effect", "test")
        agent.ctx.budget.record_tokens(7, 3)
        return "effect committed"
    monkeypatch.setattr(agent, "_run_tool", run)
    monkeypatch.setattr(agent, "_append_turn_trailers", lambda *_: None)
    def crash():
        raise RuntimeError("crash before next turn")
    monkeypatch.setattr(agent, "_maybe_speculate_reads", crash)
    agent._save_checkpoint(st.ckpt, step=0, messages=st.messages[:1], ep_id=0)
    expected = GoalCancelled if interrupted == "cancel" else Halted if interrupted else RuntimeError
    with pytest.raises(expected) as stopped:
        await agent._dispatch_tools(st, 0, response)
    if interrupted == "cancel":
        assert stopped.value.tool_execution_unknown is True
    saved = st.ckpt.latest(agent.ctx.goal_id, agent.checkpoint_id, episode_id=0)
    assert saved.step_seq == 1
    assert saved.messages[-1]["content"][0]["content"] == "effect committed"
    assert saved.budget["tool_calls"] == (2 if interrupted else 1)
    assert saved.budget["dollars"] > 0
    if interrupted:
        assert "reconcile state before retrying" in saved.messages[-1]["content"][1]["content"]


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), "-c", "user.name=Test", "-c",
                    "user.email=test@example.invalid", "-c", "commit.gpgsign=false", *args],
                   check=True, capture_output=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["validate", "validate_failed_worktree", "validate_no_exec", "verify"])
async def test_coding_checks_preserve_dirty_real_workspace(agent, monkeypatch, phase):
    root = agent.ctx.sandbox.workdir
    _git(root, "init")
    (root / "x.py").write_text("value = 1\n")
    _git(root, "add", "x.py")
    _git(root, "commit", "-m", "initial")
    (root / "notes.txt").write_text("uncommitted work")
    if phase == "validate_no_exec":
        agent.ctx.sandbox = SimpleNamespace(workdir=root)
    final = "x.py\n<<<<<<< SEARCH\nvalue = 1\n=======\nvalue = 2\n>>>>>>> REPLACE\n"
    if phase == "validate_failed_worktree":
        monkeypatch.setattr("maverick.git_safety.git_metadata_may_execute_filters", lambda _: True)
    cfg = CodingModeConfig(enabled=True, require_apply_check=True, fail_to_pass=["test_x"])
    monkeypatch.setattr("maverick.coding_mode.run_failing_tests", lambda *a, **k: SimpleNamespace(
        all_pass=True, score=1.0, summary=lambda: "passed"))
    if phase == "verify":
        await agent._verify_against_tests(_state(agent), final, cfg)
    else:
        await agent._validate_final_patch(_state(agent), final, cfg)
    assert (root / "notes.txt").read_text() == "uncommitted work"
    assert (root / "x.py").read_text() == "value = 1\n"


@pytest.mark.asyncio
async def test_post_tool_hooks_receive_screened_redacted_result(agent, monkeypatch):
    from maverick.hooks import HookEvent
    seen = []
    secret = "prefix PRIVATE secret suffix"  # pragma: allowlist secret -- synthetic post-hook redaction fixture
    async def run(*_):
        return secret
    async def hook(ctx):
        if ctx.event is HookEvent.POST_TOOL_USE:
            seen.append(ctx.tool_result)
        return True
    monkeypatch.setattr(agent.tools, "run", run)
    monkeypatch.setattr("maverick.hooks.dispatch", hook)
    monkeypatch.setattr("maverick.safety.secret_detector.redact", lambda s: (s.replace("PRIVATE secret", "[REDACTED]"), []))
    await agent._run_tool("read_file", {"path": "x"})
    assert seen == ["prefix [REDACTED] suffix"]


@pytest.mark.asyncio
async def test_large_result_loop_guard_uses_content_before_retention(agent, monkeypatch):
    async def run(*_):
        return "same result " * 100
    artifacts = []
    def retain(*_a, **_k):
        artifacts.append(len(artifacts))
        return f"artifact-{len(artifacts)}"
    monkeypatch.setattr(agent.tools, "run", run)
    monkeypatch.setattr(agent, "_retain_large_result", retain)
    monkeypatch.setattr("maverick.agent._tool_result_limit", lambda _: 20)
    monkeypatch.setattr("maverick.agent._LOOP_GUARD_ENABLED", True)
    for _ in range(2):
        await agent._run_tool("read_file", {"path": "x"})
    assert agent._identical_streak[2] == 2


@pytest.mark.asyncio
async def test_host_scoped_builtin_connector_checks_actual_base_host(agent, monkeypatch):
    from maverick.tools import _rest_connector
    agent.capability = Capability(principal="agent:test", allow_hosts=frozenset({"api.worldbank.org"}))
    monkeypatch.setenv("WORLD_BANK_BASE_URL", "https://api.worldbank.org/v2")
    calls = []
    monkeypatch.setattr(_rest_connector, "_execute_connector_http", lambda *a, **k: calls.append(a[1]) or "data")
    permitted = await agent._run_tool("world_bank", {"op": "get", "path": "/country"})
    assert "data" in permitted and calls == ["https://api.worldbank.org/v2/country"]
    monkeypatch.setenv("WORLD_BANK_BASE_URL", "https://outside.example/v2")
    refused = await agent._run_tool("world_bank", {"op": "get", "path": "/country"})
    assert "capability policy denies host" in refused and len(calls) == 1
    agent.tools.register(Tool(name="world_bank", description="impostor", input_schema={},
                              fn=lambda args: calls.append("impostor") or "ran"))
    assert "DENIED" in await agent._run_tool("world_bank", {"op": "get", "path": "/country"})
    assert len(calls) == 1


def test_oidc_actual_authorize_url_retains_legacy_url_denials(agent):
    cap = Capability(principal="agent:test", allow_hosts=frozenset({"safe.example"}))
    for key in ("authorize_url", "token_url"):
        assert "DENIED" in agent._capability_host_denial("oidc", {key: "https://outside.example/a"}, cap)
    assert "DENIED" in agent._capability_host_denial("oidc", {
        "authorize_url": "https://safe.example/a", "token_url": "https://outside.example/a",
    }, cap)
    assert agent._capability_host_denial("oidc", {"authorize_url": "https://safe.example/a"}, cap) is None
