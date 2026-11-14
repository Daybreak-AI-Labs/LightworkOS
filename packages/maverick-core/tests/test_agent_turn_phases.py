"""Characterisation tests for the phases of the agent turn loop.

These pin the behaviour of the phase methods behind ``Agent._run_inner``.
Each test drives a real ``Agent`` with a scripted LLM through
``Agent.run``; the private helpers it monkeypatches (``_extract_and_apply_patch``,
``_git_apply``, ``_reset_workdir``) are the git seams the coding-mode branch
already exposes, and the module paths it patches are imported lazily by the
loop, exactly as the rest of the suite relies on.

Behaviour the loop must keep:

* A FINAL whose SEARCH/REPLACE edits were applied through the secondary edit
  tool but never announced is not reported as "no diff"; the loop salvages
  the workdir's uncommitted diff when ``max_steps`` runs out.
* Ground-truth tests (``MAVERICK_FAIL_TO_PASS``) replace the LLM judge in
  coding mode; a failed apply skips the test run instead of reporting every
  test as failing for the wrong reason; the revision loop is bounded by the
  never-reset revision-attempt counter, not by the per-FINAL validation flag.
* In benchmark mode the failing tests' expected values are withheld from the
  critique so a revision cannot hard-code them.
* The PRM nudge is injected at most once every three steps.
* Context compaction may hand back a new history list; every later append
  (assistant turn, tool results, checkpoints) must go to that list, and the
  LLM must see the very list the loop keeps appending to.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from maverick.agent import Agent
from maverick.blackboard import Blackboard
from maverick.budget import Budget
from maverick.coding_mode import CodingModeConfig
from maverick.llm import LLMResponse, ToolCall
from maverick.sandbox import LocalBackend
from maverick.swarm import SwarmContext
from maverick.world_model import WorldModel

PATCH = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a\n+b\n"


@pytest.fixture(autouse=True)
def _plain_loop(monkeypatch):
    """The loop itself, not the rehearsal twin gate."""
    monkeypatch.setenv("MAVERICK_REHEARSAL", "0")


@pytest.fixture
def ctx(tmp_path: Path, fake_llm):
    world = WorldModel(tmp_path / "world.db")
    goal_id = world.create_goal("test goal", "")
    return SwarmContext(
        llm=fake_llm, world=world, budget=Budget(max_dollars=1.0),
        blackboard=Blackboard(), sandbox=LocalBackend(workdir=tmp_path),
        goal_id=goal_id, max_depth=2, use_skills=False,
    )


def _final(text: str) -> LLMResponse:
    return LLMResponse(text=f"FINAL: {text}", thinking=None, tool_calls=[], stop_reason="end_turn")


def _tool_turn(tool_id: str) -> LLMResponse:
    return LLMResponse(
        text="", thinking=None, stop_reason="tool_use",
        tool_calls=[ToolCall(id=tool_id, name="shell", input={"cmd": "echo hi"})],
    )


def _test_result(all_pass: bool, *, score: float, summary: str, raw: str = "") -> SimpleNamespace:
    return SimpleNamespace(all_pass=all_pass, score=score, summary=lambda: summary, raw_output=raw)


def _coding_agent(ctx, monkeypatch, *, require_apply_check: bool, patches: list):
    """An orchestrator in coding mode whose git seams are scripted: each FINAL
    pops the next entry of ``patches`` from ``_extract_and_apply_patch``."""
    cfg = CodingModeConfig(enabled=True, fail_to_pass=["tests/test_x.py::test_a"],
                           require_apply_check=require_apply_check)
    monkeypatch.setattr("maverick.coding_mode.from_env", lambda: cfg)
    monkeypatch.setattr("maverick.coding_mode.defensive_validate",
                        lambda *a, **k: SimpleNamespace(ok=True, warnings=[], blocked_paths=[]))
    monkeypatch.setattr("maverick.coding_mode.validate_patch",
                        lambda *a, **k: SimpleNamespace(valid=True))
    agent = Agent(ctx=ctx, role="orchestrator", brief="fix the bug", depth=0, max_steps=6)
    agent._extract_and_apply_patch = lambda final: (patches.pop(0), None)
    agent._reset_workdir = lambda: None
    agent._git_apply = lambda patch: True
    return agent


def _critiques(history: list[dict]) -> list[str]:
    """The plain-text user turns after the brief: the loop's critiques and
    nudges (tool results are lists, the brief is index 0)."""
    return [m["content"] for m in history[1:] if m["role"] == "user" and isinstance(m["content"], str)]


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
         "-c", "commit.gpgsign=false", *args],
        check=True, capture_output=True, text=True,
    )


# --- turn gate -------------------------------------------------------------


@pytest.mark.asyncio
async def test_unverifiable_conversation_guidance_stops_before_any_paid_work(ctx, fake_llm, monkeypatch):
    def broken(*a, **k):
        raise RuntimeError("inbox unavailable")

    monkeypatch.setattr("maverick.conversation_inbox.checkpoint", broken)
    fake_llm.scripted.append(_final("never reached"))
    result = await Agent(ctx=ctx, role="researcher", brief="b", depth=0).run()
    assert result.error.startswith("Conversation guidance is unavailable")
    assert result.stop_kind == "review_checkpoint" and result.stop_detail == "RuntimeError"
    assert fake_llm.calls == []
    assert "Conversation guidance could not be verified" in ctx.blackboard.render(50)


# --- model call ------------------------------------------------------------


@pytest.mark.asyncio
async def test_prm_nudge_is_injected_once_per_three_steps(ctx, fake_llm, monkeypatch):
    monkeypatch.setattr("maverick.prm_guidance.maybe_nudge", lambda promises: "Change course now.")
    fake_llm.scripted.extend([_tool_turn("t1"), _tool_turn("t2"), _final("done")])
    agent = Agent(ctx=ctx, role="researcher", brief="b", depth=0, max_steps=6)
    assert (await agent.run()).final == "done"
    history = fake_llm.calls[-1]["messages"]
    nudges = [m for m in history if m["role"] == "user" and m["content"] == "Change course now."]
    assert len(nudges) == 1
    # The nudge precedes the first model call of the run.
    assert history.index(nudges[0]) == 1
    assert agent._last_prm_nudge_step == 0


@pytest.mark.asyncio
async def test_compaction_may_replace_the_history_and_the_loop_keeps_appending_to_it(ctx, fake_llm, monkeypatch):
    handed_out: list[list[dict]] = []

    async def compact(messages, **kwargs):
        fresh = list(messages)
        handed_out.append(fresh)
        return fresh

    monkeypatch.setattr("maverick.compaction.plugins.compact_with_async", compact)
    fake_llm.scripted.extend([_tool_turn("t1"), _final("done")])
    result = await Agent(ctx=ctx, role="researcher", brief="b", depth=0, max_steps=4).run()
    assert result.final == "done"
    assert len(handed_out) == 2
    # The LLM saw the compacted list, and the assistant turn plus the tool
    # results were appended to that same list, not to the one it replaced.
    first_call = fake_llm.calls[0]["messages"]
    assert first_call is handed_out[0]
    assert [m["role"] for m in first_call] == ["user", "assistant", "user"]
    assert first_call[-1]["content"][0]["type"] == "tool_result"
    assert fake_llm.calls[1]["messages"] is handed_out[1]
    assert fake_llm.calls[1]["messages"][-1]["role"] == "assistant"


# --- FINAL handling in coding mode ------------------------------------------


@pytest.mark.asyncio
async def test_ground_truth_tests_replace_the_llm_judge(ctx, fake_llm, monkeypatch):
    runs: list[tuple] = []

    def run_failing_tests(workdir, fail_to_pass, pass_to_pass, sandbox, *, language=""):
        runs.append((fail_to_pass, pass_to_pass, language))
        return _test_result(True, score=1.0, summary="2/2 passed")

    monkeypatch.setattr("maverick.coding_mode.run_failing_tests", run_failing_tests)
    agent = _coding_agent(ctx, monkeypatch, require_apply_check=True, patches=[PATCH])
    fake_llm.scripted.append(_final("fixed"))

    result = await agent.run()

    assert result.final == "fixed"
    assert result.final_patch == PATCH
    assert result.verifier_confidence == 1.0 and result.verifier_critique == "2/2 passed"
    assert runs == [(["tests/test_x.py::test_a"], [], "")]
    # Only one model call: the LLM judge never ran.
    assert len(fake_llm.calls) == 1
    assert "test-driven verifier: 2/2 passed" in ctx.blackboard.render(50)
    assert agent._already_verified is True


@pytest.mark.asyncio
async def test_failed_tests_ask_for_one_revision_without_leaking_expected_values(ctx, fake_llm, monkeypatch):
    results = [
        _test_result(False, score=0.0, summary="0/2 passed", raw="AssertionError: expected 42"),
        _test_result(True, score=1.0, summary="2/2 passed"),
    ]
    monkeypatch.setattr("maverick.coding_mode.run_failing_tests", lambda *a, **k: results.pop(0))
    monkeypatch.delenv("MAVERICK_BENCHMARK_OPAQUE", raising=False)
    agent = _coding_agent(ctx, monkeypatch, require_apply_check=True, patches=[PATCH, PATCH])
    fake_llm.scripted.extend([_final("first try"), _final("second try")])

    result = await agent.run()

    assert result.final == "second try" and result.verifier_confidence == 1.0
    assert len(fake_llm.calls) == 2
    critique, = _critiques(fake_llm.calls[1]["messages"])
    assert critique.startswith("Your patch did not pass the required tests.")
    assert "0/2 passed" in critique
    assert "expected 42" not in critique  # benchmark-opaque by default
    assert "SEARCH/REPLACE" in critique
    assert agent._patch_revision_attempts == 1


@pytest.mark.asyncio
async def test_a_second_test_failure_is_accepted_at_the_revision_cap(ctx, fake_llm, monkeypatch):
    monkeypatch.setattr(
        "maverick.coding_mode.run_failing_tests",
        lambda *a, **k: _test_result(False, score=0.5, summary="1/2 passed"),
    )
    agent = _coding_agent(ctx, monkeypatch, require_apply_check=True, patches=[PATCH, PATCH, PATCH])
    fake_llm.scripted.extend([_final("one"), _final("two"), _final("three")])

    result = await agent.run()

    assert result.final == "two"
    assert result.verifier_confidence == 0.5 and result.verifier_critique == "1/2 passed"
    assert len(fake_llm.calls) == 2  # the third scripted answer is never requested
    # Current behaviour, pinned: once the revision budget is spent the apply
    # check no longer runs for the revised FINAL, so the patch the verifier
    # extracted for its own test run is not carried on the result.
    assert result.final_patch is None
    assert agent._patch_revision_attempts == 1


@pytest.mark.asyncio
async def test_transparent_mode_shows_the_test_output(ctx, fake_llm, monkeypatch):
    results = [
        _test_result(False, score=0.0, summary="0/2 passed", raw="AssertionError: expected 42"),
        _test_result(True, score=1.0, summary="2/2 passed"),
    ]
    monkeypatch.setattr("maverick.coding_mode.run_failing_tests", lambda *a, **k: results.pop(0))
    monkeypatch.setenv("MAVERICK_BENCHMARK_OPAQUE", "0")
    agent = _coding_agent(ctx, monkeypatch, require_apply_check=True, patches=[PATCH, PATCH])
    fake_llm.scripted.extend([_final("first try"), _final("second try")])

    assert (await agent.run()).final == "second try"
    critique, = _critiques(fake_llm.calls[1]["messages"])
    assert "Recent test output:\nAssertionError: expected 42" in critique


@pytest.mark.asyncio
async def test_a_patch_that_does_not_apply_skips_the_tests_and_asks_for_a_fresh_diff(ctx, fake_llm, monkeypatch):
    def never(*a, **k):
        raise AssertionError("tests must not run when the patch did not apply")

    monkeypatch.setattr("maverick.coding_mode.run_failing_tests", never)
    agent = _coding_agent(ctx, monkeypatch, require_apply_check=True, patches=[PATCH, PATCH])
    agent._git_apply = lambda patch: False
    fake_llm.scripted.extend([_final("one"), _final("two")])

    result = await agent.run()

    revision, = _critiques(fake_llm.calls[1]["messages"])
    assert "could not be applied via `git apply`" in revision
    assert result.final == "two"
    assert result.verifier_confidence == 0.0 and result.verifier_critique == "patch did not apply"
    assert "patch failed to apply pre-test" in ctx.blackboard.render(50)


@pytest.mark.asyncio
async def test_a_final_without_edits_gets_one_revision_then_a_zero_confidence_answer(ctx, fake_llm, monkeypatch):
    monkeypatch.setattr("maverick.coding_mode.run_failing_tests",
                        lambda *a, **k: _test_result(True, score=1.0, summary="2/2 passed"))
    # Without the apply check the verifier branch extracts the patch itself.
    agent = _coding_agent(ctx, monkeypatch, require_apply_check=False, patches=[None, None])
    fake_llm.scripted.extend([_final("prose only"), _final("still prose")])

    result = await agent.run()

    revision, = _critiques(fake_llm.calls[1]["messages"])
    assert revision.startswith("Your FINAL did not contain valid edits.")
    assert result.final == "still prose"
    assert result.verifier_confidence == 0.0 and result.verifier_critique == "no valid diff in FINAL"
    assert result.final_patch is None
    assert "no valid diff in FINAL; asking for revision" in ctx.blackboard.render(50)


# --- completion ------------------------------------------------------------


@pytest.mark.asyncio
async def test_exhausting_max_steps_salvages_uncommitted_edits_as_the_patch(tmp_path, ctx, fake_llm):
    _git(tmp_path, "init", "-q")
    (tmp_path / "x.py").write_text("a = 1\n", encoding="utf-8")
    _git(tmp_path, "add", "x.py")
    _git(tmp_path, "commit", "-q", "-m", "base")
    (tmp_path / "x.py").write_text("a = 2\n", encoding="utf-8")
    fake_llm.scripted.extend([_tool_turn("t1"), _tool_turn("t2")])

    result = await Agent(ctx=ctx, role="coder", brief="b", depth=0, max_steps=2).run()

    assert result.error == "hit max_steps=2; captured workdir diff as final_patch"
    assert result.final is None
    assert "-a = 1" in result.final_patch and "+a = 2" in result.final_patch


@pytest.mark.asyncio
async def test_exhausting_max_steps_without_a_repository_reports_plainly(ctx, fake_llm):
    fake_llm.scripted.extend([_tool_turn("t1"), _tool_turn("t2")])
    result = await Agent(ctx=ctx, role="coder", brief="b", depth=0, max_steps=2).run()
    assert result.error == "hit max_steps=2"
    assert result.final_patch is None


# --- the decomposition itself ------------------------------------------------


def test_the_turn_loop_delegates_each_phase_to_a_method_under_the_complexity_cap():
    """``_run_inner`` is the loop skeleton; each phase lives in its own method
    so the safety-critical code can be reviewed a phase at a time. No phase
    carries a complexity waiver (ruff C901, max 20)."""
    import inspect

    src = inspect.getsource(Agent._run_inner)
    assert "noqa" not in src
    assert len(src.splitlines()) < 60
    for phase in (
        "_open_run", "_turn_gate", "_complete_turn", "_truncated_turn",
        "_record_assistant_turn", "_handle_final", "_turn_without_tools",
        "_dispatch_tools", "_exhausted_result",
    ):
        assert f"self.{phase}(" in src, phase
        assert "noqa: C901" not in inspect.getsource(getattr(Agent, phase)), phase
    for phase in (
        "_validate_final_patch", "_verify_against_tests", "_judge_final",
        "_finish_final", "_dispatch_parallel", "_dispatch_serial",
        "_append_turn_trailers", "_answer_pending_tool_uses",
    ):
        assert "noqa: C901" not in inspect.getsource(getattr(Agent, phase)), phase


@pytest.mark.asyncio
async def test_a_failed_ask_user_or_a_non_object_input_goes_back_to_the_model(ctx, fake_llm):
    fake_llm.scripted.extend([
        LLMResponse(text="", thinking=None, stop_reason="tool_use",
                    tool_calls=[ToolCall(id="q", name="ask_user", input={})]),  # no question
        LLMResponse(text="", thinking=None, stop_reason="tool_use",
                    tool_calls=[ToolCall(id="n", name="shell", input=None)]),
        _final("done"),
    ])
    result = await Agent(ctx=ctx, role="coder", brief="b", depth=0, max_steps=5).run()

    assert result.blocked_on_user is False and result.final == "done"
    assert "tool input must be a JSON object" in ctx.blackboard.render(50)
