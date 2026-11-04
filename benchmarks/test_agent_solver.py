"""The in-process live solver drives a real goal and returns a scorable answer.

Uses a scripted FakeLLM, so the whole path (run_goal -> answer -> GAIA scorer)
runs with no API key and no network -- the contract that lets the benchmark
machinery be validated for free, then run for real by swapping the llm_factory.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agent_solver  # noqa: E402
import eval_gaia  # noqa: E402
from maverick.llm import LLMResponse  # noqa: E402


class FakeLLM:
    """Returns the same end_turn answer for every call, so run_goal converges
    regardless of how many steps it takes."""

    def __init__(self, text: str):
        self.text = text
        self.model = "fake:test"
        self.calls = 0

    def _resp(self) -> LLMResponse:
        self.calls += 1
        return LLMResponse(text=self.text, thinking=None, tool_calls=[], stop_reason="end_turn")

    async def complete_async(self, **kwargs) -> LLMResponse:
        return self._resp()

    def complete(self, **kwargs) -> LLMResponse:
        return self._resp()


class _Task:
    def __init__(self, prompt: str, answer: str):
        self.task_id = "t"
        self.prompt = prompt
        self.answer = answer
        self.metadata: dict = {}


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch, tmp_path):
    # No learning side effects; isolate home so nothing real is touched.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("MAVERICK_USE_SKILLS", "0")
    monkeypatch.setenv("MAVERICK_REFLEXION", "0")
    monkeypatch.setenv("MAVERICK_BUILTIN_SKILLS", "0")


def test_dry_run_solver_is_empty():
    assert agent_solver.dry_run_solver(_Task("q", "a")) == ""


def test_solver_runs_goal_and_returns_scorable_answer():
    solver = agent_solver.make_agent_solver(
        llm_factory=lambda: FakeLLM("Working it out.\nFINAL ANSWER: 42"),
        max_dollars=1.0, max_depth=1,
    )
    task = _Task("What is 6 * 7?", "42")
    out = solver(task)
    assert "FINAL ANSWER: 42" in out
    # End-to-end through the real GAIA scorer.
    assert eval_gaia.GaiaBenchmark().score(task, out) == 1.0


def test_solver_wrong_answer_scores_zero():
    solver = agent_solver.make_agent_solver(
        llm_factory=lambda: FakeLLM("FINAL ANSWER: 41"),
        max_dollars=1.0, max_depth=1,
    )
    task = _Task("What is 6 * 7?", "42")
    assert eval_gaia.GaiaBenchmark().score(task, solver(task)) == 0.0
