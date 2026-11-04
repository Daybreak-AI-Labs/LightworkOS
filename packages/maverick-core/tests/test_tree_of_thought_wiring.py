"""Tree-of-thought planning, wired into the orchestrator.

The plan_tree_of_thought primitive existed but nothing called it. It is now
opt-in via MAVERICK_TREE_OF_THOUGHT=1 or [planning] mode = "tree_of_thought";
when on, run_goal forks N candidate plans, a critic picks the winner, and the
winning plan is prepended to the orchestrator's brief. Off by default.
"""
from __future__ import annotations

from pathlib import Path

import maverick.config as cfg
import pytest
from maverick import tree_of_thought
from maverick.budget import Budget
from maverick.llm import LLMResponse
from maverick.orchestrator import run_goal
from maverick.sandbox import LocalBackend
from maverick.tree_of_thought import ToTResult
from maverick.world_model import WorldModel

# ---------- config helpers ----------

class TestTotConfig:
    def test_off_by_default(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_TREE_OF_THOUGHT", raising=False)
        monkeypatch.setattr(cfg, "load_config", dict)
        assert tree_of_thought.enabled() is False

    def test_enabled_via_env(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_TREE_OF_THOUGHT", "1")
        assert tree_of_thought.enabled() is True

    def test_enabled_via_config(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_TREE_OF_THOUGHT", raising=False)
        monkeypatch.setattr(cfg, "load_config",
                            lambda: {"planning": {"mode": "tree_of_thought"}})
        assert tree_of_thought.enabled() is True

    def test_candidate_count_default_env_config_and_clamp(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_TOT_CANDIDATES", raising=False)
        monkeypatch.setattr(cfg, "load_config", dict)
        assert tree_of_thought.candidate_count() == 3
        monkeypatch.setenv("MAVERICK_TOT_CANDIDATES", "5")
        assert tree_of_thought.candidate_count() == 5
        monkeypatch.setenv("MAVERICK_TOT_CANDIDATES", "0")   # clamp to >= 1
        assert tree_of_thought.candidate_count() == 3
        monkeypatch.setenv("MAVERICK_TOT_CANDIDATES", "junk")
        assert tree_of_thought.candidate_count() == 3
        monkeypatch.delenv("MAVERICK_TOT_CANDIDATES", raising=False)
        monkeypatch.setattr(cfg, "load_config",
                            lambda: {"planning": {"candidates": 7}})
        assert tree_of_thought.candidate_count() == 7


# ---------- orchestrator wiring ----------

def _prompt_blob(fake_llm) -> str:
    blob = ""
    for c in fake_llm.calls:
        blob += c.get("system") or ""
        for m in (c.get("messages") or []):
            blob += str(m.get("content", ""))
    return blob


@pytest.mark.asyncio
async def test_winning_plan_reaches_prompt_when_enabled(monkeypatch, tmp_path: Path, fake_llm):
    monkeypatch.setenv("MAVERICK_TREE_OF_THOUGHT", "1")

    called: dict = {}

    def _fake_plan(llm, goal_text, *, n=3, budget=None, **kw):
        called["goal_text"] = goal_text
        called["n"] = n
        called["budget"] = budget
        return ToTResult(
            winning_plan="TOT-SENTINEL-PLAN: step one then step two",
            candidates=[], scores=[], winning_index=0,
            critic_reason="stub", total_dollars=0.0,
        )

    monkeypatch.setattr(tree_of_thought, "plan_tree_of_thought", _fake_plan)
    fake_llm.scripted = [
        LLMResponse(text="FINAL: done", thinking=None, stop_reason="end_turn", tool_calls=[]),
    ]

    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("Build feature X", "with tests")
    await run_goal(
        llm=fake_llm, world=world, budget=Budget(max_dollars=1.0),
        goal_id=gid, sandbox=LocalBackend(workdir=tmp_path), max_depth=1,
    )

    assert called.get("goal_text", "").startswith("Build feature X")
    assert called["n"] == 3
    assert called["budget"] is not None              # shared budget passed through
    prompt = _prompt_blob(fake_llm)
    assert "TOT-SENTINEL-PLAN" in prompt  # injected into the brief
    assert "untrusted model output" in prompt
    assert "<tree_of_thought_plan>" in prompt


@pytest.mark.asyncio
async def test_planner_not_invoked_when_disabled(monkeypatch, tmp_path: Path, fake_llm):
    monkeypatch.delenv("MAVERICK_TREE_OF_THOUGHT", raising=False)
    monkeypatch.setattr(cfg, "load_config", dict)

    calls = {"n": 0}
    monkeypatch.setattr(
        tree_of_thought, "plan_tree_of_thought",
        lambda *a, **k: calls.__setitem__("n", calls["n"] + 1),
    )
    fake_llm.scripted = [
        LLMResponse(text="FINAL: done", thinking=None, stop_reason="end_turn", tool_calls=[]),
    ]

    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("X", "")
    await run_goal(
        llm=fake_llm, world=world, budget=Budget(max_dollars=1.0),
        goal_id=gid, sandbox=LocalBackend(workdir=tmp_path), max_depth=1,
    )
    assert calls["n"] == 0


@pytest.mark.asyncio
async def test_winning_plan_is_scanned_and_redacted_when_blocked(
    monkeypatch, tmp_path: Path, fake_llm,
):
    monkeypatch.setenv("MAVERICK_TREE_OF_THOUGHT", "1")

    class _Shield:
        def __init__(self):
            self.outputs: list[str] = []

        def scan_input(self, text):
            return type("Verdict", (), {"allowed": True, "reasons": []})()

        def scan_output(self, text):
            self.outputs.append(text)
            allowed = "TOT-BLOCKME" not in (text or "")
            return type(
                "Verdict", (),
                {"allowed": allowed, "reasons": [] if allowed else ["tot-policy"]},
            )()

    shield = _Shield()
    monkeypatch.setattr("maverick.orchestrator._build_shield", lambda: shield)

    def _fake_plan(llm, goal_text, *, n=3, budget=None, **kw):
        return ToTResult(
            winning_plan="safe preface\nTOT-BLOCKME\nunsafe restatement",
            candidates=[], scores=[], winning_index=0,
            critic_reason="stub", total_dollars=0.0,
        )

    monkeypatch.setattr(tree_of_thought, "plan_tree_of_thought", _fake_plan)
    fake_llm.scripted = [
        LLMResponse(text="FINAL: done", thinking=None, stop_reason="end_turn", tool_calls=[]),
    ]

    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("Build feature X", "with tests")
    await run_goal(
        llm=fake_llm, world=world, budget=Budget(max_dollars=1.0),
        goal_id=gid, sandbox=LocalBackend(workdir=tmp_path), max_depth=1,
    )

    prompt = _prompt_blob(fake_llm)
    assert any("TOT-BLOCKME" in output for output in shield.outputs)
    assert "TOT-BLOCKME" not in prompt
    assert "[redacted by Shield: tot-policy]" in prompt
