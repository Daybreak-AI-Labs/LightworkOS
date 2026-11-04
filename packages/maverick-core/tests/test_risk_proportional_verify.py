"""Risk-proportional verification (opt-in).

When ``MAVERICK_RISK_PROPORTIONAL_VERIFY`` is on, the orchestrator skips
the LLM verifier on clearly low-risk answers (short, prose-only, no tools,
no code) and records a distinct "skipped" confidence. Default off: nothing
changes. Coding tasks, tool use, embedded code, and long answers always
get full verification.
"""
from pathlib import Path

import pytest
from maverick.agent import (
    Agent,
    _final_is_low_risk,
    _risk_proportional_verify_enabled,
)
from maverick.blackboard import Blackboard
from maverick.budget import Budget
from maverick.llm import LLMResponse
from maverick.sandbox import LocalBackend
from maverick.swarm import SwarmContext
from maverick.world_model import WorldModel

# --- pure classifier -------------------------------------------------------

def test_short_prose_no_tools_is_low_risk():
    assert _final_is_low_risk("The capital of France is Paris.",
                              coding=False, tool_calls=0) is True


def test_coding_mode_is_never_low_risk():
    assert _final_is_low_risk("looks fine", coding=True, tool_calls=0) is False


def test_any_tool_use_is_not_low_risk():
    assert _final_is_low_risk("done", coding=False, tool_calls=1) is False


def test_empty_final_is_not_low_risk():
    assert _final_is_low_risk("", coding=False, tool_calls=0) is False
    assert _final_is_low_risk(None, coding=False, tool_calls=0) is False


def test_long_answer_is_not_low_risk():
    assert _final_is_low_risk("x " * 600, coding=False, tool_calls=0) is False


@pytest.mark.parametrize("body", [
    "Here is code:\n```python\nprint(1)\n```",
    "diff --git a/x b/x",
    "<<<<<<< SEARCH\nfoo\n=======\nbar\n>>>>>>> REPLACE",
    "--- a/file.py",
])
def test_embedded_code_is_not_low_risk(body):
    assert _final_is_low_risk(body, coding=False, tool_calls=0) is False


# --- enable flag -----------------------------------------------------------

def test_enabled_via_env(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config", dict)
    monkeypatch.setenv("MAVERICK_RISK_PROPORTIONAL_VERIFY", "1")
    assert _risk_proportional_verify_enabled() is True


def test_disabled_by_default(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config", dict)
    monkeypatch.delenv("MAVERICK_RISK_PROPORTIONAL_VERIFY", raising=False)
    assert _risk_proportional_verify_enabled() is False


def test_enabled_via_config(monkeypatch):
    monkeypatch.delenv("MAVERICK_RISK_PROPORTIONAL_VERIFY", raising=False)
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda: {"verification": {"risk_proportional": True}},
    )
    assert _risk_proportional_verify_enabled() is True


# --- end-to-end ------------------------------------------------------------

class _ScriptedLLM:
    """Returns scripted responses in order; counts calls so a test can prove
    whether the verifier (a second LLM call) ran."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.model = "fake:test"

    async def complete_async(self, **kwargs):
        self.calls.append(kwargs)
        if self.responses:
            return self.responses.pop(0)
        return LLMResponse(text="FINAL: done", thinking=None, tool_calls=[],
                           stop_reason="end_turn")


def _ctx(tmp_path: Path, llm) -> SwarmContext:
    world = WorldModel(tmp_path / "world.db")
    goal_id = world.create_goal("what is 2+2", "")
    return SwarmContext(
        llm=llm,
        world=world,
        budget=Budget(max_dollars=1.0),
        blackboard=Blackboard(),
        sandbox=LocalBackend(workdir=tmp_path),
        goal_id=goal_id,
        max_depth=2,
        use_skills=False,
    )


_FINAL = LLMResponse(text="FINAL: the answer is 42", thinking=None,
                     tool_calls=[], stop_reason="end_turn")


@pytest.mark.asyncio
async def test_low_risk_skips_verifier_when_enabled(tmp_path, monkeypatch):
    monkeypatch.setattr("maverick.config.load_config", dict)
    monkeypatch.setenv("MAVERICK_RISK_PROPORTIONAL_VERIFY", "1")
    llm = _ScriptedLLM([_FINAL])
    ctx = _ctx(tmp_path, llm)
    result = await Agent(ctx=ctx, role="orchestrator", brief="what is 2+2").run()
    # Verifier never ran -> only the single FINAL call was made.
    assert len(llm.calls) == 1
    assert result.final == "the answer is 42"          # no caveat on a skip
    assert result.verifier_confidence == 0.9
    assert "skipped" in result.verifier_critique


@pytest.mark.asyncio
async def test_low_risk_still_verified_when_disabled(tmp_path, monkeypatch):
    monkeypatch.setattr("maverick.config.load_config", dict)
    monkeypatch.delenv("MAVERICK_RISK_PROPORTIONAL_VERIFY", raising=False)
    accept = '{"confidence":0.77,"accepts":true,"critique":"looks good","issues":[]}'
    llm = _ScriptedLLM([
        _FINAL,
        LLMResponse(text=accept, thinking=None, tool_calls=[],
                    stop_reason="end_turn"),
    ])
    ctx = _ctx(tmp_path, llm)
    result = await Agent(ctx=ctx, role="orchestrator", brief="what is 2+2").run()
    # Verifier ran: a second LLM call, and the verdict's confidence flows out.
    assert len(llm.calls) == 2
    assert result.verifier_confidence == pytest.approx(0.77)
    assert "skipped" not in result.verifier_critique
