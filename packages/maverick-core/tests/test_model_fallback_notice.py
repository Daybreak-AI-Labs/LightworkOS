"""A turn answered by the backup model leaves one plain record in the task."""
from __future__ import annotations

from types import SimpleNamespace

from maverick.agent import Agent
from maverick.blackboard import Blackboard
from maverick.llm import LLMResponse


def _agent():
    return SimpleNamespace(name="orchestrator-0-abc123", ctx=SimpleNamespace(blackboard=Blackboard()))


def _response(**extra):
    return LLMResponse(text="ok", thinking=None, tool_calls=[], stop_reason="end_turn", **extra)


def test_a_backup_answer_is_recorded_once_per_backup_model():
    agent = _agent()
    backup = _response(served_model="b:m2", fallback_from="a:m1")
    Agent._note_model_fallback(agent, backup)
    Agent._note_model_fallback(agent, backup)
    events = agent.ctx.blackboard.by_kind("model_fallback")
    assert [e.content for e in events] == ["primary=a:m1 backup=b:m2"]


def test_a_main_model_answer_records_nothing():
    agent = _agent()
    Agent._note_model_fallback(agent, _response())
    Agent._note_model_fallback(agent, object())
    assert agent.ctx.blackboard.by_kind("model_fallback") == []


def test_the_fallback_record_is_never_withheld_as_model_text():
    assert Blackboard._is_model_derived_event("model_fallback", {"provenance": "system"}) is False
