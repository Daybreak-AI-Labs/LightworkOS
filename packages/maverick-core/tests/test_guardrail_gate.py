"""The live guardrail gate: when the data engine is on, the agent holds an action
a learned guardrail flags as causally harmful -- and stays a no-op when off.
"""
from __future__ import annotations

from maverick import negative_knowledge as nk
from maverick.agent import Agent
from maverick.data_engine import FailureClass


class _Ctx:
    goal_id = 1


class _StubAgent:
    """Minimal stand-in: _guardrail_denial only reads self.name / self.ctx."""
    name = "tester"
    ctx = _Ctx()


def _registry_flagging(tmp_path, action):
    reg = nk.GuardrailRegistry(path=tmp_path / "g.json")
    reg.update(nk.mine([FailureClass(
        action=action, count=5, mean_outcome=0.2, causal_effect=-0.5,
        ci_low=-0.6, ci_high=-0.2, trustworthy=True, exemplars=())]))
    return reg


def test_guardrail_holds_a_flagged_action(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_DATA_ENGINE", "1")
    monkeypatch.setattr("maverick.negative_knowledge.shared",
                        lambda: _registry_flagging(tmp_path, "shell"))
    held = Agent._guardrail_denial(_StubAgent(), "shell")
    assert held is not None and "guardrail" in held.lower()
    # an action with no guardrail runs normally
    assert Agent._guardrail_denial(_StubAgent(), "read_file") is None


def test_guardrail_is_noop_when_data_engine_off(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_DATA_ENGINE", raising=False)
    monkeypatch.setattr("maverick.config.get_data_engine", lambda: {"enable": False})
    monkeypatch.setattr("maverick.negative_knowledge.shared",
                        lambda: _registry_flagging(tmp_path, "shell"))
    # even a flagged action runs when the engine is off (fail-open default)
    assert Agent._guardrail_denial(_StubAgent(), "shell") is None
