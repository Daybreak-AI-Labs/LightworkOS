"""Pre-execution rehearsal: the twin must proceed where confident, block a
confidently-poor plan, and ESCALATE where it's uncertain or has no support --
and stay fail-open while disabled.
"""
from __future__ import annotations

from maverick import rehearsal as rh
from maverick.counterfactual_rollout import Transition, TransitionModel

START, MID, GOOD, BAD = ("start",), ("mid",), ("good",), ("bad",)


def _model(transitions):
    return TransitionModel(alpha=0.5).fit(transitions)


def _good():
    return _model([Transition(START, "a", GOOD)] * 20 + [Transition(GOOD, "go", None, 1.0)] * 20)


def _bad():
    return _model([Transition(START, "a", BAD)] * 20 + [Transition(BAD, "go", None, 0.0)] * 20)


def _uncertain():
    return _model(
        [Transition(START, "a", GOOD)] * 10
        + [Transition(START, "a", BAD)] * 10
        + [Transition(GOOD, "go", None, 1.0)] * 10
        + [Transition(BAD, "go", None, 0.0)] * 10
    )


def test_proceed_when_confidently_good():
    v = rh.rehearse(_good(), START, ["a"])
    assert v.decision == rh.PROCEED and v.proceed
    assert v.known and v.predicted_outcome > 0.9 and v.uncertainty < 0.05


def test_block_when_confidently_poor():
    v = rh.rehearse(_bad(), START, ["a"])
    assert v.decision == rh.BLOCK
    assert v.known and v.predicted_outcome < 0.1


def test_escalate_when_uncertain():
    v = rh.rehearse(_uncertain(), START, ["a"], rollouts=400)
    assert v.decision == rh.ESCALATE
    assert v.known and v.uncertainty > 0.25


def test_escalate_when_unknown():
    # The model has never seen action "b" in START -> it cannot vouch for it.
    v = rh.rehearse(_good(), START, ["b"])
    assert v.decision == rh.ESCALATE
    assert not v.known and v.uncertainty == 1.0 and v.support == 0


def test_empty_plan_escalates():
    v = rh.rehearse(_good(), START, [])
    assert v.decision == rh.ESCALATE


def test_multistep_plan_forces_the_sequence():
    model = _model([Transition(START, "a", MID)] * 20 + [Transition(MID, "b", None, 1.0)] * 20)
    v = rh.rehearse(model, START, ["a", "b"])
    assert v.decision == rh.PROCEED and v.predicted_outcome > 0.9


def test_gate_action_fail_open_when_disabled(monkeypatch):
    monkeypatch.delenv("MAVERICK_REHEARSAL", raising=False)
    monkeypatch.setattr(rh, "_settings", lambda: dict(rh._DEFAULTS))  # enable=False
    # Even a confidently-poor plan proceeds when the gate is OFF (fail-open).
    v = rh.gate_action(_bad(), START, ["a"])
    assert v.decision == rh.PROCEED and "disabled" in v.reason


def test_gate_action_blocks_bad_plan_when_enabled(monkeypatch):
    monkeypatch.setenv("MAVERICK_REHEARSAL", "1")
    assert rh.gate_action(_bad(), START, ["a"]).decision == rh.BLOCK
    assert rh.gate_action(_good(), START, ["a"]).decision == rh.PROCEED
    assert rh.gate_action(_good(), START, ["b"]).decision == rh.ESCALATE


def test_enabled_off_by_default(monkeypatch):
    monkeypatch.delenv("MAVERICK_REHEARSAL", raising=False)
    monkeypatch.setattr("maverick.config.get_rehearsal", lambda: {"enable": False})
    assert rh.enabled() is False
    monkeypatch.setenv("MAVERICK_REHEARSAL", "1")
    assert rh.enabled() is True


def test_live_rehearsal_observes_by_default_and_requires_explicit_hold(monkeypatch):
    from maverick import config

    monkeypatch.delenv("MAVERICK_REHEARSAL", raising=False)
    monkeypatch.setattr(config, "load_config", dict)
    assert config.get_rehearsal()["mode"] == "observe"
    assert rh.enforcing() is False

    monkeypatch.setattr(config, "load_config", lambda: {"rehearsal": {"mode": "hold"}})
    assert rh.enforcing() is True

    monkeypatch.setattr(config, "load_config", lambda: {"rehearsal": {"mode": "typo"}})
    assert config.get_rehearsal()["mode"] == "observe"
    assert rh.enforcing() is False
