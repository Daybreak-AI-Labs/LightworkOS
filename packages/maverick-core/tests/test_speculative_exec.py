"""Speculative execution: a confident, well-trodden turn is drafted by the cheap
model; novel or ambiguous turns fall through to the frontier model.
"""
from __future__ import annotations

from maverick import speculative_exec as se
from maverick.counterfactual_rollout import Transition, TransitionModel

OPS = ("ops", "coder", "")


def _model(policy):
    """A model whose behaviour policy at OPS is the given {action: count}."""
    trans = []
    for action, n in policy.items():
        trans += [Transition(OPS, action, None, 1.0)] * n
    return TransitionModel().fit(trans)


def test_predict_speculatable_on_dominant_action():
    spec = se.predict(_model({"shell": 18, "read": 2}), OPS)
    assert spec.speculatable
    assert spec.action == "shell" and spec.confidence >= 0.85 and spec.support == 20


def test_not_speculatable_when_ambiguous():
    spec = se.predict(_model({"shell": 10, "read": 10}), OPS)
    assert not spec.speculatable and spec.confidence == 0.5


def test_not_speculatable_when_thin_support():
    spec = se.predict(_model({"shell": 3}), OPS, min_support=8)
    assert not spec.speculatable and spec.support == 3


def test_not_speculatable_when_state_unseen():
    spec = se.predict(_model({"shell": 18}), ("novel", "role", ""))
    assert not spec.speculatable and spec.action is None


def test_accepted_match_and_mismatch():
    spec = se.predict(_model({"shell": 18, "read": 2}), OPS)
    assert se.accepted(spec, "shell")
    assert not se.accepted(spec, "read")


def test_draft_model_none_when_disabled(monkeypatch):
    monkeypatch.delenv("MAVERICK_SPECULATIVE", raising=False)
    monkeypatch.setattr(se, "_settings", lambda: dict(se._DEFAULTS))
    assert se.draft_model_for_turn("ops", "coder", "") is None


def test_draft_model_none_without_configured_draft(monkeypatch):
    monkeypatch.setenv("MAVERICK_SPECULATIVE", "1")
    monkeypatch.setattr(se, "_settings", lambda: {**se._DEFAULTS, "enable": True, "draft_model": None})
    assert se.draft_model_for_turn("ops", "coder", "") is None


def test_draft_model_returned_for_speculatable_turn(monkeypatch):
    monkeypatch.setenv("MAVERICK_SPECULATIVE", "1")
    monkeypatch.setattr(se, "_settings", lambda: {
        "enable": True, "draft_model": "cheap:model", "min_confidence": 0.85, "min_support": 8})
    monkeypatch.setattr("maverick.rehearsal_runtime.world_model",
                        lambda: _model({"shell": 18, "read": 2}))
    # speculatable -> downshift to the cheap draft
    assert se.draft_model_for_turn("ops", "coder", "") == "cheap:model"


def test_draft_model_none_for_uncertain_turn(monkeypatch):
    monkeypatch.setenv("MAVERICK_SPECULATIVE", "1")
    monkeypatch.setattr(se, "_settings", lambda: {
        "enable": True, "draft_model": "cheap:model", "min_confidence": 0.85, "min_support": 8})
    monkeypatch.setattr("maverick.rehearsal_runtime.world_model",
                        lambda: _model({"shell": 10, "read": 10}))
    # ambiguous -> frontier model (None)
    assert se.draft_model_for_turn("ops", "coder", "") is None
