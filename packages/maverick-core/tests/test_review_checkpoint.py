"""Long-horizon review checkpoint: interval firing + reviewer gate."""
from __future__ import annotations

import types

from maverick.review_checkpoint import (
    CheckpointEvent,
    CheckpointPolicy,
    ReviewCheckpoint,
    consent_review,
    policy_from_config,
)


def _budget(dollars=0.0, tool_calls=0, elapsed=0.0):
    return types.SimpleNamespace(dollars=dollars, tool_calls=tool_calls,
                                 elapsed=lambda: elapsed)


def test_inactive_policy_never_fires():
    cp = ReviewCheckpoint(CheckpointPolicy())
    assert cp.check(_budget(dollars=1000)) is None
    assert cp.fired == 0


def test_dollar_interval_fires_each_tranche():
    seen = []
    cp = ReviewCheckpoint(CheckpointPolicy(dollars=10),
                          review=lambda e: seen.append(e) or True)
    assert cp.check(_budget(dollars=5)) is None      # under interval
    assert cp.check(_budget(dollars=10)) is None     # crossed -> approved
    assert cp.check(_budget(dollars=15)) is None     # under next interval
    assert cp.check(_budget(dollars=21)) is None     # crossed again
    assert cp.fired == 2
    assert [e.reason for e in seen] == ["dollars", "dollars"]


def test_reviewer_halt_returns_event():
    cp = ReviewCheckpoint(CheckpointPolicy(tool_calls=100),
                          review=lambda e: False)  # vote to halt
    assert cp.check(_budget(tool_calls=50)) is None
    event = cp.check(_budget(tool_calls=100))
    assert event is not None and event.reason == "tool_calls"
    assert event.value == 100


def test_wall_seconds_interval():
    cp = ReviewCheckpoint(CheckpointPolicy(wall_seconds=60), review=lambda e: True)
    assert cp.check(_budget(elapsed=30)) is None
    assert cp.check(_budget(elapsed=61)) is None
    assert cp.fired == 1


def test_heartbeat_only_no_reviewer():
    cp = ReviewCheckpoint(CheckpointPolicy(dollars=5))  # no reviewer
    assert cp.check(_budget(dollars=6)) is None   # records + continues
    assert cp.fired == 1


def test_reviewer_error_continues():
    def boom(e):
        raise RuntimeError("reviewer down")

    cp = ReviewCheckpoint(CheckpointPolicy(dollars=5), review=boom)
    assert cp.check(_budget(dollars=6)) is None   # error -> continue, not crash
    assert cp.fired == 1


def test_policy_from_config_env(monkeypatch):
    monkeypatch.setenv("MAVERICK_REVIEW_CHECKPOINT_DOLLARS", "25")
    monkeypatch.setenv("MAVERICK_REVIEW_CHECKPOINT_TOOL_CALLS", "200")
    p = policy_from_config()
    assert p.dollars == 25 and p.tool_calls == 200 and p.wall_seconds is None
    assert p.is_active()


def test_policy_from_config_off_by_default(monkeypatch):
    for v in ("DOLLARS", "TOOL_CALLS", "WALL_SECONDS"):
        monkeypatch.delenv(f"MAVERICK_REVIEW_CHECKPOINT_{v}", raising=False)
    import maverick.config as config_mod
    monkeypatch.setattr(config_mod, "load_config", dict)
    assert not policy_from_config().is_active()


def test_consent_review_requires_fresh_explicit_approval(monkeypatch):
    calls = []

    def fake_require_consent(*args, **kwargs):
        calls.append((args, kwargs))
        return types.SimpleNamespace(granted=True)

    import maverick.safety.consent as consent
    monkeypatch.setattr(consent, "require_consent", fake_require_consent)

    event = CheckpointEvent("tool_calls", 100, 50)
    assert consent_review(event, goal_id=123) is True

    assert len(calls) == 1
    positional, keywords = calls[0]
    assert positional == ("review-checkpoint",)
    assert keywords["risk"] == "medium"
    assert keywords["scope"] == "goal:123"
    assert keywords["detail"] == (
        "Long-horizon review checkpoint reached tool_calls=100 "
        "(interval 50). Continue the run?"
    )
    assert keywords["provenance"] == "review_checkpoint"
    assert keywords["allow_auto_approve"] is False
    assert keywords["consult_ledger"] is False
    card = keywords["approval_card"]
    assert card["action"] == "review-checkpoint"
    assert card["target"]["label"] == "goal:123"
    assert card["consequences"]["known_effects"] == [
        "Allows the current run to continue beyond this checkpoint."
    ]


def test_consent_review_denies_silent_auto_approval(monkeypatch):
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "auto-approve")

    event = CheckpointEvent("dollars", 10, 10)
    assert consent_review(event, goal_id=7) is False
