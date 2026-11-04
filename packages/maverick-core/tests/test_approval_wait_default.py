"""Risky steps wait 30 minutes for a decision on the Approvals page.

``[approval] dashboard_wait_seconds`` defaults to 1800 (it was 300); explicit
values and ``MAVERICK_CONSENT_DASHBOARD_TIMEOUT`` keep working. A parked
request's card stays approvable for that wait plus the undo window (a decision
settles only after it), capped at one hour, so a person who decides at minute 20
is not refused as "expired". A timeout still refuses.
"""
from __future__ import annotations

import copy
import time

import pytest
from maverick.safety import consent


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    from maverick import config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_CONSENT_DASHBOARD_TIMEOUT", raising=False)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _config(tmp_path, text):
    from maverick import config

    (tmp_path / "config.toml").write_text(text, encoding="utf-8")
    config.reset_config_cache()


def test_a_risky_step_waits_thirty_minutes_by_default():
    assert consent.dashboard_wait_seconds() == 1800.0


def test_explicit_waits_keep_working(tmp_path, monkeypatch):
    _config(tmp_path, "[approval]\ndashboard_wait_seconds = 300\n")
    assert consent.dashboard_wait_seconds() == 300.0
    monkeypatch.setenv("MAVERICK_CONSENT_DASHBOARD_TIMEOUT", "45")
    assert consent.dashboard_wait_seconds() == 45.0
    monkeypatch.setenv("MAVERICK_CONSENT_DASHBOARD_TIMEOUT", "not a number")
    assert consent.dashboard_wait_seconds() == 1800.0


@pytest.mark.parametrize(("wait", "grace", "lifetime"), [
    (1800, 30, 1830), (300, 0, 300), (300, 30, 330), (7200, 30, 3600), (3590, 30, 3600), (5, 30, 60),
])
def test_a_card_stays_approvable_for_the_wait_and_undo_window_capped_at_one_hour(
        tmp_path, monkeypatch, wait, grace, lifetime):
    monkeypatch.setenv("MAVERICK_APPROVAL_UNDO_GRACE_SECONDS", str(grace))
    _config(tmp_path, f"[approval]\ndashboard_wait_seconds = {wait}\n")
    assert consent._approval_card_ttl() == float(lifetime)


def test_an_exact_operation_card_lives_as_long_as_the_wait_and_undo_window(monkeypatch):
    authority = {
        "actor": "user:alice", "workspace": "local", "role": "operator",
        "versions": {"principal_sha256": "a" * 64, "role_permissions_sha256": "b" * 64,
                     "budget_authority_sha256": "c" * 64},
    }
    budget = {"currency": "USD", "external_effect_cost": "unmeasured", "authority_sha256": "c" * 64}
    monkeypatch.setattr(consent, "_runtime_approval_authority",
                        lambda *, actor_hint=None: (copy.deepcopy(authority), dict(budget), True))
    cards = []

    def decide(*_args, approval_card=None, **_kwargs):
        cards.append(approval_card)
        return consent.ConsentDecision(True, "dashboard", "high", time.time(), actor="user:dana")

    monkeypatch.setattr(consent, "require_consent", decide)
    before = time.time()
    permit = consent.require_operation_consent(
        "shell", risk="high", scope="sandbox:/work", detail="Run a command in the sandbox.",
        provenance="shell", target={"workdir": "/work"}, parameters={"command": "ls"},
        parameter_summary=["Runs this exact command once."], known_effects=["Runs one command."],
        unresolved_assumptions=[], before="Not run.", after="Run once.", irreversible=True,
    )
    assert cards and permit.card["expires_at"] == pytest.approx(before + 1800 + 30, abs=5)
    # An explicit lifetime still wins.
    permit = consent.require_operation_consent(
        "shell", risk="high", scope="sandbox:/work", detail="Run a command in the sandbox.",
        provenance="shell", target={"workdir": "/work"}, parameters={"command": "ls"},
        parameter_summary=["Runs this exact command once."], known_effects=["Runs one command."],
        unresolved_assumptions=[], before="Not run.", after="Run once.", irreversible=True,
        ttl_seconds=120.0,
    )
    assert permit.card["expires_at"] == pytest.approx(time.time() + 120, abs=5)


def test_a_waiting_request_is_still_refused_when_nobody_decides(tmp_path, monkeypatch):
    """No decision within the wait is a refusal, never an approval (fake clock)."""
    from maverick import world_model
    from maverick.world_model import WorldModel

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    world = WorldModel(tmp_path / "world.db")
    approval_id = world.create_approval("shell", risk="high")
    clock = {"now": 1000.0}
    monkeypatch.setattr(consent.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(consent.time, "sleep", lambda seconds: clock.update(now=clock["now"] + seconds))
    card = {"binding_sha256": "x"}
    assert consent._await_dashboard_decision(world, approval_id, card, "high", goal_id=None,
                                             withdraw_on_timeout=True) is None
    assert clock["now"] >= 1000.0 + 1800
    assert world.get_approval(approval_id).status == "denied"


@pytest.mark.parametrize("vote_at", [50, 95, 100, 119])
def test_a_vote_in_the_last_seconds_of_the_wait_is_not_refused_as_stale(tmp_path, monkeypatch, vote_at):
    """The undo grace runs past the wait; the parked card must outlive both (fake clock)."""
    from maverick import world_model
    from maverick.world_model import WorldModel

    authority = {
        "actor": "user:alice", "workspace": "local", "role": "operator",
        "versions": {"principal_sha256": "a" * 64, "role_permissions_sha256": "b" * 64,
                     "budget_authority_sha256": "c" * 64},
    }
    budget = {"currency": "USD", "external_effect_cost": "unmeasured", "authority_sha256": "c" * 64}
    monkeypatch.setattr(consent, "_runtime_approval_authority",
                        lambda *, actor_hint=None: (copy.deepcopy(authority), dict(budget), True))
    monkeypatch.setenv("MAVERICK_CONSENT_DASHBOARD_TIMEOUT", "120")
    monkeypatch.setenv("MAVERICK_APPROVAL_UNDO_GRACE_SECONDS", "30")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    world = WorldModel(tmp_path / "world.db")
    clock = {"now": 1_000_000.0}
    start = clock["now"]
    voted = []

    def sleep(seconds):
        clock["now"] += seconds
        if not voted and clock["now"] - start >= vote_at:
            voted.append(world.decide_approval(approval_id, "approved", decided_by="user:dana"))

    monkeypatch.setattr(consent.time, "time", lambda: clock["now"])
    monkeypatch.setattr(consent.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(consent.time, "sleep", sleep)
    card = consent._dashboard_approval_card("shell", "high", "sandbox:/work", "Run one command.", "shell", None)
    from maverick.approval_cards import encode_approval_detail

    approval_id = world.create_approval("shell", risk="high", detail=encode_approval_detail(card))
    decision = consent._await_dashboard_decision(world, approval_id, card, "high", goal_id=None,
                                                 withdraw_on_timeout=True)
    assert voted == [True]
    assert (decision.granted, decision.source) == (True, "dashboard")
