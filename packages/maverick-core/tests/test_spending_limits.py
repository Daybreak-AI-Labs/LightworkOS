"""Workspace and per-person spending limits (none unless an administrator sets one)."""
from __future__ import annotations

import pytest
from maverick import spending_limits
from maverick.budget import Budget, BudgetExceeded
from maverick.quotas import UsageLedger
from maverick.spending_limits import SpendingLimitError, SpendingLimitReached


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    spending_limits._ACTIVE.clear()
    yield
    spending_limits._ACTIVE.clear()


def _budget(principal="user:alice", dollars=0.0):
    budget = Budget()
    budget._organization_principal = principal
    budget.dollars = dollars
    return budget


def test_no_limits_by_default_and_nothing_is_written():
    spending_limits.admit(_budget(dollars=1e6), projected=1e6)
    assert spending_limits.start_refusal("user:alice") is None
    assert not spending_limits._path().exists()
    assert spending_limits.load() == {"workspace": None, "default": None, "users": {}}


def test_limits_are_validated_with_codes_a_page_can_explain():
    for amount, period, code in (("0", "day", "amount"), ("-1", "day", "amount"),
                                 ("abc", "day", "amount"), ("nan", "day", "amount"),
                                 ("inf", "day", "amount"), ("5", "week", "period")):
        with pytest.raises(SpendingLimitError) as exc:
            spending_limits.set_default_limit(amount, period, actor="user:admin")
        assert exc.value.code == code
    with pytest.raises(SpendingLimitError) as exc:
        spending_limits.set_workspace_limit("5", "task", actor="user:admin")
    assert exc.value.code == "period"  # a workspace limit is per day or month
    with pytest.raises(SpendingLimitError) as exc:
        spending_limits.set_user_limit("  ", "5", "day", actor="user:admin")
    assert exc.value.code == "person"


def test_per_task_limit_stops_the_request_that_would_cross_it():
    spending_limits.set_user_limit("user:alice", "5", "task", actor="user:admin")
    spending_limits.admit(_budget(dollars=4.0), projected=0.5)
    with pytest.raises(SpendingLimitReached) as exc:
        spending_limits.admit(_budget(dollars=4.0), projected=2.0)
    assert "Your spending limit of $5.00 per task has been reached" in str(exc.value)
    assert isinstance(exc.value, BudgetExceeded)  # runs stop the way a budget stop does
    # Another person is not limited by Alice's personal limit.
    spending_limits.admit(_budget("user:bob", dollars=40.0), projected=2.0)
    # A per-task limit never blocks starting new work.
    assert spending_limits.start_refusal("user:alice") is None


def test_daily_limit_counts_recorded_spend_and_live_runs():
    spending_limits.set_user_limit("user:alice", "10", "day", actor="user:admin")
    UsageLedger().record("user:alice", 6.0, 0, 0)
    UsageLedger().record("user:bob", 50.0, 0, 0)
    spending_limits.admit(_budget(dollars=0.0), projected=3.0)
    running = _budget(dollars=3.5)  # another run of Alice's, not yet on the ledger
    spending_limits.admit(running, projected=0.0)
    with pytest.raises(SpendingLimitReached):
        spending_limits.admit(_budget(dollars=0.0), projected=1.0)
    assert spending_limits.start_refusal("user:alice") is None  # $9.50 of $10 used
    # Once that run's spend reaches the ledger it is not counted twice.
    UsageLedger().record("user:alice", 3.5, 0, 0)
    spending_limits.mark_recorded(running)
    with pytest.raises(SpendingLimitReached):
        spending_limits.admit(_budget(dollars=0.0), projected=1.0)
    spending_limits.admit(_budget(dollars=0.0), projected=0.4)


def test_start_refusal_once_the_limit_is_used_up():
    spending_limits.set_user_limit("user:alice", "10", "day", actor="user:admin")
    UsageLedger().record("user:alice", 10.0, 0, 0)
    reason = spending_limits.start_refusal("user:alice")
    assert reason.startswith("Your spending limit of $10.00 per day has been reached")
    assert "Admin > Spending limits" in reason
    assert spending_limits.start_refusal("user:bob") is None


def test_month_window_includes_earlier_days_but_day_window_does_not(monkeypatch):
    monkeypatch.setattr(spending_limits, "_window",
                        lambda period, now=None: "2026-09-15" if period == "day" else "2026-09")
    UsageLedger().record("user:alice", 7.0, 0, 0, day="2026-09-02")
    UsageLedger().record("user:alice", 1.0, 0, 0, day="2026-08-31")
    UsageLedger().record("user:alice", 2.0, 0, 0, day="2026-09-15")
    assert spending_limits.recorded_spend("day", "user:alice") == 2.0
    assert spending_limits.recorded_spend("month", "user:alice") == 9.0
    spending_limits.set_user_limit("user:alice", "10", "month", actor="user:admin")
    with pytest.raises(SpendingLimitReached):
        spending_limits.admit(_budget(), projected=1.5)
    spending_limits.set_user_limit("user:alice", "10", "day", actor="user:admin")
    spending_limits.admit(_budget(), projected=1.5)


def test_workspace_limit_adds_up_everyone():
    spending_limits.set_workspace_limit("20", "day", actor="user:admin")
    UsageLedger().record("user:alice", 9.0, 0, 0)
    UsageLedger().record("user:bob", 9.0, 0, 0)
    with pytest.raises(SpendingLimitReached) as exc:
        spending_limits.admit(_budget("user:carol"), projected=3.0)
    assert str(exc.value).startswith("The workspace spending limit of $20.00 per day")
    spending_limits.clear_workspace_limit(actor="user:admin")
    spending_limits.admit(_budget("user:carol"), projected=3.0)


def test_personal_limit_replaces_the_limit_for_everyone():
    spending_limits.set_default_limit("5", "day", actor="user:admin")
    spending_limits.set_user_limit("user:alice", "50", "day", actor="user:admin")
    UsageLedger().record("user:alice", 20.0, 0, 0)
    UsageLedger().record("user:bob", 4.0, 0, 0)
    spending_limits.admit(_budget("user:alice"), projected=1.0)
    with pytest.raises(SpendingLimitReached):
        spending_limits.admit(_budget("user:bob"), projected=2.0)
    spending_limits.clear_user_limit("user:alice", actor="user:admin")
    with pytest.raises(SpendingLimitReached):
        spending_limits.admit(_budget("user:alice"), projected=1.0)


def test_unreadable_limits_pause_paid_work_instead_of_lifting_limits():
    spending_limits.set_workspace_limit("20", "day", actor="user:admin")
    spending_limits._path().write_text("{not json", encoding="utf-8")
    with pytest.raises(SpendingLimitReached) as exc:
        spending_limits.admit(_budget(), projected=0.01)
    assert "could not be read" in str(exc.value)
    with pytest.raises(SpendingLimitError):
        spending_limits.start_refusal("user:alice")


def test_installer_config_seeds_limits_until_an_admin_saves(tmp_path, monkeypatch):
    from maverick import config
    cfg = tmp_path / "config.toml"
    cfg.write_text("[spending_limits]\nworkspace_dollars = 100.0\nworkspace_period = \"month\"\n"
                   "default_user_dollars = 25.0\ndefault_user_period = \"month\"\n",
                   encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    config.reset_config_cache()
    try:
        limits = spending_limits.load()
        assert limits["workspace"] == {"amount": 100.0, "period": "month"}
        assert limits["default"] == {"amount": 25.0, "period": "month"}
        spending_limits.clear_workspace_limit(actor="user:admin")
        assert spending_limits.load()["workspace"] is None
        assert spending_limits.load()["default"] == {"amount": 25.0, "period": "month"}
    finally:
        config.reset_config_cache()


def test_every_change_is_audited(monkeypatch):
    rows = []
    import maverick.audit as audit
    monkeypatch.setattr(audit, "audit_event", lambda kind, **kw: rows.append((kind, kw)) or True)
    spending_limits.set_user_limit("user:alice", "5", "day", actor="user:admin")
    assert rows == [("spending_limits_changed", {
        "agent": "operator", "actor": "user:admin", "workspace": None, "default": None,
        "people": 1})]


def test_every_paid_provider_request_is_checked():
    from maverick import provider_cost_cap
    spending_limits.set_workspace_limit("1", "day", actor="user:admin")
    UsageLedger().record("user:alice", 1.0, 0, 0)
    with pytest.raises(SpendingLimitReached):
        provider_cost_cap.reserve("anthropic", 0.25, organization_budget=_budget())


def test_new_workspaces_have_no_daily_cap_by_default():
    from maverick.tenant import registry
    assert registry.DEFAULT_TENANT_DAILY_DOLLARS == 0.0
    record = registry.create_tenant("acme-limits")
    assert record.max_daily_dollars == 0.0
    assert registry.tenant_over_quota("acme-limits") is None


def _final_script(make_llm_response):
    return [
        make_llm_response(text="FINAL: the answer is 42"),
        make_llm_response(
            text='{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}',
        ),
        make_llm_response(text="FINAL: (no skill)"),
    ]


async def _run(tmp_path, fake_llm, user_id=None):
    from maverick.orchestrator import run_goal
    from maverick.sandbox import LocalBackend
    from maverick.world_model import WorldModel
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("compute the answer", "trivial")
    budget = Budget(max_dollars=1.0)
    out = await run_goal(llm=fake_llm, world=world, budget=budget, goal_id=gid,
                         sandbox=LocalBackend(workdir=tmp_path), max_depth=1,
                         user_id=user_id)
    return out, world.get_goal(gid), budget


@pytest.mark.asyncio
async def test_goal_is_refused_before_any_paid_work_when_the_limit_is_used_up(
    tmp_path, fake_llm, make_llm_response, monkeypatch,
):
    monkeypatch.setenv("MAVERICK_BILLING_STRICT", "false")
    spending_limits.set_user_limit("user:alice", "5", "day", actor="user:admin")
    UsageLedger().record("user:alice", 5.0, 0, 0)
    fake_llm.scripted = _final_script(make_llm_response)
    out, goal, _ = await _run(tmp_path, fake_llm, user_id="alice")
    assert out.startswith("Your spending limit of $5.00 per day has been reached")
    assert fake_llm.calls == []
    assert goal.status == "blocked"
    # Bob has no limit, so his work runs, and its spend is marked as recorded.
    fake_llm.scripted = _final_script(make_llm_response)
    out, goal, budget = await _run(tmp_path, fake_llm, user_id="bob")
    assert goal.status == "done"
    assert budget._spending_recorded == budget.dollars


@pytest.mark.asyncio
async def test_unreadable_limits_pause_new_work(tmp_path, fake_llm, make_llm_response, monkeypatch):
    monkeypatch.setenv("MAVERICK_BILLING_STRICT", "false")
    spending_limits.set_workspace_limit("20", "day", actor="user:admin")
    spending_limits._path().write_text("{broken", encoding="utf-8")
    fake_llm.scripted = _final_script(make_llm_response)
    out, goal, _ = await _run(tmp_path, fake_llm)
    assert "spending limits could not be read" in out
    assert fake_llm.calls == []
    assert goal.status == "blocked"


def test_each_limit_remembers_who_set_it_and_when():
    spending_limits.set_workspace_limit("100", "month", actor="user:ann")
    spending_limits.set_default_limit("20", "day", actor="user:ben")
    spending_limits.set_user_limit("user:alice", "5", "task", actor="user:cat")
    marks = spending_limits.provenance()
    assert marks["workspace"]["by"] == "user:ann"
    assert marks["default"]["by"] == "user:ben"
    assert marks["users"]["user:alice"]["by"] == "user:cat"
    assert marks["users"]["user:alice"]["at"] > 0
    # Changing one limit leaves the other marks alone; clearing drops its mark.
    spending_limits.set_user_limit("user:bob", "9", "day", actor="user:dan")
    assert spending_limits.provenance()["users"]["user:alice"]["by"] == "user:cat"
    spending_limits.clear_user_limit("user:alice", actor="user:dan")
    assert "user:alice" not in spending_limits.provenance()["users"]
    spending_limits.clear_workspace_limit(actor="user:dan")
    assert spending_limits.provenance()["workspace"] is None
    assert spending_limits.provenance()["default"]["by"] == "user:ben"
    # The limits themselves keep their saved shape.
    assert spending_limits.load()["users"] == {"user:bob": {"amount": 9.0, "period": "day"}}


def test_a_damaged_mark_never_changes_a_limit():
    import json
    spending_limits.set_user_limit("user:alice", "5", "day", actor="user:cat")
    path = spending_limits._path()
    document = json.loads(path.read_text(encoding="utf-8"))
    document["set_by"] = {"users": {"user:alice": "not a mark"}, "workspace": {"by": "", "at": 1}}
    path.write_text(json.dumps(document), encoding="utf-8")
    assert spending_limits.provenance() == {"workspace": None, "default": None, "users": {}}
    assert spending_limits.load()["users"]["user:alice"] == {"amount": 5.0, "period": "day"}
    spending_limits.admit(_budget(), projected=4.0)
    with pytest.raises(SpendingLimitReached):
        spending_limits.admit(_budget(), projected=6.0)


def test_standing_shows_what_admission_enforces():
    spending_limits.set_default_limit("10", "day", actor="user:ben")
    spending_limits.set_workspace_limit("15", "day", actor="user:ann")
    UsageLedger().record("user:alice", 4.0, 0, 0)
    UsageLedger().record("user:bob", 7.0, 0, 0)
    person, workspace = spending_limits.standing("user:alice")["limits"]
    assert person["kind"] == "everyone" and person["set"]["by"] == "user:ben"
    assert person["spent"] == 4.0 and person["remaining"] == 6.0
    assert workspace["kind"] == "workspace" and workspace["set"]["by"] == "user:ann"
    assert workspace["spent"] == 11.0 and workspace["remaining"] == 4.0
    # Admission agrees: the smaller amount left decides.
    spending_limits.admit(_budget("user:alice"), projected=3.99)
    with pytest.raises(SpendingLimitReached):
        spending_limits.admit(_budget("user:alice"), projected=4.01)
    # A personal per-task limit has no running total.
    spending_limits.set_user_limit("user:alice", "2", "task", actor="user:cat")
    person = spending_limits.standing("user:alice")["limits"][0]
    assert person["kind"] == "person" and person["set"]["by"] == "user:cat"
    assert "remaining" not in person and "spent" not in person
    assert spending_limits.standing("user:alice")["installer_defaults"] is False


def test_standing_without_limits_is_empty():
    assert spending_limits.standing("user:alice") == {"limits": [], "installer_defaults": True,
                                                      "spend_recorded_at": None}


def test_spend_views_say_when_spending_was_last_recorded():
    import time
    assert spending_limits.spend_recorded_at() is None  # nothing recorded: no made-up time
    before = time.time()
    UsageLedger().record("user:alice", 2.0, 0, 0)
    stamp = spending_limits.spend_recorded_at()
    assert stamp is not None and before - 2 <= stamp <= time.time() + 2
    spending_limits.set_workspace_limit("50", "month", actor="user:admin")
    assert spending_limits.standing("user:alice")["spend_recorded_at"] == stamp
    assert spending_limits.workspace_standing()["spend_recorded_at"] == stamp
    assert spending_limits.overview(["user:alice"])["spend_recorded_at"] == stamp
