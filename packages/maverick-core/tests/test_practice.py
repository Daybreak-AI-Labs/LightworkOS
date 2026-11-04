"""Practice mode keeps practised work apart and lets nothing leave Lightwork."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest


@pytest.fixture
def home(tmp_path, monkeypatch):
    from maverick import config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def test_practice_is_off_unless_a_context_turns_it_on(home):
    from maverick import practice

    assert practice.active() is False
    with practice.scope():
        assert practice.active() is True
    assert practice.active() is False


def test_practised_tasks_use_a_separate_world_database(home, monkeypatch):
    from maverick import practice, world_model

    live = world_model.default_db_path()
    with practice.scope():
        practised = world_model.default_db_path()
        assert practised != live and "practice" in str(practised)
        world = world_model.world_for_tenant("acme")
        assert "practice" in str(world.path)
    assert "practice" not in str(world_model.world_for_tenant("acme").path)
    # A test or embedder that points the world elsewhere gets a practice file beside it.
    monkeypatch.setattr(world_model, "DEFAULT_DB", home / "custom.db")
    with practice.scope():
        assert world_model.default_db_path() == home / "custom.practice.db"


def _deny(name, args):
    from maverick.agent import Agent

    fake = SimpleNamespace(name="Finance specialist", ctx=SimpleNamespace(goal_id=7))
    return asyncio.run(Agent._practice_denial(fake, name, args))


def test_only_local_reads_and_coordination_run_in_practice(home, monkeypatch):
    from maverick import practice
    from maverick.safety import consent

    asked = []
    monkeypatch.setattr(consent, "require_consent", lambda action, **kw: asked.append((action, kw)) or
                        SimpleNamespace(granted=True))
    assert _deny("send_email", {"to": "pat@example.com"}) is None  # live: no gate
    with practice.scope():
        for tool in ("read_file", "list_dir", "ask_user", "spawn_subagent"):
            assert _deny(tool, {}) is None
        for tool in ("send_email", "slack", "send_payment", "shell", "http_fetch", "web_search",
                     "write_file", "gl_read_journal", "some_new_connector"):
            refusal = _deny(tool, {"to": "pat@example.com"})
            assert refusal and "did not run" in refusal and "Nothing was sent" in refusal
    held = practice.outbox()
    assert [row["name"] for row in held][:2] == ["some_new_connector", "gl_read_journal"]
    assert all(row["goal_id"] == 7 and row["kind"] == "tool" for row in held)
    # The approval a live run would need is still practised, never skipped.
    assert asked[0][0] == "send_email" and asked[0][1]["provenance"] == "practice"
    assert "does not run either way" in asked[0][1]["detail"]


def test_a_refused_practice_approval_still_runs_nothing(home, monkeypatch):
    from maverick import practice
    from maverick.safety import consent

    monkeypatch.setattr(consent, "require_consent", lambda action, **kw: SimpleNamespace(granted=False))
    with practice.scope():
        refusal = _deny("send_payment", {"amount": 900})
    assert "was not approved" in refusal and "did not run" in refusal
    assert practice.outbox()[0]["kind"] == "refused"


def test_alerts_email_webhooks_and_approval_cards_are_recorded_not_sent(home, monkeypatch):
    import smtplib

    from maverick import (
        approval_notify,
        notifications,
        personal_notification_delivery,
        practice,
        webhooks,
    )

    def boom(*args, **kwargs):  # any real transport is a leak
        raise AssertionError("a practice delivery reached a real transport")

    monkeypatch.setattr(smtplib, "SMTP", boom)
    monkeypatch.setattr(smtplib, "SMTP_SSL", boom)
    monkeypatch.setattr(webhooks, "_post", boom)
    monkeypatch.setattr(webhooks, "_post_result", boom)
    monkeypatch.setattr(notifications, "_dispatch", boom)
    monkeypatch.setattr(approval_notify, "install_announcers", boom)
    with practice.scope():
        assert notifications.send_email("pat@example.com", "Invoice paid", "Body") is False
        assert notifications.notify("Your task finished", title="Lightwork", async_dispatch=False) == 0
        assert webhooks.fire("goal.finished", {"goal": 1}, urls=["https://hooks.example.com/x"]) == 0
        assert approval_notify.approval_created(5) is None
        assert personal_notification_delivery.dispatch("user:pat", {"items": [{"id": 1}]},
                                                       {"mode": "all"}) is None
    kinds = [row["kind"] for row in practice.outbox()]
    assert kinds == ["personal message", "approval card", "webhook", "alert", "email"]


def test_practice_is_unavailable_when_turned_off_or_on_another_database(home, monkeypatch):
    from maverick import config, practice, world_model_backends

    assert practice.unavailable_reason() == ""
    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)
    assert "built-in database" in practice.unavailable_reason()
    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: False)
    from maverick import runner

    class Queue:
        def submit(self, *args, **kwargs):
            return "queued"

    monkeypatch.setattr(runner, "_dispatcher", Queue())
    assert "separate workers" in practice.unavailable_reason()
    monkeypatch.undo()
    (home / "config.toml").write_text("[practice]\nenable = false\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HOME", str(home / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(home / "config.toml"))
    config.reset_config_cache()
    assert practice.enabled() is False
    assert practice.unavailable_reason() == "Practice mode is turned off in Settings."


class _Run:
    """A paid run as the spending limits see it."""

    def __init__(self, dollars=0.0):
        self.dollars, self._reserved, self._organization_principal = dollars, 0.0, "pat"


def _budget():
    return _Run()


def test_practice_spending_is_counted_apart_from_real_limits(home):
    from maverick import practice, quotas, spending_limits

    spending_limits.set_user_limit("pat", 1.0, "day", actor="admin")
    with practice.scope():
        assert quotas.record_usage("pat", 0.40)
        assert spending_limits.recorded_spend("day", "pat", spending_limits._ledger()[0]) == pytest.approx(0.40)
    # Live spending and the real limit never see the practice spend.
    assert spending_limits.recorded_spend("day", "pat") == 0.0
    spending_limits.admit(_budget(), 0.90)
    assert practice.spending("pat") == {"cap": 1.0, "spent_today": pytest.approx(0.40), "real_ai_calls": True}


def test_practice_spending_has_its_own_daily_cap(home):
    from maverick import practice, quotas, spending_limits

    (home / "config.toml").write_text("[practice]\ndaily_spend_cap = 0.5\n", encoding="utf-8")
    from maverick import config
    config.reset_config_cache()
    assert practice.spend_cap() == 0.5
    with practice.scope():
        quotas.record_usage("pat", 0.30)
        spending_limits.admit(_budget(), 0.10)
        with pytest.raises(spending_limits.SpendingLimitReached) as refused:
            spending_limits.admit(_budget(), 0.25)
        assert "practice spending limit of $0.50 per day" in str(refused.value).lower()
        assert "real spending limits are not affected" in str(refused.value)
        assert spending_limits.start_refusal("pat") is None
        quotas.record_usage("pat", 0.20)
        assert "practice spending limit" in (spending_limits.start_refusal("pat") or "").lower()
    assert spending_limits.start_refusal("pat") is None  # live work can still start


def test_practice_cap_never_exceeds_a_real_limit(home):
    from maverick import practice, spending_limits

    spending_limits.set_user_limit("pat", 0.20, "day", actor="admin")
    with practice.scope():
        with pytest.raises(spending_limits.SpendingLimitReached):
            spending_limits.admit(_budget(), 0.30)
        assert practice.spending("pat")["cap"] == 0.20


def test_a_running_practice_task_does_not_count_toward_live_spend(home):
    from maverick import practice, spending_limits

    spending_limits.set_user_limit("pat", 1.0, "day", actor="admin")
    running = _Run(0.8)
    with practice.scope():
        spending_limits.admit(running, 0.0)
    spending_limits.admit(_budget(), 0.9)  # live: the practice run's $0.80 is not counted
    with practice.scope(), pytest.raises(spending_limits.SpendingLimitReached):
        spending_limits.admit(_budget(), 0.3)  # practice: it is


def test_a_practice_task_is_refused_on_separate_workers_not_run_live(home, monkeypatch):
    from maverick import practice, runner
    from maverick.world_model import open_world

    submitted = []

    class Queue:
        def submit(self, goal_id, **kwargs):
            submitted.append(goal_id)
            return "queued"

    with practice.scope():
        goal = open_world().create_goal("Practice: chase the PO", "practice")
        monkeypatch.setattr(runner, "_dispatcher", Queue())
        assert runner.run_goal_in_background(goal) == "error"
        assert submitted == []
        row = open_world().get_goal(goal)
        assert row.status == "blocked" and "separate workers" in (row.result or "")


def test_practice_refuses_a_postgres_world_instead_of_writing_live(home, monkeypatch):
    from maverick import practice, world_model_backends
    from maverick.world_model import open_world

    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)
    with practice.scope(), pytest.raises(practice.PracticeUnavailable) as refused:
        open_world()
    assert "built-in database" in str(refused.value)


def test_pins_and_notes_on_practice_tasks_stay_in_practice(home):
    from maverick import practice, ux_store

    ux_store.reset_shared()
    with practice.scope():
        ux_store.shared().pin("pat", 3)
        ux_store.shared().annotate(3, 1, "practice note", author="pat")
        assert ux_store.shared().pins("pat") == [3]
    # Task 3 in practice is not task 3 in live work.
    assert ux_store.shared().pins("pat") == []
    assert ux_store.shared().annotations(3) == []
    ux_store.reset_shared()
