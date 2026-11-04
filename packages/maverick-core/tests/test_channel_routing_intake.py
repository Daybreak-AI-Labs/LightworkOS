"""[channels.routing] rules applied at channel intake.

A message that matches a rule is handled by the rule's specialist pack (the
goal is created with that domain); with no rules, or no match, intake is
exactly as before: no domain is passed at all.
"""
from __future__ import annotations

import asyncio

import pytest


@pytest.fixture()
def intake(monkeypatch, tmp_path):
    from maverick import config, runner
    from maverick import server as server_mod
    from maverick.world_model import WorldModel

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    for name in ("MAVERICK_TENANT", "MAVERICK_TENANT_BY_USER", "MAVERICK_CONFIG_OVERLAY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("maverick.world_model.DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr("maverick.compliance.first_turn_disclosure", lambda *a, **k: None)

    class Dispatcher:
        def submit(self, goal_id, **kwargs):
            return "queued"

    monkeypatch.setattr(runner, "_dispatcher", Dispatcher())
    world = WorldModel(tmp_path / "world.db")
    calls = []
    create_goal = world.create_goal

    def recording_create_goal(*args, **kwargs):
        calls.append(kwargs)
        return create_goal(*args, **kwargs)

    monkeypatch.setattr(world, "create_goal", recording_create_goal)
    srv = server_mod.Server.__new__(server_mod.Server)
    srv._db_path = None  # set by Server.__init__
    srv.world, srv.llm, srv.sandbox, srv.max_depth = world, object(), object(), 3
    srv._channels, srv._tasks, srv._shield = [], [], None

    def rules(text: str) -> None:
        (tmp_path / "config.toml").write_text(text, encoding="utf-8")
        config.reset_config_cache()

    def send(text: str):
        class Message:
            channel = "mattermost"
            user_id = "alice"
            attachments: list = []

        Message.text = text
        asyncio.run(srv._handle_message(Message()))

    yield srv, world, calls, rules, send
    world.close()
    config.reset_config_cache()


def _specialist() -> str:
    from maverick.domain import enabled_domains

    return sorted(enabled_domains())[0]


def test_without_rules_intake_is_unchanged(intake):
    _srv, world, calls, rules, send = intake
    rules("")
    send("please pay this invoice")
    assert calls and "domain" not in calls[-1]


def test_a_saved_rule_sends_matching_messages_to_its_specialist(intake):
    _srv, world, calls, rules, send = intake
    specialist = _specialist()
    rules(f'[[channels.routing.rules]]\nany_keyword = ["invoice"]\nurgency = ""\n'
          f'attachments = []\nmin_length = 0\nspecialist = "{specialist}"\n')
    send("please pay this invoice today")
    assert calls[-1]["domain"] == specialist
    send("what is on my calendar")
    assert "domain" not in calls[-1]


def test_a_rule_naming_a_pack_that_is_not_enabled_is_ignored(intake):
    _srv, world, calls, rules, send = intake
    rules('[[channels.routing.rules]]\nany_keyword = ["invoice"]\nspecialist = "no_such_pack"\n')
    send("please pay this invoice")
    assert "domain" not in calls[-1]


def test_message_signals_describe_attached_files():
    from maverick.channel_autorouting import RouteRule, signals_for_message, specialist_for

    class Message:
        text = "see attached"
        channel = "slack"
        attachments = [{"mime": "application/pdf"}, {"mime": "image/png"}, {"mime": ""}]

    assert signals_for_message(Message()).attachments == ("pdf", "image", "file")
    specialist = _specialist()
    rule = RouteRule(channel="", attachments=("pdf",), specialist=specialist, name="pdfs")
    assert specialist_for(Message(), rules=[rule]) == specialist
    assert specialist_for(Message(), rules=[RouteRule(channel="email")]) == ""
