"""Agent-written answers sent to Slack, Teams or email say so, with the way into "why"."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

import pytest


@dataclass
class ChannelMessage:
    channel: str
    user_id: str
    sender_id: str | None
    text: str
    conversation_ref: str | None = None
    attachments: list | None = None
    question_reply_only: bool = False
    # Provider identities carried by the real maverick_channels ChannelMessage.
    provider_tenant_id: str | None = None
    provider_sender_id: str | None = None

    @property
    def principal_id(self):
        return self.sender_id or self.user_id


def _server(monkeypatch, tmp_path, outcome):
    from maverick import runner
    from maverick import server as server_mod
    from maverick.world_model import WorldModel

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT_BY_USER", raising=False)
    monkeypatch.setattr("maverick.compliance.first_turn_disclosure", lambda *a, **k: None)
    # The voice reply re-reads its saved answer from the deployment's world, so
    # the default world must be the same database the server writes to.
    monkeypatch.setattr("maverick.world_model.DEFAULT_DB", tmp_path / "world.db")
    world = WorldModel(tmp_path / "world.db")

    async def dispatch(goal_id, **kwargs):
        status, result = outcome
        world.set_goal_status(goal_id, status, result=result)
        return status

    monkeypatch.setattr(runner, "run_goal_in_background_async", dispatch)
    srv = server_mod.Server.__new__(server_mod.Server)
    srv._db_path = None  # set by Server.__init__
    srv.world, srv.llm, srv.sandbox, srv.max_depth = world, object(), object(), 3
    srv._shield = None
    return srv, world


@pytest.mark.parametrize("channel", ["slack", "teams", "email"])
def test_an_agent_answer_is_marked_and_links_to_its_steps(monkeypatch, tmp_path, channel):
    monkeypatch.setenv("MAVERICK_PUBLIC_BASE_URL", "https://lightwork.example.test/")
    srv, world = _server(monkeypatch, tmp_path, ("done", "The Acme report is ready."))
    try:
        reply = asyncio.run(srv._handle_message(ChannelMessage(channel, "U1", "U1", "Prepare a report")))
    finally:
        world.close()
    answer, label = reply.rsplit("\n\n", 1)
    assert answer == "The Acme report is ready."
    assert label.startswith("-- Written by an agent in Lightwork.")
    assert label.endswith("See how it was made: https://lightwork.example.test/goals/1/trajectory")


def test_without_a_public_address_the_mark_names_the_task(monkeypatch, tmp_path):
    monkeypatch.delenv("MAVERICK_PUBLIC_BASE_URL", raising=False)
    srv, world = _server(monkeypatch, tmp_path, ("done", "Done."))
    try:
        reply = asyncio.run(srv._handle_message(ChannelMessage("slack", "U1", "U1", "Do it")))
    finally:
        world.close()
    assert reply.endswith("See how it was made: open task #1 in Lightwork and choose Steps.")


def test_a_stopped_task_message_is_not_labelled_as_an_agent_answer(monkeypatch, tmp_path):
    srv, world = _server(monkeypatch, tmp_path, ("failed", "Stopped: spending limit reached."))
    try:
        reply = asyncio.run(srv._handle_message(ChannelMessage("slack", "U1", "U1", "Do it")))
    finally:
        world.close()
    assert "Written by an agent" not in reply


def test_unknown_dispatch_asks_for_reconciliation_without_repainting_goal(monkeypatch, tmp_path):
    from maverick import runner

    srv, world = _server(monkeypatch, tmp_path, ("done", "unused"))

    async def unknown_dispatch(goal_id, **kwargs):
        return None

    monkeypatch.setattr(runner, "run_goal_in_background_async", unknown_dispatch)
    try:
        reply = asyncio.run(srv._handle_message(ChannelMessage("slack", "U1", "U1", "Do it")))
        assert world.get_goal(1).status == "pending"
    finally:
        world.close()
    assert "may still be running" in reply
    assert "Check its status before trying again" in reply


def test_a_spoken_answer_says_it_was_written_by_an_agent_without_reading_a_link(monkeypatch, tmp_path):
    from maverick_dashboard import rbac

    monkeypatch.setenv("MAVERICK_PUBLIC_BASE_URL", "https://lightwork.example.test/")
    srv, world = _server(monkeypatch, tmp_path, ("done", "The report is ready."))
    rbac.set_role("user:voice:U1", "operator")
    try:
        reply = asyncio.run(srv._handle_message(ChannelMessage("voice", "U1", "U1", "Prepare a report")))
    finally:
        world.close()
    assert reply == "The report is ready.\n\nWritten by an agent in Lightwork."


@pytest.mark.parametrize("channel", ["sms", "rcs", "bluesky", "mastodon", "threads", "irc"])
def test_a_short_message_channel_gets_a_short_mark(monkeypatch, tmp_path, channel):
    monkeypatch.setenv("MAVERICK_PUBLIC_BASE_URL", "https://lightwork.example.test/")
    srv, world = _server(monkeypatch, tmp_path, ("done", "Done."))
    try:
        reply = asyncio.run(srv._handle_message(ChannelMessage(channel, "U1", "U1", "Do it")))
    finally:
        world.close()
    assert reply == "Done.\n\n-- Written by an agent in Lightwork. Task #1."
