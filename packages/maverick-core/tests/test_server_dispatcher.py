"""Channel-server integration with the installed goal dispatcher."""
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

    @property
    def principal_id(self):
        return self.sender_id or self.user_id


@pytest.mark.parametrize(
    ("channel", "recipient", "sender", "thread"),
    [
        ("slack", "C123", "U123", "111.222"),
        ("telegram", "-100123", "123", "topic-4"),
        ("email", "alice@example.test", None, None),
    ],
)
def test_channel_question_reaches_sender_and_reply_resumes_same_goal(
    monkeypatch, tmp_path, channel, recipient, sender, thread,
):
    from maverick import runner
    from maverick import server as server_mod
    from maverick.world_model import WorldModel

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT_BY_USER", raising=False)
    monkeypatch.setattr("maverick.compliance.first_turn_disclosure", lambda *a, **k: None)
    world = WorldModel(tmp_path / "world.db")
    calls = []

    async def dispatch(goal_id, **kwargs):
        calls.append((goal_id, kwargs))
        if goal_id == 1 and len(calls) == 1:
            world.ask("Which customer should I use?", goal_id)
            world.set_goal_status(goal_id, "blocked")
            return "blocked"
        if goal_id != 1:
            world.set_goal_status(goal_id, "done", result="Separate task is done.")
            return "done"
        question = world.all_questions(goal_id)[0]
        assert question.answer == "Acme"
        world.set_goal_status(goal_id, "done", result="The Acme report is ready.")
        return "done"

    monkeypatch.setattr(runner, "run_goal_in_background_async", dispatch)
    srv = server_mod.Server.__new__(server_mod.Server)
    srv._db_path = None  # set by Server.__init__
    srv.world, srv.llm, srv.sandbox, srv.max_depth = world, object(), object(), 3
    srv._shield = None
    try:
        first = asyncio.run(srv._handle_message(ChannelMessage(
            channel, recipient, sender, "Prepare a report", thread,
        )))
        assert "Question #1 for task #1: Which customer should I use?" in first
        if channel == "slack":
            assert "Reply here with your answer" in first
            reply = "Acme"
        else:
            assert "#1 your answer" in first
            unrelated = asyncio.run(srv._handle_message(ChannelMessage(
                channel, recipient, sender, "A separate request", thread,
            )))
            assert "Separate task is done." in unrelated
            assert [goal_id for goal_id, _ in calls] == [1, 2]
            assert world.all_questions(1)[0].answer is None
            reply = "#1 Acme"
        if channel == "email":
            reply = "Subject: Re: Report\n\n#1 Acme"
        second = asyncio.run(srv._handle_message(ChannelMessage(
            channel, recipient, sender, reply, thread,
        )))
        expected = [1, 1] if channel == "slack" else [1, 2, 1]
        assert [goal_id for goal_id, _ in calls] == expected
        assert "saved your answer to Question #1" in second
        assert "The Acme report is ready." in second
        assert world.get_goal(1).status == "done"
    finally:
        world.close()


def test_channel_question_stays_with_authenticated_sender_and_thread(monkeypatch, tmp_path):
    from maverick import runner
    from maverick import server as server_mod
    from maverick.world_model import WorldModel

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT_BY_USER", raising=False)
    monkeypatch.setattr("maverick.compliance.first_turn_disclosure", lambda *a, **k: None)
    world = WorldModel(tmp_path / "world.db")
    calls = []

    async def dispatch(goal_id, **kwargs):
        calls.append(goal_id)
        if goal_id == 1:
            if len(calls) == 1:
                world.ask("Private customer?", goal_id)
                world.set_goal_status(goal_id, "blocked")
                return "blocked"
            assert world.all_questions(goal_id)[0].answer == "Acme"
            world.set_goal_status(goal_id, "done", result="Done")
            return "done"
        world.set_goal_status(goal_id, "done", result="Separate task")
        return "done"

    monkeypatch.setattr(runner, "run_goal_in_background_async", dispatch)
    srv = server_mod.Server.__new__(server_mod.Server)
    srv._db_path = None  # set by Server.__init__
    srv.world, srv.llm, srv.sandbox, srv.max_depth = world, object(), object(), 3
    srv._shield = None
    try:
        def send(sender, thread, text):
            return asyncio.run(srv._handle_message(
                ChannelMessage("slack", "C123", sender, text, thread)))
        assert "Private customer?" in send("U1", "root-1", "Prepare report")
        # An agent's answer is the whole reply, under the AI mark.
        for reply in (send("U2", "root-1", "Other work"), send("U1", "root-2", "Different thread")):
            answer, mark = reply.split("\n\n", 1)
            assert answer == "Separate task" and mark.startswith("-- Written by an agent in Lightwork.")
        assert asyncio.run(srv._handle_message(ChannelMessage(
            "slack", "C123", "U1", "Unrelated thread", "root-3",
            question_reply_only=True,
        ))) == ""
        assert world.all_questions(1)[0].answer is None
        assert "saved your answer" in send("U1", "root-1", "Acme")
        assert calls == [1, 2, 3, 1]
    finally:
        world.close()


def test_queued_question_lookup_rechecks_goal_owner_and_conversation(monkeypatch, tmp_path):
    from maverick import server as server_mod
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "world.db")
    monkeypatch.setattr("maverick.world_model.open_world", lambda: world)
    monkeypatch.setattr("maverick.world_model.close_world_if_owned", lambda _: None)
    monkeypatch.setattr(server_mod, "_linked_channel_refusal", lambda *a: None)
    monkeypatch.delenv("MAVERICK_TENANT_BY_USER", raising=False)
    try:
        conv = world.get_or_create_conversation("slack", "U1:conversation:x")
        foreign = world.get_or_create_conversation("slack", "U1:conversation:y")
        goal_id = world.create_goal("Report", "Prepare report", owner="user:slack:U1",
                                    execution_principal="user:slack:U1")
        world.append_turn(conv.id, "user", "Prepare report", goal_id=goal_id)
        world.ask("Which customer?", goal_id)
        world.set_goal_status(goal_id, "blocked")
        watch = {"goal_id": goal_id, "conversation_id": conv.id,
                 "tenant": None, "owner": "user:slack:U1",
                 "execution_principal": "user:slack:U1"}
        msg = ChannelMessage("slack", "C1", "U1", "answer", "root")
        text, retire = server_mod.queued_channel_question(watch, msg, "")
        assert "Which customer?" in text and retire is False
        assert server_mod.queued_channel_question(watch, ChannelMessage(
            "slack", "C1", "U2", "answer", "root"), "") == (None, False)
        assert server_mod.queued_channel_question(
            {**watch, "conversation_id": foreign.id}, msg, "",
        ) == (None, True)
    finally:
        world.close()


def test_a_watch_for_an_erased_or_handed_off_task_is_retired(monkeypatch, tmp_path):
    from maverick import server as server_mod
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "world.db")
    monkeypatch.setattr("maverick.world_model.open_world", lambda: world)
    monkeypatch.setattr("maverick.world_model.close_world_if_owned", lambda _: None)
    monkeypatch.setattr(server_mod, "_linked_channel_refusal", lambda *a: None)
    monkeypatch.delenv("MAVERICK_TENANT_BY_USER", raising=False)
    try:
        conv = world.get_or_create_conversation("slack", "U1:conversation:x")
        watch = {"goal_id": 999, "conversation_id": conv.id, "tenant": None,
                 "owner": "user:slack:U1", "execution_principal": "user:slack:U1"}
        msg = ChannelMessage("slack", "C1", "U1", "answer", "root")
        assert server_mod.queued_channel_question(watch, msg, "") == (None, True)
        theirs = world.create_goal("Report", "Prepare report", owner="user:slack:U9",
                                   execution_principal="user:slack:U9")
        assert server_mod.queued_channel_question({**watch, "goal_id": theirs}, msg, "") == (None, True)
    finally:
        world.close()


def test_answer_to_queued_question_watches_same_goal_for_next_question(monkeypatch, tmp_path):
    from maverick import runner
    from maverick import server as server_mod
    from maverick.world_model import WorldModel

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT_BY_USER", raising=False)
    monkeypatch.setattr("maverick.compliance.first_turn_disclosure", lambda *a, **k: None)
    monkeypatch.setattr("maverick.world_model.open_world", lambda: world)
    monkeypatch.setattr("maverick.world_model.close_world_if_owned", lambda _: None)
    monkeypatch.setattr(server_mod, "_linked_channel_refusal", lambda *a: None)
    world = WorldModel(tmp_path / "world.db")
    seen = []

    async def queued(goal_id, **kwargs):
        seen.append(goal_id)
        return "queued"

    monkeypatch.setattr(runner, "run_goal_in_background_async", queued)
    srv = server_mod.Server.__new__(server_mod.Server)
    srv._db_path = None  # set by Server.__init__
    srv.world, srv.llm, srv.sandbox, srv.max_depth = world, object(), object(), 3
    srv._shield = None
    first = ChannelMessage("slack", "C1", "U1", "Prepare report", "root-1")
    try:
        assert "queued" in asyncio.run(srv._handle_message(first))
        assert first._channel_question_watch["goal_id"] == 1
        world.ask("Which customer?", 1)
        world.set_goal_status(1, "blocked")
        second = ChannelMessage("slack", "C1", "U1", "Acme", "root-1",
                                question_reply_only=True)
        assert "queued" in asyncio.run(srv._handle_message(second))
        assert seen == [1, 1]
        assert second._channel_question_watch["goal_id"] == 1
        world.ask("Which region?", 1)
        world.set_goal_status(1, "blocked")
        text, retire = server_mod.queued_channel_question(
            second._channel_question_watch, second, "",
        )
        assert "Which region?" in text and retire is False
    finally:
        world.close()


def test_existing_slack_dm_question_keeps_legacy_conversation_key(monkeypatch, tmp_path):
    from maverick import runner
    from maverick import server as server_mod
    from maverick.world_model import WorldModel

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT_BY_USER", raising=False)
    monkeypatch.setattr("maverick.compliance.first_turn_disclosure", lambda *a, **k: None)
    world = WorldModel(tmp_path / "world.db")
    conv = world.get_or_create_conversation("slack", "U1")
    goal_id = world.create_goal("Report", "Prepare report", owner="user:slack:U1",
                                execution_principal="user:slack:U1")
    world.append_turn(conv.id, "user", "Prepare report", goal_id=goal_id)
    world.ask("Which customer?", goal_id)
    world.set_goal_status(goal_id, "blocked")
    called = []

    async def dispatch(resumed_goal, **kwargs):
        called.append((resumed_goal, kwargs["conversation_id"]))
        result = "Report ready" if resumed_goal == goal_id else "Separate request ready"
        world.set_goal_status(resumed_goal, "done", result=result)
        return "done"

    monkeypatch.setattr(runner, "run_goal_in_background_async", dispatch)
    srv = server_mod.Server.__new__(server_mod.Server)
    srv._db_path = None  # set by Server.__init__
    srv.world, srv.llm, srv.sandbox, srv.max_depth = world, object(), object(), 3
    srv._shield = None
    try:
        fresh = asyncio.run(srv._handle_message(ChannelMessage(
            "slack", "D123", "U1", "A separate request",
        )))
        assert "Separate request ready" in fresh
        assert world.all_questions(goal_id)[0].answer is None
        reply = asyncio.run(srv._handle_message(ChannelMessage(
            "slack", "D123", "U1", "#1 Acme",
        )))
        assert called == [(goal_id + 1, conv.id), (goal_id, conv.id)]
        assert world.all_questions(goal_id)[0].answer == "Acme"
        assert "Report ready" in reply
    finally:
        world.close()


@pytest.mark.parametrize(
    ("dispatch_result", "response_text", "goal_status"),
    [
        ("queued", "queued for background processing", "pending"),
        (None, "may still be running", "pending"),
    ],
)
def test_channel_submission_uses_dispatcher_and_never_runs_locally(
    monkeypatch, tmp_path, dispatch_result, response_text, goal_status,
):
    from maverick import runner
    from maverick import server as server_mod
    from maverick.world_model import WorldModel

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT_BY_USER", raising=False)
    monkeypatch.setattr("maverick.world_model.DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(
        "maverick.compliance.first_turn_disclosure", lambda *a, **k: None,
    )

    world = WorldModel(tmp_path / "world.db")
    submitted = []

    class FakeDispatcher:
        def submit(self, goal_id, **kwargs):
            submitted.append((goal_id, kwargs))
            return dispatch_result

    monkeypatch.setattr(runner, "_dispatcher", FakeDispatcher())
    monkeypatch.setattr(
        runner,
        "run_goal_in_thread",
        lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("channel bypassed installed dispatcher")
        ),
    )

    srv = server_mod.Server.__new__(server_mod.Server)
    srv._db_path = None  # set by Server.__init__
    srv.world = world
    srv.llm = object()
    srv.sandbox = object()
    srv.max_depth = 3
    srv._channels = []
    srv._tasks = []
    srv._shield = None

    class Message:
        channel = "telegram"
        user_id = "alice"
        text = "review the handoff"
        attachments: list = []

    try:
        response = asyncio.run(srv._handle_message(Message()))
        goal = world.get_goal(submitted[0][0])
    finally:
        world.close()

    assert response_text in response
    assert len(submitted) == 1
    goal_id, kwargs = submitted[0]
    assert goal_id > 0
    assert goal.status == goal_status
    assert goal.owner == "user:telegram:alice"
    assert kwargs["channel"] == "telegram"
    assert kwargs["user_id"] == "telegram:alice"
    assert kwargs["conversation_id"] > 0
