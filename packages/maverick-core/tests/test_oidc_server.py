from __future__ import annotations

import asyncio
from dataclasses import dataclass


class _World:
    def __init__(self):
        self.conversation_key = None
        self.turns = []
        self.goals = []

    def latest_artifacts(self, goal_id):
        return []  # the goal saved no output files

    def open_channel_questions(self, conversation_id, owner, execution_principal):
        return []  # no blocked question awaits a reply

    def get_or_create_conversation(self, channel, user_id):
        self.conversation_key = (channel, user_id)
        return type("Conversation", (), {"id": 1})()

    def append_turn(self, conversation_id, role, text, *, goal_id=None):
        self.turns.append((conversation_id, role, text))

    def create_goal(self, title, text, *, owner="", execution_principal=""):
        self.goals.append((title, text, owner, execution_principal))
        return 7

    def set_goal_status(self, *args, **kwargs):
        return None

    def get_goal(self, goal_id):
        return type("Goal", (), {"result": "ok", "status": "done"})()


@dataclass(frozen=True)
class _Principal:
    principal: str


def _server(server_mod):
    srv = server_mod.Server.__new__(server_mod.Server)
    srv._db_path = None  # set by Server.__init__
    srv.world = _World()
    srv.llm = object()
    srv.sandbox = object()
    srv.max_depth = 3
    srv._channels = []
    srv._tasks = []
    srv._shield = None
    return srv


def test_oidc_enabled_rejects_unlinked_message_without_token(monkeypatch):
    from maverick import oidc as oidc_mod
    from maverick import server as server_mod

    monkeypatch.setattr(oidc_mod, "oidc_enabled", lambda: True)
    seen_tokens = []

    def _reject(token):
        seen_tokens.append(token)
        raise oidc_mod.OIDCError("missing token")

    async def _dispatch_must_not_run(*args, **kwargs):
        raise AssertionError("dispatch must not run without a verified OIDC token")

    monkeypatch.setattr(oidc_mod, "verify_oidc_token", _reject)
    monkeypatch.setattr(
        "maverick.runner.run_goal_in_background_async", _dispatch_must_not_run,
    )

    class _Msg:
        channel = "slack"
        user_id = "CROOM"
        principal_id = "attacker"
        text = "spend budget"

    srv = _server(server_mod)
    out = asyncio.run(srv._handle_message(_Msg()))

    assert "Connect this chat account from My work" in out
    assert seen_tokens == []  # A token-free chat message needs a verified link.
    assert srv.world.goals == []
    assert srv.world.turns == []


def test_oidc_enabled_uses_verified_principal_for_goal_context(monkeypatch):
    from maverick import oidc as oidc_mod
    from maverick import server as server_mod

    monkeypatch.setattr(oidc_mod, "oidc_enabled", lambda: True)
    monkeypatch.setattr("maverick.paths.tenant_by_user_enabled", lambda: False)
    monkeypatch.setattr(
        "maverick.compliance.first_turn_disclosure", lambda *a, **k: None
    )

    seen_tokens = []

    def _verify(token):
        seen_tokens.append(token)
        return _Principal("user:alice")

    captured = {}

    async def _fake_dispatch(*args, **kwargs):
        captured.update(kwargs)
        return "done"

    monkeypatch.setattr(oidc_mod, "verify_oidc_token", _verify)
    monkeypatch.setattr(
        "maverick.runner.run_goal_in_background_async", _fake_dispatch,
    )

    class _Msg:
        channel = "slack"
        user_id = "CROOM"  # reply target, not trusted as the authenticated user
        principal_id = "attacker"
        authorization = "Bearer signed.jwt"
        text = "hello"

    srv = _server(server_mod)
    out = asyncio.run(srv._handle_message(_Msg()))

    assert _answer(out) == "ok"
    assert seen_tokens == ["signed.jwt"]
    assert srv.world.conversation_key == ("slack", "user:alice")
    assert srv.world.turns == [(1, "user", "hello")]
    assert srv.world.goals == [
        ("hello", "hello", "user:slack:user:alice", "user:slack:user:alice")
    ]
    assert captured["channel"] == "slack"
    assert captured["user_id"] == "slack:user:alice"


def test_oidc_opaque_subject_is_bound_exactly_without_path_interpolation(monkeypatch):
    from maverick import oidc as oidc_mod
    from maverick import server as server_mod

    subject = "auth0|North America/María 李"
    monkeypatch.setattr(oidc_mod, "oidc_enabled", lambda: True)
    monkeypatch.setattr("maverick.paths.tenant_by_user_enabled", lambda: False)
    monkeypatch.setattr(
        "maverick.compliance.first_turn_disclosure", lambda *a, **k: None,
    )
    monkeypatch.setattr(
        oidc_mod,
        "verify_oidc_token",
        lambda _token: _Principal(subject),
    )
    captured = {}

    async def _fake_dispatch(*args, **kwargs):
        captured.update(kwargs)
        return "done"

    monkeypatch.setattr(
        "maverick.runner.run_goal_in_background_async", _fake_dispatch,
    )

    class _Msg:
        channel = "slack"
        user_id = "CROOM"
        principal_id = "attacker"
        authorization = "Bearer signed.jwt"
        text = "hello"

    srv = _server(server_mod)
    assert _answer(asyncio.run(srv._handle_message(_Msg()))) == "ok"

    expected_user_id = f"slack:{subject}"
    assert captured["user_id"] == expected_user_id
    assert srv.world.goals == [
        ("hello", "hello", f"user:{expected_user_id}", f"user:{expected_user_id}")
    ]


def _answer(reply):
    """The goal's answer, without the agent-written label channels append."""
    answer, label = reply.rsplit("\n\n", 1)
    assert label.startswith("-- Written by an agent in Lightwork.")
    return answer
