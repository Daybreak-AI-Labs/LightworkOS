"""Tests for the channel server (maverick.server)."""
from __future__ import annotations


def _answer(reply):
    """The goal's answer, without the agent-written label channels append."""
    answer, label = reply.rsplit("\n\n", 1)
    assert label.startswith("-- Written by an agent in Lightwork.")
    return answer


def test_server_passes_channel_user_to_run_goal(monkeypatch):
    import maverick.server as server_mod

    class _World:
        def __init__(self):
            self._cid = 1
            self._gid = 1
            self.created_goal = None
        def latest_artifacts(self, goal_id):
            return []  # the goal saved no output files

        def open_channel_questions(self, conversation_id, owner, execution_principal):
            return []  # no blocked question awaits a reply

        def get_or_create_conversation(self, channel, user_id):
            class C:
                pass
            c = C()
            c.id = self._cid
            return c
        def append_turn(self, conversation_id, role, text, *, goal_id=None):
            return None
        def create_goal(
            self, title, text, *, owner="", execution_principal="",
        ):
            self.created_goal = (title, text, owner, execution_principal)
            return self._gid
        def set_goal_status(self, *args, **kwargs):
            return None
        def get_goal(self, goal_id):
            return type("Goal", (), {"result": "ok", "status": "done"})()

    captured = {}
    async def _fake_dispatch(*args, **kwargs):
        captured.update(kwargs)
        return "done"

    monkeypatch.setattr(
        "maverick.runner.run_goal_in_background_async", _fake_dispatch,
    )
    monkeypatch.setattr(server_mod, "build_sandbox", lambda: object())
    monkeypatch.setattr("maverick.compliance.first_turn_disclosure", lambda *a, **k: None)

    world = _World()
    srv = server_mod.Server(world=world, llm=object(), sandbox=object())

    class _Msg:
        channel = "telegram"
        user_id = "42"
        text = "hello"

    import asyncio
    out = asyncio.run(srv._handle_message(_Msg()))
    assert _answer(out) == "ok"
    assert captured["channel"] == "telegram"
    assert captured["user_id"] == "telegram:42"
    assert world.created_goal == (
        "hello", "hello", "user:telegram:42", "user:telegram:42",
    )
