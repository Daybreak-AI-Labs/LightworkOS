from __future__ import annotations

from pathlib import Path


def test_build_from_config_uses_configured_sandbox_backend(monkeypatch, tmp_path):
    from maverick import server as server_mod

    class _FakeWorld:
        pass

    class _FakeLLM:
        def __init__(self, **_kwargs):
            pass

    calls = {}

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    monkeypatch.setattr(server_mod, "load_config", lambda: {
        "sandbox": {"backend": "docker", "workdir": str(tmp_path)},
        "channels": {},
    })
    monkeypatch.setattr(server_mod, "WorldModel", _FakeWorld)
    monkeypatch.setattr(server_mod, "LLM", _FakeLLM)

    def _fake_build_sandbox(*, workdir=None, backend=None):
        calls["workdir"] = workdir
        calls["backend"] = backend

        class _Sandbox:
            pass

        return _Sandbox()

    monkeypatch.setattr(server_mod, "build_sandbox", _fake_build_sandbox)

    try:
        server_mod.build_from_config()
    except RuntimeError as e:
        assert "No channels enabled" in str(e)

    assert calls["backend"] == "docker"
    assert Path(calls["workdir"]) == tmp_path


def _make_bare_server():
    """A Server with just enough state to exercise add_channel (no world/llm)."""
    from maverick import server as server_mod

    srv = object.__new__(server_mod.Server)
    srv._channels = []
    return srv


class _DummyChannel:
    name = "dummy"

    async def start(self):  # pragma: no cover - never run in this test
        pass

    async def send(self, user_id, text):  # pragma: no cover
        pass


def test_rich_render_is_prepared_with_the_reply_not_by_wrapping_the_channel(monkeypatch):
    # The durable reply path attaches the rendered copy before custody; a
    # send() wrapper could not intercept an adapter's saved-reply transport.
    from types import SimpleNamespace

    from maverick import channel_reply_results
    from maverick_channels import rich_render

    monkeypatch.setattr(rich_render, "enabled", lambda: True)
    srv = _make_bare_server()
    ch = _DummyChannel()
    srv.add_channel(ch)
    assert srv._channels[0] is ch

    monkeypatch.setattr(channel_reply_results, "require_source", lambda _source: None)
    world = SimpleNamespace(get_goal=lambda _id: SimpleNamespace(status="done"),
                            latest_artifacts=lambda _id: [])
    text = "Result: $$x^2$$"
    assert rich_render.has_rich_blocks(text)

    def msg(channel):
        return SimpleNamespace(channel=channel, provider_tenant_id=None, provider_sender_id=None,
                               conversation_ref="thread", message_id="m1")

    kwargs = {"owner": "user:a", "execution_principal": "user:a", "principal": "user:a"}
    reply = channel_reply_results.prepare_reply(world, msg("slack"), 1, text, **kwargs)
    assert reply.attachments == ["Rendered reply.html"]
    plain = channel_reply_results.prepare_reply(world, msg("sms"), 1, text, **kwargs)
    assert isinstance(plain, str) and "cannot attach a rendered copy" in plain


def test_add_channel_passthrough_when_rich_render_off(monkeypatch):
    from maverick_channels import rich_render

    monkeypatch.setattr(rich_render, "enabled", lambda: False)
    srv = _make_bare_server()
    ch = _DummyChannel()
    srv.add_channel(ch)
    # Default (knob off): the channel is stored unchanged, no wrapping.
    assert srv._channels[0] is ch
