"""Config-driven startup of channel plugins and the built-in Mattermost channel.

An enabled ``[channels.<name>]`` table naming an installed channel plugin is
started, sent to and stopped by the server like a built-in channel, with the
server's own message handler; a plugin that is missing or fails to load is
skipped with a warning and the other channels still start.
"""
from __future__ import annotations

import asyncio
import logging

import pytest
from maverick import server as server_mod


class _Closable:
    def close(self):
        pass


class PluginWithConfig:
    """A plugin channel that builds itself from its config table."""

    started: list[str] = []
    stopped: list[str] = []

    def __init__(self, handler, options):
        self.handler, self.options, self.name = handler, options, "pager"

    @classmethod
    def from_config(cls, handler, options):
        return cls(handler, options)

    async def start(self):
        PluginWithConfig.started.append(self.name)

    async def send(self, user_id, text):
        return None

    async def stop(self):
        PluginWithConfig.stopped.append(self.name)


class PluginBare:
    """A plugin channel written like docs/plugins.md: handler only."""

    name = "rooms"

    def __init__(self, handler):
        self.handler = handler

    async def start(self):
        return None

    async def send(self, user_id, text):
        return None

    async def stop(self):
        return None


class PluginBroken:
    def __init__(self, handler):
        raise RuntimeError("cannot reach its server")


def _build(monkeypatch, tmp_path, channels, plugins):
    monkeypatch.setattr(server_mod, "load_config",
                        lambda: {"sandbox": {"workdir": str(tmp_path)}, "channels": channels})
    monkeypatch.setattr(server_mod, "open_world", lambda: _Closable())
    monkeypatch.setattr(server_mod, "LLM", lambda **_kwargs: object())
    monkeypatch.setattr(server_mod, "build_sandbox", lambda **_kw: _Closable())
    monkeypatch.setattr(server_mod, "_install_goal_dispatcher", lambda: None)
    monkeypatch.setattr("maverick.operator_preflight._routed_configuration_missing",
                        lambda _config: {})
    monkeypatch.setattr("maverick.config.get_sandbox", lambda: {"workdir": str(tmp_path)})
    monkeypatch.setattr("maverick.plugins.discover_channels", lambda: list(plugins.items()))
    return server_mod.build_from_config()


def test_enabled_plugin_channels_start_with_the_server_handler(monkeypatch, tmp_path, caplog):
    caplog.set_level(logging.WARNING, logger="maverick.server")
    server = _build(monkeypatch, tmp_path, {
        "rich_render": True,
        "routing": {"rules": [], "enabled": True},
        "pager": {"enabled": True, "url": "https://pager.example", "allowed_user_ids": ["ops"]},
        "rooms": {"enabled": True, "room": "general"},
        "broken": {"enabled": True},
        "missing": {"enabled": True},
        "quiet": {"enabled": False},
    }, {"pager": PluginWithConfig, "rooms": PluginBare, "broken": PluginBroken,
        "quiet": PluginBare})
    by_name = {channel.name: channel for channel in server._channels}
    assert set(by_name) == {"pager", "rooms"}
    assert by_name["pager"].handler == server._handle_message
    assert by_name["pager"].options == {"url": "https://pager.example", "allowed_user_ids": ["ops"]}
    assert by_name["rooms"].config == {"room": "general"}
    text = caplog.text
    assert "plugin channel broken failed to load" in text
    assert "no installed channel plugin provides it" in text and "missing" in text


def test_plugin_channels_are_started_and_stopped_by_the_server(monkeypatch, tmp_path):
    PluginWithConfig.started.clear()
    PluginWithConfig.stopped.clear()
    server = _build(monkeypatch, tmp_path, {"pager": {"enabled": True}},
                    {"pager": PluginWithConfig})
    monkeypatch.setattr(server.world, "reclaim_orphan_goals", lambda: 0, raising=False)
    monkeypatch.setattr(server_mod, "_reclaim_tenant_orphans", lambda: 0)
    asyncio.run(server.run())
    assert PluginWithConfig.started == ["pager"] and PluginWithConfig.stopped == ["pager"]


def test_a_built_in_name_is_never_taken_by_a_plugin(monkeypatch, tmp_path):
    with pytest.raises(RuntimeError, match="No channels enabled"):
        _build(monkeypatch, tmp_path, {"mattermost": {"enabled": True}},
               {"mattermost": PluginWithConfig})


def test_mattermost_starts_from_config_and_the_environment_token_wins(monkeypatch, tmp_path):
    pytest.importorskip("httpx")
    monkeypatch.delenv("MATTERMOST_BOT_TOKEN", raising=False)
    table = {"enabled": True, "url": "https://chat.example.com", "bot_token": "saved-token",  # pragma: allowlist secret
             "allowed_user_ids": ["alice"], "poll_interval": 30}
    server = _build(monkeypatch, tmp_path, {"mattermost": table}, {})
    (channel,) = server._channels
    assert channel.name == "mattermost" and channel.base_url == "https://chat.example.com"
    assert channel.bot_token == "saved-token" and channel.poll_interval == 30  # pragma: allowlist secret
    assert channel.handler == server._handle_message
    monkeypatch.setenv("MATTERMOST_BOT_TOKEN", "server-token")
    server = _build(monkeypatch, tmp_path, {"mattermost": table}, {})
    assert server._channels[0].bot_token == "server-token"
