"""Embedded mode (MAVERICK_NO_CLI=1) skips third-party plugin auto-discovery.

A library embedder drives the toolset programmatically and shouldn't inherit
whatever plugins happen to be installed/allowlisted in the host environment.
The no_cli() marker (maverick.embeddable) now actually gates the plugin
discover_* functions, which previously checked it nowhere.
"""
from __future__ import annotations


class _FakeToolEP:
    name = "fake_tool"

    def load(self):
        return lambda: "a-tool-instance"


class _FakeChannelEP:
    name = "fake_chan"

    def load(self):
        class _Chan:
            pass
        return _Chan


def _patch_entry_points(monkeypatch):
    from maverick import plugins

    def _eps(group):
        return {
            "maverick.tools": [_FakeToolEP()],
            "maverick.channels": [_FakeChannelEP()],
            "maverick.skills": [_FakeToolEP()],
            "maverick.personas": [],
        }.get(group, [])

    monkeypatch.setattr(plugins, "_entry_points", _eps)
    monkeypatch.setattr(plugins, "_allowed_plugin_names", lambda: None)  # allow all
    return plugins


def test_plugins_discovered_when_not_embedded(monkeypatch):
    monkeypatch.delenv("MAVERICK_NO_CLI", raising=False)
    plugins = _patch_entry_points(monkeypatch)
    assert any(n == "fake_tool" for n, _ in plugins.discover_tools())
    assert any(n == "fake_chan" for n, _ in plugins.discover_channels())


def test_embedded_mode_skips_plugin_discovery(monkeypatch):
    monkeypatch.setenv("MAVERICK_NO_CLI", "1")
    plugins = _patch_entry_points(monkeypatch)
    # Same registered entry points, but embedded mode short-circuits them.
    assert plugins.discover_tools() == []
    assert plugins.discover_channels() == []
    assert plugins.discover_skills() == []
    assert plugins.discover_personas() == {}
