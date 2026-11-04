"""Plugin telemetry (opt-in): local counts, discovery wrapping, CLI stats."""
from __future__ import annotations

import asyncio
import inspect
import types

from click.testing import CliRunner
from maverick import plugin_telemetry as pt
from maverick import plugins as plugins_mod
from maverick.tools import _execute_tool_fn


def test_off_by_default(monkeypatch):
    monkeypatch.delenv("MAVERICK_PLUGIN_TELEMETRY", raising=False)
    import maverick.config as config_mod
    monkeypatch.setattr(config_mod, "load_config", dict)
    assert pt.enabled() is False
    monkeypatch.setenv("MAVERICK_PLUGIN_TELEMETRY", "1")
    assert pt.enabled() is True


def test_record_and_stats(tmp_path):
    p = tmp_path / "telemetry.json"
    pt.record("acme_search", "acme-tools", path=p)
    pt.record("acme_search", "acme-tools", path=p)
    pt.record("other_tool", None, path=p)
    data = pt.stats(path=p)
    assert data["acme_search"]["calls"] == 2
    assert data["acme_search"]["dist"] == "acme-tools"
    assert data["other_tool"]["calls"] == 1
    assert data["acme_search"]["last_used"] > 0


def test_record_never_raises(monkeypatch, tmp_path):
    # Unwritable path: record must swallow, not raise.
    pt.record("x", None, path=tmp_path)  # path is a DIRECTORY -> write fails


def test_wrap_factory_counts(tmp_path, monkeypatch):
    monkeypatch.setattr(pt, "telemetry_path", lambda: tmp_path / "t.json")
    tool = types.SimpleNamespace(name="t", fn=lambda args: "ran", parallel_safe=True)
    factory = pt.wrap_factory("t", "dist-x", lambda: tool)
    wrapped = factory()
    assert wrapped.fn({}) == "ran"
    assert pt.stats()["t"]["calls"] == 1


def test_wrap_factory_preserves_async_generator_semantics(tmp_path, monkeypatch):
    monkeypatch.setattr(pt, "telemetry_path", lambda: tmp_path / "t.json")

    async def stream(args):
        yield "hello"
        yield " world"

    tool = types.SimpleNamespace(name="t", fn=stream, parallel_safe=True)
    factory = pt.wrap_factory("t", "dist-x", lambda: tool)
    wrapped = factory()

    assert inspect.isasyncgenfunction(wrapped.fn)

    async def run():
        return await _execute_tool_fn(wrapped.fn, {}, str)

    assert asyncio.run(run()) == "hello world"
    assert pt.stats()["t"]["calls"] == 1


def test_discovery_wraps_when_enabled(tmp_path, monkeypatch):
    monkeypatch.setattr(pt, "telemetry_path", lambda: tmp_path / "t.json")
    monkeypatch.setenv("MAVERICK_PLUGIN_TELEMETRY", "1")
    monkeypatch.delenv("MAVERICK_PLUGIN_ISOLATION", raising=False)
    import maverick.config as config_mod
    monkeypatch.setattr(config_mod, "load_config", dict)

    class _EP:
        name = "counted_tool"
        value = "mod:factory"
        dist = types.SimpleNamespace(name="counted-dist", version="1.0")

        @staticmethod
        def load():
            return lambda: types.SimpleNamespace(
                name="counted_tool", fn=lambda a: "ok", parallel_safe=True)

    monkeypatch.setattr(plugins_mod, "_entry_points",
                        lambda group: [_EP()] if group == "maverick.tools" else [])
    monkeypatch.setattr(plugins_mod, "_allowed_plugin_names", lambda: None)
    monkeypatch.setattr(plugins_mod, "_permission_policy", lambda: (set(), False))
    tools = plugins_mod.discover_tools()
    tools[0][1]().fn({})
    assert pt.stats()["counted_tool"]["dist"] == "counted-dist"


def test_cli_stats(tmp_path, monkeypatch):
    from maverick import cli as cli_mod
    monkeypatch.setattr(pt, "telemetry_path", lambda: tmp_path / "t.json")
    monkeypatch.delenv("MAVERICK_PLUGIN_TELEMETRY", raising=False)
    import maverick.config as config_mod
    monkeypatch.setattr(config_mod, "load_config", dict)
    r = CliRunner().invoke(cli_mod.main, ["plugin", "stats"])
    assert r.exit_code == 0 and "telemetry is OFF" in r.output
    pt.record("acme_search", "acme-tools", path=tmp_path / "t.json")
    r2 = CliRunner().invoke(cli_mod.main, ["plugin", "stats"])
    assert "acme_search [acme-tools]: 1 call(s)" in r2.output
