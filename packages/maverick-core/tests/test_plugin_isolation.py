"""Plugin sandboxing: subinterpreter + subprocess isolation backends.

A real demo plugin module is written to a tmp dir and imported through the
isolation seam, proving: results round-trip, exceptions become ERROR strings,
host module state is untouched (subinterpreter), and a hard-crashing plugin
kills the child, not the agent (subprocess)."""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
import types

import pytest
from maverick.plugin_isolation import isolation_mode, run_isolated

_PLUGIN = textwrap.dedent("""
    import sys

    CALLS = 0

    def tool(args):
        global CALLS
        CALLS += 1
        # Pollute interpreter state on purpose -- isolation should contain it.
        sys._mvk_polluted = True
        return f"hello {args.get('name', 'world')} (calls={CALLS})"

    def boom(args):
        raise RuntimeError("plugin exploded")

    def segfault(args):
        import os
        os.abort()  # hard crash, not an exception (portable across platforms)

    def not_a_string(args):
        return {"structured": True}
""").strip()


@pytest.fixture
def plugin_on_path(tmp_path, monkeypatch):
    (tmp_path / "demo_iso_plugin.py").write_text(_PLUGIN)
    monkeypatch.syspath_prepend(str(tmp_path))
    sys.modules.pop("demo_iso_plugin", None)
    yield "demo_iso_plugin"
    sys.modules.pop("demo_iso_plugin", None)


def test_mode_default_none(monkeypatch):
    monkeypatch.delenv("MAVERICK_PLUGIN_ISOLATION", raising=False)
    import maverick.config as config_mod
    monkeypatch.setattr(config_mod, "load_config", dict)
    assert isolation_mode() == "none"
    monkeypatch.setenv("MAVERICK_PLUGIN_ISOLATION", "subprocess")
    assert isolation_mode() == "subprocess"
    monkeypatch.setenv("MAVERICK_PLUGIN_ISOLATION", "bogus")
    with pytest.raises(ValueError, match="invalid plugin isolation"):
        isolation_mode()
    assert "isolation policy" in run_isolated("example:tool", {})


@pytest.mark.parametrize("bad_config", [[], {"plugins": []}, {"plugins": {"isolation": "unknown"}}])
def test_invalid_plugin_policy_refuses_direct_execution(monkeypatch, bad_config):
    import maverick.config as config_mod
    monkeypatch.delenv("MAVERICK_PLUGIN_ISOLATION", raising=False)
    monkeypatch.setattr(config_mod, "load_config", lambda: bad_config)
    assert "isolation policy" in run_isolated("example:tool", {})
    assert "isolation policy" in run_isolated("example:tool", {}, mode="invalid")


def test_plugin_policy_lookup_failure_is_not_a_direct_fallback(monkeypatch):
    import maverick.config as config_mod
    monkeypatch.delenv("MAVERICK_PLUGIN_ISOLATION", raising=False)
    def unavailable():
        raise OSError("unavailable")
    monkeypatch.setattr(config_mod, "load_config", unavailable)
    assert "isolation policy" in run_isolated("example:tool", {})


def test_corrupt_plugin_config_does_not_enable_direct_execution(monkeypatch, tmp_path):
    from maverick import config
    bad = tmp_path / "config.toml"
    bad.write_text("[plugins\nisolation = 'subprocess'\n", encoding="utf-8")
    monkeypatch.delenv("MAVERICK_PLUGIN_ISOLATION", raising=False)
    monkeypatch.setenv("MAVERICK_CONFIG", str(bad))
    config.reset_config_cache()
    try:
        assert "isolation policy" in run_isolated("example:tool", {})
    finally:
        config.reset_config_cache()


def test_none_mode_runs_in_process(plugin_on_path):
    out = run_isolated(f"{plugin_on_path}:tool", {"name": "ada"}, mode="none")
    assert out == "hello ada (calls=1)"


def test_subprocess_args_passed_via_stdin_not_argv(monkeypatch):
    secret = "MVK_ARG_SECRET_not_on_cmdline"  # pragma: allowlist secret
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["input"] = kwargs.get("input")
        return types.SimpleNamespace(returncode=1, stderr="forced stop")

    monkeypatch.setattr(subprocess, "run", fake_run)

    out = run_isolated("demo_iso_plugin:tool", {"token": secret}, mode="subprocess")

    assert out.startswith("ERROR: plugin process exited 1")
    assert captured["input"] == json.dumps({"token": secret})
    assert secret not in "\0".join(captured["cmd"])


def test_subprocess_roundtrip_and_host_state_untouched(plugin_on_path):
    had = hasattr(sys, "_mvk_polluted")
    out = run_isolated(f"{plugin_on_path}:tool", {"name": "ada"}, mode="subprocess")
    assert out == "hello ada (calls=1)"
    assert hasattr(sys, "_mvk_polluted") == had  # pollution stayed in the child


def test_subprocess_exception_becomes_error(plugin_on_path):
    out = run_isolated(f"{plugin_on_path}:boom", {}, mode="subprocess")
    assert out.startswith("ERROR: plugin call failed: RuntimeError: plugin exploded")


def test_subprocess_survives_hard_crash(plugin_on_path):
    out = run_isolated(f"{plugin_on_path}:segfault", {}, mode="subprocess")
    assert out.startswith("ERROR: plugin process exited")  # child died, agent lives


def test_subprocess_structured_result_jsonified(plugin_on_path):
    out = run_isolated(f"{plugin_on_path}:not_a_string", {}, mode="subprocess")
    assert out == '{"structured": true}'


def test_subprocess_timeout(plugin_on_path, tmp_path, monkeypatch):
    (tmp_path / "sleepy_plugin.py").write_text(
        "import time\ndef tool(args):\n    time.sleep(30)\n    return 'late'\n")
    out = run_isolated("sleepy_plugin:tool", {}, mode="subprocess", timeout_s=1.5)
    assert "timed out" in out


@pytest.mark.skipif(
    not pytest.importorskip("maverick.plugin_isolation")._subinterpreters_available(),
    reason="subinterpreters unavailable on this Python",
)
def test_subinterpreter_isolates_module_state(plugin_on_path):
    # Import in the HOST first and bump its counter.
    import importlib
    host_mod = importlib.import_module(plugin_on_path)
    host_mod.tool({})
    assert host_mod.CALLS == 1
    # The subinterpreter gets FRESH module state: calls=1 again, and the host
    # module's counter is unchanged.
    out = run_isolated(f"{plugin_on_path}:tool", {"name": "iso"}, mode="subinterpreter")
    assert out == "hello iso (calls=1)"
    assert host_mod.CALLS == 1


def test_validation():
    assert run_isolated("no-colon", {}, mode="none").startswith("ERROR: bad plugin entry")
    out = run_isolated("m:f", {"bad": object()}, mode="none")
    assert out.startswith("ERROR: plugin args are not JSON-serializable")


def test_discover_tools_wraps_with_isolation(tmp_path, monkeypatch):
    """With [plugins] isolation on, a discovered tool's fn runs isolated."""
    import types

    from maverick import plugins as plugins_mod

    (tmp_path / "iso_tool_plugin.py").write_text(
        "import sys\n"
        "def factory():\n"
        "    import types\n"
        "    def fn(args):\n"
        "        sys._iso_tool_polluted = True\n"
        "        return 'ran for ' + str(args.get('who'))\n"
        "    return types.SimpleNamespace(name='iso_tool', description='d',\n"
        "                                 input_schema={}, fn=fn, parallel_safe=True)\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    sys.modules.pop("iso_tool_plugin", None)

    class _EP:
        name = "iso_tool"
        value = "iso_tool_plugin:factory"
        dist = types.SimpleNamespace(name="iso-tool-dist")

        @staticmethod
        def load():
            import iso_tool_plugin
            return iso_tool_plugin.factory

    monkeypatch.setattr(plugins_mod, "_entry_points",
                        lambda group: [_EP()] if group == "maverick.tools" else [])
    monkeypatch.setattr(plugins_mod, "_allowed_plugin_names", lambda: None)
    monkeypatch.setattr(plugins_mod, "_permission_policy", lambda: (set(), False))
    monkeypatch.setenv("MAVERICK_PLUGIN_ISOLATION", "subprocess")

    tools = plugins_mod.discover_tools()
    assert len(tools) == 1
    name, factory = tools[0]
    tool = factory()
    had = hasattr(sys, "_iso_tool_polluted")
    out = tool.fn({"who": "ada"})
    assert out == "ran for ada"
    assert hasattr(sys, "_iso_tool_polluted") == had  # ran in the child
    sys.modules.pop("iso_tool_plugin", None)


def test_isolated_factory_refuses_immutable_or_ignored_wrapper():
    from maverick import plugins

    class Immutable:
        @property
        def fn(self):
            return lambda _args: "unsafe direct call"

    class IgnoresAssignment:
        @property
        def fn(self):
            return lambda _args: "unsafe direct call"

        @fn.setter
        def fn(self, _value):
            pass

    for target in (Immutable, IgnoresAssignment):
        factory = plugins._isolated_factory("example", "example:factory", target, mode="subprocess")
        with pytest.raises(RuntimeError, match="refusing to load"):
            factory()


def test_isolated_discovery_skips_entry_without_worker_target(monkeypatch):
    from maverick import plugin_isolation, plugins
    monkeypatch.setattr(plugin_isolation, "isolation_mode", lambda: "subprocess")
    monkeypatch.setattr(plugins, "_iter_loaded_with_value", lambda *_args: [
        ("example", lambda: pytest.fail("unwrapped factory called"), "", "example-dist"),
    ])
    assert plugins.discover_tools() == []


def test_isolated_factory_keeps_the_selected_mode(monkeypatch):
    from types import SimpleNamespace

    from maverick import plugin_isolation, plugins
    monkeypatch.setattr(plugin_isolation, "isolation_mode", lambda: "none")
    monkeypatch.setattr(plugin_isolation, "run_isolated",
                        lambda _entry, _args, **kwargs: kwargs["mode"])
    factory = plugins._isolated_factory(
        "example", "example:factory", lambda: SimpleNamespace(fn=lambda _args: "direct"),
        mode="subprocess",
    )
    assert factory().fn({}) == "subprocess"


def test_discover_tools_direct_when_isolation_off(tmp_path, monkeypatch):
    import types

    from maverick import plugins as plugins_mod

    (tmp_path / "direct_tool_plugin.py").write_text(
        "import types\n"
        "def factory():\n"
        "    return types.SimpleNamespace(name='t', description='d',\n"
        "                                 input_schema={}, fn=lambda a: 'direct',\n"
        "                                 parallel_safe=True)\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    sys.modules.pop("direct_tool_plugin", None)

    class _EP:
        name = "t"
        value = "direct_tool_plugin:factory"
        dist = types.SimpleNamespace(name="direct-dist")

        @staticmethod
        def load():
            import direct_tool_plugin
            return direct_tool_plugin.factory

    monkeypatch.setattr(plugins_mod, "_entry_points",
                        lambda group: [_EP()] if group == "maverick.tools" else [])
    monkeypatch.setattr(plugins_mod, "_allowed_plugin_names", lambda: None)
    monkeypatch.setattr(plugins_mod, "_permission_policy", lambda: (set(), False))
    monkeypatch.delenv("MAVERICK_PLUGIN_ISOLATION", raising=False)
    import maverick.config as config_mod
    monkeypatch.setattr(config_mod, "load_config", dict)

    tools = plugins_mod.discover_tools()
    assert tools[0][1]().fn({}) == "direct"
    sys.modules.pop("direct_tool_plugin", None)


def test_subprocess_isolation_never_imports_or_constructs_the_plugin_in_host(tmp_path, monkeypatch):
    """Under [plugins] isolation = "subprocess" the host process must not run
    plugin code at all: not the module import at discovery, not the factory.
    The child describes the tool (name, description, schema) and every call
    runs there; the host only holds a proxy built from that description."""
    import types

    from maverick import plugins as plugins_mod

    marker = tmp_path / "imported-in-host"
    (tmp_path / "oop_tool_plugin.py").write_text(
        "import os, sys\n"
        f"if os.getpid() == {__import__('os').getpid()}:\n"
        f"    open({str(marker)!r}, 'w').close()\n"
        "def factory():\n"
        "    import types\n"
        "    def fn(args):\n"
        "        return 'child says ' + str(args.get('who'))\n"
        "    return types.SimpleNamespace(name='oop_tool', description='runs apart',\n"
        "                                 input_schema={'type': 'object'}, fn=fn,\n"
        "                                 parallel_safe=False, strict=True)\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    sys.modules.pop("oop_tool_plugin", None)

    class _EP:
        name = "oop_tool"
        value = "oop_tool_plugin:factory"
        dist = types.SimpleNamespace(name="oop-tool-dist")

        @staticmethod
        def load():
            pytest.fail("plugin entry point loaded in the host process")

    monkeypatch.setattr(plugins_mod, "_entry_points",
                        lambda group: [_EP()] if group == "maverick.tools" else [])
    monkeypatch.setattr(plugins_mod, "_allowed_plugin_names", lambda: None)
    monkeypatch.setattr(plugins_mod, "_permission_policy", lambda: (set(), False))
    monkeypatch.setenv("MAVERICK_PLUGIN_ISOLATION", "subprocess")

    tools = plugins_mod.discover_tools()
    assert [name for name, _ in tools] == ["oop_tool"]
    tool = tools[0][1]()
    assert not marker.exists()
    assert "oop_tool_plugin" not in sys.modules
    assert (tool.name, tool.description, tool.input_schema) == (
        "oop_tool", "runs apart", {"type": "object"})
    assert tool.strict is True and tool.parallel_safe is False
    assert tool.fn({"who": "ada"}) == "child says ada"
    assert not marker.exists() and "oop_tool_plugin" not in sys.modules


def test_subprocess_isolation_refuses_a_tool_the_child_cannot_describe(monkeypatch):
    from maverick import plugin_isolation, plugins

    monkeypatch.setattr(plugin_isolation, "isolation_mode", lambda: "subprocess")
    monkeypatch.setattr(plugin_isolation, "describe_isolated",
                        lambda entry, **kw: "ERROR: plugin call failed: ImportError: nope")
    monkeypatch.setattr(plugins, "_iter_loaded_with_value", lambda *_args: [
        ("example", None, "example_mod:factory", "example-dist"),
    ])
    tools = plugins.discover_tools()
    assert [name for name, _ in tools] == ["example"]
    with pytest.raises(RuntimeError, match="refusing to load"):
        tools[0][1]()
