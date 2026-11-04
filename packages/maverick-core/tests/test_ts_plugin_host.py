"""NDJSON plugin host tests (ts_plugin_host).

The child is a tiny Python script speaking the same NDJSON wire protocol as
the TypeScript SDK (sdks/plugin-ts), so CI needs no Node. It embeds the value
of a canary secret env var into the manifest and an `env` tool, which is how
the scrubbed-env tests observe what reached the child.
"""
from __future__ import annotations

import sys
import textwrap

import maverick.ts_plugin_host as plugin_host
import pytest
from maverick.tools import Tool
from maverick.ts_plugin_host import (
    TsPluginError,
    load_configured_ts_plugins,
    load_ts_plugin,
)


@pytest.fixture(autouse=True)
def _close_plugin_children_after_each_test():
    """Do not retain persistent fixture subprocesses across the full suite."""
    yield
    plugin_host._close_all_children()
    plugin_host._CHILDREN.clear()


# argv: fake_plugin.py <sentinel-path> [--describe]
FAKE_PLUGIN = textwrap.dedent('''
    import json, os, sys, time

    CANARY = os.environ.get("MAVERICK_TEST_CANARY_TOKEN", "MISSING")
    MANIFEST = {
        "protocol": "maverick-plugin/1",
        "tools": [
            {"name": "echo", "description": "echo text; canary=" + CANARY,
             "inputSchema": {"type": "object",
                             "properties": {"text": {"type": "string"}}}},
            {"name": "env", "description": "read canary", "inputSchema": {"type": "object"}},
            {"name": "boom", "description": "protocol error", "inputSchema": {"type": "object"}},
            {"name": "crash", "description": "always exits", "inputSchema": {"type": "object"}},
            {"name": "flaky", "description": "exits on first run only",
             "inputSchema": {"type": "object"}},
            {"name": "sleep", "description": "sleep", "inputSchema": {"type": "object"}},
            {"name": "bad name!", "description": "skipped", "inputSchema": {"type": "object"}},
        ],
    }

    def main():
        if "--describe" in sys.argv[1:]:
            print(json.dumps(MANIFEST))
            return
        sentinel = sys.argv[1]
        for line in sys.stdin:
            req = json.loads(line)
            rid, tool, args = req["id"], req["tool"], req.get("args") or {}
            if tool == "crash":
                sys.exit(1)
            if tool == "flaky" and not os.path.exists(sentinel):
                open(sentinel, "w").write("x")
                sys.exit(1)
            if tool == "echo":
                resp = {"id": rid, "result": "echo:" + str(args.get("text", ""))}
            elif tool == "env":
                resp = {"id": rid, "result": CANARY}
            elif tool == "boom":
                resp = {"id": rid, "error": "boom exploded"}
            elif tool == "flaky":
                resp = {"id": rid, "result": "recovered"}
            elif tool == "sleep":
                time.sleep(float(args.get("seconds", 30)))
                resp = {"id": rid, "result": "slept"}
            else:
                resp = {"id": rid, "error": "unknown tool"}
            sys.stdout.write(json.dumps(resp) + "\\n")
            sys.stdout.flush()

    main()
''')


@pytest.fixture
def fake_cmd(tmp_path):
    script = tmp_path / "fake_plugin.py"
    script.write_text(FAKE_PLUGIN)
    return [sys.executable, str(script), str(tmp_path / "flaky.sentinel")]


def _by_name(tools):
    return {t.name: t for t in tools}


def test_manifest_builds_tools(fake_cmd):
    tools = load_ts_plugin(fake_cmd)
    assert all(isinstance(t, Tool) for t in tools)
    by_name = _by_name(tools)
    # "bad name!" fails the tool-name check and is skipped.
    assert set(by_name) == {"echo", "env", "boom", "crash", "flaky", "sleep"}
    echo = by_name["echo"]
    assert echo.description.startswith("echo text")
    assert echo.input_schema["properties"]["text"] == {"type": "string"}


def test_round_trip_call(fake_cmd):
    by_name = _by_name(load_ts_plugin(fake_cmd))
    assert by_name["echo"].fn({"text": "hi"}) == "echo:hi"
    assert by_name["echo"].fn({"text": "again"}) == "echo:again"  # same child


def test_protocol_error_maps_to_error_string(fake_cmd):
    by_name = _by_name(load_ts_plugin(fake_cmd))
    out = by_name["boom"].fn({})
    assert out.startswith("ERROR:")
    assert "boom exploded" in out


def test_timeout_returns_error(fake_cmd):
    by_name = _by_name(load_ts_plugin(fake_cmd, call_timeout=0.5))
    out = by_name["sleep"].fn({"seconds": 30})
    assert out.startswith("ERROR:")
    assert "timed out" in out


def test_crashed_child_is_not_replayed(fake_cmd):
    by_name = _by_name(load_ts_plugin(fake_cmd))
    # The first call changed the sentinel, then died without a response.
    # Restarting is allowed only for a separate, deliberate new invocation.
    first = by_name["flaky"].fn({})
    assert "outcome unknown" in first
    assert first.attempt.outcome_unknown
    assert not first.attempt.retryable
    assert by_name["flaky"].fn({}) == "recovered"


def test_persistently_crashing_child_is_error(fake_cmd):
    by_name = _by_name(load_ts_plugin(fake_cmd))
    out = by_name["crash"].fn({})
    assert out.startswith("ERROR:")
    assert "crashed" in out
    # The plugin still works afterwards on a fresh child.
    assert by_name["echo"].fn({"text": "alive"}) == "echo:alive"


def test_child_env_is_scrubbed(fake_cmd, monkeypatch):
    monkeypatch.setenv("MAVERICK_TEST_CANARY_TOKEN", "supersecret")
    by_name = _by_name(load_ts_plugin(fake_cmd))
    # --describe subprocess: the canary would be embedded in the description.
    assert "canary=MISSING" in by_name["echo"].description
    # Persistent call child: the canary would be returned by the env tool.
    assert by_name["env"].fn({}) == "MISSING"


def test_bad_manifest_raises():
    with pytest.raises(TsPluginError):
        load_ts_plugin([sys.executable, "-c", "print('not a manifest')"])


def test_load_configured_ts_plugins(fake_cmd, monkeypatch):
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"plugins": {"ts": [
            fake_cmd,
            ["/nonexistent-ts-plugin-xyz"],  # broken entry: logged + skipped
            "not-an-argv-list",              # malformed entry: logged + skipped
        ]}},
    )
    by_name = _by_name(load_configured_ts_plugins())
    assert "echo" in by_name
    assert by_name["echo"].fn({"text": "cfg"}) == "echo:cfg"


def test_load_configured_ts_plugins_reads_the_dashboard_form(fake_cmd, monkeypatch):
    """The dashboard writes each plugin as a program, a file and extra words."""
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"plugins": {"ts": [
            {"program": fake_cmd[0], "file": fake_cmd[1], "args": fake_cmd[2:]},
            {"program": "", "file": "x"},        # malformed: no program
            {"program": fake_cmd[0], "args": [1]},  # malformed: words must be text
        ]}},
    )
    by_name = _by_name(load_configured_ts_plugins())
    assert by_name["echo"].fn({"text": "form"}) == "echo:form"
    assert plugin_host._entry_command({"program": "/bin/node", "file": "", "args": []}) == \
        ["/bin/node"]


def test_load_configured_ts_plugins_default_empty(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    assert load_configured_ts_plugins() == []


def test_plugin_file_change_after_manifest_is_blocked(fake_cmd):
    by_name = _by_name(load_ts_plugin(fake_cmd))
    script = fake_cmd[1]
    with open(script, "a", encoding="utf-8") as f:
        f.write("\n# modified after manifest discovery\n")

    out = by_name["echo"].fn({"text": "hi"})
    assert out.startswith("ERROR:")
    assert "changed after manifest discovery" in out



def test_a_cleanup_failure_is_a_tool_error_not_an_exception(monkeypatch):
    """A child whose descendant outlives cleanup is reported with its dispatch
    state, never raised out of the tool."""
    from maverick import ts_plugin_host as host
    from maverick.owned_process import ProcessCleanupError

    child = host._PluginChild.__new__(host._PluginChild)
    child.call_timeout, child._lock, child._buffer, child._proc = 5.0, __import__("threading").Lock(), bytearray(), None
    child.protocol = "v1"

    def failed_cleanup(*a, **k):
        raise ProcessCleanupError("owned child cleanup incomplete")
    monkeypatch.setattr(child, "_ensure_started", failed_cleanup, raising=False)
    monkeypatch.setattr(child, "close", failed_cleanup)
    result = child.call("tool", {})
    text = result if isinstance(result, str) else str(getattr(result, "text", result))
    assert "ERROR" in text and "not dispatched" in text
