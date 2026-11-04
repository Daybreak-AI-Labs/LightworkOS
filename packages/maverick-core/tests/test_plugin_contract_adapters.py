"""Local trusted fixtures only: no installed plugins, containers or services."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from maverick.sandbox import plugin_contracts as contracts


def test_persona_invokes_real_renderer_and_rejects_wrong_result():
    pytest.importorskip("jsonschema")  # the plugin-workbench extra validates contract schemas
    events = []
    assert contracts.execute("maverick.personas", lambda: events.append("render") or "Prompt", {}, lambda: events.append("dispatch")) == "Prompt"
    assert events == ["dispatch", "render"]
    with pytest.raises(ValueError, match="nonempty"):
        contracts.execute("maverick.personas", dict, {}, lambda: None)


def test_skill_exercises_selection_and_native_rendering():
    pytest.importorskip("jsonschema")  # the plugin-workbench extra validates contract schemas
    from maverick.skills import Skill
    skill = Skill("weather", ["weather forecast"], ["weather_read"], "Use the approved weather tool.", Path("synthetic.md"))
    result = contracts.execute("maverick.skills", skill, {"goal": "weather forecast"}, lambda: None)
    assert result["selected"] == ["weather"]
    assert "Use the approved weather tool." in result["prompt"]
    skill.triggers = [123]
    with pytest.raises(ValueError, match="malformed"):
        contracts.execute("maverick.skills", skill, {"goal": "weather"}, lambda: None)


def test_channel_runs_start_send_stop_and_validates_reply():
    pytest.importorskip("jsonschema")  # the plugin-workbench extra validates contract schemas
    from maverick_channels.base import Channel
    calls = []
    class Synthetic(Channel):
        name = "synthetic"
        async def start(self):
            calls.append("start")
        async def send(self, user_id, text):
            calls.append(("send", user_id, text))
        async def stop(self):
            calls.append("stop")
    result = contracts.execute("maverick.channels", Synthetic,
        {"user_id": "fixture", "text": "hello", "reply": "received"}, lambda: calls.append("dispatch"))
    assert calls == ["dispatch", "start", ("send", "fixture", "received"), "stop"]
    assert result["reply"]["text"] == "received"
    assert result["received"] == [{"user_id": "fixture", "text": "hello", "channel": "synthetic"}]
    assert result["send_completed"] is True


def test_schema_ref_and_invalid_sample_refuse_before_dispatch():
    pytest.importorskip("jsonschema")  # the plugin-workbench extra validates contract schemas
    called = []
    def tool():
        return SimpleNamespace(input_schema={"type": "object", "$ref": "https://invalid.example/schema"}, fn=lambda _: called.append(True))
    with pytest.raises(ValueError, match="external schema"):
        contracts.execute("maverick.tools", tool, {}, lambda: called.append("dispatch"))
    assert called == []


def test_node_inspection_never_launches_configured_program(tmp_path, monkeypatch):
    from maverick import plugin_workbench_ts as node
    from maverick.plugin_workbench import _digest
    script = tmp_path / "plugin.js"
    script.write_text("throw new Error('must not execute on host')", encoding="utf-8")
    command = ["node", str(script)]
    rows = node.rows({"ts": [command], "workbench_image": "sha256:" + "a" * 64}, "b" * 64, _digest)
    assert rows[0]["eligible"] and rows[0]["permission_denial_checked"]
    assert node.command_for(_digest(command), {}) is None
    changed = node.rows({"ts": [["node", str(script), "--token=private"]]}, "b" * 64, _digest)
    assert not changed[0]["eligible"]
    assert "private" not in json.dumps(changed)


def test_flow_pin_survives_restart_and_blocks_owner_revision_or_bytes_drift(tmp_path, monkeypatch):
    from maverick import plugin_execution_pins as pins
    monkeypatch.setattr(pins, "data_dir", lambda: tmp_path)
    with pins.flow_scope("run-1", "employee:alice", "revision-1"):
        pins.check_pin("maverick.tools", "tool", "distribution", "a" * 64)
    for owner, revision, fingerprint in [("employee:alice", "revision-1", "b" * 64),
                                         ("employee:bob", "revision-1", "a" * 64),
                                         ("employee:alice", "revision-2", "a" * 64)]:
        with pins.flow_scope("run-1", owner, revision), pytest.raises(PermissionError, match="earlier plugin version"):
            pins.check_pin("maverick.tools", "tool", "distribution", fingerprint)
    saved = json.loads(pins.flow_path("run-1").read_text(encoding="utf-8"))
    assert saved["distribution:tool"]["fingerprint"] == "a" * 64


def test_node_tool_checks_current_configuration_before_handler(tmp_path, monkeypatch):
    from maverick import plugin_execution_pins as pins
    from maverick import plugin_workbench_ts as node
    script = tmp_path / "plugin.js"
    script.write_text("synthetic", encoding="utf-8")
    command = ["node", str(script)]
    monkeypatch.setattr(pins, "data_dir", lambda: tmp_path)
    enabled = [True]
    def current(identity):
        if not enabled[0]:
            raise PermissionError("no longer configured")
        return command
    monkeypatch.setattr(node, "configured_command", current)
    called = []
    tool = node.pin_tools(command, [SimpleNamespace(fn=lambda args: called.append(args) or "done")])[0]
    with pins.flow_scope("run-2", "alice", "r1"):
        assert tool.fn({"first": True}) == "done"
        script.write_text("changed", encoding="utf-8")
        with pytest.raises(PermissionError, match="changed"):
            tool.fn({"must_not_execute": True})
        enabled[0] = False
        with pytest.raises(PermissionError, match="configured"):
            tool.fn({})
    assert called == [{"first": True}]


def test_changed_cached_module_cannot_be_relabeled_as_current_bytes(monkeypatch):
    import sys

    from maverick import plugin_lock, plugins
    module = SimpleNamespace()
    name = "lightwork_fixture_cached_plugin"
    monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.setattr(plugins, "_plugins_config", lambda: {"workbench": True})
    monkeypatch.setattr(plugins, "_ep_dist_name", lambda ep: "fixture-dist")
    monkeypatch.setattr(plugin_lock, "_dist_content_hash", lambda dist: "b" * 64)
    monkeypatch.setattr(plugins, "_PINNED_IMPORTS", {("fixture-dist", name): (module, "a" * 64)})
    entry = SimpleNamespace(value=name + ":factory", load=lambda: pytest.fail("must not load stale cached target"))
    with pytest.raises(ValueError, match="import cache"):
        plugins._load_current_entry(entry)


def test_bound_skill_copy_does_not_mutate_module_export(monkeypatch):
    from maverick import plugin_execution_pins as pins
    from maverick import plugin_lock
    from maverick.skills import Skill
    original = Skill("fixture", ["fixture"], [], "body", Path("fixture.md"))
    monkeypatch.setattr(plugin_lock, "_dist_content_hash", lambda dist: "a" * 64)
    bound = pins.bind_entry("maverick.skills", "fixture", "fixture-dist", original)
    assert bound is not original
    assert not hasattr(original, "_plugin_binding")
    assert bound._plugin_binding[3] == "a" * 64


def test_node_drift_refuses_manifest_process_before_construction(tmp_path, monkeypatch):
    import hashlib

    from maverick import config
    from maverick import plugin_execution_pins as pins
    from maverick import plugin_workbench as workbench
    from maverick import ts_plugin_host as host
    script = tmp_path / "entry.js"
    script.write_text("old", encoding="utf-8")
    command = ["node", str(script)]
    policy = {"workbench": True, "ts": [command]}
    monkeypatch.setattr(workbench, "config", lambda: policy)
    monkeypatch.setattr(config, "load_config", lambda: {"plugins": policy})
    monkeypatch.setattr(pins, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(host, "load_ts_plugin", lambda *args, **kwargs: pytest.fail("must not even describe a drifted plugin"))
    with pins.flow_scope("run-3", "alice", "r1"):
        pins.check_pin("maverick.ts", "Node plugin", "ts-command:" + workbench._digest(command), hashlib.sha256(b"old").hexdigest())
        script.write_text("new", encoding="utf-8")
        assert host.load_configured_ts_plugins() == []


def test_python_drift_refuses_import_before_factory(tmp_path, monkeypatch):
    from maverick import plugin_execution_pins as pins
    from maverick import plugin_lock, plugins
    monkeypatch.setattr(pins, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(plugins, "_plugins_config", lambda: {"workbench": True})
    monkeypatch.setattr(plugins, "_ep_dist_name", lambda ep: "fixture-dist")
    monkeypatch.setattr(plugin_lock, "_dist_content_hash", lambda dist: "b" * 64)
    entry = SimpleNamespace(name="fixture", group="maverick.tools", value="never_import_fixture:factory",
                            load=lambda: pytest.fail("must not import new bytes into an old pinned run"))
    with pins.flow_scope("run-4", "alice", "r1"):
        pins.check_pin("maverick.tools", "fixture", "fixture-dist", "a" * 64)
        with pytest.raises(PermissionError, match="earlier plugin version"):
            plugins._load_current_entry(entry)


def test_portable_qualification_hash_deduplicates_windows_path_spellings(tmp_path, monkeypatch):
    import hashlib
    import importlib.metadata

    from maverick.plugin_lock import _dist_content_hash
    package = tmp_path / "fixture_package"
    package.mkdir()
    source = package / "__init__.py"
    source.write_bytes(b"source")
    class Entry(str):
        def locate(self):
            return source
    monkeypatch.setattr(importlib.metadata, "files", lambda dist: [Entry("fixture_package/__init__.py")])
    expected = hashlib.sha256(b"fixture_package/__init__.py\0source\0").hexdigest()
    assert _dist_content_hash("fixture", portable_paths=True) == expected


def test_node_malformed_schema_refuses_load_and_dispatch(monkeypatch):
    pytest.importorskip("jsonschema")  # the plugin-workbench extra validates contract schemas
    from maverick import ts_plugin_host as host
    monkeypatch.setattr(host._PinnedCommand, "from_command", lambda command: command)
    monkeypatch.setattr(host, "_fetch_manifest", lambda command: ("maverick-plugin/2", [{"name": "broken", "inputSchema": "invalid"}]))
    monkeypatch.setattr(host, "load_ts_plugin", lambda *args, **kwargs: pytest.fail("invalid schema must not dispatch"))
    with pytest.raises(ValueError, match="input schema"):
        contracts.execute_node({"source_suffix": ".js", "sample": {"tool": "broken", "arguments": {}}}, lambda: pytest.fail("no dispatch"))


def test_grpc_inspection_blocks_connection_only_unknown_versions(tmp_path):
    from maverick import plugin_workbench_grpc as grpc
    from maverick.plugin_workbench import _digest
    source = tmp_path / "server.py"
    source.write_text("raise AssertionError('never execute during metadata inspection')", encoding="utf-8")
    rows = grpc.rows({"grpc": [{"target": "127.0.0.1:50061", "command": ["python", str(source)]},
                                {"target": "127.0.0.1:50062"}]}, "a" * 64, _digest)
    assert rows[0]["eligible"] and rows[0]["permission_denial_checked"]
    assert not rows[1]["eligible"] and "no inspectable version" in rows[1]["blocked"]
    with pytest.raises(PermissionError):
        grpc.current(rows[0]["command_identity"], {})


def test_grpc_pin_blocks_drift_before_server_start(tmp_path, monkeypatch):
    import hashlib

    from maverick import config
    from maverick import grpc_plugin_host as host
    from maverick import plugin_execution_pins as pins
    from maverick import plugin_workbench as workbench
    source = tmp_path / "server.py"
    source.write_bytes(b"old")
    entry = {"target": "127.0.0.1:50061", "command": ["python", str(source)]}
    policy = {"workbench": True, "grpc": [entry]}
    monkeypatch.setattr(workbench, "config", lambda: policy)
    monkeypatch.setattr(config, "load_config", lambda: {"plugins": policy})
    monkeypatch.setattr(pins, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(host, "load_grpc_plugin", lambda *args, **kwargs: pytest.fail("no changed server startup"))
    with pins.flow_scope("grpc-run", "alice", "r1"):
        pins.check_pin("maverick.grpc", "gRPC plugin", "grpc-command:" + workbench._digest(entry), hashlib.sha256(b"old").hexdigest())
        source.write_bytes(b"new")
        assert host.load_configured_grpc_plugins() == []
