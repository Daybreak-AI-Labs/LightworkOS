"""Regressions for tool request, resource and approval boundaries."""
from __future__ import annotations

import io
import shlex
import subprocess
import sys
import types
import wave
from decimal import Decimal
from pathlib import Path

import pytest


def test_databricks_request_uses_egress_guard(monkeypatch):
    import httpx
    from maverick import governed_http
    from maverick.tools import databricks_tool as module
    calls = []
    monkeypatch.setenv("DATABRICKS_HOST", "https://db.example")
    monkeypatch.setenv("DATABRICKS_TOKEN", "test")
    monkeypatch.setattr(httpx, "request", lambda *a, **k: calls.append(a) or types.SimpleNamespace(
        status_code=200, json=dict))
    def guard(sender):
        def refused(*args, **kwargs):
            raise PermissionError("egress refused")
        return refused
    monkeypatch.setattr(governed_http, "guarded_sender", guard)
    with pytest.raises(PermissionError, match="egress refused"):
        module._req("GET", "/api/2.0/jobs/list")
    assert not calls


@pytest.mark.parametrize("op,field", [("get", "key"), ("put", "item"), ("delete", "key"),
                                     ("query", "expression_values"), ("scan", "expression_values")])
def test_dynamodb_converts_nested_json_numbers_before_dispatch(monkeypatch, op, field):
    from maverick.tools import dynamodb_tool as module
    calls = []
    table = types.SimpleNamespace(**{name: lambda **kw: calls.append(kw) or {}
                                    for name in ("get_item", "put_item", "delete_item", "query", "scan")})
    monkeypatch.setattr(module, "_client", lambda: types.SimpleNamespace(Table=lambda _: table))
    args = {"table": "records", "confirm": True, "key_cond_expression": "id = :v",
            "filter_expression": "id = :v", field: {":v": [1.25, {"amount": -0.1, "flag": True}]}}
    getattr(module, "_op_" + op)(args)
    key = {"key": "Key", "item": "Item", "expression_values": "ExpressionAttributeValues"}[field]
    assert calls[0][key] == {":v": [Decimal("1.25"), {"amount": Decimal("-0.1"), "flag": True}]}
    assert isinstance(calls[0][key][":v"][0], Decimal)


@pytest.mark.parametrize("streaming", [True, False])
def test_database_streams_or_bounds_mysql_read_before_execute(monkeypatch, streaming):
    from maverick.tools import database_tool as module
    events = []
    class Connection:
        dialect = types.SimpleNamespace(supports_server_side_cursors=streaming, name="mysql")
        def execution_options(self, **kwargs):
            events.append(("options", kwargs))
            return self
        def execute(self, statement):
            events.append(("execute", str(statement)))
            raise ValueError("end probe before data")
    execution = types.SimpleNamespace(started=lambda: None, transactional=True,
        cancellation_support="mysql_server_and_connection", rollback=lambda conn: None,
        failure=lambda exc: "ERROR", stop_monitor=lambda: None, state="rolled_back")
    monkeypatch.setattr(module, "_prepare_query_driver", lambda *a: None)
    module._query_connection(Connection(), "SELECT n FROM records", 10, False, "text", execution)
    if streaming:
        assert events[0] == ("options", {"yield_per": 11})
        assert events[1][0] == "execute"
    else:
        assert events == [("execute", "SELECT * FROM (SELECT n FROM records\n) AS maverick_bounded_result LIMIT 11")]


@pytest.mark.parametrize("reply", [False, True])
def test_discord_disables_mentions_and_discloses_truncation(monkeypatch, reply):
    from maverick.tools import discord_bot as module
    bodies = []
    monkeypatch.setattr(module, "_post_json", lambda path, body: bodies.append(body) or (200, {"id": "1"}))
    content = "@everyone " + "x" * 2000
    result = module._op_reply("c", "m", content) if reply else module._op_post("c", content)
    assert bodies[0]["allowed_mentions"]["parse"] == []
    assert len(bodies[0]["content"]) == 2000
    assert "truncat" in result.lower()


def test_browser_unsupported_press_has_no_dom_effect():
    from maverick.approval_cards import digest
    from maverick.tools.browser import _BrowserSession
    effects = []
    page = types.SimpleNamespace(url="https://example.test", evaluate=lambda *a: effects.append(a) or "dispatched")
    session = _BrowserSession()
    session._page, session._context = page, object()
    args = {"selector": "#target", "text": "Tab"}
    session._approval_dispatch = {"action": "press", "parameters_sha256": digest(args),
        "page_instance_sha256": digest(id(page)), "context_instance_sha256": digest(id(session._context)),
        "targets": [{"handle": object(), "snapshot": {}}]}
    result = session.dispatch_approved("press", args, 1000, set())
    assert "not supported" in result
    assert effects == []


def test_finance_partial_enqueue_reports_committed_ids(monkeypatch):
    from maverick.finance import anomaly_engine
    from maverick.tools import finance_anomaly as module
    monkeypatch.setattr(module, "_operations_enabled", lambda: True)
    monkeypatch.setattr(anomaly_engine, "scan_transactions", lambda *a, **k: types.SimpleNamespace(findings=[1, 2]))
    monkeypatch.setattr(anomaly_engine, "with_configured_materiality", lambda config: config)
    calls = []
    class Queue:
        def enqueue(self, finding, **kwargs):
            calls.append(finding)
            if finding == 2:
                raise OSError("storage unavailable")
            return {"id": "case-written"}
    monkeypatch.setattr(anomaly_engine, "FinanceAnomalyCaseQueue", Queue)
    result = module._run({"transactions": []})
    assert result.startswith("ERROR:") and "case-written" in result
    assert calls == [1, 2]


def test_git_approval_tracks_resolved_tip_through_sandbox(tmp_path, monkeypatch):
    from maverick.safety import ConsentDenied
    from maverick.tools import git_advanced as module
    def git(*args):
        return subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True, text=True)
    git("init", "-q")
    git("config", "user.name", "Test")
    git("config", "user.email", "test@example.test")
    git("-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", "first")
    commands = []
    class Sandbox:
        workdir = str(tmp_path)
        def exec(self, command, timeout=None):
            commands.append(command)
            completed = subprocess.run(shlex.split(command), cwd=tmp_path, capture_output=True, text=True)
            return types.SimpleNamespace(exit_code=completed.returncode, stdout=completed.stdout, stderr=completed.stderr)
    versions = []
    def review(*args, **kwargs):
        provider = kwargs["input_versions_provider"]
        versions.append(provider())
        git("-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", "second")
        versions.append(provider())
        raise ConsentDenied("git_advanced")
    monkeypatch.setattr(module, "request_execution_consent", review)
    module.git_advanced(Sandbox()).fn({"op": "bisect_start"})
    assert versions[0] != versions[1]
    assert len(commands) == 2 and all("rev-parse" in command for command in commands)


def test_container_paths_are_relative_to_sandbox_workspace(tmp_path, monkeypatch):
    import maverick.safety.consent as consent
    from maverick.tools.container_build import container_build
    context = tmp_path / "context with spaces"
    context.mkdir()
    (context / "Dockerfile").write_text("FROM scratch\n")
    commands = []
    monkeypatch.setattr(consent, "require_consent", lambda *a, **k: types.SimpleNamespace(
        granted=True, source="dashboard", actor="user:reviewer"))
    sandbox = types.SimpleNamespace(workdir=str(tmp_path), exec=lambda command, **k:
        commands.append(shlex.split(command)) or types.SimpleNamespace(exit_code=0, stdout="ok", stderr=""))
    result = container_build(sandbox).fn({"op": "build", "context": context.name, "tag": "test:local"})
    assert "ok" in result
    argv = commands[0]
    for value in [argv[argv.index("-f") + 1], argv[-1]]:
        assert not Path(value).is_absolute()
        assert (tmp_path / value).exists()


def test_embedding_cache_keeps_only_most_recent_model(monkeypatch):
    from maverick.tools import embeddings as module
    built = []
    monkeypatch.setitem(sys.modules, "fastembed", types.SimpleNamespace(
        TextEmbedding=lambda model_name: built.append(model_name) or object()))
    monkeypatch.setattr(module, "_model_cache", {})
    module._load_model("first")
    module._load_model("second")
    module._load_model("first")
    assert built == ["first", "second", "first"]
    assert len(module._model_cache) == 1


def test_wav_decode_uses_compact_numeric_samples(monkeypatch):
    import numpy as np
    from maverick.tools import audio_understanding as module
    monkeypatch.setattr(module, "_audio_limit", lambda: 1000000)
    buf = io.BytesIO()
    with wave.open(buf, "wb") as output:
        output.setparams((2, 2, 16000, 0, "NONE", "not compressed"))
        output.writeframes(b"\x00\x40\x00\x00" * 10000)
    samples, rate = module.decode_wav(buf.getvalue())
    assert isinstance(samples, np.ndarray) and samples.dtype == np.float32
    assert samples.nbytes == 40000 and rate == 16000
    np.testing.assert_array_equal(samples, np.full(10000, 0.25, dtype=np.float32))


def test_sensor_import_does_not_mutate_other_threads_search_path(tmp_path, monkeypatch):
    import builtins

    from maverick.tools import hardware_sensors as module
    workspace, site = tmp_path / "work", tmp_path / "site"
    workspace.mkdir()
    site.mkdir()
    (site / "psutil.py").write_text("import builtins, sys\nbuiltins.sensor_import_paths.append(sys.path)\n")
    monkeypatch.chdir(workspace)
    monkeypatch.syspath_prepend(str(site))
    monkeypatch.syspath_prepend(str(workspace))
    monkeypatch.delitem(sys.modules, "psutil", raising=False)
    observed = []
    monkeypatch.setattr(builtins, "sensor_import_paths", observed, raising=False)
    original = sys.path
    try:
        assert module._psutil() is not None
        assert observed == [original]
        assert observed[0] is original and sys.path is original
    finally:
        sys.modules.pop("psutil", None)


def test_x11_focus_changes_computer_approval_digest(monkeypatch):
    from maverick.tools import computer as module
    active = [101]
    closed = []
    class Display:
        def __init__(self, *args):
            pass
        def intern_atom(self, name, **kwargs):
            return name
        def screen(self):
            return types.SimpleNamespace(root=types.SimpleNamespace(get_full_property=lambda *a:
                types.SimpleNamespace(value=active)))
        def close(self):
            closed.append(True)
    monkeypatch.setenv("DISPLAY", ":99")
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setitem(sys.modules, "Xlib", types.SimpleNamespace(
        X=types.SimpleNamespace(AnyPropertyType=0), display=types.SimpleNamespace(Display=Display)))
    before = module._computer_approval_context()
    active[0] = 202
    after = module._computer_approval_context()
    assert before["foreground_window_sha256"] != after["foreground_window_sha256"]
    assert closed == [True, True]
