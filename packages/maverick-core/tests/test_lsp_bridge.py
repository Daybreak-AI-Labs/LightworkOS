"""Cross-language LSP bridge tests.

A scripted fake LSP server (a tiny Python script speaking real
Content-Length-framed JSON-RPC over stdio) exercises the full session
lifecycle — initialize, didOpen, query, shutdown — without any real language
server installed.
"""
from __future__ import annotations

import importlib
import sys
import textwrap
from contextlib import nullcontext

import pytest
from maverick.tools.lsp_bridge import lsp_bridge

lsp_bridge_module = importlib.import_module("maverick.tools.lsp_bridge")


@pytest.fixture(autouse=True)
def _approved_execution(monkeypatch):
    monkeypatch.setattr(lsp_bridge_module, "request_execution_consent",
                        lambda *a, **kw: object())
    monkeypatch.setattr(lsp_bridge_module, "consume_operation_consent",
                        lambda permit: nullcontext())

# A minimal LSP server: answers initialize/shutdown, publishes one diagnostic
# after didOpen, and serves documentSymbol / definition / hover canned.
_FAKE_SERVER = textwrap.dedent("""
    import json, sys

    def read():
        line = sys.stdin.buffer.readline()
        length = 0
        while line and line.strip():
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":")[1])
            line = sys.stdin.buffer.readline()
        if not length:
            return None
        return json.loads(sys.stdin.buffer.read(length))

    def send(payload):
        body = json.dumps(payload).encode()
        sys.stdout.buffer.write(b"Content-Length: %d\\r\\n\\r\\n" % len(body))
        sys.stdout.buffer.write(body)
        sys.stdout.buffer.flush()

    uri = None
    while True:
        msg = read()
        if msg is None:
            break
        method = msg.get("method")
        if method == "initialize":
            send({"jsonrpc": "2.0", "id": msg["id"], "result": {"capabilities": {}}})
        elif method == "textDocument/didOpen":
            uri = msg["params"]["textDocument"]["uri"]
            send({"jsonrpc": "2.0", "method": "textDocument/publishDiagnostics",
                  "params": {"uri": uri, "diagnostics": [
                      {"severity": 1, "message": "name 'frob' is not defined",
                       "range": {"start": {"line": 2, "character": 4},
                                 "end": {"line": 2, "character": 8}}}]}})
        elif method == "textDocument/documentSymbol":
            send({"jsonrpc": "2.0", "id": msg["id"], "result": [
                {"name": "Widget", "kind": 5,
                 "range": {"start": {"line": 0, "character": 0},
                           "end": {"line": 5, "character": 0}},
                 "selectionRange": {"start": {"line": 0, "character": 6},
                                    "end": {"line": 0, "character": 12}},
                 "children": [
                     {"name": "spin", "kind": 6,
                      "range": {"start": {"line": 1, "character": 4},
                                "end": {"line": 2, "character": 0}},
                      "selectionRange": {"start": {"line": 1, "character": 8},
                                         "end": {"line": 1, "character": 12}}}]}]})
        elif method == "textDocument/definition":
            send({"jsonrpc": "2.0", "id": msg["id"], "result": [
                {"uri": uri, "range": {"start": {"line": 9, "character": 0},
                                       "end": {"line": 9, "character": 5}}}]})
        elif method == "textDocument/hover":
            send({"jsonrpc": "2.0", "id": msg["id"],
                  "result": {"contents": {"kind": "markdown",
                                          "value": "(class) Widget"}}})
        elif method == "shutdown":
            send({"jsonrpc": "2.0", "id": msg["id"], "result": None})
        elif method == "exit":
            break
""").strip()


def _fake_argv():
    return [sys.executable, "-c", _FAKE_SERVER]


def _tool():
    import os
    from types import SimpleNamespace
    return lsp_bridge(SimpleNamespace(workdir=os.environ.get("MAVERICK_WORKSPACE_ROOT")))


def _use_fake_server(monkeypatch, tmp_path, argv=None):
    monkeypatch.setenv("MAVERICK_WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setitem(lsp_bridge_module.DEFAULT_SERVERS, "python", argv or _fake_argv())


def test_symbols(tmp_path, monkeypatch):
    _use_fake_server(monkeypatch, tmp_path)
    f = tmp_path / "widget.py"
    f.write_text("class Widget:\n    def spin(self):\n        pass\n")
    out = _tool().fn({"op": "symbols", "file": str(f)})
    assert "class Widget  :1" in out
    assert "  method spin  :2" in out


def test_denied_lsp_does_not_spawn(tmp_path, monkeypatch):
    from maverick.safety import ConsentDenied

    _use_fake_server(monkeypatch, tmp_path)
    f = tmp_path / "widget.py"
    f.write_text("x = 1\n")
    started = []

    def deny(*args, **kwargs):
        raise ConsentDenied("lsp_bridge")

    monkeypatch.setattr(lsp_bridge_module, "request_execution_consent", deny)
    monkeypatch.setattr(lsp_bridge_module, "_LspSession", lambda *a, **kw: started.append(1))
    assert "not approved" in _tool().fn({"op": "symbols", "file": str(f)})
    assert started == []


def test_definition_and_hover(tmp_path, monkeypatch):
    _use_fake_server(monkeypatch, tmp_path)
    f = tmp_path / "w.py"
    f.write_text("x = 1\n")
    out = _tool().fn({"op": "definition", "file": str(f), "line": 0, "character": 0})
    assert out.strip().endswith(":10:1")  # canned definition at line 9 (0-based)
    hov = _tool().fn({"op": "hover", "file": str(f), "line": 0, "character": 0})
    assert "(class) Widget" in hov


def test_diagnostics(tmp_path, monkeypatch):
    _use_fake_server(monkeypatch, tmp_path)
    f = tmp_path / "w.py"
    f.write_text("def f():\n    return frob\n")
    out = _tool().fn({"op": "diagnostics", "file": str(f)})
    assert "error :3:5 name 'frob' is not defined" in out


def test_position_required_and_validation(tmp_path, monkeypatch):
    _use_fake_server(monkeypatch, tmp_path)
    f = tmp_path / "w.py"
    f.write_text("x = 1\n")
    assert _tool().fn({"op": "definition", "file": str(f)}).startswith("ERROR:")
    assert _tool().fn({"op": "symbols", "file": "/nope.py"}).startswith("ERROR:")
    assert _tool().fn({"op": "symbols"}).startswith("ERROR:")


def test_unknown_language_and_missing_server(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_WORKSPACE_ROOT", str(tmp_path))
    f = tmp_path / "w.weird"
    f.write_text("x")
    out = _tool().fn({"op": "symbols", "file": str(f)})
    assert out.startswith("ERROR:") and "language" in out
    f2 = tmp_path / "w.py"
    f2.write_text("x = 1\n")
    monkeypatch.setitem(lsp_bridge_module.DEFAULT_SERVERS, "python", ["missing-lsp-server-for-test"])
    out2 = _tool().fn({"op": "symbols", "file": str(f2), "language": "python"})
    assert out2.startswith("ERROR:") and "not installed" in out2


def test_server_timeout_is_an_error_not_a_hang(tmp_path, monkeypatch):
    f = tmp_path / "w.py"
    f.write_text("x = 1\n")
    # A configured server that never speaks LSP.
    silent = [sys.executable, "-c", "import time; time.sleep(60)"]
    _use_fake_server(monkeypatch, tmp_path, argv=silent)
    out = _tool().fn({"op": "symbols", "file": str(f), "timeout_s": 1.5})
    assert out.startswith("ERROR:")


def test_server_that_stops_reading_cannot_block_past_the_deadline(tmp_path, monkeypatch):
    # The didOpen frame carries the whole file; a server that never reads its
    # stdin used to block the write forever, whatever timeout_s said.
    f = tmp_path / "big.py"
    f.write_text("x = 1\n" * 150_000)
    deaf = [sys.executable, "-c", "import time; time.sleep(60)"]
    _use_fake_server(monkeypatch, tmp_path, argv=deaf)
    out = _tool().fn({"op": "symbols", "file": str(f), "timeout_s": 1.5})
    assert out.startswith("ERROR:")
    assert _tool().fn({"op": "symbols", "file": str(f), "timeout_s": float("nan")}).startswith("ERROR:")


def test_per_call_server_override_is_rejected(tmp_path, monkeypatch):
    _use_fake_server(monkeypatch, tmp_path)
    f = tmp_path / "w.py"
    f.write_text("x = 1\n")
    marker = tmp_path / "should_not_exist"
    out = _tool().fn({
        "op": "symbols",
        "file": str(f),
        "server": [
            sys.executable,
            "-c",
            f"from pathlib import Path; Path({str(marker)!r}).write_text('bad')",
        ],
    })
    assert out.startswith("ERROR:") and "not allowed" in out
    assert not marker.exists()
    assert "server" not in _tool().input_schema["properties"]


def test_file_and_root_must_stay_in_workspace(tmp_path, monkeypatch):
    _use_fake_server(monkeypatch, tmp_path)
    outside = tmp_path.parent / "outside.py"
    outside.write_text("x = 1\n")
    inside = tmp_path / "inside.py"
    inside.write_text("x = 1\n")
    assert "escapes the workspace" in _tool().fn({"op": "symbols", "file": str(outside)})
    assert "escapes the workspace" in _tool().fn({"op": "symbols", "file": str(inside),
                                                 "root": str(tmp_path.parent)})


def test_task_workspace_overrides_host_cwd_and_environment(tmp_path, monkeypatch):
    from types import SimpleNamespace
    workspace = tmp_path / "task"
    workspace.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("private = True\n")
    monkeypatch.setenv("MAVERICK_WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    tool = lsp_bridge(SimpleNamespace(workdir=workspace))
    assert "escapes the workspace" in tool.fn({"op": "symbols", "file": str(outside)})
    assert "require a local task workspace" in lsp_bridge().fn({"op": "symbols", "file": str(outside)})


def test_lsp_approval_discloses_host_repository_execution(tmp_path, monkeypatch):
    from maverick.safety import ConsentDenied
    _use_fake_server(monkeypatch, tmp_path)
    path = tmp_path / "code.py"
    path.write_text("x = 1\n")
    seen = {}
    def deny(*args, **kwargs):
        seen.update(kwargs)
        raise ConsentDenied("lsp_bridge")
    monkeypatch.setattr(lsp_bridge_module, "request_execution_consent", deny)
    assert "not approved" in _tool().fn({"op": "symbols", "file": str(path)})
    assert "outside the task sandbox" in seen["effect"]
    assert "build scripts" in seen["effect"] and "plugins" in seen["effect"]


def test_lsp_binds_source_bytes_and_absolute_executable(tmp_path, monkeypatch):
    from types import SimpleNamespace

    workspace = tmp_path / "task"
    workspace.mkdir()
    path = workspace / "code.py"
    path.write_text("original\n")
    executable = tmp_path / "local-lsp"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", ".")
    monkeypatch.setitem(lsp_bridge_module.DEFAULT_SERVERS, "python", ["local-lsp"])
    def changed(*args, **kwargs):
        assert kwargs["parameters"]["argv"][0] == str(executable)
        path.write_text("different\n")
        kwargs["input_versions_provider"]()
        raise AssertionError("changed source was accepted")
    monkeypatch.setattr(lsp_bridge_module, "request_execution_consent", changed)
    result = lsp_bridge(SimpleNamespace(workdir=workspace)).fn({"op": "symbols", "file": str(path)})
    assert "changed" in result


def test_lsp_revalidation_refuses_substituted_fifo(tmp_path, monkeypatch):
    import os
    if not hasattr(os, "mkfifo"):
        pytest.skip("named pipes are not supported")
    _use_fake_server(monkeypatch, tmp_path)
    path = tmp_path / "code.py"
    path.write_text("original\n")
    def replaced(*args, **kwargs):
        path.unlink()
        os.mkfifo(path)
        kwargs["input_versions_provider"]()
    monkeypatch.setattr(lsp_bridge_module, "request_execution_consent", replaced)
    assert "changed" in _tool().fn({"op": "symbols", "file": str(path)})


def test_lsp_bridge_is_high_risk():
    from maverick.safety.tool_risk import tool_risk

    assert tool_risk("lsp_bridge") == "high"


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        pass

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "lsp_bridge" in names


def test_close_reaps_child_and_closes_pipes(tmp_path):
    # close() must reap the killed child (no zombie) and close the PIPE fds.
    # A fresh server is spawned per query, so a leak here accumulates under fanout.
    from pathlib import Path

    session = lsp_bridge_module._LspSession(_fake_argv(), Path(tmp_path))
    proc = session._proc
    assert proc.poll() is None  # running before close
    session.close()
    assert proc.poll() is not None  # reaped (waited), not left a zombie
    assert proc.stdin is None or proc.stdin.closed
    assert proc.stdout is None or proc.stdout.closed
