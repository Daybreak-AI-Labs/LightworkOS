"""The stdio JSON-RPC server must not crash on malformed `params`.

A client (which the server treats as untrusted) can send `params` as a
non-object -- a list, string, or number. Handlers call ``params.get(...)``,
so an unguarded value raised ``AttributeError``, surfaced as a scrubbed
-32603 "internal error". The server now coerces a non-dict `params` to
``{}`` so the handler returns the correct -32602 "invalid params" instead,
and never crashes the read loop.
"""
from __future__ import annotations

import io
import json
import sys

import pytest
from maverick_mcp.server import MCPServer, _ProtocolError


def _run_lines(monkeypatch, *lines: str) -> list[dict]:
    monkeypatch.setattr(sys, "stdin", io.StringIO("".join(line + "\n" for line in lines)))
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    MCPServer().run()  # loops until stdin EOF, then returns
    return [json.loads(s) for s in out.getvalue().splitlines() if s.strip()]


def test_non_dict_params_is_invalid_params_not_crash(monkeypatch):
    req = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": ["hostile", "list"]}
    )
    msgs = _run_lines(monkeypatch, req)
    assert msgs, "server produced no response"
    resp = msgs[-1]
    assert resp.get("id") == 1
    assert "error" in resp, f"expected a JSON-RPC error, got {resp}"
    # Coerced params -> handler reports invalid params, not a scrubbed internal error.
    assert resp["error"]["code"] == -32602


def test_non_dict_arguments_is_invalid_params_not_crash(monkeypatch):
    # A truthy non-dict `arguments` (number/bool) survived the `or {}` guard and
    # raised TypeError on the required-argument membership test, escaping the
    # tools/call dispatch helper as a scrubbed -32603. It must be -32602 instead.
    for bad in ("5", "true", "3.14", '"str"'):
        req = (
            '{"jsonrpc":"2.0","id":2,"method":"tools/call",'
            '"params":{"name":"maverick_start","arguments":' + bad + "}}"
        )
        msgs = _run_lines(monkeypatch, req)
        assert msgs, "server produced no response"
        resp = msgs[-1]
        assert resp.get("id") == 2
        assert "error" in resp, f"expected a JSON-RPC error, got {resp}"
        assert resp["error"]["code"] == -32602, resp


def test_handle_tools_call_non_dict_arguments_raises_protocol_error():
    # Direct dispatch-helper invariant: never a raw TypeError out of the helper.
    srv = MCPServer()
    for bad in (5, True, 3.14):
        with pytest.raises(_ProtocolError) as ei:
            srv.handle_tools_call({"name": "maverick_start", "arguments": bad})
        assert ei.value.code == -32602


def test_various_non_dict_params_never_crash(monkeypatch):
    for bad in ("[1,2]", '"str"', "42", "true", "null"):
        req = f'{{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{bad}}}'
        msgs = _run_lines(monkeypatch, req)
        # tools/list ignores params, so this should succeed (result), never crash.
        assert msgs and msgs[-1].get("id") == 7
        assert "result" in msgs[-1] or "error" in msgs[-1]


def test_handle_tools_call_non_string_name_raises_protocol_error():
    # A non-hashable `name` (list/dict) raised TypeError on the `name not in
    # _TOOL_NAMES` set-membership test, escaping as a scrubbed -32603.
    srv = MCPServer()
    for bad in (["x"], {"a": 1}, 5, None):
        with pytest.raises(_ProtocolError) as ei:
            srv.handle_tools_call({"name": bad, "arguments": {}})
        assert ei.value.code == -32602


def test_non_hashable_tool_name_is_invalid_params_not_crash(monkeypatch):
    req = (
        '{"jsonrpc":"2.0","id":3,"method":"tools/call",'
        '"params":{"name":["x"],"arguments":{}}}'
    )
    msgs = _run_lines(monkeypatch, req)
    assert msgs and msgs[-1].get("id") == 3
    assert msgs[-1].get("error", {}).get("code") == -32602, msgs[-1]


def test_handle_resources_read_non_string_uri_raises_protocol_error():
    # A non-string `uri` (number/null/list -- `null` even overrides the ""
    # default) raised AttributeError/TypeError on `.startswith`, scrubbed to -32603.
    srv = MCPServer()
    for bad in (5, None, ["maverick://goals"], {"x": 1}):
        with pytest.raises(_ProtocolError) as ei:
            srv.handle_resources_read({"uri": bad})
        assert ei.value.code == -32602
