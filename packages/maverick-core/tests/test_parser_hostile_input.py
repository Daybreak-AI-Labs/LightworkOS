"""Crash-robustness for parsers that consume untrusted structured input.

The MCP client reads JSON-RPC from a server that may be hostile or buggy.
A malformed-but-valid-JSON message -- the right keys with the wrong *types*
-- must not reach an unguarded ``.get()`` and raise ``AttributeError``,
killing the read loop and failing every in-flight call.

These tests fuzz the parser with type-confused / truncated / deeply
wrong shapes and assert it degrades gracefully (no unexpected exception)
rather than crashing.
"""
from __future__ import annotations

import pytest
from maverick.mcp_client import MCPClient, _format_rpc_error


# --- MCP client: a hostile server can send a malformed JSON-RPC `error` ------
def _client_stub() -> MCPClient:
    c = MCPClient.__new__(MCPClient)  # skip __init__/subprocess; _dispatch only
    c._pending = {}                   # needs _pending + spec.name
    c.spec = type("S", (), {"name": "evil"})()
    return c


@pytest.mark.parametrize(
    "msg",
    [
        {"id": None, "error": "hostile-string"},     # id:null broadcast path
        {"id": None, "error": [1, 2]},
        {"id": None, "error": None},
        {"id": None, "error": 500},
        {"id": None, "error": {"code": -1, "message": "real"}},
    ],
)
def test_mcp_dispatch_survives_malformed_error(msg):
    # Must not raise (previously AttributeError killed the read loop).
    _client_stub()._dispatch(msg)


def test_format_rpc_error_is_total():
    assert _format_rpc_error({"code": -1, "message": "m"}) == "-1: m"
    assert _format_rpc_error("oops") == "'oops'"
    assert _format_rpc_error(None) == "None"
    assert _format_rpc_error([1, 2]) == "[1, 2]"


def test_mcp_dispatch_unknown_id_is_dropped_not_crashed():
    # A reply for an id we don't track must be ignored, not crash.
    _client_stub()._dispatch({"id": 9999, "result": {"ok": True}})
    _client_stub()._dispatch({"id": 9999, "error": "whatever"})
