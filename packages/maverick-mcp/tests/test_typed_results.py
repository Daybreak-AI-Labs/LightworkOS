"""Explicit kernel outcomes remain truthful at the MCP result boundary."""
from __future__ import annotations

import pytest
from maverick.tool_results import ToolOutcome, ToolResultState
from maverick_mcp.server import MCPServer


@pytest.mark.parametrize("state, content, is_error", [
    (ToolResultState.SUCCEEDED, "ERROR is a title", False),
    (ToolResultState.FAILED, "request failed", True),
    (ToolResultState.REFUSED, "not approved", True),
    (ToolResultState.INDETERMINATE, "receipt missing", True),
])
def test_mcp_carries_explicit_state_and_only_notifies_success(monkeypatch, state, content, is_error):
    server = MCPServer()
    notices = []
    monkeypatch.setattr(server, "_dispatch_tool", lambda *_a, **_k: ToolOutcome(state, content))
    monkeypatch.setattr(server, "_structured_result", lambda *_a, **_k: None)
    monkeypatch.setattr(server, "_queue_resource_update", notices.append)
    response = server.handle_tools_call({"name": "maverick_status", "arguments": {}})
    assert response["isError"] is is_error
    assert response["content"] == [{"type": "text", "text": content}]
    assert notices == ([] if is_error else ["maverick_status"])
    if is_error:
        assert "structuredContent" not in response


def test_legacy_mcp_string_retains_existing_semantics(monkeypatch):
    server = MCPServer()
    monkeypatch.setattr(server, "_dispatch_tool", lambda *_a, **_k: "ERROR is untyped text")
    monkeypatch.setattr(server, "_structured_result", lambda *_a, **_k: None)
    response = server.handle_tools_call({"name": "maverick_status", "arguments": {}})
    assert response["isError"] is False
