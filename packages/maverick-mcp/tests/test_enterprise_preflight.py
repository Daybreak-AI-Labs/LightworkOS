"""MCP entrypoints and goal execution must honor enterprise preflight."""
from __future__ import annotations

import pytest


def test_http_serve_runs_enterprise_preflight_before_uvicorn(monkeypatch):
    from maverick import deployment
    from maverick_mcp import http_transport

    calls = {"gate": 0, "uvicorn": 0}

    def _gate():
        calls["gate"] += 1
        raise RuntimeError("enterprise gate blocked")

    monkeypatch.setattr(deployment, "require_enterprise_or_die", _gate)

    with pytest.raises(RuntimeError, match="enterprise gate blocked"):
        http_transport.serve()

    assert calls == {"gate": 1, "uvicorn": 0}


def test_mcp_tool_start_runs_enterprise_preflight_before_goal_creation(monkeypatch):
    from maverick import deployment
    from maverick_mcp.server import MCPServer

    calls = {"gate": 0, "world": 0}

    def _gate():
        calls["gate"] += 1
        raise RuntimeError("enterprise gate blocked")

    monkeypatch.setattr(deployment, "require_enterprise_or_die", _gate)
    monkeypatch.setattr("maverick.world_model.WorldModel", lambda: calls.__setitem__("world", calls["world"] + 1))

    server = MCPServer()
    server._shield = None
    with pytest.raises(RuntimeError, match="enterprise gate blocked"):
        server._tool_start({"title": "blocked"})

    assert calls == {"gate": 1, "world": 0}
