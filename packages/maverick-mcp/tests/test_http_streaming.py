"""MCP Streamable HTTP: SSE streaming path (progress + final response).

The blocking JSON path is covered by test_http_transport.py; here we
exercise the `Accept: text/event-stream` branch.
"""
import time

import pytest

pytest.importorskip("fastapi")

import maverick_mcp.http_transport as ht  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from maverick_mcp.server import MCPServer  # noqa: E402


def _client(monkeypatch):
    monkeypatch.setenv("MAVERICK_MCP_TOKEN", "test-token")
    return TestClient(ht.build_app(MCPServer()))


_AUTH = {"Authorization": "Bearer test-token"}
_SSE = {**_AUTH, "Accept": "text/event-stream"}


def test_sse_streams_final_result(monkeypatch):
    client = _client(monkeypatch)
    resp = client.post("/mcp", headers=_SSE, json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/list",
    })
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    body = resp.text
    # The final JSON-RPC response is delivered as an SSE `data:` event.
    assert "data:" in body
    assert '"result"' in body
    assert "maverick_start" in body


def test_blocking_path_when_sse_not_requested(monkeypatch):
    client = _client(monkeypatch)
    resp = client.post("/mcp", headers=_AUTH, json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/list",
    })
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    assert "result" in resp.json()


def test_sse_emits_progress_with_token(monkeypatch):
    # A slow dispatch + tiny heartbeat guarantees at least one progress
    # event before the final result.
    monkeypatch.setenv("MAVERICK_MCP_SSE_HEARTBEAT", "0.05")

    def _slow_dispatch(
        server, method, params, *, task_owner=None, caller_identity=None, **_auth,
    ):
        time.sleep(0.3)
        return {"ok": True}

    monkeypatch.setattr(ht, "_dispatch", _slow_dispatch)
    client = _client(monkeypatch)
    resp = client.post("/mcp", headers=_SSE, json={
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"_meta": {"progressToken": "tok-1"}},
    })
    assert resp.status_code == 200
    body = resp.text
    assert "notifications/progress" in body
    assert "tok-1" in body
    # final result still arrives after the progress events
    assert '"ok"' in body


def test_sse_no_progress_without_token(monkeypatch):
    monkeypatch.setenv("MAVERICK_MCP_SSE_HEARTBEAT", "0.05")

    def _slow_dispatch(
        server, method, params, *, task_owner=None, caller_identity=None, **_auth,
    ):
        time.sleep(0.2)
        return {"ok": True}

    monkeypatch.setattr(ht, "_dispatch", _slow_dispatch)
    client = _client(monkeypatch)
    resp = client.post("/mcp", headers=_SSE, json={
        "jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {},
    })
    assert resp.status_code == 200
    body = resp.text
    assert "notifications/progress" not in body
    assert '"ok"' in body


def test_sse_rejects_oversized_progress_token(monkeypatch):
    client = _client(monkeypatch)
    resp = client.post("/mcp", headers=_SSE, json={
        "jsonrpc": "2.0", "id": 10, "method": "tools/call",
        "params": {"_meta": {"progressToken": "x" * 129}},
    })
    assert resp.status_code == 400
    assert "progressToken" in resp.text


def test_sse_rejects_non_scalar_progress_token(monkeypatch):
    client = _client(monkeypatch)
    resp = client.post("/mcp", headers=_SSE, json={
        "jsonrpc": "2.0", "id": 11, "method": "tools/call",
        "params": {"_meta": {"progressToken": ["tok"]}},
    })
    assert resp.status_code == 400
    assert "progressToken" in resp.text


def test_sse_caps_progress_events(monkeypatch):
    monkeypatch.setenv("MAVERICK_MCP_SSE_HEARTBEAT", "0.01")
    monkeypatch.setenv("MAVERICK_MCP_SSE_MAX_PROGRESS_EVENTS", "2")

    def _slow_dispatch(
        server, method, params, *, task_owner=None, caller_identity=None, **_auth,
    ):
        time.sleep(0.08)
        return {"ok": True}

    monkeypatch.setattr(ht, "_dispatch", _slow_dispatch)
    client = _client(monkeypatch)
    resp = client.post("/mcp", headers=_SSE, json={
        "jsonrpc": "2.0", "id": 12, "method": "tools/call",
        "params": {"_meta": {"progressToken": "tok-capped"}},
    })
    assert resp.status_code == 200
    body = resp.text
    assert body.count("notifications/progress") == 2
    assert '"ok"' in body


def test_sse_streams_error_as_event(monkeypatch):
    client = _client(monkeypatch)
    resp = client.post("/mcp", headers=_SSE, json={
        "jsonrpc": "2.0", "id": 9, "method": "no/such/method",
    })
    assert resp.status_code == 200
    body = resp.text
    assert '"error"' in body
    assert "-32601" in body


def test_dispatch_binds_caller_identity_for_fleet_ops(monkeypatch):
    # The authenticated caller identity must reach fleet_memory's ContextVar so
    # a fleet tool cannot act AS another rostered agent. Capture what the handler
    # sees mid-dispatch.
    from maverick import fleet_memory

    seen = {}

    def _capture(params, *, task_owner=None):
        seen["caller"] = fleet_memory._caller.get()
        return {"ok": True}

    server = MCPServer()
    monkeypatch.setattr(server, "handle_tools_call", _capture)
    ht._dispatch(server, "tools/call", {}, caller_identity="vega")
    assert seen["caller"] == "vega"
    # ...and the binding is unwound after dispatch (no cross-request leak).
    assert fleet_memory._caller.get() is None


def test_heartbeat_seconds_env(monkeypatch):
    monkeypatch.setenv("MAVERICK_MCP_SSE_HEARTBEAT", "0.5")
    assert ht._heartbeat_seconds() == 0.5
    monkeypatch.setenv("MAVERICK_MCP_SSE_HEARTBEAT", "garbage")
    assert ht._heartbeat_seconds() == 15.0


def test_max_progress_events_env(monkeypatch):
    monkeypatch.setenv("MAVERICK_MCP_SSE_MAX_PROGRESS_EVENTS", "3")
    assert ht._max_progress_events() == 3
    monkeypatch.setenv("MAVERICK_MCP_SSE_MAX_PROGRESS_EVENTS", "-1")
    assert ht._max_progress_events() == 0
    monkeypatch.setenv("MAVERICK_MCP_SSE_MAX_PROGRESS_EVENTS", "garbage")
    assert ht._max_progress_events() == 240


def test_http_subscribe_then_tool_pushes_resource_update(monkeypatch):
    # The same HTTP client session should receive updates after subscribing.
    monkeypatch.setenv("MAVERICK_MCP_TOKEN", "test-token")
    server = MCPServer()
    server._shield = None
    client = TestClient(ht.build_app(server))

    r = client.post("/mcp", headers=_AUTH, json={
        "jsonrpc": "2.0", "id": 1, "method": "resources/subscribe",
        "params": {"uri": "maverick://goals"},
    })
    assert r.status_code == 200

    # Avoid real goal creation; the mutating tool still dirties the resource.
    monkeypatch.setattr(server, "_dispatch_tool", lambda name, args: "started")
    resp = client.post("/mcp", headers=_SSE, json={
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "maverick_start", "arguments": {"title": "x"}},
    })
    body = resp.text
    assert '"result"' in body                              # tool result first
    assert "notifications/resources/updated" in body       # then the push
    assert "maverick://goals" in body


def test_http_no_update_pushed_without_subscription(monkeypatch):
    monkeypatch.setenv("MAVERICK_MCP_TOKEN", "test-token")
    server = MCPServer()
    server._shield = None
    client = TestClient(ht.build_app(server))
    monkeypatch.setattr(server, "_dispatch_tool", lambda name, args: "started")
    resp = client.post("/mcp", headers=_SSE, json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "maverick_start", "arguments": {"title": "x"}},
    })
    assert "notifications/resources/updated" not in resp.text


def test_http_non_subscription_requests_do_not_create_sessions(monkeypatch):
    monkeypatch.setenv("MAVERICK_MCP_TOKEN", "test-token")
    app = ht.build_app(MCPServer())
    client = TestClient(app)

    for i in range(5):
        client.cookies.clear()
        resp = client.post("/mcp", headers=_AUTH, json={
            "jsonrpc": "2.0", "id": i, "method": "tools/list",
        })
        assert resp.status_code == 200
        assert "Mcp-Session-Id" not in resp.headers

    assert len(app.state.resource_sessions) == 0


def test_http_resource_sessions_are_capped(monkeypatch):
    monkeypatch.setenv("MAVERICK_MCP_TOKEN", "test-token")
    monkeypatch.setenv("MAVERICK_MCP_MAX_RESOURCE_SESSIONS", "2")
    app = ht.build_app(MCPServer())
    client = TestClient(app)
    seen = []

    for i in range(3):
        client.cookies.clear()
        resp = client.post("/mcp", headers=_AUTH, json={
            "jsonrpc": "2.0", "id": i, "method": "resources/subscribe",
            "params": {"uri": "maverick://goals"},
        })
        assert resp.status_code == 200
        seen.append(resp.headers["Mcp-Session-Id"])

    assert len(app.state.resource_sessions) == 2
    assert seen[0] not in app.state.resource_sessions
    assert seen[1] in app.state.resource_sessions
    assert seen[2] in app.state.resource_sessions


def test_http_resource_subscriptions_are_client_scoped(monkeypatch):
    monkeypatch.setenv("MAVERICK_MCP_TOKEN", "test-token")
    server = MCPServer()
    server._shield = None
    app = ht.build_app(server)
    client_a = TestClient(app)
    client_b = TestClient(app)

    subscribe = client_a.post("/mcp", headers=_AUTH, json={
        "jsonrpc": "2.0", "id": 1, "method": "resources/subscribe",
        "params": {"uri": "maverick://goals"},
    })
    assert subscribe.status_code == 200

    monkeypatch.setattr(server, "_dispatch_tool", lambda name, args: "started")

    # A separate HTTP client has its own session and must not inherit A's
    # subscription, even though both requests use the shared MCPServer object.
    b_resp = client_b.post("/mcp", headers=_SSE, json={
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "maverick_start", "arguments": {"title": "x"}},
    })
    assert "notifications/resources/updated" not in b_resp.text

    unsubscribe = client_b.post("/mcp", headers=_AUTH, json={
        "jsonrpc": "2.0", "id": 3, "method": "resources/unsubscribe",
        "params": {"uri": "maverick://goals"},
    })
    assert unsubscribe.status_code == 200

    # B's idempotent unsubscribe must not remove A's expected notification.
    a_resp = client_a.post("/mcp", headers=_SSE, json={
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "maverick_start", "arguments": {"title": "x"}},
    })
    assert "notifications/resources/updated" in a_resp.text
    assert "maverick://goals" in a_resp.text
