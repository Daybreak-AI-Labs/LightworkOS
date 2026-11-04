"""MCP Streamable HTTP transport tests."""
from __future__ import annotations

import pytest


def _have_fastapi() -> bool:
    try:
        import fastapi  # noqa: F401
        return True
    except ImportError:
        return False


@pytest.mark.skipif(not _have_fastapi(), reason="fastapi not installed")
class TestHTTPTransport:
    def _client(self):
        from fastapi.testclient import TestClient
        from maverick_mcp.http_transport import build_app
        from maverick_mcp.server import MCPServer
        app = build_app(MCPServer())
        return TestClient(app)

    def test_a2a_agent_card_served_when_enabled(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_A2A_ENABLED", "1")
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        client = self._client()
        resp = client.get("/.well-known/agent-card.json")
        assert resp.status_code == 200
        body = resp.json()
        assert body["name"] == "Lightwork"
        # The card advertises the A2A version the installed task surface speaks.
        assert body["protocolVersion"] == "0.3.0"

    def test_initialize_returns_capabilities(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        client = self._client()
        resp = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25"},
        }, headers={"Authorization": "Bearer s3cr3t"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["jsonrpc"] == "2.0"
        assert body["id"] == 1
        assert "result" in body
        assert "capabilities" in body["result"]

    def test_tools_call_runs_sync_asyncio_tool_without_loop_crash(self, monkeypatch):
        """Regression: the HTTP endpoint dispatched synchronously inside
        FastAPI's running loop, so maverick_start (run_goal_sync ->
        asyncio.run) crashed with 'asyncio.run() cannot be called from a
        running event loop'. The dispatch now runs in a worker thread."""
        import asyncio

        from maverick_mcp import server as srv

        async def _trivial():
            return "DONE: stub run"

        def _fake_start(self, args):
            # Mirror run_goal_sync's pattern (asyncio.run on a coroutine) --
            # exactly what crashed before the to_thread fix.
            return asyncio.run(_trivial())

        monkeypatch.setattr(srv.MCPServer, "_tool_start", _fake_start, raising=True)
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        client = self._client()
        resp = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": "maverick_start", "arguments": {"title": "hi"}},
        }, headers={"Authorization": "Bearer s3cr3t"})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["result"]["isError"] is False, body
        assert "DONE: stub run" in body["result"]["content"][0]["text"]

    def test_skill_install_rejects_bare_local_path(self, monkeypatch):
        """The MCP skill-install must pass trusted_local=False so a network
        client can't read arbitrary host files via a bare local path."""
        from types import SimpleNamespace

        from maverick import skills as skills_mod
        captured: dict = {}

        def _fake_install(source, *, trusted_local=True):
            captured["trusted_local"] = trusted_local
            return SimpleNamespace(name="x", path="/tmp/x")

        monkeypatch.setattr(skills_mod, "install_skill", _fake_install)
        monkeypatch.setenv("MAVERICK_ALLOW_SKILL_INSTALL", "1")
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        client = self._client()
        resp = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 8, "method": "tools/call",
            "params": {"name": "maverick_skill_install",
                       "arguments": {"source": "/etc/passwd"}},
        }, headers={"Authorization": "Bearer s3cr3t"})
        assert resp.status_code == 200, resp.text
        assert captured.get("trusted_local") is False

    def test_unknown_method_returns_jsonrpc_error(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        client = self._client()
        resp = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 2, "method": "no/such/method",
            "params": {},
        }, headers={"Authorization": "Bearer s3cr3t"})
        body = resp.json()
        assert "error" in body
        assert body["error"]["code"] == -32601

    def test_resources_list_works_over_http(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        client = self._client()
        resp = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 3, "method": "resources/list",
            "params": {},
        }, headers={"Authorization": "Bearer s3cr3t"})
        body = resp.json()
        assert "result" in body
        assert "resources" in body["result"]

    def test_bearer_required_when_token_set(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        client = self._client()
        resp = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {},
        })
        assert resp.status_code == 401

    def test_bearer_accepted_when_correct(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        client = self._client()
        resp = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {},
        }, headers={"Authorization": "Bearer s3cr3t"})
        assert resp.status_code == 200

    def test_wrong_bearer_rejected(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        client = self._client()
        resp = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {},
        }, headers={"Authorization": "Bearer wrong"})
        assert resp.status_code == 401

    def test_auth_required_when_token_unset(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_MCP_TOKEN", raising=False)
        client = self._client()
        resp = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {},
        })
        assert resp.status_code == 401

    def test_healthz_exempt(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        client = self._client()
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json()["transport"] == "http"

    def test_oversized_body_rejected(self, monkeypatch):
        """A body over the cap is rejected (413) before dispatch -- post-auth
        memory-DoS guard."""
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        monkeypatch.setenv("MAVERICK_MCP_MAX_BODY", "2048")
        client = self._client()
        huge = "x" * 5000
        resp = client.post(
            "/mcp",
            content=b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"pad":"'
            + huge.encode() + b'"}}',
            headers={"Authorization": "Bearer s3cr3t", "Content-Type": "application/json"},
        )
        assert resp.status_code == 413

    def test_body_cap_does_not_block_normal_requests(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        monkeypatch.setenv("MAVERICK_MCP_MAX_BODY", "2048")
        client = self._client()
        resp = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {},
        }, headers={"Authorization": "Bearer s3cr3t"})
        assert resp.status_code == 200

    def test_cross_origin_request_rejected(self, monkeypatch):
        """DNS-rebinding defense: a browser cross-origin Origin is rejected
        before dispatch, even with a valid bearer."""
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        client = self._client()
        resp = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {},
        }, headers={"Authorization": "Bearer s3cr3t",
                    "Origin": "http://evil.example.com"})
        assert resp.status_code == 403

    def test_dns_rebinding_host_origin_rejected(self, monkeypatch):
        """Do not trust Host-derived same-origin checks for DNS rebinding."""
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        client = self._client()
        resp = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {},
        }, headers={"Authorization": "Bearer s3cr3t",
                    "Host": "attacker.example:8771",
                    "Origin": "http://attacker.example:8771"})
        assert resp.status_code == 403

    def test_loopback_origin_allowed(self, monkeypatch):
        """Local browser clients loaded from loopback remain supported."""
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        client = self._client()
        resp = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {},
        }, headers={"Authorization": "Bearer s3cr3t",
                    "Origin": "http://127.0.0.1:8771"})
        assert resp.status_code == 200

    def test_no_origin_header_allowed(self, monkeypatch):
        """Native MCP clients / curl omit Origin and must still work."""
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        client = self._client()
        resp = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {},
        }, headers={"Authorization": "Bearer s3cr3t"})
        assert resp.status_code == 200

    def test_configured_origin_allowed(self, monkeypatch):
        """An operator can allowlist a gateway origin."""
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        monkeypatch.setenv("MAVERICK_MCP_ALLOWED_ORIGINS",
                           "http://gateway.example.com")
        client = self._client()
        resp = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {},
        }, headers={"Authorization": "Bearer s3cr3t",
                    "Origin": "http://gateway.example.com"})
        assert resp.status_code == 200

    def test_notification_returns_204(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        client = self._client()
        resp = client.post("/mcp", json={
            "jsonrpc": "2.0", "method": "notifications/initialized",
            "params": {},
        }, headers={"Authorization": "Bearer s3cr3t"})
        # No "id" -> notification -> 204
        assert resp.status_code == 204


@pytest.mark.skipif(not _have_fastapi(), reason="fastapi not installed")
class TestHTTPNotifications:
    def _client(self):
        from fastapi.testclient import TestClient
        from maverick_mcp.http_transport import build_app
        from maverick_mcp.server import MCPServer
        return TestClient(build_app(MCPServer()))

    def test_notification_returns_204_with_no_body(self, monkeypatch):
        # A JSON-RPC notification (no id) must get 204 No Content with an
        # empty body -- JSONResponse({}) wrote "{}" which strict proxies
        # reject as a 204-with-body protocol violation.
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        client = self._client()
        resp = client.post("/mcp", json={
            "jsonrpc": "2.0", "method": "notifications/initialized",
        }, headers={"Authorization": "Bearer s3cr3t"})
        assert resp.status_code == 204
        assert resp.content == b""

    def test_id_null_is_a_request_not_a_notification(self, monkeypatch):
        # A MISSING "id" is a notification (204); an explicit {"id": null} is a
        # request still owed a response. The two must NOT be conflated -- HTTP
        # and stdio both distinguish "id" not in body from body["id"] is None.
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        client = self._client()
        resp = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": None, "method": "notifications/initialized",
        }, headers={"Authorization": "Bearer s3cr3t"})
        # id is present (null) -> request -> a JSON-RPC response, not a 204.
        assert resp.status_code == 200
        body = resp.json()
        assert body["id"] is None
        assert body.get("result") == {}


@pytest.mark.skipif(not _have_fastapi(), reason="fastapi not installed")
class TestHTTPTasks:
    """Async MCP tasks over the Streamable HTTP transport (opt-in).

    Tasks are off by default over HTTP; MAVERICK_MCP_HTTP_TASKS=1 enables a
    bearer-scoped task store shared across requests on the same server instance.
    """

    _AUTH = {"Authorization": "Bearer s3cr3t"}

    def _client(self):
        from fastapi.testclient import TestClient
        from maverick_mcp.http_transport import build_app
        from maverick_mcp.server import MCPServer
        # build_app reads MAVERICK_MCP_HTTP_TASKS, so env must be set first.
        return TestClient(build_app(MCPServer()))

    def _enable(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        monkeypatch.setenv("MAVERICK_MCP_HTTP_TASKS", "1")

    def _stub_start(self, monkeypatch):
        """Make maverick_start deterministic (no LLM): patched at the class so
        the fresh per-task worker MCPServer instance picks it up too."""
        from maverick_mcp import server as srv

        def _fake_start(self, args):
            return "DONE: " + str(args.get("title", ""))

        monkeypatch.setattr(srv.MCPServer, "_tool_start", _fake_start, raising=True)

    def _create_task(self, client, title="hi", req_id=100):
        resp = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": req_id, "method": "tools/call",
            "params": {"name": "maverick_start", "arguments": {"title": title},
                       "task": {"ttl": 60000}},
        }, headers=self._AUTH)
        return resp.json()

    def test_initialize_advertises_tasks_when_enabled(self, monkeypatch):
        self._enable(monkeypatch)
        client = self._client()
        body = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {},
        }, headers=self._AUTH).json()
        assert "tasks" in body["result"]["capabilities"]

    def test_initialize_omits_tasks_by_default(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        monkeypatch.delenv("MAVERICK_MCP_HTTP_TASKS", raising=False)
        client = self._client()
        body = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {},
        }, headers=self._AUTH).json()
        assert "tasks" not in body["result"]["capabilities"]

    def test_task_augmented_call_returns_create_task_result(self, monkeypatch):
        self._enable(monkeypatch)
        self._stub_start(monkeypatch)
        client = self._client()
        body = self._create_task(client, title="hi", req_id=2)
        # CreateTaskResult: a frozen "working" snapshot, never the final status.
        assert "task" in body["result"]
        assert body["result"]["task"]["status"] == "working"
        assert body["result"]["task"]["taskId"]

    def test_task_result_returns_final_call_result(self, monkeypatch):
        self._enable(monkeypatch)
        self._stub_start(monkeypatch)
        client = self._client()
        tid = self._create_task(client, title="deep work", req_id=3)["result"]["task"]["taskId"]
        # tasks/result blocks until terminal (in a worker thread, so the loop
        # isn't wedged), then returns exactly the CallToolResult + related-task meta.
        res = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 4, "method": "tasks/result",
            "params": {"taskId": tid},
        }, headers=self._AUTH).json()
        assert res["result"]["isError"] is False
        assert "DONE: deep work" in res["result"]["content"][0]["text"]
        meta = res["result"]["_meta"]["io.modelcontextprotocol/related-task"]
        assert meta["taskId"] == tid

    def test_tasks_get_and_list(self, monkeypatch):
        self._enable(monkeypatch)
        self._stub_start(monkeypatch)
        client = self._client()
        tid = self._create_task(client, req_id=5)["result"]["task"]["taskId"]
        # Drain so the status is settled, then poll get + list.
        client.post("/mcp", json={"jsonrpc": "2.0", "id": 6, "method": "tasks/result",
                                  "params": {"taskId": tid}}, headers=self._AUTH)
        got = client.post("/mcp", json={"jsonrpc": "2.0", "id": 7, "method": "tasks/get",
                                        "params": {"taskId": tid}}, headers=self._AUTH).json()
        assert got["result"]["taskId"] == tid
        assert got["result"]["status"] == "completed"
        listed = client.post("/mcp", json={"jsonrpc": "2.0", "id": 8, "method": "tasks/list",
                                           "params": {}}, headers=self._AUTH).json()
        assert any(t["taskId"] == tid for t in listed["result"]["tasks"])

    def test_tasks_cancel(self, monkeypatch):
        import threading
        self._enable(monkeypatch)
        # A worker that blocks until released, so cancel wins the race.
        from maverick_mcp import server as srv
        release = threading.Event()

        def _blocking_start(self, args):
            release.wait(timeout=10)
            return "DONE late"

        monkeypatch.setattr(srv.MCPServer, "_tool_start", _blocking_start, raising=True)
        client = self._client()
        try:
            tid = self._create_task(client, req_id=9)["result"]["task"]["taskId"]
            cancelled = client.post("/mcp", json={
                "jsonrpc": "2.0", "id": 10, "method": "tasks/cancel",
                "params": {"taskId": tid},
            }, headers=self._AUTH).json()
            assert cancelled["result"]["status"] == "cancelled"
        finally:
            release.set()  # let the blocked worker exit cleanly

    def test_unknown_task_id_returns_invalid_params(self, monkeypatch):
        self._enable(monkeypatch)
        client = self._client()
        body = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 11, "method": "tasks/get",
            "params": {"taskId": "nope"},
        }, headers=self._AUTH).json()
        assert body["error"]["code"] == -32602

    def test_http_tasks_are_isolated_by_client_session(self, monkeypatch):
        self._enable(monkeypatch)
        self._stub_start(monkeypatch)
        from fastapi.testclient import TestClient
        from maverick_mcp.http_transport import build_app
        from maverick_mcp.server import MCPServer

        app = build_app(MCPServer())
        alice = TestClient(app)
        bob = TestClient(app)

        tid = self._create_task(alice, title="alice secret", req_id=50)["result"]["task"]["taskId"]
        alice_result = alice.post("/mcp", json={
            "jsonrpc": "2.0", "id": 51, "method": "tasks/result",
            "params": {"taskId": tid},
        }, headers=self._AUTH).json()
        assert "DONE: alice secret" in alice_result["result"]["content"][0]["text"]

        bob_list = bob.post("/mcp", json={
            "jsonrpc": "2.0", "id": 52, "method": "tasks/list", "params": {},
        }, headers=self._AUTH).json()
        assert bob_list["result"]["tasks"] == []

        bob_result = bob.post("/mcp", json={
            "jsonrpc": "2.0", "id": 53, "method": "tasks/result",
            "params": {"taskId": tid},
        }, headers=self._AUTH).json()
        assert bob_result["error"]["code"] == -32602

        bob_cancel = bob.post("/mcp", json={
            "jsonrpc": "2.0", "id": 54, "method": "tasks/cancel",
            "params": {"taskId": tid},
        }, headers=self._AUTH).json()
        assert bob_cancel["error"]["code"] == -32602

    def test_tasks_disabled_returns_method_not_found(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        monkeypatch.delenv("MAVERICK_MCP_HTTP_TASKS", raising=False)
        client = self._client()
        body = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 12, "method": "tasks/get",
            "params": {"taskId": "x"},
        }, headers=self._AUTH).json()
        assert body["error"]["code"] == -32601

    def test_task_field_ignored_when_disabled(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        monkeypatch.delenv("MAVERICK_MCP_HTTP_TASKS", raising=False)
        self._stub_start(monkeypatch)
        client = self._client()
        body = self._create_task(client, title="x", req_id=13)
        # Tasks off -> the `task` field is ignored, the tool runs synchronously,
        # and the response is a normal CallToolResult, not a CreateTaskResult.
        assert "task" not in body["result"]
        assert body["result"]["isError"] is False
        assert "DONE: x" in body["result"]["content"][0]["text"]


@pytest.mark.skipif(not _have_fastapi(), reason="fastapi not installed")
class TestHTTPMalformedBody:
    def _client(self):
        from fastapi.testclient import TestClient
        from maverick_mcp.http_transport import build_app
        from maverick_mcp.server import MCPServer
        return TestClient(build_app(MCPServer()))

    def test_non_object_body_returns_400_not_500(self, monkeypatch):
        # A top-level JSON array (valid JSON, not an object) made body.get(...)
        # raise AttributeError -> 500 stack trace. Must be a clean 400.
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        client = self._client()
        resp = client.post("/mcp", json=[1, 2, 3],
                           headers={"Authorization": "Bearer s3cr3t"})
        assert resp.status_code == 400

    def test_malformed_json_returns_400_not_500(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        client = self._client()
        resp = client.post("/mcp", content=b"{not json",
                           headers={"Authorization": "Bearer s3cr3t",
                                    "Content-Type": "application/json"})
        assert resp.status_code == 400


@pytest.mark.skipif(not _have_fastapi(), reason="fastapi not installed")
class TestSessionCookieHardening:
    """The session cookie must never leak over plain HTTP off-box and must
    not live forever: Secure on non-loopback peers, bounded Max-Age."""

    _AUTH = {"Authorization": "Bearer s3cr3t"}
    _SUBSCRIBE = {
        "jsonrpc": "2.0", "id": 1, "method": "resources/subscribe",
        "params": {"uri": "maverick://runs/recent"},
    }

    def _app(self):
        from maverick_mcp.http_transport import build_app
        from maverick_mcp.server import MCPServer
        return build_app(MCPServer())

    def test_loopback_peer_cookie_attributes(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        from fastapi.testclient import TestClient
        resp = TestClient(self._app()).post(
            "/mcp", json=self._SUBSCRIBE, headers=self._AUTH)
        cookie = resp.headers["set-cookie"]
        assert "maverick_mcp_session=" in cookie
        assert "HttpOnly" in cookie
        # Cookie-only clients must retain the caller-bound session for the
        # TaskStore's maximum accepted TTL (7 days), even if resource state is
        # evicted independently.
        assert "Max-Age=604800" in cookie
        # Loopback dev over plain http must still receive the cookie.
        assert "Secure" not in cookie

    def test_non_loopback_peer_gets_secure_cookie(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", "s3cr3t")
        from starlette.testclient import TestClient
        resp = TestClient(self._app(), client=("203.0.113.9", 4444)).post(
            "/mcp", json=self._SUBSCRIBE, headers=self._AUTH)
        cookie = resp.headers["set-cookie"]
        assert "maverick_mcp_session=" in cookie
        assert "Secure" in cookie
