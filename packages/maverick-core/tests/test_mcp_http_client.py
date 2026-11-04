"""Remote MCP servers over Streamable HTTP.

StreamableHttpMCPClient lets Lightwork consume a REMOTE MCP server (a `url` in
config) instead of only stdio subprocesses. These tests drive it against an
httpx MockTransport, so no network/server is needed; they cover the JSON and
SSE response paths, session-id continuity, auth, error surfacing, the spec
parsing, and that it's a drop-in for start_mcp_clients + tools_from_mcp.
"""
from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from maverick.mcp_client import (
    MCPClientError,
    MCPServerSpec,
    StreamableHttpMCPClient,
)


def make_handler(record: list | None = None, *, sse=False, rpc_error=False, http_status=200):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if record is not None:
            record.append({k.lower(): v for k, v in request.headers.items()})
        method = body.get("method")
        if method == "initialize":
            return httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": body["id"],
                      "result": {"protocolVersion": "2025-11-25", "capabilities": {},
                                 "serverInfo": {"name": "remote"}}},
                headers={"Mcp-Session-Id": "sess-1"},
            )
        if method == "notifications/initialized":
            return httpx.Response(202)
        if method == "tools/list":
            return httpx.Response(200, json={
                "jsonrpc": "2.0", "id": body["id"],
                "result": {"tools": [{"name": "echo", "description": "echoes",
                                      "inputSchema": {"type": "object"}}]}})
        if method == "tools/call":
            if http_status >= 400:
                return httpx.Response(http_status, text="upstream down")
            if rpc_error:
                return httpx.Response(200, json={
                    "jsonrpc": "2.0", "id": body["id"],
                    "error": {"code": -32000, "message": "boom"}})
            result = {"jsonrpc": "2.0", "id": body["id"],
                      "result": {"content": [{"type": "text",
                                              "text": "hi " + str(body["params"]["arguments"].get("msg", ""))}]}}
            if sse:
                return httpx.Response(
                    200, headers={"content-type": "text/event-stream"},
                    text=f": heartbeat\n\ndata: {json.dumps(result)}\n\n")
            return httpx.Response(200, json=result)
        return httpx.Response(404, text="unknown method")
    return handler


def _install(monkeypatch, handler):
    real = httpx.AsyncClient

    def fake(*a, **k):
        k["transport"] = httpx.MockTransport(handler)
        return real(*a, **k)

    monkeypatch.setattr(httpx, "AsyncClient", fake)


def _client(name="remote", **kw):
    return StreamableHttpMCPClient(MCPServerSpec(name=name, url="https://x/mcp", **kw))


# ---- core request/response --------------------------------------------------

@pytest.mark.asyncio
async def test_lists_and_calls_tools(monkeypatch):
    _install(monkeypatch, make_handler())
    c = _client()
    await c.start()
    assert [t["name"] for t in c.tools] == ["echo"]
    assert await c.call_tool("echo", {"msg": "there"}) == "hi there"
    await c.stop()


@pytest.mark.asyncio
async def test_handles_sse_response(monkeypatch):
    _install(monkeypatch, make_handler(sse=True))
    c = _client()
    await c.start()
    assert await c.call_tool("echo", {"msg": "sse"}) == "hi sse"  # extracted past the heartbeat
    await c.stop()


class NeverEndingSSE(httpx.AsyncByteStream):
    def __init__(self, result: dict):
        self.result = result
        self.closed = False

    async def __aiter__(self):
        yield b": heartbeat\n\n"
        yield f"data: {json.dumps(self.result)}\n\n".encode()
        while True:
            await asyncio.sleep(3600)

    async def aclose(self) -> None:
        self.closed = True


class ChunkedSSE(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]):
        self.chunks = chunks

    async def __aiter__(self):
        for chunk in self.chunks:
            yield chunk


@pytest.mark.asyncio
async def test_streaming_sse_returns_without_waiting_for_close(monkeypatch):
    streams: list[NeverEndingSSE] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        method = body.get("method")
        if method != "tools/call":
            return make_handler()(request)
        result = {"jsonrpc": "2.0", "id": body["id"],
                  "result": {"content": [{"type": "text", "text": "streamed"}]}}
        stream = NeverEndingSSE(result)
        streams.append(stream)
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, stream=stream)

    _install(monkeypatch, handler)
    c = _client()
    await c.start()
    assert await asyncio.wait_for(c.call_tool("echo", {}), timeout=1) == "streamed"
    assert streams and streams[0].closed
    await c.stop()


@pytest.mark.asyncio
async def test_sse_response_size_is_capped(monkeypatch):
    import maverick.mcp_client as mcp_client

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        method = body.get("method")
        if method != "tools/call":
            return make_handler()(request)
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=ChunkedSSE([b": heartbeat\n\n", b"data: ", b"x" * 64]),
        )

    _install(monkeypatch, handler)
    c = _client()
    await c.start()
    monkeypatch.setattr(mcp_client, "_MAX_HTTP_RESPONSE_BYTES", 32)
    with pytest.raises(MCPClientError, match="SSE response exceeded"):
        await c.call_tool("echo", {})
    await c.stop()


@pytest.mark.asyncio
async def test_resends_session_id_and_accepts_sse(monkeypatch):
    record: list = []
    _install(monkeypatch, make_handler(record))
    c = _client()
    await c.start()
    await c.call_tool("echo", {})
    await c.stop()
    assert "text/event-stream" in record[0]["accept"]      # we accept both forms
    assert record[0].get("mcp-session-id") is None          # none to send yet on initialize
    assert all(h.get("mcp-session-id") == "sess-1" for h in record[1:])  # captured + resent


@pytest.mark.asyncio
async def test_sends_auth_token(monkeypatch):
    record: list = []
    _install(monkeypatch, make_handler(record))
    c = _client(auth_token="s3cr3t")
    await c.start()
    await c.stop()
    assert record[0].get("authorization") == "Bearer s3cr3t"


# ---- error surfacing --------------------------------------------------------

@pytest.mark.asyncio
async def test_surfaces_jsonrpc_error(monkeypatch):
    _install(monkeypatch, make_handler(rpc_error=True))
    c = _client()
    await c.start()
    with pytest.raises(MCPClientError):
        await c.call_tool("echo", {})
    await c.stop()


@pytest.mark.asyncio
async def test_surfaces_http_error(monkeypatch):
    _install(monkeypatch, make_handler(http_status=503))
    c = _client()
    await c.start()
    with pytest.raises(MCPClientError):
        await c.call_tool("echo", {})
    await c.stop()


# ---- spec parsing + wiring --------------------------------------------------

def test_from_config_http_vs_stdio():
    http = MCPServerSpec.from_config("r", {"url": "https://x/mcp", "auth_token": "t"})
    assert http.is_http and http.url == "https://x/mcp" and http.auth_token == "t"
    stdio = MCPServerSpec.from_config("s", {"command": "npx", "args": ["y"]})
    assert not stdio.is_http and stdio.command == "npx"


def test_http_spec_rejects_bad_url():
    with pytest.raises(ValueError):
        MCPServerSpec(name="r", url="ftp://x/mcp")
    with pytest.raises(ValueError):
        MCPServerSpec(name="r", url="not-a-url")


@pytest.mark.asyncio
async def test_start_mcp_clients_builds_http_for_url(monkeypatch):
    _install(monkeypatch, make_handler())
    from maverick.mcp_client import start_mcp_clients, stop_mcp_clients
    clients = await start_mcp_clients([MCPServerSpec(name="remote", url="https://x/mcp")])
    assert len(clients) == 1
    assert type(clients[0]).__name__ == "StreamableHttpMCPClient"
    assert [t["name"] for t in clients[0].tools] == ["echo"]
    await stop_mcp_clients(clients)


@pytest.mark.asyncio
async def test_tools_from_mcp_wraps_http_client(monkeypatch):
    _install(monkeypatch, make_handler())
    import inspect

    from maverick.mcp_tools import tools_from_mcp
    c = _client()
    await c.start()
    tools = tools_from_mcp(c)
    assert [t.name for t in tools] == ["mcp_remote__echo"]
    out = tools[0].fn({"msg": "wrapped"})
    if inspect.isawaitable(out):
        out = await out
    assert "hi wrapped" in out
    await c.stop()
