"""Catalog correctness and authority invariants; no external MCP services."""
from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest
from maverick.mcp_catalog import CatalogError, CatalogLimits, ToolCatalog
from maverick.mcp_client import MCPClient, MCPServerSpec, StreamableHttpMCPClient
from maverick.tools import ToolRegistry, _apply_mcp_tools


def spec(name="one", **extra):
    return {"name": name, "description": "A bounded test tool", "inputSchema": {"type": "object"}, **extra}


class StdioPeer:
    def __init__(self, handler):
        self.handler = handler
        self.returncode = None
        self.stdout = asyncio.StreamReader()
        self.stdin = self
        self.stderr = None
        self.requests = []

    def write(self, data):
        request = json.loads(data)
        self.requests.append(request)
        if "id" in request:
            self.stdout.feed_data((json.dumps(self.handler(request)) + "\n").encode())

    async def drain(self):
        pass

    def terminate(self):
        self.returncode = 0

    async def wait(self):
        return 0


async def make_client(transport, handler, monkeypatch):
    if transport == "stdio":
        client = MCPClient(MCPServerSpec("catalog", command="fake"))
        peer = StdioPeer(handler)

        async def spawn(*args, **kwargs):
            return peer

        monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    else:
        client = StreamableHttpMCPClient(MCPServerSpec("catalog", url="http://localhost/mcp"))
        real = httpx.AsyncClient

        def respond(request):
            body = json.loads(request.content)
            if "id" not in body:
                return httpx.Response(202)
            return httpx.Response(200, json=handler(body))

        monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: real(transport=httpx.MockTransport(respond), **kwargs))
    await client.start()
    return client


@pytest.mark.parametrize("transport", ["stdio", "http"])
@pytest.mark.asyncio
async def test_paginated_startup_routes_both_transports(transport, monkeypatch):
    calls = []

    def handler(request):
        calls.append(request)
        if request["method"] == "tools/list":
            result = {"tools": [spec("two")]} if request["params"].get("cursor") == "page2" else {"tools": [spec()], "nextCursor": "page2"}
        elif request["method"] == "tools/call":
            result = {"content": [{"type": "text", "text": request["params"]["name"]}]}
        else:
            result = {"protocolVersion": "2024-11-05"}
        return {"jsonrpc": "2.0", "id": request["id"], "result": result}

    client = await make_client(transport, handler, monkeypatch)
    try:
        assert [s["name"] for s in client.tools] == ["one", "two"]
        registry = ToolRegistry()
        _apply_mcp_tools(registry, [client])
        assert [t.name for t in registry.all()] == ["mcp_catalog__one", "mcp_catalog__two"]
        assert await registry.run("mcp_catalog__two", {}) == "two"
        assert len([r for r in calls if r["method"] == "tools/list"]) == 2
        client.tools[0]["inputSchema"]["properties"] = {"bad": {"type": "string"}}
        assert "properties" not in client.tools[0]["inputSchema"]
    finally:
        await client.stop()


@pytest.mark.parametrize("pages,limits,reason", [
    ([{"tools": [spec()], "nextCursor": "same"}, {"tools": [], "nextCursor": "same"}], {}, "cursor"),
    ([{"tools": [spec()], "nextCursor": "next"}, {"tools": [spec(description="different")]}], {}, "duplicate"),
    ([{"tools": [spec(inputSchema=[])]}], {}, "object schema"),
    ([{"tools": [spec(inputSchema={"type": "object", "properties": {"x": {"type": "wrong"}}})]}], {}, "schema type"),
    ([{"tools": [spec(inputSchema={"type": "object", "required": ["x", "x"]})]}], {}, "duplicate required"),
    ([{"tools": [spec("bad__name")]}], {}, "name"),
    ([{"tools": [spec()], "nextCursor": "next"}], {"pages": 1}, "page limit"),
    ([{"tools": [spec(), spec("two")]}], {"tools": 1}, "tool limit"),
    ([{"tools": [spec(description="secret" * 100)]}], {"bytes": 150}, "byte limit"),
    ([{"tools": [spec(inputSchema={"type": "object", "examples": [[[1]]]})]}], {"depth": 4}, "structural"),
    ([{"tools": [spec()], "nextCursor": "private-cursor" * 1000}], {}, "cursor"),
    ([{"tools": "wrong"}], {}, "page"),
    ([{"tools": [spec(description=None)]}], {}, "description"),
])
@pytest.mark.asyncio
async def test_invalid_catalog_never_publishes_partial_generation(pages, limits, reason):
    pending = iter(pages)
    requests = []

    async def request(method, params):
        requests.append(params)
        return next(pending)

    catalog = ToolCatalog(request, limits=replace(CatalogLimits(), **limits))
    with pytest.raises(CatalogError, match=reason):
        await catalog.refresh()
    assert catalog.tools == []
    assert catalog.status["generation"] == 0 and catalog.status["stale"]
    assert "secret" not in catalog.status["error"] and "private-cursor" not in catalog.status["error"]
    assert len(requests) <= len(pages)
    await catalog.close()


@pytest.mark.asyncio
async def test_catalog_deadline_closes_owned_request_and_retains_previous_generation():
    closed = asyncio.Event()
    blocking = False

    async def request(method, params):
        if not blocking:
            return {"tools": [spec()]}
        try:
            await asyncio.Event().wait()
        finally:
            closed.set()

    catalog = ToolCatalog(request, limits=replace(CatalogLimits(), seconds=0.03))
    await catalog.refresh()
    before = catalog.generation
    blocking = True
    with pytest.raises(CatalogError, match="TimeoutError"):
        await catalog.refresh()
    assert closed.is_set() and catalog.generation is before
    assert catalog.identity("one") is None and catalog.status["stale"]
    await catalog.close()


@pytest.mark.asyncio
async def test_refresh_coalesces_atomic_generations_and_never_expands_admitted_authority():
    entered, release = asyncio.Event(), asyncio.Event()
    calls = 0

    async def request(method, params):
        nonlocal calls
        calls += 1
        if calls == 1:
            return {"tools": [spec()]}
        entered.set()
        await release.wait()
        return {"tools": [spec(), spec("new")]}

    catalog = ToolCatalog(request)
    await catalog.refresh()
    client = SimpleNamespace(catalog=catalog, spec=SimpleNamespace(name="catalog"))
    client.tools = catalog.tools
    registry = ToolRegistry()
    _apply_mcp_tools(registry, [client])
    assert len(registry.to_anthropic()) == 1
    catalog.changed()
    await entered.wait()
    for _ in range(100):
        catalog.changed()
    assert registry.to_anthropic() == []
    assert "stale" in await registry.run("mcp_catalog__one", {})
    release.set()
    await catalog.refresh()
    assert calls == 3  # Initial plus two bounded passes, not 101 refreshes.
    assert catalog.status["generation"] == 2
    assert [t.name for t in registry.all()] == ["mcp_catalog__one"]
    assert len(registry.to_anthropic()) == 1
    assert "unknown" in await registry.run("mcp_catalog__new", {})
    registry.set_acl(denied={"mcp_catalog__one"})
    assert registry.to_anthropic() == []
    assert "denied" in await registry.run("mcp_catalog__one", {})
    client.tools = catalog.tools
    next_registry = ToolRegistry()
    next_registry.set_acl(allowed={"mcp_catalog__new"})
    _apply_mcp_tools(next_registry, [client])
    assert [t.name for t in next_registry.all()] == ["mcp_catalog__new"]
    await catalog.close()


@pytest.mark.asyncio
async def test_changed_schema_cannot_execute_with_old_binding():
    descriptor = spec()

    async def request(method, params):
        return {"tools": [descriptor]}

    client = MCPClient(MCPServerSpec("catalog", command="fake"))
    client.catalog = ToolCatalog(request)
    await client.refresh_tools()
    registry = ToolRegistry()
    _apply_mcp_tools(registry, [client])
    assert registry.to_anthropic()
    descriptor = spec(inputSchema={"type": "object", "properties": {"write": {"type": "boolean"}}})
    await client.refresh_tools()
    assert registry.to_anthropic() == []
    assert registry.deferred_tools() == []
    assert "stale" in await registry.run("mcp_catalog__one", {})
    with pytest.raises(KeyError):
        registry.get("mcp_catalog__one")
    await client.stop()


@pytest.mark.asyncio
async def test_permission_revoked_during_stdio_write_lock_never_dispatches():
    async def listing(method, params):
        return {"tools": [spec()]}

    client = MCPClient(MCPServerSpec("catalog", command="fake"))
    client.catalog = ToolCatalog(listing)
    await client.refresh_tools()
    peer = StdioPeer(lambda request: {"id": request["id"], "result": {}})
    client._proc = peer
    registry = ToolRegistry()
    _apply_mcp_tools(registry, [client])
    await client._lock.acquire()
    call = asyncio.create_task(registry.run("mcp_catalog__one", {}))
    await asyncio.sleep(0.03)
    assert not call.done()
    registry.set_acl(denied={"mcp_catalog__one"})
    client._lock.release()
    assert "no longer authorized" in await call
    assert peer.requests == [] and not client._pending
    await client.stop()


@pytest.mark.asyncio
async def test_stdio_notification_refreshes_and_stop_cancels_owned_loader():
    client = MCPClient(MCPServerSpec("catalog", command="fake"))
    entered, closed = asyncio.Event(), asyncio.Event()

    async def listing(method, params):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            closed.set()

    client.catalog = ToolCatalog(listing)
    client._dispatch({"method": "notifications/tools/list_changed"})
    await entered.wait()
    await client.stop()
    assert closed.is_set() and client.catalog.status["stale"]


@pytest.mark.asyncio
async def test_http_interleaved_notification_triggers_same_loader(monkeypatch):
    lists = 0
    real = httpx.AsyncClient

    def respond(request):
        nonlocal lists
        body = json.loads(request.content)
        if "id" not in body:
            return httpx.Response(202)
        if body["method"] == "tools/list":
            lists += 1
            result = {"tools": [spec("one" if lists == 1 else "two")]}
        elif body["method"] == "tools/call":
            notice = {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}
            response = {"jsonrpc": "2.0", "id": body["id"], "result": {"content": [{"type": "text", "text": "ok"}]}}
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, text=f"data: {json.dumps(notice)}\n\ndata: {json.dumps(response)}\n\n")
        else:
            result = {}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: real(transport=httpx.MockTransport(respond), **kwargs))
    client = StreamableHttpMCPClient(MCPServerSpec("catalog", url="http://localhost/mcp"))
    await client.start()
    try:
        assert await client.call_tool("one", {}) == "ok"
        await client.refresh_tools()
        assert lists == 2 and [s["name"] for s in client.tools] == ["two"]
    finally:
        await client.stop()


@pytest.mark.asyncio
async def test_repeated_changes_share_total_page_budget_and_keep_last_good():
    requests = 0
    changing = False

    async def listing(method, params):
        nonlocal requests
        requests += 1
        if changing:
            catalog.changed()
        return {"tools": [spec()]}

    catalog = ToolCatalog(listing, limits=replace(CatalogLimits(), pages=1))
    await catalog.refresh()
    before = catalog.generation
    changing = True
    with pytest.raises(CatalogError, match="page limit"):
        await catalog.refresh()
    assert requests == 2 and catalog.generation is before and catalog.stale
    await catalog.close()


@pytest.mark.asyncio
async def test_catalog_timeout_cleans_pending_request_blocked_in_stdio_drain():
    client = MCPClient(MCPServerSpec("catalog", command="fake"), timeout=0.03)
    peer = StdioPeer(lambda request: {"id": request["id"], "result": {"tools": [spec()]}})
    waiting = asyncio.Event()

    async def blocked_drain():
        waiting.set()
        await asyncio.Event().wait()

    peer.drain = blocked_drain
    client._proc = peer
    with pytest.raises(CatalogError, match="TimeoutError"):
        await client.refresh_tools()
    assert waiting.is_set() and not client._pending
    await client.stop()


@pytest.mark.asyncio
async def test_refresh_during_shield_scan_cannot_pair_old_metadata_with_new_identity(monkeypatch):
    import maverick.mcp_tools as module

    current = spec()

    async def listing(method, params):
        return {"tools": [current]}

    client = MCPClient(MCPServerSpec("catalog", command="fake"))
    client.catalog = ToolCatalog(listing)
    await client.refresh_tools()
    old = client.catalog.generation
    current = spec(description="Changed metadata")
    await client.refresh_tools()
    new = client.catalog.generation
    client.catalog.generation = old

    class Shield:
        def scan_input(self, payload):
            client.catalog.generation = new
            return SimpleNamespace(allowed=True)

    monkeypatch.setattr(module, "_try_shield", lambda: Shield())
    registry = ToolRegistry()
    _apply_mcp_tools(registry, [client])
    assert registry.all() == []
    await client.stop()
