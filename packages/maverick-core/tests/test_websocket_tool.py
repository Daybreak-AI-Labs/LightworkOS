"""WebSocket tool."""
from __future__ import annotations

import asyncio

import pytest
from maverick.tools.websocket_tool import _check_url, websocket_tool


def test_check_url_rejects_bad_scheme():
    assert "ERROR" in _check_url("http://example.com")
    assert "ERROR" in _check_url("https://example.com")


def test_check_url_accepts_ws():
    assert _check_url("ws://example.com/socket") is None
    assert _check_url("wss://example.com/socket") is None


def test_run_blocks_ssrf_without_dep(monkeypatch):
    # link-local metadata host must be refused before importing websockets
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    out = asyncio.run(websocket_tool().fn({"url": "ws://169.254.169.254/x"}))
    assert "ERROR" in out and "SSRF" in out


def test_run_requires_url():
    out = asyncio.run(websocket_tool().fn({"url": ""}))
    assert out.startswith("ERROR")


def test_receive_roundtrip(monkeypatch):
    websockets = pytest.importorskip("websockets")
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")  # allow loopback

    async def scenario():
        async def handler(ws, *args):
            await ws.send("server message")

        async with websockets.serve(handler, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            return await websocket_tool().fn({"url": f"ws://127.0.0.1:{port}"})

    assert asyncio.run(scenario()) == "server message"


def test_sending_is_refused_before_network(monkeypatch):
    from maverick.tools import websocket_tool as ws_tool
    monkeypatch.setattr(ws_tool, "_safe_connector", lambda: pytest.fail("network reached"))
    result = asyncio.run(ws_tool.websocket_tool().fn({"url": "wss://example.com", "message": "data"}))
    assert "sending is unavailable" in result


@pytest.mark.parametrize("relative", [False, True])
def test_redirect_does_not_contact_destination(monkeypatch, relative):
    pytest.importorskip("websockets.legacy.client")
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")

    async def scenario():
        contacted = []
        attempts = []

        async def target(reader, writer):
            contacted.append(True)
            writer.close()
            await writer.wait_closed()

        target_server = await asyncio.start_server(target, "127.0.0.1", 0)
        target_port = target_server.sockets[0].getsockname()[1]

        async def redirect(reader, writer):
            attempts.append(True)
            await reader.readuntil(b"\r\n\r\n")
            location = "/other" if relative else f"ws://127.0.0.1:{target_port}/private"
            writer.write(f"HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n".encode())
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        first_server = await asyncio.start_server(redirect, "127.0.0.1", 0)
        first_port = first_server.sockets[0].getsockname()[1]
        try:
            result = await websocket_tool().fn({"url": f"ws://127.0.0.1:{first_port}/start", "timeout": 1})
            assert "redirects are not allowed" in result
            assert not contacted
            assert len(attempts) == 1
        finally:
            first_server.close()
            target_server.close()
            await first_server.wait_closed()
            await target_server.wait_closed()

    asyncio.run(scenario())
