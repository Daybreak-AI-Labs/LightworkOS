"""Streaming owners check the live policy before network-capable dispatch."""
import httpx
import pytest
from maverick.enterprise import EgressBlocked
from maverick.mcp_client import MCPClientError, MCPServerSpec, StreamableHttpMCPClient
from maverick.model_proxy import ProxyConfig
from maverick.model_proxy_stream import forward_stream


class NetworkLikeMock(httpx.MockTransport):
    """Custom transports are not eligible for the exact-type in-process exemption."""


def _deny(url):
    raise EgressBlocked("policy denies this destination")


@pytest.mark.asyncio
async def test_mcp_stream_denial_precedes_dispatch_and_keeps_client_owned(monkeypatch):
    calls = []
    monkeypatch.setattr("maverick.egress_guard._check", _deny)
    transport = NetworkLikeMock(lambda request: calls.append(request) or httpx.Response(200))
    client = httpx.AsyncClient(transport=transport)
    mcp = StreamableHttpMCPClient(MCPServerSpec(name="fixture", url="https://example.com/mcp"))
    mcp._client = client
    try:
        with pytest.raises(MCPClientError, match="policy denies"):
            await mcp._post({"method": "tools/list"}, req_id=1)
        assert calls == []
        assert not client.is_closed
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_proxy_stream_denial_precedes_dispatch_and_preserves_client_owner(monkeypatch):
    calls = []
    monkeypatch.setattr("maverick.egress_guard._check", _deny)
    transport = NetworkLikeMock(lambda request: calls.append(request) or httpx.Response(200))
    client = httpx.AsyncClient(transport=transport)
    config = ProxyConfig(upstream="https://example.com", api_key="fixture")
    try:
        with pytest.raises(EgressBlocked):
            async with forward_stream(config, client, "POST", "/v1/messages", {}, b"{}"):
                pytest.fail("denied request must not enter its response stream")
        assert calls == []
        assert not client.is_closed
    finally:
        await client.aclose()
