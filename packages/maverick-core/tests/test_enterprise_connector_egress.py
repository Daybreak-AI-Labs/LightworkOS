"""The enterprise tool-egress lock also covers REST connectors and MCP-HTTP,
not just http_fetch / web_search."""
from __future__ import annotations

import asyncio

import pytest


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for v in ("MAVERICK_ENTERPRISE", "ACME_URL", "ACME_TOKEN"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})


def _acme_tool(monkeypatch, base):
    monkeypatch.setenv("ACME_URL", base)
    monkeypatch.setenv("ACME_TOKEN", "tok")
    from maverick.tools._rest_connector import make_rest_tool
    return make_rest_tool(name="acme", base_url_env="ACME_URL",
                          token_env="ACME_TOKEN", description="x")


def test_connector_egress_blocked_under_enterprise(monkeypatch):
    tool = _acme_tool(monkeypatch, "https://acme.invalid")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    out = tool.fn({"op": "get", "path": "/tickets"})
    assert out.startswith("ERROR:") and "enterprise mode" in out
    assert "acme.invalid" in out


def test_connector_allowed_when_host_allow_listed(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"enterprise": {"allowed_hosts": ["acme.invalid"]}},
    )
    tool = _acme_tool(monkeypatch, "https://acme.invalid")
    out = tool.fn({"op": "get", "path": "/x"})
    # Past the egress gate -> it attempts the request (and fails to connect), so
    # the error is the connection failure, NOT the enterprise denial.
    assert "enterprise mode" not in out


def test_connector_egress_noop_when_enterprise_off(monkeypatch):
    tool = _acme_tool(monkeypatch, "https://acme.invalid")
    out = tool.fn({"op": "get", "path": "/x"})       # enterprise off
    assert "enterprise mode" not in out               # not blocked


def test_mcp_http_egress_blocked_under_enterprise(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    from maverick.mcp_client import (
        MCPClientError,
        MCPServerSpec,
        StreamableHttpMCPClient,
    )
    client = StreamableHttpMCPClient(
        MCPServerSpec(name="remote", url="https://mcp.invalid/rpc"))
    with pytest.raises(MCPClientError) as exc:
        asyncio.run(client.start())                   # refused before connecting
    assert "enterprise mode" in str(exc.value) and "mcp.invalid" in str(exc.value)


def test_mcp_http_allowed_host_passes_the_egress_gate(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"enterprise": {"allowed_hosts": ["mcp.invalid"]}},
    )
    from maverick.mcp_client import MCPServerSpec, StreamableHttpMCPClient
    client = StreamableHttpMCPClient(
        MCPServerSpec(name="remote", url="https://mcp.invalid/rpc"))
    # Allow-listed: past the gate, so any failure is a connection error, not the
    # enterprise egress denial.
    with pytest.raises(Exception) as exc:  # noqa: PT011 - connection error shape varies
        asyncio.run(client.start())
    assert "enterprise mode" not in str(exc.value)
