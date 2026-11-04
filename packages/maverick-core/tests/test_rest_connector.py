"""Tests for the REST and GraphQL connector factory (maverick.tools._rest_connector)."""
from __future__ import annotations

import pytest

# --- REST + GraphQL connectors pin the host IP --------------------

@pytest.fixture(autouse=True)
def _no_allow_private(monkeypatch):
    # The SSRF guard honours MAVERICK_FETCH_ALLOW_PRIVATE=1 (on-prem opt-in);
    # make sure these tests run with the guard armed regardless of host env.
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)


def test_rest_connector_blocks_private_host(monkeypatch):
    from maverick.tools._rest_connector import make_rest_tool
    # A literal link-local IP avoids any DNS lookup: getaddrinfo returns it
    # verbatim and the guard rejects it as non-public (cloud metadata range).
    monkeypatch.setenv("RB_BASE", "http://169.254.169.254")
    monkeypatch.setenv("RB_TOKEN", "secret-bearer")  # pragma: allowlist secret
    tool = make_rest_tool(
        name="rb", base_url_env="RB_BASE", token_env="RB_TOKEN",
        description="test connector",
    )
    out = tool.fn({"op": "get", "path": "/latest/meta-data/"})
    assert "blocked host (SSRF guard)" in out
    # The bearer token must not leak into the error surface.
    assert "secret-bearer" not in out


def test_graphql_connector_blocks_private_host(monkeypatch):
    from maverick.tools._rest_connector import make_graphql_tool
    monkeypatch.setenv("GB_BASE", "http://169.254.169.254/graphql")
    monkeypatch.setenv("GB_TOKEN", "secret-bearer")  # pragma: allowlist secret
    tool = make_graphql_tool(
        name="gb", base_url_env="GB_BASE", token_env="GB_TOKEN",
        description="test graphql connector",
    )
    out = tool.fn({"query": "{ viewer { id } }"})
    assert "blocked host (SSRF guard)" in out
    assert "secret-bearer" not in out


# --- GraphQL connector honours the enterprise tool-egress lock ---------------

def test_graphql_connector_egress_blocked_under_enterprise(monkeypatch):
    monkeypatch.delenv("MAVERICK_ENTERPRISE", raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    monkeypatch.setenv("ACME_GQL_URL", "https://acme.invalid/graphql")
    monkeypatch.setenv("ACME_GQL_TOKEN", "tok")
    from maverick.tools._rest_connector import make_graphql_tool
    tool = make_graphql_tool(name="acmegql", base_url_env="ACME_GQL_URL",
                             token_env="ACME_GQL_TOKEN", description="x")

    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    out = tool.fn({"query": "{ me { id } }"})
    assert out.startswith("ERROR:") and "enterprise mode" in out
