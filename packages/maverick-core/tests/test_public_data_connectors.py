"""Primary-source / public-reference data connectors and the auth modes that
make them possible.

These are GET-only, LOW-risk connectors over authoritative government and public
data APIs (SEC EDGAR, FRED, World Bank, openFDA, weather.gov, ...). They ground
the analyst-style packs in primary sources. This locks in:

* the three new ``make_rest_tool`` auth modes -- ``keyless`` (no credential),
  ``query_auth`` (key on the query string, not a header), and
  ``default_base_url`` (zero-config fixed public host);
* the batch's invariants: every public-data connector is read-only (GET-only)
  and LOW risk, and none leak the credential into a header it shouldn't.
"""
from __future__ import annotations

import contextlib

import httpx
import pytest
from maverick.safety.tool_risk import tool_risk
from maverick.tools._rest_connector import make_rest_tool
from maverick.tools.enterprise_connectors import (
    ENTERPRISE_CONNECTOR_NAMES,
    PUBLIC_DATA_CONNECTOR_NAMES,
    READ_CONNECTOR_NAMES,
    enterprise_connectors,
)


def _tools() -> dict:
    return {t.name: t for t in enterprise_connectors()}


# --- captured-request harness (no network) ----------------------------------

@pytest.fixture()
def capture(monkeypatch):
    """Patch the SSRF-safe client + egress gate; capture the outbound request."""
    seen: dict = {}

    class _Client:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        @contextlib.contextmanager
        def stream(self, method, url, headers=None, params=None, json=None):
            seen.update(method=method, url=url, headers=headers or {},
                        params=params or {}, json=json)
            with contextlib.closing(httpx.Response(200, headers={"content-type": "application/json"},
                                                  stream=httpx.ByteStream(b'{"ok": true}'))) as response:
                yield response

    @contextlib.contextmanager
    def _safe_client(url, **kwargs):
        yield _Client()

    import maverick.enterprise as ent
    import maverick.tools._ssrf as ssrf
    monkeypatch.setattr(ssrf, "safe_client", _safe_client)
    monkeypatch.setattr(ent, "enterprise_egress_denial", lambda url, tool=None: None)
    return seen


# --- the three auth modes ---------------------------------------------------

def test_keyless_needs_no_credential_and_sends_no_auth_header(capture):
    t = make_rest_tool(
        name="kl", base_url_env="KL_BASE_URL", token_env="KL_API_KEY",
        keyless=True, read_only=True, default_base_url="https://data.example.gov",
        description="x")
    out = t.fn({"op": "get", "path": "/v1/thing"})
    assert not out.startswith("ERROR"), out
    assert capture["url"] == "https://data.example.gov/v1/thing"
    assert "Authorization" not in capture["headers"]


def test_query_auth_puts_key_on_query_string_not_header(monkeypatch, capture):
    monkeypatch.setenv("QA_API_KEY", "SECRET123")
    t = make_rest_tool(
        name="qa", base_url_env="QA_BASE_URL", token_env="QA_API_KEY",
        query_auth="api_key", read_only=True,
        default_base_url="https://api.example.gov", description="x")
    out = t.fn({"op": "get", "path": "/series", "params": {"id": "GDP"}})
    assert not out.startswith("ERROR"), out
    assert capture["params"].get("api_key") == "SECRET123"
    assert capture["params"].get("id") == "GDP"
    assert "Authorization" not in capture["headers"]


def test_query_auth_missing_key_fails_loudly(monkeypatch):
    monkeypatch.delenv("QA2_API_KEY", raising=False)
    t = make_rest_tool(
        name="qa2", base_url_env="QA2_BASE_URL", token_env="QA2_API_KEY",
        query_auth="api_key", read_only=True,
        default_base_url="https://api.example.gov", description="x")
    out = t.fn({"op": "get", "path": "/series"})
    assert out.startswith("ERROR") and "QA2_API_KEY" in out


def test_default_base_url_overridable_by_env(monkeypatch, capture):
    monkeypatch.setenv("OV_BASE_URL", "https://onprem.internal.example")
    t = make_rest_tool(
        name="ov", base_url_env="OV_BASE_URL", token_env="OV_API_KEY",
        keyless=True, read_only=True, default_base_url="https://public.example.gov",
        description="x")
    t.fn({"op": "get", "path": "/x"})
    assert capture["url"].startswith("https://onprem.internal.example")


def test_standard_header_auth_path_is_unchanged():
    # No keyless/query_auth/default_base_url -> the original strict env contract.
    t = make_rest_tool(name="plain", base_url_env="PLAIN_BASE_URL",
                       token_env="PLAIN_TOKEN", description="x")
    out = t.fn({"op": "get", "path": "/x"})
    assert out.startswith("ERROR") and "PLAIN_BASE_URL + PLAIN_TOKEN" in out


# --- the public-data batch invariants ---------------------------------------

def test_public_data_batch_is_present_and_read_only_low():
    tools = _tools()
    assert len(PUBLIC_DATA_CONNECTOR_NAMES) >= 30
    for name in PUBLIC_DATA_CONNECTOR_NAMES:
        assert name in tools, name
        assert name in READ_CONNECTOR_NAMES
        # not in the write long-tail; GET-only; LOW risk (passes a read-only ceiling)
        assert name not in ENTERPRISE_CONNECTOR_NAMES, name
        assert tools[name].input_schema["properties"]["op"]["enum"] == ["get"], name
        assert tool_risk(name) == "low", name


def test_sec_edgar_works_with_zero_config(capture):
    # keyless + default_base_url -> usable out of the box, no env at all.
    out = _tools()["sec_edgar"].fn(
        {"op": "get", "path": "/submissions/CIK0000320193.json"})
    assert not out.startswith("ERROR"), out
    assert capture["url"].startswith("https://data.sec.gov/")
    assert "Authorization" not in capture["headers"]


def test_finnhub_uses_its_custom_token_header(monkeypatch, capture):
    monkeypatch.setenv("FINNHUB_API_KEY", "fh_key")
    _tools()["finnhub"].fn({"op": "get", "path": "/api/v1/quote", "params": {"symbol": "AAPL"}})
    assert capture["headers"].get("X-Finnhub-Token") == "fh_key"
    assert "api_key" not in capture["params"]


def test_rest_connector_honors_capability_host_scope(capture):
    t = make_rest_tool(
        name="scoped", base_url_env="SCOPED_BASE_URL", token_env="SCOPED_API_KEY",
        keyless=True, read_only=True, default_base_url="https://data.example.gov",
        description="x")
    out = t.fn({
        "op": "get",
        "path": "/v1/thing",
        "_capability_allow_hosts": ("*.moderntreasury.com",),
    })
    assert out.startswith("ERROR:"), out
    assert "capability policy" in out
    assert "data.example.gov" in out
    assert "url" not in capture


def test_rest_connector_allows_capability_scoped_host(capture):
    t = make_rest_tool(
        name="scoped_ok", base_url_env="SCOPED_OK_BASE_URL", token_env="SCOPED_OK_API_KEY",
        keyless=True, read_only=True, default_base_url="https://data.example.gov",
        description="x")
    out = t.fn({
        "op": "get",
        "path": "/v1/thing",
        "_capability_allow_hosts": ("*.example.gov",),
    })
    assert not out.startswith("ERROR"), out
    assert capture["url"] == "https://data.example.gov/v1/thing"
