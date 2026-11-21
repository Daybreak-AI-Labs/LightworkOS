"""The provider connection test reaches a hosted provider the way real AI calls do.

The probe used an anti-SSRF helper that connects directly, while the provider
SDKs honour HTTPS_PROXY. Behind a mandatory proxy the test failed ("the service
did not accept the key"), the provider read as failed and the composer refused
every task, although real calls would have worked.
"""
from types import SimpleNamespace

import httpx
import pytest
from maverick_dashboard import integration_readiness as readiness


def _record(monkeypatch):
    calls = {}

    def fake_get(url, **kwargs):
        calls["httpx"] = (url, kwargs)
        return SimpleNamespace(status_code=200)

    def fake_safe_get(url, **kwargs):
        calls["safe_get"] = (url, kwargs)
        return SimpleNamespace(status_code=200)

    monkeypatch.setattr(httpx, "get", fake_get)
    from maverick.tools import _ssrf
    monkeypatch.setattr(_ssrf, "safe_get", fake_safe_get)
    return calls


@pytest.fixture(autouse=True)
def _no_host_proxy(monkeypatch):
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy",
                 "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)


def test_a_hosted_provider_is_tested_through_the_configured_proxy(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.corp.example:3128")
    calls = _record(monkeypatch)
    result = readiness.probe_provider("openai", {"api_key": "sk-test"})  # pragma: allowlist secret
    assert result["verified"] is True
    url, kwargs = calls["httpx"]
    assert url == "https://api.openai.com/v1/models"
    assert kwargs["proxy"] == "http://proxy.corp.example:3128"
    # trust_env as the SDKs do, so a TLS-inspecting proxy's CA (SSL_CERT_FILE) is trusted.
    assert kwargs["follow_redirects"] is False and kwargs["trust_env"] is True
    assert kwargs["headers"] == {"Authorization": "Bearer sk-test"}  # pragma: allowlist secret
    assert "safe_get" not in calls


def test_without_a_proxy_the_direct_pinned_probe_is_kept(monkeypatch):
    calls = _record(monkeypatch)
    readiness.probe_provider("openai", {"api_key": "sk-test"})  # pragma: allowlist secret
    assert calls["safe_get"][0] == "https://api.openai.com/v1/models"
    assert "httpx" not in calls


def test_a_host_excluded_from_the_proxy_is_probed_directly(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.corp.example:3128")
    monkeypatch.setenv("NO_PROXY", "api.openai.com")
    calls = _record(monkeypatch)
    readiness.probe_provider("openai", {"api_key": "sk-test"})  # pragma: allowlist secret
    assert "safe_get" in calls and "httpx" not in calls


def test_an_operator_supplied_address_keeps_the_pinned_probe(monkeypatch):
    # Only the built-in public endpoints go through the proxy; a custom address
    # keeps the anti-SSRF checks.
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.corp.example:3128")
    calls = _record(monkeypatch)
    readiness.probe_provider("openai", {"api_key": "sk-test", "base_url": "https://gateway.example/v1"})  # pragma: allowlist secret
    assert calls["safe_get"][0] == "https://gateway.example/v1/models"
    assert "httpx" not in calls


def test_the_outbound_policy_still_applies_through_the_proxy(monkeypatch):
    from maverick import egress_guard

    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.corp.example:3128")
    monkeypatch.setattr(egress_guard, "_denied", lambda url: "outbound connections are locked")
    calls = _record(monkeypatch)
    result = readiness.probe_provider("openai", {"api_key": "sk-test"})  # pragma: allowlist secret
    assert result["verified"] is False
    assert result["evidence"]["blocked_by_egress_policy"] is True
    assert calls == {}
