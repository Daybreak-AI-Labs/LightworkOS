"""Connector auth header helpers."""
from __future__ import annotations


def test_auth_headers_for_can_omit_environment_backed_auxiliary_secrets(monkeypatch):
    from maverick.tools.enterprise_connectors import auth_headers_for

    monkeypatch.setenv("CCH_AXCESS_SUBSCRIPTION_KEY", "operator-secret")

    headers = auth_headers_for(
        "cch_axcess", "saved-token", include_extra_headers_env=False,
    )

    assert headers["Authorization"] == "Bearer saved-token"
    assert "Ocp-Apim-Subscription-Key" not in headers


def test_auth_headers_for_keeps_environment_headers_for_trusted_connector_calls(monkeypatch):
    from maverick.tools.enterprise_connectors import auth_headers_for

    monkeypatch.setenv("CCH_AXCESS_SUBSCRIPTION_KEY", "operator-secret")

    headers = auth_headers_for("cch_axcess", "saved-token")

    assert headers["Ocp-Apim-Subscription-Key"] == "operator-secret"
