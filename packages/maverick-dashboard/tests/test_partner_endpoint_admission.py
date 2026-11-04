"""Partner Fleet endpoints are admitted before any server-side secret can use them."""
from __future__ import annotations

import socket

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated_partner_registry(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    monkeypatch.delenv(
        "MAVERICK_PARTNER_ALLOW_TEST_ESTATE_LOOPBACK", raising=False
    )
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import config
    from maverick.tenant import kms

    config.reset_config_cache()
    kms._dek_cache.clear()
    yield
    kms._dek_cache.clear()
    config.reset_config_cache()


def _address_info(*addresses: str):
    rows = []
    for address in addresses:
        if ":" in address:
            rows.append(
                (
                    socket.AF_INET6,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    (address, 0, 0, 0),
                )
            )
        else:
            rows.append(
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    (address, 0),
                )
            )
    return rows


def _post(base_url: str, **extra):
    return client.post(
        "/api/v1/partner/tenants",
        json={"name": "Test estate", "base_url": base_url, **extra},
    )


@pytest.mark.parametrize(
    ("base_url", "resolved_address"),
    [
        ("http://127.0.0.1:9000", "127.0.0.1"),
        ("http://10.20.30.40", "10.20.30.40"),
        ("http://169.254.169.254", "169.254.169.254"),
        ("http://[::1]:9000", "::1"),
        ("http://[fe80::1]", "fe80::1"),
    ],
)
def test_partner_save_rejects_non_public_endpoints_by_default(
    monkeypatch, base_url, resolved_address
):
    from maverick.tools import _ssrf

    monkeypatch.setattr(
        _ssrf.socket,
        "getaddrinfo",
        lambda _host, _port: _address_info(resolved_address),
    )

    response = _post(base_url)

    assert response.status_code == 400, response.text
    assert "not admitted" in response.json()["detail"]


def test_partner_save_rejects_mixed_public_private_dns_answer(monkeypatch):
    from maverick.tools import _ssrf

    monkeypatch.setattr(
        _ssrf.socket,
        "getaddrinfo",
        lambda _host, _port: _address_info("93.184.216.34", "127.0.0.1"),
    )

    response = _post("https://partner.example")

    assert response.status_code == 400, response.text
    assert "not admitted" in response.json()["detail"]


def test_trusted_test_estate_exception_cannot_authorize_a_hostname(monkeypatch):
    from maverick.tools import _ssrf

    monkeypatch.setenv("MAVERICK_PARTNER_ALLOW_TEST_ESTATE_LOOPBACK", "1")

    def should_not_resolve(_host, _port):
        raise AssertionError("a trusted-test hostname must be rejected before DNS")

    monkeypatch.setattr(_ssrf.socket, "getaddrinfo", should_not_resolve)

    response = _post(
        "http://localhost:9000", trusted_test_estate_loopback=True
    )

    assert response.status_code == 400, response.text
    assert "not admitted" in response.json()["detail"]


def test_trusted_test_estate_exception_is_limited_to_exact_loopback(monkeypatch):
    from maverick.tools import _ssrf

    monkeypatch.setenv("MAVERICK_PARTNER_ALLOW_TEST_ESTATE_LOOPBACK", "1")

    monkeypatch.setattr(
        _ssrf.socket,
        "getaddrinfo",
        lambda _host, _port: _address_info("10.20.30.40"),
    )

    private_response = _post(
        "http://10.20.30.40", trusted_test_estate_loopback=True
    )

    assert private_response.status_code == 400, private_response.text


@pytest.mark.parametrize(
    ("base_url", "resolved_address"),
    [
        ("http://127.0.0.1:9000", "127.0.0.1"),
        ("http://[::1]:9000", "::1"),
    ],
)
def test_trusted_test_estate_exception_admits_exact_loopback_literal(
    monkeypatch, base_url, resolved_address
):
    from maverick.tools import _ssrf

    monkeypatch.setenv("MAVERICK_PARTNER_ALLOW_TEST_ESTATE_LOOPBACK", "1")

    monkeypatch.setattr(
        _ssrf.socket,
        "getaddrinfo",
        lambda _host, _port: _address_info(resolved_address),
    )

    response = _post(base_url, trusted_test_estate_loopback=True)

    assert response.status_code == 201, response.text
    assert response.json()["trusted_test_estate_loopback"] is True


def test_loopback_request_cannot_enable_operator_policy(monkeypatch):
    from maverick.tools import _ssrf
    from maverick_dashboard import partner_store

    monkeypatch.setattr(
        _ssrf.socket,
        "getaddrinfo",
        lambda _host, _port: _address_info("127.0.0.1"),
    )

    response = _post(
        "http://127.0.0.1:9000", trusted_test_estate_loopback=True
    )

    assert response.status_code == 403, response.text
    assert partner_store.list_tenants() == []


def test_revoked_loopback_policy_blocks_every_live_probe_before_network(monkeypatch):
    from maverick.tools import _ssrf

    monkeypatch.setenv("MAVERICK_PARTNER_ALLOW_TEST_ESTATE_LOOPBACK", "1")
    monkeypatch.setattr(
        _ssrf.socket,
        "getaddrinfo",
        lambda _host, _port: _address_info("127.0.0.1"),
    )
    enrolled = _post(
        "http://127.0.0.1:9000", trusted_test_estate_loopback=True
    )
    assert enrolled.status_code == 201, enrolled.text
    tenant_id = enrolled.json()["id"]

    monkeypatch.delenv("MAVERICK_PARTNER_ALLOW_TEST_ESTATE_LOOPBACK")

    def network_must_not_run(*_args, **_kwargs):
        raise AssertionError("revoked loopback policy reached the network")

    monkeypatch.setattr(_ssrf, "safe_get", network_must_not_run)

    check = client.post(f"/api/v1/partner/tenants/{tenant_id}/check")
    fleet = client.get("/api/v1/partner/fleet", params={"check": "1"})

    assert check.status_code == 403, check.text
    assert fleet.status_code == 403, fleet.text
    assert "disabled by operator policy" in check.json()["detail"]
    assert "disabled by operator policy" in fleet.json()["detail"]


def test_partner_save_preserves_valid_public_https_path(monkeypatch):
    from maverick.tools import _ssrf

    monkeypatch.setattr(
        _ssrf.socket,
        "getaddrinfo",
        lambda _host, _port: _address_info("93.184.216.34"),
    )

    response = _post("https://partner.example/")

    assert response.status_code == 201, response.text
    assert response.json()["base_url"] == "https://partner.example"
    assert response.json()["trusted_test_estate_loopback"] is False


def test_rejected_update_does_not_mutate_existing_partner(monkeypatch):
    from maverick.tools import _ssrf
    from maverick_dashboard import partner_store

    def resolve_for_host(host, _port):
        address = "93.184.216.34" if host == "partner.example" else "127.0.0.1"
        return _address_info(address)

    monkeypatch.setattr(_ssrf.socket, "getaddrinfo", resolve_for_host)
    existing = partner_store.upsert_tenant(
        name="Original", base_url="https://partner.example", token="old-token"
    )

    with pytest.raises(partner_store.PartnerEndpointRejected, match="not admitted"):
        partner_store.upsert_tenant(
            tenant_id=existing["id"],
            name="Mutated",
            base_url="http://127.0.0.1:9000",
            token="new-token",
        )

    persisted = partner_store.list_tenants()[0]
    assert persisted["name"] == "Original"
    assert persisted["base_url"] == "https://partner.example"
    assert persisted["token"] == "old-token"
