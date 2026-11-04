from __future__ import annotations

import json
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import HTTPException
from fastapi.testclient import TestClient
from maverick import agent_trust, ai_discovery_sensors, config
from maverick.ai_discovery_sensor_clients import (
    SensorBinding,
    SignedDiscoverySensorClient,
    normalize_network_egress,
)
from maverick.paths import tenant_scope
from maverick_dashboard import external_gateway
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1")

_TENANT = "tenant-a"
_AGENT_ID = "network-sensor"
_CONFIG_SHA = "b" * 64
_EVENT_SHA = "a" * 64


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text(
        "[ai_discovery_sensors]\nenable = true\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(external_gateway, "_rate_times", {})
    config.reset_config_cache()
    from maverick.tenant.registry import create_tenant
    create_tenant(_TENANT)
    yield
    config.reset_config_cache()


def _keypair():
    private = ed25519.Ed25519PrivateKey.generate()
    public_hex = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()
    return private, public_hex


def _provision(
    private,
    public_hex: str,
    *,
    tenant: str = _TENANT,
    agent_id: str = _AGENT_ID,
    allow_sensor: bool = True,
    sensor_type: str = "network_egress",
):
    from maverick.tenant.registry import create_tenant, get_tenant
    if get_tenant(tenant) is None:
        create_tenant(tenant)
    with tenant_scope(tenant=tenant):
        service = ai_discovery_sensors.default_service()
        sensor = service.register_sensor(
            sensor_name=agent_id,
            sensor_type=sensor_type,
            config_sha256=_CONFIG_SHA,
            actor=ai_discovery_sensors.SensorActor("user:preparer"),
        )
        sensor = service.approve_sensor(
            sensor["sensor_id"],
            expected_revision=sensor["revision"],
            actor=ai_discovery_sensors.SensorActor("user:approver"),
        )
        agent_trust.put_agent(
            {
                "id": agent_id,
                "pubkey": public_hex,
                "direction": "inbound",
                "allow_tools": (
                    ["ai_discovery_observation"] if allow_sensor else ["screen"]
                ),
            }
        )
    return sensor


def _request(private, sensor: dict, *, tenant: str = _TENANT, nonce: str = "nonce-1"):
    event = normalize_network_egress(
        hostname="api.openai.com",
        source_event_sha256=_EVENT_SHA,
        observed_at=time.time(),
        environment_code="production",
        context_codes=("managed_device",),
    )
    assert event is not None
    return SignedDiscoverySensorClient(
        SensorBinding(
            tenant_ref=tenant,
            agent_id=_AGENT_ID,
            sensor_id=sensor["sensor_id"],
            sensor_revision=sensor["sensor_revision"],
            config_sha256=sensor["config_sha256"],
        ),
        signer=private.sign,
        nonce_factory=lambda: nonce,
    ).build(event)


def test_signed_machine_sensor_ingress_roundtrip_and_replay_refusal() -> None:
    private, public_hex = _keypair()
    sensor = _provision(private, public_hex)
    request = _request(private, sensor)

    first = client.post(request.path, headers=request.headers, content=request.body)
    assert first.status_code == 201, first.text
    response = first.json()
    assert response["machine_authenticated"] is True
    assert response["sensor_agent_id"] == _AGENT_ID
    assert response["observation"]["event_sha256"] == _EVENT_SHA
    assert (
        response["observation"]["sensor_binding"]["sensor_id"]
        == sensor["sensor_id"]
    )

    replay = client.post(request.path, headers=request.headers, content=request.body)
    assert replay.status_code == 401
    assert replay.json()["detail"] == "invalid credentials"
    with tenant_scope(tenant=_TENANT):
        assert len(ai_discovery_sensors.default_service().list_observations()) == 1


def test_unknown_tenant_cannot_create_namespace_claims(tmp_path):
    claims = tmp_path / ".tenant-namespaces"
    before = set(claims.rglob("*.json")) if claims.exists() else set()
    for index in range(10):
        response = client.post(
            f"/api/v1/external/discovery-sensors/DSN-{'c' * 32}/observations",
            json={"tenant_ref": f"unknown-{index}"},
        )
        assert response.status_code == 401
    after = set(claims.rglob("*.json")) if claims.exists() else set()
    assert after == before


def test_legacy_implicit_tenant_is_admitted_without_creating_a_claim(tmp_path, monkeypatch):
    from maverick.tenant import registry

    registry._registry_path().unlink()
    monkeypatch.setenv("MAVERICK_TENANT", "legacy")
    claims = tmp_path / ".tenant-namespaces"
    before = set(claims.rglob("*.json")) if claims.exists() else set()
    external_gateway._require_registered_external_tenant("legacy")
    with pytest.raises(HTTPException):
        external_gateway._require_registered_external_tenant("other")
    after = set(claims.rglob("*.json")) if claims.exists() else set()
    assert after == before


def test_machine_sensor_requires_explicit_sensor_capability() -> None:
    private, public_hex = _keypair()
    sensor = _provision(private, public_hex, allow_sensor=False)
    request = _request(private, sensor)

    response = client.post(
        request.path,
        headers=request.headers,
        content=request.body,
    )
    assert response.status_code == 401
    with tenant_scope(tenant=_TENANT):
        assert ai_discovery_sensors.default_service().list_observations() == []


def test_machine_sensor_identity_must_equal_approved_sensor_name() -> None:
    private, public_hex = _keypair()
    sensor = _provision(
        private,
        public_hex,
        agent_id="approved-sensor",
    )
    with tenant_scope(tenant=_TENANT):
        agent_trust.put_agent(
            {
                "id": _AGENT_ID,
                "pubkey": public_hex,
                "direction": "inbound",
                "allow_tools": ["ai_discovery_observation"],
            }
        )
    request = _request(private, sensor)

    response = client.post(
        request.path,
        headers=request.headers,
        content=request.body,
    )
    assert response.status_code == 403
    assert "not authorized" in response.json()["detail"]


def test_machine_sensor_rejects_cross_tenant_body_even_with_valid_other_key() -> None:
    private, public_hex = _keypair()
    sensor = _provision(private, public_hex)
    request = _request(private, sensor)
    payload = json.loads(request.body)
    payload["tenant_ref"] = "tenant-b"
    changed_body = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    response = client.post(
        request.path,
        headers=request.headers,
        content=changed_body,
    )
    assert response.status_code == 401
    with tenant_scope(tenant=_TENANT):
        assert ai_discovery_sensors.default_service().list_observations() == []


def test_machine_sensor_requires_exact_active_configuration() -> None:
    private, public_hex = _keypair()
    sensor = _provision(private, public_hex)
    request = _request(private, sensor, nonce="nonce-config")
    payload = json.loads(request.body)
    payload["config_sha256"] = "c" * 64
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    from maverick.external_identity import envelope_message

    timestamp = str(int(time.time()))
    nonce = "nonce-config-changed"
    signature = private.sign(
        envelope_message(_AGENT_ID, timestamp, nonce, body)
    ).hex()
    headers = {
        "Content-Type": "application/json",
        "X-Lightwork-Agent-Id": _AGENT_ID,
        "X-Maverick-Timestamp": timestamp,
        "X-Lightwork-Nonce": nonce,
        "X-Lightwork-Request-Signature": signature,
    }

    response = client.post(request.path, headers=headers, content=body)
    assert response.status_code == 409
    assert "exact approved sensor configuration" in response.json()["detail"]


def test_machine_sensor_refuses_bearer_fallback_and_oversize_body() -> None:
    response = client.post(
        f"/api/v1/external/discovery-sensors/DSN-{'c' * 32}/observations",
        headers={"Authorization": "Bearer not-accepted"},
        json={"tenant_ref": _TENANT},
    )
    assert response.status_code == 401

    response = client.post(
        f"/api/v1/external/discovery-sensors/DSN-{'c' * 32}/observations",
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(65 * 1024),
        },
        content=b"{}",
    )
    assert response.status_code == 413


def test_machine_sensor_route_is_inert_while_feature_disabled(tmp_path) -> None:
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()

    response = client.post(
        f"/api/v1/external/discovery-sensors/DSN-{'c' * 32}/observations",
        json={"tenant_ref": _TENANT},
    )
    assert response.status_code == 404
