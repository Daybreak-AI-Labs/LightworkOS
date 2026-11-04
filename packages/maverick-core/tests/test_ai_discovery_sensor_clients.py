from __future__ import annotations

import hashlib
import json

import pytest
from maverick.ai_discovery_sensor_clients import (
    DiscoverySensorClientError,
    NormalizedSensorEvent,
    SensorBinding,
    SignedDiscoverySensorClient,
    normalize_browser_oauth,
    normalize_identity_audit,
    normalize_network_egress,
    safe_request_digest,
)

_EVENT_SHA = "a" * 64
_CONFIG_SHA = "b" * 64
_SENSOR_ID = "DSN-" + "c" * 32


def _binding(**changes) -> SensorBinding:
    values = {
        "tenant_ref": "tenant-a",
        "agent_id": "network-sensor",
        "sensor_id": _SENSOR_ID,
        "sensor_revision": 2,
        "config_sha256": _CONFIG_SHA,
    }
    values.update(changes)
    return SensorBinding(**values)


def _event(**changes) -> NormalizedSensorEvent:
    values = {
        "event_sha256": _EVENT_SHA,
        "observed_at": 1_700_000_000.0,
        "ai_service_code": "openai",
        "ai_product_code": "openai_api",
        "provider_code": "openai",
        "domain_category": "network_egress",
        "deployment_type": "hosted_api",
        "environment_code": "production",
        "context_codes": ("managed_device",),
    }
    values.update(changes)
    return NormalizedSensorEvent(**values)


def test_network_normalizer_is_boundary_aware_and_drops_raw_host() -> None:
    event = normalize_network_egress(
        hostname="east.api.openai.com",
        source_event_sha256=_EVENT_SHA,
        observed_at=1_700_000_000,
        environment_code="production",
        context_codes=("managed_device",),
    )

    assert event is not None
    assert event.provider_code == "openai"
    assert event.ai_product_code == "openai_api"
    assert "east.api.openai.com" not in repr(event)
    assert (
        normalize_network_egress(
            hostname="api.openai.com.attacker.example",
            source_event_sha256=_EVENT_SHA,
            observed_at=1_700_000_000,
            environment_code="production",
        )
        is None
    )


@pytest.mark.parametrize(
    "hostname",
    [
        "https://api.openai.com/v1/chat",
        "user@api.openai.com",
        "api.openai.com:443",
        "api.openai.com?q=secret",
        "one label",
    ],
)
def test_network_normalizer_refuses_url_identity_or_unbounded_host_data(
    hostname: str,
) -> None:
    with pytest.raises(DiscoverySensorClientError):
        normalize_network_egress(
            hostname=hostname,
            source_event_sha256=_EVENT_SHA,
            observed_at=1_700_000_000,
            environment_code="production",
        )


def test_browser_oauth_normalizer_is_closed_and_sorted() -> None:
    event = normalize_browser_oauth(
        source_event_sha256=_EVENT_SHA,
        observed_at=1_700_000_000,
        provider_code="Microsoft",
        ai_product_code="Copilot",
        environment_code="Workforce",
        oauth_grant=True,
        context_codes=("delegated", "admin_consent"),
    )

    assert event.domain_category == "oauth_grant"
    assert event.provider_code == "microsoft"
    assert event.context_codes == ("admin_consent", "delegated")


def test_identity_audit_normalizer_takes_only_reviewed_codes() -> None:
    event = normalize_identity_audit(
        source_event_sha256=_EVENT_SHA,
        observed_at=1_700_000_000,
        ai_service_code="OpenAI",
        ai_product_code="ChatGPT",
        provider_code="openai",
        environment_code="Workforce",
        context_codes=("managed_device",),
    )

    assert event.domain_category == "identity_directory"
    assert event.deployment_type == "saas"
    assert (event.ai_service_code, event.ai_product_code) == ("openai", "chatgpt")
    assert set(event.__dataclass_fields__) == {
        "event_sha256", "observed_at", "ai_service_code", "ai_product_code",
        "provider_code", "domain_category", "deployment_type", "environment_code",
        "context_codes",
    }
    with pytest.raises(DiscoverySensorClientError, match="provider_code"):
        normalize_identity_audit(
            source_event_sha256=_EVENT_SHA,
            observed_at=1_700_000_000,
            ai_service_code="openai",
            ai_product_code="chatgpt",
            provider_code="raw_url",
            environment_code="workforce",
        )


def test_signed_request_binds_exact_body_identity_tenant_and_nonce() -> None:
    messages: list[bytes] = []

    def signer(message: bytes) -> bytes:
        messages.append(message)
        return b"s" * 64

    client = SignedDiscoverySensorClient(
        _binding(),
        signer=signer,
        clock=lambda: 1_700_000_001.9,
        nonce_factory=lambda: "nonce-1",
    )
    request = client.build(_event())
    payload = json.loads(request.body)

    assert request.path == f"/api/v1/external/discovery-sensors/{_SENSOR_ID}/observations"
    assert payload["tenant_ref"] == "tenant-a"
    assert payload["sensor_revision"] == 2
    assert payload["config_sha256"] == _CONFIG_SHA
    assert payload["context_codes"] == ["managed_device"]
    assert request.headers["X-Lightwork-Agent-Id"] == "network-sensor"
    assert request.headers["X-Lightwork-Nonce"] == "nonce-1"
    assert request.headers["X-Lightwork-Request-Signature"] == (b"s" * 64).hex()
    assert len(messages) == 1
    assert b"tenant-a" not in messages[0]
    assert hashlib.sha256(request.body).hexdigest().encode() in messages[0]
    assert safe_request_digest(request) == hashlib.sha256(request.body).hexdigest()
    serialized = request.body.decode()
    for forbidden in ("hostname", "url", "ip_address", "user_id", "prompt", "content"):
        assert forbidden not in serialized


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"sensor_revision": 0}, "sensor_revision"),
        ({"sensor_id": "bad"}, "sensor_id"),
        ({"agent_id": "Network Sensor"}, "agent_id"),
        ({"config_sha256": "bad"}, "config_sha256"),
        ({"tenant_ref": ""}, "tenant_ref"),
    ],
)
def test_signed_client_refuses_bad_binding(changes, message: str) -> None:
    with pytest.raises(DiscoverySensorClientError, match=message):
        SignedDiscoverySensorClient(_binding(**changes), signer=lambda _: b"s" * 64)


def test_signed_client_refuses_bad_nonce_or_signature() -> None:
    with pytest.raises(DiscoverySensorClientError, match="nonce"):
        SignedDiscoverySensorClient(
            _binding(),
            signer=lambda _: b"s" * 64,
            nonce_factory=lambda: "bad nonce",
        ).build(_event())
    with pytest.raises(DiscoverySensorClientError, match="64-byte"):
        SignedDiscoverySensorClient(
            _binding(),
            signer=lambda _: b"short",
            nonce_factory=lambda: "nonce-2",
        ).build(_event())


def test_normalizers_refuse_duplicate_or_prohibited_taxonomy_shape() -> None:
    with pytest.raises(DiscoverySensorClientError, match="duplicates"):
        normalize_browser_oauth(
            source_event_sha256=_EVENT_SHA,
            observed_at=1_700_000_000,
            provider_code="openai",
            ai_product_code="chatgpt",
            environment_code="workforce",
            oauth_grant=False,
            context_codes=("managed", "managed"),
        )
    with pytest.raises(DiscoverySensorClientError, match="provider_code"):
        normalize_browser_oauth(
            source_event_sha256=_EVENT_SHA,
            observed_at=1_700_000_000,
            provider_code="raw_url",
            ai_product_code="chatgpt",
            environment_code="workforce",
            oauth_grant=False,
        )
