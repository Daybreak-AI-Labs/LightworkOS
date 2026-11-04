from __future__ import annotations

import base64
import hashlib
import itertools

import pytest
from maverick import config
from maverick.consent_delivery import (
    ConsentDeliveryConfigError,
    ConsentDeliveryStore,
    DeliveryResponse,
)
from maverick.consent_delivery_runtime import (
    EnvironmentHMACDeliverySigner,
    run_delivery_once,
    signing_secret_environment_name,
)
from maverick.consent_preferences import (
    ConsentContext,
    ConsentPreferenceStore,
    PreferenceChoice,
)

NOW = 1_800_000_000.0
DIGEST = "a" * 64


@pytest.fixture(autouse=True)
def _enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "config_source_errors", lambda **kwargs: ())
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "consent_preferences": {
                "enable": True,
                "delivery": {"enable": True},
            }
        },
    )


class _Transport:
    def __init__(self) -> None:
        self.requests = []

    def post(self, request, *, timeout_seconds, max_response_bytes):
        self.requests.append((request, timeout_seconds, max_response_bytes))
        return DeliveryResponse(status_code=204, response_sha256=hashlib.sha256(b"").hexdigest())


def _stores(tmp_path):
    ids = itertools.count(1)
    preferences = ConsentPreferenceStore(
        tmp_path / "preferences.sqlite3",
        clock=lambda: NOW,
        id_factory=lambda prefix: f"{prefix}-{next(ids)}",
    )
    delivery = ConsentDeliveryStore(
        tmp_path / "delivery.sqlite3",
        clock=lambda: NOW,
        id_factory=lambda prefix: f"{prefix}-{next(ids)}",
        config_gate=lambda: True,
        origin_validator=lambda _origin: None,
    )
    preferences.publish_policy(
        "tenant-a", "notice", 1, {"analytics": "consent"}, DIGEST, NOW - 1
    )
    preferences.create_profile("tenant-a", "profile-a", "anonymous", DIGEST, "profile")
    preferences.record_preferences(
        "tenant-a",
        "profile-a",
        "notice",
        1,
        ConsentContext("global", "US", "", "web", asserted_source="edge"),
        [PreferenceChoice("analytics", "grant")],
        expected_revision=0,
        idempotency_key="receipt",
        actor_sha256=DIGEST,
    )
    delivery.enroll_destination(
        "tenant-a",
        destination_id="crm",
        origin="https://crm.example.com",
        signing_key_id="crm-key-v1",
        idempotency_key="destination",
    )
    return preferences, delivery


def test_environment_signer_uses_key_id_derived_external_custody() -> None:
    name = signing_secret_environment_name("crm-key-v1")
    secret = b"s" * 32
    signer = EnvironmentHMACDeliverySigner(
        environ={name: base64.urlsafe_b64encode(secret).decode().rstrip("=")}
    )
    assert signer.sign("crm-key-v1", b"payload") == __import__("hmac").new(
        secret, b"payload", hashlib.sha256
    ).digest()
    assert "crm-key-v1" not in name
    with pytest.raises(ConsentDeliveryConfigError):
        EnvironmentHMACDeliverySigner(environ={}).sign("crm-key-v1", b"payload")


def test_runtime_bridges_signs_and_dispatches_without_raw_caller_event(tmp_path) -> None:
    preferences, delivery = _stores(tmp_path)
    transport = _Transport()
    signer = EnvironmentHMACDeliverySigner(
        environ={
            signing_secret_environment_name("crm-key-v1"): base64.urlsafe_b64encode(
                b"k" * 32
            ).decode()
        }
    )
    result = run_delivery_once(
        "tenant-a",
        ["crm"],
        worker_id="worker-a",
        preference_store=preferences,
        delivery_store=delivery,
        signer=signer,
        transport=transport,
    )
    assert result["synchronized"]["changes_queued"] == 1
    assert result["dispatched"]["delivered"] == 1
    assert result["live_external_acceptance"] is False
    assert len(transport.requests) == 1
    request = transport.requests[0][0]
    assert request.header_map()["X-Lightwork-Key-Id"] == "crm-key-v1"
    assert delivery.counts("tenant-a")["delivered"] == 1


def test_runtime_rejects_unbounded_or_invalid_worker_contract(tmp_path) -> None:
    preferences, delivery = _stores(tmp_path)
    with pytest.raises(ConsentDeliveryConfigError):
        run_delivery_once(
            "tenant-a",
            ["crm"],
            worker_id="bad worker",
            preference_store=preferences,
            delivery_store=delivery,
            transport=_Transport(),
        )
