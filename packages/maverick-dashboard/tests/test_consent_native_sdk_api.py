from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from dataclasses import asdict
from types import SimpleNamespace

import pytest
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient
from maverick.consent_native_sdk import (
    NativeApplicationAuthority,
    NativeConsentDeviceRegistry,
    NativeConsentGateway,
    NativeDeviceAuthority,
    VerifiedNativeAttestation,
    build_envelope,
)
from maverick_dashboard.consent_native_sdk_api import (
    NativeConsentSDKAPIDependencies,
    create_consent_native_sdk_router,
)


def _digest(value: bytes | str) -> str:
    raw = value if isinstance(value, bytes) else value.encode()
    return hashlib.sha256(raw).hexdigest()


def _public_hex(private: Ed25519PrivateKey) -> str:
    return private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()


class _Signer:
    key_id = "native-receipt"
    key_revision = 1

    def __init__(self, private: Ed25519PrivateKey) -> None:
        self.private = private

    def sign(self, body: bytes) -> bytes:
        return self.private.sign(body)


class _Verifier:
    def verify(self, evidence, material):
        assert _digest(material) == evidence.attestation_evidence_sha256
        return VerifiedNativeAttestation(
            authority="play-integrity",
            application_ref=evidence.application_ref,
            tenant_id=evidence.tenant_id,
            application_id=evidence.application_id,
            platform=evidence.platform,
            install_subject_sha256=evidence.install_subject_sha256,
            public_key_hex=evidence.public_key_hex,
            attestation_nonce=evidence.attestation_nonce,
            attestation_evidence_sha256=evidence.attestation_evidence_sha256,
            verified_at=1_000,
            valid_until=2_000,
            verdict="allow",
            sdk_version=evidence.sdk_version,
        )


def _authority() -> NativeApplicationAuthority:
    return NativeApplicationAuthority(
        application_ref="native-prod",
        tenant_id="tenant-one",
        property_id="property-one",
        application_id="com.example.native",
        platform="android",
        public_client_credential_sha256=_digest("client"),
        public_client_revision=1,
        public_client_record_sha256=_digest("client-record"),
        property_revision=1,
        property_sha256=_digest("property"),
        publication_sha256=_digest("publication"),
        publication_bundle_sha256=_digest("bundle"),
        configuration_sha256=_digest("configuration"),
        policy_id="policy-one",
        policy_version=1,
        policy_sha256=_digest("policy"),
        standards_contract_sha256=_digest("standards"),
        minimum_sdk_version=1,
        default_locale="en-US",
        locales=("en-US",),
    )


def test_enrollment_and_signed_dispatch_are_mounted_and_private(tmp_path) -> None:
    authority = _authority()
    registry = NativeConsentDeviceRegistry(tmp_path / "native.sqlite3", clock=lambda: 1_000)
    registry.register_application(authority, expected_revision=0)
    receipt_private = Ed25519PrivateKey.generate()
    gateway = NativeConsentGateway(
        registry,
        client_authority_resolver=lambda _value: SimpleNamespace(
            credential_sha256=authority.public_client_credential_sha256,
            tenant_id=authority.tenant_id,
            property_id=authority.property_id,
            client_kind="service",
            service_client_id=authority.application_ref,
            target_bundle_id=authority.application_id,
            target_platform=authority.platform,
            revision=authority.public_client_revision,
            record_sha256=authority.public_client_record_sha256,
            property_revision=authority.property_revision,
            property_sha256=authority.property_sha256,
            publication_sha256=authority.publication_sha256,
            bundle_sha256=authority.publication_bundle_sha256,
            policy_id=authority.policy_id,
            policy_version=authority.policy_version,
            policy_sha256=authority.policy_sha256,
        ),
        handler=lambda *_args: {"configuration_sha256": authority.configuration_sha256},
        receipt_signer=_Signer(receipt_private),
    )
    calls = []
    deps = NativeConsentSDKAPIDependencies(
        gate=lambda: True,
        registry=registry,
        attestation_verifier=_Verifier(),
        gateway=gateway,
        rate_limit=lambda subject, operation: calls.append((subject, operation)),
    )
    app = FastAPI()
    app.include_router(create_consent_native_sdk_router(deps))
    hostile_client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "https://attacker.invalid"})
    material = b"play-integrity-statement"
    private = Ed25519PrivateKey.generate()
    enrollment = {
        "application_ref": authority.application_ref,
        "tenant_id": authority.tenant_id,
        "application_id": authority.application_id,
        "platform": authority.platform,
        "install_subject_sha256": _digest("installation"),
        "public_key_hex": _public_hex(private),
        "attestation_nonce": "nonce-one",
        "attestation_evidence_sha256": _digest(material),
        "attestation_material_b64url": base64.urlsafe_b64encode(material).rstrip(b"=").decode(),
        "issued_at": 999,
        "expires_at": 1_120,
        "sdk_version": 1,
    }
    rejected = hostile_client.post("/api/v1/public/consent/native/enroll", json=enrollment)
    assert rejected.status_code == 401
    # Exact-origin Tizen/webOS JSON POSTs are admitted; ambient credentials are not.
    native_client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    enrolled = native_client.post(
        "/api/v1/public/consent/native/enroll",
        json=enrollment,
    )
    assert enrolled.status_code == 201
    assert enrolled.headers["cache-control"] == "no-store, private, max-age=0"
    device = NativeDeviceAuthority(**enrolled.json()["device"])
    envelope = build_envelope(
        authority,
        device,
        request_id="request-one",
        counter=1,
        operation="configuration",
        payload={},
        signer=_Signer(private),
        issued_at=1_000,
    )
    dispatched = native_client.post(
        "/api/v1/public/consent/native/dispatch",
        json=asdict(envelope),
    )
    assert dispatched.status_code == 200
    assert dispatched.json()["request_id"] == "request-one"
    assert dispatched.json()["result"]["configuration_sha256"] == authority.configuration_sha256
    assert len(dispatched.json()["signature_hex"]) == 128
    signed_payload = dispatched.json()["signed_payload_b64url"]
    decoded = base64.urlsafe_b64decode(signed_payload + "=" * (-len(signed_payload) % 4))
    assert json.loads(decoded)["request_id"] == "request-one"
    receipt_private.public_key().verify(bytes.fromhex(dispatched.json()["signature_hex"]), decoded)

    refresh_material = b"play-integrity-refresh-statement"
    refresh_request = {
        **enrollment,
        "device_id": device.device_id,
        "expected_revision": device.revision,
        "attestation_nonce": "nonce-refresh-one",
        "attestation_evidence_sha256": _digest(refresh_material),
        "attestation_material_b64url": base64.urlsafe_b64encode(refresh_material)
        .rstrip(b"=")
        .decode(),
    }
    credentialed_client = TestClient(
        app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1", "Cookie": "session=ambient"},
    )
    assert (
        credentialed_client.post(
            "/api/v1/public/consent/native/refresh",
            json=refresh_request,
        ).status_code
        == 401
    )
    refreshed_response = native_client.post(
        "/api/v1/public/consent/native/refresh",
        json=refresh_request,
    )
    assert refreshed_response.status_code == 200
    refreshed = NativeDeviceAuthority(**refreshed_response.json()["device"])
    assert refreshed.revision == device.revision + 1
    assert refreshed.key_revision == device.key_revision
    assert refreshed.public_key_hex == device.public_key_hex
    assert refreshed.application_authority_sha256 == authority.authority_sha256

    replayed = native_client.post(
        "/api/v1/public/consent/native/refresh",
        json=refresh_request,
    )
    assert replayed.status_code == 409
    rebound_material = b"play-integrity-rebound-statement"
    rebound = {
        **refresh_request,
        "expected_revision": refreshed.revision,
        "public_key_hex": _public_hex(Ed25519PrivateKey.generate()),
        "attestation_nonce": "nonce-refresh-rebound",
        "attestation_evidence_sha256": _digest(rebound_material),
        "attestation_material_b64url": base64.urlsafe_b64encode(rebound_material)
        .rstrip(b"=")
        .decode(),
    }
    assert (
        native_client.post("/api/v1/public/consent/native/refresh", json=rebound).status_code
        == 401
    )
    assert (
        native_client.post(
            "/api/v1/public/consent/native/dispatch",
            json=asdict(envelope),
        ).status_code
        == 409
    )
    next_envelope = build_envelope(
        authority,
        refreshed,
        request_id="request-two",
        counter=2,
        operation="configuration",
        payload={},
        signer=_Signer(private),
        issued_at=1_000,
    )
    assert (
        native_client.post(
            "/api/v1/public/consent/native/dispatch",
            json=asdict(next_envelope),
        ).status_code
        == 200
    )
    assert [operation for _subject, operation in calls] == [
        "enroll",
        "dispatch",
        "refresh",
        "refresh",
        "refresh",
        "dispatch",
        "dispatch",
    ]


def test_disabled_native_boundary_is_not_discoverable(tmp_path) -> None:
    authority = _authority()
    registry = NativeConsentDeviceRegistry(tmp_path / "native.sqlite3", clock=lambda: 1_000)
    registry.register_application(authority, expected_revision=0)
    gateway = NativeConsentGateway(
        registry,
        client_authority_resolver=lambda _value: None,
        handler=lambda *_args: {},
        receipt_signer=_Signer(Ed25519PrivateKey.generate()),
    )
    app = FastAPI()
    app.include_router(
        create_consent_native_sdk_router(
            NativeConsentSDKAPIDependencies(
                gate=lambda: False,
                registry=registry,
                attestation_verifier=_Verifier(),
                gateway=gateway,
                rate_limit=lambda *_args: None,
            )
        )
    )
    material = b"attestation"
    response = TestClient(app, base_url="http://127.0.0.1").post(
        "/api/v1/public/consent/native/enroll",
        json={
            "application_ref": authority.application_ref,
            "tenant_id": authority.tenant_id,
            "application_id": authority.application_id,
            "platform": authority.platform,
            "install_subject_sha256": _digest("installation"),
            "public_key_hex": _public_hex(Ed25519PrivateKey.generate()),
            "attestation_nonce": "nonce-one",
            "attestation_evidence_sha256": _digest(material),
            "attestation_material_b64url": base64.urlsafe_b64encode(material).rstrip(b"=").decode(),
            "issued_at": 999,
            "expires_at": 1_120,
            "sdk_version": 1,
        },
    )
    assert response.status_code == 404


_NATIVE = "/api/v1/public/consent/native"


def _preflight_only_app(*, gate, rate_limit=lambda *_args: None) -> FastAPI:
    """The native router with only the request checks wired (no registry work)."""

    app = FastAPI()
    app.include_router(
        create_consent_native_sdk_router(
            NativeConsentSDKAPIDependencies(
                gate=gate,
                registry=SimpleNamespace(),
                attestation_verifier=SimpleNamespace(),
                gateway=SimpleNamespace(),
                rate_limit=rate_limit,
            )
        )
    )
    return app


@pytest.mark.parametrize("endpoint", ["enroll", "dispatch", "refresh"])
def test_gate_runs_off_the_event_loop(endpoint: str) -> None:
    """The gate reads the application directory from disk for every anonymous
    request; running it on the event-loop thread stalled every other request."""

    where: list[str] = []

    def gate() -> bool:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            where.append("worker thread")
        else:
            where.append("event loop")
        return False

    client = TestClient(_preflight_only_app(gate=gate), base_url="http://127.0.0.1")
    assert client.post(f"{_NATIVE}/{endpoint}", json={}).status_code == 404
    assert where == ["worker thread"]


def _address_keys(monkeypatch, *, forwarded_allow_ips: str | None, peer: str, forwarded: list[str]):
    """The per-address throttle keys the endpoint used when ``peer`` relayed
    requests that carry the given X-Forwarded-For values, with uvicorn
    configured exactly as the dashboard's launcher does (its own defaults, or
    the FORWARDED_ALLOW_IPS setting operators are told to use)."""

    keys: list[str] = []
    app = _preflight_only_app(
        gate=lambda: True,
        rate_limit=lambda subject, _operation: keys.append(subject),
    )
    if forwarded_allow_ips is None:
        monkeypatch.delenv("FORWARDED_ALLOW_IPS", raising=False)
    else:
        monkeypatch.setenv("FORWARDED_ALLOW_IPS", forwarded_allow_ips)
    config = uvicorn.Config(app)
    config.load()
    client = TestClient(config.loaded_app, base_url="http://127.0.0.1", client=(peer, 4000))
    for address in forwarded:
        # An empty body is refused after the throttle has been charged.
        client.post(f"{_NATIVE}/dispatch", json={}, headers={"X-Forwarded-For": address})
    return keys


def test_balancer_in_forwarded_allow_ips_gives_each_device_its_own_throttle_key(monkeypatch) -> None:
    keys = _address_keys(
        monkeypatch,
        forwarded_allow_ips="10.0.0.5",
        peer="10.0.0.5",
        forwarded=["203.0.113.9", "198.51.100.7"],
    )
    assert keys == ["203.0.113.9", "198.51.100.7"]


def test_untrusted_balancer_makes_every_device_share_one_throttle_key(monkeypatch) -> None:
    # uvicorn's default trusts only loopback, so a balancer elsewhere on the
    # network is just one address: the situation docs/deployment.md tells
    # operators to fix with FORWARDED_ALLOW_IPS.
    keys = _address_keys(
        monkeypatch,
        forwarded_allow_ips=None,
        peer="10.0.0.5",
        forwarded=["203.0.113.9", "198.51.100.7"],
    )
    assert keys == ["10.0.0.5", "10.0.0.5"]


def test_a_direct_caller_cannot_choose_its_own_throttle_key(monkeypatch) -> None:
    keys = _address_keys(
        monkeypatch,
        forwarded_allow_ips="10.0.0.5",
        peer="192.0.2.50",
        forwarded=["203.0.113.9"],
    )
    assert keys == ["192.0.2.50"]
