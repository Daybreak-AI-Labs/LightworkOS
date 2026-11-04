from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import replace
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from maverick.consent_native_sdk import (
    NativeApplicationAuthority,
    NativeConsentCapacityError,
    NativeConsentConflict,
    NativeConsentDenied,
    NativeConsentDeviceRegistry,
    NativeConsentGateway,
    NativeConsentIntegrityError,
    NativeConsentValidationError,
    NativeEnrollmentEvidence,
    NativeOfflineQueue,
    NativeResponseReceipt,
    VerifiedNativeAttestation,
    build_envelope,
    localized_ui_contract,
    normalize_operation_payload,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class _Clock:
    def __init__(self, value: float = 1_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class _Signer:
    def __init__(self, private: Ed25519PrivateKey, *, key_id: str = "receipt-key") -> None:
        self.private = private
        self.key_id = key_id
        self.key_revision = 1

    def sign(self, body: bytes) -> bytes:
        return self.private.sign(body)


class _Verifier:
    def __init__(self, clock: _Clock) -> None:
        self.clock = clock

    def verify(
        self,
        evidence: NativeEnrollmentEvidence,
        attestation_material: bytes,
    ) -> VerifiedNativeAttestation:
        assert hashlib.sha256(attestation_material).hexdigest() == evidence.attestation_evidence_sha256
        return VerifiedNativeAttestation(
            authority="test-attestation",
            application_ref=evidence.application_ref,
            tenant_id=evidence.tenant_id,
            application_id=evidence.application_id,
            platform=evidence.platform,
            install_subject_sha256=evidence.install_subject_sha256,
            public_key_hex=evidence.public_key_hex,
            attestation_nonce=evidence.attestation_nonce,
            attestation_evidence_sha256=evidence.attestation_evidence_sha256,
            verified_at=self.clock(),
            valid_until=self.clock() + 3_600,
            verdict="allow",
            sdk_version=evidence.sdk_version,
        )


def _public_hex(private: Ed25519PrivateKey) -> str:
    return private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()


def _authority(**changes) -> NativeApplicationAuthority:
    values = {
        "application_ref": "mobile-prod",
        "tenant_id": "tenant-one",
        "property_id": "property-one",
        "application_id": "com.example.lightwork",
        "platform": "ios",
        "public_client_credential_sha256": _digest("client"),
        "public_client_revision": 3,
        "public_client_record_sha256": _digest("client-record"),
        "property_revision": 5,
        "property_sha256": _digest("property"),
        "publication_sha256": _digest("publication"),
        "publication_bundle_sha256": _digest("bundle"),
        "configuration_sha256": _digest("configuration"),
        "policy_id": "policy-one",
        "policy_version": 7,
        "policy_sha256": _digest("policy"),
        "standards_contract_sha256": _digest("standards"),
        "minimum_sdk_version": 4,
        "default_locale": "en-US",
        "locales": ("en-US", "es-US"),
    }
    values.update(changes)
    return NativeApplicationAuthority(**values)


def _client(authority: NativeApplicationAuthority, **changes):
    values = {
        "credential_sha256": authority.public_client_credential_sha256,
        "tenant_id": authority.tenant_id,
        "property_id": authority.property_id,
        "client_kind": "service",
        "service_client_id": authority.application_ref,
        "target_bundle_id": authority.application_id,
        "target_platform": authority.platform,
        "revision": authority.public_client_revision,
        "record_sha256": authority.public_client_record_sha256,
        "property_revision": authority.property_revision,
        "property_sha256": authority.property_sha256,
        "publication_sha256": authority.publication_sha256,
        "bundle_sha256": authority.publication_bundle_sha256,
        "policy_id": authority.policy_id,
        "policy_version": authority.policy_version,
        "policy_sha256": authority.policy_sha256,
    }
    values.update(changes)
    return SimpleNamespace(**values)


def _evidence(
    authority: NativeApplicationAuthority,
    private: Ed25519PrivateKey,
    clock: _Clock,
    *,
    nonce: str = "nonce-one",
    subject: str = "install-one",
) -> NativeEnrollmentEvidence:
    return NativeEnrollmentEvidence(
        application_ref=authority.application_ref,
        tenant_id=authority.tenant_id,
        application_id=authority.application_id,
        platform=authority.platform,
        install_subject_sha256=_digest(subject),
        public_key_hex=_public_hex(private),
        attestation_nonce=nonce,
        attestation_evidence_sha256=_digest(f"attestation:{nonce}"),
        issued_at=clock() - 1,
        expires_at=clock() + 120,
    )


def _enrolled(tmp_path, *, max_devices: int = 100_000, max_requests: int = 1_000_000):
    clock = _Clock()
    authority = _authority()
    registry = NativeConsentDeviceRegistry(
        tmp_path / "registry.sqlite3",
        clock=clock,
        max_devices=max_devices,
        max_requests=max_requests,
    )
    assert registry.register_application(authority, expected_revision=0)["revision"] == 1
    private = Ed25519PrivateKey.generate()
    device = registry.enroll_device(
        _evidence(authority, private, clock),
        verifier=_Verifier(clock),
        attestation_material=b"attestation:nonce-one",
        sdk_version=4,
    )
    return clock, authority, registry, private, device


def _preference_payload() -> dict:
    return {
        "profile_credential_sha256": _digest("profile-capability"),
        "expected_revision": 0,
        "idempotency_key": "mobile-pref-one",
        "choices": [
            {"purpose_id": "analytics", "action": "deny"},
            {
                "purpose_id": "essential",
                "action": "grant",
                "channel": "mobile",
                "vendor_id": "all",
            },
        ],
    }


def test_closed_operations_localization_and_opaque_standards() -> None:
    tcf = "COwK6gaOwK6gaFmAAAENAPCAAAAAAAAAAAAAAAAAAAAA.IFMsv_Z_G____bvQXQlf9eY1f9_z_q7ff9_3zv9_7___5_3--_eV1v9zLv9____39nP___9v-_4-1v9zLv9____39nP___9v-_4-0"
    signals = normalize_operation_payload(
        "privacy_signals",
        {
            "profile_credential_sha256": _digest("profile"),
            "expected_revision": 2,
            "idempotency_key": "signals-one",
            "signals": {
                "gpc": True,
                "do_not_sell_or_share": True,
                "standards_contract_sha256": _digest("standards"),
                "purposes": ["sale", "sharing"],
                "tcf_string": tcf,
                "tcf_string_sha256": hashlib.sha256(tcf.encode("ascii")).hexdigest(),
            },
        },
    )
    assert signals["signals"]["gpc"] is True
    assert signals["signals"]["purposes"] == ["sale", "sharing"]
    ui = localized_ui_contract(
        locale="en-US",
        direction="ltr",
        strings={"accept": "Accept all", "reject": "Reject all", "manage": "Manage"},
        required_keys=("accept", "reject", "manage"),
        content_revision=2,
        content_sha256=_digest("localized-document"),
    )
    assert ui["rendering"]["supports_screen_reader"] is True
    assert len(ui["contract_sha256"]) == 64
    with pytest.raises(NativeConsentValidationError, match="plain text"):
        localized_ui_contract(
            locale="en-US",
            direction="ltr",
            strings={"accept": "<script>alert(1)</script>"},
            required_keys=("accept",),
            content_revision=1,
            content_sha256=_digest("bad"),
        )
    with pytest.raises(NativeConsentValidationError, match="unknown or missing"):
        normalize_operation_payload("configuration", {"tenant_id": "attacker"})


def test_enrollment_gateway_receipt_and_exact_replay(tmp_path) -> None:
    clock, authority, registry, private, device = _enrolled(tmp_path)
    envelope = build_envelope(
        authority,
        device,
        request_id="request-one",
        counter=1,
        operation="record_preferences",
        payload=_preference_payload(),
        signer=_Signer(private),
        issued_at=clock(),
    )
    receipt_key = Ed25519PrivateKey.generate()
    calls: list[str] = []

    def handler(app, admitted_device, operation, payload, request_id):
        assert app == authority
        assert admitted_device.device_id == device.device_id
        assert operation == "record_preferences"
        assert payload["idempotency_key"] == "mobile-pref-one"
        calls.append(request_id)
        return {"receipt_id": "CP-RCP-one", "profile_revision": 1, "status": "accepted"}

    gateway = NativeConsentGateway(
        registry,
        client_authority_resolver=lambda _digest_value: _client(authority),
        handler=handler,
        receipt_signer=_Signer(receipt_key),
    )
    receipt = gateway.dispatch(envelope)
    assert receipt.payload["operation"] == "record_preferences"
    assert receipt.payload["result"]["profile_revision"] == 1
    assert receipt.verify({"receipt-key": _public_hex(receipt_key)}) is True
    replay = gateway.dispatch(envelope)
    assert replay == receipt
    assert calls == ["request-one"]
    assert registry.verify_integrity()["events"] == 4

    rebound = replace(envelope, payload={**_preference_payload(), "expected_revision": 1})
    with pytest.raises(NativeConsentDenied, match="signature"):
        gateway.dispatch(rebound)


def test_client_drift_counter_and_revocation_fail_closed(tmp_path) -> None:
    clock, authority, registry, private, device = _enrolled(tmp_path)
    receipt_key = Ed25519PrivateKey.generate()
    envelope = build_envelope(
        authority,
        device,
        request_id="request-drift",
        counter=1,
        operation="configuration",
        payload={},
        signer=_Signer(private),
        issued_at=clock(),
    )
    drifted = _client(authority, policy_version=authority.policy_version + 1)
    gateway = NativeConsentGateway(
        registry,
        client_authority_resolver=lambda _value: drifted,
        handler=lambda *_args: {"ok": True},
        receipt_signer=_Signer(receipt_key),
    )
    with pytest.raises(NativeConsentConflict, match="public client"):
        gateway.dispatch(envelope)

    valid = NativeConsentGateway(
        registry,
        client_authority_resolver=lambda _value: _client(authority),
        handler=lambda *_args: {"ok": True},
        receipt_signer=_Signer(receipt_key),
    )
    jump = build_envelope(
        authority,
        device,
        request_id="request-jump",
        counter=10_001,
        operation="configuration",
        payload={},
        signer=_Signer(private),
        issued_at=clock(),
    )
    with pytest.raises(NativeConsentConflict, match="counter"):
        valid.dispatch(jump)
    registry.revoke_device(
        device.device_id,
        expected_revision=1,
        evidence_sha256=_digest("operator-revocation"),
    )
    with pytest.raises(NativeConsentDenied, match="unavailable"):
        valid.dispatch(envelope)


def test_key_rotation_requires_fresh_exact_attestation(tmp_path) -> None:
    clock, authority, registry, old_private, device = _enrolled(tmp_path)
    new_private = Ed25519PrivateKey.generate()
    rotated = registry.rotate_device_key(
        device.device_id,
        _evidence(authority, new_private, clock, nonce="rotation-one"),
        verifier=_Verifier(clock),
        attestation_material=b"attestation:rotation-one",
        expected_revision=1,
    )
    assert rotated.key_revision == 2
    assert rotated.revision == 2
    assert rotated.public_key_hex == _public_hex(new_private)
    stale = build_envelope(
        authority,
        device,
        request_id="old-key-request",
        counter=1,
        operation="configuration",
        payload={},
        signer=_Signer(old_private),
        issued_at=clock(),
    )
    gateway = NativeConsentGateway(
        registry,
        client_authority_resolver=lambda _value: _client(authority),
        handler=lambda *_args: {"ok": True},
        receipt_signer=_Signer(Ed25519PrivateKey.generate()),
    )
    with pytest.raises(NativeConsentConflict, match="authority changed"):
        gateway.dispatch(stale)
    with pytest.raises(NativeConsentConflict, match="nonce"):
        registry.rotate_device_key(
            rotated.device_id,
            _evidence(authority, Ed25519PrivateKey.generate(), clock, nonce="rotation-one"),
            verifier=_Verifier(clock),
            attestation_material=b"attestation:rotation-one",
            expected_revision=2,
        )


def test_application_authority_refresh_is_attested_cas_and_preserves_key(tmp_path) -> None:
    clock, authority, registry, private, device = _enrolled(tmp_path)
    old_envelope = build_envelope(
        authority,
        device,
        request_id="before-authority-refresh",
        counter=1,
        operation="configuration",
        payload={},
        signer=_Signer(private),
        issued_at=clock(),
    )
    updated = replace(
        authority,
        public_client_revision=authority.public_client_revision + 1,
        public_client_record_sha256=_digest("client-record-v2"),
        publication_sha256=_digest("publication-v2"),
        publication_bundle_sha256=_digest("bundle-v2"),
        configuration_sha256=_digest("configuration-v2"),
        policy_version=authority.policy_version + 1,
        policy_sha256=_digest("policy-v2"),
        minimum_sdk_version=5,
    )
    assert registry.register_application(updated, expected_revision=1)["revision"] == 2
    gateway = NativeConsentGateway(
        registry,
        client_authority_resolver=lambda _value: _client(updated),
        handler=lambda *_args: {"configuration_sha256": updated.configuration_sha256},
        receipt_signer=_Signer(Ed25519PrivateKey.generate()),
    )
    with pytest.raises(NativeConsentConflict, match="authority changed"):
        gateway.dispatch(old_envelope)

    refresh = replace(
        _evidence(updated, private, clock, nonce="authority-refresh-one"),
        sdk_version=5,
    )
    unbound_sdk = _evidence(updated, private, clock, nonce="authority-refresh-unbound-sdk")
    with pytest.raises(NativeConsentDenied, match="did not bind the SDK version"):
        registry.refresh_device_authority(
            device.device_id,
            unbound_sdk,
            verifier=_Verifier(clock),
            attestation_material=b"attestation:authority-refresh-unbound-sdk",
            expected_revision=1,
            admitted_sdk_version=5,
        )

    class _NonceRebinder:
        def verify(self, evidence, material):
            decision = _Verifier(clock).verify(evidence, material)
            return replace(decision, attestation_nonce="different-refresh-nonce")

    with pytest.raises(NativeConsentDenied, match="decision was rebound"):
        registry.refresh_device_authority(
            device.device_id,
            refresh,
            verifier=_NonceRebinder(),
            attestation_material=b"attestation:authority-refresh-one",
            expected_revision=1,
            admitted_sdk_version=5,
        )
    refreshed = registry.refresh_device_authority(
        device.device_id,
        refresh,
        verifier=_Verifier(clock),
        attestation_material=b"attestation:authority-refresh-one",
        expected_revision=1,
        admitted_sdk_version=5,
    )
    assert refreshed.device_id == device.device_id
    assert refreshed.public_key_hex == device.public_key_hex
    assert refreshed.key_revision == device.key_revision
    assert refreshed.revision == 2
    assert refreshed.sdk_version == 5
    assert refreshed.application_authority_sha256 == updated.authority_sha256

    with pytest.raises(NativeConsentConflict, match="nonce"):
        registry.refresh_device_authority(
            device.device_id,
            refresh,
            verifier=_Verifier(clock),
            attestation_material=b"attestation:authority-refresh-one",
            expected_revision=2,
            admitted_sdk_version=5,
        )
    stale = replace(
        _evidence(updated, private, clock, nonce="authority-refresh-stale"),
        sdk_version=5,
    )
    with pytest.raises(NativeConsentConflict, match="revision"):
        registry.refresh_device_authority(
            device.device_id,
            stale,
            verifier=_Verifier(clock),
            attestation_material=b"attestation:authority-refresh-stale",
            expected_revision=1,
            admitted_sdk_version=5,
        )
    rebound_private = Ed25519PrivateKey.generate()
    rebound = replace(
        _evidence(updated, rebound_private, clock, nonce="authority-refresh-rebound"),
        sdk_version=5,
    )
    with pytest.raises(NativeConsentDenied, match="rebound"):
        registry.refresh_device_authority(
            device.device_id,
            rebound,
            verifier=_Verifier(clock),
            attestation_material=b"attestation:authority-refresh-rebound",
            expected_revision=2,
            admitted_sdk_version=5,
        )

    with pytest.raises(NativeConsentConflict, match="authority changed"):
        gateway.dispatch(old_envelope)
    new_envelope = build_envelope(
        updated,
        refreshed,
        request_id="after-authority-refresh",
        counter=1,
        operation="configuration",
        payload={},
        signer=_Signer(private),
        issued_at=clock(),
    )
    receipt = gateway.dispatch(new_envelope)
    assert receipt.payload["result"]["configuration_sha256"] == updated.configuration_sha256


def test_offline_retry_renew_acknowledge_and_local_revocation(tmp_path) -> None:
    clock, authority, _registry, private, device = _enrolled(tmp_path / "server")
    queue = NativeOfflineQueue(
        tmp_path / "client" / "queue.sqlite3",
        clock=clock,
        max_messages=2,
        max_attempts=2,
        retry_base_seconds=1,
        retry_max_seconds=4,
    )
    first = build_envelope(
        authority,
        device,
        request_id="offline-one",
        counter=1,
        operation="record_preferences",
        payload=_preference_payload(),
        signer=_Signer(private),
        issued_at=clock(),
        ttl_seconds=2,
    )
    assert queue.enqueue(first)["status"] == "pending"
    assert queue.enqueue(first)["status"] == "pending"
    assert queue.due() == (first,)
    retry = queue.retry(first.request_id, b"network unavailable")
    assert retry["attempts"] == 1
    clock.value += 3
    renewed = queue.renew_expired(
        first.request_id,
        authority,
        device,
        new_request_id="offline-two",
        counter=2,
        signer=_Signer(private),
    )
    assert renewed.payload["idempotency_key"] == "mobile-pref-one"
    assert queue.due() == (renewed,)
    receipt_key = Ed25519PrivateKey.generate()
    receipt_signer = _Signer(receipt_key)
    receipt_body = {
        "schema": "lightwork.native-consent-receipt.v1",
        "application_ref": authority.application_ref,
        "application_authority_sha256": authority.authority_sha256,
        "tenant_sha256": hashlib.sha256(authority.tenant_id.encode()).hexdigest(),
        "device_id": device.device_id,
        "device_revision": device.revision,
        "request_id": renewed.request_id,
        "request_sha256": renewed.request_sha256,
        "operation": renewed.operation,
        "result": {"status": "accepted"},
        "result_sha256": hashlib.sha256(b'{"status":"accepted"}').hexdigest(),
        "publication_sha256": authority.publication_sha256,
        "configuration_sha256": authority.configuration_sha256,
        "policy_sha256": authority.policy_sha256,
        "key_id": receipt_signer.key_id,
        "key_revision": receipt_signer.key_revision,
        "completed_at": int(clock()),
    }
    receipt = NativeResponseReceipt(
        receipt_body,
        receipt_signer.sign(
            __import__("json").dumps(
                receipt_body,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        ).hex(),
    )
    with pytest.raises(NativeConsentDenied, match="signature"):
        queue.acknowledge(
            replace(receipt, signature_hex="0" * 128),
            trusted_public_keys={receipt_signer.key_id: _public_hex(receipt_key)},
        )
    queue.acknowledge(
        receipt,
        trusted_public_keys={receipt_signer.key_id: _public_hex(receipt_key)},
    )
    assert queue.due() == ()

    second = build_envelope(
        authority,
        device,
        request_id="offline-three",
        counter=3,
        operation="configuration",
        payload={},
        signer=_Signer(private),
        issued_at=clock(),
    )
    queue.enqueue(second)
    assert queue.revoke_device(device.device_id) == 1
    assert queue.due() == ()


def test_registry_capacity_and_audit_tampering_are_detected(tmp_path) -> None:
    clock, authority, registry, _private, _device = _enrolled(tmp_path, max_devices=1)
    with pytest.raises(NativeConsentCapacityError, match="device registry"):
        registry.enroll_device(
            _evidence(
                authority,
                Ed25519PrivateKey.generate(),
                clock,
                nonce="second-device",
                subject="install-two",
            ),
            verifier=_Verifier(clock),
            attestation_material=b"attestation:second-device",
            sdk_version=4,
        )
    with sqlite3.connect(registry.path) as connection:
        connection.execute("DROP TRIGGER native_consent_audit_no_update")
        connection.execute(
            "UPDATE native_consent_audit SET event_sha256=? WHERE sequence=1",
            (_digest("tampered"),),
        )
    with pytest.raises(NativeConsentIntegrityError, match="audit chain"):
        registry.verify_integrity()


def test_non_ascii_stored_digests_are_integrity_errors_not_type_errors(tmp_path) -> None:
    # Edited digests must not raise TypeError from hmac.compare_digest in the
    # shared comparison helper instead of the registry's integrity refusal.
    _clock, authority, registry, _private, _device = _enrolled(tmp_path)
    with sqlite3.connect(registry.path) as connection:
        connection.execute("DROP TRIGGER native_consent_audit_no_update")
        connection.execute("UPDATE native_consent_audit SET event_sha256=?", ("é" * 64,))
        connection.execute(
            "UPDATE native_consent_apps SET authority_sha256=? WHERE application_ref=?",
            ("é" * 64, authority.application_ref),
        )
    with pytest.raises(NativeConsentIntegrityError, match="audit chain"):
        registry.verify_integrity()
    with pytest.raises(NativeConsentIntegrityError, match="application authority changed"):
        registry.get_application(authority.application_ref)


def test_household_link_and_rights_handoff_are_digest_only() -> None:
    linked = normalize_operation_payload(
        "link_profile",
        {
            "profile_credential_sha256": _digest("living-room"),
            "target_profile_credential_sha256": _digest("phone"),
            "pairing_authorization_sha256": _digest("pairing"),
            "scope": "household",
            "idempotency_key": "link-household-one",
        },
    )
    assert linked["scope"] == "household"
    assert all("raw" not in key for key in linked)
    rights = normalize_operation_payload(
        "rights_request",
        {
            "profile_credential_sha256": _digest("phone"),
            "rights": ["access", "opt_out", "erasure"],
            "expected_revision": 0,
            "idempotency_key": "rights-mobile-one",
        },
    )
    assert rights["rights"] == ["access", "erasure", "opt_out"]
    with pytest.raises(NativeConsentValidationError, match="distinct target"):
        normalize_operation_payload(
            "link_profile",
            {
                "profile_credential_sha256": _digest("same"),
                "target_profile_credential_sha256": _digest("same"),
                "pairing_authorization_sha256": _digest("pairing"),
                "scope": "device",
                "idempotency_key": "bad-link",
            },
        )
