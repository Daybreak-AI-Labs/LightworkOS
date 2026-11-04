from __future__ import annotations

import base64
import hashlib
import sqlite3
import time
from dataclasses import replace

import pytest
from maverick.consent_identity_federation import (
    ConsentIdentityFederationConflict,
    ConsentIdentityFederationDenied,
    ConsentIdentityFederationIntegrityError,
    ConsentIdentityFederationStore,
    ConsentIdentitySettings,
    ConsentPairingContext,
    InjectedConsentOIDCVerifier,
    VerifiedConsentOIDCClaims,
    consent_identity_enabled,
    load_consent_identity_settings,
)
from maverick.consent_preferences import ConsentPreferenceStore


class Clock:
    def __init__(self, value: float = 1_800_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def pkce(verifier: str) -> str:
    raw = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def settings() -> ConsentIdentitySettings:
    return ConsentIdentitySettings(
        enabled=True,
        issuer="https://id.example.test",
        audience="lightwork-consent",
        jwks_origin="https://keys.example.test",
        token_ttl_seconds=300,
    )


def context(profile_id: str, client: str, *, revision: int = 0) -> ConsentPairingContext:
    return ConsentPairingContext(
        tenant_id="tenant-a",
        property_id="property-a",
        profile_id=profile_id,
        profile_revision=revision,
        client_credential_sha256=digest(f"client:{client}"),
        client_revision=1,
        client_record_sha256=digest(f"client-record:{client}"),
        profile_credential_sha256=digest(f"profile-cap:{client}"),
        profile_binding_sha256=digest(f"profile-binding:{client}"),
        property_revision=2,
        property_sha256=digest("property"),
        publication_sha256=digest("publication"),
        bundle_sha256=digest("bundle"),
        configuration_sha256=digest("configuration"),
        policy_id="policy-a",
        policy_version=3,
        policy_sha256=digest("policy"),
        channel_kind=("browser-origin" if client == "source" else "service-client"),
        channel_binding_sha256=digest(f"channel:{client}"),
    )


@pytest.fixture
def material(tmp_path):
    clock = Clock()
    preferences = ConsentPreferenceStore(tmp_path / "preferences.sqlite3", clock=clock)
    preferences.create_profile(
        "tenant-a", "source-profile", "anonymous", digest("source-subject"), "source-create"
    )
    preferences.create_profile(
        "tenant-a", "target-profile", "anonymous", digest("target-subject"), "target-create"
    )
    base = {
        digest("client:source"): context("source-profile", "source"),
        digest("client:target"): context("target-profile", "target"),
    }

    def resolve(expected: ConsentPairingContext) -> ConsentPairingContext:
        current = base[expected.client_credential_sha256]
        profile = preferences.get_profile_authority(expected.tenant_id, expected.profile_id)
        return replace(current, profile_revision=int(profile["revision"]))

    pairing = ConsentIdentityFederationStore(
        tmp_path / "pairing.sqlite3",
        preference_store_for=lambda tenant: preferences,
        context_resolver=resolve,
        clock=clock,
    )
    return clock, preferences, pairing, base


def verifier_for(*, subject: str = "oidc-user-123", mutation: str | None = None):
    def verify(token, expected):
        values = {
            "subject": subject,
            "issuer": expected.issuer,
            "audiences": (expected.audience,),
            "nonce": expected.nonce,
            "issued_at": expected.now - 10,
            "expires_at": expected.now + 120,
            "not_before": expected.now - 10,
            "key_id": "kid-2026-08",
            "token_sha256": digest(token),
        }
        if mutation == "issuer":
            values["issuer"] = "https://attacker.invalid"
        elif mutation == "audience":
            values["audiences"] = (expected.audience, "confused-deputy")
        elif mutation == "nonce":
            values["nonce"] = "wrong-nonce"
        elif mutation == "expired":
            values["expires_at"] = expected.now
        elif mutation == "kid":
            values["key_id"] = ""
        elif mutation == "token":
            values["token_sha256"] = digest("different")
        return VerifiedConsentOIDCClaims(**values)

    return verify


def test_settings_are_default_off_and_require_existing_parent_contract():
    assert not consent_identity_enabled({})
    assert not consent_identity_enabled(
        {"consent_preferences": {"enable": True, "identity": {"enable": True}}}
    )
    config = {
        "consent_preferences": {
            "enable": True,
            "publishing": {"enable": True},
            "public_api": {"enable": True},
            "identity": {
                "enable": True,
                "issuer": "https://id.example.test",
                "audience": "lightwork-consent",
                "jwks_origin": "https://keys.example.test",
                "token_ttl_seconds": 300,
            },
        }
    }
    assert consent_identity_enabled(config)
    assert load_consent_identity_settings(config) == settings()


def test_browser_to_service_pairing_links_through_existing_store_and_is_one_time(
    material,
):
    clock, preferences, pairing, base = material
    verifier = "v" * 64
    challenge = pairing.begin_pairing(
        base[digest("client:target")],
        code_challenge=pkce(verifier),
        ttl_seconds=300,
    )
    authorized = pairing.authorize_pairing(
        challenge.pairing_code,
        oidc_nonce=challenge.oidc_nonce,
        oidc_token="signed-oidc-token-not-persisted",
        source=base[digest("client:source")],
        settings=settings(),
        oidc_verifier=verifier_for(subject="raw-subject-not-persisted"),
        subject_digest_key=b"k" * 32,
    )
    assert authorized.status == "authorized"
    source = preferences.get_profile_authority("tenant-a", "source-profile")
    assert source["linked_known_profile_id"].startswith("CP-KNOWN-")

    redeemed = pairing.redeem_pairing(
        challenge.pairing_code,
        code_verifier=verifier,
        target=base[digest("client:target")],
    )
    assert redeemed.status == "redeemed"
    target = preferences.get_profile_authority("tenant-a", "target-profile")
    assert target["linked_known_profile_id"] == source["linked_known_profile_id"]
    target_context = replace(
        base[digest("client:target")],
        profile_revision=int(target["revision"]),
    )
    evidence = pairing.resolve_redeemed_identity_evidence(target_context)
    assert evidence.target_fingerprint == target_context.fingerprint
    assert evidence.valid_until == clock() + 120
    assert "raw-subject-not-persisted" not in repr(evidence)
    clock.value += 121
    with pytest.raises(ConsentIdentityFederationDenied, match="fresh identity"):
        pairing.resolve_redeemed_identity_evidence(target_context)
    revoked = pairing.revoke_pairing(
        challenge.pairing_code,
        authority=target_context,
        reason_sha256=digest("consumer-revoked-redeemed-proof"),
    )
    assert revoked["status"] == "revoked"
    with sqlite3.connect(pairing.path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM consent_identity_evidence_current"
        ).fetchone()[0] == 0
    with pytest.raises(ConsentIdentityFederationDenied):
        pairing.redeem_pairing(
            challenge.pairing_code,
            code_verifier=verifier,
            target=replace(base[digest("client:target")], profile_revision=1),
        )
    assert pairing.verify_integrity() == {"pairings_verified": 1, "events_verified": 5}

    stored = pairing.path.read_bytes()
    for forbidden in (
        b"signed-oidc-token-not-persisted",
        b"raw-subject-not-persisted",
        challenge.pairing_code.encode(),
        challenge.oidc_nonce.encode(),
        verifier.encode(),
    ):
        assert forbidden not in stored


@pytest.mark.parametrize("mutation", ["issuer", "audience", "nonce", "expired", "kid", "token"])
def test_verified_oidc_contract_fails_closed(material, mutation):
    _clock, _preferences, pairing, base = material
    verifier = "x" * 64
    challenge = pairing.begin_pairing(
        base[digest("client:target")],
        code_challenge=pkce(verifier),
        ttl_seconds=300,
    )
    with pytest.raises(ConsentIdentityFederationDenied):
        pairing.authorize_pairing(
            challenge.pairing_code,
            oidc_nonce=challenge.oidc_nonce,
            oidc_token="signed-token",
            source=base[digest("client:source")],
            settings=settings(),
            oidc_verifier=verifier_for(mutation=mutation),
            subject_digest_key=b"k" * 32,
        )


def test_non_ascii_nonce_claim_and_stored_digest_are_refused_not_type_errors(material):
    # The nonce claim comes from the presented IdP token and stored digests can
    # be edited; non-ASCII text in either must not raise TypeError from
    # hmac.compare_digest instead of the denial or integrity refusal.
    _clock, _preferences, pairing, base = material
    verifier = "n" * 64
    challenge = pairing.begin_pairing(
        base[digest("client:target")],
        code_challenge=pkce(verifier),
        ttl_seconds=300,
    )
    honest = verifier_for()

    def non_ascii_nonce(token, expected):
        return replace(honest(token, expected), nonce="é" * len(expected.nonce))

    with pytest.raises(ConsentIdentityFederationDenied):
        pairing.authorize_pairing(
            challenge.pairing_code,
            oidc_nonce=challenge.oidc_nonce,
            oidc_token="signed-token",
            source=base[digest("client:source")],
            settings=settings(),
            oidc_verifier=non_ascii_nonce,
            subject_digest_key=b"k" * 32,
        )
    with sqlite3.connect(pairing.path) as connection:
        connection.execute("UPDATE consent_identity_pairings SET record_sha256=?", ("é" * 64,))
    with pytest.raises(ConsentIdentityFederationIntegrityError):
        pairing.verify_integrity()


def test_drift_cross_tenant_expiry_and_revocation_fail_closed(material):
    clock, _preferences, pairing, base = material
    verifier = "z" * 64
    target = base[digest("client:target")]
    challenge = pairing.begin_pairing(target, code_challenge=pkce(verifier), ttl_seconds=60)

    with pytest.raises(ConsentIdentityFederationDenied):
        pairing.authorize_pairing(
            challenge.pairing_code,
            oidc_nonce=challenge.oidc_nonce,
            oidc_token="token",
            source=replace(base[digest("client:source")], tenant_id="tenant-b"),
            settings=settings(),
            oidc_verifier=verifier_for(),
            subject_digest_key=b"k" * 32,
        )

    base[digest("client:target")] = replace(target, client_revision=2)
    with pytest.raises(ConsentIdentityFederationConflict):
        pairing.authorize_pairing(
            challenge.pairing_code,
            oidc_nonce=challenge.oidc_nonce,
            oidc_token="token",
            source=base[digest("client:source")],
            settings=settings(),
            oidc_verifier=verifier_for(),
            subject_digest_key=b"k" * 32,
        )
    base[digest("client:target")] = target

    revoked = pairing.revoke_pairing(
        challenge.pairing_code,
        authority=target,
        reason_sha256=digest("consumer-cancelled"),
    )
    assert revoked["status"] == "revoked"
    with pytest.raises(ConsentIdentityFederationDenied):
        pairing.authorize_pairing(
            challenge.pairing_code,
            oidc_nonce=challenge.oidc_nonce,
            oidc_token="token",
            source=base[digest("client:source")],
            settings=settings(),
            oidc_verifier=verifier_for(),
            subject_digest_key=b"k" * 32,
        )

    expiring = pairing.begin_pairing(target, code_challenge=pkce(verifier), ttl_seconds=60)
    clock.value += 61
    with pytest.raises(ConsentIdentityFederationDenied):
        pairing.authorize_pairing(
            expiring.pairing_code,
            oidc_nonce=expiring.oidc_nonce,
            oidc_token="token",
            source=base[digest("client:source")],
            settings=settings(),
            oidc_verifier=verifier_for(),
            subject_digest_key=b"k" * 32,
        )
    assert pairing.verify_integrity()["pairings_verified"] == 2


def test_current_identity_pointer_cannot_be_starved_by_newer_revoked_pairings(material):
    _clock, preferences, pairing, base = material
    verifier = "p" * 64
    challenge = pairing.begin_pairing(
        base[digest("client:target")],
        code_challenge=pkce(verifier),
        ttl_seconds=300,
    )
    pairing.authorize_pairing(
        challenge.pairing_code,
        oidc_nonce=challenge.oidc_nonce,
        oidc_token="current-identity-token",
        source=base[digest("client:source")],
        settings=settings(),
        oidc_verifier=verifier_for(),
        subject_digest_key=b"k" * 32,
    )
    pairing.redeem_pairing(
        challenge.pairing_code,
        code_verifier=verifier,
        target=base[digest("client:target")],
    )
    target_revision = preferences.get_profile_authority(
        "tenant-a", "target-profile"
    )["revision"]
    target = replace(
        base[digest("client:target")],
        profile_revision=int(target_revision),
    )
    expected = pairing.resolve_redeemed_identity_evidence(target)

    for index in range(20):
        abandoned = pairing.begin_pairing(
            target,
            code_challenge=pkce(chr(ord("a") + index) * 64),
            ttl_seconds=60,
        )
        pairing.revoke_pairing(
            abandoned.pairing_code,
            authority=target,
            reason_sha256=digest(f"abandoned-{index}"),
        )

    assert pairing.resolve_redeemed_identity_evidence(target) == expected
    pairing.revoke_pairing(
        challenge.pairing_code,
        authority=target,
        reason_sha256=digest("revoke-current-proof"),
    )
    with pytest.raises(ConsentIdentityFederationDenied, match="fresh identity"):
        pairing.resolve_redeemed_identity_evidence(target)


def test_pairing_recovers_only_from_its_exact_partial_link(material, monkeypatch):
    _clock, preferences, pairing, base = material
    verifier = "r" * 64
    challenge = pairing.begin_pairing(
        base[digest("client:target")],
        code_challenge=pkce(verifier),
        ttl_seconds=300,
    )
    original_create = preferences.create_profile

    def interrupted_create(*_args, **_kwargs):
        raise RuntimeError("simulated interruption after verified state")

    monkeypatch.setattr(preferences, "create_profile", interrupted_create)
    with pytest.raises(RuntimeError, match="simulated interruption"):
        pairing.authorize_pairing(
            challenge.pairing_code,
            oidc_nonce=challenge.oidc_nonce,
            oidc_token="same-signed-token",
            source=base[digest("client:source")],
            settings=settings(),
            oidc_verifier=verifier_for(),
            subject_digest_key=b"k" * 32,
        )
    monkeypatch.setattr(preferences, "create_profile", original_create)
    recovered = pairing.authorize_pairing(
        challenge.pairing_code,
        oidc_nonce=challenge.oidc_nonce,
        oidc_token="same-signed-token",
        source=base[digest("client:source")],
        settings=settings(),
        oidc_verifier=verifier_for(),
        subject_digest_key=b"k" * 32,
    )
    assert recovered.status == "authorized"

    original_save = pairing._save_record

    def interrupted_save(connection, record, *, expected_revision, now):
        if record.get("status") == "redeemed":
            raise RuntimeError("simulated interruption after target link")
        return original_save(
            connection,
            record,
            expected_revision=expected_revision,
            now=now,
        )

    monkeypatch.setattr(pairing, "_save_record", interrupted_save)
    with pytest.raises(RuntimeError, match="simulated interruption"):
        pairing.redeem_pairing(
            challenge.pairing_code,
            code_verifier=verifier,
            target=base[digest("client:target")],
        )
    monkeypatch.setattr(pairing, "_save_record", original_save)
    target_revision = preferences.get_profile_authority("tenant-a", "target-profile")["revision"]
    recovered_redemption = pairing.redeem_pairing(
        challenge.pairing_code,
        code_verifier=verifier,
        target=replace(
            base[digest("client:target")],
            profile_revision=target_revision,
        ),
    )
    assert recovered_redemption.status == "redeemed"
    assert pairing.verify_integrity() == {"pairings_verified": 1, "events_verified": 4}


def test_injected_oidc_verifier_uses_exact_jwks_origin_and_kid_without_fetching(
    material,
):
    try:
        import jwt
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except Exception as exc:  # pragma: no cover - environment-dependent crypto
        pytest.skip(f"working cryptography/PyJWT unavailable: {type(exc).__name__}")

    clock, _preferences, pairing, base = material
    clock.value = time.time()
    verifier = "j" * 64
    challenge = pairing.begin_pairing(
        base[digest("client:target")],
        code_challenge=pkce(verifier),
        ttl_seconds=300,
    )
    private_key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    token = jwt.encode(
        {
            "sub": "verified-user",
            "iss": settings().issuer,
            "aud": settings().audience,
            "iat": int(clock.value) - 1,
            "exp": int(clock.value) + 120,
            "nonce": challenge.oidc_nonce,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "consent-key-1"},
    )
    resolutions = []

    def signing_key_for(origin, kid):
        resolutions.append((origin, kid))
        return public_pem

    result = pairing.authorize_pairing(
        challenge.pairing_code,
        oidc_nonce=challenge.oidc_nonce,
        oidc_token=token,
        source=base[digest("client:source")],
        settings=settings(),
        oidc_verifier=InjectedConsentOIDCVerifier(signing_key_for),
        subject_digest_key=b"k" * 32,
    )
    assert result.status == "authorized"
    assert resolutions == [("https://keys.example.test", "consent-key-1")]


def test_unlink_recovers_revokes_evidence_and_relink_needs_fresh_pairing(
    material,
    monkeypatch,
):
    _clock, preferences, pairing, base = material
    verifier = "u" * 64
    challenge = pairing.begin_pairing(
        base[digest("client:target")],
        code_challenge=pkce(verifier),
        ttl_seconds=300,
    )
    pairing.authorize_pairing(
        challenge.pairing_code,
        oidc_nonce=challenge.oidc_nonce,
        oidc_token="unlink-authority-token",
        source=base[digest("client:source")],
        settings=settings(),
        oidc_verifier=verifier_for(),
        subject_digest_key=b"k" * 32,
    )
    pairing.redeem_pairing(
        challenge.pairing_code,
        code_verifier=verifier,
        target=base[digest("client:target")],
    )
    authority = preferences.get_profile_authority("tenant-a", "target-profile")
    target = replace(
        base[digest("client:target")],
        profile_revision=int(authority["revision"]),
    )
    original_save = pairing._save_record
    interrupted = False

    def interrupt_finalize(connection, record, *, expected_revision, now):
        nonlocal interrupted
        if (
            not interrupted
            and record.get("status") == "revoked"
            and record.get("unlink_operation_key_sha256")
        ):
            interrupted = True
            raise RuntimeError("simulated interruption after core unlink")
        return original_save(
            connection,
            record,
            expected_revision=expected_revision,
            now=now,
        )

    monkeypatch.setattr(pairing, "_save_record", interrupt_finalize)
    with pytest.raises(RuntimeError, match="after core unlink"):
        pairing.unlink_current_identity(
            target,
            expected_profile_revision=target.profile_revision,
            expected_link_revision=int(authority["link_revision"]),
            idempotency_key="unlink-target-1",
            reason_sha256=digest("consumer-requested-unlink"),
            settings=settings(),
        )
    current = preferences.get_profile_authority("tenant-a", "target-profile")
    assert current["link_status"] == "unlinked"
    monkeypatch.setattr(pairing, "_save_record", original_save)
    recovered_target = replace(target, profile_revision=int(current["revision"]))
    recovered = pairing.unlink_current_identity(
        recovered_target,
        expected_profile_revision=target.profile_revision,
        expected_link_revision=int(authority["link_revision"]),
        idempotency_key="unlink-target-1",
        reason_sha256=digest("consumer-requested-unlink"),
        settings=settings(),
    )
    assert recovered["link_status"] == "unlinked"
    assert pairing.unlink_current_identity(
        recovered_target,
        expected_profile_revision=target.profile_revision,
        expected_link_revision=int(authority["link_revision"]),
        idempotency_key="unlink-target-1",
        reason_sha256=digest("consumer-requested-unlink"),
        settings=settings(),
    ) == recovered
    with pytest.raises(ConsentIdentityFederationConflict, match="rebound"):
        pairing.unlink_current_identity(
            recovered_target,
            expected_profile_revision=target.profile_revision,
            expected_link_revision=int(authority["link_revision"]),
            idempotency_key="unlink-target-1",
            reason_sha256=digest("different-reason"),
            settings=settings(),
        )
    with pytest.raises(ConsentIdentityFederationDenied, match="fresh identity"):
        pairing.resolve_redeemed_identity_evidence(recovered_target)

    fresh_verifier = "w" * 64
    fresh = pairing.begin_pairing(
        recovered_target,
        code_challenge=pkce(fresh_verifier),
        ttl_seconds=300,
    )
    source_authority = preferences.get_profile_authority("tenant-a", "source-profile")
    pairing.authorize_pairing(
        fresh.pairing_code,
        oidc_nonce=fresh.oidc_nonce,
        oidc_token="fresh-relink-authority-token",
        source=replace(
            base[digest("client:source")],
            profile_revision=int(source_authority["revision"]),
        ),
        settings=settings(),
        oidc_verifier=verifier_for(),
        subject_digest_key=b"k" * 32,
    )
    pairing.redeem_pairing(
        fresh.pairing_code,
        code_verifier=fresh_verifier,
        target=recovered_target,
    )
    history = preferences.get_profile_link_history("tenant-a", "target-profile")
    assert history["events"][0]["action"] == "relinked"
    assert preferences.get_profile_authority("tenant-a", "target-profile")[
        "link_status"
    ] == "linked"
