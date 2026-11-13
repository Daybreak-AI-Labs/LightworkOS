"""Focused governance tests for administration document access."""

from __future__ import annotations

import gc
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
from maverick import administration_document_access as access


class Clock:
    def __init__(self, value: float = 2_000_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def _config(**overrides):
    section = {
        "enable": True,
        "default_ttl_seconds": 30,
        "max_ttl_seconds": 120,
        "max_uses": 2,
        "delivery_grant_ttl_seconds": 10,
        "retention_seconds": 60,
    }
    section.update(overrides)
    return {"administration_document_access": section}


def _authority(
    tenant_id: str,
    principal_ref: str,
    document_ref: str,
    *,
    revision: int = 7,
    authority_sha256: str = "b" * 64,
    allowed: bool = True,
) -> access.DocumentAuthority:
    return access.DocumentAuthority(
        tenant_id=tenant_id,
        principal_ref=principal_ref,
        document_ref=document_ref,
        product_area="privacy_automation",
        record_type="incident_attachment",
        safe_display_name="incident evidence.pdf",
        media_type="application/pdf",
        byte_size=2_048,
        content_sha256="a" * 64,
        authority_revision=revision,
        authority_sha256=authority_sha256,
        download_allowed=allowed,
    )


def _service(tmp_path, *, clock=None, principal=None, state=None, issuer=None):
    selected_clock = clock or Clock()
    selected_principal = principal or {"value": "principal.alice"}
    resolver_state = state or {"revision": 7, "authority_sha256": "b" * 64, "allowed": True}
    resolver_calls = []
    issuer_calls = []

    def resolver(tenant_id, principal_ref, document_ref):
        resolver_calls.append((tenant_id, principal_ref, document_ref))
        return _authority(
            tenant_id,
            principal_ref,
            document_ref,
            revision=resolver_state["revision"],
            authority_sha256=resolver_state["authority_sha256"],
            allowed=resolver_state["allowed"],
        )

    def default_issuer(claim):
        issuer_calls.append(claim)
        return access.DeliveryGrant(
            grant="delivery_grant_" + "g" * 40,
            expires_at=claim.grant_expires_at,
        )

    store = access.DocumentAccessStore(
        tmp_path / "document-access.sqlite3",
        tenant_id="tenant-a",
        clock=selected_clock,
    )
    service = access.DocumentAccessService(
        store=store,
        config=access.require_enabled(_config()),
        principal_resolver=lambda: selected_principal["value"],
        document_resolver=resolver,
        delivery_grant_issuer=issuer or default_issuer,
        clock=selected_clock,
    )
    return service, selected_clock, selected_principal, resolver_state, resolver_calls, issuer_calls


def test_exact_default_off_gate_and_closed_versioned_catalog():
    assert access.enabled({}) is False
    assert access.enabled({"administration_document_access": {"enable": False}}) is False
    assert access.enabled({"administration_document_access": {"enable": "true"}}) is False
    assert access.enabled({"administration_document_access": {"enable": 1}}) is False
    assert access.enabled(_config()) is True
    assert access.enabled(_config(unexpected=True)) is False
    with pytest.raises(access.DocumentAccessConfigError, match="disabled"):
        access.require_enabled({})

    catalog = access.list_event_types()
    assert isinstance(catalog, tuple)
    assert len(catalog) == len({item.event_type for item in catalog})
    assert {item.catalog_version for item in catalog} == {access.CATALOG_VERSION}
    token_events = access.list_event_types(
        product_area="administration",
        record_type="document_download_token",
    )
    assert token_events
    assert all(item.record_type == "document_download_token" for item in token_events)
    attachment_events = access.list_event_types(record_type="document_attachment")
    assert {item.event_type for item in attachment_events} == {
        "administration.document_attachment.delivery_grant_issued",
        "administration.document_attachment.delivery_grant_failed",
    }
    privacy_events = access.list_event_types(
        product_area="privacy_automation",
        record_type="normalized_audit_record",
    )
    assert {item.event_type for item in privacy_events} == {
        "privacy_automation.normalized_audit.request_submitted",
        "privacy_automation.normalized_audit.status_changed",
    }
    assert not hasattr(access, "register_event_type")


def test_mint_returns_raw_once_and_persists_no_raw_or_filename(tmp_path):
    service, _clock, _principal, _state, resolver_calls, _issuer_calls = _service(tmp_path)
    minted = service.mint_token(
        "doc-123",
        ttl_seconds=45,
        max_uses=2,
        idempotency_key="mint-1",
    )
    assert minted.download_token is not None
    assert minted.download_token.startswith("lwddt_v1_")
    assert minted.record.document_ref == "doc-123"
    assert minted.record.product_area == "privacy_automation"
    assert minted.record.record_type == "incident_attachment"
    assert minted.record.content_sha256 == "a" * 64
    assert minted.record.expires_at - minted.record.issued_at == 45
    assert resolver_calls == [("tenant-a", "principal.alice", "doc-123")]

    replay = service.mint_token(
        "doc-123",
        ttl_seconds=45,
        max_uses=2,
        idempotency_key="mint-1",
    )
    assert replay.record.token_id == minted.record.token_id
    assert replay.download_token is None
    assert replay.idempotent_replay is True
    assert len(resolver_calls) == 1

    database_bytes = service.store.path.read_bytes()
    assert minted.download_token.encode() not in database_bytes
    assert b"incident evidence.pdf" not in database_bytes
    with pytest.raises(access.DocumentAccessConflict, match="idempotency_conflict"):
        service.mint_token("doc-456", idempotency_key="mint-1")


@pytest.mark.parametrize(
    "document_ref", ["../secret", "folder/file", r"folder\file", "C:secret", ".."]
)
def test_caller_cannot_submit_paths_or_locators(tmp_path, document_ref):
    service, *_rest = _service(tmp_path)
    with pytest.raises(access.DocumentAccessValidationError, match="document_ref_invalid"):
        service.mint_token(document_ref, idempotency_key="mint-path")


def test_claim_is_principal_bound_one_use_and_returns_only_opaque_grant(tmp_path):
    service, _clock, _principal, _state, _resolver_calls, issuer_calls = _service(tmp_path)
    minted = service.mint_token("doc-claim", idempotency_key="mint-claim")
    raw_token = minted.download_token
    assert raw_token is not None

    result = service.claim(raw_token, idempotency_key="claim-1")
    assert result == access.ClaimedDeliveryGrant(
        delivery_grant="delivery_grant_" + "g" * 40,
        expires_at=minted.record.issued_at + 10,
    )
    assert len(issuer_calls) == 1
    claim = issuer_calls[0]
    assert claim.tenant_id == "tenant-a"
    assert claim.principal_ref == "principal.alice"
    assert claim.document_ref == "doc-claim"
    assert claim.safe_display_name == "incident evidence.pdf"
    assert service.get_token(minted.record.token_id).state == "exhausted"

    with pytest.raises(access.DocumentAccessConflict, match="claim_replay"):
        service.claim(raw_token, idempotency_key="claim-1")
    with pytest.raises(access.DocumentAccessConflict, match="token_not_active"):
        service.claim(raw_token, idempotency_key="claim-2")
    database_bytes = service.store.path.read_bytes()
    assert raw_token.encode() not in database_bytes
    assert result.delivery_grant.encode() not in database_bytes


def test_cross_principal_claim_is_denied_before_resolver_or_issuer(tmp_path):
    principal = {"value": "principal.alice"}
    service, _clock, _principal, _state, resolver_calls, issuer_calls = _service(
        tmp_path,
        principal=principal,
    )
    minted = service.mint_token("doc-principal", idempotency_key="mint-principal")
    principal["value"] = "principal.mallory"
    with pytest.raises(access.DocumentAccessPermissionDenied, match="principal_mismatch"):
        service.claim(minted.download_token or "", idempotency_key="claim-principal")
    assert len(resolver_calls) == 1
    assert issuer_calls == []


def test_cross_tenant_store_cannot_redeem_token(tmp_path):
    service, *_rest = _service(tmp_path / "tenant-a")
    minted = service.mint_token("doc-tenant", idempotency_key="mint-tenant")
    issuer_calls = []

    def resolver(tenant_id, principal_ref, document_ref):
        return _authority(tenant_id, principal_ref, document_ref)

    def issuer(claim):
        issuer_calls.append(claim)
        return access.DeliveryGrant(
            "cross_tenant_grant_" + "x" * 40,
            claim.grant_expires_at,
        )

    other_store = access.DocumentAccessStore(
        tmp_path / "tenant-b" / "document-access.sqlite3",
        tenant_id="tenant-b",
    )
    other_service = access.DocumentAccessService(
        store=other_store,
        config=access.require_enabled(_config()),
        principal_resolver=lambda: "principal.alice",
        document_resolver=resolver,
        delivery_grant_issuer=issuer,
    )
    with pytest.raises(access.DocumentAccessNotFound):
        other_service.claim(
            minted.download_token or "",
            idempotency_key="claim-other-tenant",
        )
    assert issuer_calls == []


def test_concurrent_single_use_claim_has_one_cas_winner(tmp_path):
    service, *_rest = _service(tmp_path)
    minted = service.mint_token("doc-cas", idempotency_key="mint-cas")
    raw_token = minted.download_token or ""

    def claim(index):
        try:
            result = service.claim(raw_token, idempotency_key=f"claim-cas-{index}")
            return ("issued", result.delivery_grant)
        except access.DocumentAccessConflict as exc:
            return ("conflict", str(exc))

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(claim, range(2)))
    assert [outcome[0] for outcome in outcomes].count("issued") == 1
    assert [outcome[0] for outcome in outcomes].count("conflict") == 1
    record = service.get_token(minted.record.token_id)
    assert record.state == "exhausted"
    assert record.claim_count == 1


def test_authority_drift_revokes_before_delivery(tmp_path):
    service, _clock, _principal, resolver_state, _resolver_calls, issuer_calls = _service(tmp_path)
    minted = service.mint_token("doc-drift", idempotency_key="mint-drift")
    resolver_state["revision"] = 8
    resolver_state["authority_sha256"] = "c" * 64
    with pytest.raises(access.DocumentAccessConflict, match="authority_changed"):
        service.claim(minted.download_token or "", idempotency_key="claim-drift")
    assert service.get_token(minted.record.token_id).state == "revoked"
    assert issuer_calls == []
    assert any(
        event["event_type"] == "administration.document_download_token.authority_invalidated"
        for event in service.store.list_audit()
    )


def test_authoritative_download_denial_revokes_before_delivery(tmp_path):
    service, _clock, _principal, resolver_state, _resolver_calls, issuer_calls = _service(tmp_path)
    minted = service.mint_token("doc-denied", idempotency_key="mint-denied")
    resolver_state["allowed"] = False
    with pytest.raises(access.DocumentAccessPermissionDenied, match="not_authorized"):
        service.claim(minted.download_token or "", idempotency_key="claim-denied")
    assert service.get_token(minted.record.token_id).state == "revoked"
    assert issuer_calls == []


def test_expiry_is_persisted_and_replay_is_rejected(tmp_path):
    clock = Clock()
    service, *_rest = _service(tmp_path, clock=clock)
    minted = service.mint_token(
        "doc-expiry",
        ttl_seconds=30,
        idempotency_key="mint-expiry",
    )
    clock.advance(31)
    with pytest.raises(access.DocumentAccessExpired, match="token_expired"):
        service.claim(minted.download_token or "", idempotency_key="claim-expiry")
    expired = service.get_token(minted.record.token_id)
    assert expired.state == "expired"
    assert expired.revision == 2
    with pytest.raises(access.DocumentAccessConflict, match="token_not_active"):
        service.claim(minted.download_token or "", idempotency_key="claim-expiry-2")


def test_revoke_uses_cas_and_idempotency(tmp_path):
    service, *_rest = _service(tmp_path)
    minted = service.mint_token("doc-revoke", idempotency_key="mint-revoke")
    revoked = service.revoke_token(
        minted.record.token_id,
        expected_revision=1,
        idempotency_key="revoke-1",
    )
    assert revoked.state == "revoked"
    assert revoked.revision == 2
    replay = service.revoke_token(
        minted.record.token_id,
        expected_revision=1,
        idempotency_key="revoke-1",
    )
    assert replay == revoked
    with pytest.raises(access.DocumentAccessConflict, match="revision_conflict"):
        service.revoke_token(
            minted.record.token_id,
            expected_revision=1,
            idempotency_key="revoke-2",
        )


def test_failed_issuer_gives_the_reserved_use_back_and_is_idempotent(tmp_path):
    failures = {"remaining": 1}

    def issuer(claim):
        if failures["remaining"]:
            failures["remaining"] -= 1
            raise RuntimeError("object store unavailable: sensitive detail")
        return access.DeliveryGrant(
            grant="second_delivery_grant_" + "z" * 40,
            expires_at=claim.grant_expires_at,
        )

    service, *_rest = _service(tmp_path, issuer=issuer)
    # The default single-use token must survive a transient issuer outage.
    minted = service.mint_token("doc-retry", idempotency_key="mint-retry")
    with pytest.raises(access.DocumentAccessConfigError, match="issuer_unavailable"):
        service.claim(minted.download_token or "", idempotency_key="claim-failed")
    after_failure = service.get_token(minted.record.token_id)
    assert after_failure.state == "active"
    assert after_failure.uses_remaining == 1
    assert after_failure.claim_count == 0
    with pytest.raises(access.DocumentAccessConflict, match="claim_replay"):
        service.claim(minted.download_token or "", idempotency_key="claim-failed")
    result = service.claim(minted.download_token or "", idempotency_key="claim-second")
    assert result.delivery_grant.startswith("second_delivery_grant_")
    assert service.get_token(minted.record.token_id).state == "exhausted"
    assert service.store.verify_integrity()["ok"] is True


def test_retention_purge_leaves_integrity_checked_tombstone(tmp_path):
    clock = Clock()
    service, *_rest = _service(tmp_path, clock=clock)
    minted = service.mint_token("doc-purge", idempotency_key="mint-purge")
    revoked = service.revoke_token(
        minted.record.token_id,
        expected_revision=1,
        idempotency_key="revoke-purge",
    )
    with pytest.raises(access.DocumentAccessConflict, match="retention_not_elapsed"):
        service.purge_token(
            revoked.token_id,
            expected_revision=revoked.revision,
            idempotency_key="purge-1",
        )
    clock.advance(61)
    tombstone = service.purge_token(
        revoked.token_id,
        expected_revision=revoked.revision,
        idempotency_key="purge-1",
    )
    replay = service.purge_token(
        revoked.token_id,
        expected_revision=revoked.revision,
        idempotency_key="purge-1",
    )
    assert replay == tombstone
    with pytest.raises(access.DocumentAccessNotFound):
        service.get_token(revoked.token_id)
    with pytest.raises(access.DocumentAccessConflict, match="retention_purged"):
        service.mint_token("doc-purge", idempotency_key="mint-purge")
    integrity = service.store.verify_integrity()
    assert integrity["ok"] is True
    assert integrity["token_count"] == 0
    assert integrity["tombstone_count"] == 1


def test_integrity_verification_detects_token_tampering(tmp_path):
    service, *_rest = _service(tmp_path)
    minted = service.mint_token("doc-tamper", idempotency_key="mint-tamper")
    with sqlite3.connect(service.store.path) as connection:
        connection.execute(
            "UPDATE document_download_tokens SET content_sha256=? WHERE token_id=?",
            ("f" * 64, minted.record.token_id),
        )
    with pytest.raises(access.DocumentAccessIntegrityError, match="token_integrity"):
        service.store.verify_integrity()


def test_non_ascii_stored_digests_are_integrity_errors_not_type_errors(tmp_path):
    # Edited ledger digests must not raise TypeError from hmac.compare_digest
    # on the request paths instead of the store's integrity refusal.
    service, *_rest = _service(tmp_path)
    minted = service.mint_token("doc-non-ascii", idempotency_key="mint-non-ascii")
    with sqlite3.connect(service.store.path) as connection:
        connection.execute(
            "UPDATE document_access_operations SET integrity_sha256=?", ("é" * 64,)
        )
    with pytest.raises(access.DocumentAccessIntegrityError, match="operation_integrity"):
        service.mint_token("doc-non-ascii", idempotency_key="mint-non-ascii")
    with sqlite3.connect(service.store.path) as connection:
        connection.execute("UPDATE document_access_meta SET tenant_sha256=?", ("é" * 64,))
    with pytest.raises(access.DocumentAccessIntegrityError, match="metadata_invalid"):
        service.get_token(minted.record.token_id)


def test_resolver_cannot_return_cross_tenant_or_unsafe_display_name(tmp_path):
    clock = Clock()
    store = access.DocumentAccessStore(
        tmp_path / "invalid-authority.sqlite3",
        tenant_id="tenant-a",
        clock=clock,
    )

    def wrong_tenant(_tenant, principal, document_ref):
        return _authority("tenant-b", principal, document_ref)

    service = access.DocumentAccessService(
        store=store,
        config=access.require_enabled(_config()),
        principal_resolver=lambda: "principal.alice",
        document_resolver=wrong_tenant,
        delivery_grant_issuer=lambda claim: access.DeliveryGrant(
            "grant_" + "x" * 40,
            claim.grant_expires_at,
        ),
        clock=clock,
    )
    with pytest.raises(access.DocumentAccessPermissionDenied, match="binding_mismatch"):
        service.mint_token("doc-wrong-tenant", idempotency_key="mint-wrong")

    authority = _authority("tenant-a", "principal.alice", "doc-name")
    with pytest.raises(access.DocumentAccessValidationError, match="display_name_invalid"):
        replace(authority, safe_display_name="../secret.pdf")


def _assert_closed(connections):
    for connection in connections:
        with pytest.raises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")


def test_every_store_connection_is_closed_when_its_call_returns(tmp_path, monkeypatch):
    # CPython 3.12 keeps an unclosed sqlite3 connection alive until a cyclic GC pass,
    # so GC is disabled here: any connection left open by a call stays open.
    opened = []
    real_connect = sqlite3.connect
    fail_pragma = {"on": True}

    class _PragmaFails(sqlite3.Connection):
        def execute(self, sql, *args):
            if sql == "PRAGMA foreign_keys=ON" and fail_pragma["on"]:
                raise sqlite3.OperationalError("pragma failed")
            return super().execute(sql, *args)

    def recording_connect(*args, **kwargs):
        connection = real_connect(*args, factory=_PragmaFails, **kwargs)
        opened.append(connection)
        return connection

    monkeypatch.setattr(access.sqlite3, "connect", recording_connect)
    gc.disable()
    try:
        with pytest.raises(access.DocumentAccessError):
            _service(tmp_path)
        fail_pragma["on"] = False
        before = len(opened)
        service, *_ = _service(tmp_path)
        assert len(opened) > before, "__init__"
        _assert_closed(opened[before:])
        before = len(opened)
        minted = service.mint_token("doc-123", idempotency_key="mint-close-1")
        assert len(opened) > before, "mint_token"
        _assert_closed(opened[before:])
        calls = [
            # A repeated mint reads the operation log through find_mint_replay.
            ("mint_token", lambda: service.mint_token("doc-123", idempotency_key="mint-close-1")),
            ("get_token", lambda: service.get_token(minted.record.token_id)),
            ("list_tokens", service.list_tokens),
            ("claim", lambda: service.claim(minted.download_token, idempotency_key="claim-close-1")),
            ("list_audit", service.store.list_audit),
            ("status", service.status),
            ("verify_integrity", service.store.verify_integrity),
        ]
        for name, call in calls:
            before = len(opened)
            call()
            assert len(opened) > before, name
            _assert_closed(opened[before:])
    finally:
        gc.enable()
    _assert_closed(opened)
