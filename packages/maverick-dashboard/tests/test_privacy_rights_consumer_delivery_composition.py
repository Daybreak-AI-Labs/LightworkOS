from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from maverick import administration_document_access as document_access
from maverick import privacy_rights_consumer_delivery as delivery
from maverick_dashboard import privacy_rights_consumer_delivery_composition as composition
from starlette.requests import Request

NOW = 2_100_000_000.0
TENANT = "tenant-a"
SUBJECT = hashlib.sha256(b"tenant-a:consumer").hexdigest()
CONTENT = b'{"records":[{"id":"redacted"}]}'
PACKAGE_SHA256 = hashlib.sha256(CONTENT).hexdigest()


@dataclass(frozen=True)
class Case:
    tenant_id: str = TENANT
    case_id: str = "case-access"
    subject_sha256: str = SUBJECT
    revision: int = 8
    integrity_sha256: str = "a" * 64
    identity_status: str = "verified"
    identity_evidence_sha256: str = "d" * 64
    status: str = "closed"
    closure_approved_by: str = "reviewer"
    closed_by: str = "opener"
    rights: tuple[str, ...] = ("access",)
    retained_until: float = NOW + 1_200


@dataclass(frozen=True)
class Package:
    tenant_id: str = TENANT
    package_id: str = "package-access"
    case_id: str = "case-access"
    object_ref: str = "doc-rights-package"
    package_sha256: str = PACKAGE_SHA256
    encryption_key_ref: str = "env:MAVERICK_ENCRYPTION_KEY"
    expires_at: float = NOW + 600
    delivery_performed: bool = False
    integrity_sha256: str = "b" * 64


@dataclass(frozen=True)
class Document:
    document_ref: str = "doc-rights-package"
    product_area: str = "privacy_automation"
    record_type: str = "privacy_rights_source_retrieval"
    safe_display_name: str = "privacy-rights-package.json"
    media_type: str = "application/json"
    byte_size: int = len(CONTENT)
    content_sha256: str = PACKAGE_SHA256
    authority_revision: int = 3
    authority_sha256: str = "c" * 64
    state: str = "active"


class FakeOrchestration:
    def __init__(self) -> None:
        self.case = Case()
        self.package = Package()
        self.reads = 0

    def get_case(self, tenant_id: str, case_id: str) -> Case:
        assert tenant_id == TENANT
        assert case_id == self.case.case_id
        self.reads += 1
        return replace(self.case)

    def get_response_package(self, tenant_id: str, package_id: str) -> Package:
        assert tenant_id == TENANT
        assert package_id == self.package.package_id
        self.reads += 1
        return replace(self.package)


class FakeVault:
    def __init__(self) -> None:
        self.document = Document()
        self.get_calls = 0
        self.revoke_after_get: int | None = None
        self.issued: document_access.DeliveryClaim | None = None

    def get(self, document_ref: str) -> Document:
        assert document_ref == self.document.document_ref
        self.get_calls += 1
        if (
            self.revoke_after_get is not None
            and self.get_calls > self.revoke_after_get
        ):
            return replace(self.document, state="revoked", authority_revision=4)
        return replace(self.document)

    def issue_delivery_grant(
        self,
        claim: document_access.DeliveryClaim,
    ) -> document_access.DeliveryGrant:
        assert claim.document_ref == self.document.document_ref
        assert claim.content_sha256 == self.document.content_sha256
        assert claim.authority_revision == self.document.authority_revision
        assert claim.authority_sha256 == self.document.authority_sha256
        self.issued = claim
        return document_access.DeliveryGrant(
            grant="lwdvg_v1_" + "g" * 43,
            expires_at=NOW + 20,
        )

    def consume_delivery_grant(self, raw_grant: str, *, principal_ref: str):
        assert raw_grant == "lwdvg_v1_" + "g" * 43
        assert self.issued is not None
        assert principal_ref == self.issued.principal_ref
        return SimpleNamespace(
            document_ref=self.document.document_ref,
            content_sha256=self.document.content_sha256,
            content=CONTENT,
        )


def config() -> dict:
    return {
        "privacy_automation": {
            "enable": True,
            "rights_orchestration": {"enable": True},
            "rights_consumer_delivery": {
                "enable": True,
                "digest_key_ref": (
                    "env:MAVERICK_PRIVACY_RIGHTS_DELIVERY_DIGEST_KEY"
                ),
                "export_signing_key_ref": (
                    "env:MAVERICK_PRIVACY_RIGHTS_DELIVERY_EXPORT_KEY"
                ),
                "package_encryption_key_ref": "env:MAVERICK_ENCRYPTION_KEY",
                "server_grant_ttl_seconds": 30,
                "max_package_bytes": 16_777_216,
            },
        },
        "governed_document_vault": {"enable": True},
    }


def request_for(app: FastAPI) -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 1234),
            "server": ("127.0.0.1", 80),
            "app": app,
        }
    )


def public_authority() -> object:
    return SimpleNamespace(
        binding=SimpleNamespace(
            tenant_id=TENANT,
            property_id="property-one",
            record_sha256="e" * 64,
        ),
        profile=SimpleNamespace(
            profile_id="profile-one",
            binding_sha256="f" * 64,
            subject_binding_sha256=SUBJECT,
        ),
    )


@pytest.fixture()
def runtime(tmp_path: Path):
    app = FastAPI()
    orchestration = FakeOrchestration()
    vault = FakeVault()
    app.state.privacy_rights_consumer_delivery_config_factory = (
        lambda **_kwargs: config()
    )
    app.state.privacy_rights_consumer_delivery_path_factory = (
        lambda **_kwargs: tmp_path / "rights-delivery.sqlite3"
    )
    app.state.privacy_rights_consumer_delivery_orchestration_store_factory = (
        lambda **_kwargs: orchestration
    )
    app.state.privacy_rights_consumer_delivery_vault_store_factory = (
        lambda **_kwargs: vault
    )
    app.state.privacy_rights_consumer_delivery_key_resolver = (
        lambda **_kwargs: b"k" * 32
    )
    app.state.privacy_rights_consumer_delivery_clock = lambda: NOW
    composition.attach_privacy_rights_consumer_delivery_composition(app)
    return app, orchestration, vault, tmp_path


def test_attach_is_lazy_and_operator_identity_mapping_stays_fail_closed(
    tmp_path: Path,
) -> None:
    app = FastAPI()
    app.state.privacy_rights_consumer_delivery_config_factory = (
        lambda **_kwargs: config()
    )
    app.state.privacy_rights_consumer_delivery_path_factory = (
        lambda **_kwargs: tmp_path / "not-opened.sqlite3"
    )
    app.state.privacy_rights_consumer_delivery_key_resolver = (
        lambda **_kwargs: b"k" * 32
    )
    composition.attach_privacy_rights_consumer_delivery_composition(app)

    assert not (tmp_path / "not-opened.sqlite3").exists()
    status = composition.readiness(app, TENANT)
    assert status["status_probe_opened_tenant_storage"] is False
    assert status["status_probe_resolved_secret_value"] is False
    assert status["identity_inferred_from_package"] is False
    assert status["operator_subject_mapping_ready"] is False
    assert status["operator_mint_ready"] is False
    with pytest.raises(
        composition.PrivacyRightsConsumerDeliveryCompositionError,
        match="independent operator-to-consumer",
    ):
        app.state.privacy_rights_consumer_delivery_store_factory(
            tenant_id=TENANT,
            principal_ref="operator-one",
            principal_resolver=lambda: "operator-one",
            request=request_for(app),
        )
    assert not (tmp_path / "not-opened.sqlite3").exists()


def test_public_store_and_stock_vault_adapter_deliver_exact_pinned_bytes(runtime) -> None:
    app, orchestration, vault, _tmp_path = runtime
    request = request_for(app)
    store = app.state.rights_consumer_delivery_store_factory(
        tenant_id=TENANT,
        consumer_subject_binding_sha256=SUBJECT,
        public_authority_resolver=public_authority,
        request=request,
    )
    minted = store.mint_delivery(
        TENANT,
        "case-access",
        "package-access",
        "delivery-one",
        reauthentication_receipt_sha256="9" * 64,
        ttl_seconds=60,
        retained_until=NOW + 500,
        idempotency_key="mint-delivery-one",
    )
    assert minted.capability is not None
    server_grant = store.redeem(
        minted.capability,
        reauthentication_receipt_sha256="9" * 64,
        request_context_sha256="8" * 64,
    )
    claimed = store.claim_server_grant(server_grant)

    download = app.state.rights_package_delivery_adapter(
        claimed_grant=claimed,
        request=request,
    )

    assert download.content == CONTENT
    assert download.package_sha256 == PACKAGE_SHA256
    assert vault.issued is not None
    assert vault.get_calls >= 6
    assert orchestration.reads >= 12


def test_stock_adapter_discards_bytes_when_vault_is_revoked_between_reads(runtime) -> None:
    app, _orchestration, vault, _tmp_path = runtime
    request = request_for(app)
    store = app.state.rights_consumer_delivery_store_factory(
        tenant_id=TENANT,
        consumer_subject_binding_sha256=SUBJECT,
        public_authority_resolver=public_authority,
        request=request,
    )
    minted = store.mint_delivery(
        TENANT,
        "case-access",
        "package-access",
        "delivery-drift",
        reauthentication_receipt_sha256="9" * 64,
        ttl_seconds=60,
        retained_until=NOW + 500,
        idempotency_key="mint-delivery-drift",
    )
    server_grant = store.redeem(
        minted.capability or "",
        reauthentication_receipt_sha256="9" * 64,
        request_context_sha256="7" * 64,
    )
    claimed = store.claim_server_grant(server_grant)
    vault.get_calls = 0
    vault.revoke_after_get = 2

    with pytest.raises(delivery.RightsConsumerDeliveryDenied):
        app.state.rights_package_delivery_adapter(
            claimed_grant=claimed,
            request=request,
        )


def test_reauthentication_requires_strict_independent_evidence_and_rereads_public(runtime) -> None:
    app, _orchestration, _vault, _tmp_path = runtime
    request = request_for(app)
    calls = 0

    def public_resolver() -> object:
        nonlocal calls
        calls += 1
        return public_authority()

    with pytest.raises(
        composition.PrivacyRightsConsumerDeliveryCompositionError,
        match="independent consumer reauthentication",
    ):
        app.state.rights_reauthentication_resolver(
            raw_receipt="reauthentication-one",
            tenant_id=TENANT,
            property_id="property-one",
            profile_binding_sha256="f" * 64,
            public_authority_resolver=public_resolver,
            request=request,
        )

    def verifier(**kwargs):
        assert kwargs["public_snapshot"].subject_binding_sha256 == SUBJECT
        return composition.VerifiedRightsReauthentication(
            tenant_id=TENANT,
            property_id="property-one",
            profile_binding_sha256="f" * 64,
            receipt_sha256=hashlib.sha256(
                b"reauthentication-one"
            ).hexdigest(),
            identity_authority_sha256="6" * 64,
            assurance_level="aal2",
            verified_at=NOW - 1,
            valid_until=NOW + 60,
        )

    app.state.privacy_rights_consumer_delivery_reauthentication_verifier = verifier
    digest = app.state.rights_reauthentication_resolver(
        raw_receipt="reauthentication-one",
        tenant_id=TENANT,
        property_id="property-one",
        profile_binding_sha256="f" * 64,
        public_authority_resolver=public_resolver,
        request=request,
    )
    assert digest == hashlib.sha256(b"reauthentication-one").hexdigest()
    assert calls >= 3
    status = composition.readiness(app, TENANT)
    assert status["public_delivery_ready"] is True
    assert status["operator_mint_ready"] is False


def test_package_key_and_config_drift_fail_closed(runtime) -> None:
    app, orchestration, _vault, _tmp_path = runtime
    request = request_for(app)
    store = app.state.rights_consumer_delivery_store_factory(
        tenant_id=TENANT,
        consumer_subject_binding_sha256=SUBJECT,
        public_authority_resolver=public_authority,
        request=request,
    )
    orchestration.package = replace(
        orchestration.package,
        encryption_key_ref="env:OTHER_PACKAGE_KEY",
    )
    with pytest.raises(delivery.RightsConsumerDeliveryDenied):
        store.mint_delivery(
            TENANT,
            "case-access",
            "package-access",
            "delivery-key-drift",
            reauthentication_receipt_sha256="9" * 64,
            ttl_seconds=60,
            retained_until=NOW + 500,
            idempotency_key="mint-delivery-key-drift",
        )


def test_stock_key_resolution_refuses_vault_and_secret_references(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Without an installed resolver only env: resolves; the other schemes
    # must not be read as if they named an environment variable.
    monkeypatch.setenv("DELIVERY_KEY", "k" * 40)
    app = SimpleNamespace(state=SimpleNamespace())
    for ref in ("vault:DELIVERY_KEY", "secret:DELIVERY_KEY"):
        with pytest.raises(
            composition.PrivacyRightsConsumerDeliveryCompositionError,
            match="not supported",
        ):
            composition._resolve_key(
                app, tenant_id="tenant-a", key_ref=ref, expected_ref=ref, purpose="digest"
            )
        assert composition._reference_ready(app, ref, "digest") is False
    assert composition._resolve_key(
        app,
        tenant_id="tenant-a",
        key_ref="env:DELIVERY_KEY",
        expected_ref="env:DELIVERY_KEY",
        purpose="digest",
    ) == b"k" * 40
