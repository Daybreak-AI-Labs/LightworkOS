from __future__ import annotations

import hashlib
import inspect
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest
from maverick import privacy_rights_consumer_delivery as delivery
from maverick import privacy_rights_orchestration as rights


class MutableClock:
    def __init__(self, value: float = 2_100_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def token(prefix: str, value: int) -> str:
    return f"{prefix}.{value:043d}"


class PublicRightsAuthority:
    """Only the two public methods allowed by the delivery resolver."""

    def __init__(self, clock: MutableClock) -> None:
        self.clock = clock
        self.cases: dict[tuple[str, str], rights.RightsCase] = {}
        self.packages: dict[tuple[str, str], rights.ResponsePackage] = {}
        self.calls: list[tuple[str, str, str]] = []

    def add_ready(
        self,
        tenant: str,
        *,
        case_id: str = "case:access",
        package_id: str = "package:access",
        subject_sha256: str | None = None,
        object_ref: str = "encrypted-object:secret-locator",
        encryption_key_ref: str = "vault:secret-package-key",
    ) -> tuple[rights.RightsCase, rights.ResponsePackage]:
        subject = subject_sha256 or digest(f"subject:{tenant}")
        case = rights.RightsCase(
            tenant_id=tenant,
            case_id=case_id,
            request_version=1,
            external_request_sha256=digest(f"external:{tenant}"),
            subject_sha256=subject,
            rights=("access",),
            identity_status="verified",
            identity_evidence_sha256=digest(f"identity:{tenant}"),
            identity_evidence_ref="identity:evidence",
            legal_hold=False,
            legal_hold_evidence_sha256=None,
            legal_hold_evidence_ref=None,
            retention_blocks_deletion=False,
            retention_rule_ref=None,
            retention_evidence_sha256=None,
            status="closed",
            retained_until=self.clock() + 1_200,
            opened_by="operator",
            closure_approved_by="reviewer",
            closed_by="operator",
            revision=8,
            created_at=self.clock() - 60,
            updated_at=self.clock(),
            integrity_sha256=digest(f"case-record:{tenant}"),
        )
        package = rights.ResponsePackage(
            tenant_id=tenant,
            package_id=package_id,
            case_id=case_id,
            object_ref=object_ref,
            package_sha256=digest(f"package-bytes:{tenant}"),
            encryption_key_ref=encryption_key_ref,
            expires_at=self.clock() + 600,
            delivery_performed=False,
            created_by="operator",
            created_at=self.clock(),
            integrity_sha256=digest(f"package-record:{tenant}"),
        )
        self.cases[(tenant, case_id)] = case
        self.packages[(tenant, package_id)] = package
        return case, package

    def get_case(self, tenant_id: str, case_id: str) -> rights.RightsCase:
        self.calls.append(("get_case", tenant_id, case_id))
        try:
            return self.cases[(tenant_id, case_id)]
        except KeyError as exc:
            raise rights.PrivacyRightsNotFound("case unavailable") from exc

    def get_response_package(self, tenant_id: str, package_id: str) -> rights.ResponsePackage:
        self.calls.append(("get_response_package", tenant_id, package_id))
        try:
            return self.packages[(tenant_id, package_id)]
        except KeyError as exc:
            raise rights.PrivacyRightsNotFound("package unavailable") from exc


class Harness:
    def __init__(self, tmp_path: Path, *, fixed_capability: bool = False) -> None:
        self.clock = MutableClock()
        self.actor = {"value": "operator@example.test"}
        self.consumer = {"value": digest("subject:tenant-a")}
        self.authority = PublicRightsAuthority(self.clock)
        self.authority.add_ready("tenant-a")
        self.authority.add_ready("tenant-b")
        self.capability_counter = 0
        self.grant_counter = 0

        def next_capability() -> str:
            if fixed_capability:
                return token("lwrcd1", 1)
            self.capability_counter += 1
            return token("lwrcd1", self.capability_counter)

        def next_grant() -> str:
            self.grant_counter += 1
            return token("lwrcg1", self.grant_counter)

        self.store = delivery.RightsConsumerDeliveryStore(
            tmp_path / "rights-consumer-delivery.sqlite3",
            authorization_resolver=delivery.resolver_from_orchestration_store(self.authority),
            current_consumer_binding_resolver=lambda: self.consumer["value"],
            config_gate=lambda: None,
            principal_resolver=lambda: self.actor["value"],
            digest_key_resolver=lambda _tenant: b"d" * 32,
            signing_key_resolver=lambda _tenant, _ref: b"s" * 32,
            clock=self.clock,
            capability_factory=next_capability,
            server_grant_factory=next_grant,
            server_grant_ttl_seconds=30,
        )

    def mint(
        self,
        *,
        tenant: str = "tenant-a",
        delivery_id: str = "delivery:one",
        idempotency_key: str = "mint:one",
        ttl_seconds: int = 60,
        max_attempts: int = 3,
        min_attempt_interval_seconds: int = 0,
    ) -> delivery.MintedRightsConsumerDelivery:
        return self.store.mint_delivery(
            tenant,
            "case:access",
            "package:access",
            delivery_id,
            reauthentication_receipt_sha256=digest("reauth:receipt"),
            ttl_seconds=ttl_seconds,
            retained_until=self.clock() + 500,
            max_attempts=max_attempts,
            min_attempt_interval_seconds=min_attempt_interval_seconds,
            idempotency_key=idempotency_key,
        )


@pytest.fixture
def harness(tmp_path: Path) -> Harness:
    return Harness(tmp_path)


def test_exact_three_level_gate_is_default_off(monkeypatch) -> None:
    from maverick import config

    monkeypatch.setattr(config, "config_source_errors", list)
    for configured in (
        {},
        {"privacy_automation": {"enable": True}},
        {
            "privacy_automation": {
                "enable": True,
                "rights_orchestration": {"enable": True},
            }
        },
        {
            "privacy_automation": {
                "enable": True,
                "rights_orchestration": {"enable": True},
                "rights_consumer_delivery": {"enable": False},
            }
        },
    ):
        monkeypatch.setattr(config, "load_config", lambda value=configured: value)
        assert delivery.enabled() is False
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "privacy_automation": {
                "enable": True,
                "rights_orchestration": {"enable": True},
                "rights_consumer_delivery": {"enable": True},
            }
        },
    )
    assert delivery.enabled() is True


def test_public_resolver_binds_exact_closed_case_and_package(harness: Harness) -> None:
    resolved = delivery.resolver_from_orchestration_store(harness.authority)(
        "tenant-a", "case:access", "package:access"
    )
    case = harness.authority.cases[("tenant-a", "case:access")]
    package = harness.authority.packages[("tenant-a", "package:access")]
    assert resolved.case_revision == case.revision
    assert resolved.case_record_sha256 == case.integrity_sha256
    assert resolved.package_revision == 1
    assert resolved.package_record_sha256 == package.integrity_sha256
    assert resolved.identity_evidence_sha256 == case.identity_evidence_sha256
    assert resolved.completeness_ready is True
    assert resolved.redaction_ready is True
    assert resolved.closure_ready is True
    assert resolved.delivery_object_ref_sha256 != package.object_ref
    assert harness.authority.calls[-2:] == [
        ("get_case", "tenant-a", "case:access"),
        ("get_response_package", "tenant-a", "package:access"),
    ]


@pytest.mark.parametrize(
    "case_change,package_change",
    [
        ({"identity_status": "unverified", "identity_evidence_sha256": None}, {}),
        (
            {
                "status": "open",
                "closure_approved_by": None,
                "closed_by": None,
            },
            {},
        ),
        ({}, {"delivery_performed": True}),
    ],
)
def test_mint_denies_unverified_incomplete_or_already_delivered_authority(
    harness: Harness,
    case_change: dict[str, object],
    package_change: dict[str, object],
) -> None:
    key = ("tenant-a", "case:access")
    package_key = ("tenant-a", "package:access")
    harness.authority.cases[key] = replace(harness.authority.cases[key], **case_change)
    harness.authority.packages[package_key] = replace(
        harness.authority.packages[package_key], **package_change
    )
    with pytest.raises(delivery.RightsConsumerDeliveryDenied) as exc:
        harness.mint()
    assert str(exc.value) == "delivery capability is unavailable"


def test_mint_returns_capability_once_and_exact_replay_is_safe(
    harness: Harness,
) -> None:
    first = harness.mint()
    assert first.capability == token("lwrcd1", 1)
    assert first.capability_returned is True
    assert first.idempotent_replay is False
    assert first.delivery.case_revision == 8
    assert first.delivery.package_revision == 1
    assert first.delivery.status == "active"
    assert not hasattr(first.delivery, "capability_sha256")
    replay = harness.mint()
    assert replay.delivery == first.delivery
    assert replay.capability is None
    assert replay.capability_returned is False
    assert replay.idempotent_replay is True


def test_tenant_and_authenticated_consumer_are_exactly_bound(
    harness: Harness,
) -> None:
    minted = harness.mint()
    with pytest.raises(delivery.RightsConsumerDeliveryNotFound):
        harness.store.get_delivery("tenant-b", minted.delivery.delivery_id)
    harness.consumer["value"] = digest("subject:tenant-b")
    with pytest.raises(delivery.RightsConsumerDeliveryDenied) as wrong_subject:
        harness.store.redeem(
            minted.capability or "",
            reauthentication_receipt_sha256=digest("reauth:receipt"),
            request_context_sha256=digest("request:wrong-subject"),
        )
    with pytest.raises(delivery.RightsConsumerDeliveryDenied) as unknown:
        harness.store.redeem(
            token("lwrcd1", 999),
            reauthentication_receipt_sha256=digest("reauth:receipt"),
            request_context_sha256=digest("request:unknown"),
        )
    assert type(wrong_subject.value) is type(unknown.value)
    assert str(wrong_subject.value) == str(unknown.value)
    harness.consumer["value"] = digest("subject:tenant-a")
    grant = harness.store.redeem(
        minted.capability or "",
        reauthentication_receipt_sha256=digest("reauth:receipt"),
        request_context_sha256=digest("request:correct-subject"),
    )
    assert grant == token("lwrcg1", 1)


def test_reauthentication_attempts_are_bounded_and_non_enumerating(
    harness: Harness,
) -> None:
    minted = harness.mint(max_attempts=2)
    for attempt in range(2):
        with pytest.raises(delivery.RightsConsumerDeliveryDenied) as exc:
            harness.store.redeem(
                minted.capability or "",
                reauthentication_receipt_sha256=digest("wrong-reauth"),
                request_context_sha256=digest(f"request:{attempt}"),
            )
        assert str(exc.value) == "delivery capability is unavailable"
    current = harness.store.get_delivery("tenant-a", minted.delivery.delivery_id)
    assert current.status == "exhausted"
    assert current.attempts == 2
    assert current.last_request_context_sha256 == digest("request:1")
    with pytest.raises(delivery.RightsConsumerDeliveryDenied):
        harness.store.redeem(
            minted.capability or "",
            reauthentication_receipt_sha256=digest("reauth:receipt"),
            request_context_sha256=digest("request:after-exhaustion"),
        )


def test_expiry_and_revocation_cannot_be_distinguished_from_unknown(
    harness: Harness,
) -> None:
    expired = harness.mint(ttl_seconds=30)
    harness.clock.advance(31)
    with pytest.raises(delivery.RightsConsumerDeliveryDenied) as expiry_error:
        harness.store.redeem(
            expired.capability or "",
            reauthentication_receipt_sha256=digest("reauth:receipt"),
            request_context_sha256=digest("request:expired"),
        )
    assert harness.store.get_delivery("tenant-a", "delivery:one").status == "expired"

    second = harness.mint(delivery_id="delivery:two", idempotency_key="mint:two")
    revoked = harness.store.revoke_delivery(
        "tenant-a",
        second.delivery.delivery_id,
        reason_code="consumer_requested",
        expected_revision=second.delivery.revision,
        idempotency_key="revoke:two",
    )
    assert revoked.status == "revoked"
    replay = harness.store.revoke_delivery(
        "tenant-a",
        second.delivery.delivery_id,
        reason_code="consumer_requested",
        expected_revision=second.delivery.revision,
        idempotency_key="revoke:two",
    )
    assert replay == revoked
    with pytest.raises(delivery.RightsConsumerDeliveryDenied) as revoked_error:
        harness.store.redeem(
            second.capability or "",
            reauthentication_receipt_sha256=digest("reauth:receipt"),
            request_context_sha256=digest("request:revoked"),
        )
    assert str(expiry_error.value) == str(revoked_error.value)


@pytest.mark.parametrize("drift", ["case", "package"])
def test_case_or_package_drift_invalidates_unredeemed_capability(
    harness: Harness, drift: str
) -> None:
    minted = harness.mint()
    if drift == "case":
        key = ("tenant-a", "case:access")
        current = harness.authority.cases[key]
        harness.authority.cases[key] = replace(
            current,
            revision=current.revision + 1,
            integrity_sha256=digest("case-record:changed"),
        )
    else:
        key = ("tenant-a", "package:access")
        current_package = harness.authority.packages[key]
        harness.authority.packages[key] = replace(
            current_package,
            package_sha256=digest("package-bytes:changed"),
            integrity_sha256=digest("package-record:changed"),
        )
    with pytest.raises(delivery.RightsConsumerDeliveryDenied):
        harness.store.redeem(
            minted.capability or "",
            reauthentication_receipt_sha256=digest("reauth:receipt"),
            request_context_sha256=digest(f"request:drift:{drift}"),
        )
    current_delivery = harness.store.get_delivery("tenant-a", "delivery:one")
    assert current_delivery.status == "active"
    assert current_delivery.attempts == 1


def test_atomic_concurrent_redeem_has_exactly_one_winner(harness: Harness) -> None:
    minted = harness.mint(max_attempts=5)

    def attempt(number: int) -> tuple[str, str]:
        try:
            return (
                "granted",
                harness.store.redeem(
                    minted.capability or "",
                    reauthentication_receipt_sha256=digest("reauth:receipt"),
                    request_context_sha256=digest(f"request:concurrent:{number}"),
                ),
            )
        except delivery.RightsConsumerDeliveryDenied as exc:
            return "denied", str(exc)

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(attempt, range(8)))
    granted = [value for status, value in outcomes if status == "granted"]
    denied = [value for status, value in outcomes if status == "denied"]
    assert granted == [token("lwrcg1", 1)]
    assert len(denied) == 7
    assert set(denied) == {"delivery capability is unavailable"}
    current = harness.store.get_delivery("tenant-a", "delivery:one")
    assert current.status == "redeemed"
    assert current.attempts == 1


def test_server_grant_is_one_time_and_returns_no_object_secret(
    harness: Harness,
) -> None:
    minted = harness.mint()
    grant = harness.store.redeem(
        minted.capability or "",
        reauthentication_receipt_sha256=digest("reauth:receipt"),
        request_context_sha256=digest("request:redeem"),
    )
    assert isinstance(grant, str)
    claimed = harness.store.claim_server_grant(grant)
    assert claimed.case_id == "case:access"
    assert claimed.package_id == "package:access"
    assert claimed.delivery_object_ref_sha256 != "encrypted-object:secret-locator"
    assert "object_ref" not in claimed.__dict__
    assert "encryption_key_ref" not in claimed.__dict__
    assert "bytes" not in claimed.__dict__
    with pytest.raises(delivery.RightsConsumerDeliveryDenied):
        harness.store.claim_server_grant(grant)


def test_raw_capabilities_identity_object_key_and_plaintext_are_not_persisted(
    harness: Harness,
) -> None:
    minted = harness.mint()
    raw_capability = minted.capability or ""
    raw_grant = harness.store.redeem(
        raw_capability,
        reauthentication_receipt_sha256=digest("reauth:receipt"),
        request_context_sha256=digest("request:secrets"),
    )
    database = harness.store.path.read_bytes()
    for forbidden in (
        raw_capability,
        raw_grant,
        "operator@example.test",
        "subject:tenant-a",
        "encrypted-object:secret-locator",
        "vault:secret-package-key",
        "package-bytes:tenant-a",
    ):
        assert forbidden.encode("utf-8") not in database


def test_capability_fixation_collision_is_rejected(tmp_path: Path) -> None:
    fixed = Harness(tmp_path, fixed_capability=True)
    fixed.mint()
    with pytest.raises(delivery.RightsConsumerDeliveryConflict):
        fixed.mint(delivery_id="delivery:two", idempotency_key="mint:two")


def test_signed_export_integrity_tamper_detection_and_retention(
    harness: Harness,
) -> None:
    minted = harness.mint()
    exported = harness.store.export_signed_metadata(
        "tenant-a",
        minted.delivery.delivery_id,
        "export:one",
        expected_delivery_revision=minted.delivery.revision,
        signing_key_ref="env:RIGHTS_DELIVERY_EXPORT_KEY",
        retained_until=harness.clock() + 400,
        idempotency_key="export:one",
    )
    assert exported.body_sha256 == digest(
        json.dumps(
            exported.body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
    )
    assert harness.store.get_export("tenant-a", "export:one") == exported
    assert "lwrcd1" not in json.dumps(exported.body)
    verified = harness.store.verify_integrity("tenant-a")
    assert verified.verified_records > 0
    assert verified.audit_events == 2

    with sqlite3.connect(harness.store.path) as connection:
        connection.execute(
            "UPDATE rights_consumer_deliveries SET payload_json=? "
            "WHERE tenant_id=? AND delivery_id=?",
            ("{}", "tenant-a", "delivery:one"),
        )
    with pytest.raises(delivery.RightsConsumerDeliveryIntegrityError):
        harness.store.verify_integrity("tenant-a")


def test_retention_purge_removes_delivery_state_but_keeps_audit(tmp_path: Path) -> None:
    local = Harness(tmp_path)
    minted = local.mint(ttl_seconds=30)
    local.clock.advance(501)
    result = local.store.purge_expired(
        "tenant-a", cutoff=local.clock(), idempotency_key="purge:one"
    )
    assert result == {"deliveries": 1, "history": 1, "exports": 0}
    with pytest.raises(delivery.RightsConsumerDeliveryNotFound):
        local.store.get_delivery("tenant-a", minted.delivery.delivery_id)
    verification = local.store.verify_integrity("tenant-a")
    assert verification.audit_events == 2


def test_redeem_contract_has_no_authority_selectors_and_boundaries_are_honest() -> None:
    parameters = inspect.signature(delivery.RightsConsumerDeliveryStore.redeem).parameters
    assert set(parameters) == {
        "self",
        "capability",
        "reauthentication_receipt_sha256",
        "request_context_sha256",
    }
    boundaries = delivery.RightsConsumerDeliveryStore.product_boundaries()
    assert boundaries["network_io"] is False
    assert boundaries["provider_writes"] is False
    assert boundaries["object_bytes_returned"] is False
    assert boundaries["object_store_credentials_returned"] is False
    assert boundaries["identity_verification_performed"] is False
    assert boundaries["live_source_acceptance_verified"] is False
    assert boundaries["live_identity_acceptance_verified"] is False
    assert boundaries["consumer_redeem_returns"] == "opaque_server_grant_only"
