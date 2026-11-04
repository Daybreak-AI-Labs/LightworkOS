from __future__ import annotations

import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest
from maverick.third_party_contracts import (
    AUTHORITY_SCHEMA,
    ThirdPartyContractConflict,
    ThirdPartyContractIntegrityError,
    ThirdPartyContractNotFound,
    ThirdPartyContractPermissionDenied,
    ThirdPartyContractStore,
    ThirdPartyContractValidationError,
    VendorAuthority,
    issue_vendor_authority,
    redacted_record,
)


def _authority(
    now: float,
    *,
    tenant: str = "tenant-a",
    vendor: str = "vendor-1",
    revision: int = 7,
    revoked: bool = False,
) -> VendorAuthority:
    return issue_vendor_authority(
        tenant_id=tenant,
        vendor_id=vendor,
        vendor_revision=revision,
        vendor_type="service_provider",
        criticality="high",
        jurisdiction_codes=("US", "CA"),
        classification_refs=("hosting", "processor"),
        issuer_ref="vendor-registry",
        issued_at=now - 60,
        valid_until=now + 3_600,
        revoked=revoked,
    )


def _contract_lifecycle(parent: str | None = None) -> dict[str, object]:
    return {
        "agreement_type": "subscription",
        "agreement_ref": "agreement-vault-ref",
        "effective_at": 2_000.0,
        "expires_at": 4_000.0,
        "renewal_mode": "automatic",
        "notice_period_days": 45,
        "governing_law_ref": "law-ref",
        "parent_contract_id": parent,
    }


def _engagement_lifecycle(*contracts: str) -> dict[str, object]:
    return {
        "engagement_type": "software",
        "service_category_ref": "ai-service",
        "start_at": 2_100.0,
        "end_at": 3_900.0,
        "operational_criticality": "high",
        "data_access": "confidential",
        "hosting_model": "vendor_cloud",
        "linked_contract_ids": list(contracts),
        "business_owner_ref": "business-owner",
    }


def _fields() -> list[dict[str, object]]:
    return [
        {
            "field_id": "annual_cost",
            "label_ref": "label-annual-cost",
            "field_type": "decimal",
            "required": True,
            "sensitivity": "confidential",
            "options": [],
        },
        {
            "field_id": "licensed_regions",
            "label_ref": "label-regions",
            "field_type": "multi_choice",
            "required": True,
            "sensitivity": "internal",
            "options": ["us", "ca", "gb"],
        },
        {
            "field_id": "document_ref",
            "label_ref": "label-document",
            "field_type": "text_ref",
            "required": True,
            "sensitivity": "restricted",
            "options": [],
        },
    ]


def _formulas() -> list[dict[str, object]]:
    return [
        {
            "formula_id": "cost_per_region",
            "operator": "divide",
            "operands": [
                {"source": "field", "field_id": "annual_cost", "value": None},
                {"source": "field", "field_id": "licensed_regions", "value": None},
            ],
            "round_digits": 2,
        }
    ]


def _store(
    tmp_path: Path,
    *,
    clock: list[float] | None = None,
    resolver=None,
    maintenance: bool = True,
    id_factory=None,
) -> ThirdPartyContractStore:
    moment = clock or [2_500.0]
    authority = _authority(moment[0])
    return ThirdPartyContractStore(
        tmp_path / "contracts.sqlite3",
        tenant_id="tenant-a",
        vendor_authority_resolver=resolver or (lambda *_: authority),
        principal_resolver=lambda: "principal-1",
        maintenance_authorizer=lambda: maintenance,
        config_gate=lambda: None,
        retention_seconds=86_400,
        clock=lambda: moment[0],
        id_factory=id_factory,
    )


def test_contract_lifecycle_history_formulas_redaction_and_idempotency(tmp_path: Path) -> None:
    calls: list[tuple[str, str, int]] = []
    authority = _authority(2_500.0)

    def resolver(tenant: str, vendor: str, revision: int) -> VendorAuthority:
        calls.append((tenant, vendor, revision))
        return authority

    store = _store(tmp_path, resolver=resolver, id_factory=lambda _: "contract-1")
    created = store.create_contract(
        "tenant-a",
        vendor_id="vendor-1",
        vendor_revision=7,
        title_ref="contract-title",
        owner_ref="owner-1",
        status="draft",
        lifecycle=_contract_lifecycle(),
        field_schema=_fields(),
        field_values={
            "annual_cost": 120_000.0,
            "licensed_regions": ["us", "ca"],
            "document_ref": "encrypted-document-ref",
        },
        formulas=_formulas(),
        idempotency_key="create-1",
    )
    assert calls == [("tenant-a", "vendor-1", 7), ("tenant-a", "vendor-1", 7)]
    assert created.computed_values == {"cost_per_region": 60_000.0}
    assert created.vendor_authority_sha256 == authority.authority_sha256
    assert created.sensitive_field_ids == ("annual_cost", "document_ref")

    replay = store.create_contract(
        "tenant-a",
        vendor_id="vendor-1",
        vendor_revision=7,
        title_ref="contract-title",
        owner_ref="owner-1",
        status="draft",
        lifecycle=_contract_lifecycle(),
        field_schema=_fields(),
        field_values={
            "annual_cost": 120_000.0,
            "licensed_regions": ["us", "ca"],
            "document_ref": "encrypted-document-ref",
        },
        formulas=_formulas(),
        idempotency_key="create-1",
    )
    assert replay == created
    projected = redacted_record(created)
    assert projected["field_values"]["annual_cost"] == {"redacted": True}
    assert projected["field_values"]["document_ref"] == {"redacted": True}
    assert projected["field_values"]["licensed_regions"] == ["us", "ca"]
    assert projected["redaction"]["licensed_template_content_included"] is False

    updated = store.update_record(
        "tenant-a",
        created.record_id,
        expected_revision=1,
        changes={"status": "active", "owner_ref": "owner-2"},
        idempotency_key="update-1",
    )
    assert updated.revision == 2
    assert updated.previous_integrity_sha256 == created.integrity_sha256
    assert [event.event_type for event in store.history("tenant-a", created.record_id)] == [
        "contract_created",
        "contract_updated",
    ]
    assert store.verify_integrity("tenant-a")["verified"] is True


def test_engagement_links_only_exact_vendor_contracts(tmp_path: Path) -> None:
    identifiers = iter(("contract-1", "engagement-1", "engagement-other"))
    authorities = {
        "vendor-1": _authority(2_500.0),
        "vendor-2": _authority(2_500.0, vendor="vendor-2"),
    }
    store = _store(
        tmp_path,
        resolver=lambda _tenant, vendor, _revision: authorities[vendor],
        id_factory=lambda _: next(identifiers),
    )
    contract = store.create_contract(
        "tenant-a",
        vendor_id="vendor-1",
        vendor_revision=7,
        title_ref="contract-title",
        owner_ref="owner",
        status="active",
        lifecycle=_contract_lifecycle(),
        field_schema=[],
        field_values={},
        formulas=[],
        idempotency_key="create-contract",
    )
    engagement = store.create_engagement(
        "tenant-a",
        vendor_id="vendor-1",
        vendor_revision=7,
        title_ref="engagement-title",
        owner_ref="owner",
        status="planned",
        lifecycle=_engagement_lifecycle(contract.record_id),
        field_schema=[],
        field_values={},
        formulas=[],
        idempotency_key="create-engagement",
    )
    assert engagement.record_kind == "engagement"
    assert store.list_records("tenant-a", record_kind="engagement") == (engagement,)
    assert store.context_record_count("tenant-a") == 2
    with pytest.raises(ThirdPartyContractNotFound):
        store.context_record_count("tenant-b")

    with pytest.raises(ThirdPartyContractConflict):
        store.create_engagement(
            "tenant-a",
            vendor_id="vendor-2",
            vendor_revision=7,
            title_ref="engagement-title",
            owner_ref="owner",
            status="planned",
            lifecycle=_engagement_lifecycle("contract-1"),
            field_schema=[],
            field_values={},
            formulas=[],
            idempotency_key="create-other",
        )


def test_closed_custom_schema_safe_formula_and_transition_validation(tmp_path: Path) -> None:
    store = _store(tmp_path, id_factory=lambda _: "contract-1")
    malformed = _fields()
    malformed[0]["prompt"] = "unlicensed free-form content"
    with pytest.raises(ThirdPartyContractValidationError, match="closed"):
        store.create_contract(
            "tenant-a",
            vendor_id="vendor-1",
            vendor_revision=7,
            title_ref="title",
            owner_ref="owner",
            status="draft",
            lifecycle=_contract_lifecycle(),
            field_schema=malformed,
            field_values={
                "annual_cost": 1,
                "licensed_regions": ["us"],
                "document_ref": "doc",
            },
            formulas=[],
            idempotency_key="malformed",
        )
    unsafe_formula = _formulas()
    unsafe_formula[0]["expression"] = "__import__('os')"
    with pytest.raises(ThirdPartyContractValidationError, match="closed"):
        store.create_contract(
            "tenant-a",
            vendor_id="vendor-1",
            vendor_revision=7,
            title_ref="title",
            owner_ref="owner",
            status="draft",
            lifecycle=_contract_lifecycle(),
            field_schema=_fields(),
            field_values={
                "annual_cost": 1,
                "licensed_regions": ["us"],
                "document_ref": "doc",
            },
            formulas=unsafe_formula,
            idempotency_key="unsafe",
        )

    created = store.create_contract(
        "tenant-a",
        vendor_id="vendor-1",
        vendor_revision=7,
        title_ref="title",
        owner_ref="owner",
        status="draft",
        lifecycle=_contract_lifecycle(),
        field_schema=[],
        field_values={},
        formulas=[],
        idempotency_key="create",
    )
    with pytest.raises(ThirdPartyContractConflict, match="transition"):
        store.update_record(
            "tenant-a",
            created.record_id,
            expected_revision=1,
            changes={"status": "expired"},
            idempotency_key="bad-transition",
        )
    with pytest.raises(ThirdPartyContractConflict, match="revision"):
        store.update_record(
            "tenant-a",
            created.record_id,
            expected_revision=2,
            changes={"status": "active"},
            idempotency_key="bad-cas",
        )


def test_authority_drift_revocation_and_tenant_isolation_fail_closed(tmp_path: Path) -> None:
    current = [_authority(2_500.0)]
    calls = [0]

    def drifting(*_: object) -> VendorAuthority:
        calls[0] += 1
        if calls[0] % 2:
            return current[0]
        return replace(current[0], authority_sha256="f" * 64)

    drift_store = _store(tmp_path / "drift", resolver=drifting)
    with pytest.raises(ThirdPartyContractValidationError, match="digest"):
        drift_store.create_contract(
            "tenant-a",
            vendor_id="vendor-1",
            vendor_revision=7,
            title_ref="title",
            owner_ref="owner",
            status="draft",
            lifecycle=_contract_lifecycle(),
            field_schema=[],
            field_values={},
            formulas=[],
            idempotency_key="drift",
        )

    revoked = _authority(2_500.0, revoked=True)
    revoked_store = _store(tmp_path / "revoked", resolver=lambda *_: revoked)
    with pytest.raises(ThirdPartyContractConflict, match="current"):
        revoked_store.create_contract(
            "tenant-a",
            vendor_id="vendor-1",
            vendor_revision=7,
            title_ref="title",
            owner_ref="owner",
            status="draft",
            lifecycle=_contract_lifecycle(),
            field_schema=[],
            field_values={},
            formulas=[],
            idempotency_key="revoked",
        )
    with pytest.raises(ThirdPartyContractNotFound):
        revoked_store.list_records("tenant-b")


def test_archive_delete_tombstone_retention_and_reuse_prevention(tmp_path: Path) -> None:
    clock = [2_500.0]
    store = _store(
        tmp_path,
        clock=clock,
        resolver=lambda *_: _authority(clock[0]),
        id_factory=lambda _: "contract-1",
    )
    created = store.create_contract(
        "tenant-a",
        vendor_id="vendor-1",
        vendor_revision=7,
        title_ref="title",
        owner_ref="owner",
        status="draft",
        lifecycle=_contract_lifecycle(),
        field_schema=[],
        field_values={},
        formulas=[],
        idempotency_key="create",
    )
    clock[0] += 1
    archived = store.archive_record(
        "tenant-a", created.record_id, expected_revision=1, idempotency_key="archive"
    )
    with pytest.raises(ThirdPartyContractConflict, match="immutable"):
        store.update_record(
            "tenant-a",
            archived.record_id,
            expected_revision=2,
            changes={"owner_ref": "new-owner"},
            idempotency_key="mutate-archived",
        )
    clock[0] = archived.retained_until + 1
    assert store.retention_due("tenant-a") == (archived,)
    assert store.purge_expired("tenant-a") == 1
    tombstone = store.get_tombstone("tenant-a", archived.record_id)
    assert tombstone.last_integrity_sha256 == archived.integrity_sha256
    with pytest.raises(ThirdPartyContractNotFound):
        store.get_record("tenant-a", archived.record_id)
    with pytest.raises(ThirdPartyContractConflict, match="tombstoned"):
        store.create_contract(
            "tenant-a",
            vendor_id="vendor-1",
            vendor_revision=7,
            title_ref="title",
            owner_ref="owner",
            status="draft",
            lifecycle=_contract_lifecycle(),
            field_schema=[],
            field_values={},
            formulas=[],
            idempotency_key="recreate",
        )


def test_integrity_tamper_detection_and_verified_recovery_backup(tmp_path: Path) -> None:
    store = _store(tmp_path, id_factory=lambda _: "contract-1")
    store.create_contract(
        "tenant-a",
        vendor_id="vendor-1",
        vendor_revision=7,
        title_ref="title",
        owner_ref="owner",
        status="draft",
        lifecycle=_contract_lifecycle(),
        field_schema=[],
        field_values={},
        formulas=[],
        idempotency_key="create",
    )
    backup = store.create_recovery_backup("tenant-a", tmp_path / "backup.sqlite3")
    assert Path(str(backup["backup_path"])).is_file()
    assert len(str(backup["backup_sha256"])) == 64

    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE third_party_contract_records SET record_json=replace(record_json,'\"title_ref\":\"title\"','\"title_ref\":\"changed-title\"')"
        )
    with pytest.raises(ThirdPartyContractIntegrityError):
        store.verify_integrity("tenant-a")

    denied = _store(tmp_path / "denied", maintenance=False)
    with pytest.raises(ThirdPartyContractPermissionDenied):
        denied.create_recovery_backup("tenant-a", tmp_path / "denied-backup.sqlite3")


def test_authority_shape_is_closed_and_self_verifying() -> None:
    authority = _authority(2_500.0)
    assert authority.schema == AUTHORITY_SCHEMA
    with pytest.raises(ThirdPartyContractValidationError, match="digest"):
        replace(authority, vendor_revision=8).normalized()


def test_non_ascii_tenant_ids_are_compared_not_crashed(tmp_path: Path) -> None:
    # Tenant ids may be any NFC text: an accented id from another workspace is
    # the normal not-found, and a workspace named with an accent still works.
    store = _store(tmp_path / "plain")
    with pytest.raises(ThirdPartyContractNotFound):
        store.list_records("tenant-é")

    accented = ThirdPartyContractStore(
        tmp_path / "accented.sqlite3",
        tenant_id="atelier-café",
        vendor_authority_resolver=lambda *_: _authority(2_500.0, tenant="atelier-café"),
        principal_resolver=lambda: "principal-1",
        maintenance_authorizer=lambda: True,
        config_gate=lambda: None,
        retention_seconds=86_400,
        clock=lambda: 2_500.0,
    )
    assert accented.context_record_count("atelier-café") == 0
