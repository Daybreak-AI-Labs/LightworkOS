"""Focused authority tests for provider-neutral data-use governance."""

from __future__ import annotations

import hashlib
import itertools
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from maverick.data_use_governance import (
    CONTEXT_KINDS,
    DataUseConflict,
    DataUseCorruptionError,
    DataUseGovernanceStore,
    DataUseIdempotencyConflict,
    DataUseValidationError,
    normalize_policy_document,
)

TENANT = "tenant-alpha"
OTHER_TENANT = "tenant-beta"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class Clock:
    def __init__(self, value: float = 1_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


@pytest.fixture
def authority(tmp_path: Path) -> tuple[DataUseGovernanceStore, Clock]:
    counter = itertools.count(1)
    clock = Clock()
    store = DataUseGovernanceStore(
        tmp_path / "data-use.sqlite",
        clock=clock,
        id_factory=lambda prefix: f"{prefix}-{next(counter)}",
    )
    return store, clock


def test_canonical_tenant_ids_flow_through_provider_neutral_authority(
    authority: tuple[DataUseGovernanceStore, Clock],
) -> None:
    store, _clock = authority
    decomposed = "Acme Cafe\u0301 Corp"
    canonical = "Acme Caf\u00e9 Corp"
    created = store.put_asset(
        decomposed,
        "customers",
        asset_type="table",
        catalog_binding_sha256=_digest("acme-customers"),
        expected_revision=0,
        idempotency_key="acme-asset-create",
    )

    assert created["tenant_id"] == canonical
    assert store.get_record(canonical, "asset", "customers") == created
    assert store.get_record("Other Corp", "asset", "customers") is None
    with pytest.raises(DataUseValidationError, match="opaque identifier"):
        store.get_record(canonical, "asset", "customer records")


def _catalog(store: DataUseGovernanceStore, tenant: str = TENANT) -> None:
    store.put_asset(
        tenant,
        "customers",
        asset_type="table",
        catalog_binding_sha256=_digest(f"{tenant}:asset"),
        expected_revision=0,
        idempotency_key=f"{tenant}-asset-1",
    )
    for field_id, data_type, nullable in (
        ("email", "string", False),
        ("region", "string", False),
        ("amount", "number", True),
    ):
        store.put_field(
            tenant,
            "customers",
            field_id,
            data_type=data_type,
            nullable=nullable,
            catalog_binding_sha256=_digest(f"{tenant}:{field_id}"),
            expected_revision=0,
            idempotency_key=f"{tenant}-field-{field_id}",
        )


def _contexts(
    store: DataUseGovernanceStore,
    *,
    tenant: str = TENANT,
    fresh_until: float = 2_000.0,
    duplicate_source: bool = False,
    omit: str | None = None,
) -> None:
    values = {
        "business_purpose": ("analytics", "fraud_detection"),
        "regulatory": ("gdpr", "ccpa"),
        "consent": ("granted",),
        "observed_classification": ("personal", "sensitive"),
    }
    for index, kind in enumerate(CONTEXT_KINDS):
        if kind == omit:
            continue
        source_key = "shared" if duplicate_source else f"source-{index}"
        store.put_context_authority(
            tenant,
            "customers",
            kind,
            values=values[kind],
            source_system=f"authority-{kind}",
            source_revision=7 + index,
            source_authority_sha256=_digest(f"{tenant}:{source_key}"),
            evidence_sha256=_digest(f"{tenant}:evidence:{kind}"),
            reviewer_id=f"reviewer-{kind}",
            reviewer_authority_sha256=_digest(f"{tenant}:reviewer:{kind}"),
            observed_at=900.0,
            fresh_until=fresh_until,
            expected_revision=0,
            idempotency_key=f"{tenant}-context-{kind}",
        )


def _label(store: DataUseGovernanceStore, tenant: str = TENANT) -> None:
    store.publish_machine_label(
        tenant,
        "personal_data",
        version=1,
        taxonomy_id="enterprise_taxonomy",
        sensitivity=80,
        definition_sha256=_digest("personal-data-definition"),
        reviewer_id="label-reviewer",
        reviewer_authority_sha256=_digest("label-reviewer-authority"),
        reviewed_at=950.0,
        expected_current_version=0,
        expected_revision=0,
        idempotency_key=f"{tenant}-label-v1",
    )
    store.assign_machine_label(
        tenant,
        "customers",
        "email",
        "personal_data",
        label_version=1,
        assignment_evidence_sha256=_digest("label-assignment-evidence"),
        reviewer_id="assignment-reviewer",
        reviewer_authority_sha256=_digest("assignment-reviewer-authority"),
        expected_revision=0,
        idempotency_key=f"{tenant}-label-assignment",
    )


def _policy_document(
    effect: str,
    *,
    control_id: str,
    field_ids: tuple[str, ...] = ("email",),
) -> dict[str, object]:
    control: dict[str, object] = {
        "control_id": control_id,
        "effect": effect,
        "field_ids": list(field_ids),
    }
    if effect == "mask":
        control["mask_method"] = "hash_sha256"
    return {
        "scope": {
            "asset_ids": ["customers"],
            "field_ids": list(field_ids),
            "project_ids": [],
            "actions": ["read"],
        },
        "conditions": {
            "business_purpose_any": ["analytics"],
            "regulatory_any": ["gdpr"],
            "consent_any": ["granted"],
            "observed_classification_any": ["personal"],
            "label_any": ["personal_data"],
        },
        "controls": [control],
    }


def _policy(
    store: DataUseGovernanceStore,
    policy_id: str,
    effect: str,
    *,
    control_id: str,
    tenant: str = TENANT,
) -> dict[str, object]:
    draft = store.put_policy_version(
        tenant,
        policy_id,
        version=1,
        document=_policy_document(effect, control_id=control_id),
        author_id=f"author-{policy_id}",
        author_authority_sha256=_digest(f"author:{policy_id}"),
        expected_current_version=0,
        expected_revision=0,
        idempotency_key=f"{tenant}-{policy_id}-draft",
    )
    return store.activate_policy(
        tenant,
        policy_id,
        version=1,
        reviewer_id=f"reviewer-{policy_id}",
        reviewer_authority_sha256=_digest(f"reviewer:{policy_id}"),
        reviewed_at=975.0,
        expected_revision=int(draft["revision"]),
        idempotency_key=f"{tenant}-{policy_id}-activate",
    )


def _request(
    store: DataUseGovernanceStore,
    request_id: str,
    *,
    fields: tuple[str, ...] = ("email",),
    tenant: str = TENANT,
) -> dict[str, object]:
    return store.create_data_use_request(
        tenant,
        request_id,
        project_id="project-analytics",
        asset_id="customers",
        field_ids=fields,
        action="read",
        purpose_codes=("analytics",),
        requester_id=f"requester-{request_id}",
        requester_authority_sha256=_digest(f"requester:{request_id}"),
        request_evidence_sha256=_digest(f"request:{request_id}"),
        idempotency_key=f"{tenant}-{request_id}-create",
    )


def _authorize(
    store: DataUseGovernanceStore,
    request_id: str,
    *,
    tenant: str = TENANT,
    key: str | None = None,
) -> dict[str, object]:
    return store.authorize_data_use_request(
        tenant,
        request_id,
        authorizer_id=f"authorizer-{request_id}",
        authorizer_authority_sha256=_digest(f"authorizer:{request_id}"),
        expected_request_revision=1,
        idempotency_key=key or f"{tenant}-{request_id}-authorize",
    )


def _ready(store: DataUseGovernanceStore) -> None:
    _catalog(store)
    _contexts(store)
    _label(store)


def test_asset_field_lineage_replay_cas_and_cross_tenant(
    authority: tuple[DataUseGovernanceStore, Clock],
) -> None:
    store, _clock = authority
    asset = store.put_asset(
        TENANT,
        "source",
        asset_type="table",
        catalog_binding_sha256=_digest("source-v1"),
        expected_revision=0,
        idempotency_key="asset-source",
    )
    assert (
        store.put_asset(
            TENANT,
            "source",
            asset_type="table",
            catalog_binding_sha256=_digest("source-v1"),
            expected_revision=0,
            idempotency_key="asset-source",
        )
        == asset
    )
    with pytest.raises(DataUseIdempotencyConflict):
        store.put_asset(
            TENANT,
            "source",
            asset_type="view",
            catalog_binding_sha256=_digest("source-v1"),
            expected_revision=0,
            idempotency_key="asset-source",
        )
    assert store.get_record(OTHER_TENANT, "asset", "source") is None

    store.put_asset(
        TENANT,
        "target",
        asset_type="table",
        catalog_binding_sha256=_digest("target-v1"),
        expected_revision=0,
        idempotency_key="asset-target",
    )
    for asset_id in ("source", "target"):
        store.put_field(
            TENANT,
            asset_id,
            "customer_id",
            data_type="uuid",
            nullable=False,
            catalog_binding_sha256=_digest(f"{asset_id}:customer-id"),
            expected_revision=0,
            idempotency_key=f"field-{asset_id}",
        )
    edge = store.put_lineage(
        TENANT,
        "customer-copy",
        source_asset_id="source",
        source_field_id="customer_id",
        target_asset_id="target",
        target_field_id="customer_id",
        transformation_sha256=_digest("copy-transform"),
        observed_at=990.0,
        expected_revision=0,
        idempotency_key="lineage-copy",
    )
    assert edge["source_asset_id"] == "source"
    with pytest.raises(DataUseConflict):
        store.put_asset(
            TENANT,
            "source",
            asset_type="view",
            catalog_binding_sha256=_digest("source-v2"),
            expected_revision=99,
            idempotency_key="asset-source-stale",
        )
    with pytest.raises(DataUseValidationError):
        store.put_lineage(
            TENANT,
            "self-copy",
            source_asset_id="source",
            source_field_id="customer_id",
            target_asset_id="source",
            target_field_id="customer_id",
            transformation_sha256=_digest("self"),
            observed_at=990.0,
            expected_revision=0,
            idempotency_key="lineage-self",
        )


def test_context_completeness_independence_and_freshness_fail_closed(
    authority: tuple[DataUseGovernanceStore, Clock],
) -> None:
    store, clock = authority
    _catalog(store)
    _contexts(store, omit="consent")
    _label(store)
    _policy(store, "allow-policy", "allow", control_id="allow-email")
    _request(store, "missing-context")
    decision = _authorize(store, "missing-context")
    assert decision["outcome"] == "deny"
    assert "missing_context:consent" in decision["reasons"]

    other_path = store.path.parent / "duplicate.sqlite"
    duplicate = DataUseGovernanceStore(other_path, clock=clock)
    _catalog(duplicate)
    _contexts(duplicate, duplicate_source=True)
    _label(duplicate)
    _policy(duplicate, "allow-policy", "allow", control_id="allow-email")
    _request(duplicate, "duplicate-source")
    duplicate_decision = _authorize(duplicate, "duplicate-source")
    assert duplicate_decision["outcome"] == "deny"
    assert "contexts_not_independently_sourced" in duplicate_decision["reasons"]

    stale = DataUseGovernanceStore(store.path.parent / "stale.sqlite", clock=clock)
    _catalog(stale)
    _contexts(stale, fresh_until=1_050.0)
    _label(stale)
    _policy(stale, "allow-policy", "allow", control_id="allow-email")
    _request(stale, "stale-context")
    clock.value = 1_100.0
    stale_decision = _authorize(stale, "stale-context")
    assert stale_decision["outcome"] == "deny"
    assert any(reason.startswith("stale_context:") for reason in stale_decision["reasons"])


def test_reviewed_labels_policy_lifecycle_strictest_and_exception(
    authority: tuple[DataUseGovernanceStore, Clock],
) -> None:
    store, _clock = authority
    _ready(store)
    allow = _policy(store, "allow-policy", "allow", control_id="allow-email")
    deny = _policy(store, "deny-policy", "deny", control_id="deny-email")
    assert allow["state"] == deny["state"] == "active"
    _request(store, "strictest")
    denied = _authorize(store, "strictest")
    assert denied["outcome"] == "deny"
    assert denied["controls"][0]["source_policy_id"] == "deny-policy"

    requested = store.request_policy_exception(
        TENANT,
        "deny-exception",
        "deny-policy",
        scope={
            "asset_ids": ["customers"],
            "field_ids": ["email"],
            "project_ids": ["project-analytics"],
            "actions": ["read"],
        },
        replacement_control={
            "control_id": "exception-allow-email",
            "effect": "allow",
            "field_ids": ["email"],
        },
        rationale_sha256=_digest("approved-purpose"),
        requester_id="exception-requester",
        requester_authority_sha256=_digest("exception-requester"),
        expires_at=1_500.0,
        idempotency_key="exception-request",
    )
    approved = store.review_policy_exception(
        TENANT,
        "deny-exception",
        approve=True,
        reviewer_id="exception-reviewer",
        reviewer_authority_sha256=_digest("exception-reviewer"),
        reviewed_at=990.0,
        expected_revision=int(requested["revision"]),
        idempotency_key="exception-review",
    )
    assert approved["state"] == "approved"
    _request(store, "excepted")
    allowed = _authorize(store, "excepted")
    assert allowed["outcome"] == "allow"
    assert {item["source_exception_id"] for item in allowed["controls"]} == {"deny-exception"}

    retired = store.retire_policy(
        TENANT,
        "deny-policy",
        expected_revision=int(deny["revision"]),
        idempotency_key="deny-policy-retire",
    )
    assert retired["state"] == "retired"
    with pytest.raises(DataUseConflict):
        store.put_policy_version(
            TENANT,
            "deny-policy",
            version=2,
            document=_policy_document("allow", control_id="late-allow"),
            author_id="new-author",
            author_authority_sha256=_digest("new-author"),
            expected_current_version=1,
            expected_revision=int(retired["revision"]),
            idempotency_key="retired-policy-revise",
        )


def test_policy_semantics_are_deterministic_and_require_four_eyes(
    authority: tuple[DataUseGovernanceStore, Clock],
) -> None:
    store, _clock = authority
    left = _policy_document("mask", control_id="mask-email")
    right = {
        "controls": [
            {
                "field_ids": ["email"],
                "mask_method": "hash_sha256",
                "effect": "mask",
                "control_id": "mask-email",
            }
        ],
        "conditions": {
            "label_any": ["personal_data"],
            "observed_classification_any": ["personal"],
            "consent_any": ["granted"],
            "regulatory_any": ["gdpr"],
            "business_purpose_any": ["analytics"],
        },
        "scope": {
            "actions": ["read"],
            "project_ids": [],
            "field_ids": ["email"],
            "asset_ids": ["customers"],
        },
    }
    assert normalize_policy_document(left) == normalize_policy_document(right)

    draft = store.put_policy_version(
        TENANT,
        "four-eyes",
        version=1,
        document=left,
        author_id="same-person",
        author_authority_sha256=_digest("same-person-authority"),
        expected_current_version=0,
        expected_revision=0,
        idempotency_key="four-eyes-draft",
    )
    with pytest.raises(DataUseValidationError, match="must differ"):
        store.activate_policy(
            TENANT,
            "four-eyes",
            version=1,
            reviewer_id="same-person",
            reviewer_authority_sha256=_digest("same-person-review"),
            reviewed_at=990.0,
            expected_revision=int(draft["revision"]),
            idempotency_key="four-eyes-invalid",
        )


def test_default_deny_authorization_replay_and_request_cas(
    authority: tuple[DataUseGovernanceStore, Clock],
) -> None:
    store, _clock = authority
    _ready(store)
    _request(store, "default-deny")
    decision = _authorize(store, "default-deny", key="decision-replay")
    assert decision["outcome"] == "deny"
    assert decision["reasons"] == ["default_deny_no_applicable_policy"]
    assert _authorize(store, "default-deny", key="decision-replay") == decision
    with pytest.raises(DataUseConflict):
        store.authorize_data_use_request(
            TENANT,
            "default-deny",
            authorizer_id="second-authorizer",
            authorizer_authority_sha256=_digest("second-authorizer"),
            expected_request_revision=1,
            idempotency_key="second-decision",
        )
    with pytest.raises(DataUseIdempotencyConflict):
        store.authorize_data_use_request(
            TENANT,
            "default-deny",
            authorizer_id="different-authorizer",
            authorizer_authority_sha256=_digest("different-authorizer"),
            expected_request_revision=1,
            idempotency_key="decision-replay",
        )
    assert decision["provider_writes_possible"] is False
    assert store.status()["provider_writes_possible"] is False


def test_concurrent_asset_cas_has_exactly_one_winner(
    authority: tuple[DataUseGovernanceStore, Clock],
) -> None:
    store, _clock = authority
    first = store.put_asset(
        TENANT,
        "concurrent",
        asset_type="table",
        catalog_binding_sha256=_digest("concurrent-v1"),
        expected_revision=0,
        idempotency_key="concurrent-create",
    )

    def update(index: int) -> str:
        try:
            result = store.put_asset(
                TENANT,
                "concurrent",
                asset_type="view",
                catalog_binding_sha256=_digest(f"concurrent-v{index}"),
                expected_revision=int(first["revision"]),
                idempotency_key=f"concurrent-update-{index}",
            )
        except DataUseConflict:
            return "conflict"
        return f"revision-{result['revision']}"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = sorted(pool.map(update, (2, 3)))
    assert outcomes == ["conflict", "revision-2"]


def test_persisted_record_corruption_is_detected(
    authority: tuple[DataUseGovernanceStore, Clock],
) -> None:
    store, _clock = authority
    store.put_asset(
        TENANT,
        "corrupt-me",
        asset_type="table",
        catalog_binding_sha256=_digest("corrupt-me"),
        expected_revision=0,
        idempotency_key="corrupt-create",
    )
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "UPDATE data_use_records SET body_json = ? WHERE tenant_id = ? "
            "AND record_type = 'asset' AND record_id = ?",
            ('{"tenant_id":"tenant-alpha"}', TENANT, "corrupt-me"),
        )
    with pytest.raises(DataUseCorruptionError):
        store.get_record(TENANT, "asset", "corrupt-me")


def _installation_limits(monkeypatch: pytest.MonkeyPatch, **limits: int) -> None:
    from maverick import config

    monkeypatch.setattr(
        config, "load_config", lambda *a, **k: {"data_use_governance": {"limits": limits}}
    )


def test_installation_caps_how_many_assets_fields_and_links_a_workspace_registers(
    authority: tuple[DataUseGovernanceStore, Clock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _clock = authority
    _catalog(store)  # no limits set: nothing changes
    _installation_limits(monkeypatch, max_assets=1, max_fields=3)
    with pytest.raises(DataUseValidationError, match="most asset records"):
        store.put_asset(
            TENANT, "orders", asset_type="table",
            catalog_binding_sha256=_digest("orders"), expected_revision=0,
            idempotency_key="asset-over-cap",
        )
    with pytest.raises(DataUseValidationError, match="most field records"):
        store.put_field(
            TENANT, "customers", "phone", data_type="string", nullable=True,
            catalog_binding_sha256=_digest("phone"), expected_revision=0,
            idempotency_key="field-over-cap",
        )
    # Another workspace has its own count.
    store.put_asset(
        OTHER_TENANT, "customers", asset_type="table",
        catalog_binding_sha256=_digest("other"), expected_revision=0,
        idempotency_key="other-asset",
    )


def test_installation_context_age_limit_refuses_and_expires_old_facts(
    authority: tuple[DataUseGovernanceStore, Clock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _clock = authority
    _catalog(store)
    _installation_limits(monkeypatch, max_context_age_seconds=600)
    with pytest.raises(DataUseValidationError, match="freshness is longer"):
        _contexts(store)  # observed 900, declared fresh until 2000: 1100 s
    _installation_limits(monkeypatch)
    _contexts(store)
    _label(store)
    _request(store, "aged")
    _installation_limits(monkeypatch, max_context_age_seconds=60)  # now 1000 - 900 > 60
    decision = _authorize(store, "aged")
    assert decision["outcome"] == "deny"
    assert any(reason.startswith("stale_context:") for reason in decision["reasons"])
