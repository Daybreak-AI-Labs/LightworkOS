"""Adversarial and binding tests for the data-use policy compiler."""

from __future__ import annotations

import hashlib
import itertools
import json
from pathlib import Path
from typing import Any

import pytest
from maverick.data_use_governance import (
    DataUseCorruptionError,
    DataUseGovernanceStore,
)
from maverick.data_use_policy_compiler import (
    CONTROL_IR_SCHEMA,
    DataUseCompilationStale,
    DataUseCompilationValidationError,
    DataUsePolicyCompiler,
    DataUseProviderOperationError,
    DataUseUnsafeFilter,
    DataUseUnsupportedType,
    normalize_row_filter_ast,
    thaw_control_ir,
)

from tests.test_data_use_governance import (
    TENANT,
    Clock,
    _authorize,
    _catalog,
    _contexts,
    _digest,
    _label,
    _policy,
    _ready,
    _request,
)


def _object_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest()


@pytest.fixture
def authority(tmp_path: Path) -> tuple[DataUseGovernanceStore, Clock]:
    counter = itertools.count(1)
    clock = Clock()
    return (
        DataUseGovernanceStore(
            tmp_path / "compiler.sqlite",
            clock=clock,
            id_factory=lambda prefix: f"{prefix}-{next(counter)}",
        ),
        clock,
    )


def _row_policy(store: DataUseGovernanceStore) -> None:
    document = {
        "scope": {
            "asset_ids": ["customers"],
            "field_ids": [],
            "project_ids": [],
            "actions": ["read"],
        },
        "conditions": {
            "business_purpose_any": ["analytics"],
            "regulatory_any": ["gdpr"],
            "consent_any": ["granted"],
            "observed_classification_any": ["personal"],
            "label_any": [],
        },
        "controls": [
            {
                "control_id": "mask-email",
                "effect": "mask",
                "field_ids": ["email"],
                "mask_method": "hash_sha256",
            },
            {
                "control_id": "us-region-only",
                "effect": "row_filter",
                "field_ids": [],
                "row_filter": {
                    "op": "eq",
                    "field": "region",
                    "value": "US",
                },
            },
        ],
    }
    draft = store.put_policy_version(
        TENANT,
        "masked-regional-access",
        version=1,
        document=document,
        author_id="policy-author",
        author_authority_sha256=_digest("policy-author"),
        expected_current_version=0,
        expected_revision=0,
        idempotency_key="row-policy-draft",
    )
    store.activate_policy(
        TENANT,
        "masked-regional-access",
        version=1,
        reviewer_id="policy-reviewer",
        reviewer_authority_sha256=_digest("policy-reviewer"),
        reviewed_at=980.0,
        expected_revision=int(draft["revision"]),
        idempotency_key="row-policy-activate",
    )


def _compiled_decision(
    store: DataUseGovernanceStore,
) -> tuple[dict[str, object], DataUsePolicyCompiler]:
    _ready(store)
    _row_policy(store)
    _request(store, "compile-me", fields=("email", "region"))
    decision = _authorize(store, "compile-me")
    assert decision["outcome"] == "row_filter"
    return decision, DataUsePolicyCompiler(store, clock=lambda: 1_000.0)


def test_compilation_is_deterministic_immutable_and_digest_bound(
    authority: tuple[DataUseGovernanceStore, Clock],
) -> None:
    store, _clock = authority
    decision, compiler = _compiled_decision(store)
    first = compiler.compile(
        TENANT,
        str(decision["decision_id"]),
        expected_decision_sha256=str(decision["decision_sha256"]),
    )
    second = compiler.compile(TENANT, str(decision["decision_id"]))
    assert first == second
    material = thaw_control_ir(first)
    assert material["schema"] == CONTROL_IR_SCHEMA
    assert material["provider_writes_possible"] is False
    assert compiler.status()["provider_writes_possible"] is False
    assert {item["operation"] for item in material["desired_state"]} == {
        "mask",
        "row_filter",
    }
    assert {item["operation"] for item in material["rollback_state"]} == {"deny"}
    assert material["desired_state_sha256"] == _object_digest(
        {
            "kind": "desired",
            "bindings_sha256": material["bindings_sha256"],
            "controls": material["desired_state"],
        }
    )
    assert material["rollback_state_sha256"] == _object_digest(
        {
            "kind": "rollback",
            "bindings_sha256": material["bindings_sha256"],
            "controls": material["rollback_state"],
        }
    )
    ir_material = {
        key: value for key, value in material.items() if key not in {"compilation_id", "ir_sha256"}
    }
    assert material["ir_sha256"] == _object_digest(ir_material)
    assert material["compilation_id"] == f"duc-{material['ir_sha256'][:40]}"
    with pytest.raises(TypeError):
        first["provider_writes_possible"] = True  # type: ignore[index]
    with pytest.raises(TypeError):
        first["compiler"]["version"] = "tampered"  # type: ignore[index]


@pytest.mark.parametrize(
    ("ast", "field_types", "error"),
    [
        (
            {"op": "eq", "field": "missing", "value": "US"},
            {"region": "string"},
            DataUseUnsafeFilter,
        ),
        (
            {
                "op": "eq",
                "left": {
                    "function": "sql",
                    "args": [{"field": "region"}],
                },
                "value": "US",
            },
            {"region": "string"},
            DataUseUnsafeFilter,
        ),
        (
            {"op": "eq", "field": "region", "value": "US; DROP TABLE users"},
            {"region": "string"},
            DataUseUnsafeFilter,
        ),
        (
            {"op": "eq", "field": "region", "value": "US -- bypass"},
            {"region": "string"},
            DataUseUnsafeFilter,
        ),
        (
            {"op": "raw_sql", "field": "region", "value": "US"},
            {"region": "string"},
            DataUseUnsafeFilter,
        ),
        (
            {"op": "eq", "field": "payload", "value": {}},
            {"payload": "json"},
            DataUseUnsupportedType,
        ),
    ],
)
def test_row_filter_ast_rejects_injection_unknowns_and_unsupported_types(
    ast: dict[str, Any], field_types: dict[str, str], error: type[Exception]
) -> None:
    with pytest.raises(error):
        normalize_row_filter_ast(ast, field_types)


def test_row_filter_normalization_is_closed_and_order_deterministic() -> None:
    left = normalize_row_filter_ast(
        {
            "op": "and",
            "args": [
                {"op": "eq", "field": "region", "value": "US"},
                {"op": "gte", "field": "amount", "value": 10.5},
            ],
        },
        {"region": "string", "amount": "number"},
    )
    right = normalize_row_filter_ast(
        {
            "op": "and",
            "args": [
                {"op": "gte", "field": "amount", "value": 10.5},
                {"op": "eq", "field": "region", "value": "US"},
            ],
        },
        {"amount": "number", "region": "string"},
    )
    assert left == right
    assert "left" in left["args"][0]


def test_compiler_rejects_context_policy_and_label_staleness(
    authority: tuple[DataUseGovernanceStore, Clock],
) -> None:
    store, _clock = authority
    decision, compiler = _compiled_decision(store)
    current = store.get_record(
        TENANT,
        "context",
        store._context_record_id("customers", "consent"),
    )
    assert current is not None
    store.put_context_authority(
        TENANT,
        "customers",
        "consent",
        values=("withdrawn",),
        source_system="authority-consent",
        source_revision=99,
        source_authority_sha256=_digest("updated-consent-root"),
        evidence_sha256=_digest("updated-consent-evidence"),
        reviewer_id="updated-consent-reviewer",
        reviewer_authority_sha256=_digest("updated-consent-reviewer"),
        observed_at=995.0,
        fresh_until=2_100.0,
        expected_revision=int(current["revision"]),
        idempotency_key="update-consent-context",
    )
    with pytest.raises(DataUseCompilationStale):
        compiler.compile(TENANT, str(decision["decision_id"]))

    policy_store = DataUseGovernanceStore(store.path.parent / "policy-stale.sqlite", clock=_clock)
    policy_decision, policy_compiler = _compiled_decision(policy_store)
    pointer = policy_store.get_record(TENANT, "policy", "masked-regional-access")
    assert pointer is not None
    policy_store.retire_policy(
        TENANT,
        "masked-regional-access",
        expected_revision=int(pointer["revision"]),
        idempotency_key="retire-compiled-policy",
    )
    with pytest.raises(DataUseCompilationStale):
        policy_compiler.compile(TENANT, str(policy_decision["decision_id"]))

    label_store = DataUseGovernanceStore(store.path.parent / "label-stale.sqlite", clock=_clock)
    label_decision, label_compiler = _compiled_decision(label_store)
    label_pointer = label_store.get_record(TENANT, "label", "personal_data")
    assert label_pointer is not None
    label_store.publish_machine_label(
        TENANT,
        "personal_data",
        version=2,
        taxonomy_id="enterprise_taxonomy",
        sensitivity=90,
        definition_sha256=_digest("personal-data-definition-v2"),
        reviewer_id="label-reviewer-v2",
        reviewer_authority_sha256=_digest("label-reviewer-v2"),
        reviewed_at=990.0,
        expected_current_version=1,
        expected_revision=int(label_pointer["revision"]),
        idempotency_key="label-v2",
    )
    with pytest.raises(DataUseCompilationStale):
        label_compiler.compile(TENANT, str(label_decision["decision_id"]))


def test_missing_context_decision_cannot_be_compiled(
    authority: tuple[DataUseGovernanceStore, Clock],
) -> None:
    store, _clock = authority
    _catalog(store)
    _contexts(store, omit="regulatory")
    _label(store)
    _policy(store, "allow", "allow", control_id="allow-email")
    _request(store, "missing-regulatory")
    decision = _authorize(store, "missing-regulatory")
    assert decision["outcome"] == "deny"
    with pytest.raises(DataUseCompilationStale):
        DataUsePolicyCompiler(store, clock=lambda: 1_000.0).compile(
            TENANT, str(decision["decision_id"])
        )


def test_unsupported_catalog_type_is_rejected_even_for_default_deny(
    authority: tuple[DataUseGovernanceStore, Clock],
) -> None:
    store, _clock = authority
    _catalog(store)
    store.put_field(
        TENANT,
        "customers",
        "payload",
        data_type="binary",
        nullable=True,
        catalog_binding_sha256=_digest("payload-binary"),
        expected_revision=0,
        idempotency_key="payload-field",
    )
    _contexts(store)
    _request(store, "binary-request", fields=("payload",))
    decision = _authorize(store, "binary-request")
    with pytest.raises(DataUseUnsupportedType):
        DataUsePolicyCompiler(store, clock=lambda: 1_000.0).compile(
            TENANT, str(decision["decision_id"])
        )


class _BundleStore:
    def __init__(self, bundle: dict[str, Any]) -> None:
        self.bundle = bundle

    def resolve_compilation_authority(self, tenant_id: str, decision_id: str) -> dict[str, Any]:
        return self.bundle


def _rebind_bundle(bundle: dict[str, Any]) -> None:
    bundle["bundle_sha256"] = _object_digest(
        {key: value for key, value in bundle.items() if key != "bundle_sha256"}
    )


def _rebind_decision(bundle: dict[str, Any]) -> None:
    decision = bundle["decision"]
    decision["decision_sha256"] = _object_digest(
        {
            key: value
            for key, value in decision.items()
            if key
            not in {
                "revision",
                "record_sha256",
                "created_at",
                "updated_at",
                "decision_sha256",
            }
        }
    )
    _rebind_bundle(bundle)


def test_cross_tenant_and_corrupt_bundles_are_rejected(
    authority: tuple[DataUseGovernanceStore, Clock],
) -> None:
    store, _clock = authority
    decision, _compiler = _compiled_decision(store)
    original = store.resolve_compilation_authority(TENANT, str(decision["decision_id"]))

    cross_tenant = json.loads(json.dumps(original))
    cross_tenant["current_authority"]["fields"][0]["tenant_id"] = "tenant-beta"
    _rebind_bundle(cross_tenant)
    with pytest.raises(DataUseCompilationValidationError, match="cross-tenant"):
        DataUsePolicyCompiler(
            _BundleStore(cross_tenant),  # type: ignore[arg-type]
            clock=lambda: 1_000.0,
        ).compile(TENANT, str(decision["decision_id"]))


def test_tampered_policy_bindings_raw_filters_and_provider_fields_are_rejected(
    authority: tuple[DataUseGovernanceStore, Clock],
) -> None:
    store, _clock = authority
    decision, _compiler = _compiled_decision(store)
    original = store.resolve_compilation_authority(TENANT, str(decision["decision_id"]))

    policy_tamper = json.loads(json.dumps(original))
    policy_tamper["decision"]["controls"][0]["source_policy_sha256"] = "0" * 64
    _rebind_decision(policy_tamper)
    with pytest.raises(DataUseCompilationStale, match="exact active policy"):
        DataUsePolicyCompiler(
            _BundleStore(policy_tamper),  # type: ignore[arg-type]
            clock=lambda: 1_000.0,
        ).compile(TENANT, str(decision["decision_id"]))

    raw_filter = json.loads(json.dumps(original))
    row_control = next(
        item for item in raw_filter["decision"]["controls"] if item["effect"] == "row_filter"
    )
    row_control["row_filter"]["value"] = "US; DROP TABLE accounts"
    _rebind_decision(raw_filter)
    with pytest.raises(DataUseUnsafeFilter):
        DataUsePolicyCompiler(
            _BundleStore(raw_filter),  # type: ignore[arg-type]
            clock=lambda: 1_000.0,
        ).compile(TENANT, str(decision["decision_id"]))

    provider_field = json.loads(json.dumps(original))
    provider_field["decision"]["controls"][0]["provider_operation"] = "drop_table"
    _rebind_decision(provider_field)
    with pytest.raises(DataUseProviderOperationError, match="uncontrolled fields"):
        DataUsePolicyCompiler(
            _BundleStore(provider_field),  # type: ignore[arg-type]
            clock=lambda: 1_000.0,
        ).compile(TENANT, str(decision["decision_id"]))

    corrupt = json.loads(json.dumps(original))
    corrupt["decision"]["decision_sha256"] = "0" * 64
    _rebind_bundle(corrupt)
    with pytest.raises(DataUseCorruptionError, match="decision digest"):
        DataUsePolicyCompiler(
            _BundleStore(corrupt),  # type: ignore[arg-type]
            clock=lambda: 1_000.0,
        ).compile(TENANT, str(decision["decision_id"]))


def test_uncontrolled_provider_adapters_and_operations_are_rejected(
    authority: tuple[DataUseGovernanceStore, Clock],
) -> None:
    store, _clock = authority
    decision, _compiler = _compiled_decision(store)

    class BadAdapter:
        adapter_id = "bad-adapter"
        adapter_authority_sha256 = _digest("bad-adapter-authority")
        control_schema = CONTROL_IR_SCHEMA
        supported_effects = frozenset({"allow"})
        controlled_operations = frozenset({"apply_control_ir", "drop_table"})

        def apply_control_ir(self, control_ir, *, idempotency_sha256):
            raise AssertionError("must not execute")

        def rollback_control_ir(self, control_ir, *, idempotency_sha256):
            raise AssertionError("must not execute")

    with pytest.raises(DataUseProviderOperationError, match="uncontrolled"):
        DataUsePolicyCompiler(store, native_adapter=BadAdapter())  # type: ignore[arg-type]

    calls: list[str] = []

    class NarrowAdapter:
        adapter_id = "narrow-adapter"
        adapter_authority_sha256 = _digest("narrow-adapter-authority")
        control_schema = CONTROL_IR_SCHEMA
        supported_effects = frozenset({"allow"})
        controlled_operations = frozenset({"apply_control_ir", "rollback_control_ir"})

        def apply_control_ir(self, control_ir, *, idempotency_sha256):
            calls.append("apply")
            return {}

        def rollback_control_ir(self, control_ir, *, idempotency_sha256):
            calls.append("rollback")
            return {}

    narrow = DataUsePolicyCompiler(
        store,
        clock=lambda: 1_000.0,
        native_adapter=NarrowAdapter(),  # type: ignore[arg-type]
    )
    assert narrow.provider_writes_possible is True
    with pytest.raises(DataUseProviderOperationError, match="does not control"):
        narrow.compile(TENANT, str(decision["decision_id"]))
    assert calls == []

    class FullAdapter(NarrowAdapter):
        adapter_id = "full-adapter"
        adapter_authority_sha256 = _digest("full-adapter-authority")
        supported_effects = frozenset({"allow", "deny", "mask", "row_filter", "review"})

    full = DataUsePolicyCompiler(
        store,
        clock=lambda: 1_000.0,
        native_adapter=FullAdapter(),  # type: ignore[arg-type]
    )
    attached_ir = thaw_control_ir(full.compile(TENANT, str(decision["decision_id"])))
    assert attached_ir["provider_writes_possible"] is True
    assert attached_ir["native_adapter"]["adapter_authority_sha256"] == _digest(
        "full-adapter-authority"
    )
    assert calls == []


def test_freshness_expiry_rejects_previously_valid_compilation(
    authority: tuple[DataUseGovernanceStore, Clock],
) -> None:
    store, clock = authority
    decision, compiler = _compiled_decision(store)
    compiler.compile(TENANT, str(decision["decision_id"]))
    clock.value = 2_001.0
    expired = DataUsePolicyCompiler(store, clock=clock)
    with pytest.raises(DataUseCompilationStale):
        expired.compile(TENANT, str(decision["decision_id"]))


def _compiler_settings(monkeypatch: pytest.MonkeyPatch, **values: int) -> None:
    from maverick import config

    monkeypatch.setattr(
        config, "load_config", lambda *a, **k: {"data_use_governance": {"compiler": values}}
    )


def test_installation_caps_compiled_operations(
    authority: tuple[DataUseGovernanceStore, Clock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _clock = authority
    decision, compiler = _compiled_decision(store)
    _compiler_settings(monkeypatch, max_operations=1)
    with pytest.raises(DataUseCompilationValidationError, match="more operations"):
        compiler.compile(TENANT, str(decision["decision_id"]))
    _compiler_settings(monkeypatch, max_operations=10)
    assert compiler.compile(TENANT, str(decision["decision_id"]))


def test_installation_row_filter_bound_can_only_lower_the_built_in_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maverick.data_use_policy_compiler import compiler_limits

    ast = {"op": "and", "args": [
        {"op": "eq", "field": "region", "value": "US"},
        {"op": "eq", "field": "region", "value": "CA"},
    ]}
    assert normalize_row_filter_ast(ast, {"region": "string"})
    _compiler_settings(monkeypatch, max_row_filter_nodes=2)
    with pytest.raises(DataUseUnsafeFilter):
        normalize_row_filter_ast(ast, {"region": "string"})
    _compiler_settings(monkeypatch, max_row_filter_nodes=257)
    with pytest.raises(DataUseCompilationValidationError):
        compiler_limits()
