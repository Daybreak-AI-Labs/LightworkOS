from __future__ import annotations

import copy
import hashlib
import inspect
import json
import sqlite3
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace

import pytest
from maverick import compliance_scope_actions as actions


class MutableClock:
    def __init__(self, value: float = 2_100_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def responsibilities() -> dict[str, str]:
    return {
        "first_line": "ref:business-owner",
        "second_line": "ref:risk-owner",
        "control_owner": "ref:control-owner",
        "evidence_owner": "ref:evidence-owner",
    }


def finalized_scope(clock: MutableClock) -> dict[str, object]:
    assignments = responsibilities()
    return {
        "tenant_id": "tenant-a",
        "scope_id": "scope-final-a",
        "scope_revision": 3,
        "scope_integrity_sha256": digest("final-scope-v3"),
        "assessment_id": "assessment-a",
        "assessment_revision": 11,
        "assessment_integrity_sha256": digest("assessment-v11"),
        "status": "finalized",
        "applicable_frameworks": ["framework-baseline", "framework-privacy"],
        "control_applicability": [
            {
                "framework_ref": "framework-baseline",
                "control_ref": "control-inventory",
                "reason_codes": ["baseline_scope", "system_present"],
                "responsibilities": assignments,
            },
            {
                "framework_ref": "framework-privacy",
                "control_ref": "control-records",
                "reason_codes": ["regulated_data"],
                "responsibilities": assignments,
            },
        ],
        "responsibility_assignments": assignments,
        "retained_until": clock() + 20_000,
    }


def catalog_entries() -> list[dict[str, object]]:
    return [
        {
            "entry_id": "map-inventory",
            "framework_ref": "framework-baseline",
            "scope_control_ref": "control-inventory",
            "desired_control_ref": "register-asset-inventory",
            "desired_control_state": "planned",
            "control_owner_role": "control_owner",
            "evidence_tasks": [
                {
                    "evidence_mapping_ref": "evidence-map-shared-inventory",
                    "task_kind": "collect",
                    "owner_role": "evidence_owner",
                    "cadence": "quarterly",
                }
            ],
        },
        {
            "entry_id": "map-records",
            "framework_ref": "framework-privacy",
            "scope_control_ref": "control-records",
            "desired_control_ref": "register-data-records",
            "desired_control_state": "not_started",
            "control_owner_role": "second_line",
            "evidence_tasks": [
                {
                    "evidence_mapping_ref": "evidence-map-record-review",
                    "task_kind": "review",
                    "owner_role": "second_line",
                    "cadence": "annual",
                },
                {
                    "evidence_mapping_ref": "evidence-map-shared-inventory",
                    "task_kind": "collect",
                    "owner_role": "evidence_owner",
                    "cadence": "quarterly",
                },
            ],
        },
    ]


class LocalApplier:
    def __init__(self) -> None:
        self.requests: list[dict[str, object]] = []
        self.outcomes = ["no_change", "reconciled", "rolled_back"]

    def __call__(self, request: object) -> dict[str, object]:
        assert isinstance(request, dict)
        captured = copy.deepcopy(request)
        self.requests.append(captured)
        operation = str(request["operation"])
        outcome = self.outcomes.pop(0)
        if operation == "rollback":
            change = "removed"
        elif outcome == "no_change":
            change = "reused"
        else:
            change = "updated"
        intents = [
            *request["control_intents"],
            *request["evidence_task_intents"],
        ]
        return {
            "operation": operation,
            "operation_ref": request["operation_ref"],
            "desired_sha256": request["desired_sha256"],
            "outcome": outcome,
            "intent_bindings": [
                {
                    "intent_id": intent["intent_id"],
                    "resource_ref": f"ref:local-{intent['intent_id']}",
                    "change": change,
                }
                for intent in intents
            ],
        }


@pytest.fixture
def authority(tmp_path: Path):
    actor = {"value": "catalog-author"}
    clock = MutableClock()
    scope_state = finalized_scope(clock)
    resolver_calls: list[tuple[str, str]] = []

    def resolver(tenant_id: str, scope_id: str) -> dict[str, object]:
        resolver_calls.append((tenant_id, scope_id))
        value = copy.deepcopy(scope_state)
        return value

    applier = LocalApplier()
    store = actions.ComplianceScopeActionStore(
        tmp_path / "scope-actions.sqlite3",
        scope_resolver=resolver,
        config_gate=lambda: None,
        principal_resolver=lambda: actor["value"],
        apply_callback=applier,
        signing_key_resolver=lambda _tenant, _ref: b"scope-actions-signing-key-material",
        clock=clock,
    )
    return store, actor, clock, scope_state, resolver_calls, applier


def publish_catalog(
    store: actions.ComplianceScopeActionStore,
    actor: dict[str, str],
) -> actions.ActionCatalogVersion:
    actor["value"] = "catalog-author"
    created = store.create_catalog_version(
        "tenant-a",
        "catalog-a",
        entries=catalog_entries(),
        expected_latest_version=0,
        idempotency_key="catalog-create",
    )
    actor["value"] = "catalog-reviewer"
    return store.approve_catalog_version(
        "tenant-a",
        "catalog-a",
        1,
        expected_revision=created.revision,
        idempotency_key="catalog-approve",
    )


def create_plan(
    store: actions.ComplianceScopeActionStore,
    actor: dict[str, str],
    clock: MutableClock,
) -> actions.ScopeActionPlan:
    publish_catalog(store, actor)
    actor["value"] = "scope-planner"
    return store.create_plan(
        "tenant-a",
        "scope-final-a",
        "plan-a",
        catalog_id="catalog-a",
        catalog_version=1,
        expected_scope_revision=3,
        retained_until=clock() + 10_000,
        idempotency_key="plan-create",
    )


def approve_plan(
    store: actions.ComplianceScopeActionStore,
    actor: dict[str, str],
    clock: MutableClock,
) -> actions.ScopeActionPlan:
    plan = create_plan(store, actor, clock)
    actor["value"] = "plan-reviewer"
    return store.approve_plan(
        "tenant-a",
        plan.plan_id,
        expected_revision=plan.revision,
        idempotency_key="plan-approve",
    )


def test_exact_two_level_gate_is_default_off(monkeypatch, tmp_path: Path) -> None:
    from maverick import config

    monkeypatch.setattr(config, "config_source_errors", list)
    disabled = (
        {},
        {"tech_risk_compliance": {"enable": True}},
        {
            "tech_risk_compliance": {
                "enable": False,
                "scope_actions": {"enable": True},
            }
        },
        {
            "tech_risk_compliance": {
                "enable": True,
                "scope_actions": {"enable": False},
            }
        },
        {
            "tech_risk_compliance": {
                "enable": 1,
                "scope_actions": {"enable": True},
            }
        },
    )
    for index, configured in enumerate(disabled):
        monkeypatch.setattr(config, "load_config", lambda value=configured: value)
        assert actions.enabled() is False
        with pytest.raises(actions.ComplianceScopeActionConfigError):
            actions.ComplianceScopeActionStore(
                tmp_path / f"disabled-{index}.sqlite3",
                scope_resolver=lambda _tenant, _scope: {},
            )
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "tech_risk_compliance": {
                "enable": True,
                "scope_actions": {"enable": True},
            }
        },
    )
    assert actions.enabled() is True


def test_public_operations_derive_actor_and_scope_from_trusted_seams(
    tmp_path: Path,
) -> None:
    for name, method in inspect.getmembers(
        actions.ComplianceScopeActionStore, predicate=inspect.isfunction
    ):
        if name.startswith("_") or name == "product_boundaries":
            continue
        assert "actor" not in inspect.signature(method).parameters
        assert "actor_ref" not in inspect.signature(method).parameters
    create_parameters = inspect.signature(actions.ComplianceScopeActionStore.create_plan).parameters
    for forbidden in (
        "control_applicability",
        "responsibility_assignments",
        "assessment_id",
        "assessment_integrity_sha256",
        "scope_integrity_sha256",
    ):
        assert forbidden not in create_parameters

    store = actions.ComplianceScopeActionStore(
        tmp_path / "anonymous.sqlite3",
        scope_resolver=lambda _tenant, _scope: {},
        config_gate=lambda: None,
        principal_resolver=lambda: None,
    )
    with pytest.raises(actions.ComplianceScopeActionPermissionDenied):
        store.get_plan("tenant-a", "plan-a")


def test_catalog_is_strict_versioned_idempotent_and_four_eyes(authority) -> None:
    store, actor, clock, _scope, _calls, _applier = authority
    created = store.create_catalog_version(
        "tenant-a",
        "catalog-a",
        entries=catalog_entries(),
        expected_latest_version=0,
        idempotency_key="catalog-create",
    )
    replay = store.create_catalog_version(
        "tenant-a",
        "catalog-a",
        entries=catalog_entries(),
        expected_latest_version=0,
        idempotency_key="catalog-create",
    )
    assert replay == created
    actor["value"] = "scope-planner"
    with pytest.raises(actions.ComplianceScopeActionConflict, match="approved catalogs"):
        store.create_plan(
            "tenant-a",
            "scope-final-a",
            "pending-catalog-plan",
            catalog_id="catalog-a",
            catalog_version=1,
            expected_scope_revision=3,
            retained_until=clock() + 1_000,
            idempotency_key="pending-catalog-plan",
        )
    actor["value"] = "catalog-author"
    with pytest.raises(actions.ComplianceScopeActionPermissionDenied):
        store.approve_catalog_version(
            "tenant-a",
            "catalog-a",
            1,
            expected_revision=1,
            idempotency_key="self-approve",
        )
    actor["value"] = "catalog-reviewer"
    published = store.approve_catalog_version(
        "tenant-a",
        "catalog-a",
        1,
        expected_revision=1,
        idempotency_key="catalog-approve",
    )
    assert published.status == "published"
    assert published.created_by == "catalog-author"
    assert published.reviewed_by == "catalog-reviewer"
    with pytest.raises(actions.ComplianceScopeActionConflict):
        store.create_catalog_version(
            "tenant-a",
            "catalog-a",
            entries=catalog_entries(),
            expected_latest_version=0,
            idempotency_key="stale-version",
        )
    with pytest.raises(actions.ComplianceScopeActionNotFound):
        store.get_catalog_version("tenant-b", "catalog-a", 1)

    raw_evidence = "licensed framework prose and raw customer evidence secret"
    extra = catalog_entries()
    extra[0]["raw_evidence"] = raw_evidence
    with pytest.raises(actions.ComplianceScopeActionValidationError):
        store.create_catalog_version(
            "tenant-a",
            "bad-extra",
            entries=extra,
            expected_latest_version=0,
            idempotency_key="bad-extra",
        )
    assert raw_evidence.encode("utf-8") not in store.path.read_bytes()
    conflict = catalog_entries()
    conflict[1]["evidence_tasks"][1]["cadence"] = "monthly"
    with pytest.raises(actions.ComplianceScopeActionValidationError):
        store.create_catalog_version(
            "tenant-a",
            "bad-shared-contract",
            entries=conflict,
            expected_latest_version=0,
            idempotency_key="bad-shared-contract",
        )
    arbitrary = catalog_entries()
    arbitrary[0]["desired_control_ref"] = "__import__('os').system('whoami')"
    with pytest.raises(actions.ComplianceScopeActionValidationError):
        store.create_catalog_version(
            "tenant-a",
            "bad-code",
            entries=arbitrary,
            expected_latest_version=0,
            idempotency_key="bad-code",
        )


def test_plan_pins_authority_and_carries_reason_coded_operating_model(authority) -> None:
    store, actor, clock, scope, resolver_calls, _applier = authority
    plan = create_plan(store, actor, clock)
    assert resolver_calls[-1] == ("tenant-a", "scope-final-a")
    assert plan.scope_revision == scope["scope_revision"]
    assert plan.scope_integrity_sha256 == scope["scope_integrity_sha256"]
    assert plan.assessment_revision == scope["assessment_revision"]
    assert plan.assessment_integrity_sha256 == scope["assessment_integrity_sha256"]
    assert plan.catalog_version == 1
    assert plan.responsibility_assignments == responsibilities()
    assert len(plan.control_intents) == 2
    assert len(plan.evidence_task_intents) == 2

    controls = {item["control_ref"]: item for item in plan.control_intents}
    inventory = controls["register-asset-inventory"]
    assert inventory["first_line_ref"] == "ref:business-owner"
    assert inventory["second_line_ref"] == "ref:risk-owner"
    assert inventory["owner_ref"] == "ref:control-owner"
    assert inventory["evidence_owner_ref"] == "ref:evidence-owner"
    assert inventory["reason_codes"] == ["baseline_scope", "system_present"]

    evidence = {item["evidence_mapping_ref"]: item for item in plan.evidence_task_intents}
    shared = evidence["evidence-map-shared-inventory"]
    assert shared["owner_ref"] == "ref:evidence-owner"
    assert shared["second_line_ref"] == "ref:risk-owner"
    assert shared["control_refs"] == [
        "register-asset-inventory",
        "register-data-records",
    ]
    assert shared["reason_codes"] == [
        "baseline_scope",
        "regulated_data",
        "system_present",
    ]
    assert (
        len(
            [
                item
                for item in plan.evidence_task_intents
                if item["evidence_mapping_ref"] == "evidence-map-shared-inventory"
            ]
        )
        == 1
    )

    replay = store.create_plan(
        "tenant-a",
        "scope-final-a",
        "plan-a",
        catalog_id="catalog-a",
        catalog_version=1,
        expected_scope_revision=3,
        retained_until=clock() + 10_000,
        idempotency_key="plan-create",
    )
    assert replay == plan
    with pytest.raises(actions.ComplianceScopeActionConflict):
        store.create_plan(
            "tenant-a",
            "scope-final-a",
            "plan-forged-revision",
            catalog_id="catalog-a",
            catalog_version=1,
            expected_scope_revision=4,
            retained_until=clock() + 10_000,
            idempotency_key="forged-revision",
        )


def test_finalized_scope_and_complete_mapping_fail_closed(authority) -> None:
    store, actor, clock, scope, _calls, _applier = authority
    publish_catalog(store, actor)
    actor["value"] = "scope-planner"
    scope["status"] = "approved"
    with pytest.raises(actions.ComplianceScopeActionConflict, match="finalized"):
        store.create_plan(
            "tenant-a",
            "scope-final-a",
            "not-final",
            catalog_id="catalog-a",
            catalog_version=1,
            expected_scope_revision=3,
            retained_until=clock() + 1_000,
            idempotency_key="not-final",
        )
    scope["status"] = "finalized"
    scope["control_applicability"].append(
        {
            "framework_ref": "framework-baseline",
            "control_ref": "control-unmapped",
            "reason_codes": ["new_reason"],
            "responsibilities": responsibilities(),
        }
    )
    with pytest.raises(actions.ComplianceScopeActionConflict, match="does not map"):
        store.create_plan(
            "tenant-a",
            "scope-final-a",
            "unmapped",
            catalog_id="catalog-a",
            catalog_version=1,
            expected_scope_revision=3,
            retained_until=clock() + 1_000,
            idempotency_key="unmapped",
        )


def test_plan_requires_independent_approval_and_rechecks_scope_pin(authority) -> None:
    store, actor, clock, scope, _calls, applier = authority
    plan = create_plan(store, actor, clock)
    with pytest.raises(actions.ComplianceScopeActionPermissionDenied):
        store.approve_plan(
            "tenant-a",
            plan.plan_id,
            expected_revision=plan.revision,
            idempotency_key="self-plan-approve",
        )
    actor["value"] = "plan-reviewer"
    approved = store.approve_plan(
        "tenant-a",
        plan.plan_id,
        expected_revision=plan.revision,
        idempotency_key="plan-approve",
    )
    assert approved.status == "approved"
    assert approved.approved_by == "plan-reviewer"

    scope["scope_revision"] = 4
    scope["scope_integrity_sha256"] = digest("changed-scope")
    actor["value"] = "scope-planner"
    with pytest.raises(actions.ComplianceScopeActionConflict, match="changed"):
        store.apply_plan(
            "tenant-a",
            approved.plan_id,
            expected_revision=approved.revision,
            idempotency_key="drifted-apply",
        )
    assert applier.requests == []
    assert store.get_plan("tenant-a", plan.plan_id).status == "approved"


def test_expired_authoritative_scope_blocks_approval(authority) -> None:
    store, actor, clock, scope, _calls, _applier = authority
    plan = create_plan(store, actor, clock)
    scope["retained_until"] = clock() - 1
    actor["value"] = "plan-reviewer"
    with pytest.raises(actions.ComplianceScopeActionConflict, match="expired"):
        store.approve_plan(
            "tenant-a",
            plan.plan_id,
            expected_revision=plan.revision,
            idempotency_key="expired-approve",
        )
    assert store.get_plan("tenant-a", plan.plan_id).status == "draft"


def test_apply_no_change_reconcile_and_rollback_are_explicit(authority) -> None:
    store, actor, clock, _scope, _calls, applier = authority
    approved = approve_plan(store, actor, clock)
    actor["value"] = "scope-planner"
    unchanged = store.apply_plan(
        "tenant-a",
        approved.plan_id,
        expected_revision=approved.revision,
        idempotency_key="apply",
    )
    assert unchanged.status == "no_change"
    assert unchanged.last_outcome == "no_change"
    assert unchanged.last_receipt is not None
    assert {item["change"] for item in unchanged.last_receipt["intent_bindings"]} == {"reused"}
    replay = store.apply_plan(
        "tenant-a",
        approved.plan_id,
        expected_revision=approved.revision,
        idempotency_key="apply",
    )
    assert replay == unchanged
    assert len(applier.requests) == 1

    reconciled = store.reconcile_plan(
        "tenant-a",
        unchanged.plan_id,
        expected_revision=unchanged.revision,
        idempotency_key="reconcile",
    )
    assert reconciled.status == "applied"
    assert reconciled.last_outcome == "reconciled"
    assert reconciled.reconciliation_count == 1
    rolled_back = store.rollback_plan(
        "tenant-a",
        reconciled.plan_id,
        expected_revision=reconciled.revision,
        idempotency_key="rollback",
    )
    assert rolled_back.status == "rolled_back"
    assert rolled_back.last_outcome == "rolled_back"
    assert rolled_back.rollback_of_revision == reconciled.revision
    assert [item.status for item in store.get_plan_history("tenant-a", "plan-a")] == [
        "draft",
        "approved",
        "no_change",
        "applied",
        "rolled_back",
    ]

    request = applier.requests[0]
    assert request["schema"] == actions.APPLY_SCHEMA
    assert request["responsibility_assignments"] == responsibilities()
    assert "raw_evidence" not in json.dumps(request)


def test_without_local_callback_plan_remains_write_free(tmp_path: Path) -> None:
    actor = {"value": "catalog-author"}
    clock = MutableClock()
    scope = finalized_scope(clock)
    store = actions.ComplianceScopeActionStore(
        tmp_path / "write-free.sqlite3",
        scope_resolver=lambda _tenant, _scope: copy.deepcopy(scope),
        config_gate=lambda: None,
        principal_resolver=lambda: actor["value"],
        signing_key_resolver=lambda _tenant, _ref: b"s" * 32,
        clock=clock,
    )
    approved = approve_plan(store, actor, clock)
    with pytest.raises(actions.ComplianceScopeActionConfigError, match="write-free"):
        store.apply_plan(
            "tenant-a",
            approved.plan_id,
            expected_revision=approved.revision,
            idempotency_key="apply",
        )
    assert store.get_plan("tenant-a", approved.plan_id).status == "approved"


def test_ambiguous_callback_retry_reuses_exact_operation_ref(authority) -> None:
    store, actor, clock, _scope, _calls, _applier = authority
    approved = approve_plan(store, actor, clock)
    actor["value"] = "plan-operator"
    attempts: list[str] = []

    def idempotent_callback(request: Mapping[str, object]) -> dict[str, object]:
        operation_ref = str(request["operation_ref"])
        attempts.append(operation_ref)
        if len(attempts) == 1:
            raise RuntimeError("response lost after the callback-side write")
        intents = [
            *request["control_intents"],
            *request["evidence_task_intents"],
        ]
        return {
            "operation": "apply",
            "operation_ref": operation_ref,
            "desired_sha256": request["desired_sha256"],
            "outcome": "applied",
            "intent_bindings": [
                {
                    "intent_id": intent["intent_id"],
                    "resource_ref": f"ref:local-{intent['intent_id']}",
                    "change": "reused",
                }
                for intent in intents
            ],
        }

    store._apply_callback = idempotent_callback
    with pytest.raises(actions.ComplianceScopeActionConflict, match="state was not advanced"):
        store.apply_plan(
            "tenant-a",
            approved.plan_id,
            expected_revision=approved.revision,
            idempotency_key="ambiguous-apply",
        )
    assert store.get_plan("tenant-a", approved.plan_id).status == "approved"

    recovered = store.apply_plan(
        "tenant-a",
        approved.plan_id,
        expected_revision=approved.revision,
        idempotency_key="ambiguous-apply",
    )
    assert recovered.status == "applied"
    assert recovered.last_outcome == "applied"
    assert len(attempts) == 2 and attempts[0] == attempts[1]


def test_invalid_apply_receipt_is_atomic(authority) -> None:
    store, actor, clock, _scope, _calls, applier = authority
    approved = approve_plan(store, actor, clock)

    def invalid_callback(request: Mapping[str, object]) -> dict[str, object]:
        return {
            "operation": request["operation"],
            "operation_ref": request["operation_ref"],
            "desired_sha256": request["desired_sha256"],
            "outcome": "applied",
            "intent_bindings": [],
        }

    store._apply_callback = invalid_callback
    actor["value"] = "scope-planner"
    with pytest.raises(actions.ComplianceScopeActionIntegrityError, match="every"):
        store.apply_plan(
            "tenant-a",
            approved.plan_id,
            expected_revision=approved.revision,
            idempotency_key="invalid-receipt",
        )
    assert store.get_plan("tenant-a", approved.plan_id).status == "approved"
    assert applier.requests == []


def test_signed_export_audit_integrity_and_no_sensitive_payload(authority) -> None:
    store, actor, clock, _scope, _calls, _applier = authority
    approved = approve_plan(store, actor, clock)
    exported = store.export_plan(
        "tenant-a",
        approved.plan_id,
        "export-a",
        signing_key_ref="vault:scope-action-signing-v1",
        retained_until=clock() + 5_000,
        idempotency_key="export",
    )
    assert exported.schema == actions.EXPORT_SCHEMA
    assert store.get_export("tenant-a", "export-a") == exported
    verification = store.verify_integrity("tenant-a")
    assert verification.audit_events >= 5
    assert verification.verified_records >= verification.audit_events
    assert verification.terminal_audit_sha256 != "0" * 64

    raw_evidence = "licensed framework prose and raw customer evidence secret"
    database_bytes = store.path.read_bytes()
    assert raw_evidence.encode("utf-8") not in database_bytes
    assert b"scope-actions-signing-key-material" not in database_bytes
    boundaries = store.product_boundaries()
    assert boundaries == {
        "authority": "local_provider_neutral",
        "scope_source": "injected_finalized_scope_resolver",
        "mapping_catalog": "opaque_refs_only_four_eyes",
        "licensed_framework_content_included": False,
        "raw_evidence_persisted": False,
        "free_text_task_descriptions_persisted": False,
        "arbitrary_code_or_expression_evaluation": False,
        "built_in_provider_writes": False,
        "apply_requires_injected_local_callback": True,
        "callback_must_be_idempotent": True,
        "cross_store_atomicity": False,
        "callback_exception_proves_no_change": False,
        "live_provider_acceptance_verified": False,
        "legal_or_certification_determination": False,
    }

    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            "SELECT payload_json FROM scope_action_exports WHERE tenant_id=? AND export_id=?",
            ("tenant-a", "export-a"),
        ).fetchone()
        assert row is not None
        payload = json.loads(row[0])
        payload["body_sha256"] = "0" * 64
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE scope_action_exports SET payload_json=? WHERE tenant_id=? AND export_id=?",
                (json.dumps(payload), "tenant-a", "export-a"),
            )


def test_current_plan_must_match_latest_immutable_history(authority) -> None:
    store, actor, clock, _scope, _calls, _applier = authority
    approve_plan(store, actor, clock)
    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            "SELECT payload_json FROM scope_action_plans WHERE tenant_id=? AND plan_id=?",
            ("tenant-a", "plan-a"),
        ).fetchone()
        assert row is not None
        payload = json.loads(row[0])
        payload["last_outcome"] = "tampered"
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        connection.execute(
            "UPDATE scope_action_plans SET payload_json=?,integrity_sha256=? "
            "WHERE tenant_id=? AND plan_id=?",
            (
                encoded,
                hashlib.sha256(encoded.encode("ascii")).hexdigest(),
                "tenant-a",
                "plan-a",
            ),
        )
    with pytest.raises(actions.ComplianceScopeActionIntegrityError, match="history"):
        store.verify_integrity("tenant-a")


def test_non_ascii_stored_digests_are_integrity_errors_not_type_errors(authority) -> None:
    # An edited export signature or row digest must not raise TypeError from
    # hmac.compare_digest instead of the store's integrity refusal.
    store, actor, clock, _scope, _calls, _applier = authority
    approved = approve_plan(store, actor, clock)
    store.export_plan(
        "tenant-a",
        approved.plan_id,
        "export-a",
        signing_key_ref="vault:scope-action-signing-v1",
        retained_until=clock() + 5_000,
        idempotency_key="export",
    )
    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            "SELECT payload_json FROM scope_action_exports WHERE tenant_id=? AND export_id=?",
            ("tenant-a", "export-a"),
        ).fetchone()
        payload = json.loads(row[0])
        payload["signature_hmac_sha256"] = "é" * 64
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        )
        connection.execute("DROP TRIGGER scope_action_export_no_update")
        connection.execute(
            "UPDATE scope_action_exports SET payload_json=?,integrity_sha256=? "
            "WHERE tenant_id=? AND export_id=?",
            (encoded, hashlib.sha256(encoded.encode("ascii")).hexdigest(), "tenant-a", "export-a"),
        )
        connection.execute(
            "UPDATE scope_action_plans SET integrity_sha256=? WHERE tenant_id=? AND plan_id=?",
            ("é" * 64, "tenant-a", approved.plan_id),
        )
    with pytest.raises(actions.ComplianceScopeActionIntegrityError, match="signature"):
        store.get_export("tenant-a", "export-a")
    with pytest.raises(actions.ComplianceScopeActionIntegrityError, match="integrity check"):
        store.get_plan("tenant-a", approved.plan_id)


def test_scoping_store_adapter_pins_scope_and_assessment() -> None:
    scope = SimpleNamespace(
        tenant_id="tenant-a",
        scope_id="scope-a",
        assessment_id="assessment-a",
        revision=3,
        integrity_sha256=digest("scope"),
        status="finalized",
        applicable_frameworks=("framework-a",),
        control_applicability=(
            {
                "framework_ref": "framework-a",
                "control_ref": "control-a",
                "reason_codes": ["reason-a"],
                "responsibilities": responsibilities(),
            },
        ),
        responsibility_assignments=responsibilities(),
        retained_until=2_100_010_000.0,
    )
    assessment = SimpleNamespace(
        assessment_id="assessment-a",
        revision=9,
        integrity_sha256=digest("assessment"),
    )

    class FakeScopeStore:
        def get_scope(self, tenant_id: str, scope_id: str):
            assert (tenant_id, scope_id) == ("tenant-a", "scope-a")
            return scope

        def get_assessment(self, tenant_id: str, assessment_id: str):
            assert (tenant_id, assessment_id) == ("tenant-a", "assessment-a")
            return assessment

    resolved = actions.resolver_from_scoping_store(FakeScopeStore())("tenant-a", "scope-a")
    assert resolved["scope_revision"] == 3
    assert resolved["assessment_revision"] == 9
    assert resolved["assessment_integrity_sha256"] == digest("assessment")
