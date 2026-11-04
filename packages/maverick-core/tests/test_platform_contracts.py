from __future__ import annotations

import copy
import json
import tracemalloc
from decimal import Decimal, localcontext

import pytest
from maverick.platform_contracts import (
    CONTRACT_SCHEMAS,
    PlatformContractError,
    build_contract,
    export_contract,
    read_contract,
    transition_work_item,
)

NOW = 1_800_000_000.0
TENANT = "customer-a"


def _common(kind: str, fields: dict) -> dict:
    return build_contract(
        kind,
        contract_id=f"{kind}-1",
        tenant_id=TENANT,
        owner_id="procurement",
        purpose="Evaluate one bounded workflow",
        created_at=NOW,
        updated_at=NOW,
        revision=4,
        fields=fields,
        provenance={"source": "synthetic-test", "version": "1"},
        policy_snapshot_ref={"id": "policy", "version": 1, "sha256": "a" * 64},
        authority_versions={"policy": "7"},
        credential_versions={"jira": "3"},
        idempotency={"state": "bound", "key": "operation-1"},
        budget={"state": "bounded", "currency": "USD", "limit": "1.25", "spent": "0.25"},
        cost={"state": "exact", "currency": "USD", "amount": "0.25"},
        fresh_until=NOW + 3600,
        human_intervention={"required": True, "count": 1},
        uncertainty={"state": "bounded", "basis": "authoritative-readback"},
        causal_status={"state": "unknown", "basis": "not_estimated"},
    )


CONTRACT_CASES = [
    ("work-item", {
        "requester": "reviewer@example.test",
        "process": {"id": "journey", "version": 1, "sha256": "b" * 64},
        "supported_deployment": {"topology": "single_replica"},
        "acceptance_contract": {"technical": "verified", "business": "human"},
        "out_of_scope": ["payment"],
        "lifecycle": "Awaiting approval",
        "next_action": "review",
        "technical_effect": "not_verified",
        "business_outcome": "pending",
        "target_scope": {"provider": "jira", "project": "VEND"},
        "deployment_profile": {"topology": "single_replica"},
        "admission_id": "work-item-1",
        "acceptance_contract_ref": {"id": "acceptance-1"},
        "parent_work_item_id": None,
    }),
    ("action-intent", {
        "work_item_id": "work-item-1",
        "action": "jira.create",
        "parameters_sha256": "c" * 64,
        "preconditions": {"source_version": "4"},
        "authority_ref": {"actor": "reviewer@example.test"},
        "approval_ref": {"id": "approval-1"},
        "dispatch_state": "approved",
        "reconciliation": {"mode": "read_before_retry"},
        "target": {"provider": "jira", "account": "customer-a", "resource": "VEND"},
        "source_versions": {"document": "4"},
        "declared_effects": ["create_one_task"],
        "irreversible_effects": [],
        "credential_ref": {"kind": "managed_connection", "id": "jira"},
        "credential_version": "3",
        "expires_at": "2027-01-15T09:00:00.000Z",
        "budget_reservation": {"currency": "USD", "amount": "1.00"},
        "idempotency_scope": {"tenant": "customer-a", "operation": "operation-1"},
    }),
    ("observation", {
        "subject_ref": {"id": "ticket-1"},
        "source_version": "5",
        "observed_at": "2027-01-15T08:00:00.000Z",
        "collection_method": "authoritative_readback",
        "facts": [{"name": "status", "value": "created"}],
        "artifact_refs": [{"sha256": "d" * 64}],
        "intent_id": "action-intent-1",
        "source_locator": {"provider": "jira", "key": "VEND-1"},
        "collected_at": "2027-01-15T08:00:01.000Z",
        "provider_request_id": "request-1",
        "provider_receipt_id": "receipt-1",
        "raw_artifact_ref": {"sha256": "d" * 64},
        "asserted_fact": {"status": "created"},
        "collector_ref": {"kind": "jira_readback"},
    }),
    ("outcome-record", {
        "work_item_id": "work-item-1",
        "verdict": "accepted",
        "evaluator_ref": {"kind": "authorized_human"},
        "evidence_refs": [{"sha256": "e" * 64}],
        "unintended_changes": [],
        "human_interventions": 1,
        "cost_refs": ["cost-1"],
        "reason_codes": ["customer_accepted"],
        "acceptance_contract_ref": {"id": "acceptance-1", "version": 1},
        "actor_ref": {"id": "reviewer@example.test"},
        "supersedes_ref": None,
    }),
    ("experience-record", {
        "origin_refs": ["outcome-1"],
        "label_kind": "human_outcome",
        "rights_basis": "customer_owned",
        "training_eligible": False,
        "retention_deadline": "2028-01-15T08:00:00.000Z",
        "correction_refs": [],
        "derivative_refs": [],
        "source_versions": {"outcome-1": "1"},
        "sensitivity": {"classification": "customer_confidential"},
        "training_expires_at": {"state": "not_applicable"},
        "deletion_state": {"state": "retained"},
    }),
    ("experiment-spec", {
        "hypothesis": "The candidate reduces correction rate",
        "baseline_refs": ["baseline-1"],
        "split_refs": ["split-1"],
        "seeds": [7, 11],
        "primary_endpoint": "correction_rate",
        "stopping_rule": {"max_samples": 1000},
        "analysis_plan": {"method": "fixed_holdout"},
        "permitted_queries": ["aggregate_metrics"],
        "question": "Does the candidate reduce correction rate?",
        "environment_ref": {"sha256": "1" * 64},
        "dataset_refs": [{"sha256": "2" * 64}],
        "data_rights": {"basis": "owned"},
        "family_split_ref": {"sha256": "3" * 64},
        "component_versions": {"evaluator": "1"},
        "secondary_endpoints": ["latency"],
        "replication_plan": {"runs": 2},
        "protocol_registration": {"sha256": "4" * 64, "registered_at": "2027-01-15T08:00:00.000Z"},
    }),
    ("candidate-manifest", {
        "artifact_refs": [{"sha256": "f" * 64}],
        "parent_refs": ["candidate-0"],
        "data_rights": {"basis": "owned"},
        "dependency_refs": ["runtime-1"],
        "evaluation_refs": ["evaluation-1"],
        "applicability": {"workflow": "vendor_onboarding"},
        "permissions": ["sandbox_only"],
        "compatibility": {"python": "3.12"},
        "restore_target": "candidate-0",
        "reviewer_decision": {"state": "pending"},
        "resource_use": {"state": "unknown"},
        "rollout_plan": {"state": "sandbox_only"},
        "supported_domain": {"workflow": "vendor_onboarding"},
    }),
]


@pytest.fixture(params=CONTRACT_CASES, ids=lambda value: value[0])
def contract(request):
    kind, fields = request.param
    return kind, _common(kind, fields)


def test_every_platform_contract_has_one_versioned_envelope_and_round_trips(contract):
    kind, record = contract
    assert record["schema"] == CONTRACT_SCHEMAS[kind]
    assert record["schema_version"] == 1
    assert record["tenant_id"] == TENANT
    assert record["revision"] == 4
    assert record["created_at"].endswith("Z")
    assert read_contract(record, expected_kind=kind, expected_tenant_id=TENANT) == record


def test_legacy_v1_optional_fields_are_defaulted_without_changing_identity_or_meaning():
    current = _common("observation", {
        "subject_ref": {"id": "ticket-1"},
        "source_version": "5",
        "observed_at": "2027-01-15T08:00:00.000Z",
        "collection_method": "authoritative_readback",
        "facts": [{"name": "status", "value": "created"}],
        "artifact_refs": [],
        "intent_id": "action-intent-1",
        "source_locator": {"provider": "jira", "key": "VEND-1"},
        "collected_at": "2027-01-15T08:00:01.000Z",
        "provider_request_id": "request-1", "provider_receipt_id": "receipt-1",
        "raw_artifact_ref": {"sha256": "d" * 64},
        "asserted_fact": {"status": "created"},
        "collector_ref": {"kind": "jira_readback"},
    })
    legacy = copy.deepcopy(current)
    for optional in ("schema_version", "updated_at", "authority_versions", "credential_versions"):
        legacy.pop(optional)

    restored = read_contract(legacy, expected_kind="observation")
    assert restored["id"] == current["id"]
    assert restored["facts"] == current["facts"]
    assert restored["schema_version"] == 1
    assert restored["updated_at"] == current["created_at"]
    assert restored["authority_versions"] == {}
    assert restored["credential_versions"] == {}
    assert read_contract(restored) == restored


@pytest.mark.parametrize(("mutate", "code"), [
    (lambda value: value["budget"].update(limit=float("nan")), "invalid_budget"),
    (lambda value: value.update(schema="lightwork.contract.work-item.v999"), "unsupported_contract_schema"),
])
def test_malformed_budget_and_unknown_schema_fail_with_stable_codes(mutate, code):
    record = _common("work-item", {
        "requester": "requester",
        "process": {"id": "journey", "version": 1, "sha256": "b" * 64},
        "supported_deployment": {},
        "acceptance_contract": {},
        "out_of_scope": [],
        "lifecycle": "Draft",
        "next_action": "collect",
        "technical_effect": "not_verified",
        "business_outcome": "pending",
        "target_scope": {}, "deployment_profile": {}, "admission_id": "work-item-1",
        "acceptance_contract_ref": {}, "parent_work_item_id": None,
    })
    mutate(record)
    with pytest.raises(PlatformContractError) as raised:
        read_contract(record)
    assert raised.value.code == code


def test_tenant_mismatch_and_invalid_transition_fail_before_mutation():
    record = _common("work-item", {
        "requester": "requester",
        "process": {"id": "journey", "version": 1, "sha256": "b" * 64},
        "supported_deployment": {},
        "acceptance_contract": {},
        "out_of_scope": [],
        "lifecycle": "Draft",
        "next_action": "collect",
        "technical_effect": "not_verified",
        "business_outcome": "pending",
        "target_scope": {}, "deployment_profile": {}, "admission_id": "work-item-1",
        "acceptance_contract_ref": {}, "parent_work_item_id": None,
    })
    original = copy.deepcopy(record)
    with pytest.raises(PlatformContractError) as mismatch:
        read_contract(record, expected_tenant_id="customer-b")
    assert mismatch.value.code == "tenant_mismatch"
    with pytest.raises(PlatformContractError) as invalid:
        transition_work_item(record, "Accepted", expected_revision=4, updated_at=NOW + 1)
    assert invalid.value.code == "invalid_transition"
    assert record == original


def test_transition_requires_the_reviewed_revision_and_preserves_business_distinction():
    record = _common("work-item", {
        "requester": "requester",
        "process": {"id": "journey", "version": 1, "sha256": "b" * 64},
        "supported_deployment": {},
        "acceptance_contract": {},
        "out_of_scope": [],
        "lifecycle": "Running",
        "next_action": "wait",
        "technical_effect": "not_verified",
        "business_outcome": "pending",
        "target_scope": {}, "deployment_profile": {}, "admission_id": "work-item-1",
        "acceptance_contract_ref": {}, "parent_work_item_id": None,
    })
    observing = transition_work_item(
        record,
        "Awaiting observation",
        expected_revision=4,
        updated_at=NOW + 1,
        updates={"next_action": "observe"},
    )
    verified = transition_work_item(
        observing,
        "Verified",
        expected_revision=5,
        updated_at=NOW + 2,
        updates={"technical_effect": "verified", "next_action": "accept_or_reject"},
    )
    assert verified["revision"] == 6
    assert verified["technical_effect"] == "verified"
    assert verified["business_outcome"] == "pending"
    with pytest.raises(PlatformContractError) as conflict:
        transition_work_item(record, "Verified", expected_revision=3, updated_at=NOW + 1)
    assert conflict.value.code == "revision_conflict"


@pytest.mark.parametrize("lifecycle,effect", [
    ("Draft", "not_verified"), ("Ready", "not_verified"),
    ("Awaiting approval", "not_verified"), ("Running", "indeterminate"),
    ("Awaiting observation", "indeterminate"), ("Needs reconciliation", "indeterminate"),
    ("Verified", "verified"),
])
def test_cancellation_preserves_known_effects_and_permits_only_readback(lifecycle, effect):
    record = _common("work-item", dict(CONTRACT_CASES[0][1], lifecycle=lifecycle, technical_effect=effect))
    cancelled = transition_work_item(record, "Cancelled", expected_revision=4, updated_at=NOW + 1,
                                     updates={"next_action": "closed"})
    assert cancelled["technical_effect"] == effect
    assert cancelled["business_outcome"] == "pending"
    assert record["lifecycle"] == lifecycle
    reconciliation = transition_work_item(cancelled, "Needs reconciliation", expected_revision=5,
                                          updated_at=NOW + 2, updates={"next_action": "reconcile"})
    assert reconciliation["technical_effect"] == effect
    for denied in ("Ready", "Running", "Accepted"):
        with pytest.raises(PlatformContractError) as error:
            transition_work_item(cancelled, denied, expected_revision=5, updated_at=NOW + 2)
        assert error.value.code == "invalid_transition"


def test_cancellation_cannot_relabel_a_verified_effect_as_not_verified():
    record = _common("work-item", dict(CONTRACT_CASES[0][1], lifecycle="Verified", technical_effect="verified"))
    with pytest.raises(PlatformContractError) as error:
        transition_work_item(record, "Cancelled", expected_revision=4, updated_at=NOW + 1,
                             updates={"technical_effect": "not_verified"})
    assert error.value.code == "invalid_transition"
    assert record["technical_effect"] == "verified"


def test_export_redacts_secret_values_but_preserves_managed_references():
    record = _common("observation", {
        "subject_ref": {"id": "ticket-1"},
        "source_version": "5",
        "observed_at": "2027-01-15T08:00:00.000Z",
        "collection_method": "authoritative_readback",
        "facts": [],
        "artifact_refs": [],
        "intent_id": "action-intent-1",
        "source_locator": {"provider": "jira", "key": "VEND-1"},
        "collected_at": "2027-01-15T08:00:01.000Z",
        "provider_request_id": "request-1", "provider_receipt_id": "receipt-1",
        "raw_artifact_ref": {"sha256": "d" * 64},
        "asserted_fact": {"status": "created"},
        "collector_ref": {"kind": "jira_readback"},
        "diagnostic": {
            "api_key": "plaintext-secret-value",  # pragma: allowlist secret
            "credential_ref": "vault://customer-a/jira",
            "nested": {"password": "do-not-export"},  # pragma: allowlist secret
        },
    })
    exported = export_contract(record)
    rendered = str(exported)
    assert "plaintext-secret-value" not in rendered
    assert "do-not-export" not in rendered
    assert exported["diagnostic"]["api_key"] == "[redacted]"
    assert exported["diagnostic"]["credential_ref"] == "vault://customer-a/jira"


def _review_work_item():
    return _common("work-item", {
        "requester": "requester", "process": {}, "supported_deployment": {},
        "acceptance_contract": {}, "out_of_scope": [], "lifecycle": "Verified",
        "next_action": "accept", "technical_effect": "verified", "business_outcome": "pending",
        "target_scope": {}, "deployment_profile": {}, "admission_id": "work-item-1",
        "acceptance_contract_ref": {}, "parent_work_item_id": None,
    })


@pytest.mark.parametrize("amount", ["1e1000000", "1e-1000000"])
@pytest.mark.parametrize("field", ["budget", "cost"])
def test_decimal_exponents_are_rejected_without_allocating_the_expanded_string(amount, field):
    record = _review_work_item()
    record[field]["limit" if field == "budget" else "amount"] = amount
    tracemalloc.start()
    try:
        with pytest.raises(PlatformContractError) as raised:
            read_contract(record)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert raised.value.code == ("invalid_budget" if field == "budget" else "invalid_contract")
    # A 9/10-byte input must not allocate its million-character representation.
    assert peak < 200_000


@pytest.mark.parametrize(("amount", "normalized"), [
    ("1e63", "1" + "0" * 63), ("1e-62", "0." + "0" * 61 + "1"),
    (Decimal("1.2300"), "1.23"), ("-0", "0"),
])
def test_bounded_exact_decimal_values_preserve_value(amount, normalized):
    record = _review_work_item()
    record["cost"]["amount"] = amount
    assert read_contract(record)["cost"]["amount"] == normalized


@pytest.mark.parametrize("schema", [{}, [], None, True])
def test_malformed_schema_types_have_a_stable_contract_error(schema):
    record = dict(_review_work_item(), schema=schema)
    with pytest.raises(PlatformContractError) as raised:
        read_contract(record)
    assert raised.value.code == "unsupported_contract_schema"


@pytest.mark.parametrize("extension", [{1: "value"}, ("value",), b"value", {"value"}])
def test_non_json_extensions_are_rejected_by_the_reader(extension):
    record = dict(_review_work_item(), extension=extension)
    with pytest.raises(PlatformContractError) as raised:
        read_contract(record)
    assert raised.value.code == "invalid_contract"


def test_deep_or_cyclic_contracts_fail_with_stable_errors_before_copying():
    cycle = {}
    cycle["again"] = cycle
    deep = {}
    for _ in range(1100):
        deep = {"next": deep}
    for extension in (cycle, deep):
        with pytest.raises(PlatformContractError) as raised:
            read_contract(dict(_review_work_item(), extension=extension))
        assert raised.value.code == "invalid_contract"


def test_export_has_a_closed_diagnostic_and_unknown_extension_boundary():
    record = _review_work_item()
    record["diagnostic"] = {
        "Authorization": "Bearer synthetic-secret", "Cookie": "session=synthetic-secret",
        "accessKey": "synthetic-secret", "provider_response": "free-form synthetic-secret",
        "credential_ref": {"kind": "managed_connection", "id": "jira"},
        "nested": [{"arbitrary_new_name": "synthetic-secret"}],
    }
    record["future_extension"] = {"unknown": "synthetic-secret"}
    exported = export_contract(record)
    assert "synthetic-secret" not in str(exported)
    assert exported["diagnostic"]["Authorization"] == "[redacted]"
    assert exported["diagnostic"]["credential_ref"] == {"kind": "managed_connection", "id": "jira"}
    assert exported["future_extension"] == "[redacted]"
    # Compatibility readers preserve unknown fields; safe exports apply a separate policy.
    assert read_contract(record)["future_extension"] == record["future_extension"]


@pytest.mark.parametrize("key", [
    "Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "accessKey",
    "clientSecret", "apiKey", "APIKey", "X-Api-Key", "refreshToken", "password", "credentials",
])
def test_export_scrubs_credential_aliases_inside_defined_domain_maps(key):
    record = _review_work_item()
    record["provenance"]["headers"] = {key: "synthetic-secret"}
    assert "synthetic-secret" not in str(export_contract(record))


@pytest.mark.parametrize("reference", [
    "plaintext-credential", "https://example.test/?token=synthetic-secret",
    {"kind": "managed_connection", "id": "jira", "token": "synthetic-secret"},
])
def test_reference_suffix_does_not_exempt_raw_or_unrecognized_credentials(reference):
    record = _review_work_item()
    record["provenance"]["credential_ref"] = reference
    assert export_contract(record)["provenance"]["credential_ref"] == "[redacted]"


def test_plural_credential_references_validate_each_managed_reference():
    record = _review_work_item()
    record["provenance"]["credential_refs"] = [
        "plaintext-credential", {"kind": "managed_connection", "id": "jira"},
    ]
    assert export_contract(record)["provenance"]["credential_refs"] == [
        "[redacted]", {"kind": "managed_connection", "id": "jira"},
    ]


def test_export_preserves_defined_domain_text_without_claiming_to_sanitize_prose():
    record = _review_work_item()
    record["purpose"] = "Customer supplied prose remains customer data"
    record["objective"] = record["purpose"]
    exported = export_contract(record)
    assert exported["purpose"] == record["purpose"]
    assert exported["objective"] == record["objective"]


def test_acceptance_transition_requires_explicit_accepted_business_outcome():
    record = _review_work_item()
    with pytest.raises(PlatformContractError) as raised:
        transition_work_item(record, "Accepted", expected_revision=4, updated_at=NOW + 1)
    assert raised.value.code == "invalid_transition"
    accepted = transition_work_item(
        record, "Accepted", expected_revision=4, updated_at=NOW + 1,
        updates={"business_outcome": "accepted", "next_action": "check_renewal"},
    )
    assert accepted["technical_effect"] == "verified"
    assert accepted["business_outcome"] == "accepted"
    assert record["business_outcome"] == "pending"


@pytest.mark.parametrize(("lifecycle", "technical", "business"), [
    ("Verified", "not_verified", "pending"), ("Verified", "indeterminate", "pending"),
    ("Accepted", "verified", "pending"), ("Accepted", "verified", "rejected"),
    ("Accepted", "not_verified", "accepted"), ("Running", "verified", "accepted"),
])
def test_contradictory_lifecycle_outcomes_are_rejected(lifecycle, technical, business):
    record = dict(_review_work_item(), lifecycle=lifecycle, technical_effect=technical, business_outcome=business)
    with pytest.raises(PlatformContractError) as raised:
        read_contract(record)
    assert raised.value.code == "invalid_transition"


def test_malformed_transition_arguments_have_stable_codes():
    record = _review_work_item()
    with pytest.raises(PlatformContractError) as raised:
        transition_work_item(record, [], expected_revision=4, updated_at=NOW + 1)
    assert raised.value.code == "invalid_transition"
    with pytest.raises(PlatformContractError) as raised:
        transition_work_item(dict(record, revision=1), "Failed", expected_revision=True, updated_at=NOW + 1)
    assert raised.value.code == "revision_conflict"


@pytest.mark.parametrize("malformed", [{}, []], ids=["object", "array"])
@pytest.mark.parametrize("field", ["budget", "cost", "idempotency", "fresh_until", "causal_status"])
def test_unhashable_common_state_values_have_stable_errors_for_every_kind(contract, field, malformed):
    _, record = contract
    record[field] = {"state": malformed}
    for boundary in (read_contract, export_contract):
        with pytest.raises(PlatformContractError) as raised:
            boundary(record)
        assert raised.value.code == ("invalid_budget" if field == "budget" else "invalid_contract")


@pytest.mark.parametrize("malformed", [{}, []], ids=["object", "array"])
@pytest.mark.parametrize(("kind", "field"), [
    ("work-item", "lifecycle"), ("work-item", "technical_effect"), ("work-item", "business_outcome"),
    ("action-intent", "dispatch_state"), ("outcome-record", "verdict"),
    ("experience-record", "training_expires_at"),
])
def test_unhashable_domain_state_values_are_rejected_before_enum_lookup(kind, field, malformed):
    record = _common(kind, dict(CONTRACT_CASES)[kind])
    record[field] = {"state": malformed} if field == "training_expires_at" else malformed
    for boundary in (read_contract, export_contract):
        with pytest.raises(PlatformContractError) as raised:
            boundary(record)
        assert raised.value.code == "invalid_contract"


@pytest.mark.parametrize("malformed", [{}, []], ids=["object", "array"])
def test_public_kind_and_transition_boundaries_reject_unhashable_selectors(malformed):
    record = _review_work_item()
    with pytest.raises(PlatformContractError) as raised:
        _common(malformed, dict(CONTRACT_CASES)["work-item"])
    assert raised.value.code == "unsupported_contract_schema"
    with pytest.raises(PlatformContractError) as raised:
        read_contract(record, expected_kind=malformed)
    assert raised.value.code == "contract_kind_mismatch"
    with pytest.raises(PlatformContractError) as raised:
        read_contract(record, expected_tenant_id=malformed)
    assert raised.value.code == "tenant_mismatch"
    with pytest.raises(PlatformContractError) as raised:
        transition_work_item(record, malformed, expected_revision=4, updated_at=NOW + 1)
    assert raised.value.code == "invalid_transition"
    with pytest.raises(PlatformContractError) as raised:
        transition_work_item(record, "Failed", expected_revision=malformed, updated_at=NOW + 1)
    assert raised.value.code == "revision_conflict"


@pytest.mark.parametrize("extension", [{1: "value"}, ("value",), b"value", {"value"}])
def test_build_and_transition_enforce_json_shape_before_returning_a_record(extension):
    fields = dict(dict(CONTRACT_CASES)["work-item"], extension=extension)
    with pytest.raises(PlatformContractError) as raised:
        _common("work-item", fields)
    assert raised.value.code == "invalid_contract"
    record = _review_work_item()
    with pytest.raises(PlatformContractError) as raised:
        transition_work_item(record, "Failed", expected_revision=4, updated_at=NOW + 1,
                             updates={"extension": extension})
    assert raised.value.code == "invalid_contract"
    assert "extension" not in record


def test_timestamp_overflow_is_a_stable_error_at_the_public_reader():
    with pytest.raises(PlatformContractError) as raised:
        read_contract(dict(_review_work_item(), updated_at=10**400))
    assert raised.value.code == "invalid_timestamp"


@pytest.mark.parametrize("oversized", [
    ["x" * 1024] * 4096,
    {"\n" * 600_000: 0},
], ids=["repeated_string_aliases", "escaped_object_key"])
def test_aggregate_size_is_rejected_before_copying_or_serializing(oversized):
    record = dict(_review_work_item(), extension=oversized)
    tracemalloc.start()
    try:
        with pytest.raises(PlatformContractError) as raised:
            read_contract(record)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert raised.value.code == "invalid_contract"
    assert peak < 1_500_000


@pytest.mark.parametrize("character", ["x", "\n", "\x00", "\x7f", "é", "😀", '"', "\\"])
def test_exact_transport_boundary_counts_unicode_escapes_and_punctuation(character):
    record = dict(_review_work_item(), extension={
        "escaped\nkey": "", "scalars": [None, True, False, 0, -1, 2.5, -0.0, 1e20],
        "empty_list": [], "empty_map": {},
    })
    limit = 1024 * 1024

    def dump(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")

    available = limit - len(dump(record))
    unit_size = len(json.dumps(character)) - 2
    repeats, remaining = divmod(available, unit_size)
    record["extension"]["escaped\nkey"] = character * repeats + "x" * remaining
    assert len(dump(record)) == limit
    assert read_contract(record) == record
    record["extension"]["escaped\nkey"] += "x"
    assert len(dump(record)) == limit + 1
    with pytest.raises(PlatformContractError) as raised:
        read_contract(record)
    assert raised.value.code == "invalid_contract"


@pytest.mark.parametrize("field", ["budget", "cost"])
@pytest.mark.parametrize("amount", [
    Decimal("1" * 100_000), Decimal("0." + "1" * 100_000),
    Decimal("1." + "0" * 99_999 + "1"),
], ids=["large_magnitude", "large_fractional_coefficient", "nonzero_far_beyond_precision"])
def test_native_decimal_coefficients_are_bounded_before_string_or_tuple_expansion(field, amount):
    record = _review_work_item()
    record[field]["limit" if field == "budget" else "amount"] = amount
    tracemalloc.start()
    try:
        with pytest.raises(PlatformContractError) as raised:
            read_contract(record)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert raised.value.code == ("invalid_budget" if field == "budget" else "invalid_contract")
    assert peak < 20_000


@pytest.mark.parametrize(("amount", "expected"), [
    (Decimal("1." + "0" * 100_000), "1"),
    (Decimal("9" * 64), "9" * 64),
    (Decimal("1e-62"), "0." + "0" * 61 + "1"),
    (Decimal("1.23456789"), "1.23456789"),
])
def test_native_decimal_normalization_is_exact_and_independent_of_ambient_precision(amount, expected):
    record = _review_work_item()
    record["cost"]["amount"] = amount
    with localcontext() as context:
        context.prec = 3
        tracemalloc.start()
        try:
            normalized = read_contract(record)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
    assert normalized["cost"]["amount"] == expected
    assert peak < 20_000


@pytest.mark.parametrize("key", [
    "APIKEY", "ACCESSKEY", "CLIENTSECRET", "PRIVATEKEY", "PROXYAUTHORIZATION",
    "SETCOOKIE", "SERVICE_APIKEY", "providerACCESSKEY",
])
def test_compact_uppercase_credential_aliases_are_redacted_in_defined_maps(key):
    record = _review_work_item()
    record["provenance"][key] = "synthetic-secret"
    assert export_contract(record)["provenance"][key] == "[redacted]"


@pytest.mark.parametrize("key", ["APIKEYREF", "ACCESSKEYREFERENCE", "CLIENTSECRETREFS", "PRIVATEKEYREFERENCES"])
def test_compact_credential_reference_aliases_use_the_same_closed_reference_policy(key):
    record = _review_work_item()
    record["provenance"][key] = "synthetic-secret"
    assert export_contract(record)["provenance"][key] == "[redacted]"
    record["provenance"][key] = {"kind": "managed_connection", "id": "jira"}
    assert export_contract(record)["provenance"][key] == {"kind": "managed_connection", "id": "jira"}
