"""Versioned interoperability contracts for product and research records.

The contracts in this module are transport projections. Domain services keep
their existing systems of record and persistence invariants; projections make
identity, tenancy, authority, cost, uncertainty, and lifecycle semantics
portable without weakening those authorities.
"""
from __future__ import annotations

import copy
import json
import math
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from decimal import Context, Decimal, DecimalException, Inexact, InvalidOperation, Overflow
from typing import Any

CONTRACT_SCHEMAS = {
    "work-item": "lightwork.contract.work-item.v1",
    "action-intent": "lightwork.contract.action-intent.v1",
    "observation": "lightwork.contract.observation.v1",
    "outcome-record": "lightwork.contract.outcome-record.v1",
    "experience-record": "lightwork.contract.experience-record.v1",
    "experiment-spec": "lightwork.contract.experiment-spec.v1",
    "candidate-manifest": "lightwork.contract.candidate-manifest.v1",
}
_SCHEMA_KINDS = {schema: kind for kind, schema in CONTRACT_SCHEMAS.items()}
_COMMON_REQUIRED = frozenset({
    "schema", "id", "tenant_id", "owner_id", "purpose", "created_at", "revision",
})
_COMMON_DEFAULTS: dict[str, Any] = {
    "schema_version": 1,
    "authority_versions": {},
    "credential_versions": {},
    "provenance": {"state": "unknown", "reason": "not_recorded"},
    "policy_snapshot_ref": {"state": "unknown", "reason": "not_recorded"},
    "idempotency": {"state": "unknown", "reason": "not_recorded"},
    "budget": {"state": "unknown", "reason": "not_recorded"},
    "cost": {"state": "unknown", "reason": "not_measured"},
    "fresh_until": {"state": "unknown", "reason": "not_recorded"},
    "human_intervention": {"state": "unknown", "reason": "not_recorded"},
    "uncertainty": {"state": "unknown", "reason": "not_estimated"},
    "causal_status": {"state": "unknown", "basis": "not_estimated"},
}
_KIND_REQUIRED = {
    "work-item": frozenset({
        "requester", "process", "supported_deployment", "acceptance_contract",
        "out_of_scope", "lifecycle", "next_action", "technical_effect",
        "business_outcome", "target_scope", "deployment_profile", "admission_id",
        "acceptance_contract_ref", "parent_work_item_id",
    }),
    "action-intent": frozenset({
        "work_item_id", "action", "parameters_sha256", "preconditions",
        "authority_ref", "approval_ref", "dispatch_state", "reconciliation",
        "target", "source_versions", "declared_effects", "irreversible_effects",
        "credential_ref", "credential_version", "expires_at", "budget_reservation",
        "idempotency_scope",
    }),
    "observation": frozenset({
        "subject_ref", "source_version", "observed_at", "collection_method",
        "facts", "artifact_refs", "intent_id", "source_locator", "collected_at",
        "provider_request_id", "provider_receipt_id", "raw_artifact_ref",
        "asserted_fact", "collector_ref",
    }),
    "outcome-record": frozenset({
        "work_item_id", "verdict", "evaluator_ref", "evidence_refs",
        "unintended_changes", "human_interventions", "cost_refs", "reason_codes",
        "acceptance_contract_ref", "actor_ref", "supersedes_ref",
    }),
    "experience-record": frozenset({
        "origin_refs", "label_kind", "rights_basis", "training_eligible",
        "retention_deadline", "correction_refs", "derivative_refs",
        "source_versions", "sensitivity", "training_expires_at", "deletion_state",
    }),
    "experiment-spec": frozenset({
        "hypothesis", "baseline_refs", "split_refs", "seeds", "primary_endpoint",
        "stopping_rule", "analysis_plan", "permitted_queries",
        "question", "environment_ref", "dataset_refs", "data_rights",
        "family_split_ref", "component_versions", "secondary_endpoints",
        "replication_plan", "protocol_registration",
    }),
    "candidate-manifest": frozenset({
        "artifact_refs", "parent_refs", "data_rights", "dependency_refs",
        "evaluation_refs", "applicability", "permissions", "compatibility",
        "restore_target", "reviewer_decision", "resource_use", "rollout_plan",
        "supported_domain",
    }),
}
_MAP_FIELDS = frozenset({
    "provenance", "policy_snapshot_ref", "authority_versions", "credential_versions",
    "idempotency", "budget", "cost", "human_intervention", "uncertainty",
    "causal_status", "process", "supported_deployment", "acceptance_contract",
    "preconditions", "authority_ref", "approval_ref", "reconciliation",
    "subject_ref", "evaluator_ref", "stopping_rule", "analysis_plan", "data_rights",
    "applicability", "compatibility", "target_scope", "deployment_profile",
    "acceptance_contract_ref", "target", "source_versions", "credential_ref",
    "budget_reservation", "idempotency_scope", "source_locator", "raw_artifact_ref",
    "asserted_fact", "collector_ref", "actor_ref", "sensitivity", "deletion_state",
    "environment_ref", "family_split_ref", "component_versions", "replication_plan",
    "protocol_registration", "reviewer_decision", "resource_use", "rollout_plan",
    "supported_domain",
})
_LIST_FIELDS = frozenset({
    "out_of_scope", "facts", "artifact_refs", "evidence_refs", "unintended_changes",
    "cost_refs", "reason_codes", "origin_refs", "correction_refs", "derivative_refs",
    "baseline_refs", "split_refs", "seeds", "permitted_queries", "parent_refs",
    "dependency_refs", "evaluation_refs", "permissions",
    "declared_effects", "irreversible_effects", "dataset_refs", "secondary_endpoints",
})
_TEXT_FIELDS = frozenset({
    "requester", "next_action", "work_item_id", "action", "source_version",
    "collection_method", "label_kind", "rights_basis", "hypothesis",
    "primary_endpoint", "restore_target", "admission_id", "credential_version", "question",
    "lifecycle", "technical_effect", "business_outcome", "dispatch_state", "verdict",
})
_WORK_LIFECYCLES = frozenset({
    "Draft", "Ready", "Awaiting approval", "Running", "Awaiting observation",
    "Needs reconciliation", "Verified", "Accepted", "Failed", "Cancelled",
})
_WORK_TRANSITIONS = {
    "Draft": frozenset({"Ready", "Failed", "Cancelled"}),
    "Ready": frozenset({"Awaiting approval", "Running", "Failed", "Cancelled"}),
    "Awaiting approval": frozenset({"Ready", "Running", "Failed", "Cancelled"}),
    "Running": frozenset({"Awaiting observation", "Needs reconciliation", "Failed", "Cancelled"}),
    "Awaiting observation": frozenset({"Verified", "Needs reconciliation", "Failed", "Cancelled"}),
    "Needs reconciliation": frozenset({"Ready", "Verified", "Failed", "Cancelled"}),
    "Verified": frozenset({"Accepted", "Failed", "Cancelled"}),
    "Accepted": frozenset(),
    "Failed": frozenset(),
    "Cancelled": frozenset({"Needs reconciliation"}),
}
_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_CONTRACT_BYTES = 1024 * 1024
_MAX_CONTRACT_DEPTH = 64
_MAX_CONTRACT_NODES = 65_536
_MONEY_PATHS = frozenset({("budget", "limit"), ("budget", "spent"), ("cost", "amount")})
_WORK_OPTIONAL_EXPORT_FIELDS = frozenset({"objective", "contract_binding", "due_at"})


class PlatformContractError(ValueError):
    """A platform record cannot be interpreted without guessing."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> None:
    raise PlatformContractError(message, code=code)


def _text(value: object, name: str, limit: int = 4000) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        _fail("invalid_contract", f"{name} must be a nonempty bounded string")
    return value.strip()


def _timestamp(value: object, name: str) -> str:
    if isinstance(value, bool):
        _fail("invalid_timestamp", f"{name} must be a UTC timestamp")
    if isinstance(value, (int, float)):
        try:
            if not math.isfinite(value) or value < 0:
                _fail("invalid_timestamp", f"{name} must be a UTC timestamp")
            parsed = datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            _fail("invalid_timestamp", f"{name} must be a UTC timestamp")
    elif isinstance(value, str):
        if not value.endswith("Z"):
            _fail("invalid_timestamp", f"{name} must end in Z")
        try:
            parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        except ValueError:
            _fail("invalid_timestamp", f"{name} must be a UTC timestamp")
        if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
            _fail("invalid_timestamp", f"{name} must be a UTC timestamp")
        parsed = parsed.astimezone(timezone.utc)
    else:
        _fail("invalid_timestamp", f"{name} must be a UTC timestamp")
    return parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _native_decimal(value: Decimal, name: str) -> Decimal:
    """Reduce native coefficients within fixed resources, without rounding value."""
    if not value.is_finite() or value < 0:
        _fail("invalid_budget", f"{name} must be a finite nonnegative decimal")
    if value.is_zero():
        return Decimal(0)
    adjusted = value.adjusted()
    if not -62 <= adjusted <= 63:
        _fail("invalid_budget", f"{name} must be a bounded decimal")
    # A <=64-character fixed-point value has at most 64 significant digits
    # and, when fractional, room for the integer part plus a decimal point.
    # Quantize before normalize/str/as_tuple: normalizing the original native
    # value can itself copy its arbitrarily large coefficient. Inexact is fatal;
    # only redundant trailing zeros may be discarded.
    quantum = Decimal((0, (1,), max(-62, min(0, adjusted - 62))))
    context = Context(prec=64, Emax=63, Emin=-62, traps=[Inexact, InvalidOperation, Overflow])
    try:
        return context.normalize(value.quantize(quantum, context=context))
    except DecimalException as exc:
        raise PlatformContractError(
            f"{name} must be an exact bounded decimal", code="invalid_budget",
        ) from exc


def _decimal(value: object, name: str) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        _fail("invalid_budget", f"{name} must be a finite nonnegative decimal")
    if isinstance(value, float) and not math.isfinite(value):
        _fail("invalid_budget", f"{name} must be a finite nonnegative decimal")
    if isinstance(value, Decimal):
        amount = _native_decimal(value, name)
    else:
        raw = str(value)
        if len(raw) > 64:
            _fail("invalid_budget", f"{name} must be a bounded decimal")
        try:
            amount = Decimal(raw)
        except (InvalidOperation, ValueError):
            _fail("invalid_budget", f"{name} must be a finite nonnegative decimal")
    if not amount.is_finite() or amount < 0:
        _fail("invalid_budget", f"{name} must be a finite nonnegative decimal")
    if amount.is_zero():
        return "0"
    # Fixed-point formatting expands exponent notation. Bound its output before
    # allocating it; the input and final JSON limits cannot prevent that expansion.
    parts = amount.as_tuple()
    exponent = parts.exponent
    digits = len(parts.digits)
    rendered_length = (digits + exponent if exponent >= 0 else
                       max(digits + 1, 2 - exponent))
    if rendered_length > 64:
        _fail("invalid_budget", f"{name} must be a bounded decimal")
    rendered = format(amount, "f")
    return rendered.rstrip("0").rstrip(".") if "." in rendered else rendered


def _mapping(value: object, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        _fail("invalid_contract", f"{name} must be an object")
    # The public reader validates the complete graph before making its owned copy.
    return dict(value)


def _json_string_size(value: str) -> int:
    """Size of json.dumps' quoted ensure_ascii representation, without rendering."""
    size = 2
    for char in value:
        if char in '"\\\b\f\n\r\t':
            size += 2
        elif " " <= char <= "~":
            size += 1
        else:
            size += 6 if ord(char) <= 0xFFFF else 12
    return size


def _validate_json_shape(value: Mapping[str, Any]) -> None:
    """Bound traversal before deepcopy/serialization, including cyclic inputs."""
    pending = [(value, ())]
    visited = 0
    encoded_bytes = 0
    while pending:
        item, path = pending.pop()
        visited += 1
        if len(path) > _MAX_CONTRACT_DEPTH or visited > _MAX_CONTRACT_NODES:
            _fail("invalid_contract", "contract nesting or node count exceeds its limit")
        if isinstance(item, Mapping):
            if len(item) + len(pending) + visited > _MAX_CONTRACT_NODES:
                _fail("invalid_contract", "contract node count exceeds its limit")
            # Braces, commas, and the colon after every quoted key.
            encoded_bytes += 2 + max(0, len(item) - 1) + len(item)
            for key, child in item.items():
                if not isinstance(key, str) or len(key) > _MAX_CONTRACT_BYTES:
                    _fail("invalid_contract", "contract objects require bounded string keys")
                encoded_bytes += _json_string_size(key)
                if encoded_bytes > _MAX_CONTRACT_BYTES:
                    _fail("invalid_contract", "contract exceeds the 1 MiB transport limit")
                pending.append((child, (*path, key)))
        elif isinstance(item, list):
            if len(item) + len(pending) + visited > _MAX_CONTRACT_NODES:
                _fail("invalid_contract", "contract node count exceeds its limit")
            encoded_bytes += 2 + max(0, len(item) - 1)
            pending.extend((child, (*path, index)) for index, child in enumerate(item))
        elif isinstance(item, Decimal) and path in _MONEY_PATHS:
            # Native exact money is not a JSON scalar; count its supported
            # string representation, using the same bounded normalizer as read.
            try:
                normalized = _decimal(item, " ".join(path))
            except PlatformContractError as exc:
                if path[0] == "cost":
                    raise PlatformContractError(str(exc), code="invalid_contract") from exc
                raise
            encoded_bytes += len(normalized) + 2
        elif type(item) not in (str, int, float, bool, type(None)):
            _fail("invalid_contract", "contract must contain JSON values")
        elif isinstance(item, str):
            if len(item) > _MAX_CONTRACT_BYTES:
                _fail("invalid_contract", "contract string exceeds its transport limit")
            encoded_bytes += _json_string_size(item)
        elif type(item) is int:
            if item.bit_length() > 4096:
                _fail("invalid_contract", "contract integer exceeds its transport limit")
            encoded_bytes += len(str(item))
        elif type(item) is float:
            encoded_bytes += len(repr(item))
        else:
            encoded_bytes += 5 if item is False else 4  # false / true / null
        if encoded_bytes > _MAX_CONTRACT_BYTES:
            _fail("invalid_contract", "contract exceeds the 1 MiB transport limit")


def _state(value: object, name: str, allowed: frozenset[str]) -> dict[str, Any]:
    normalized = _mapping(value, name)
    if not isinstance(normalized.get("state"), str) or normalized["state"] not in allowed:
        _fail("invalid_contract", f"{name} has an unsupported state")
    return normalized


def _budget(value: object) -> dict[str, Any]:
    normalized = _mapping(value, "budget")
    state = normalized.get("state")
    if state == "unknown":
        _text(normalized.get("reason"), "budget reason", 256)
        return normalized
    if state != "bounded" or not isinstance(normalized.get("currency"), str):
        _fail("invalid_budget", "budget must be bounded or explicitly unknown")
    currency = normalized["currency"].strip().upper()
    if not re.fullmatch(r"[A-Z]{3}", currency):
        _fail("invalid_budget", "budget currency must be a three-letter code")
    limit = _decimal(normalized.get("limit"), "budget limit")
    spent = _decimal(normalized.get("spent"), "budget spent")
    if Decimal(spent) > Decimal(limit):
        _fail("invalid_budget", "budget spent exceeds its limit")
    return dict(normalized, currency=currency, limit=limit, spent=spent)


def _cost(value: object) -> dict[str, Any]:
    normalized = _mapping(value, "cost")
    state = normalized.get("state")
    if state == "unknown":
        _text(normalized.get("reason"), "cost reason", 256)
        return normalized
    if state != "exact" or not isinstance(normalized.get("currency"), str):
        _fail("invalid_contract", "cost must be exact or explicitly unknown")
    currency = normalized["currency"].strip().upper()
    if not re.fullmatch(r"[A-Z]{3}", currency):
        _fail("invalid_contract", "cost currency must be a three-letter code")
    try:
        amount = _decimal(normalized.get("amount"), "cost amount")
    except PlatformContractError as exc:
        raise PlatformContractError(str(exc), code="invalid_contract") from exc
    return dict(normalized, currency=currency, amount=amount)


def _json_bound(value: Mapping[str, Any]) -> None:
    try:
        rendered = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise PlatformContractError(
            "contract must contain bounded JSON values", code="invalid_contract",
        ) from exc
    if len(rendered.encode("utf-8")) > _MAX_CONTRACT_BYTES:
        _fail("invalid_contract", "contract exceeds the 1 MiB transport limit")


def _validate_work_item(record: dict[str, Any]) -> None:
    if record["lifecycle"] not in _WORK_LIFECYCLES:
        _fail("invalid_transition", "work-item lifecycle is unsupported")
    if record["technical_effect"] not in {"not_verified", "indeterminate", "verified"}:
        _fail("invalid_contract", "technical effect is unsupported")
    if record["business_outcome"] not in {"pending", "accepted", "rejected"}:
        _fail("invalid_contract", "business outcome is unsupported")
    if record["lifecycle"] in {"Verified", "Accepted"} and record["technical_effect"] != "verified":
        _fail("invalid_transition", "verified or accepted work requires a verified technical effect")
    if (record["lifecycle"] == "Accepted") != (record["business_outcome"] == "accepted"):
        _fail("invalid_transition", "accepted work requires an accepted business outcome")
    if record["parent_work_item_id"] is not None:
        record["parent_work_item_id"] = _text(
            record["parent_work_item_id"], "parent_work_item_id", 128,
        )
    if record.get("due_at") is not None:
        record["due_at"] = _timestamp(record["due_at"], "due_at")


def _validate_action_intent(record: dict[str, Any]) -> None:
    if _HEX_64.fullmatch(str(record["parameters_sha256"])) is None:
        _fail("invalid_contract", "action parameters digest is invalid")
    if record["dispatch_state"] not in {
        "prepared", "approved", "executing", "reconciliation_required", "verified", "failed",
    }:
        _fail("invalid_contract", "action dispatch state is unsupported")
    record["expires_at"] = _timestamp(record["expires_at"], "expires_at")


def _validate_observation(record: dict[str, Any]) -> None:
    record["observed_at"] = _timestamp(record["observed_at"], "observed_at")
    record["collected_at"] = _timestamp(record["collected_at"], "collected_at")
    for field in ("intent_id", "provider_request_id", "provider_receipt_id"):
        if record[field] is not None:
            record[field] = _text(record[field], field, 256)


def _validate_outcome(record: dict[str, Any]) -> None:
    if record["verdict"] not in {"accepted", "rejected", "inconclusive"}:
        _fail("invalid_contract", "outcome verdict is unsupported")
    if isinstance(record["human_interventions"], bool) or not isinstance(
        record["human_interventions"], int,
    ) or record["human_interventions"] < 0:
        _fail("invalid_contract", "human_interventions must be a nonnegative integer")
    if record["supersedes_ref"] is not None and not isinstance(
        record["supersedes_ref"], Mapping,
    ):
        _fail("invalid_contract", "supersedes_ref must be an object or null")


def _validate_experience(record: dict[str, Any]) -> None:
    if not isinstance(record["training_eligible"], bool):
        _fail("invalid_contract", "training_eligible must be a boolean")
    record["retention_deadline"] = _timestamp(
        record["retention_deadline"], "retention_deadline",
    )
    if isinstance(record["training_expires_at"], Mapping):
        record["training_expires_at"] = _state(
            record["training_expires_at"], "training_expires_at",
            frozenset({"unknown", "not_applicable"}),
        )
    else:
        record["training_expires_at"] = _timestamp(
            record["training_expires_at"], "training_expires_at",
        )


def _validate_experiment(record: dict[str, Any]) -> None:
    if any(isinstance(seed, bool) or not isinstance(seed, int) for seed in record["seeds"]):
        _fail("invalid_contract", "experiment seeds must be integers")


_KIND_VALIDATORS = {
    "work-item": _validate_work_item,
    "action-intent": _validate_action_intent,
    "observation": _validate_observation,
    "outcome-record": _validate_outcome,
    "experience-record": _validate_experience,
    "experiment-spec": _validate_experiment,
}


def _validate_kind(record: dict[str, Any], kind: str) -> None:
    missing = _KIND_REQUIRED[kind] - record.keys()
    if missing:
        _fail("invalid_contract", f"{kind} is missing required fields")
    for field in _MAP_FIELDS & record.keys():
        record[field] = _mapping(record[field], field)
    for field in _LIST_FIELDS & record.keys():
        if not isinstance(record[field], list):
            _fail("invalid_contract", f"{field} must be a list")
        record[field] = copy.deepcopy(record[field])
    for field in _TEXT_FIELDS & record.keys():
        record[field] = _text(record[field], field)
    validator = _KIND_VALIDATORS.get(kind)
    if validator is not None:
        validator(record)


def read_contract(
    value: Mapping[str, Any],
    *,
    expected_kind: str | None = None,
    expected_tenant_id: str | None = None,
) -> dict[str, Any]:
    """Validate and normalize a v1 contract, including legacy optional defaults."""
    if not isinstance(value, Mapping):
        _fail("invalid_contract", "contract must be an object")
    schema = value.get("schema")
    if not isinstance(schema, str):
        _fail("unsupported_contract_schema", "contract schema is unsupported")
    kind = _SCHEMA_KINDS.get(schema)
    if kind is None:
        _fail("unsupported_contract_schema", "contract schema is unsupported")
    _validate_json_shape(value)
    record = copy.deepcopy(dict(value))
    if expected_kind is not None and kind != expected_kind:
        _fail("contract_kind_mismatch", "contract kind does not match the requested reader")
    missing = _COMMON_REQUIRED - record.keys()
    if missing:
        _fail("invalid_contract", "contract is missing required envelope fields")
    for field, default in _COMMON_DEFAULTS.items():
        record.setdefault(field, copy.deepcopy(default))
    record.setdefault("updated_at", record["created_at"])
    if type(record["schema_version"]) is not int or record["schema_version"] != 1:
        _fail("unsupported_contract_schema", "contract schema version is unsupported")
    record["id"] = _text(record["id"], "id", 128)
    record["tenant_id"] = _text(record["tenant_id"], "tenant_id", 200)
    record["owner_id"] = _text(record["owner_id"], "owner_id", 256)
    record["purpose"] = _text(record["purpose"], "purpose")
    if expected_tenant_id is not None and record["tenant_id"] != expected_tenant_id:
        _fail("tenant_mismatch", "contract belongs to a different tenant")
    if isinstance(record["revision"], bool) or not isinstance(record["revision"], int) or record["revision"] < 0:
        _fail("invalid_contract", "revision must be a nonnegative integer")
    record["created_at"] = _timestamp(record["created_at"], "created_at")
    record["updated_at"] = _timestamp(record["updated_at"], "updated_at")
    if record["updated_at"] < record["created_at"]:
        _fail("invalid_timestamp", "updated_at precedes created_at")
    record["budget"] = _budget(record["budget"])
    record["cost"] = _cost(record["cost"])
    if isinstance(record["fresh_until"], Mapping):
        record["fresh_until"] = _state(
            record["fresh_until"], "fresh_until", frozenset({"unknown", "not_applicable"}),
        )
    else:
        record["fresh_until"] = _timestamp(record["fresh_until"], "fresh_until")
    record["idempotency"] = _state(
        record["idempotency"], "idempotency", frozenset({"unknown", "not_applicable", "bound"}),
    )
    if record["idempotency"]["state"] == "bound":
        record["idempotency"]["key"] = _text(
            record["idempotency"].get("key"), "idempotency key", 256,
        )
    record["causal_status"] = _state(
        record["causal_status"], "causal_status",
        frozenset({"unknown", "observational", "causal", "not_applicable"}),
    )
    for field in ("provenance", "policy_snapshot_ref", "authority_versions",
                  "credential_versions", "human_intervention", "uncertainty"):
        record[field] = _mapping(record[field], field)
    _validate_kind(record, kind)
    _json_bound(record)
    return record


def build_contract(
    kind: str,
    *,
    contract_id: str,
    tenant_id: str,
    owner_id: str,
    purpose: str,
    created_at: object,
    revision: int,
    fields: Mapping[str, Any],
    updated_at: object | None = None,
    provenance: Mapping[str, Any] | None = None,
    policy_snapshot_ref: Mapping[str, Any] | None = None,
    authority_versions: Mapping[str, Any] | None = None,
    credential_versions: Mapping[str, Any] | None = None,
    idempotency: Mapping[str, Any] | None = None,
    budget: Mapping[str, Any] | None = None,
    cost: Mapping[str, Any] | None = None,
    fresh_until: object | None = None,
    human_intervention: Mapping[str, Any] | None = None,
    uncertainty: Mapping[str, Any] | None = None,
    causal_status: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one normalized v1 contract from domain-owned source fields."""
    if not isinstance(kind, str) or kind not in CONTRACT_SCHEMAS:
        _fail("unsupported_contract_schema", "contract kind is unsupported")
    field_values = _mapping(fields, "fields")
    if set(field_values) & (_COMMON_REQUIRED | _COMMON_DEFAULTS.keys() | {"updated_at"}):
        _fail("invalid_contract", "kind fields overlap the common envelope")
    record = {
        "schema": CONTRACT_SCHEMAS[kind],
        "schema_version": 1,
        "id": contract_id,
        "tenant_id": tenant_id,
        "owner_id": owner_id,
        "purpose": purpose,
        "created_at": created_at,
        "updated_at": created_at if updated_at is None else updated_at,
        "revision": revision,
        "provenance": provenance,
        "policy_snapshot_ref": policy_snapshot_ref,
        "authority_versions": authority_versions,
        "credential_versions": credential_versions,
        "idempotency": idempotency,
        "budget": budget,
        "cost": cost,
        "fresh_until": fresh_until,
        "human_intervention": human_intervention,
        "uncertainty": uncertainty,
        "causal_status": causal_status,
        **field_values,
    }
    for field, default in _COMMON_DEFAULTS.items():
        if record.get(field) is None:
            record[field] = copy.deepcopy(default)
    return read_contract(record, expected_kind=kind, expected_tenant_id=tenant_id)


def transition_work_item(
    value: Mapping[str, Any],
    lifecycle: str,
    *,
    expected_revision: int,
    updated_at: object,
    updates: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a validated next work-item revision without mutating the input."""
    current = read_contract(value, expected_kind="work-item")
    if type(expected_revision) is not int or current["revision"] != expected_revision:
        _fail("revision_conflict", "work-item changed after it was reviewed")
    if not isinstance(lifecycle, str) or lifecycle not in _WORK_TRANSITIONS[current["lifecycle"]]:
        _fail("invalid_transition", "work-item transition is not permitted")
    changed = copy.deepcopy(current)
    forbidden = _COMMON_REQUIRED | {"schema_version", "created_at", "revision", "updated_at"}
    if updates is not None:
        normalized_updates = _mapping(updates, "updates")
        if set(normalized_updates) & forbidden:
            _fail("invalid_contract", "transition cannot replace envelope identity")
        changed.update(normalized_updates)
    if lifecycle == "Cancelled" and changed["technical_effect"] != current["technical_effect"]:
        _fail("invalid_transition", "cancellation cannot change the recorded technical effect")
    changed.update(lifecycle=lifecycle, revision=expected_revision + 1, updated_at=updated_at)
    return read_contract(changed, expected_kind="work-item")


def _normalized_key(name: str) -> str:
    # Case and word separators carry no credential meaning: APIKEY, apiKey
    # and api_key must use the same policy, including their reference suffixes.
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _secret_key(name: str) -> bool:
    return _normalized_key(name).endswith((
        "secret", "token", "password", "passwd", "apikey", "accesskey",
        "clientsecret", "privatekey", "credential", "credentials", "authorization",
        "proxyauthorization", "cookie", "setcookie",
    ))


def _credential_reference_key(name: str) -> bool:
    key = _normalized_key(name)
    for suffix in ("ref", "reference", "refs", "references"):
        if key.endswith(suffix):
            return _secret_key(key[:-len(suffix)])
    return False


def _export_credential_reference(value: Any) -> Any:
    # Support the existing opaque vault locator plus a closed structured form.
    # Neither form permits embedded auth, query parameters, or provider payloads.
    if isinstance(value, list):
        return [_export_credential_reference(item) for item in value]
    if isinstance(value, str) and len(value) <= 512 and re.fullmatch(
        r"vault://[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+", value,
    ):
        return value
    if (isinstance(value, dict) and set(value) == {"kind", "id"}
            and value.get("kind") == "managed_connection"
            and isinstance(value.get("id"), str)
            and re.fullmatch(r"[A-Za-z0-9._:/-]{1,256}", value["id"])):
        return dict(value)
    return "[redacted]"


def _redact(value: Any, *, diagnostic: bool = False) -> Any:
    if isinstance(value, Mapping):
        return {
            key: (_export_credential_reference(item) if _credential_reference_key(key) else
                  "[redacted]" if _secret_key(key) else _redact(item, diagnostic=diagnostic))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item, diagnostic=diagnostic) for item in value]
    return "[redacted]" if diagnostic else copy.deepcopy(value)


def export_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    """Export known domain fields; close unknown and free-form diagnostic data.

    Domain prose remains customer data, not automatically sanitized text. Its
    producer must exclude secrets and authorize export to the intended recipient.
    """
    record = read_contract(value)
    kind = _SCHEMA_KINDS[record["schema"]]
    known = _COMMON_REQUIRED | _COMMON_DEFAULTS.keys() | _KIND_REQUIRED[kind] | {"updated_at"}
    if kind == "work-item":
        known |= _WORK_OPTIONAL_EXPORT_FIELDS
    return {
        key: (_redact(item, diagnostic=True) if key == "diagnostic" else
              _redact({key: item})[key] if key in known else "[redacted]")
        for key, item in record.items()
    }


__all__ = [
    "CONTRACT_SCHEMAS", "PlatformContractError", "build_contract", "export_contract",
    "read_contract", "transition_work_item",
]
