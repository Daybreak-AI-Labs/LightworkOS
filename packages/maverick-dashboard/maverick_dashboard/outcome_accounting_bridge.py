"""Project governed pilot events into the shared outcome-accounting ledger.

The pilot store remains the source of its frozen experimental design. This
bridge gives every planned case a stable admission before work and mirrors only
current, source-authorized observations. Exact retries repair partial cross-
store publication without duplicating logical events.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from decimal import Decimal

from maverick.outcome_accounting import (
    COST_COVERAGE_FAMILIES,
    OutcomeAccounting,
    default_service,
)
from maverick.outcome_value_reporting import OutcomeValueReporting
from maverick.privacy_ops import RecordConflict

_SOURCE_FRESHNESS_SECONDS = 300
_SOURCE_REFRESH_MARGIN_SECONDS = 60
_RECONCILER = "system:outcome-source-reconciler"
_MAX_PROVIDER_RECEIPTS = 2000
_PROVIDER_OPERATION_ID = re.compile(r"[A-Za-z0-9_.:-]{1,192}\Z")
_PROVIDER_COST_CATEGORIES = frozenset({
    "evaluation", "generation", "human", "inference", "other", "retrieval",
    "rework", "retry", "search", "storage", "update",
})
_PROVIDER_USAGE_CATEGORIES = frozenset({
    "evaluation", "generation", "inference", "retrieval", "search", "storage",
    "update",
})
_PROVIDER_ATTEMPT_STATES = frozenset({
    "cancelled", "failed", "succeeded", "unknown",
})


def _operation(*parts: object) -> str:
    encoded = json.dumps(parts, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return "sync-" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:48]


def _version(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _case(record: dict, case_id: str) -> dict:
    selected = next((case for case in record.get("cases", []) if case.get("id") == case_id), None)
    if selected is None:
        raise LookupError("The admitted pilot case is unavailable")
    return selected


def _admit(record: dict, case: dict, service: OutcomeAccounting) -> dict:
    return service.admit(
        admission_id=f"{record['id']}:{case['id']}",
        work_item_id=f"{case['kind']}:{case['reference']}",
        acceptance_contract_ref=f"outcome-pilot:{record['id']}:{record['plan_version']}",
        owner_id=record["actor"],
        actor=record["actor"],
    )


def _accounting_id(entry: dict, service: OutcomeAccounting) -> str:
    return service.store.prefix + "-" + hashlib.sha256(
        entry["admission_id"].encode("utf-8")
    ).hexdigest()[:48]


def _validate_accounting_binding(
    record: dict, case: dict, entry: dict, raw: dict | None,
) -> dict:
    if raw is None or any(raw.get(key) != value for key, value in {
        "id": entry["accounting_record_id"],
        "admission_id": entry["admission_id"],
        "work_item_id": entry["work_item_id"],
        "acceptance_contract_ref": entry["acceptance_contract_ref"],
        "owner_id": record["actor"],
    }.items()):
        raise RecordConflict(
            "A frozen pilot case is missing its exact durable accounting admission."
        )
    if entry.get("admitted_at") != raw.get("admitted_at"):
        raise RecordConflict(
            "A frozen pilot case admission no longer matches its manifest."
        )
    if entry["work_item_id"] != f"{case['kind']}:{case['reference']}":
        raise RecordConflict("A frozen pilot case no longer matches its admission binding.")
    return raw


def require_complete_admission(
    record: dict, *, service: OutcomeAccounting | None = None,
) -> dict[str, dict]:
    """Read and verify every manifest-bound admission before any sync side effect."""
    from . import outcome_pilots

    accounting = service or default_service
    if record.get("state", "frozen") != "frozen":
        raise RecordConflict("Outcome accounting requires a fully frozen pilot.")
    manifest = outcome_pilots.validate_admission_manifest(
        record, require_complete=True,
    )
    cases = {case["id"]: case for case in record.get("cases", [])}
    admitted = {}
    for entry in manifest["entries"]:
        case = cases.get(entry["case_id"])
        if case is None:
            raise RecordConflict("The pilot admission manifest contains an unknown case.")
        if entry["accounting_record_id"] != _accounting_id(entry, accounting):
            raise RecordConflict("A frozen pilot case has an invalid accounting identity.")
        admitted[entry["case_id"]] = _validate_accounting_binding(
            record, case, entry, accounting.store.get(entry["accounting_record_id"]),
        )
    return admitted


def _admission_precedes_work(case: dict, source: dict, raw: dict | None) -> None:
    if source.get("input_version") != case.get("input_version"):
        raise RecordConflict("A case changed before every frozen admission completed.")
    started_at = source.get("first_started_at")
    if source.get("unstarted") is True and started_at is None:
        return
    admitted_at = raw.get("admitted_at") if raw is not None else None
    if (isinstance(started_at, bool) or not isinstance(started_at, (int, float))
            or not math.isfinite(started_at)
            or isinstance(admitted_at, bool) or not isinstance(admitted_at, (int, float))
            or not math.isfinite(admitted_at)
            or admitted_at >= started_at):
        raise RecordConflict(
            "Work started before its durable pilot admission could be verified."
        )


def admit_pilot(
    record: dict, *, resolve, service: OutcomeAccounting | None = None,
) -> dict:
    """Idempotently admit the complete frozen plan without partial publication."""
    from . import outcome_pilots

    accounting = service or default_service
    if record.get("state", "frozen") != "frozen":
        raise RecordConflict("Outcome accounting requires a fully frozen pilot.")
    manifest = outcome_pilots.validate_admission_manifest(record)
    if manifest["status"] == "complete":
        require_complete_admission(record, service=accounting)
        return manifest
    cases = {case["id"]: case for case in record.get("cases", [])}
    admissions = {}
    for entry in manifest["entries"]:
        case = cases.get(entry["case_id"])
        if case is None:
            raise RecordConflict("The pilot admission manifest contains an unknown case.")
        expected_id = _accounting_id(entry, accounting)
        raw = accounting.store.get(expected_id)
        _admission_precedes_work(case, resolve(case["kind"], case["reference"]), raw)
        raw = _admit(record, case, accounting)
        provisional = {**entry, "accounting_record_id": raw["id"],
                       "admitted_at": raw.get("admitted_at")}
        _validate_accounting_binding(record, case, provisional, raw)
        admissions[case["id"]] = raw
    # Sources live in separate authorities. A second complete pass prevents a
    # start or input change during per-case admission from publishing success.
    for case_id, raw in admissions.items():
        case = cases[case_id]
        _admission_precedes_work(
            case, resolve(case["kind"], case["reference"]), raw,
        )
    return outcome_pilots.completed_admission_manifest(record, admissions)


def _current_observation(report: dict, source_id: str) -> str | None:
    return next((row["id"] for row in reversed(report["observations"])
                 if row["current"] and row["source_id"] == source_id), None)


def _current_cost(report: dict, source_ref: str) -> str | None:
    return next((row["id"] for row in reversed(report["costs"]["events"])
                 if row["current"] and row["source_ref"] == source_ref), None)


def _current_cost_row(report: dict, source_ref: str) -> dict | None:
    return next((row for row in reversed(report["costs"]["events"])
                 if row["current"] and row["source_ref"] == source_ref), None)


def _same_decimal(actual: object | None, expected: object | None) -> bool:
    if actual is None or expected is None:
        return actual is None and expected is None
    try:
        return Decimal(str(actual)) == Decimal(str(expected))
    except Exception:
        return False


def _cost_projection_matches(
    row: dict | None,
    report: dict,
    *,
    category: str,
    amount: object | None,
    currency: str | None,
    source_ref: str,
    source_version: str,
    attempt_state: str,
    basis: str,
    aggregation: str,
    coverage: str,
    attempt_ref: str | None,
    quantity: object | None,
    unit: str | None,
    unknown_reason: str | None,
    budget_state: str,
    source_assurance: str,
    reservation_ref: str | None,
    pricing_evidence: dict[str, object] | None,
    coverage_declarations: dict[str, object] | None,
    evidence_note: str | None,
    all_in_total: bool,
    allocation_method: str,
    allocation_assumption: str | None,
) -> bool:
    """Whether the current row is the exact source-owned bridge projection."""

    if row is None:
        return False
    expected = {
        "category": category,
        "source_ref": source_ref,
        "source_version": source_version,
        "attempt_state": attempt_state,
        "basis": basis,
        "aggregation": aggregation,
        "coverage": coverage,
        "attempt_ref": attempt_ref or source_ref,
        "unit": unit,
        "unknown_reason": unknown_reason,
        "budget_state": budget_state,
        "source_assurance": source_assurance,
        "pricing_evidence": pricing_evidence,
        "coverage_declarations": coverage_declarations,
        "evidence_note": evidence_note,
        "all_in_total": all_in_total,
        "allocation_method": allocation_method,
        "allocation_assumption": allocation_assumption,
    }
    if any(row.get(key) != value for key, value in expected.items()):
        return False
    reconciliation = row.get("budget_reconciliation")
    if reservation_ref is None:
        if reconciliation is not None or not _same_decimal(row.get("amount"), amount):
            return False
        if row.get("currency") != currency:
            return False
    elif (
        not isinstance(reconciliation, dict)
        or reconciliation.get("reservation_ref") != reservation_ref
    ):
        return False
    if not _same_decimal(row.get("quantity"), quantity):
        return False
    if coverage == "complete":
        additive_ids = [
            event["id"] for event in report["costs"]["events"]
            if event["current"] and event.get("aggregation", "additive") == "additive"
        ]
        if row.get("coverage_scope_sha256") != _version(additive_ids):
            return False
    return True


def _source_result(source: dict, measurement: dict) -> str:
    if source.get("version") != measurement.get("source_version"):
        return "unavailable"
    if (
        source.get("finished") is not True
        or type(source.get("accepted")) is not bool
        or type(measurement.get("criteria_met")) is not bool
    ):
        return "missing"
    if measurement["criteria_met"] is not source["accepted"]:
        return "contradictory"
    return "confirmed"


def _cost(
    accounting: OutcomeAccounting,
    raw: dict,
    *,
    operation_id: str,
    actor: str,
    category: str,
    amount: object | None,
    currency: str | None,
    source_ref: str,
    source_version: str,
    attempt_state: str,
    basis: str,
    aggregation: str = "additive",
    coverage: str = "partial",
    attempt_ref: str | None = None,
    quantity: object | None = None,
    unit: str | None = None,
    unknown_reason: str | None = None,
    budget_state: str = "not_applicable",
    source_assurance: str = "application_observation",
    reservation_ref: str | None = None,
    pricing_evidence: dict[str, object] | None = None,
    coverage_declarations: dict[str, object] | None = None,
    evidence_note: str | None = None,
    all_in_total: bool = False,
    allocation_method: str = "direct",
    allocation_assumption: str | None = None,
) -> dict:
    report = accounting.report(raw["id"])
    current = _current_cost_row(report, source_ref)
    operation_exists = operation_id in raw.get("operations", {})
    if operation_exists and _cost_projection_matches(
        current,
        report,
        category=category,
        amount=amount,
        currency=currency,
        source_ref=source_ref,
        source_version=source_version,
        attempt_state=attempt_state,
        basis=basis,
        aggregation=aggregation,
        coverage=coverage,
        attempt_ref=attempt_ref,
        quantity=quantity,
        unit=unit,
        unknown_reason=unknown_reason,
        budget_state=budget_state,
        source_assurance=source_assurance,
        reservation_ref=reservation_ref,
        pricing_evidence=pricing_evidence,
        coverage_declarations=coverage_declarations,
        evidence_note=evidence_note,
        all_in_total=all_in_total,
        allocation_method=allocation_method,
        allocation_assumption=allocation_assumption,
    ):
        return raw
    if operation_exists:
        operation_id = _operation(
            operation_id,
            "restore-current-projection",
            current["id"] if current is not None else "missing",
            source_version,
        )
    prior = current["id"] if current is not None else None
    return accounting.record_cost(
        raw["id"], expected_revision=raw["revision"], operation_id=operation_id,
        actor=actor, category=category, attempt_state=attempt_state, basis=basis,
        amount=amount, currency=currency, source_ref=source_ref,
        source_version=source_version, correction_of=prior, aggregation=aggregation,
        correction_reason=(
            "The source version or authoritative value changed; this bridge event "
            "supersedes the prior projection."
            if prior is not None else None
        ),
        coverage=coverage, attempt_ref=attempt_ref,
        quantity=quantity, unit=unit, unknown_reason=unknown_reason,
        budget_state=budget_state,
        source_assurance=source_assurance,
        reservation_ref=reservation_ref,
        pricing_evidence=pricing_evidence,
        coverage_declarations=coverage_declarations,
        evidence_note=evidence_note,
        all_in_total=all_in_total,
        allocation_method=allocation_method,
        allocation_assumption=allocation_assumption,
    )


def _provider_operation(value: object) -> dict | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {
        "operation_id", "category", "parent_category", "attempt_no",
        "service", "attempt_state",
    }:
        raise ValueError("Provider receipt operation metadata is invalid")
    operation_id = value.get("operation_id")
    category = value.get("category")
    parent_category = value.get("parent_category")
    attempt_no = value.get("attempt_no")
    service = value.get("service")
    attempt_state = value.get("attempt_state")
    if (
        not isinstance(operation_id, str)
        or not _PROVIDER_OPERATION_ID.fullmatch(operation_id)
        or category not in _PROVIDER_COST_CATEGORIES
        or parent_category not in _PROVIDER_COST_CATEGORIES
        or type(attempt_no) is not int
        or not 1 <= attempt_no <= 1_000_000
        or attempt_state not in _PROVIDER_ATTEMPT_STATES
        or (
            service is not None
            and (
                not isinstance(service, str)
                or not 1 <= len(service) <= 256
                or service != service.strip()
                or any(ord(character) < 32 or ord(character) == 127 for character in service)
            )
        )
    ):
        raise ValueError("Provider receipt operation metadata is invalid")
    return dict(value)


def _provider_receipt_rows(source: dict) -> list[dict]:
    value = source.get("provider_cost_receipts")
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > _MAX_PROVIDER_RECEIPTS:
        raise ValueError("Provider receipt discovery is invalid or incomplete")
    seen: set[str] = set()
    rows: list[dict] = []
    for row in value:
        if not isinstance(row, dict):
            raise ValueError("Provider receipt discovery returned an invalid row")
        reference = row.get("reference")
        state = row.get("state")
        if (
            not isinstance(reference, str)
            or not reference
            or len(reference) > 512
            or state not in {"held", "unknown", "settled"}
            or reference in seen
        ):
            raise ValueError("Provider receipt discovery returned an invalid row")
        seen.add(reference)
        rows.append({**row, "operation": _provider_operation(row.get("operation"))})
    return rows


def _provider_receipt_version(row: dict) -> str:
    encoded = json.dumps(
        {
            key: row.get(key) for key in (
                "reference", "provider", "period", "request_id", "projected",
                "state", "actual", "currency", "cost_basis", "pricing_evidence",
                "work_item_sha256", "operation",
            )
        },
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _provider_catalog_version(source: dict, receipts: list[dict]) -> str:
    trusted = source.get("provider_cost_receipts_catalog_version")
    if trusted is not None and (
        not isinstance(trusted, str)
        or len(trusted) != 64
        or any(character not in "0123456789abcdef" for character in trusted)
    ):
        raise ValueError("Provider receipt catalogue version is invalid")
    if source.get("provider_cost_receipts_complete") is True and trusted is None:
        raise ValueError("Complete provider receipt coverage requires a snapshot version")
    return hashlib.sha256(json.dumps(
        {
            "declared_complete": source.get("provider_cost_receipts_complete") is True,
            "unavailable": source.get("provider_cost_receipts_error"),
            "trusted_catalogue": trusted,
            "receipts": [_provider_receipt_version(row) for row in receipts],
            "source_version": source.get("version"),
        },
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")).hexdigest()


def _coverage_ref(raw: dict) -> str:
    return f"outcome-accounting:{raw['id']}:complete-cost-coverage"


def _invalidate_stale_coverage(
    accounting: OutcomeAccounting,
    raw: dict,
    *,
    actor: str,
    catalog_version: str,
) -> dict:
    reference = _coverage_ref(raw)
    current = _current_cost_row(accounting.report(raw["id"]), reference)
    if current is None or current["source_version"] == catalog_version:
        return raw
    return _cost(
        accounting,
        raw,
        operation_id=_operation(
            raw["id"], "cost-coverage-invalidated", current["id"], catalog_version,
        ),
        actor=actor,
        category="other",
        amount=None,
        currency=None,
        source_ref=reference,
        source_version=catalog_version,
        attempt_state="unknown",
        basis="unknown",
        aggregation="informational",
        coverage="partial",
        attempt_ref=reference,
        unknown_reason="Cost coverage changed before every current component was republished.",
        budget_state="metering_failed",
        source_assurance="application_observation",
    )


def _finalize_cost_coverage(
    accounting: OutcomeAccounting,
    raw: dict,
    source: dict,
    measurement: dict,
    receipts: list[dict],
    *,
    actor: str,
    catalog_version: str,
) -> dict:
    report = accounting.report(raw["id"])
    current = [row for row in report["costs"]["events"] if row["current"]]
    additive = [row for row in current if row.get("aggregation", "additive") == "additive"]
    declarations = measurement.get("cost_coverage")
    if (
        not isinstance(declarations, dict)
        or set(declarations) != set(COST_COVERAGE_FAMILIES)
        or any(
            not isinstance(declarations.get(family), dict)
            or set(declarations[family]) != {"status", "note"}
            or declarations[family].get("status") not in {"included", "zero"}
            or not isinstance(declarations[family].get("note"), str)
            or not declarations[family]["note"].strip()
            for family in COST_COVERAGE_FAMILIES
        )
    ):
        return raw
    receipt_refs = {row["reference"] for row in receipts}
    receipt_events = {
        row["source_ref"]: row for row in current if row["source_ref"] in receipt_refs
    }
    provider_receipts_complete = (
        source.get("provider_cost_receipts_complete") is True
        and all(row.get("state") == "settled" for row in receipts)
        and receipt_refs == set(receipt_events)
        and all(row["amount"] is not None for row in receipt_events.values())
        and all(
            row["attempt_state"] != "unknown"
            for row in receipt_events.values()
        )
    )
    provider_additive_complete = (
        provider_receipts_complete
        and all(
            row.get("aggregation", "additive") == "additive"
            for row in receipt_events.values()
        )
    )
    reviewed_allocations = [
        row for row in current
        if row["category"] == "allocation"
        and row.get("source_assurance") == "application_observation"
        and row.get("allocation_method") == "operator_estimate"
        and row["source_ref"].startswith("outcome-pilot:")
        and ":provider-allocation:" in row["source_ref"]
    ]
    reviewed_allocation_additive_complete = bool(reviewed_allocations) and all(
        row.get("aggregation", "additive") == "additive"
        and row.get("amount") is not None
        and row.get("attempt_state") != "unknown"
        for row in reviewed_allocations
    )
    reported_total = any(
        row.get("all_in_total") is True and row["amount"] is not None
        for row in additive
    )
    def family_events(family: str) -> list[dict]:
        if family == "provider_usage":
            return [
                row for row in current
                if row["source_ref"] in receipt_refs
                or row in reviewed_allocations
                or row.get("category") in _PROVIDER_USAGE_CATEGORIES
            ]
        if family == "failed_attempts":
            return [
                row for row in current
                if row["attempt_state"] == "failed" or row["category"] == "retry"
            ]
        if family == "review":
            return [row for row in current if row["category"] in {"human", "review"}]
        if family == "allocation":
            return [
                row for row in current
                if row["category"] == "allocation"
                or row.get("allocation_method", "direct") != "direct"
            ]
        return [row for row in current if row["category"] == family]

    contradictions = False
    if receipts and not provider_receipts_complete:
        contradictions = True
    for family in COST_COVERAGE_FAMILIES:
        rows = family_events(family)
        status = declarations[family]["status"]
        if status == "zero" and any(
            row.get("amount") is not None and Decimal(row["amount"]) != 0
            for row in rows
        ):
            contradictions = True
        if status == "included" and not reported_total and not any(
            row.get("amount") is not None
            and row.get("aggregation", "additive") == "additive"
            for row in rows
        ):
            contradictions = True
    if (
        not (
            reported_total
            or provider_additive_complete
            or reviewed_allocation_additive_complete
        )
        or contradictions
        or any(row["amount"] is None or row["attempt_state"] == "unknown" for row in additive)
    ):
        return raw
    scope = hashlib.sha256(json.dumps(
        [row["id"] for row in additive],
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")).hexdigest()
    currency = next((row["currency"] for row in additive if row["currency"]), "USD")
    reference = _coverage_ref(raw)
    return _cost(
        accounting,
        raw,
        operation_id=_operation(raw["id"], "cost-coverage-complete", catalog_version, scope),
        actor=actor,
        category="other",
        amount="0",
        currency=currency,
        source_ref=reference,
        source_version=catalog_version,
        attempt_state="succeeded",
        basis="observed",
        aggregation="coverage",
        coverage="complete",
        attempt_ref=reference,
        source_assurance="application_observation",
        coverage_declarations=declarations,
        evidence_note=(
            "Complete cost coverage is bound to explicit included-or-zero declarations "
            "for provider usage, failed attempts, setup, review, exceptions, rework, "
            "support, and shared allocation."
        ),
    )


def _sync_provider_receipts(
    accounting: OutcomeAccounting,
    raw: dict,
    source: dict,
    measurement: dict,
    *,
    actor: str,
    rows: list[dict] | None = None,
) -> dict:
    receipts = _provider_receipt_rows(source) if rows is None else rows
    catalog_version = _provider_catalog_version(source, receipts)
    raw = _invalidate_stale_coverage(
        accounting,
        raw,
        actor=actor,
        catalog_version=catalog_version,
    )
    for row in receipts:
        reference = row["reference"]
        state = row["state"]
        settled = state == "settled"
        operation = row.get("operation")
        receipt_version = _provider_receipt_version(row)
        receipt_aggregation = (
            "informational"
            if measurement.get("ai_total_cost") is not None else "additive"
        )
        raw = _cost(
            accounting,
            raw,
            operation_id=_operation(
                raw["id"], "provider-reservation", reference, state,
                receipt_version, receipt_aggregation,
            ),
            actor=actor,
            category=operation["category"] if operation is not None else "other",
            amount=None,
            currency=None,
            source_ref=reference,
            source_version=receipt_version,
            attempt_state=(
                operation["attempt_state"] if operation is not None else "unknown"
            ),
            basis=row.get("cost_basis", "estimated") if settled else "unknown",
            coverage="partial",
            attempt_ref=(
                f"provider-operation:{operation['operation_id']}:attempt:{operation['attempt_no']}"
                if operation is not None else reference
            ),
            unknown_reason=(
                None if settled else
                "The provider reservation has no final priced settlement."
            ),
            budget_state="not_applicable" if settled else "metering_failed",
            source_assurance="application_observation",
            reservation_ref=reference,
            pricing_evidence=row.get("pricing_evidence") if settled else None,
            aggregation=receipt_aggregation,
            evidence_note=(
                "Provider receipt is bound to "
                f"{operation['parent_category']} attempt {operation['attempt_no']}"
                + (
                    f" via {operation['service']}."
                    if operation["service"] is not None else "."
                )
                if operation is not None else
                "Legacy provider receipt lacks trusted operation classification."
            ),
        )
    return _finalize_cost_coverage(
        accounting,
        raw,
        source,
        measurement,
        receipts,
        actor=actor,
        catalog_version=catalog_version,
    )


def sync_case(
    record: dict,
    case_id: str,
    source: dict,
    *,
    source_operation_id: str,
    actor: str,
    service: OutcomeAccounting | None = None,
) -> dict:
    """Publish one saved pilot observation and its non-overlapping cost views."""
    accounting = service or default_service
    admitted = require_complete_admission(record, service=accounting)
    case = _case(record, case_id)
    measurement = case.get("measurement")
    if not isinstance(measurement, dict):
        raise ValueError("Save the pilot observation before accounting for it")
    source_version = source.get("version")
    if source_version != measurement.get("source_version"):
        raise ValueError("The source changed before outcome accounting completed")
    raw = admitted[case_id]
    _admission_precedes_work(case, source, raw)
    source_id = f"{case['kind']}:{case['reference']}"
    attempt_ref = f"outcome-pilot:{record['id']}:{case_id}:attempt:{source_operation_id}"
    observation_operation = _operation(record["id"], case_id, source_operation_id, "observation")
    if observation_operation not in raw.get("operations", {}):
        result = _source_result(source, measurement)
        now = accounting.store.authoritative_time()
        refresh_slot = int(now // _SOURCE_FRESHNESS_SECONDS)
        raw = accounting.record_observation(
            raw["id"], expected_revision=raw["revision"],
            operation_id=observation_operation, actor=actor, source_id=source_id,
            source_version=source_version, result=result, authoritative=True,
            summary=measurement["evidence"],
            valid_until=(refresh_slot + 2) * _SOURCE_FRESHNESS_SECONDS,
            correction_of=_current_observation(accounting.report(raw["id"]), source_id),
        )

    status = str(source.get("status") or "").lower()
    disposition = "cancelled" if status == "cancelled" else "failed" if status == "failed" else (
        "completed" if source.get("finished") else "active"
    )
    disposition_operation = _operation(record["id"], case_id, source_operation_id, "disposition")
    if disposition_operation not in raw.get("operations", {}):
        raw = accounting.record_disposition(
            raw["id"], expected_revision=raw["revision"],
            operation_id=disposition_operation, actor=actor, disposition=disposition,
            reason="Current source lifecycle observed through the frozen pilot.",
        )

    reviewer = source.get("reviewer")
    decision_operation = _operation(record["id"], case_id, source_operation_id, "decision")
    if (source.get("finished") and isinstance(reviewer, str) and reviewer.startswith("user:")
            and decision_operation not in raw.get("operations", {})):
        current = accounting.report(raw["id"])
        if source.get("accepted") is True and current["technical_outcome"]["status"] == "verified":
            decision = "accepted"
            rationale = "Current named-human source acceptance matches authoritative pilot evidence."
        elif source.get("accepted") is False:
            decision = "rejected"
            rationale = "Current named-human source rejection was read through the frozen pilot."
        else:
            decision = "unresolved"
            rationale = "Source acceptance conflicts with or lacks current authoritative pilot evidence."
        raw = accounting.record_decision(
            raw["id"], expected_revision=raw["revision"],
            operation_id=decision_operation, actor=reviewer,
            decision=decision, rationale=rationale,
            evidence_version=current["evidence_version"],
        )

    cost_state = "failed" if disposition == "failed" else (
        "cancelled" if disposition == "cancelled" else
        "unknown" if disposition == "active" else "succeeded"
    )
    currency = measurement.get("currency")
    total = measurement.get("ai_total_cost")
    receipt_rows = _provider_receipt_rows(source)
    current_costs = accounting.report(raw["id"])["costs"]["events"]
    has_reviewed_provider_allocations = bool(record.get("provider_cost_allocations")) or any(
        row["current"]
        and row.get("source_ref", "").startswith(
            f"outcome-pilot:{record['id']}:{case_id}:provider-allocation:"
        )
        for row in current_costs
    )
    has_provider_receipts = bool(receipt_rows) or any(
        row["current"] and row.get("budget_reconciliation") is not None
        for row in current_costs
    )
    total_ref = f"outcome-pilot:{record['id']}:{case_id}:reported-total"
    prior_total = _current_cost(accounting.report(raw["id"]), total_ref)
    if (
        total is not None
        or not (has_provider_receipts or has_reviewed_provider_allocations)
        or (prior_total is not None and not has_reviewed_provider_allocations)
    ):
        # The pilot contract defines ai_total_cost as the all-in workflow total.
        # When present, it is the sole additive aggregate; provider and labour
        # detail remain auditable components without being added a second time.
        total_aggregation = (
            "additive" if total is not None or not has_provider_receipts
            else "informational"
        )
        raw = _cost(
            accounting, raw,
            operation_id=_operation(
                record["id"], case_id, source_operation_id, "total-cost",
                total_aggregation,
            ),
            actor=actor, category="other", amount=total,
            currency=currency if total is not None else None,
            source_ref=total_ref,
            source_version=source_version, attempt_state=cost_state,
            basis="observed" if total is not None else "unknown",
            aggregation=total_aggregation,
            coverage="partial",
            attempt_ref=attempt_ref,
            all_in_total=total is not None,
            unknown_reason=(
                None if total is not None else
                "Reported total AI workflow cost was not supplied."
            ),
        )

    for category, amount_key, minute_keys in (
        ("human", "human_cost", ("ai_hands_on_minutes", "review_minutes")),
        ("rework", "rework_cost", ("rework_minutes",)),
    ):
        amount = measurement.get(amount_key)
        minute_values = [measurement.get(key) for key in minute_keys]
        quantity = (
            None if any(value is None for value in minute_values)
            else sum((Decimal(str(value)) for value in minute_values), Decimal(0))
        )
        source_ref = f"outcome-pilot:{record['id']}:{case_id}:{category}"
        raw = _cost(
            accounting, raw,
            operation_id=_operation(record["id"], case_id, source_operation_id, category),
            actor=actor, category=category, amount=amount,
            currency=currency if amount is not None else None,
            source_ref=source_ref,
            source_version=source_version, attempt_state=cost_state,
            basis="observed" if amount is not None else "unknown",
            aggregation="informational" if total is not None else "additive",
            attempt_ref=attempt_ref,
            quantity=None if quantity is None else str(quantity),
            unit=None if quantity is None else "minutes",
            unknown_reason=(
                None if amount is not None else
                f"Current pilot evidence has no priced {category} cost."
            ),
        )

    runtime = source.get("runtime_cost_usd")
    runtime_ref = f"outcome-pilot:{record['id']}:{case_id}:runtime"
    prior_runtime = _current_cost(accounting.report(raw["id"]), runtime_ref)
    if runtime is not None or prior_runtime is not None:
        runtime_aggregation = (
            "informational" if total is not None or has_provider_receipts
            else "additive"
        )
        raw = _cost(
            accounting, raw,
            operation_id=_operation(
                record["id"], case_id, source_operation_id, "runtime",
                runtime_aggregation,
            ),
            actor=actor, category="inference", amount=runtime,
            currency="USD" if runtime is not None else None,
            source_ref=runtime_ref,
            source_version=source_version, attempt_state=cost_state,
            basis="observed" if runtime is not None else "unknown",
            aggregation=runtime_aggregation,
            attempt_ref=attempt_ref,
            unknown_reason=(
                None if runtime is not None else
                "Current source no longer supplies runtime cost; the prior value was superseded."
            ),
        )
    # Supersede any previously additive aggregate before publishing complete
    # per-call coverage. Otherwise its removal would immediately stale the
    # coverage-scope hash carried by the final authoritative receipt.
    raw = _sync_provider_receipts(
        accounting,
        raw,
        source,
        measurement,
        actor=actor,
        rows=receipt_rows,
    )
    return accounting.report(raw["id"])


def _pilot_binding(record: dict) -> tuple[str, str, str] | None:
    contract = str(record.get("acceptance_contract_ref") or "")
    admission = str(record.get("admission_id") or "")
    if not contract.startswith("outcome-pilot:") or ":" not in admission:
        return None
    try:
        pilot_id, plan_version = contract.removeprefix("outcome-pilot:").rsplit(":", 1)
        admission_pilot, case_id = admission.rsplit(":", 1)
    except ValueError:
        return None
    if pilot_id != admission_pilot or not pilot_id.startswith("OPL-"):
        return None
    if len(plan_version) != 64 or any(c not in "0123456789abcdef" for c in plan_version):
        return None
    return pilot_id, case_id, plan_version


def _invalidate_source_costs(
    accounting: OutcomeAccounting,
    raw: dict,
    report: dict,
    *,
    pilot_id: str,
    case_id: str,
    source_version: str,
    refresh_slot: int,
) -> dict:
    prefix = f"outcome-pilot:{pilot_id}:{case_id}:"
    current = [
        row for row in report["costs"]["events"]
        if row["current"] and row["source_ref"].startswith(prefix)
        and (row["amount"] is not None or row["source_version"] != source_version)
    ]
    for row in current:
        raw = accounting.record_cost(
            raw["id"], expected_revision=raw["revision"],
            operation_id=_operation(
                pilot_id, case_id, "source-cost-invalidation", row["id"],
                source_version, refresh_slot,
            ),
            actor=_RECONCILER, category=row["category"], attempt_state="unknown",
            basis="unknown", amount=None, currency=None,
            source_ref=row["source_ref"], source_version=source_version,
            unknown_reason="The authoritative source changed or became unavailable; review cost again.",
            correction_of=row["id"], aggregation=row.get("aggregation", "additive"),
            correction_reason=(
                "The authoritative source changed or became unavailable; this event "
                "invalidates the prior cost projection."
            ),
            coverage="partial", attempt_ref=row.get("attempt_ref"),
            budget_state="metering_failed",
            source_assurance="application_observation",
        )
    return raw


def _measurement_operation_id(
    pilot_id: str, case_id: str, measurement: dict,
) -> str:
    supplied = measurement.get("source_operation_id")
    if isinstance(supplied, str) and _PROVIDER_OPERATION_ID.fullmatch(supplied):
        return supplied
    return _operation(
        pilot_id,
        case_id,
        "legacy-observation",
        measurement.get("source_version"),
        measurement.get("observed_at"),
    )


def _legacy_sync_complete(
    report: dict,
    record: dict,
    case_id: str,
    source: dict,
    measurement: dict,
) -> bool:
    """Recognize an already published legacy observation lacking its operation id."""

    case = _case(record, case_id)
    source_id = f"{case['kind']}:{case['reference']}"
    if not any(
        row["source_id"] == source_id
        and row["source_version"] == measurement.get("source_version")
        for row in report["observations"]
    ):
        return False
    status = str(source.get("status") or "").lower()
    disposition = (
        "cancelled" if status == "cancelled" else
        "failed" if status == "failed" else
        "completed" if source.get("finished") else "active"
    )
    if not any(row["disposition"] == disposition for row in report["dispositions"]):
        return False
    reviewer = source.get("reviewer")
    if (
        source.get("finished")
        and isinstance(reviewer, str)
        and reviewer.startswith("user:")
        and not report["decisions"]
    ):
        return False
    receipts = _provider_receipt_rows(source)
    current_costs = [row for row in report["costs"]["events"] if row["current"]]
    expected_refs = {
        f"outcome-pilot:{record['id']}:{case_id}:human",
        f"outcome-pilot:{record['id']}:{case_id}:rework",
        *(row["reference"] for row in receipts),
    }
    total_ref = f"outcome-pilot:{record['id']}:{case_id}:reported-total"
    if (
        measurement.get("ai_total_cost") is not None
        or not receipts
        or any(row["source_ref"] == total_ref for row in current_costs)
    ):
        expected_refs.add(total_ref)
    runtime_ref = f"outcome-pilot:{record['id']}:{case_id}:runtime"
    if source.get("runtime_cost_usd") is not None or any(
        row["source_ref"] == runtime_ref for row in current_costs
    ):
        expected_refs.add(runtime_ref)
    return expected_refs.issubset({row["source_ref"] for row in current_costs})


def _sync_reviewed_provider_allocations(
    accounting: OutcomeAccounting,
    raw: dict,
    record: dict,
    case_id: str,
    source: dict,
    measurement: dict,
    *,
    resolve,
) -> dict:
    """Project the pilot's reviewed provider allocation without double counting."""

    from . import outcome_pilot_costs

    projection = outcome_pilot_costs.report(record, resolve=resolve)
    if projection.get("provider_invoice_verified") is not False:
        raise ValueError("Reviewed pilot cost must preserve its unverified-invoice boundary")
    case_totals = projection.get("current_case_totals")
    coverage = projection.get("coverage")
    if not isinstance(case_totals, dict) or not isinstance(coverage, dict):
        raise ValueError("Reviewed pilot cost projection is invalid")
    projection_version = _version({
        "status": projection.get("status"),
        "evidence_class": projection.get("evidence_class"),
        "provider_invoice_verified": projection.get("provider_invoice_verified"),
        "unsupported_credit_count": projection.get("unsupported_credit_count", 0),
        "current_case_totals": case_totals,
        "coverage_version": coverage.get("version"),
    })
    projected = case_totals.get(case_id, {})
    if not isinstance(projected, dict):
        raise ValueError("Reviewed pilot case cost projection is invalid")
    desired: dict[str, object] = {}
    unsupported_credit = bool(projection.get("unsupported_credit_count", 0))
    for currency, amount in projected.items():
        try:
            numeric = Decimal(str(amount))
        except Exception as exc:
            raise ValueError("Reviewed pilot case cost projection is invalid") from exc
        if not numeric.is_finite():
            raise ValueError("Reviewed pilot case cost projection is invalid")
        if numeric < 0:
            unsupported_credit = True
            continue
        desired[str(currency)] = amount
    projection_current = projection.get("status") == "current" and not unsupported_credit

    prefix = f"outcome-pilot:{record['id']}:{case_id}:provider-allocation:"
    current_report = accounting.report(raw["id"])
    current_rows = [row for row in current_report["costs"]["events"] if row["current"]]
    prior_rows = [row for row in current_rows if row["source_ref"].startswith(prefix)]
    receipt_refs = {row["reference"] for row in _provider_receipt_rows(source)}
    has_primary_total = any(
        row.get("all_in_total") is True and row.get("amount") is not None
        for row in current_rows
    )
    has_work_receipt = any(row["source_ref"] in receipt_refs for row in current_rows)
    aggregation = "informational" if has_primary_total or has_work_receipt else "additive"

    desired_refs: set[str] = set()
    for currency, amount in sorted(desired.items()):
        source_ref = prefix + str(currency)
        desired_refs.add(source_ref)
        raw = _cost(
            accounting,
            raw,
            operation_id=_operation(
                record["id"], case_id, "provider-allocation",
                projection_version, currency, amount, aggregation,
            ),
            actor=_RECONCILER,
            category="allocation",
            amount=amount,
            currency=currency,
            source_ref=source_ref,
            source_version=projection_version,
            attempt_state="succeeded",
            basis="observed",
            aggregation=aggregation,
            coverage="partial",
            attempt_ref=source_ref,
            source_assurance="application_observation",
            allocation_method="operator_estimate",
            allocation_assumption=(
                "The amount is this case's operator-reviewed basis-point share of "
                "provider billing admitted by the pilot cost workflow."
            ),
            evidence_note=(
                "Projected from reviewed pilot provider-cost allocation. Provider "
                "invoice authenticity is not independently verified."
            ),
        )

    incomplete_ref = prefix + "unavailable-remainder"
    if not projection_current:
        desired_refs.add(incomplete_ref)
        raw = _cost(
            accounting,
            raw,
            operation_id=_operation(
                record["id"], case_id, "provider-allocation-remainder",
                projection_version,
            ),
            actor=_RECONCILER,
            category="allocation",
            amount=None,
            currency=None,
            source_ref=incomplete_ref,
            source_version=projection_version,
            attempt_state="unknown",
            basis="unknown",
            aggregation="additive",
            coverage="partial",
            attempt_ref=incomplete_ref,
            unknown_reason=(
                "One or more provider billing sources have a negative net credit that "
                "cannot be represented as delivery cost; current unaffected amounts "
                "remain a lower bound until the credit is reviewed separately."
                if unsupported_credit else
                "One or more provider allocation lines changed or became unavailable; "
                "current unaffected amounts remain a lower bound until review completes."
            ),
            budget_state="metering_failed",
            source_assurance="application_observation",
            allocation_method="operator_estimate",
            allocation_assumption=(
                "This marker represents only the unavailable remainder; current reviewed "
                "case amounts are projected separately."
            ),
        )
    else:
        prior_incomplete = next(
            (row for row in prior_rows if row["source_ref"] == incomplete_ref), None,
        )
        if prior_incomplete is not None:
            desired_refs.add(incomplete_ref)
            raw = _cost(
                accounting,
                raw,
                operation_id=_operation(
                    record["id"], case_id, "provider-allocation-remainder-cleared",
                    projection_version,
                ),
                actor=_RECONCILER,
                category="allocation",
                amount="0",
                currency="USD",
                source_ref=incomplete_ref,
                source_version=projection_version,
                attempt_state="succeeded",
                basis="observed",
                aggregation="informational",
                coverage="partial",
                attempt_ref=incomplete_ref,
                budget_state="not_applicable",
                source_assurance="application_observation",
                allocation_method="operator_estimate",
                allocation_assumption=(
                    "The formerly unavailable remainder is now fully reconciled."
                ),
            )

    for row in prior_rows:
        if row["source_ref"] in desired_refs:
            continue
        raw = _cost(
            accounting,
            raw,
            operation_id=_operation(
                record["id"], case_id, "provider-allocation-unavailable",
                projection_version, row["id"],
            ),
            actor=_RECONCILER,
            category="allocation",
            amount=None,
            currency=None,
            source_ref=row["source_ref"],
            source_version=projection_version,
            attempt_state="unknown",
            basis="unknown",
            aggregation=row.get("aggregation", "additive"),
            coverage="partial",
            attempt_ref=row.get("attempt_ref"),
            unknown_reason=(
                "The reviewed provider allocation changed or became unavailable; "
                "review the case allocation again."
            ),
            budget_state="metering_failed",
            source_assurance="application_observation",
            allocation_method="operator_estimate",
            allocation_assumption=(
                "The prior amount was this case's operator-reviewed share of admitted "
                "provider billing."
            ),
        )

    # An absent operator-reported all-in total is informational once a separate
    # additive provider allocation supplies the case's provider amount. The
    # allocation itself remains partial until all declared families reconcile.
    total_ref = f"outcome-pilot:{record['id']}:{case_id}:reported-total"
    total_row = _current_cost_row(accounting.report(raw["id"]), total_ref)
    if desired_refs and total_row is not None and total_row.get("amount") is None:
        raw = _cost(
            accounting,
            raw,
            operation_id=_operation(
                record["id"], case_id, "reported-total-relationship",
                projection_version, aggregation,
            ),
            actor=_RECONCILER,
            category=total_row["category"],
            amount=None,
            currency=None,
            source_ref=total_ref,
            source_version=projection_version,
            attempt_state="unknown",
            basis="unknown",
            aggregation="informational",
            coverage="partial",
            attempt_ref=total_row.get("attempt_ref"),
            unknown_reason=(
                "No all-in workflow total was supplied; the reviewed provider "
                "allocation is accounted separately."
            ),
            budget_state="not_applicable",
            source_assurance="application_observation",
        )

    if desired_refs or prior_rows:
        receipts = _provider_receipt_rows(source)
        raw = _finalize_cost_coverage(
            accounting,
            raw,
            source,
            measurement,
            receipts,
            actor=_RECONCILER,
            catalog_version=_provider_catalog_version(source, receipts),
        )
    return raw


def _sync_reported_baseline(
    accounting: OutcomeAccounting,
    raw: dict,
    record: dict,
    case_id: str,
    measurement: dict,
    *,
    owner_id: str | None,
    service: OutcomeValueReporting | None,
) -> None:
    """Preserve the legacy pilot baseline as explicitly modeled value evidence."""

    values = service or OutcomeValueReporting(accounting=accounting)
    report = values.case_report(raw["id"], owner_id=owner_id)
    source_ref = f"outcome-pilot:{record['id']}:{case_id}:reported-baseline"
    current = report.get("baseline")
    if current is not None and current.get("source_ref") != source_ref:
        return
    cost = measurement.get("baseline_cost")
    minutes = measurement.get("baseline_minutes")
    if cost is None and minutes is None and current is None:
        return
    source_version = _version({
        "pilot_plan_version": record.get("plan_version"),
        "measurement_source_version": measurement.get("source_version"),
        "baseline_cost": cost,
        "baseline_minutes": minutes,
        "currency": measurement.get("currency"),
        "evidence": measurement.get("evidence"),
        "note": measurement.get("note"),
    })
    if current is not None and current.get("source_version") == source_version:
        return
    values.record_baseline(
        raw["id"],
        expected_revision=report["value_revision"],
        operation_id=_operation(
            record["id"], case_id, "reported-baseline", source_version,
        ),
        actor=_RECONCILER,
        cost_basis="estimated" if cost is not None else "unknown",
        cost_amount=cost,
        currency=measurement.get("currency") if cost is not None else None,
        cost_unknown_reason=(
            None if cost is not None else
            "The pilot observation did not include a modeled baseline cost."
        ),
        human_basis="estimated" if minutes is not None else "unknown",
        human_minutes=minutes,
        human_unknown_reason=(
            None if minutes is not None else
            "The pilot observation did not include modeled baseline human time."
        ),
        source_ref=source_ref,
        source_version=source_version,
        evidence_note=(
            "Modeled baseline projected from the operator-entered pilot observation; "
            "it is not independently verified."
        ),
        correction_of=current["id"] if current is not None else None,
        correction_reason=(
            "The current pilot observation changed its reported baseline."
            if current is not None else None
        ),
        owner_id=owner_id,
    )


def _sync_pilot_value_sources(
    request,
    accounting: OutcomeAccounting,
    raw: dict,
    record: dict,
    case_id: str,
    source: dict,
    measurement: dict,
    *,
    owner_id: str | None,
    value_service: OutcomeValueReporting | None,
) -> dict:
    from . import outcome_pilot_sources

    allocation_prefix = f"outcome-pilot:{record['id']}:{case_id}:provider-allocation:"
    has_current_projection = any(
        row.get("current") and row.get("source_ref", "").startswith(allocation_prefix)
        for row in accounting.report(raw["id"])["costs"]["events"]
    )
    if record.get("provider_cost_allocations") or has_current_projection:
        case = _case(record, case_id)

        def resolve(kind: str, reference: str) -> dict:
            if kind == case["kind"] and reference == case["reference"]:
                return source
            return outcome_pilot_sources.resolve(request, kind, reference)

        raw = _sync_reviewed_provider_allocations(
            accounting,
            raw,
            record,
            case_id,
            source,
            measurement,
            resolve=resolve,
        )
    _sync_reported_baseline(
        accounting,
        raw,
        record,
        case_id,
        measurement,
        owner_id=owner_id,
        service=value_service,
    )
    return raw


def reconcile_record(
    request,
    context: str,
    record_id: str,
    *,
    service: OutcomeAccounting | None = None,
    owner_id: str | None = None,
    value_service: OutcomeValueReporting | None = None,
) -> dict:
    """Refresh one pilot-backed accounting record from its current source."""

    from . import outcome_pilot_sources, outcome_pilots

    accounting = service or default_service
    report = accounting.report(record_id, owner_id=owner_id)
    raw = accounting.store.get(record_id)
    binding = _pilot_binding(raw or {})
    if raw is None or binding is None:
        return report
    pilot_id, case_id, plan_version = binding
    source_id = str(raw.get("work_item_id") or "")
    if ":" not in source_id:
        return report
    kind, reference = source_id.split(":", 1)
    # The pilot authority binds the accounting admission to the exact current
    # account/workspace context. Failure to load it is an authorization or
    # authority failure, not evidence that may be written into another
    # workspace's ledger merely because the owner principal is the same.
    pilot = outcome_pilots.get(pilot_id, context)
    if pilot.get("plan_version") != plan_version:
        raise RecordConflict("The accounting admission references another pilot plan version.")
    require_complete_admission(pilot, service=accounting)
    case = _case(pilot, case_id)
    if case.get("kind") != kind or case.get("reference") != reference:
        raise RecordConflict("The frozen pilot case binding changed.")
    measurement = case.get("measurement")
    unavailable_reason = None
    try:
        source = outcome_pilot_sources.resolve(request, kind, reference)
    except Exception as exc:
        unavailable_reason = type(exc).__name__
        source = {
            "version": hashlib.sha256(
                f"unavailable\0{source_id}\0{unavailable_reason}".encode()
            ).hexdigest(),
        }
    admission_error = None
    if unavailable_reason is None and isinstance(measurement, dict):
        try:
            _admission_precedes_work(case, source, raw)
        except RecordConflict as exc:
            admission_error = str(exc)
            unavailable_reason = "admission_binding_invalid"

    if unavailable_reason is not None or not isinstance(measurement, dict):
        result = "unavailable"
    else:
        result = _source_result(source, measurement)
    cost_measurement = measurement if isinstance(measurement, dict) else {}
    version = str(source.get("version") or "")
    if len(version) != 64 or any(c not in "0123456789abcdef" for c in version):
        version = hashlib.sha256(f"invalid\0{source_id}".encode()).hexdigest()

    # A pilot observation and the accounting record are separate durable stores.
    # Replaying the exact saved operation repairs a crash after the pilot commit
    # without duplicating any observation, disposition, decision, or cost event.
    supplied_operation = (
        measurement.get("source_operation_id")
        if isinstance(measurement, dict) else None
    )
    if (
        unavailable_reason is None
        and isinstance(measurement, dict)
        and version == measurement.get("source_version")
        and (
            isinstance(supplied_operation, str)
            and _PROVIDER_OPERATION_ID.fullmatch(supplied_operation)
            or not _legacy_sync_complete(
                report, pilot, case_id, source, measurement,
            )
        )
    ):
        sync_case(
            pilot,
            case_id,
            source,
            source_operation_id=_measurement_operation_id(
                pilot_id, case_id, measurement,
            ),
            actor=_RECONCILER,
            service=accounting,
        )
        raw = accounting.store.get(record_id)
        if raw is None:
            raise RecordConflict("The accounting record disappeared during reconciliation.")
        report = accounting.report(record_id, owner_id=owner_id)

    now = accounting.store.authoritative_time()
    current = next((
        row for row in reversed(report["observations"])
        if row["current"] and row["source_id"] == source_id
    ), None)
    if (
        current is not None and current["source_version"] == version
        and current["result"] == result
        and current.get("valid_until") is not None
        and current["valid_until"] > now + _SOURCE_REFRESH_MARGIN_SECONDS
    ):
        if unavailable_reason is None:
            raw = _sync_provider_receipts(
                accounting,
                raw,
                source,
                cost_measurement,
                actor=_RECONCILER,
            )
            if isinstance(measurement, dict):
                raw = _sync_pilot_value_sources(
                    request,
                    accounting,
                    raw,
                    pilot,
                    case_id,
                    source,
                    measurement,
                    owner_id=owner_id,
                    value_service=value_service,
                )
            return accounting.report(raw["id"], owner_id=owner_id)
        return report

    refresh_slot = int(now // _SOURCE_FRESHNESS_SECONDS)
    summary = (
        admission_error
        if admission_error is not None else
        str(measurement.get("evidence"))
        if result != "unavailable" and isinstance(measurement, dict) else
        "The authoritative source changed or could not be read; re-evaluation is required."
    )
    raw = accounting.record_observation(
        raw["id"], expected_revision=raw["revision"],
        operation_id=_operation(
            pilot_id, case_id, "source-refresh", version, result,
            current["id"] if current else "none", refresh_slot,
        ),
        actor=_RECONCILER, source_id=source_id, source_version=version,
        result=result, authoritative=True, summary=summary,
        valid_until=(refresh_slot + 2) * _SOURCE_FRESHNESS_SECONDS,
        correction_of=current["id"] if current else None,
    )
    refreshed = accounting.report(raw["id"], owner_id=owner_id)
    if result != "confirmed":
        raw = _invalidate_source_costs(
            accounting, raw, refreshed, pilot_id=pilot_id, case_id=case_id,
            source_version=version, refresh_slot=refresh_slot,
        )
    if unavailable_reason is None:
        raw = _sync_provider_receipts(
            accounting,
            raw,
            source,
            cost_measurement,
            actor=_RECONCILER,
        )
        if isinstance(measurement, dict):
            raw = _sync_pilot_value_sources(
                request,
                accounting,
                raw,
                pilot,
                case_id,
                source,
                measurement,
                owner_id=owner_id,
                value_service=value_service,
            )
    return accounting.report(raw["id"], owner_id=owner_id)


__all__ = [
    "admit_pilot", "reconcile_record", "require_complete_admission", "sync_case",
]
