"""Cohort value reporting layered on immutable outcome admissions.

The outcome ledger remains authoritative for admissions, outcomes, and delivered
cost.  This module adds separately auditable baseline and commercial evidence,
then projects a complete cohort without dropping failures or turning missing
inputs into zero.  Renewal and expansion evidence is deliberately excluded from
the savings calculation.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from decimal import Decimal, InvalidOperation, localcontext
from typing import Any

from .governed_records import GovernedRecordStore
from .outcome_accounting import SCHEMA as OUTCOME_SCHEMA
from .outcome_accounting import OutcomeAccounting, default_service
from .privacy_ops import RecordConflict

SCHEMA = "lightwork.outcome-value-evidence.v1"
STORE = GovernedRecordStore("outcome_value_evidence", "OVE", "outcome_value_evidence")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}\Z")
_OPERATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{15,99}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_BASIS = frozenset({"estimated", "observed", "unknown"})
_COMMERCIAL_KINDS = frozenset({"expansion", "renewal"})
_COMMERCIAL_STAGES = frozenset({"lost", "observed", "planned", "proposed", "won"})
_LABOUR_CATEGORIES = frozenset({
    "exception", "human", "review", "rework", "setup", "support",
})
_MAX_EVENTS = 5000
_MAX_RECORDS = 10_000
_MAX_COMMERCIAL_REPORT = 10_000
_DECIMAL_AGGREGATION_PRECISION = 80


def _canonical(value: object) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("value evidence must contain bounded JSON values") from exc


def _decimal_sum(values) -> Decimal:
    """Sum bounded reporting decimals without default-context rounding."""
    with localcontext() as context:
        context.prec = _DECIMAL_AGGREGATION_PRECISION
        return sum(values, Decimal(0))


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _text(value: object, label: str, limit: int = 4000) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    result = value.strip()
    if not result or len(result) > limit or any(
        ord(character) < 32 or ord(character) == 127 for character in result
    ):
        raise ValueError(f"{label} must be nonempty bounded text")
    return result


def _identifier(value: object, label: str) -> str:
    result = _text(value, label, 200)
    if not _ID.fullmatch(result):
        raise ValueError(f"{label} has unsupported characters")
    return result


def _operation(value: object) -> str:
    result = _text(value, "operation_id", 100)
    if not _OPERATION.fullmatch(result):
        raise ValueError("operation_id must be 16-100 portable characters")
    return result


def _source_version(value: object) -> str:
    result = _text(value, "source_version", 64)
    if not _SHA256.fullmatch(result):
        raise ValueError("source_version must be a lowercase SHA-256 digest")
    return result


def _money(value: object, label: str) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        raise ValueError(f"{label} must be a finite nonnegative decimal")
    raw = str(value)
    if len(raw) > 64:
        raise ValueError(f"{label} is too large")
    try:
        amount = Decimal(raw)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{label} must be a finite nonnegative decimal") from exc
    if not amount.is_finite() or amount < 0:
        raise ValueError(f"{label} must be a finite nonnegative bounded decimal")
    # Decimal zeros retain their exponent. Formatting ``0e-999999999`` before
    # handling zero would allocate an attacker-controlled fixed-point string.
    if amount.is_zero():
        return "0"
    if not -18 <= amount.adjusted() <= 18:
        raise ValueError(f"{label} must be a finite nonnegative bounded decimal")
    parts = amount.as_tuple()
    rendered_length = (
        len(parts.digits) + parts.exponent
        if parts.exponent >= 0
        else max(len(parts.digits) + 1, 2 - parts.exponent)
    )
    if rendered_length > 64:
        raise ValueError(f"{label} is too large")
    rendered = format(amount, "f")
    if len(rendered) > 64:
        raise ValueError(f"{label} is too large")
    return rendered.rstrip("0").rstrip(".") if "." in rendered else rendered


def _signed(value: Decimal) -> str:
    if not value.is_finite() or (value and not -24 <= value.adjusted() <= 24):
        raise ValueError("calculated value exceeds the reporting bound")
    rendered = format(value, "f")
    if len(rendered) > 96:
        raise ValueError("calculated value exceeds the reporting bound")
    return rendered.rstrip("0").rstrip(".") if "." in rendered else rendered


def _currency(value: object) -> str:
    result = _text(value, "currency", 3).upper()
    if not re.fullmatch(r"[A-Z]{3}", result):
        raise ValueError("currency must be a three-letter code")
    return result


def _component(
    *, basis: object, value: object | None, currency: object | None = None,
    unknown_reason: object | None, label: str,
) -> dict[str, Any]:
    normalized_basis = _text(basis, f"{label}_basis", 32).lower()
    if normalized_basis not in _BASIS:
        raise ValueError(f"{label} basis is unsupported")
    if normalized_basis == "unknown":
        if value is not None or currency is not None:
            raise ValueError(f"unknown {label} cannot include a value or currency")
        return {
            "basis": "unknown", "value": None, "currency": None,
            "unknown_reason": _text(unknown_reason, f"{label}_unknown_reason", 1000),
        }
    if value is None:
        raise ValueError(f"{label} is required when its basis is {normalized_basis}")
    return {
        "basis": normalized_basis,
        "value": _money(value, label),
        "currency": None if currency is None else _currency(currency),
        "unknown_reason": None,
    }


def _current(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], set[str]]:
    superseded = {
        str(row["correction_of"]) for row in rows if row.get("correction_of")
    }
    return [row for row in rows if row["id"] not in superseded], superseded


def _event_id(record_id: str, kind: str, operation_id: str) -> str:
    return f"{kind[:3].upper()}-" + _digest([record_id, kind, operation_id])[:48]


def _record_id(outcome_record_id: str, prefix: str) -> str:
    return prefix + "-" + hashlib.sha256(outcome_record_id.encode("utf-8")).hexdigest()[:48]


def _category(report: dict[str, Any]) -> str:
    if report["disposition"] == "cancelled":
        return "cancelled"
    if report["disposition"] == "failed" or report["technical_outcome"]["status"] == "failed":
        return "failed"
    if report["business_outcome"]["status"] in {"accepted", "rejected"}:
        return report["business_outcome"]["status"]
    return "unresolved"


def _cohort_scope(
    accounting: OutcomeAccounting,
    record_ids: list[str] | tuple[str, ...] | None,
    acceptance_contract_ref: str | None,
) -> tuple[list[str] | None, str | None, list[tuple[str, str]], bool]:
    if record_ids is None:
        if acceptance_contract_ref is not None:
            raise ValueError("an exact cohort contract requires its record manifest")
        ids = list(accounting.store.iter_record_ids(limit=_MAX_RECORDS + 1))
        return None, None, ids, len(ids) <= _MAX_RECORDS
    if isinstance(record_ids, (str, bytes)):
        raise ValueError("cohort record manifest must be a bounded sequence")
    exact_ids = [_identifier(value, "cohort record id") for value in record_ids]
    if not exact_ids or len(exact_ids) > _MAX_RECORDS:
        raise ValueError("cohort record manifest is empty or exceeds its bound")
    if len(set(exact_ids)) != len(exact_ids):
        raise ValueError("cohort record manifest contains a duplicate admission")
    contract = _text(acceptance_contract_ref, "acceptance_contract_ref", 512)
    return exact_ids, contract, [("", record_id) for record_id in exact_ids], True


def _render_cost_totals(
    totals: dict[str, Decimal],
    category_totals: dict[str, dict[str, Decimal]],
    overflow: set[str],
) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    rendered_totals: dict[str, str] = {}
    for code, value in sorted(totals.items()):
        try:
            rendered_totals[code] = _signed(value)
        except ValueError:
            overflow.add(code)
    rendered_categories: dict[str, dict[str, str]] = {}
    for category, values in sorted(category_totals.items()):
        rendered_categories[category] = {}
        for code, value in sorted(values.items()):
            try:
                rendered_categories[category][code] = _signed(value)
            except ValueError:
                overflow.add(code)
    return rendered_totals, rendered_categories


class OutcomeValueReporting:
    """Durable baseline/commercial evidence and complete cohort projections."""

    def __init__(
        self,
        *,
        accounting: OutcomeAccounting | None = None,
        store: GovernedRecordStore | None = None,
    ) -> None:
        self.accounting = accounting or default_service
        self.store = store or STORE

    def _binding(self, outcome: dict[str, Any]) -> dict[str, Any]:
        return {
            "outcome_record_id": outcome["id"],
            "admission_id": outcome["admission_id"],
            "work_item_id": outcome["work_item_id"],
            "owner_id": outcome["owner_id"],
        }

    def _validate_record(self, record: dict[str, Any], outcome: dict[str, Any]) -> None:
        if record.get("schema") != SCHEMA:
            raise ValueError("outcome value evidence uses an unsupported schema")
        binding = self._binding(outcome)
        if any(record.get(key) != value for key, value in binding.items()):
            raise RecordConflict("value evidence no longer matches its admitted outcome")
        if record.get("binding_sha256") != _digest(binding):
            raise ValueError("outcome value evidence failed its binding check")

    def _load(self, outcome: dict[str, Any]) -> dict[str, Any] | None:
        record = self.store.get(_record_id(outcome["id"], self.store.prefix))
        if record is not None:
            self._validate_record(record, outcome)
        return record

    def _ensure(
        self, outcome: dict[str, Any], *, expected_revision: int, actor: str,
    ) -> dict[str, Any]:
        if isinstance(expected_revision, bool) or not isinstance(expected_revision, int) or expected_revision < 0:
            raise ValueError("expected_revision must be a nonnegative integer")
        existing = self._load(outcome)
        if existing is not None:
            return existing
        if expected_revision != 0:
            raise RecordConflict("value evidence changed before this update")
        binding = self._binding(outcome)
        value = {
            "id": _record_id(outcome["id"], self.store.prefix),
            "schema": SCHEMA,
            **binding,
            "binding_sha256": _digest(binding),
            "baseline_events": [],
            "commercial_events": [],
            "operations": {},
        }
        try:
            return self.store.create(
                value, action="admit_outcome_value_evidence", actor=_text(actor, "actor", 4096),
                max_records=_MAX_RECORDS,
            )
        except RecordConflict:
            existing = self._load(outcome)
            if existing is None:
                raise
            return existing

    def _append(
        self,
        outcome: dict[str, Any],
        *,
        expected_revision: int,
        operation_id: str,
        actor: str,
        collection: str,
        event: dict[str, Any],
        action: str,
        operation_request: str | None = None,
    ) -> dict[str, Any]:
        operation = _operation(operation_id)
        request = (
            _source_version(operation_request)
            if operation_request is not None
            else _digest({
                key: value for key, value in event.items()
                if key not in {"id", "recorded_at"}
            })
        )
        record = self._ensure(outcome, expected_revision=expected_revision, actor=actor)
        previous = record.get("operations", {}).get(operation)
        if previous is not None:
            if previous != request:
                raise RecordConflict("operation_id belongs to different value evidence")
            return record
        effective_revision = expected_revision
        if expected_revision == 0 and record["revision"] == 1 and not record.get("operations"):
            effective_revision = 1
        if record["revision"] != effective_revision:
            raise RecordConflict("value evidence changed before this update")

        def mutate(current: dict[str, Any]) -> None:
            self._validate_record(current, outcome)
            prior = current.get("operations", {}).get(operation)
            if prior is not None:
                if prior != request:
                    raise RecordConflict("operation_id belongs to different value evidence")
                return
            rows = list(current.get(collection, []))
            if len(rows) >= _MAX_EVENTS:
                raise ValueError(f"{collection} reached its retention limit")
            rows.append(copy.deepcopy(event))
            current[collection] = rows
            current["operations"] = {**current.get("operations", {}), operation: request}

        try:
            saved = self.store.update(
                record["id"], mutate, expected_revision=effective_revision,
                action=action, actor=_text(actor, "actor", 4096),
            )
        except RecordConflict:
            current = self._load(outcome)
            if current is not None and current.get("operations", {}).get(operation) == request:
                return current
            raise
        if saved is None:
            raise RecordConflict("value evidence changed or disappeared")
        return saved

    def record_baseline(
        self,
        outcome_record_id: str,
        *,
        expected_revision: int,
        operation_id: str,
        actor: str,
        cost_basis: str,
        cost_amount: object | None,
        currency: object | None,
        cost_unknown_reason: str | None,
        human_basis: str,
        human_minutes: object | None,
        human_unknown_reason: str | None,
        source_ref: str,
        source_version: str,
        evidence_note: str,
        correction_of: str | None = None,
        correction_reason: str | None = None,
        owner_id: str | None = None,
        _operation_request: str | None = None,
    ) -> dict[str, Any]:
        outcome = self.accounting.report(
            _identifier(outcome_record_id, "outcome_record_id"), owner_id=owner_id,
        )
        cost = _component(
            basis=cost_basis, value=cost_amount, currency=currency,
            unknown_reason=cost_unknown_reason, label="baseline_cost",
        )
        if cost["basis"] != "unknown" and cost["currency"] is None:
            raise ValueError("baseline cost requires a currency")
        human = _component(
            basis=human_basis, value=human_minutes, unknown_reason=human_unknown_reason,
            label="baseline_human_minutes",
        )
        correction = None if correction_of is None else _identifier(correction_of, "correction_of")
        reason = None if correction_reason is None else _text(correction_reason, "correction_reason", 2000)
        record = self._load(outcome)
        rows = [] if record is None else record.get("baseline_events", [])
        current, superseded = _current(rows)
        operation = _operation(operation_id)
        retry = record is not None and operation in record.get("operations", {})
        if correction is None and current and not retry:
            raise RecordConflict("a current baseline exists; replace it with a documented correction")
        if correction is not None and not retry:
            if reason is None:
                raise ValueError("a baseline correction requires its reason")
            if correction in superseded or not any(row["id"] == correction for row in current):
                raise RecordConflict("baseline correction must replace the current baseline")
        event = {
            "id": _event_id(outcome["id"], "baseline", operation),
            "cost": cost,
            "human_effort": human,
            "source_ref": _text(source_ref, "source_ref", 512),
            "source_version": _source_version(source_version),
            "evidence_note": _text(evidence_note, "evidence_note", 4000),
            "correction_of": correction,
            "correction_reason": reason,
            "actor": _text(actor, "actor", 4096),
            "recorded_at": self.store.authoritative_time(),
        }
        return self._append(
            outcome, expected_revision=expected_revision, operation_id=operation_id,
            actor=actor, collection="baseline_events", event=event,
            action="record_outcome_baseline",
            operation_request=_operation_request,
        )

    def record_commercial(
        self,
        outcome_record_id: str,
        *,
        expected_revision: int,
        operation_id: str,
        actor: str,
        kind: str,
        stage: str,
        basis: str,
        amount: object | None,
        currency: object | None,
        unknown_reason: str | None,
        source_ref: str,
        source_version: str,
        note: str,
        correction_of: str | None = None,
        correction_reason: str | None = None,
        owner_id: str | None = None,
        _operation_request: str | None = None,
    ) -> dict[str, Any]:
        outcome = self.accounting.report(
            _identifier(outcome_record_id, "outcome_record_id"), owner_id=owner_id,
        )
        normalized_kind = _text(kind, "kind", 32).lower()
        normalized_stage = _text(stage, "stage", 32).lower()
        if normalized_kind not in _COMMERCIAL_KINDS or normalized_stage not in _COMMERCIAL_STAGES:
            raise ValueError("commercial kind or stage is unsupported")
        commercial_amount = _component(
            basis=basis, value=amount, currency=currency,
            unknown_reason=unknown_reason, label="commercial_amount",
        )
        if commercial_amount["basis"] != "unknown" and commercial_amount["currency"] is None:
            raise ValueError("commercial amount requires a currency")
        correction = None if correction_of is None else _identifier(correction_of, "correction_of")
        reason = None if correction_reason is None else _text(correction_reason, "correction_reason", 2000)
        record = self._load(outcome)
        rows = [] if record is None else record.get("commercial_events", [])
        current, superseded = _current(rows)
        operation = _operation(operation_id)
        retry = record is not None and operation in record.get("operations", {})
        normalized_source = _text(source_ref, "source_ref", 512)
        if (
            correction is None and not retry
            and any(
                row["kind"] == normalized_kind and row["source_ref"] == normalized_source
                for row in current
            )
        ):
            raise RecordConflict(
                "a current commercial source exists; replace it with a documented correction"
            )
        if correction is not None and not retry:
            target = next((row for row in current if row["id"] == correction), None)
            if target is None or correction in superseded:
                raise RecordConflict("commercial correction must replace a current record")
            if target["kind"] != normalized_kind or reason is None:
                raise ValueError("commercial correction requires the same kind and a reason")
        event = {
            "id": _event_id(outcome["id"], normalized_kind, operation),
            "kind": normalized_kind,
            "stage": normalized_stage,
            "amount": commercial_amount,
            "source_ref": normalized_source,
            "source_version": _source_version(source_version),
            "note": _text(note, "note", 4000),
            "correction_of": correction,
            "correction_reason": reason,
            "actor": _text(actor, "actor", 4096),
            "recorded_at": self.store.authoritative_time(),
        }
        return self._append(
            outcome, expected_revision=expected_revision, operation_id=operation_id,
            actor=actor, collection="commercial_events", event=event,
            action=f"record_outcome_{normalized_kind}",
            operation_request=_operation_request,
        )

    @staticmethod
    def _delivered_effort(outcome: dict[str, Any]) -> dict[str, Any]:
        labour = [
            row for row in outcome["costs"]["events"]
            if row["current"] and row.get("aggregation", "additive") != "coverage"
            and row["category"] in _LABOUR_CATEGORIES
        ]
        rows = [row for row in labour if row.get("quantity") is not None]
        missing = [
            row["id"] for row in labour
            if row.get("quantity") is None or row.get("unit") != "minutes"
        ]
        if not rows:
            return {
                "status": "unknown", "minutes": None, "basis": "unknown",
                "reason": "delivered human-time evidence is missing",
            }
        if missing:
            return {
                "status": "unknown", "minutes": None, "basis": "unknown",
                "reason": "one or more delivered human-time components are missing",
            }
        with localcontext() as context:
            context.prec = 80
            total = _decimal_sum(Decimal(row["quantity"]) for row in rows)
        basis = "estimated" if any(row["basis"] == "estimated" for row in rows) else "observed"
        return {"status": "complete", "minutes": _signed(total), "basis": basis, "reason": None}

    @staticmethod
    def _case_comparison(outcome: dict[str, Any], baseline: dict[str, Any] | None) -> dict[str, Any]:
        missing: list[str] = []
        cost_result: dict[str, Any]
        human_result: dict[str, Any]
        if baseline is None:
            missing.extend(("baseline_cost", "baseline_human_time"))
            baseline_cost = baseline_human = None
        else:
            baseline_cost = baseline["cost"]
            baseline_human = baseline["human_effort"]
            if baseline_cost["basis"] == "unknown":
                missing.append("baseline_cost")
            if baseline_human["basis"] == "unknown":
                missing.append("baseline_human_time")

        delivered_totals = outcome["costs"]["known_totals"]
        if not outcome["costs"]["complete"] or len(delivered_totals) != 1:
            missing.append("delivered_cost_coverage")
        if baseline_cost is not None and baseline_cost["basis"] != "unknown" and outcome["costs"]["complete"] and len(delivered_totals) == 1:
            delivered_currency, delivered_amount = next(iter(delivered_totals.items()))
            if baseline_cost["currency"] != delivered_currency:
                missing.append("cost_currency_alignment")
                cost_result = {
                    "status": "unavailable", "baseline": baseline_cost,
                    "delivered": {"amount": delivered_amount, "currency": delivered_currency},
                    "net_savings": None, "roi_percent": None,
                }
            else:
                with localcontext() as context:
                    context.prec = 80
                    baseline_amount = Decimal(baseline_cost["value"])
                    delivered = Decimal(delivered_amount)
                    difference = baseline_amount - delivered
                    roi = None if baseline_amount == 0 else difference * Decimal(100) / baseline_amount
                measured = (
                    baseline_cost["basis"] == "observed"
                    and outcome["costs"]["settlement_status"] in {"observed", "settled"}
                )
                delivered_result = {
                    "amount": delivered_amount, "currency": delivered_currency,
                    "basis": outcome["costs"]["settlement_status"],
                }
                try:
                    net_savings = _signed(difference)
                    roi_percent = None if roi is None else _signed(roi)
                except ValueError:
                    # Valid bounded inputs can still produce an unreportably
                    # large ratio when a tiny baseline is divided into a large
                    # delivered cost.  Preserve the evidence while withholding
                    # the calculated comparison instead of failing the report.
                    missing.append("cost_comparison_overflow")
                    cost_result = {
                        "status": "unavailable", "baseline": baseline_cost,
                        "delivered": delivered_result, "net_savings": None,
                        "roi_percent": None, "overflow": True,
                        "reason": "the cost comparison exceeds the reporting bound",
                    }
                else:
                    cost_result = {
                        "status": "measured" if measured else "modeled",
                        "baseline": baseline_cost,
                        "delivered": delivered_result,
                        "net_savings": net_savings,
                        "roi_percent": roi_percent,
                    }
        else:
            if not outcome["costs"]["complete"] or len(delivered_totals) != 1:
                unavailable_reason = "delivered cost coverage is incomplete"
            elif baseline_cost is None or baseline_cost["basis"] == "unknown":
                unavailable_reason = "baseline cost evidence is incomplete"
            else:
                unavailable_reason = "the cost comparison is unavailable"
            cost_result = {
                "status": "unavailable", "baseline": baseline_cost,
                "delivered": None, "net_savings": None, "roi_percent": None,
                "reason": unavailable_reason,
            }

        delivered_effort = OutcomeValueReporting._delivered_effort(outcome)
        if delivered_effort["status"] != "complete":
            missing.append("delivered_human_time")
        if baseline_human is not None and baseline_human["basis"] != "unknown" and delivered_effort["status"] == "complete":
            with localcontext() as context:
                context.prec = 80
                difference = Decimal(baseline_human["value"]) - Decimal(delivered_effort["minutes"])
            measured = baseline_human["basis"] == "observed" and delivered_effort["basis"] == "observed"
            human_result = {
                "status": "measured" if measured else "modeled",
                "baseline": baseline_human,
                "delivered": delivered_effort,
                "minutes_saved": _signed(difference),
            }
        else:
            human_result = {
                "status": "unavailable", "baseline": baseline_human,
                "delivered": delivered_effort, "minutes_saved": None,
            }
        if cost_result["status"] != "unavailable" and human_result["status"] == "unavailable":
            cost_result = {
                **cost_result,
                "status": "unavailable",
                "net_savings": None,
                "roi_percent": None,
                "reason": "delivered or baseline human-time evidence is incomplete",
            }
        return {
            "cost": cost_result,
            "human_effort": human_result,
            "missing_components": sorted(set(missing)),
            "measured_positive_roi": (
                cost_result["status"] == "measured"
                and human_result["status"] == "measured"
                and cost_result["roi_percent"] is not None
                and Decimal(cost_result["roi_percent"]) > 0
            ),
        }

    def case_report(
        self, outcome_record_id: str, *, owner_id: str | None = None,
    ) -> dict[str, Any]:
        outcome = self.accounting.report(
            _identifier(outcome_record_id, "outcome_record_id"), owner_id=owner_id,
        )
        record = self._load(outcome)
        baseline_events = copy.deepcopy([] if record is None else record.get("baseline_events", []))
        current_baselines, superseded_baselines = _current(baseline_events)
        for row in baseline_events:
            row["current"] = row["id"] not in superseded_baselines
            row["current_reason"] = "current" if row["current"] else "superseded"
        if len(current_baselines) > 1:
            raise ValueError("outcome value evidence has multiple current baselines")
        commercial_events = copy.deepcopy([] if record is None else record.get("commercial_events", []))
        current_commercial, superseded_commercial = _current(commercial_events)
        for row in commercial_events:
            row["current"] = row["id"] not in superseded_commercial
            row["current_reason"] = "current" if row["current"] else "superseded"
        baseline = current_baselines[0] if current_baselines else None
        return {
            "schema": "lightwork.outcome-value-case.v1",
            "outcome": outcome,
            "value_revision": 0 if record is None else record["revision"],
            "baseline": baseline,
            "baseline_history": baseline_events,
            "comparison": self._case_comparison(outcome, baseline),
            "renewals": [row for row in commercial_events if row["kind"] == "renewal"],
            "expansions": [row for row in commercial_events if row["kind"] == "expansion"],
            "current_commercial_count": len(current_commercial),
            "commercial_included_in_savings": False,
        }

    @staticmethod
    def _aggregate_comparison(cases: list[dict[str, Any]], component: str) -> dict[str, Any]:
        if not cases:
            return {
                "status": "unavailable", "missing_records": [],
                "net_savings": None, "roi_percent": None,
            }
        rows = [case["comparison"][component] for case in cases]
        missing_records = [
            case["outcome"]["id"] for case, row in zip(cases, rows, strict=True)
            if row["status"] == "unavailable"
        ]
        if missing_records:
            key = "minutes_saved" if component == "human_effort" else "net_savings"
            result = {
                "status": "unavailable", "missing_records": missing_records,
                key: None, **({} if component == "human_effort" else {"roi_percent": None}),
            }
            if any(row.get("overflow") is True for row in rows):
                result.update({
                    "overflow": True,
                    "reason": "one or more case comparisons exceed the reporting bound",
                })
            return result
        status = "measured" if all(row["status"] == "measured" for row in rows) else "modeled"
        with localcontext() as context:
            context.prec = 80
            if component == "human_effort":
                total = _decimal_sum(Decimal(row["minutes_saved"]) for row in rows)
                return {
                    "status": status, "missing_records": [],
                    "minutes_saved": _signed(total),
                }
            currencies = {row["baseline"]["currency"] for row in rows}
            if len(currencies) != 1:
                return {
                    "status": "unavailable",
                    "missing_records": [case["outcome"]["id"] for case in cases],
                    "net_savings": None, "roi_percent": None,
                    "reason": "cost currencies do not align",
                }
            baseline_total = _decimal_sum(
                Decimal(row["baseline"]["value"]) for row in rows
            )
            delivered_total = _decimal_sum(
                Decimal(row["delivered"]["amount"]) for row in rows
            )
            difference = baseline_total - delivered_total
            roi = None if baseline_total == 0 else difference * Decimal(100) / baseline_total
        try:
            rendered_baseline = _signed(baseline_total)
            rendered_delivered = _signed(delivered_total)
            rendered_difference = _signed(difference)
            rendered_roi = None if roi is None else _signed(roi)
        except ValueError:
            return {
                "status": "unavailable",
                "missing_records": [case["outcome"]["id"] for case in cases],
                "net_savings": None,
                "roi_percent": None,
                "overflow": True,
                "reason": "the cohort cost comparison exceeds the reporting bound",
            }
        return {
            "status": status, "missing_records": [],
            "currency": next(iter(currencies)),
            "baseline_total": rendered_baseline,
            "delivered_total": rendered_delivered,
            "net_savings": rendered_difference,
            "roi_percent": rendered_roi,
            "measured_positive_roi": status == "measured" and roi is not None and roi > 0,
        }

    def cohort_report(
        self,
        *,
        owner_id: str | None = None,
        record_ids: list[str] | tuple[str, ...] | None = None,
        acceptance_contract_ref: str | None = None,
    ) -> dict[str, Any]:
        exact_ids, contract, ids, scope_complete = _cohort_scope(
            self.accounting, record_ids, acceptance_contract_ref,
        )
        categories = dict.fromkeys(
            ("accepted", "cancelled", "failed", "rejected", "unresolved"), 0,
        )
        cases: list[dict[str, Any]] = []
        totals: dict[str, Decimal] = {}
        category_totals: dict[str, dict[str, Decimal]] = {}
        unknown_categories: dict[str, int] = {}
        overflow: set[str] = set()
        allocation_assumptions_explicit = True
        allocation_missing_records: set[str] = set()
        commercial = {"renewals": [], "expansions": []}
        commercial_counts = {"renewals": 0, "expansions": 0}
        commercial_records_complete = True
        for _, record_id in ids[:_MAX_RECORDS]:
            raw = self.accounting.store.get(record_id)
            if raw is None:
                if exact_ids is not None:
                    raise RecordConflict("an exact cohort admission is missing")
                continue
            if raw.get("schema") != OUTCOME_SCHEMA:
                raise ValueError("outcome cohort contains an unsupported record")
            if owner_id is not None and raw.get("owner_id") != owner_id:
                if exact_ids is not None:
                    raise PermissionError("an exact cohort admission is outside this owner scope")
                continue
            if contract is not None and raw.get("acceptance_contract_ref") != contract:
                raise RecordConflict("an exact cohort admission no longer matches its contract")
            case = self.case_report(record_id, owner_id=owner_id)
            outcome = case["outcome"]
            categories[_category(outcome)] += 1
            for code, amount in outcome["costs"]["known_totals"].items():
                totals[code] = _decimal_sum((
                    totals.get(code, Decimal(0)), Decimal(amount),
                ))
            for event in outcome["costs"]["events"]:
                if not event["current"] or event.get("aggregation", "additive") != "additive":
                    continue
                if (
                    event.get("allocation_method", "direct") != "direct"
                    and not event.get("allocation_assumption")
                ):
                    allocation_assumptions_explicit = False
                    allocation_missing_records.add(outcome["id"])
                category = event["category"]
                if event["amount"] is None:
                    unknown_categories[category] = unknown_categories.get(category, 0) + 1
                    continue
                bucket = category_totals.setdefault(category, {})
                bucket[event["currency"]] = _decimal_sum((
                    bucket.get(event["currency"], Decimal(0)),
                    Decimal(event["amount"]),
                ))
            for kind in commercial:
                current_events = [event for event in case[kind] if event["current"]]
                commercial_counts[kind] += len(current_events)
                remaining = _MAX_COMMERCIAL_REPORT - len(commercial[kind])
                if len(current_events) > remaining:
                    commercial_records_complete = False
                commercial[kind].extend({
                    "outcome_record_id": outcome["id"], **event,
                } for event in current_events[:max(remaining, 0)])
            timestamps = {
                "admitted_at": outcome["admitted_at"],
                "last_observed_at": max((row["observed_at"] for row in outcome["observations"]), default=None),
                "last_decided_at": max((row["decided_at"] for row in outcome["decisions"]), default=None),
                "last_disposition_at": max((row["recorded_at"] for row in outcome["dispositions"]), default=None),
                "last_cost_at": max((row["recorded_at"] for row in outcome["costs"]["events"]), default=None),
                "last_baseline_at": max((row["recorded_at"] for row in case["baseline_history"]), default=None),
            }
            cost_summary = {
                key: copy.deepcopy(value)
                for key, value in outcome["costs"].items() if key != "events"
            }
            cases.append({
                "outcome": {
                    key: copy.deepcopy(outcome[key]) for key in (
                        "id", "revision", "admission_id", "work_item_id", "owner_id",
                        "acceptance_contract_ref", "disposition", "technical_outcome",
                        "business_outcome",
                    )
                } | {"costs": cost_summary},
                "category": _category(outcome),
                "timestamps": timestamps,
                "value_revision": case["value_revision"],
                "baseline": case["baseline"],
                "comparison": case["comparison"],
                "renewal_count": sum(row["current"] for row in case["renewals"]),
                "expansion_count": sum(row["current"] for row in case["expansions"]),
            })
        rendered_totals, rendered_categories = _render_cost_totals(
            totals, category_totals, overflow,
        )
        scope_complete = scope_complete and commercial_records_complete
        comparison = {
            "cost": self._aggregate_comparison(cases, "cost"),
            "human_effort": self._aggregate_comparison(cases, "human_effort"),
            "commercial_records_included": False,
        }
        if (
            comparison["cost"].get("measured_positive_roi") is True
            and comparison["human_effort"]["status"] != "measured"
        ):
            comparison["cost"]["measured_positive_roi"] = False
        if allocation_missing_records:
            comparison["cost"] = {
                "status": "unavailable",
                "missing_records": sorted(allocation_missing_records),
                "net_savings": None,
                "roi_percent": None,
                "reason": "one or more shared cost allocations omit their assumption",
            }
        if not scope_complete:
            comparison = {
                "cost": {
                    "status": "unavailable", "missing_records": [],
                    "net_savings": None, "roi_percent": None,
                    "reason": "cohort exceeds the bounded export scope",
                },
                "human_effort": {
                    "status": "unavailable", "missing_records": [],
                    "minutes_saved": None,
                    "reason": "cohort exceeds the bounded export scope",
                },
                "commercial_records_included": False,
            }
        admitted = len(cases)
        if exact_ids is not None and admitted != len(exact_ids):
            raise RecordConflict("the exact cohort did not reconcile to its admission manifest")
        return {
            "schema": "lightwork.outcome-value-cohort.v1",
            "admitted": admitted,
            "categories": categories,
            "reconciles": sum(categories.values()) == admitted,
            "scope_complete": scope_complete,
            "cases": cases,
            "costs": {
                "known_totals": rendered_totals,
                "category_totals": rendered_categories,
                "unknown_event_counts_by_category": dict(sorted(unknown_categories.items())),
                "incomplete_records": sum(not case["outcome"]["costs"]["complete"] for case in cases),
                "failed_attempts": sum(case["outcome"]["costs"]["failed_attempt_count"] for case in cases),
                "aggregate_overflow_currencies": sorted(overflow),
                "complete": (
                    scope_complete and not overflow
                    and allocation_assumptions_explicit
                    and all(case["outcome"]["costs"]["complete"] for case in cases)
                ),
                "allocation_assumptions_explicit": allocation_assumptions_explicit,
            },
            "comparison": comparison,
            "commercial": commercial,
            "commercial_counts": commercial_counts,
            "commercial_records_complete": commercial_records_complete,
            "commercial_separate_from_savings": True,
            "cohort_binding": None if exact_ids is None else {
                "acceptance_contract_ref": contract,
                "record_count": len(exact_ids),
                "record_ids_sha256": _digest(exact_ids),
            },
        }

    def export_report(
        self,
        *,
        owner_id: str | None = None,
        record_ids: list[str] | tuple[str, ...] | None = None,
        acceptance_contract_ref: str | None = None,
    ) -> dict[str, Any]:
        cohort = self.cohort_report(
            owner_id=owner_id,
            record_ids=record_ids,
            acceptance_contract_ref=acceptance_contract_ref,
        )
        limitations = [
            "Missing provider, human-time, or baseline evidence withholds net savings and ROI.",
            "Modeled comparisons remain labeled modeled and are not measured ROI.",
            "Renewal and expansion evidence is reported separately from operational savings.",
            "Invoices and verified payments require their own authenticated source evidence.",
            "Observed baseline and human effort remain operator-reported until customer evidence is qualified through the pilot program.",
        ]
        if not cohort["commercial_records_complete"]:
            limitations.append(
                "Commercial detail exceeded the bounded export; counts remain visible and complete-export status is false."
            )
        return {
            **cohort,
            "schema": "lightwork.outcome-value-export.v1",
            "generated_at": self.store.authoritative_time(),
            "cohort_sha256": _digest(cohort),
            "limitations": limitations,
        }


default_value_service = OutcomeValueReporting()

__all__ = ["OutcomeValueReporting", "SCHEMA", "STORE", "default_value_service"]
