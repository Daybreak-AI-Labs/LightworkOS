"""Durable outcome, evidence, and complete-cost accounting.

The ledger records admitted work before execution and retains every observation,
decision, disposition, and cost correction.  Its projections deliberately keep
technical verification, human business acceptance, and cost completeness as
separate questions.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import threading
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation, localcontext
from functools import wraps
from typing import Any

from .budget import Budget, BudgetExceeded, TokenCharge, UnpricedModelError
from .file_lock import cross_process_lock, ensure_private_directory
from .governed_records import GovernedRecordStore
from .paths import current_tenant_id_strict, maverick_home
from .platform_contracts import build_contract
from .privacy_ops import RecordConflict

SCHEMA = "lightwork.outcome-accounting.v1"
STORE = GovernedRecordStore("outcome_accounting", "OAC", "outcome_accounting")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}\Z")
_OPERATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{15,99}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_OBSERVATION_RESULTS = frozenset({"confirmed", "contradictory", "missing", "unavailable"})
_DECISIONS = frozenset({"accepted", "rejected", "unresolved"})
_DISPOSITIONS = frozenset({"active", "cancelled", "completed", "failed"})
_COST_CATEGORIES = frozenset({
    "allocation", "evaluation", "exception", "generation", "human", "inference",
    "other", "retrieval", "review", "rework", "retry", "search", "setup",
    "storage", "support", "update",
})
_PROVIDER_USAGE_CATEGORIES = frozenset({
    "evaluation", "generation", "inference", "retrieval", "search", "storage",
    "update",
})
_ALLOCATION_METHODS = frozenset({
    "direct", "equal_share", "operator_estimate", "unattributed", "usage_weighted",
})
_ATTEMPT_STATES = frozenset({"cancelled", "failed", "succeeded", "unknown"})
_COST_BASES = frozenset({"estimated", "observed", "settled", "unknown"})
_COST_AGGREGATIONS = frozenset({"additive", "informational", "coverage"})
_COST_COVERAGE = frozenset({"partial", "complete"})
COST_COVERAGE_FAMILIES = (
    "provider_usage", "failed_attempts", "setup", "review", "exception",
    "rework", "support", "allocation",
)
_COST_COVERAGE_STATUSES = frozenset({"included", "zero", "unknown"})
_COST_SOURCE_ASSURANCE = frozenset({
    "application_observation", "operator_assertion", "local_signed_receipt",
    "authenticated_provider_invoice",
})
_BUDGET_STATES = frozenset({
    "not_applicable", "within_limit", "limit_exceeded", "metering_failed",
})
_MAX_EVENTS = 5000
_MAX_RECORDS = 10_000
_MAX_PAGE = 200
_MAX_PAGE_SCAN = 500
_MAX_USAGE_COUNT = (1 << 63) - 1
_MAX_RATE_MULTIPLIER = 1000
_DECIMAL_AGGREGATION_PRECISION = 80
_TOKEN_USAGE_FIELDS = frozenset({
    "cache_read_tok", "cache_write_tok", "cache_write_ttl", "cache_read_mult",
    "cache_write_5m_tok", "cache_write_1h_tok",
})
_PRICING_EVIDENCE_FIELDS = frozenset({
    "model_id", "input_per_mtok", "output_per_mtok", "source", "as_of",
    "fetched_at", "currency", "confidence", "verified", "rate_card_version",
    "evidence_id", "pricing_basis", "applicability",
})
_BUDGET_ACCOUNTING_LOCK = threading.RLock()


def _canonical(value: object) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("accounting input must contain bounded JSON values") from exc


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _coverage_declarations(
    value: object | None, *, coverage: str,
) -> dict[str, dict[str, str]] | None:
    """Normalize the exact evidence boundary behind a completeness assertion."""
    if value is None:
        if coverage == "complete":
            raise ValueError(
                "complete cost coverage requires every required cost-family declaration"
            )
        return None
    if not isinstance(value, dict) or set(value) != set(COST_COVERAGE_FAMILIES):
        raise ValueError(
            "cost coverage declarations must name every required cost family exactly once"
        )
    normalized: dict[str, dict[str, str]] = {}
    for family in COST_COVERAGE_FAMILIES:
        declaration = value[family]
        if not isinstance(declaration, dict) or set(declaration) != {"status", "note"}:
            raise ValueError("each cost coverage declaration requires status and note")
        status = _required(
            declaration.get("status"), f"{family} coverage status", 32,
        ).lower()
        if status not in _COST_COVERAGE_STATUSES:
            raise ValueError("cost coverage declaration status is unsupported")
        normalized[family] = {
            "status": status,
            "note": _required(
                declaration.get("note"), f"{family} coverage note", 1000,
            ),
        }
    if coverage == "complete" and any(
        row["status"] == "unknown" for row in normalized.values()
    ):
        raise ValueError("complete cost coverage cannot contain an unknown cost family")
    return normalized


def _required(value: object, label: str, limit: int = 4000) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    text = value.strip()
    if not text or len(text) > limit:
        raise ValueError(f"{label} must be nonempty and at most {limit} characters")
    return text


def _identifier(value: object, label: str) -> str:
    text = _required(value, label, 200)
    if not _ID.fullmatch(text):
        raise ValueError(f"{label} has unsupported characters")
    return text


def _opaque(value: object, label: str, limit: int = 512) -> str:
    """Validate an externally assigned identity without rewriting its alphabet."""
    text = _required(value, label, limit)
    if any(ord(character) < 32 or ord(character) == 127 for character in text):
        raise ValueError(f"{label} contains unsupported control characters")
    return text


def _operation(value: object) -> str:
    text = _required(value, "operation_id", 100)
    if not _OPERATION.fullmatch(text):
        raise ValueError("operation_id must be 16-100 portable characters")
    return text


def _source_version(value: object) -> str:
    text = _required(value, "source_version", 64)
    if not _SHA256.fullmatch(text):
        raise ValueError("source_version must be a lowercase SHA-256 digest")
    return text


def _when(value: object | None, label: str, *, default: float | None = None) -> float:
    candidate = default if value is None else value
    if isinstance(candidate, bool) or not isinstance(candidate, (int, float)):
        raise ValueError(f"{label} must be a finite timestamp")
    parsed = float(candidate)
    if not math.isfinite(parsed) or parsed <= 0:
        raise ValueError(f"{label} must be a finite timestamp")
    return parsed


def _money(value: object, label: str = "amount") -> str:
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


def _decimal_sum(values) -> Decimal:
    """Sum bounded ledger decimals without the process default's 28-digit rounding."""
    with localcontext() as context:
        context.prec = _DECIMAL_AGGREGATION_PRECISION
        return sum(values, Decimal(0))


def _identity_scalar(value: object) -> object:
    """Return a bounded, non-secret representation for idempotency hashing."""
    if value is None or type(value) in {bool, float}:
        if isinstance(value, float) and not math.isfinite(value):
            return {"invalid_float": str(value)}
        return value
    if type(value) is int:
        return value if value.bit_length() <= 4096 else {"invalid_integer": "oversized"}
    if isinstance(value, Decimal):
        rendered = str(value)
        return (
            {"decimal": rendered}
            if len(rendered) <= 128 else
            {"decimal_sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest()}
        )
    if isinstance(value, str):
        if len(value) <= 512:
            return value
        return {"sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(), "length": len(value)}
    return {"invalid_type": f"{type(value).__module__}.{type(value).__qualname__}"}


def _validate_token_metering_input(
    in_tokens: object,
    out_tokens: object,
    model: object,
    usage: dict[str, Any],
) -> None:
    """Reject inputs that Budget could only discover after partial mutation."""
    unexpected = sorted(set(usage) - _TOKEN_USAGE_FIELDS)
    if unexpected:
        raise BudgetExceeded(f"unsupported token usage fields: {', '.join(unexpected)}")
    if model is not None:
        try:
            _required(model, "model", 512)
        except ValueError as exc:
            raise BudgetExceeded("invalid model: expected a bounded model identifier") from exc
    for label, value in (
        ("in_tokens", in_tokens),
        ("out_tokens", out_tokens),
        ("cache_read_tok", usage.get("cache_read_tok", 0)),
        ("cache_write_tok", usage.get("cache_write_tok", 0)),
        ("cache_write_5m_tok", usage.get("cache_write_5m_tok", 0)),
        ("cache_write_1h_tok", usage.get("cache_write_1h_tok", 0)),
    ):
        try:
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError("non-finite")
            count = int(value or 0)
        except (TypeError, ValueError, OverflowError) as exc:
            raise BudgetExceeded(f"invalid {label}: expected a bounded token count") from exc
        if count < 0 or count > _MAX_USAGE_COUNT:
            raise BudgetExceeded(f"invalid {label}: expected a bounded token count")
    ttl = usage.get("cache_write_ttl")
    if ttl is not None and (not isinstance(ttl, str) or len(ttl) > 64):
        raise BudgetExceeded("invalid cache_write_ttl: expected bounded text")
    multiplier = usage.get("cache_read_mult")
    if multiplier is not None:
        try:
            if isinstance(multiplier, bool):
                raise ValueError("boolean")
            parsed = float(multiplier)
        except (TypeError, ValueError, OverflowError) as exc:
            raise BudgetExceeded("invalid cache_read_mult: expected a finite multiplier") from exc
        if not math.isfinite(parsed) or not 0 <= parsed <= _MAX_RATE_MULTIPLIER:
            raise BudgetExceeded("invalid cache_read_mult: expected a finite bounded multiplier")


def _budget_snapshot(budget: Budget) -> tuple[int, int, int, int, Decimal]:
    counts: list[int] = []
    for label in (
        "input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens",
    ):
        value = getattr(budget, label, None)
        if isinstance(value, bool) or not isinstance(value, int):
            raise BudgetExceeded(f"invalid budget meter state: {label} is not a token count")
        if value < 0 or value > _MAX_USAGE_COUNT:
            raise BudgetExceeded(f"invalid budget meter state: {label} is outside its bound")
        counts.append(value)
    try:
        dollars = Decimal(str(budget.dollars))
    except (InvalidOperation, ValueError) as exc:
        raise BudgetExceeded("invalid budget meter state: dollars is not decimal") from exc
    if not dollars.is_finite() or dollars < 0:
        raise BudgetExceeded("invalid budget meter state: dollars is not finite and nonnegative")
    return counts[0], counts[1], counts[2], counts[3], dollars


def _currency(value: object) -> str:
    text = _required(value, "currency", 3).upper()
    if not re.fullmatch(r"[A-Z]{3}", text):
        raise ValueError("currency must be a three-letter code")
    return text


def _pricing_evidence(value: object | None) -> dict[str, object] | None:
    """Normalize the exact bounded rate evidence attached by Budget."""

    if value is None:
        return None
    if (not isinstance(value, dict) or not set(value).issuperset(_PRICING_EVIDENCE_FIELDS)
            or set(value) - _PRICING_EVIDENCE_FIELDS - {"valid_until"}):
        raise ValueError("pricing evidence must contain the complete rate-card contract")
    verified = value["verified"]
    if type(verified) is not bool:
        raise ValueError("pricing evidence verified must be true or false")
    confidence_value = value["confidence"]
    if isinstance(confidence_value, bool):
        raise ValueError("pricing evidence confidence must be a finite number")
    try:
        confidence = float(confidence_value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("pricing evidence confidence must be a finite number") from exc
    if not math.isfinite(confidence) or not 0 <= confidence <= 1:
        raise ValueError("pricing evidence confidence must be between zero and one")
    normalized = {
        "model_id": _opaque(value["model_id"], "pricing model_id", 512),
        "input_per_mtok": _money(value["input_per_mtok"], "input token rate"),
        "output_per_mtok": _money(value["output_per_mtok"], "output token rate"),
        "source": _opaque(value["source"], "pricing source", 2048),
        "as_of": _required(value["as_of"], "pricing as_of", 64),
        "fetched_at": _required(value["fetched_at"], "pricing fetched_at", 128),
        "currency": _currency(value["currency"]),
        "confidence": confidence,
        "verified": verified,
        "rate_card_version": _opaque(
            value["rate_card_version"], "rate_card_version", 256,
        ),
        "evidence_id": _opaque(value["evidence_id"], "pricing evidence_id", 256),
        "pricing_basis": _required(value["pricing_basis"], "pricing_basis", 1000),
        "applicability": _required(value["applicability"], "pricing applicability", 1000),
    }
    expiry = value.get("valid_until")
    if expiry is not None:
        # Preserve the date that governed the original charge, including when
        # replaying receipts after expiry. Admission/charging enforces expiry;
        # historical evidence must remain readable. Omit absent/None values so
        # legacy non-expiring receipts retain their canonical representation.
        if (not isinstance(expiry, str) or len(expiry) != 10
                or date.fromisoformat(expiry) < date.fromisoformat(normalized["as_of"])):
            raise ValueError("pricing valid_until must be an ISO date on or after as_of")
        normalized["valid_until"] = expiry
    return normalized


def _record_id(admission_id: str, prefix: str) -> str:
    return prefix + "-" + hashlib.sha256(admission_id.encode("utf-8")).hexdigest()[:48]


def _event_id(record_id: str, kind: str, operation_id: str) -> str:
    return f"{kind.upper()}-" + _digest([record_id, kind, operation_id])[:48]


def _reservation_claim_id(record_id: str, reservation_ref: str) -> str:
    return "OAC-" + _digest([record_id, "provider-reservation", reservation_ref])[:48]


def _current(rows: list[dict[str, Any]], *, now: float) -> tuple[list[dict[str, Any]], set[str]]:
    effective = [
        row for row in rows
        if row.get("observed_at", row.get("recorded_at", 0)) <= now
    ]
    superseded = {
        str(row.get("correction_of")) for row in effective if row.get("correction_of")
    }
    current = [row for row in effective if row["id"] not in superseded]
    fresh = [
        row for row in current
        if row.get("valid_until") is None or row["valid_until"] >= now
    ]
    return fresh, superseded


def _cost_family_rows(rows: list[dict[str, Any]], family: str) -> list[dict[str, Any]]:
    if family == "provider_usage":
        return [
            row for row in rows
            if row.get("category") in _PROVIDER_USAGE_CATEGORIES
            or row.get("budget_reconciliation") is not None
            or row.get("source_assurance") == "authenticated_provider_invoice"
            or row.get("pricing_evidence") is not None
            or (
                row.get("category") == "allocation"
                and row.get("source_assurance") == "application_observation"
                and row.get("allocation_method") == "operator_estimate"
                and str(row.get("source_ref") or "").startswith("outcome-pilot:")
                and ":provider-allocation:" in str(row.get("source_ref") or "")
            )
        ]
    if family == "failed_attempts":
        return [
            row for row in rows
            if row["attempt_state"] == "failed" or row["category"] == "retry"
        ]
    if family == "review":
        return [row for row in rows if row["category"] in {"human", "review"}]
    if family == "allocation":
        return [
            row for row in rows
            if row["category"] == "allocation"
            or row.get("allocation_method", "direct") != "direct"
        ]
    return [row for row in rows if row["category"] == family]


def _unresolved_provider_or_attempt_evidence(
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return current provider/attempt evidence that cannot support completeness.

    Informational rows stay outside monetary aggregation, but they still carry
    current evidence about provider usage and attempts. An all-in total cannot
    turn an unknown receipt or attempt into complete coverage. Explicitly
    correcting that row removes it from ``rows`` through the normal current-row
    projection, so stronger replacement evidence can restore completeness.
    """

    relevant = {
        row["id"]
        for family in ("provider_usage", "failed_attempts")
        for row in _cost_family_rows(rows, family)
    }
    return [
        row
        for row in rows
        if row["id"] in relevant
        and (row.get("amount") is None or row.get("attempt_state") == "unknown")
    ]


def _all_in_total(
    value: object,
    *,
    category: str,
    aggregation: str,
    amount: str | None,
) -> bool:
    if not isinstance(value, bool):
        raise ValueError("all_in_total must be true or false")
    if value and (category != "other" or aggregation != "additive" or amount is None):
        raise ValueError("an all-in total must be a priced additive other cost event")
    return value


def _bind_cost_coverage_scope(record: dict[str, Any], event: dict[str, Any]) -> None:
    if event["coverage"] != "complete" or event["aggregation"] not in {
        "additive", "coverage",
    }:
        event["coverage_scope_sha256"] = None
        return
    projected, _ = _current(
        [*record["cost_events"], event], now=event["recorded_at"],
    )
    if _unresolved_provider_or_attempt_evidence(projected):
        raise ValueError(
            "complete cost coverage requires every current provider receipt and "
            "attempt to have a known amount and state"
        )
    has_all_in_total = any(
        row.get("all_in_total") is True
        and row.get("aggregation", "additive") == "additive"
        and row.get("amount") is not None
        for row in projected
    )
    for family, declaration in event.get("coverage_declarations", {}).items():
        family_rows = _cost_family_rows(projected, family)
        if declaration["status"] == "included":
            if not has_all_in_total and not any(
                row.get("aggregation", "additive") == "additive"
                and row.get("amount") is not None
                for row in family_rows
            ):
                raise ValueError(
                    f"{family} is declared included without a current additive component "
                    "or an explicit all-in total"
                )
            continue
        if any(
            (row.get("amount") is not None and Decimal(row["amount"]) != 0)
            or (row.get("quantity") is not None and Decimal(row["quantity"]) != 0)
            for row in family_rows
        ):
            raise ValueError(
                f"{family} cannot be declared zero while a current cost component is nonzero"
            )
    event["coverage_scope_sha256"] = _digest([
        row["id"] for row in projected
        if row.get("aggregation", "additive") == "additive"
    ])


@contextmanager
def _accounting_effect_fence(record_id: str):
    """Serialize one record's durable mutations with mutable budget effects."""
    tenant = current_tenant_id_strict()
    identity = hashlib.sha256(f"{tenant}\0{record_id}".encode()).hexdigest()
    target = maverick_home() / "outcome-accounting-effects" / identity
    ensure_private_directory(target.parent)
    with cross_process_lock(target, strict=True):
        yield


def _serialize_record_mutation(function):
    @wraps(function)
    def guarded(self, record_id, *args, **kwargs):
        with _accounting_effect_fence(_identifier(record_id, "record_id")):
            return function(self, record_id, *args, **kwargs)

    return guarded


def _serialize_budget_accounting(function):
    @wraps(function)
    def guarded(self, *args, **kwargs):
        record_id = args[0] if args else kwargs.get("record_id")
        with _BUDGET_ACCOUNTING_LOCK:
            with _accounting_effect_fence(_identifier(record_id, "record_id")):
                return function(self, *args, **kwargs)

    return guarded


@dataclass(frozen=True)
class CostEvidenceAuthority:
    """Exact result returned by a trusted receipt or invoice verifier."""

    source_assurance: str
    evidence_ref: str
    evidence_sha256: str
    verification_authority: str


@dataclass(frozen=True)
class ReservationAuthority:
    """Exact provider-ledger reservation claimed for one cost event."""

    reservation_ref: str
    projected_amount: object
    state: str
    actual_amount: object | None
    currency: str
    verification_authority: str


def _verified_cost_evidence(
    resolver: Callable[[str, str, str], CostEvidenceAuthority] | None,
    assurance: str,
    evidence_ref: str | None,
    evidence_sha256: str | None,
) -> tuple[str | None, str | None, str | None]:
    if assurance not in {"local_signed_receipt", "authenticated_provider_invoice"}:
        if evidence_ref is not None or evidence_sha256 is not None:
            raise ValueError(
                "cost evidence may be bound only to a signed receipt or provider invoice"
            )
        return None, None, None
    normalized_ref = _opaque(evidence_ref, "evidence_ref", 512)
    normalized_sha256 = _source_version(evidence_sha256)
    if resolver is None:
        raise PermissionError(
            "signed receipt or provider invoice assurance requires a trusted verifier"
        )
    authority = resolver(assurance, normalized_ref, normalized_sha256)
    if (
        type(authority) is not CostEvidenceAuthority
        or authority.source_assurance != assurance
        or authority.evidence_ref != normalized_ref
        or authority.evidence_sha256 != normalized_sha256
    ):
        raise PermissionError("cost evidence authority did not verify the exact source")
    verification_authority = _opaque(
        authority.verification_authority, "verification_authority", 512,
    )
    return normalized_ref, normalized_sha256, verification_authority


@dataclass(frozen=True)
class _ReservationProjection:
    authority: ReservationAuthority
    reference: str
    projected_amount: str
    currency: str
    actual_amount: str | None
    verification_authority: str


def _inspect_reservation(
    resolver: Callable[[str, str], ReservationAuthority] | None,
    *,
    reservation_ref: str | None,
    reserved_amount: object | None,
    reserved_currency: object | None,
    amount: object | None,
    currency: object | None,
    basis: str,
    work_item_id: str,
) -> _ReservationProjection | None:
    if reservation_ref is None:
        if reserved_amount is not None or reserved_currency is not None:
            raise ValueError("reserved amount and currency require a reservation reference")
        return None
    reference = _opaque(reservation_ref, "reservation_ref", 512)
    if resolver is None:
        raise PermissionError(
            "budget reconciliation requires the trusted provider reservation authority"
        )
    authority = resolver(reference, work_item_id)
    if type(authority) is not ReservationAuthority or authority.reservation_ref != reference:
        raise PermissionError(
            "provider reservation authority did not verify the exact reservation"
        )
    state = _required(authority.state, "reservation state", 32).lower()
    if state not in {"held", "unknown", "settled"}:
        raise PermissionError("provider reservation authority returned an invalid state")
    authority_currency = _currency(authority.currency)
    projected = _money(authority.projected_amount, "projected reservation amount")
    if reserved_amount is not None and _money(
        reserved_amount, "reserved_amount",
    ) != projected:
        raise ValueError("reserved amount does not match provider authority")
    if reserved_currency is not None and _currency(reserved_currency) != authority_currency:
        raise ValueError("reserved currency does not match provider authority")
    actual = None
    if state == "settled":
        if authority.actual_amount is None:
            raise PermissionError("settled provider reservation omitted its actual amount")
        actual = _money(authority.actual_amount, "provider actual amount")
        if amount is not None and _money(amount) != actual:
            raise ValueError("final amount does not match provider authority")
        if currency is not None and _currency(currency) != authority_currency:
            raise ValueError("final currency does not match provider authority")
        if basis == "unknown":
            raise ValueError("a settled provider reservation requires a priced basis")
    elif amount is not None or currency is not None or basis != "unknown":
        raise ValueError("an unsettled provider reservation must remain an unknown cost")
    verification = _opaque(
        authority.verification_authority, "reservation verification_authority", 512,
    )
    return _ReservationProjection(
        authority, reference, projected, authority_currency, actual, verification,
    )


def _reservation_reconciliation(
    reservation: _ReservationProjection | None,
    final_amount: str | None,
) -> dict[str, Any] | None:
    if reservation is None:
        return None
    difference = None if final_amount is None else _decimal_sum((
        Decimal(final_amount),
        Decimal(reservation.projected_amount).copy_negate(),
    ))
    return {
        "reservation_ref": reservation.reference,
        "reserved_amount": reservation.projected_amount,
        "final_amount": final_amount,
        "currency": reservation.currency,
        "delta": (
            None if difference is None else
            _money(abs(difference), "reservation delta")
        ),
        "status": (
            reservation.authority.state if difference is None else
            "overrun" if difference > 0 else
            "released" if difference < 0 else "matched"
        ),
        "verification_authority": reservation.verification_authority,
    }


def _validate_cost_progress(
    record: dict[str, Any],
    event: dict[str, Any],
    correction: str | None,
    reservation: _ReservationProjection | None,
    *,
    now: float,
) -> None:
    if correction is not None:
        target = next((row for row in record["cost_events"] if row["id"] == correction), None)
        if target is None or target["source_ref"] != event["source_ref"]:
            raise ValueError("cost correction must reference the same recorded source")
        target_assurance = target.get("source_assurance", "application_observation")
        if (
            target_assurance != "operator_assertion"
            and event.get("source_assurance") != target_assurance
            and not (
                target_assurance == "application_observation"
                and event.get("source_assurance") in {
                    "authenticated_provider_invoice", "local_signed_receipt",
                }
            )
        ):
            raise PermissionError(
                "a cost correction cannot replace evidence owned by another source authority"
            )
        if target.get("budget_reconciliation") is not None and reservation is None:
            raise PermissionError(
                "a provider reservation cost can only be corrected through its trusted authority"
            )
        _, superseded = _current(record["cost_events"], now=now)
        if correction in superseded:
            raise RecordConflict("cost event was already superseded")
    if reservation is None:
        return
    prior_reservations = [
        row for row in record["cost_events"]
        if (row.get("budget_reconciliation") or {}).get("reservation_ref")
        == reservation.reference
    ]
    if prior_reservations and correction != prior_reservations[-1]["id"]:
        raise RecordConflict(
            "a provider reservation can only advance by correcting its prior cost event"
        )


def _prepare_outcome_reservation(
    claimer: Callable[[ReservationAuthority, str, str], ReservationAuthority] | None,
    reservation: _ReservationProjection | None,
    *,
    record_id: str,
    work_item_id: str,
) -> None:
    if reservation is None:
        return
    if claimer is None:
        raise PermissionError("budget reconciliation requires an atomic reservation claim")
    claimed = claimer(
        reservation.authority,
        work_item_id,
        _reservation_claim_id(record_id, reservation.reference),
    )
    if claimed != reservation.authority:
        raise PermissionError("provider reservation changed before its accounting claim")


def _commit_outcome_reservation(
    committer: Callable[
        [ReservationAuthority, str, str, str], ReservationAuthority
    ] | None,
    reservation: _ReservationProjection | None,
    *,
    record_id: str,
    work_item_id: str,
    event_id: str,
) -> None:
    if reservation is None:
        return
    if committer is None:
        raise PermissionError("budget reconciliation requires a durable claim commit")
    committed = committer(
        reservation.authority,
        work_item_id,
        _reservation_claim_id(record_id, reservation.reference),
        event_id,
    )
    if committed != reservation.authority:
        raise PermissionError("provider reservation changed before its claim commit")


class OutcomeAccounting:
    """CAS service for one tenant's append-only logical outcome records."""

    def __init__(
        self,
        *,
        store: GovernedRecordStore | None = None,
        cost_evidence_resolver: Callable[
            [str, str, str], CostEvidenceAuthority
        ] | None = None,
        reservation_resolver: Callable[[str, str], ReservationAuthority] | None = None,
        reservation_claimer: Callable[
            [ReservationAuthority, str, str], ReservationAuthority
        ] | None = None,
        reservation_committer: Callable[
            [ReservationAuthority, str, str, str], ReservationAuthority
        ] | None = None,
    ) -> None:
        self.store = store or STORE
        self.cost_evidence_resolver = cost_evidence_resolver
        self.reservation_resolver = reservation_resolver
        self.reservation_claimer = reservation_claimer
        self.reservation_committer = reservation_committer

    def admit(
        self,
        *,
        admission_id: str,
        work_item_id: str,
        acceptance_contract_ref: str,
        owner_id: str,
        actor: str,
    ) -> dict[str, Any]:
        admission = _opaque(admission_id, "admission_id")
        value = {
            "id": _record_id(admission, self.store.prefix),
            "schema": SCHEMA,
            "admission_id": admission,
            "work_item_id": _opaque(work_item_id, "work_item_id"),
            "acceptance_contract_ref": _required(
                acceptance_contract_ref, "acceptance_contract_ref", 512,
            ),
            "owner_id": _opaque(owner_id, "owner_id", 256),
            "admitted_at": self.store.authoritative_time(),
            "observations": [],
            "decisions": [],
            "dispositions": [],
            "cost_events": [],
            "operations": {},
        }
        value["admission_input_sha256"] = _digest({
            key: value[key]
            for key in ("admission_id", "work_item_id", "acceptance_contract_ref", "owner_id")
        })
        existing = self.store.get(value["id"])
        if existing is not None:
            if existing.get("admission_input_sha256") != value["admission_input_sha256"]:
                raise RecordConflict("admission identity belongs to different work")
            return existing
        try:
            return self.store.create(
                value, action="admit_outcome_work", actor=_opaque(actor, "actor", 4096),
                max_records=_MAX_RECORDS,
            )
        except RecordConflict:
            # A concurrent exact retry can win between the read and create.
            existing = self.store.get(value["id"])
            if existing is None or existing.get("admission_input_sha256") != value["admission_input_sha256"]:
                raise
            return existing

    @staticmethod
    def _load(store: GovernedRecordStore, record_id: str) -> dict[str, Any]:
        record = store.get(_identifier(record_id, "record_id"))
        if record is None or record.get("schema") != SCHEMA:
            raise LookupError("outcome accounting record is unavailable")
        return record

    @staticmethod
    def _previous(record: dict[str, Any], operation_id: str, request: str) -> bool:
        previous = record.get("operations", {}).get(operation_id)
        if previous is not None and previous != request:
            raise RecordConflict("operation_id belongs to a different accounting change")
        return previous == request

    @_serialize_record_mutation
    def _append(
        self,
        record_id: str,
        *,
        expected_revision: int,
        operation_id: str,
        request: str,
        actor: str,
        collection: str,
        event: dict[str, Any],
        action: str,
    ) -> dict[str, Any]:
        current = self._load(self.store, record_id)
        if self._previous(current, operation_id, request):
            return current

        def mutate(record: dict[str, Any]) -> None:
            if record.get("schema") != SCHEMA:
                raise ValueError("outcome accounting schema changed")
            if self._previous(record, operation_id, request):
                return
            rows = list(record.get(collection, []))
            if len(rows) >= _MAX_EVENTS:
                raise ValueError(f"{collection} reached its retention limit")
            rows.append(copy.deepcopy(event))
            record[collection] = rows
            record["operations"] = {**record.get("operations", {}), operation_id: request}

        try:
            saved = self.store.update(
                record_id, mutate, expected_revision=expected_revision,
                action=action, actor=_opaque(actor, "actor", 4096),
            )
        except RecordConflict:
            # Concurrent exact retries return the single committed operation.
            current = self._load(self.store, record_id)
            if self._previous(current, operation_id, request):
                return current
            raise
        if saved is None:
            raise RecordConflict("outcome accounting record changed or disappeared")
        return saved

    def record_observation(
        self,
        record_id: str,
        *,
        expected_revision: int,
        operation_id: str,
        actor: str,
        source_id: str,
        source_version: str,
        result: str,
        authoritative: bool,
        summary: str,
        observed_at: float | None = None,
        valid_until: float | None = None,
        correction_of: str | None = None,
    ) -> dict[str, Any]:
        operation = _operation(operation_id)
        outcome = _required(result, "result", 32).lower()
        if outcome not in _OBSERVATION_RESULTS:
            raise ValueError("observation result is unsupported")
        if type(authoritative) is not bool:
            raise ValueError("authoritative must be true or false")
        observed_was_supplied = observed_at is not None
        observed = _when(
            observed_at, "observed_at", default=self.store.authoritative_time(),
        )
        expires = None if valid_until is None else _when(valid_until, "valid_until")
        if expires is not None and expires <= observed:
            raise ValueError("valid_until must be after observed_at")
        source = _opaque(source_id, "source_id")
        if authoritative and source.casefold().startswith("simulator:"):
            raise PermissionError(
                "simulated evidence cannot be admitted as an authoritative live outcome"
            )
        correction = None if correction_of is None else _identifier(correction_of, "correction_of")
        event = {
            "id": _event_id(record_id, "observation", operation),
            "source_id": source,
            "source_version": _source_version(source_version),
            "result": outcome,
            "authoritative": authoritative,
            "summary": _required(summary, "summary", 4000),
            "observed_at": observed,
            "valid_until": expires,
            "correction_of": correction,
            "actor": _required(actor, "actor", 4096),
        }
        requested = {key: value for key, value in event.items() if key not in {"id", "observed_at"}}
        if observed_was_supplied:
            requested["observed_at"] = observed
        request = _digest(requested)
        record = self._load(self.store, record_id)
        # Exact retries must win before correction-state validation. Once the
        # first correction commits, its target is intentionally superseded.
        if self._previous(record, operation, request):
            return record
        if correction is not None:
            target = next((row for row in record["observations"] if row["id"] == correction), None)
            if target is None or target["source_id"] != source:
                raise ValueError("observation correction must reference the same recorded source")
            if observed < target["observed_at"]:
                raise ValueError("observation correction cannot predate the observation it corrects")
            if any(
                row.get("correction_of") == correction
                for row in record["observations"]
            ):
                raise RecordConflict("observation was already superseded")
        return self._append(
            record_id, expected_revision=expected_revision, operation_id=operation,
            request=request, actor=actor, collection="observations", event=event,
            action="record_outcome_observation",
        )

    def record_decision(
        self,
        record_id: str,
        *,
        expected_revision: int,
        operation_id: str,
        actor: str,
        decision: str,
        rationale: str,
        evidence_version: str,
    ) -> dict[str, Any]:
        operation = _operation(operation_id)
        verdict = _required(decision, "decision", 32).lower()
        if verdict not in _DECISIONS:
            raise ValueError("decision is unsupported")
        reviewer = _opaque(actor, "actor", 4096)
        if verdict in {"accepted", "rejected"} and not reviewer.startswith("user:"):
            raise PermissionError("a named human must accept or reject a business outcome")
        normalized_evidence = _source_version(evidence_version)
        event = {
            "id": _event_id(record_id, "decision", operation),
            "decision": verdict,
            "rationale": _required(rationale, "rationale", 4000),
            "evidence_version": normalized_evidence,
            "actor": reviewer,
            "decided_at": self.store.authoritative_time(),
        }
        request = _digest({
            key: value for key, value in event.items() if key not in {"id", "decided_at"}
        })
        record = self._load(self.store, record_id)
        # A committed decision remains retryable even after its evidence expires.
        if self._previous(record, operation, request):
            return record
        current = self._report_record(record)
        if normalized_evidence != current["evidence_version"]:
            raise RecordConflict("evidence changed or expired; review it again")
        if verdict == "accepted" and current["technical_outcome"]["status"] != "verified":
            raise ValueError("business acceptance requires current authoritative verification")
        # A fresh decision supersedes the last human disposition even when a
        # source correction or expiry made that prior decision non-current.
        # Otherwise stale decisions remain semantically live in the history.
        prior_decision = record.get("decisions", [])[-1] if record.get("decisions") else None
        event["supersedes_ref"] = (
            prior_decision["id"] if prior_decision is not None else None
        )
        return self._append(
            record_id, expected_revision=expected_revision, operation_id=operation,
            request=request,
            actor=actor, collection="decisions", event=event,
            action="record_business_outcome",
        )

    def record_disposition(
        self,
        record_id: str,
        *,
        expected_revision: int,
        operation_id: str,
        actor: str,
        disposition: str,
        reason: str,
    ) -> dict[str, Any]:
        operation = _operation(operation_id)
        state = _required(disposition, "disposition", 32).lower()
        if state not in _DISPOSITIONS:
            raise ValueError("disposition is unsupported")
        event = {
            "id": _event_id(record_id, "disposition", operation),
            "disposition": state,
            "reason": _required(reason, "reason", 4000),
            "actor": _required(actor, "actor", 4096),
            "recorded_at": self.store.authoritative_time(),
        }
        return self._append(
            record_id, expected_revision=expected_revision, operation_id=operation,
            request=_digest({key: value for key, value in event.items() if key not in {"id", "recorded_at"}}),
            actor=actor, collection="dispositions", event=event,
            action="record_outcome_disposition",
        )

    def record_cost(
        self,
        record_id: str,
        *,
        expected_revision: int,
        operation_id: str,
        actor: str,
        category: str,
        attempt_state: str,
        basis: str,
        amount: object | None,
        currency: object | None,
        source_ref: str,
        source_version: str,
        quantity: object | None = None,
        unit: str | None = None,
        unknown_reason: str | None = None,
        correction_of: str | None = None,
        aggregation: str = "additive",
        coverage: str = "partial",
        attempt_ref: str | None = None,
        budget_state: str = "not_applicable",
        source_assurance: str = "application_observation",
        evidence_ref: str | None = None,
        evidence_sha256: str | None = None,
        reservation_ref: str | None = None,
        reserved_amount: object | None = None,
        reserved_currency: object | None = None,
        pricing_evidence: dict[str, object] | None = None,
        allocation_method: str = "direct",
        allocation_assumption: str | None = None,
        correction_reason: str | None = None,
        evidence_note: str | None = None,
        coverage_declarations: dict[str, object] | None = None,
        all_in_total: bool = False,
        _operation_request: str | None = None,
    ) -> dict[str, Any]:
        operation = _operation(operation_id)
        kind = _required(category, "category", 32).lower()
        state = _required(attempt_state, "attempt_state", 32).lower()
        evidence_basis = _required(basis, "basis", 32).lower()
        rollup = _required(aggregation, "aggregation", 32).lower()
        coverage_state = _required(coverage, "coverage", 32).lower()
        enforcement = _required(budget_state, "budget_state", 32).lower()
        assurance = _required(source_assurance, "source_assurance", 64).lower()
        allocation = _required(allocation_method, "allocation_method", 32).lower()
        if (kind not in _COST_CATEGORIES or state not in _ATTEMPT_STATES
                or evidence_basis not in _COST_BASES or rollup not in _COST_AGGREGATIONS
                or coverage_state not in _COST_COVERAGE or enforcement not in _BUDGET_STATES
                or assurance not in _COST_SOURCE_ASSURANCE
                or allocation not in _ALLOCATION_METHODS):
            raise ValueError(
                "cost category, attempt state, basis, aggregation, coverage, budget state, "
                "source assurance, or allocation method is unsupported"
            )
        assumption = (
            None if allocation_assumption is None else
            _required(allocation_assumption, "allocation_assumption", 2000)
        )
        if allocation != "direct" and assumption is None:
            raise ValueError("a non-direct cost allocation requires its assumption")
        correction_note = (
            None if correction_reason is None else
            _required(correction_reason, "correction_reason", 2000)
        )
        source_note = (
            None if evidence_note is None else
            _required(evidence_note, "evidence_note", 4000)
        )
        normalized_coverage_declarations = _coverage_declarations(
            coverage_declarations, coverage=coverage_state,
        )
        record = self._load(self.store, record_id)
        if (
            operation not in record.get("operations", {})
            and (
                isinstance(expected_revision, bool)
                or not isinstance(expected_revision, int)
                or record["revision"] != expected_revision
            )
        ):
            raise RecordConflict("outcome accounting record changed before cost was recorded")
        event_identifier = _event_id(record_id, "cost", operation)

        reservation = _inspect_reservation(
            self.reservation_resolver,
            reservation_ref=reservation_ref,
            reserved_amount=reserved_amount,
            reserved_currency=reserved_currency,
            amount=amount,
            currency=currency,
            basis=evidence_basis,
            work_item_id=record["work_item_id"],
        )
        if reservation is not None:
            amount = reservation.actual_amount
            currency = reservation.currency if amount is not None else None
        if amount is None:
            if currency is not None or evidence_basis != "unknown":
                raise ValueError("an unpriced cost requires unknown basis and no currency")
            reason = _required(unknown_reason, "unknown_reason", 1000)
            normalized_amount = normalized_currency = None
        else:
            if unknown_reason is not None:
                raise ValueError("a priced cost cannot include an unknown reason")
            normalized_amount = _money(amount)
            normalized_currency = _currency(currency)
            reason = None
        normalized_all_in_total = _all_in_total(
            all_in_total,
            category=kind,
            aggregation=rollup,
            amount=normalized_amount,
        )
        normalized_pricing_evidence = _pricing_evidence(pricing_evidence)
        if normalized_pricing_evidence is not None:
            if normalized_amount is None or normalized_currency != normalized_pricing_evidence["currency"]:
                raise ValueError("pricing evidence must bind a priced cost in the same currency")
            if evidence_basis == "observed" and not normalized_pricing_evidence["verified"]:
                raise ValueError("unverified rate evidence must be labeled estimated")
        if quantity is None:
            if unit is not None:
                raise ValueError("a cost unit requires a quantity")
            normalized_quantity = normalized_unit = None
        else:
            normalized_quantity = _money(quantity, "quantity")
            normalized_unit = _required(unit, "unit", 32)
        normalized_source = _required(source_ref, "source_ref", 512)
        normalized_evidence_ref, normalized_evidence_sha256, verification_authority = (
            _verified_cost_evidence(
                self.cost_evidence_resolver, assurance, evidence_ref, evidence_sha256,
            )
        )
        reconciliation = _reservation_reconciliation(reservation, normalized_amount)
        normalized_attempt = _opaque(
            normalized_source if attempt_ref is None else attempt_ref, "attempt_ref", 512,
        )
        correction = None if correction_of is None else _identifier(correction_of, "correction_of")
        event = {
            "id": event_identifier,
            "category": kind,
            "attempt_state": state,
            "basis": evidence_basis,
            "aggregation": rollup,
            "coverage": coverage_state,
            "attempt_ref": normalized_attempt,
            "budget_state": enforcement,
            "source_assurance": assurance,
            "evidence_ref": normalized_evidence_ref,
            "evidence_sha256": normalized_evidence_sha256,
            "verification_authority": verification_authority,
            "budget_reconciliation": reconciliation,
            "pricing_evidence": normalized_pricing_evidence,
            "allocation_method": allocation,
            "allocation_assumption": assumption,
            "amount": normalized_amount,
            "currency": normalized_currency,
            "quantity": normalized_quantity,
            "unit": normalized_unit,
            "unknown_reason": reason,
            "source_ref": normalized_source,
            "source_version": _source_version(source_version),
            "evidence_note": source_note,
            "all_in_total": normalized_all_in_total,
            "correction_of": correction,
            "correction_reason": correction_note,
            "actor": _required(actor, "actor", 4096),
            "recorded_at": self.store.authoritative_time(),
        }
        if normalized_coverage_declarations is not None:
            event["coverage_declarations"] = normalized_coverage_declarations
        request = _operation_request or _digest({
            key: value for key, value in event.items() if key not in {"id", "recorded_at"}
        })
        if _operation_request is not None:
            request = _source_version(_operation_request)
        # Exact retries must return before a correction target is reclassified
        # as superseded by the first successful write.
        if self._previous(record, operation, request):
            if reservation is not None and not any(
                row.get("id") == event_identifier
                for row in record.get("cost_events", [])
            ):
                raise RecordConflict(
                    "the accounting operation exists without its provider cost event"
                )
            _commit_outcome_reservation(
                self.reservation_committer,
                reservation,
                record_id=record_id,
                work_item_id=record["work_item_id"],
                event_id=event_identifier,
            )
            return record
        if correction is not None and correction_note is None:
            raise ValueError("a cost correction requires its documented reason")
        _validate_cost_progress(
            record, event, correction, reservation,
            now=self.store.authoritative_time(),
        )
        if rollup == "coverage" and (
            coverage_state != "complete"
            or kind != "other"
            or state != "succeeded"
            or normalized_amount != "0"
        ):
            raise ValueError(
                "a coverage assertion must be a successful complete zero-value other event"
            )
        _bind_cost_coverage_scope(record, event)
        _prepare_outcome_reservation(
            self.reservation_claimer, reservation,
            record_id=record_id, work_item_id=record["work_item_id"],
        )
        saved = self._append(
            record_id, expected_revision=expected_revision, operation_id=operation,
            request=request,
            actor=actor, collection="cost_events", event=event,
            action="record_outcome_cost",
        )
        if reservation is not None and not any(
            row.get("id") == event_identifier
            for row in saved.get("cost_events", [])
        ):
            raise RecordConflict("provider cost event was not durably appended")
        _commit_outcome_reservation(
            self.reservation_committer,
            reservation,
            record_id=record_id,
            work_item_id=record["work_item_id"],
            event_id=event_identifier,
        )
        return saved

    @_serialize_budget_accounting
    def account_tokens(
        self,
        record_id: str,
        *,
        expected_revision: int,
        operation_id: str,
        actor: str,
        budget: Budget,
        in_tokens: int,
        out_tokens: int,
        source_ref: str,
        source_version: str,
        model: str | None = None,
        **usage: Any,
    ) -> dict[str, Any]:
        operation = _operation(operation_id)
        normalized_actor = _opaque(actor, "actor", 4096)
        normalized_source = _required(source_ref, "source_ref", 512)
        normalized_version = _source_version(source_version)
        token_request = _digest({
            "actor": normalized_actor,
            "in_tokens": _identity_scalar(in_tokens),
            "out_tokens": _identity_scalar(out_tokens),
            "model": _identity_scalar(model),
            "source_ref": normalized_source,
            "source_version": normalized_version,
            "usage": {
                str(key): _identity_scalar(value)
                for key, value in sorted(usage.items())
            },
        })
        budget_operation = _digest([
            current_tenant_id_strict(), record_id, operation, token_request,
        ])
        current = self._load(self.store, record_id)
        # Retrying an accounting response must not charge the mutable Budget a
        # second time. A conflicting reuse is also rejected before mutation.
        if self._previous(current, operation, token_request):
            return current
        if (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or current["revision"] != expected_revision
        ):
            raise RecordConflict("outcome accounting record changed after usage was reviewed")
        if len(current.get("cost_events", [])) >= _MAX_EVENTS:
            raise ValueError("cost_events reached its retention limit")
        failure: BudgetExceeded | None = None
        charge: TokenCharge | None = None
        try:
            _validate_token_metering_input(in_tokens, out_tokens, model, usage)
            _budget_snapshot(budget)
        except BudgetExceeded as exc:
            failure = exc
        if failure is None:
            try:
                candidate = budget.record_tokens(
                    in_tokens,
                    out_tokens,
                    model=model,
                    operation_id=budget_operation,
                    **usage,
                )
                if type(candidate) is not TokenCharge:
                    raise BudgetExceeded(
                        "budget meter did not return an attributable token charge"
                    )
                charge = candidate
            except BudgetExceeded as exc:
                failure = exc
                attached = getattr(exc, "token_charge", None)
                if type(attached) is TokenCharge:
                    charge = attached
        normalized_charge: str | None = None
        normalized_pricing: dict[str, object] | None = None
        if charge is not None:
            try:
                normalized_charge = _money(charge.dollars, "token charge")
                normalized_pricing = _pricing_evidence(charge.pricing_evidence)
                if normalized_pricing is None:
                    raise ValueError("token charge omitted rate evidence")
            except ValueError as exc:
                failure = failure or BudgetExceeded(
                    "token charge could not be represented with bounded price evidence"
                )
                failure.__cause__ = exc
                charge = None
                normalized_charge = None
                normalized_pricing = None
        metering_failed = charge is None or isinstance(failure, UnpricedModelError)
        cost_basis = (
            "unknown" if metering_failed else
            "observed" if normalized_pricing["verified"] else "estimated"
        )
        saved = self.record_cost(
            record_id, expected_revision=expected_revision, operation_id=operation,
            actor=normalized_actor, category="inference",
            attempt_state="unknown" if metering_failed else "succeeded",
            basis=cost_basis,
            amount=None if metering_failed else normalized_charge,
            currency=None if metering_failed else "USD",
            unknown_reason=(
                "Provider usage could not be validated or priced; the amount is unknown."
                if metering_failed else None
            ),
            source_ref=normalized_source, source_version=normalized_version,
            attempt_ref=normalized_source,
            budget_state=(
                "metering_failed" if metering_failed else
                "limit_exceeded" if failure is not None else "within_limit"
            ),
            pricing_evidence=normalized_pricing,
            _operation_request=token_request,
        )
        if failure is not None:
            failure.accounting_record = saved
            raise failure
        return saved

    def report(
        self,
        record_id: str,
        *,
        now: float | None = None,
        owner_id: str | None = None,
    ) -> dict[str, Any]:
        record = self._load(self.store, record_id)
        if owner_id is not None and record.get("owner_id") != _opaque(
            owner_id, "owner_id", 256,
        ):
            raise LookupError("outcome accounting record is unavailable")
        return self._report_record(record, now=now)

    def _report_record(
        self,
        record: dict[str, Any],
        *,
        now: float | None = None,
        include_contract: bool = True,
    ) -> dict[str, Any]:
        current_time = _when(
            now, "now", default=self.store.authoritative_time(),
        )
        observations = copy.deepcopy(record.get("observations", []))
        fresh_observations, superseded_observations = _current(observations, now=current_time)
        fresh_ids = {row["id"] for row in fresh_observations}
        for row in observations:
            row["current"] = row["id"] in fresh_ids
            row["current_reason"] = (
                "current" if row["current"] else
                "superseded" if row["id"] in superseded_observations else
                "not_yet_effective" if row["observed_at"] > current_time else "expired"
            )
        authoritative = [row for row in fresh_observations if row["authoritative"]]
        if not authoritative:
            technical = {"status": "unresolved", "reason": "authoritative_readback_missing_or_expired"}
        elif any(row["result"] == "contradictory" for row in authoritative):
            technical = {"status": "failed", "reason": "authoritative_readback_contradicts_intent"}
        elif any(row["result"] in {"missing", "unavailable"} for row in authoritative):
            technical = {"status": "unresolved", "reason": "authoritative_readback_incomplete"}
        elif all(row["result"] == "confirmed" for row in authoritative):
            technical = {"status": "verified", "reason": "authoritative_readback_confirmed"}
        else:
            technical = {"status": "unresolved", "reason": "authoritative_readback_mixed"}
        evidence_version = _digest({
            "acceptance_contract_ref": record["acceptance_contract_ref"],
            "observations": [{key: row.get(key) for key in (
                "source_id", "source_version", "result", "authoritative",
            )} for row in fresh_observations],
            "technical_outcome": technical,
        })
        decisions = copy.deepcopy(record.get("decisions", []))
        superseded_decisions = {
            str(row["supersedes_ref"])
            for row in decisions if row.get("supersedes_ref")
        }
        matching_decisions = [
            row for row in decisions
            if row["evidence_version"] == evidence_version
            and row["id"] not in superseded_decisions
        ]
        current_decision_id = matching_decisions[-1]["id"] if matching_decisions else None
        for row in decisions:
            row["current"] = row["id"] == current_decision_id
            row["current_reason"] = (
                "current" if row["current"] else
                "superseded" if row["id"] in superseded_decisions else
                "evidence_changed_or_expired"
            )
        current_decision = next((row for row in reversed(decisions) if row["current"]), None)
        business = {
            "status": current_decision["decision"] if current_decision else "unresolved",
            "actor": current_decision["actor"] if current_decision else None,
            "reason": "current_human_decision" if current_decision else "current_human_decision_missing",
        }
        if business["status"] == "accepted" and technical["status"] != "verified":
            business.update(status="unresolved", reason="authoritative_verification_no_longer_current")

        cost_events = copy.deepcopy(record.get("cost_events", []))
        current_costs, superseded_costs = _current(cost_events, now=current_time)
        current_cost_ids = {row["id"] for row in current_costs}
        for row in cost_events:
            # Old records predate explicit allocation/correction notes. Their
            # direct source binding remains the supported compatibility value.
            row.setdefault("allocation_method", "direct")
            row.setdefault("allocation_assumption", None)
            row.setdefault("correction_reason", None)
            row.setdefault("evidence_note", None)
            row.setdefault("coverage_declarations", None)
            row.setdefault("all_in_total", False)
            row["current"] = row["id"] in current_cost_ids
            row["current_reason"] = (
                "current" if row["current"] else
                "superseded" if row["id"] in superseded_costs else
                "not_yet_effective" if row["recorded_at"] > current_time else "expired"
            )
        totals: dict[str, Decimal] = {}
        for row in current_costs:
            if row["amount"] is not None and row.get("aggregation", "additive") == "additive":
                currency = row["currency"]
                totals[currency] = _decimal_sum((
                    totals.get(currency, Decimal(0)), Decimal(row["amount"]),
                ))
        unknown = [row for row in current_costs if row["amount"] is None]
        additive_costs = [
            row for row in current_costs
            if row.get("aggregation", "additive") == "additive"
        ]
        additive_unknown = [row for row in additive_costs if row["amount"] is None]
        unresolved_provider_or_attempt = _unresolved_provider_or_attempt_evidence(
            current_costs,
        )
        additive_ids = [
            row["id"] for row in additive_costs
        ]
        current_cost_scope = _digest(additive_ids)
        coverage_complete = any(
            row.get("coverage") == "complete"
            and row.get("aggregation", "additive") in {"additive", "coverage"}
            and row.get("coverage_scope_sha256") == current_cost_scope
            for row in current_costs
        )
        attempt_states_complete = all(
            row["attempt_state"] != "unknown" for row in additive_costs
        ) and all(
            row["attempt_state"] != "unknown"
            for row in unresolved_provider_or_attempt
        )
        rendered_totals: dict[str, str] = {}
        overflow_currencies: list[str] = []
        for code, value in sorted(totals.items()):
            try:
                rendered_totals[code] = _money(value)
            except ValueError:
                overflow_currencies.append(code)
        complete = (
            coverage_complete and not additive_unknown and attempt_states_complete
            and not unresolved_provider_or_attempt and not overflow_currencies
        )
        bases = {row["basis"] for row in additive_costs}
        if not complete:
            settlement = "incomplete"
        elif bases and bases == {"settled"}:
            settlement = "settled"
        elif "estimated" in bases:
            settlement = "estimated"
        else:
            settlement = "observed"
        summary = ", ".join(f"{code} {amount}" for code, amount in rendered_totals.items())
        display = (
            "Total incomplete; a stored aggregate exceeds the display bound."
            if overflow_currencies else
            f"At least {summary}; total incomplete." if not complete and summary else
            "Total incomplete; no priced cost recorded." if not complete else
            summary or "No cost events recorded."
        )
        failed_attempt_refs = {
            row.get("attempt_ref", row["source_ref"])
            for row in current_costs if row["attempt_state"] == "failed"
        }
        costs = {
            "complete": complete,
            "coverage_complete": coverage_complete,
            "attempt_states_complete": attempt_states_complete,
            "settlement_status": settlement,
            "known_totals": rendered_totals,
            "aggregate_overflow_currencies": overflow_currencies,
            "unknown_event_count": len(unknown),
            "additive_unknown_event_count": len(additive_unknown),
            "failed_attempt_count": len(failed_attempt_refs),
            "failed_attempt_event_count": sum(
                row["attempt_state"] == "failed" for row in current_costs
            ),
            "budget_overrun_count": sum(
                row.get("budget_state") == "limit_exceeded" for row in current_costs
            ),
            "informational_event_count": sum(
                row.get("aggregation", "additive") == "informational" for row in current_costs
            ),
            "coverage_event_count": sum(
                row.get("aggregation", "additive") == "coverage" for row in current_costs
            ),
            "additive_event_count": len(additive_costs),
            "event_count": len(current_costs),
            "display": display,
            "events": cost_events,
            "superseded_event_count": len(superseded_costs),
            "authenticated_provider_invoice_count": sum(
                row.get("source_assurance") == "authenticated_provider_invoice"
                for row in current_costs
            ),
            "local_signed_receipt_count": sum(
                row.get("source_assurance") == "local_signed_receipt"
                for row in current_costs
            ),
            "reconciled_reservation_count": sum(
                row.get("budget_reconciliation") is not None for row in current_costs
            ),
        }
        disposition = record.get("dispositions", [])[-1]["disposition"] if record.get("dispositions") else "active"
        result = {
            "id": record["id"],
            "revision": record["revision"],
            "admission_id": record["admission_id"],
            "work_item_id": record["work_item_id"],
            "owner_id": record["owner_id"],
            "acceptance_contract_ref": record["acceptance_contract_ref"],
            "admitted_at": record["admitted_at"],
            "disposition": disposition,
            "technical_outcome": technical,
            "business_outcome": business,
            "evidence_version": evidence_version,
            "observations": observations,
            "decisions": decisions,
            "dispositions": copy.deepcopy(record.get("dispositions", [])),
            "costs": costs,
        }
        if include_contract:
            result["platform_contract"] = self._platform_contract(
                record, result, fresh_observations, current_costs, current_time,
            )
        return result

    @staticmethod
    def _platform_contract(
        record: dict[str, Any],
        report: dict[str, Any],
        current_observations: list[dict[str, Any]],
        current_costs: list[dict[str, Any]],
        current_time: float,
    ) -> dict[str, Any]:
        """Project the domain ledger through the shared outcome contract."""
        business_status = report["business_outcome"]["status"]
        verdict = (
            "accepted" if business_status == "accepted" else
            "rejected" if business_status == "rejected" else "inconclusive"
        )
        evaluator = report["business_outcome"].get("actor")
        cost_totals = report["costs"]["known_totals"]
        exact_cost_sources = bool(current_costs) and all(
            row.get("aggregation", "additive") != "additive" or (
                row.get("basis") == "settled"
                and row.get("source_assurance") == "authenticated_provider_invoice"
                and row.get("evidence_ref")
                and row.get("evidence_sha256")
            )
            for row in current_costs
        )
        if (
            report["costs"]["complete"] and len(cost_totals) == 1
            and exact_cost_sources
        ):
            currency, amount = next(iter(cost_totals.items()))
            contract_cost = {"state": "exact", "currency": currency, "amount": amount}
        else:
            contract_cost = {
                "state": "unknown",
                "reason": (
                    "cost_incomplete_or_not_expressible_in_one_currency"
                    if not report["costs"]["complete"] or len(cost_totals) != 1 else
                    "cost_not_settled_by_authenticated_provider_invoice"
                ),
            }
        expiries = [
            row["valid_until"] for row in current_observations
            if row.get("valid_until") is not None
        ]
        if expiries:
            fresh_until: object = min(expiries)
        elif current_observations:
            fresh_until = {"state": "not_applicable", "reason": "no_expiry_recorded"}
        else:
            fresh_until = {"state": "unknown", "reason": "no_current_evidence"}
        human_attempts = {
            row.get("attempt_ref", row["source_ref"])
            for row in current_costs if row["category"] == "human"
        }
        return build_contract(
            "outcome-record",
            contract_id=record["id"],
            # The governed store's legacy local root is one explicit shared
            # workspace. Platform contracts require a stable nonempty identity,
            # so represent that supported boundary instead of serializing null.
            tenant_id=current_tenant_id_strict() or "shared",
            owner_id=record["owner_id"],
            purpose="governed outcome and cost accounting",
            created_at=record.get("created_at", record["admitted_at"]),
            updated_at=record.get("updated_at", current_time),
            revision=record["revision"],
            provenance={
                "state": "recorded",
                "ledger_schema": SCHEMA,
                "record_revision": record["revision"],
            },
            idempotency={"state": "bound", "key": record["id"]},
            cost=contract_cost,
            fresh_until=fresh_until,
            human_intervention={
                "state": "counted_cost_attempts",
                "count": len(human_attempts),
            },
            uncertainty={
                "state": "explicit",
                "technical": report["technical_outcome"]["status"],
                "business": business_status,
                "cost": report["costs"]["settlement_status"],
            },
            causal_status={"state": "observational", "basis": "recorded_events"},
            fields={
                "work_item_id": record["work_item_id"],
                "verdict": verdict,
                "evaluator_ref": (
                    {"state": "identified", "principal": evaluator}
                    if evaluator else {"state": "unknown", "reason": "no_current_human_decision"}
                ),
                "evidence_refs": [
                    {
                        "id": row["id"],
                        "source_id": row["source_id"],
                        "source_version": row["source_version"],
                    }
                    for row in current_observations
                ],
                "unintended_changes": [
                    {"state": "unknown", "reason": "not_recorded"},
                ],
                "human_interventions": len(human_attempts),
                "cost_refs": [
                    {
                        "id": row["id"],
                        "source_ref": row["source_ref"],
                        "source_version": row["source_version"],
                        "attempt_ref": row.get("attempt_ref", row["source_ref"]),
                        "source_assurance": row.get(
                            "source_assurance", "application_observation",
                        ),
                        "evidence_ref": row.get("evidence_ref"),
                        "evidence_sha256": row.get("evidence_sha256"),
                        "verification_authority": row.get("verification_authority"),
                        "budget_reconciliation": row.get("budget_reconciliation"),
                        "pricing_evidence": row.get("pricing_evidence"),
                    }
                    for row in current_costs
                ],
                "reason_codes": list(dict.fromkeys((
                    report["technical_outcome"]["reason"],
                    report["business_outcome"]["reason"],
                    f"disposition:{report['disposition']}",
                ))),
                "acceptance_contract_ref": {"ref": record["acceptance_contract_ref"]},
                "actor_ref": {"principal": evaluator or record["owner_id"]},
                "supersedes_ref": next((
                    {"id": row["supersedes_ref"], "kind": "outcome-decision"}
                    for row in reversed(report["decisions"])
                    if row["current"] and row.get("supersedes_ref")
                ), None),
            },
        )

    @staticmethod
    def _portfolio_summary(report: dict[str, Any]) -> dict[str, Any]:
        costs = {
            key: copy.deepcopy(value)
            for key, value in report["costs"].items()
            if key != "events"
        }
        return {
            key: copy.deepcopy(report[key])
            for key in (
                "id", "revision", "admission_id", "work_item_id", "owner_id",
                "acceptance_contract_ref", "admitted_at", "disposition",
                "technical_outcome", "business_outcome", "evidence_version",
            )
        } | {
            "observation_count": len(report["observations"]),
            "decision_count": len(report["decisions"]),
            "disposition_count": len(report["dispositions"]),
            "costs": costs,
        }

    def portfolio_report(
        self,
        *,
        now: float | None = None,
        owner_id: str | None = None,
        limit: int = 100,
        cursor: str = "",
    ) -> dict[str, Any]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_PAGE:
            raise ValueError(f"portfolio limit must be between 1 and {_MAX_PAGE}")
        start = "" if not cursor else _identifier(cursor, "cursor")
        owner = None if owner_id is None else _opaque(owner_id, "owner_id", 256)
        scan_size = min(_MAX_PAGE_SCAN, max(limit + 1, limit * 4))
        scanned = list(self.store.iter_record_ids(start_after=start, limit=scan_size + 1))
        forward: list[tuple[str, str]] = []
        wrapped = False
        for backend_cursor, record_id in scanned:
            if start and record_id <= start:
                wrapped = True
                break
            forward.append((backend_cursor, record_id))
        scan_has_more = len(forward) > scan_size or (
            not wrapped and len(scanned) == scan_size + 1
        )
        forward = forward[:scan_size]
        categories = dict.fromkeys(
            ("accepted", "cancelled", "failed", "rejected", "unresolved"), 0,
        )
        reports: list[dict[str, Any]] = []
        totals: dict[str, Decimal] = {}
        resume_cursor = start
        processed = 0
        has_more = scan_has_more
        for index, (backend_cursor, record_id) in enumerate(forward):
            record = self.store.get(record_id)
            processed += 1
            resume_cursor = backend_cursor
            if record is None:
                continue
            if record.get("schema") != SCHEMA:
                raise ValueError("outcome accounting portfolio contains an unsupported record")
            if owner is not None and record.get("owner_id") != owner:
                continue
            report = self._report_record(record, now=now, include_contract=False)
            reports.append(self._portfolio_summary(report))
            if report["disposition"] == "cancelled":
                category = "cancelled"
            elif report["disposition"] == "failed" or report["technical_outcome"]["status"] == "failed":
                category = "failed"
            elif report["business_outcome"]["status"] in {"accepted", "rejected"}:
                category = report["business_outcome"]["status"]
            else:
                category = "unresolved"
            categories[category] += 1
            for currency, amount in report["costs"]["known_totals"].items():
                totals[currency] = _decimal_sum((
                    totals.get(currency, Decimal(0)), Decimal(amount),
                ))
            if len(reports) == limit:
                has_more = index + 1 < len(forward) or scan_has_more
                break
        else:
            has_more = scan_has_more
        rendered_totals: dict[str, str] = {}
        overflow_currencies: list[str] = []
        for code, value in sorted(totals.items()):
            try:
                rendered_totals[code] = _money(value)
            except ValueError:
                overflow_currencies.append(code)
        return {
            "schema": "lightwork.outcome-accounting-portfolio.v1",
            "admitted": len(reports),
            "categories": categories,
            "reconciles": sum(categories.values()) == len(reports),
            "costs": {
                "known_totals": rendered_totals,
                "aggregate_overflow_currencies": overflow_currencies,
                "totals_complete": not overflow_currencies,
                "incomplete_records": (
                    sum(not report["costs"]["complete"] for report in reports)
                    + (1 if overflow_currencies else 0)
                ),
                "failed_attempts": sum(report["costs"]["failed_attempt_count"] for report in reports),
                "basis": (
                    "all admitted work in this scope; unknown cost is not zero"
                    if not start and not has_more else
                    "this bounded page of admitted work; unknown cost is not zero"
                ),
            },
            "records": reports,
            "page": {
                "limit": limit,
                "cursor": start or None,
                "next_cursor": resume_cursor if has_more else None,
                "has_more": has_more,
                "scope_complete": not start and not has_more,
                "scanned_records": processed,
            },
        }


def _reservation_authority(snapshot: object) -> ReservationAuthority:
    from . import provider_cost_cap

    return ReservationAuthority(
        reservation_ref=snapshot.reference,
        projected_amount=snapshot.projected,
        state=snapshot.state,
        actual_amount=snapshot.actual,
        currency=snapshot.currency,
        verification_authority=(
            "provider-cost-cap:" + provider_cost_cap.authority_identity()
        ),
    )


def _inspect_provider_reservation(
    reservation_ref: str,
    work_item_id: str,
) -> ReservationAuthority:
    from .provider_cost_cap import inspect_reservation

    return _reservation_authority(inspect_reservation(
        reservation_ref, expected_work_item_id=work_item_id,
    ))


def _claim_provider_reservation(
    authority: ReservationAuthority,
    work_item_id: str,
    claim_id: str,
) -> ReservationAuthority:
    from .provider_cost_cap import claim_reservation

    return _reservation_authority(claim_reservation(
        authority.reservation_ref,
        expected_work_item_id=work_item_id,
        claim_id=claim_id,
        expected_state=authority.state,
        expected_projected=float(authority.projected_amount),
        expected_actual=(
            None if authority.actual_amount is None else float(authority.actual_amount)
        ),
    ))


def _commit_provider_reservation(
    authority: ReservationAuthority,
    work_item_id: str,
    claim_id: str,
    event_id: str,
) -> ReservationAuthority:
    from .provider_cost_cap import commit_reservation_claim

    return _reservation_authority(commit_reservation_claim(
        authority.reservation_ref,
        expected_work_item_id=work_item_id,
        claim_id=claim_id,
        event_id=event_id,
        expected_state=authority.state,
        expected_projected=float(authority.projected_amount),
        expected_actual=(
            None if authority.actual_amount is None else float(authority.actual_amount)
        ),
    ))


default_service = OutcomeAccounting(
    reservation_resolver=_inspect_provider_reservation,
    reservation_claimer=_claim_provider_reservation,
    reservation_committer=_commit_provider_reservation,
)


__all__ = [
    "CostEvidenceAuthority", "OutcomeAccounting", "ReservationAuthority",
    "SCHEMA", "STORE", "default_service",
]
