"""Deterministic transaction anomaly screening and a governed review queue.

The finance domain packs describe duplicate-payment, Benford, approval-limit,
and off-hours review intent.  This module supplies the non-LLM execution core:
bounded normalized inputs, versioned rules, stable findings, and exact source
record provenance.  Findings are leads for a human investigator, never fraud
accusations, payment blocks, accounting entries, or audit opinions.

Detection is deliberately separate from persistence.  :func:`scan_transactions`
is a pure function over caller-supplied records.  :class:`FinanceAnomalyCaseQueue`
places selected findings into the shared governed-record CAS authority and
enforces an independent second human before a high-severity case can close.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import heapq
import json
import math
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, time, timezone
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from itertools import islice
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ..governed_records import GovernedRecordStore
from ..privacy_ops import RecordConflict

DUPLICATE_RULE_ID = "finance.duplicate_payment"
BENFORD_RULE_ID = "finance.benford_first_digit"
JUST_UNDER_RULE_ID = "finance.approval_limit.just_under"
SPLIT_PAYMENT_RULE_ID = "finance.approval_limit.split_payment"
OFF_HOURS_RULE_ID = "finance.off_hours_posting"
RULE_VERSION = "1.0.0"

FINDING_SCHEMA = "lightwork.finance-anomaly-finding.v1"
CASE_SCHEMA = "lightwork.finance-anomaly-case.v1"
CASE_PAGE_SCHEMA = "lightwork.finance-anomaly-case-page.v1"
SCREENING_NOTICE = (
    "Deterministic screening lead for human review; not evidence of fraud, an "
    "accounting conclusion, or an instruction to block or reverse a transaction."
)

_MAX_HARD_TRANSACTIONS = 10_000
_MAX_HARD_FINDINGS = 20_000
_MAX_APPROVAL_THRESHOLDS = 128
_MAX_THRESHOLD_COMPARISONS = 250_000
# At the hard input bounds: every row can be just-under every threshold;
# split findings consume at least two rows per threshold; duplicate groups
# consume at least two rows; off-hours consumes one; and each Benford currency
# finding consumes at least the 50-row minimum population.
_MAX_CANDIDATE_FINDINGS = (
    _MAX_HARD_TRANSACTIONS * _MAX_APPROVAL_THRESHOLDS
    + (_MAX_HARD_TRANSACTIONS // 2) * _MAX_APPROVAL_THRESHOLDS
    + _MAX_HARD_TRANSACTIONS
    + _MAX_HARD_TRANSACTIONS // 2
    + _MAX_HARD_TRANSACTIONS // 50
)
_MAX_CASE_LIST = 5_000
_MAX_CASE_PAGE_SCAN = 25
_MAX_CASE_SUMMARY_SCAN = 5_000
_MAX_FINDING_JSON_BYTES = 4 * 1024 * 1024
_MAX_REPORT_JSON_BYTES = 16 * 1024 * 1024
_MAX_DISPOSITIONS = 32
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_CURRENCY_RE = re.compile(r"[A-Z]{3}\Z")
_DIGEST_RE = re.compile(r"(?:sha256:)?([0-9a-fA-F]{64})\Z")
_THRESHOLD_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_CASE_STATUSES = frozenset({"open", "in_review", "dispositioned", "closed"})
_DISPOSITIONS = frozenset(
    {"confirmed", "false_positive", "accepted_risk", "needs_information", "escalated"}
)
_FINAL_DISPOSITIONS = frozenset({"confirmed", "false_positive", "accepted_risk"})
_RULE_IDS = frozenset(
    {
        DUPLICATE_RULE_ID,
        BENFORD_RULE_ID,
        JUST_UNDER_RULE_ID,
        SPLIT_PAYMENT_RULE_ID,
        OFF_HOURS_RULE_ID,
    }
)


def enabled() -> bool:
    """Return the tenant-effective anomaly scan gate under global authority."""
    try:
        from ..config import config_source_errors, load_config
        from .aml_screening import enabled as operations_enabled

        if not operations_enabled() or config_source_errors(include_tenant=True):
            return False
        section = (load_config() or {}).get("finance_operations")
        if not isinstance(section, Mapping):
            return False
        value = section.get("anomaly_enable", True)
        return isinstance(value, bool) and value is True
    except Exception:  # pragma: no cover - configuration reads fail closed
        return False

# Fixed decimal constants avoid platform-dependent probability generation.
_BENFORD_EXPECTED = {
    1: Decimal("0.301030"),
    2: Decimal("0.176091"),
    3: Decimal("0.124939"),
    4: Decimal("0.096910"),
    5: Decimal("0.079181"),
    6: Decimal("0.066947"),
    7: Decimal("0.057992"),
    8: Decimal("0.051153"),
    9: Decimal("0.045757"),
}


class FinanceAnomalyError(RuntimeError):
    """Base failure for deterministic finance anomaly processing."""


class FinanceAnomalyInputLimit(FinanceAnomalyError):
    """The caller supplied more records than the declared scan bound."""


class FinanceAnomalyStateError(FinanceAnomalyError):
    """A persisted finance anomaly case is malformed or contradictory."""


class FourEyesRequired(FinanceAnomalyError):
    """An independent human is required to close a high-severity case."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: object, label: str, limit: int, *, required: bool = True) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    result = value.strip()
    if required and not result:
        raise ValueError(f"{label} is required")
    if len(result) > limit:
        raise ValueError(f"{label} exceeds {limit} characters")
    if _CONTROL_RE.search(result):
        raise ValueError(f"{label} contains control characters")
    return result


def _decimal(value: object, label: str) -> Decimal:
    if isinstance(value, bool) or value is None:
        raise ValueError(f"{label} must be a finite decimal amount")
    try:
        result = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{label} must be a finite decimal amount") from exc
    if not result.is_finite():
        raise ValueError(f"{label} must be a finite decimal amount")
    if result == 0:
        return Decimal(0)
    if result.copy_abs() > Decimal("1000000000000000"):
        raise ValueError(f"{label} exceeds the supported finance amount bound")
    exponent = result.as_tuple().exponent
    if exponent < -8:
        raise ValueError(f"{label} exceeds 8 fractional digits")
    return result


def _materiality_amount(value: object) -> Decimal | None:
    if value is None:
        return None
    amount = _decimal(value, "materiality")
    if amount <= 0:
        raise ValueError("materiality must be positive")
    return amount


def _amount_text(value: Decimal) -> str:
    if value == 0:
        return "0"
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered


def _timestamp(value: object, label: str = "posted_at") -> datetime:
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    elif isinstance(value, datetime):
        parsed = value
    else:
        raise ValueError(f"{label} must be a timezone-aware timestamp")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone offset")
    return parsed.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _digest(value: object, label: str, *, required: bool = False) -> str:
    if value in (None, "") and not required:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a SHA-256 digest")
    match = _DIGEST_RE.fullmatch(value.strip())
    if match is None:
        raise ValueError(f"{label} must be a SHA-256 digest")
    return match.group(1).lower()


def _normal_key(value: str) -> str:
    return " ".join(value.casefold().split())


@dataclass(frozen=True)
class FinanceTransaction:
    """Normalized transaction fields consumed by deterministic rules.

    ``source_system`` plus ``source_record_id`` are mandatory provenance.  A
    source-provided SHA-256 can additionally bind the upstream record; every
    finding also contains a digest of this exact normalized snapshot.
    """

    transaction_id: str
    amount: Decimal
    currency: str
    posted_at: datetime
    source_system: str
    source_record_id: str
    counterparty_id: str = ""
    counterparty_name: str = ""
    invoice_id: str = ""
    reference: str = ""
    source_uri: str = ""
    source_sha256: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "transaction_id", _text(self.transaction_id, "transaction_id", 200)
        )
        object.__setattr__(self, "amount", _decimal(self.amount, "amount"))
        currency = _text(self.currency, "currency", 3).upper()
        if _CURRENCY_RE.fullmatch(currency) is None:
            raise ValueError("currency must be a three-letter code")
        object.__setattr__(self, "currency", currency)
        object.__setattr__(self, "posted_at", _timestamp(self.posted_at))
        for name, limit, required in (
            ("source_system", 128, True),
            ("source_record_id", 256, True),
            ("counterparty_id", 256, False),
            ("counterparty_name", 512, False),
            ("invoice_id", 256, False),
            ("reference", 512, False),
            ("source_uri", 2048, False),
        ):
            object.__setattr__(
                self,
                name,
                _text(getattr(self, name), name, limit, required=required),
            )
        object.__setattr__(
            self,
            "source_sha256",
            _digest(self.source_sha256, "source_sha256"),
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> FinanceTransaction:
        if not isinstance(value, Mapping):
            raise TypeError("transaction must be a FinanceTransaction or mapping")
        provenance = value.get("provenance") or {}
        if not isinstance(provenance, Mapping):
            raise ValueError("transaction provenance must be an object")

        def _field(name: str, *aliases: str, default: object = "") -> object:
            for key in (name, *aliases):
                if key in value:
                    return value[key]
                if key in provenance:
                    return provenance[key]
            return default

        return cls(
            transaction_id=_field("transaction_id", "id"),
            amount=_field("amount"),
            currency=_field("currency"),
            posted_at=_field("posted_at", "timestamp"),
            source_system=_field("source_system"),
            source_record_id=_field("source_record_id"),
            counterparty_id=_field("counterparty_id", "vendor_id", "payee_id"),
            counterparty_name=_field("counterparty_name", "vendor_name", "payee_name"),
            invoice_id=_field("invoice_id", "invoice_number"),
            reference=_field("reference", "payment_reference"),
            source_uri=_field("source_uri"),
            source_sha256=_field("source_sha256"),
        )

    @property
    def counterparty_key(self) -> str:
        if self.counterparty_id:
            return f"id:{_normal_key(self.counterparty_id)}"
        if self.counterparty_name:
            return f"name:{_normal_key(self.counterparty_name)}"
        return ""

    def evidence(self) -> dict[str, Any]:
        body = {
            "transaction_id": self.transaction_id,
            "amount": _amount_text(self.amount),
            "currency": self.currency,
            "posted_at": _iso(self.posted_at),
            "counterparty_id": self.counterparty_id,
            "counterparty_name": self.counterparty_name,
            "invoice_id": self.invoice_id,
            "reference": self.reference,
            "provenance": {
                "source_system": self.source_system,
                "source_record_id": self.source_record_id,
                "source_uri": self.source_uri,
                "source_sha256": self.source_sha256,
            },
        }
        return {**body, "normalized_record_sha256": _sha256(body)}


@dataclass(frozen=True)
class ApprovalThreshold:
    """One cited approval limit used by the just-under and split rules."""

    threshold_id: str
    currency: str
    amount: Decimal
    policy_ref: str

    def __post_init__(self) -> None:
        threshold_id = _text(self.threshold_id, "threshold_id", 128)
        if _THRESHOLD_ID_RE.fullmatch(threshold_id) is None:
            raise ValueError("threshold_id contains unsupported characters")
        object.__setattr__(self, "threshold_id", threshold_id)
        currency = _text(self.currency, "threshold currency", 3).upper()
        if _CURRENCY_RE.fullmatch(currency) is None:
            raise ValueError("threshold currency must be a three-letter code")
        object.__setattr__(self, "currency", currency)
        amount = _decimal(self.amount, "threshold amount")
        if amount <= 0:
            raise ValueError("threshold amount must be positive")
        object.__setattr__(self, "amount", amount)
        object.__setattr__(self, "policy_ref", _text(self.policy_ref, "policy_ref", 1024))


@dataclass(frozen=True)
class FinanceAnomalyConfig:
    """Explicit, bounded rule configuration for one deterministic scan."""

    max_transactions: int = 5_000
    max_findings: int = 5_000
    duplicate_window_hours: int = 72
    benford_population_eligible: bool = False
    benford_min_sample: int = 100
    benford_min_orders: int = 3
    benford_mad_threshold: Decimal = Decimal("0.015")
    approval_thresholds: tuple[ApprovalThreshold, ...] = field(default_factory=tuple)
    threshold_near_fraction: Decimal = Decimal("0.95")
    threshold_split_min_fraction: Decimal = Decimal("0.20")
    threshold_window_hours: int = 24
    business_timezone: str = "UTC"
    business_start: time = time(8, 0)
    business_end: time = time(18, 0)
    business_days: tuple[int, ...] = (0, 1, 2, 3, 4)
    #: ``[finance] materiality`` (see :func:`with_configured_materiality`): a
    #: transaction-level finding whose transactions total at least this amount
    #: is raised to high severity, so closing it needs a second, independent
    #: person. ``None`` leaves every rule's severity unchanged.
    materiality: Decimal | None = None

    def __post_init__(self) -> None:
        for name, value, hard_max in (
            ("max_transactions", self.max_transactions, _MAX_HARD_TRANSACTIONS),
            ("max_findings", self.max_findings, _MAX_HARD_FINDINGS),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= hard_max:
                raise ValueError(f"{name} must be between 1 and {hard_max}")
        if (
            isinstance(self.duplicate_window_hours, bool)
            or not isinstance(self.duplicate_window_hours, int)
            or not 1 <= self.duplicate_window_hours <= 24 * 31
        ):
            raise ValueError("duplicate_window_hours must be between 1 and 744")
        if not isinstance(self.benford_population_eligible, bool):
            raise ValueError("benford_population_eligible must be boolean")
        if (
            isinstance(self.benford_min_sample, bool)
            or not isinstance(self.benford_min_sample, int)
            or not 50 <= self.benford_min_sample <= _MAX_HARD_TRANSACTIONS
        ):
            raise ValueError("benford_min_sample must be between 50 and 10000")
        if (
            isinstance(self.benford_min_orders, bool)
            or not isinstance(self.benford_min_orders, int)
            or not 2 <= self.benford_min_orders <= 10
        ):
            raise ValueError("benford_min_orders must be between 2 and 10")
        mad = _decimal(self.benford_mad_threshold, "benford_mad_threshold")
        if not Decimal("0.001") <= mad <= Decimal("0.100"):
            raise ValueError("benford_mad_threshold must be between 0.001 and 0.100")
        object.__setattr__(self, "benford_mad_threshold", mad)
        thresholds = tuple(self.approval_thresholds)
        if any(not isinstance(item, ApprovalThreshold) for item in thresholds):
            raise ValueError("approval_thresholds must contain ApprovalThreshold values")
        if len(thresholds) > _MAX_APPROVAL_THRESHOLDS:
            raise ValueError(
                f"approval_thresholds exceeds {_MAX_APPROVAL_THRESHOLDS} entries"
            )
        identities = [(item.threshold_id, item.currency) for item in thresholds]
        if len(set(identities)) != len(identities):
            raise ValueError("approval threshold ids must be unique per currency")
        object.__setattr__(
            self,
            "approval_thresholds",
            tuple(sorted(thresholds, key=lambda item: (item.currency, item.amount, item.threshold_id))),
        )
        for name in ("threshold_near_fraction", "threshold_split_min_fraction"):
            fraction = _decimal(getattr(self, name), name)
            if not Decimal("0.01") <= fraction < Decimal(1):
                raise ValueError(f"{name} must be at least 0.01 and less than 1")
            object.__setattr__(self, name, fraction)
        if self.threshold_split_min_fraction > self.threshold_near_fraction:
            raise ValueError("threshold_split_min_fraction cannot exceed threshold_near_fraction")
        if (
            isinstance(self.threshold_window_hours, bool)
            or not isinstance(self.threshold_window_hours, int)
            or not 1 <= self.threshold_window_hours <= 24 * 31
        ):
            raise ValueError("threshold_window_hours must be between 1 and 744")
        timezone_name = _text(self.business_timezone, "business_timezone", 128)
        try:
            ZoneInfo(timezone_name)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("business_timezone is not an installed IANA timezone") from exc
        object.__setattr__(self, "business_timezone", timezone_name)
        if not isinstance(self.business_start, time) or not isinstance(self.business_end, time):
            raise ValueError("business_start and business_end must be time values")
        if self.business_start.tzinfo is not None or self.business_end.tzinfo is not None:
            raise ValueError("business hours must be naive local wall-clock values")
        if self.business_start >= self.business_end:
            raise ValueError("business_start must be before business_end")
        days = tuple(self.business_days)
        if not days or len(set(days)) != len(days) or any(
            isinstance(day, bool) or not isinstance(day, int) or not 0 <= day <= 6
            for day in days
        ):
            raise ValueError("business_days must contain unique weekday integers 0 through 6")
        object.__setattr__(self, "business_days", tuple(sorted(days)))
        object.__setattr__(self, "materiality", _materiality_amount(self.materiality))

    def to_dict(self) -> dict[str, Any]:
        """Canonical rule configuration bound into every scan report."""
        value = {
            "max_transactions": self.max_transactions,
            "max_findings": self.max_findings,
            "duplicate_window_hours": self.duplicate_window_hours,
            "benford_population_eligible": self.benford_population_eligible,
            "benford_min_sample": self.benford_min_sample,
            "benford_min_orders": self.benford_min_orders,
            "benford_mad_threshold": _amount_text(self.benford_mad_threshold),
            "approval_thresholds": [
                {
                    "threshold_id": row.threshold_id,
                    "currency": row.currency,
                    "amount": _amount_text(row.amount),
                    "policy_ref": row.policy_ref,
                }
                for row in self.approval_thresholds
            ],
            "threshold_near_fraction": _amount_text(self.threshold_near_fraction),
            "threshold_split_min_fraction": _amount_text(
                self.threshold_split_min_fraction
            ),
            "threshold_window_hours": self.threshold_window_hours,
            "business_timezone": self.business_timezone,
            "business_start": self.business_start.isoformat(),
            "business_end": self.business_end.isoformat(),
            "business_days": list(self.business_days),
        }
        if self.materiality is not None:
            # Only when set, so an unset materiality keeps every existing
            # configuration digest unchanged.
            value["materiality"] = _amount_text(self.materiality)
        return value


def with_configured_materiality(config: FinanceAnomalyConfig) -> FinanceAnomalyConfig:
    """Apply ``[finance] materiality`` to a scan configuration.

    The configured amount is the organisation's review threshold; a caller
    may only tighten it (the lower of the two applies). Unset, or with the
    finance layer off, the configuration is returned unchanged. The result is
    bound into the report's configuration digest, so a scan stays
    reproducible against the threshold it ran under.
    """
    from dataclasses import replace

    from .profile import configured_materiality

    configured = configured_materiality()
    if configured is None:
        return config
    if config.materiality is not None and config.materiality <= configured:
        return config
    return replace(config, materiality=configured)


@dataclass(frozen=True)
class FinanceAnomalyFinding:
    """Stable, versioned, provenance-bearing deterministic screening lead."""

    finding_id: str
    rule_id: str
    rule_version: str
    severity: str
    score: int
    explanation: str
    evidence: tuple[dict[str, Any], ...]
    metrics: dict[str, Any]
    caveats: tuple[str, ...]
    schema: str = FINDING_SCHEMA
    notice: str = SCREENING_NOTICE

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "severity": self.severity,
            "score": self.score,
            "explanation": self.explanation,
            "evidence": [dict(item) for item in self.evidence],
            "metrics": dict(self.metrics),
            "caveats": list(self.caveats),
            "notice": self.notice,
        }


@dataclass(frozen=True)
class RuleEvaluation:
    rule_id: str
    rule_version: str
    status: str
    sample_size: int
    finding_count: int
    explanation: str
    caveats: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "status": self.status,
            "sample_size": self.sample_size,
            "finding_count": self.finding_count,
            "explanation": self.explanation,
            "caveats": list(self.caveats),
        }


@dataclass(frozen=True)
class FinanceAnomalyReport:
    transactions_scanned: int
    input_sha256: str
    config_sha256: str
    scan_sha256: str
    config: dict[str, Any]
    findings: tuple[FinanceAnomalyFinding, ...]
    evaluations: tuple[RuleEvaluation, ...]
    truncated: bool
    omitted_findings: int
    notice: str = SCREENING_NOTICE

    def to_dict(self) -> dict[str, Any]:
        return {
            "transactions_scanned": self.transactions_scanned,
            "input_sha256": self.input_sha256,
            "config_sha256": self.config_sha256,
            "scan_sha256": self.scan_sha256,
            "config": dict(self.config),
            "findings": [item.to_dict() for item in self.findings],
            "evaluations": [item.to_dict() for item in self.evaluations],
            "truncated": self.truncated,
            "omitted_findings": self.omitted_findings,
            "notice": self.notice,
        }


@dataclass(frozen=True)
class FinanceAnomalyCasePage:
    """One bounded lexical page from the governed anomaly case authority."""

    cases: tuple[dict[str, Any], ...]
    next_cursor: str
    has_more: bool
    scanned_records: int
    schema: str = CASE_PAGE_SCHEMA

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "cases": [dict(item) for item in self.cases],
            "next_cursor": self.next_cursor,
            "has_more": self.has_more,
            "scanned_records": self.scanned_records,
            "order": "case_id_ascending",
        }


@dataclass(frozen=True)
class _FindingSeed:
    """A retained finding candidate whose evidence is already normalized.

    The scan can evaluate more than a million threshold candidates at the hard
    input bounds.  Keeping only these small seeds until the final top-K is known
    prevents the discarded candidates from materializing full finding objects.
    """

    finding_id: str
    rule_id: str
    severity: str
    score: int
    explanation: str
    evidence: tuple[dict[str, Any], ...]
    metrics: dict[str, Any]
    caveats: tuple[str, ...]

    @property
    def order_key(self) -> tuple[int, int, str, str]:
        return (
            -_SEVERITY_ORDER[self.severity],
            -self.score,
            self.rule_id,
            self.finding_id,
        )

    def materialize(self) -> FinanceAnomalyFinding:
        finding = FinanceAnomalyFinding(
            finding_id=self.finding_id,
            rule_id=self.rule_id,
            rule_version=RULE_VERSION,
            severity=self.severity,
            score=self.score,
            explanation=self.explanation,
            evidence=self.evidence,
            metrics=self.metrics,
            caveats=self.caveats,
        )
        if len(_canonical(finding.to_dict())) > _MAX_FINDING_JSON_BYTES:
            raise FinanceAnomalyInputLimit(
                "one finding exceeds the 4 MiB evidence bound; reduce or batch "
                "the transaction population"
            )
        return finding


class _WorstSeedFirst:
    """Heap wrapper that keeps the worst retained ordering key at the root."""

    __slots__ = ("seed",)

    def __init__(self, seed: _FindingSeed) -> None:
        self.seed = seed

    def __lt__(self, other: _WorstSeedFirst) -> bool:
        return self.seed.order_key > other.seed.order_key


class _FindingAccumulator:
    """Count every candidate while retaining only the deterministic top-K."""

    def __init__(
        self,
        transactions: tuple[FinanceTransaction, ...],
        *,
        limit: int,
        materiality: Decimal | None = None,
    ) -> None:
        self._limit = limit
        self._materiality = materiality
        self._evidence = {
            transaction.transaction_id: transaction.evidence()
            for transaction in transactions
        }
        self._heap: list[_WorstSeedFirst] = []
        self.candidate_count = 0

    @property
    def input_sha256(self) -> str:
        return _sha256(
            sorted(
                item["normalized_record_sha256"]
                for item in self._evidence.values()
            )
        )

    def add(
        self,
        rule_id: str,
        *,
        severity: str,
        score: int,
        explanation: str,
        transactions: Iterable[FinanceTransaction],
        metrics: Mapping[str, Any],
        caveats: Iterable[str] = (),
    ) -> None:
        if self.candidate_count >= _MAX_CANDIDATE_FINDINGS:
            raise FinanceAnomalyInputLimit(
                "scan exceeds the deterministic finance anomaly candidate budget"
            )
        if severity not in _SEVERITY_ORDER:
            raise ValueError("finding severity is invalid")
        if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
            raise ValueError("finding score must be an integer between 0 and 100")
        transactions = tuple(transactions)
        severity, metrics, caveats = self._apply_materiality(
            rule_id, severity, transactions, metrics, caveats,
        )
        self.candidate_count += 1
        order_prefix = (-_SEVERITY_ORDER[severity], -score, rule_id)
        if (
            len(self._heap) >= self._limit
            and order_prefix > self._heap[0].seed.order_key[:3]
        ):
            # The candidate is unambiguously below the retained top-K before
            # its evidence tuple or stable identity needs to be materialized.
            return
        evidence = tuple(
            sorted(
                (self._evidence[transaction.transaction_id] for transaction in transactions),
                key=lambda item: (
                    item["transaction_id"],
                    item["normalized_record_sha256"],
                ),
            )
        )
        if not evidence:
            raise ValueError("a finance anomaly finding requires transaction evidence")
        metric_values = dict(metrics)
        identity = {
            "rule_id": rule_id,
            "rule_version": RULE_VERSION,
            "evidence_sha256": [item["normalized_record_sha256"] for item in evidence],
            "metrics": metric_values,
        }
        seed = _FindingSeed(
            finding_id=f"FAF-{_sha256(identity)[:32]}",
            rule_id=rule_id,
            severity=severity,
            score=score,
            explanation=explanation,
            evidence=evidence,
            metrics=metric_values,
            caveats=tuple(caveats),
        )
        entry = _WorstSeedFirst(seed)
        if len(self._heap) < self._limit:
            heapq.heappush(self._heap, entry)
        elif seed.order_key < self._heap[0].seed.order_key:
            heapq.heapreplace(self._heap, entry)

    def _apply_materiality(
        self,
        rule_id: str,
        severity: str,
        transactions: tuple[FinanceTransaction, ...],
        metrics: Mapping[str, Any],
        caveats: Iterable[str],
    ) -> tuple[str, Mapping[str, Any], Iterable[str]]:
        """Raise a transaction-level finding at or above materiality to high.

        Benford is a population screen with no single exposure, so it is
        unchanged. Exposure is the total of the finding's transactions in their
        own currency (populations are expected in the reporting currency).
        """
        if self._materiality is None or rule_id == BENFORD_RULE_ID:
            return severity, metrics, caveats
        exposure = sum((abs(item.amount) for item in transactions), Decimal(0))
        if exposure < self._materiality:
            return severity, metrics, caveats
        if _SEVERITY_ORDER[severity] < _SEVERITY_ORDER["high"]:
            severity = "high"
        return severity, {
            **metrics,
            "materiality": _amount_text(self._materiality),
            "materiality_exposure": _amount_text(exposure),
        }, (*caveats, "At or above the configured materiality, so closing it needs "
                      "a second, independent reviewer.")

    def findings(self) -> tuple[FinanceAnomalyFinding, ...]:
        return tuple(
            seed.materialize()
            for seed in sorted(
                (entry.seed for entry in self._heap),
                key=lambda item: item.order_key,
            )
        )


def _duplicate_findings(
    transactions: tuple[FinanceTransaction, ...],
    config: FinanceAnomalyConfig,
    accumulator: _FindingAccumulator,
) -> RuleEvaluation:
    referenced: dict[tuple[str, str, str, str], list[FinanceTransaction]] = defaultdict(list)
    unreferenced: dict[tuple[str, str, str], list[FinanceTransaction]] = defaultdict(list)
    eligible = 0
    for transaction in transactions:
        counterparty = transaction.counterparty_key
        if not counterparty:
            continue
        eligible += 1
        base = (transaction.currency, _amount_text(transaction.amount), counterparty)
        identity = transaction.invoice_id or transaction.reference
        if identity:
            kind = "invoice" if transaction.invoice_id else "reference"
            referenced[(*base, f"{kind}:{_normal_key(identity)}")].append(transaction)
        else:
            unreferenced[base].append(transaction)

    finding_count = 0
    for key in sorted(referenced):
        group = referenced[key]
        if len(group) < 2:
            continue
        accumulator.add(
            DUPLICATE_RULE_ID,
            severity="high",
            score=97,
            explanation=(
                f"{len(group)} distinct transaction ids share the same normalized "
                "counterparty, amount, currency, and invoice/reference identity."
            ),
            transactions=group,
            metrics={
                "match_basis": "counterparty_amount_currency_invoice_or_reference",
                "match_signature_sha256": _sha256(key),
                "transaction_count": len(group),
            },
            caveats=("A repeated source record can be legitimate; verify remittance state.",),
        )
        finding_count += 1

    window_seconds = config.duplicate_window_hours * 60 * 60
    for key in sorted(unreferenced):
        rows = sorted(unreferenced[key], key=lambda item: (item.posted_at, item.transaction_id))
        start = 0
        while start < len(rows):
            end = start + 1
            while (
                end < len(rows)
                and (rows[end].posted_at - rows[start].posted_at).total_seconds()
                <= window_seconds
            ):
                end += 1
            group = rows[start:end]
            if len(group) >= 2:
                accumulator.add(
                    DUPLICATE_RULE_ID,
                    severity="medium",
                    score=76,
                    explanation=(
                        f"{len(group)} transactions share counterparty, exact amount, and "
                        f"currency within {config.duplicate_window_hours} hours but lack a "
                        "common invoice/reference identity."
                    ),
                    transactions=group,
                    metrics={
                        "match_basis": "counterparty_amount_currency_time_window",
                        "match_signature_sha256": _sha256(key),
                        "transaction_count": len(group),
                        "window_hours": config.duplicate_window_hours,
                    },
                    caveats=(
                        "This lower-confidence match can reflect valid recurring payments.",
                    ),
                )
                finding_count += 1
                start = end
            else:
                start += 1
    return RuleEvaluation(
        DUPLICATE_RULE_ID,
        RULE_VERSION,
        "finding" if finding_count else "clear",
        eligible,
        finding_count,
        "Compared normalized counterparty, amount, currency, and payment identity.",
        ("Transactions without a counterparty were not eligible for duplicate matching.",),
    )


def _first_digit(value: Decimal) -> int:
    for digit in value.copy_abs().as_tuple().digits:
        if digit:
            return digit
    raise ValueError("zero has no first significant digit")


def _benford_currency_screen(
    currency: str,
    transactions: tuple[FinanceTransaction, ...],
    config: FinanceAnomalyConfig,
    caveats: tuple[str, ...],
    accumulator: _FindingAccumulator,
) -> tuple[bool, str, str]:
    if len(transactions) < config.benford_min_sample:
        return (
            False,
            "insufficient_sample",
            f"{currency} has {len(transactions)} eligible amounts, below the configured "
            f"minimum of {config.benford_min_sample}.",
        )
    orders = {transaction.amount.copy_abs().adjusted() for transaction in transactions}
    if len(orders) < config.benford_min_orders:
        return (
            False,
            "ineligible",
            f"{currency} spans {len(orders)} decimal order(s); the configured minimum is "
            f"{config.benford_min_orders}.",
        )
    counts = dict.fromkeys(range(1, 10), 0)
    for transaction in transactions:
        digit = _first_digit(transaction.amount)
        counts[digit] += 1
    sample = Decimal(len(transactions))
    deviations = [
        abs(Decimal(counts[digit]) / sample - _BENFORD_EXPECTED[digit]) for digit in counts
    ]
    mad = (sum(deviations, Decimal(0)) / Decimal(9)).quantize(
        Decimal("0.000001"), rounding=ROUND_HALF_UP
    )
    if mad < config.benford_mad_threshold:
        return (
            False,
            "clear",
            f"{currency} first-digit MAD {_amount_text(mad)} is below the configured threshold.",
        )
    metrics = {
        "currency": currency,
        "sample_size": len(transactions),
        "decimal_orders": sorted(orders),
        "digit_counts": {str(digit): counts[digit] for digit in counts},
        "expected_proportions": {
            str(digit): _amount_text(_BENFORD_EXPECTED[digit]) for digit in counts
        },
        "mean_absolute_deviation": _amount_text(mad),
        "configured_mad_threshold": _amount_text(config.benford_mad_threshold),
        "population_eligibility_attested": True,
    }
    excess_thousandths = max(
        0,
        int((mad - config.benford_mad_threshold) * Decimal(1000)),
    )
    severity = "high" if mad >= Decimal("0.025") else "medium"
    accumulator.add(
        BENFORD_RULE_ID,
        severity=severity,
        score=min(99, 70 + excess_thousandths),
        explanation=(
            f"Eligible {currency} first-digit population MAD {_amount_text(mad)} meets or "
            f"exceeds the configured {_amount_text(config.benford_mad_threshold)} review "
            "threshold."
        ),
        transactions=transactions,
        metrics=metrics,
        caveats=caveats,
    )
    return True, "finding", f"{currency} deviated from the configured first-digit screen."


def _benford_findings(
    transactions: tuple[FinanceTransaction, ...],
    config: FinanceAnomalyConfig,
    accumulator: _FindingAccumulator,
) -> RuleEvaluation:
    caveats = (
        "Benford is a population screen, not transaction-level proof of fraud.",
        "It is appropriate only for naturally occurring amounts spanning several orders of "
        "magnitude, not assigned numbers, fixed-price, minimum/maximum, or threshold-shaped data.",
        "Zero and non-positive amounts are excluded from this first-digit population.",
        "Each currency is evaluated as a separate population; amounts are never mixed or "
        "silently converted.",
    )
    eligible = tuple(transaction for transaction in transactions if transaction.amount > 0)
    if not config.benford_population_eligible:
        return RuleEvaluation(
            BENFORD_RULE_ID,
            RULE_VERSION,
            "ineligible",
            len(eligible),
            0,
            "Benford did not run because the caller did not attest population eligibility.",
            caveats,
        )
    populations: dict[str, list[FinanceTransaction]] = defaultdict(list)
    for transaction in eligible:
        populations[transaction.currency].append(transaction)
    finding_count = 0
    outcomes: list[tuple[str, str]] = []
    for currency in sorted(populations):
        population = tuple(populations[currency])
        found, status, explanation = _benford_currency_screen(
            currency, population, config, caveats, accumulator
        )
        outcomes.append((status, explanation))
        finding_count += int(found)
    statuses = {status for status, _ in outcomes}
    if finding_count:
        status = "finding"
    elif "clear" in statuses:
        status = "clear"
    elif "ineligible" in statuses:
        status = "ineligible"
    else:
        status = "insufficient_sample"
    if len(outcomes) == 1:
        explanation = outcomes[0][1]
    else:
        counts = {name: sum(1 for item, _ in outcomes if item == name) for name in statuses}
        explanation = (
            f"Evaluated {len(outcomes)} currency population(s): "
            + ", ".join(f"{counts[name]} {name}" for name in sorted(counts))
            + "."
        )
    return RuleEvaluation(
        BENFORD_RULE_ID,
        RULE_VERSION,
        status,
        len(eligible),
        finding_count,
        explanation,
        caveats,
    )


def _just_under_findings(
    transactions: tuple[FinanceTransaction, ...],
    config: FinanceAnomalyConfig,
    accumulator: _FindingAccumulator,
) -> RuleEvaluation:
    if not config.approval_thresholds:
        return RuleEvaluation(
            JUST_UNDER_RULE_ID,
            RULE_VERSION,
            "disabled",
            0,
            0,
            "No cited approval thresholds were configured.",
        )
    finding_count = 0
    sample = 0
    for threshold in config.approval_thresholds:
        floor = threshold.amount * config.threshold_near_fraction
        rows = [
            transaction
            for transaction in transactions
            if transaction.currency == threshold.currency and transaction.amount > 0
        ]
        sample += len(rows)
        for transaction in rows:
            if not floor <= transaction.amount < threshold.amount:
                continue
            proximity = transaction.amount / threshold.amount
            score = min(
                94,
                70
                + int(
                    (proximity - config.threshold_near_fraction)
                    / (Decimal(1) - config.threshold_near_fraction)
                    * Decimal(24)
                ),
            )
            accumulator.add(
                JUST_UNDER_RULE_ID,
                severity="medium",
                score=score,
                explanation=(
                    f"Transaction amount {_amount_text(transaction.amount)} "
                    f"{transaction.currency} is immediately below approval limit "
                    f"{threshold.threshold_id} ({_amount_text(threshold.amount)})."
                ),
                transactions=(transaction,),
                metrics={
                    "threshold_id": threshold.threshold_id,
                    "threshold_amount": _amount_text(threshold.amount),
                    "currency": threshold.currency,
                    "policy_ref": threshold.policy_ref,
                    "near_fraction": _amount_text(config.threshold_near_fraction),
                    "proximity": _amount_text(proximity.quantize(Decimal("0.000001"))),
                },
                caveats=(
                    "A payment near an approval limit can be legitimate; review business purpose.",
                ),
            )
            finding_count += 1
    return RuleEvaluation(
        JUST_UNDER_RULE_ID,
        RULE_VERSION,
        "finding" if finding_count else "clear",
        sample,
        finding_count,
        "Compared positive transaction amounts with each cited approval limit.",
    )


def _split_payment_findings(
    transactions: tuple[FinanceTransaction, ...],
    config: FinanceAnomalyConfig,
    accumulator: _FindingAccumulator,
) -> RuleEvaluation:
    if not config.approval_thresholds:
        return RuleEvaluation(
            SPLIT_PAYMENT_RULE_ID,
            RULE_VERSION,
            "disabled",
            0,
            0,
            "No cited approval thresholds were configured.",
        )
    finding_count = 0
    sample = 0
    window_seconds = config.threshold_window_hours * 60 * 60
    for threshold in config.approval_thresholds:
        minimum = threshold.amount * config.threshold_split_min_fraction
        groups: dict[str, list[FinanceTransaction]] = defaultdict(list)
        for transaction in transactions:
            if (
                transaction.currency != threshold.currency
                or not minimum <= transaction.amount < threshold.amount
                or not transaction.counterparty_key
            ):
                continue
            sample += 1
            groups[transaction.counterparty_key].append(transaction)
        for counterparty in sorted(groups):
            rows = sorted(groups[counterparty], key=lambda item: (item.posted_at, item.transaction_id))
            left = 0
            right = 0
            total = Decimal(0)
            while left < len(rows):
                while (
                    right < len(rows)
                    and total < threshold.amount
                    and (
                        rows[right].posted_at - rows[left].posted_at
                    ).total_seconds()
                    <= window_seconds
                ):
                    total += rows[right].amount
                    right += 1
                if right - left >= 2 and total >= threshold.amount:
                    group = rows[left:right]
                    accumulator.add(
                        SPLIT_PAYMENT_RULE_ID,
                        severity="high",
                        score=min(
                            98,
                            86
                            + int(
                                min(Decimal("0.12"), total / threshold.amount - Decimal(1))
                                * Decimal(100)
                            ),
                        ),
                        explanation=(
                            f"{len(group)} below-limit payments to the same counterparty total "
                            f"{_amount_text(total)} {threshold.currency} within "
                            f"{config.threshold_window_hours} hours, crossing approval limit "
                            f"{threshold.threshold_id}."
                        ),
                        transactions=group,
                        metrics={
                            "threshold_id": threshold.threshold_id,
                            "threshold_amount": _amount_text(threshold.amount),
                            "aggregate_amount": _amount_text(total),
                            "currency": threshold.currency,
                            "policy_ref": threshold.policy_ref,
                            "window_hours": config.threshold_window_hours,
                            "transaction_count": len(group),
                            "counterparty_key_sha256": hashlib.sha256(
                                counterparty.encode("utf-8")
                            ).hexdigest(),
                        },
                        caveats=(
                            "Aggregation is a structuring signal only; recurring legitimate "
                            "obligations can cross the same limit.",
                        ),
                    )
                    finding_count += 1
                    left = right
                    total = Decimal(0)
                    continue
                if right == left:
                    right += 1
                else:
                    total -= rows[left].amount
                left += 1
    return RuleEvaluation(
        SPLIT_PAYMENT_RULE_ID,
        RULE_VERSION,
        "finding" if finding_count else "clear",
        sample,
        finding_count,
        "Searched bounded same-counterparty windows for below-limit payments crossing a limit.",
        ("Transactions without a counterparty cannot participate in split-payment matching.",),
    )


def _off_hours_findings(
    transactions: tuple[FinanceTransaction, ...],
    config: FinanceAnomalyConfig,
    accumulator: _FindingAccumulator,
) -> RuleEvaluation:
    zone = ZoneInfo(config.business_timezone)
    finding_count = 0
    allowed_days = set(config.business_days)
    for transaction in transactions:
        local = transaction.posted_at.astimezone(zone)
        weekend = local.weekday() not in allowed_days
        local_clock = local.timetz().replace(tzinfo=None)
        outside_clock = not config.business_start <= local_clock < config.business_end
        if not (weekend or outside_clock):
            continue
        reason = "non-business weekday" if weekend else "outside configured business hours"
        score = 65 if weekend else 55
        if local.hour < 5:
            score = max(score, 70)
        accumulator.add(
            OFF_HOURS_RULE_ID,
            severity="medium" if score >= 70 else "low",
            score=score,
            explanation=(
                f"Transaction posted at {local.isoformat()} ({config.business_timezone}), "
                f"which is {reason}."
            ),
            transactions=(transaction,),
            metrics={
                "business_timezone": config.business_timezone,
                "business_start": config.business_start.isoformat(),
                "business_end": config.business_end.isoformat(),
                "business_days": list(config.business_days),
                "local_posted_at": local.isoformat(),
                "non_business_day": weekend,
                "outside_business_clock": outside_clock,
            },
            caveats=(
                "The configured calendar does not infer holidays, shifts, or approved close windows.",
            ),
        )
        finding_count += 1
    return RuleEvaluation(
        OFF_HOURS_RULE_ID,
        RULE_VERSION,
        "finding" if finding_count else "clear",
        len(transactions),
        finding_count,
        f"Compared posting times with the explicit {config.business_timezone} business calendar.",
    )


def scan_transactions(
    transactions: Iterable[FinanceTransaction | Mapping[str, Any]],
    *,
    config: FinanceAnomalyConfig | None = None,
) -> FinanceAnomalyReport:
    """Run every deterministic rule over a bounded transaction population.

    The result is independent of input order.  If candidate findings exceed
    ``max_findings``, the highest severity/score findings are returned with an
    explicit truncation count; no result silently claims complete coverage.
    """

    active = config or FinanceAnomalyConfig()
    iterator = iter(transactions)
    raw = list(islice(iterator, active.max_transactions + 1))
    if len(raw) > active.max_transactions:
        raise FinanceAnomalyInputLimit(
            f"scan exceeds the configured {active.max_transactions}-transaction bound"
        )
    normalized = tuple(
        item if isinstance(item, FinanceTransaction) else FinanceTransaction.from_mapping(item)
        for item in raw
    )
    identifiers = [transaction.transaction_id for transaction in normalized]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("transaction_id values must be unique within a scan")
    rows = tuple(sorted(normalized, key=lambda item: (item.posted_at, item.transaction_id)))
    threshold_comparisons = len(rows) * len(active.approval_thresholds)
    if threshold_comparisons > _MAX_THRESHOLD_COMPARISONS:
        raise FinanceAnomalyInputLimit(
            "scan exceeds the deterministic approval-threshold work budget; "
            "batch transactions or reduce approval_thresholds"
        )
    accumulator = _FindingAccumulator(
        rows, limit=active.max_findings, materiality=active.materiality,
    )
    evaluations_by_rule: dict[str, RuleEvaluation] = {}
    # Higher-potential rules run first so the bounded accumulator can reject
    # unambiguously lower-ranked candidates before building their identities.
    for detector in (
        _benford_findings,
        _duplicate_findings,
        _split_payment_findings,
        _just_under_findings,
        _off_hours_findings,
    ):
        evaluation = detector(rows, active, accumulator)
        evaluations_by_rule[evaluation.rule_id] = evaluation
    evaluations = [
        evaluations_by_rule[rule_id]
        for rule_id in (
            DUPLICATE_RULE_ID,
            BENFORD_RULE_ID,
            JUST_UNDER_RULE_ID,
            SPLIT_PAYMENT_RULE_ID,
            OFF_HOURS_RULE_ID,
        )
    ]
    evaluated_candidates = sum(item.finding_count for item in evaluations)
    if evaluated_candidates != accumulator.candidate_count:
        raise RuntimeError("finance anomaly candidate accounting is inconsistent")
    findings = accumulator.findings()
    omitted = accumulator.candidate_count - len(findings)
    config_snapshot = active.to_dict()
    config_sha256 = _sha256(config_snapshot)
    scan_sha256 = _sha256({
        "input_sha256": accumulator.input_sha256,
        "config_sha256": config_sha256,
        "rule_version": RULE_VERSION,
    })
    report = FinanceAnomalyReport(
        transactions_scanned=len(rows),
        input_sha256=accumulator.input_sha256,
        config_sha256=config_sha256,
        scan_sha256=scan_sha256,
        config=config_snapshot,
        findings=findings,
        evaluations=tuple(evaluations),
        truncated=bool(omitted),
        omitted_findings=omitted,
    )
    if len(_canonical(report.to_dict())) > _MAX_REPORT_JSON_BYTES:
        raise FinanceAnomalyInputLimit(
            "scan report exceeds the 16 MiB response bound; reduce max_findings "
            "or batch the transaction population"
        )
    return report


def finding_to_signal(finding: FinanceAnomalyFinding):
    """Project a finance finding into the shared deterministic signal envelope."""
    from ..anomaly_signal import AnomalySignal

    if not isinstance(finding, FinanceAnomalyFinding):
        raise TypeError("finding must be a FinanceAnomalyFinding")
    evidence_sha256s = tuple(
        str(row.get("normalized_record_sha256") or "")
        for row in finding.evidence
        if row.get("normalized_record_sha256")
    )
    return AnomalySignal(
        detector_id=finding.rule_id,
        detector_version=finding.rule_version,
        kind=finding.rule_id,
        severity=finding.severity,
        subject_ref=finding.finding_id,
        detail=finding.explanation,
        evidence_sha256s=evidence_sha256s,
    )


_DEFAULT_CASES = GovernedRecordStore(
    "finance_anomaly_cases",
    "FAC",
    "finance_anomaly_case",
    event_kind="finance_anomaly_case_changed",
)


def _human(value: object, label: str = "human_actor", *, allow_agent: bool = False) -> str:
    """Normalise an actor label and refuse the ones that are not a person.

    An ``agent:`` principal may open a case (the scan tool does), but it is
    never the human who dispositions or closes one.
    """

    actor = " ".join(_text(value, label, 256).split())
    folded = actor.casefold()
    if folded in {"system", "automation"} or (
        not allow_agent and folded.startswith("agent:")
    ):
        raise ValueError(f"{label} must identify a human reviewer")
    return actor


def _case_id(finding_id: str) -> str:
    return f"FAC-{hashlib.sha256(finding_id.encode('utf-8')).hexdigest()[:32]}"


def _encode_case_cursor(
    *,
    backend_kind: str,
    backend_cursor: str,
    case_id: str,
) -> str:
    payload = {
        "v": 1,
        "backend": backend_kind,
        "position": backend_cursor,
        "case_id": case_id,
    }
    return base64.urlsafe_b64encode(_canonical(payload)).decode("ascii").rstrip("=")


def _decode_case_cursor(
    value: str | None,
    *,
    backend_kind: str,
) -> tuple[str, str]:
    if value in (None, ""):
        return "", ""
    encoded = _text(value, "case cursor", 512)
    try:
        raw = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4),
            altchars=b"-_",
            validate=True,
        )
        payload = json.loads(raw)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("case cursor is invalid") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "v",
        "backend",
        "position",
        "case_id",
    }:
        raise ValueError("case cursor is invalid")
    position = payload.get("position")
    case_id = payload.get("case_id")
    if (
        payload.get("v") != 1
        or payload.get("backend") != backend_kind
        or not isinstance(position, str)
        or not isinstance(case_id, str)
        or len(position) > 128
        or re.fullmatch(r"FAC-[0-9a-f]{32}", case_id) is None
    ):
        raise ValueError("case cursor is invalid")
    return position, case_id


def _validate_finding_evidence(value: object) -> list[tuple[str, str]]:
    if not isinstance(value, list) or not value or len(value) > _MAX_HARD_TRANSACTIONS:
        raise FinanceAnomalyStateError("case finding evidence is missing")
    evidence_keys: list[tuple[str, str]] = []
    for item in value:
        if not isinstance(item, dict):
            raise FinanceAnomalyStateError("case finding evidence is malformed")
        digest = item.get("normalized_record_sha256")
        if not isinstance(digest, str) or _DIGEST_RE.fullmatch(digest) is None:
            raise FinanceAnomalyStateError("case finding evidence digest is invalid")
        body = {
            key: item_value
            for key, item_value in item.items()
            if key != "normalized_record_sha256"
        }
        try:
            expected_digest = _sha256(body)
        except (TypeError, ValueError) as exc:
            raise FinanceAnomalyStateError("case finding evidence is not canonical JSON") from exc
        if digest != expected_digest:
            raise FinanceAnomalyStateError("case finding evidence digest is inconsistent")
        transaction_id = item.get("transaction_id")
        if not isinstance(transaction_id, str) or not transaction_id:
            raise FinanceAnomalyStateError("case finding transaction identity is missing")
        evidence_keys.append((transaction_id, digest))
        provenance = item.get("provenance")
        if not isinstance(provenance, dict):
            raise FinanceAnomalyStateError("case finding provenance is missing")
        if (
            not isinstance(provenance.get("source_system"), str)
            or not provenance.get("source_system")
            or not isinstance(provenance.get("source_record_id"), str)
            or not provenance.get("source_record_id")
        ):
            raise FinanceAnomalyStateError("case finding source provenance is incomplete")
        source_sha256 = provenance.get("source_sha256")
        if source_sha256 and (
            not isinstance(source_sha256, str) or _DIGEST_RE.fullmatch(source_sha256) is None
        ):
            raise FinanceAnomalyStateError("case finding source digest is invalid")
    if evidence_keys != sorted(evidence_keys) or len({item[0] for item in evidence_keys}) != len(
        evidence_keys
    ):
        raise FinanceAnomalyStateError("case finding evidence identity/order is invalid")
    return evidence_keys


def _validate_finding_dict(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FinanceAnomalyStateError("case finding is not an object")
    if value.get("schema") != FINDING_SCHEMA:
        raise FinanceAnomalyStateError("case finding schema is unsupported")
    finding_id = value.get("finding_id")
    if not isinstance(finding_id, str) or re.fullmatch(r"FAF-[0-9a-f]{32}", finding_id) is None:
        raise FinanceAnomalyStateError("case finding id is invalid")
    rule_id = value.get("rule_id")
    if rule_id not in _RULE_IDS or value.get("rule_version") != RULE_VERSION:
        raise FinanceAnomalyStateError("case finding rule identity is unsupported")
    if value.get("severity") not in _SEVERITY_ORDER:
        raise FinanceAnomalyStateError("case finding severity is invalid")
    score = value.get("score")
    if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
        raise FinanceAnomalyStateError("case finding score is invalid")
    if not isinstance(value.get("explanation"), str) or not value["explanation"]:
        raise FinanceAnomalyStateError("case finding explanation is missing")
    metrics = value.get("metrics")
    if not isinstance(metrics, dict):
        raise FinanceAnomalyStateError("case finding metrics are malformed")
    caveats = value.get("caveats")
    if not isinstance(caveats, list) or any(not isinstance(item, str) for item in caveats):
        raise FinanceAnomalyStateError("case finding caveats are malformed")
    if value.get("notice") != SCREENING_NOTICE:
        raise FinanceAnomalyStateError("case finding screening notice is missing")
    evidence_keys = _validate_finding_evidence(value.get("evidence"))
    identity = {
        "rule_id": rule_id,
        "rule_version": RULE_VERSION,
        "evidence_sha256": [item[1] for item in evidence_keys],
        "metrics": metrics,
    }
    try:
        expected_finding_id = f"FAF-{_sha256(identity)[:32]}"
    except (TypeError, ValueError) as exc:
        raise FinanceAnomalyStateError("case finding metrics are not canonical JSON") from exc
    if finding_id != expected_finding_id:
        raise FinanceAnomalyStateError("case finding stable identity is inconsistent")
    return value


def _validate_disposition_history(value: object, opened_at: float) -> tuple[list[dict], float]:
    if not isinstance(value, list) or len(value) > _MAX_DISPOSITIONS:
        raise FinanceAnomalyStateError("finance anomaly disposition history is invalid")
    last_decided_at = opened_at
    for disposition in value:
        if not isinstance(disposition, dict):
            raise FinanceAnomalyStateError("finance anomaly disposition is malformed")
        decided_at = disposition.get("decided_at")
        if (
            disposition.get("outcome") not in _DISPOSITIONS
            or disposition.get("actor_type") != "human"
            or not isinstance(disposition.get("human_actor"), str)
            or not disposition.get("human_actor")
            or not isinstance(disposition.get("rationale"), str)
            or not disposition.get("rationale")
            or isinstance(decided_at, bool)
            or not isinstance(decided_at, (int, float))
            or not math.isfinite(float(decided_at))
            or float(decided_at) < last_decided_at
        ):
            raise FinanceAnomalyStateError("finance anomaly disposition is invalid")
        last_decided_at = float(decided_at)
    return value, last_decided_at


def _validate_case_closure(
    case: dict[str, Any],
    history: list[dict],
    last_decided_at: float,
) -> None:
    closure = case.get("closure")
    if case["status"] != "closed":
        if closure is not None:
            raise FinanceAnomalyStateError("open finance anomaly case has closure evidence")
        return
    closed_at = closure.get("closed_at") if isinstance(closure, dict) else None
    if (
        not isinstance(closure, dict)
        or not isinstance(closure.get("closed_by"), str)
        or not closure.get("closed_by")
        or closure.get("actor_type") != "human"
        or not isinstance(closure.get("rationale"), str)
        or not closure.get("rationale")
        or isinstance(closed_at, bool)
        or not isinstance(closed_at, (int, float))
        or not math.isfinite(float(closed_at))
        or float(closed_at) < last_decided_at
    ):
        raise FinanceAnomalyStateError("closed finance anomaly case lacks closure evidence")
    disposition_actor = str(history[-1].get("human_actor") or "")
    four_eyes_required = case["severity"] in {"high", "critical"}
    if (
        closure.get("disposition_actor") != disposition_actor
        or closure.get("four_eyes_required") is not four_eyes_required
        or closure.get("four_eyes_satisfied") is not True
    ):
        raise FinanceAnomalyStateError("finance anomaly closure authority is inconsistent")
    if four_eyes_required and (
        str(closure.get("closed_by") or "").casefold() == disposition_actor.casefold()
    ):
        raise FinanceAnomalyStateError("high-severity closure violates four-eyes")


def _validate_case(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FinanceAnomalyStateError("finance anomaly case is not an object")
    if value.get("schema") != CASE_SCHEMA:
        raise FinanceAnomalyStateError("finance anomaly case schema is unsupported")
    finding = _validate_finding_dict(value.get("finding"))
    expected_id = _case_id(str(finding["finding_id"]))
    if value.get("id") != expected_id:
        raise FinanceAnomalyStateError("finance anomaly case identity is inconsistent")
    if value.get("finding_id") != finding.get("finding_id"):
        raise FinanceAnomalyStateError("finance anomaly case finding identity is inconsistent")
    if value.get("finding_sha256") != _sha256(finding):
        raise FinanceAnomalyStateError("finance anomaly case finding digest is inconsistent")
    if value.get("severity") != finding.get("severity"):
        raise FinanceAnomalyStateError("finance anomaly case severity is inconsistent")
    status = value.get("status")
    if status not in _CASE_STATUSES:
        raise FinanceAnomalyStateError("finance anomaly case status is invalid")
    opened_at = value.get("opened_at")
    if (
        isinstance(opened_at, bool)
        or not isinstance(opened_at, (int, float))
        or not math.isfinite(float(opened_at))
        or float(opened_at) <= 0
        or not isinstance(value.get("opened_by"), str)
        or not value.get("opened_by")
    ):
        raise FinanceAnomalyStateError("finance anomaly case opening evidence is invalid")
    history, last_decided_at = _validate_disposition_history(
        value.get("disposition_history"), float(opened_at)
    )
    if status == "open" and history:
        raise FinanceAnomalyStateError("open finance anomaly case has disposition history")
    if status == "in_review" and (
        not history or history[-1].get("outcome") in _FINAL_DISPOSITIONS
    ):
        raise FinanceAnomalyStateError("in-review case disposition is inconsistent")
    if status in {"dispositioned", "closed"}:
        if not history or history[-1].get("outcome") not in _FINAL_DISPOSITIONS:
            raise FinanceAnomalyStateError("closed/dispositioned case lacks a final disposition")
    _validate_case_closure(value, history, last_decided_at)
    revision = value.get("revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise FinanceAnomalyStateError("finance anomaly case revision is invalid")
    return value


def _case_summary(value: dict[str, Any]) -> dict[str, Any]:
    """Project queue metadata without retaining finding evidence in a list."""

    finding = value["finding"]
    history = value["disposition_history"]
    latest = history[-1] if history else None
    closure = value.get("closure")
    return {
        "id": value["id"],
        "schema": value["schema"],
        "finding_id": value["finding_id"],
        "rule_id": finding["rule_id"],
        "severity": value["severity"],
        "score": finding["score"],
        "status": value["status"],
        "opened_by": value["opened_by"],
        "opened_at": value["opened_at"],
        "revision": value["revision"],
        "disposition_count": len(history),
        "latest_disposition": (
            None
            if latest is None
            else {
                "outcome": latest["outcome"],
                "human_actor": latest["human_actor"],
                "decided_at": latest["decided_at"],
            }
        ),
        "closed_at": closure.get("closed_at") if isinstance(closure, dict) else None,
    }


class FinanceAnomalyCaseQueue:
    """Tenant-scoped durable CAS queue for human review and disposition."""

    def __init__(self, *, store: GovernedRecordStore | None = None) -> None:
        self._store = store or _DEFAULT_CASES

    @property
    def backend_kind(self) -> str:
        return self._store.backend_kind

    def enqueue(self, finding: FinanceAnomalyFinding, *, opened_by: str) -> dict[str, Any]:
        if not isinstance(finding, FinanceAnomalyFinding):
            raise TypeError("finding must be a FinanceAnomalyFinding")
        actor = _human(opened_by, "opened_by", allow_agent=True)
        finding_value = finding.to_dict()
        if len(_canonical(finding_value)) > _MAX_FINDING_JSON_BYTES:
            raise FinanceAnomalyInputLimit(
                "finding exceeds the governed case evidence bound"
            )
        _validate_finding_dict(finding_value)
        case_id = _case_id(finding.finding_id)
        existing = self._store.get(case_id)
        if existing is not None:
            current = _validate_case(existing)
            if current["finding_sha256"] != _sha256(finding_value):
                raise FinanceAnomalyStateError("stable case id is bound to a different finding")
            return current
        now = float(self._store.authoritative_time())
        if not math.isfinite(now) or now <= 0:
            raise FinanceAnomalyStateError("case authority clock is invalid")
        record = {
            "schema": CASE_SCHEMA,
            "id": case_id,
            "finding_id": finding.finding_id,
            "finding_sha256": _sha256(finding_value),
            "finding": finding_value,
            "severity": finding.severity,
            "status": "open",
            "opened_by": actor,
            "opened_at": now,
            "disposition_history": [],
            "closure": None,
        }
        try:
            saved = self._store.create(record, action="enqueue", actor=actor)
        except RecordConflict:
            concurrent = self._store.get(case_id)
            if concurrent is None:
                raise
            current = _validate_case(concurrent)
            if current["finding_sha256"] != record["finding_sha256"]:
                raise FinanceAnomalyStateError(
                    "concurrent stable case id is bound to a different finding"
                ) from None
            return current
        return _validate_case(saved)

    def get(self, case_id: str) -> dict[str, Any] | None:
        value = self._store.get(_text(case_id, "case_id", 63))
        return None if value is None else _validate_case(value)

    def list_cases(
        self,
        *,
        status: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Return the bounded first page for compatibility with list callers."""

        return sorted(
            self.list_case_page(status=status, limit=limit).cases,
            key=lambda row: (
                -_SEVERITY_ORDER[str(row["severity"])],
                float(row["opened_at"]),
                str(row["id"]),
            ),
        )

    def list_case_page(
        self,
        *,
        status: str | None = None,
        limit: int = 500,
        cursor: str | None = None,
    ) -> FinanceAnomalyCasePage:
        """Return a bounded, cursor-traversable case page.

        Record ids are the stable scan order because the governed persistence
        primitive can traverse them without loading an unbounded collection.
        Status filtering occurs while scanning, before the response limit is
        applied.  Sparse filters may therefore return an empty page with
        ``has_more=True``; following ``next_cursor`` continues the bounded
        search without losing or duplicating a matching case.
        """

        return self._list_case_page(
            status=status,
            limit=limit,
            cursor=cursor,
            summary_only=False,
        )

    def list_case_summary_page(
        self,
        *,
        status: str | None = None,
        limit: int = 100,
        cursor: str | None = None,
    ) -> FinanceAnomalyCasePage:
        """Return a cursor page that omits the potentially multi-MiB finding."""

        return self._list_case_page(
            status=status,
            limit=limit,
            cursor=cursor,
            summary_only=True,
        )

    def _list_case_page(
        self,
        *,
        status: str | None,
        limit: int,
        cursor: str | None,
        summary_only: bool,
    ) -> FinanceAnomalyCasePage:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_CASE_LIST:
            raise ValueError(f"case list limit must be between 1 and {_MAX_CASE_LIST}")
        if status is not None and status not in _CASE_STATUSES:
            raise ValueError("case status filter is invalid")
        backend_kind = self.backend_kind
        backend_cursor, last_case_id = _decode_case_cursor(
            cursor,
            backend_kind=backend_kind,
        )
        cases: list[dict[str, Any]] = []
        scanned = 0
        resume_backend_cursor = backend_cursor
        resume_case_id = last_case_id
        window = list(
            self._store.iter_record_ids(
                start_after=backend_cursor,
                limit=_MAX_CASE_PAGE_SCAN,
            )
        )
        for position, case_id in window:
            # Backend scans rotate after the lexical tail.  A page cursor is a
            # forward-only traversal, so the first wrapped identity is EOF.
            if last_case_id and case_id <= last_case_id:
                return FinanceAnomalyCasePage(
                    cases=tuple(cases),
                    next_cursor="",
                    has_more=False,
                    scanned_records=scanned,
                )
            if len(cases) >= limit:
                return FinanceAnomalyCasePage(
                    cases=tuple(cases),
                    next_cursor=_encode_case_cursor(
                        backend_kind=backend_kind,
                        backend_cursor=resume_backend_cursor,
                        case_id=resume_case_id,
                    ),
                    has_more=True,
                    scanned_records=scanned,
                )
            value = self._store.get(case_id)
            scanned += 1
            if value is None:
                resume_backend_cursor = position
                resume_case_id = case_id
                continue
            row = _validate_case(value)
            if status is not None and row["status"] != status:
                resume_backend_cursor = position
                resume_case_id = case_id
                continue
            cases.append(_case_summary(row) if summary_only else row)
            resume_backend_cursor = position
            resume_case_id = case_id

        has_more = len(window) == _MAX_CASE_PAGE_SCAN and bool(resume_case_id)
        next_cursor = (
            _encode_case_cursor(
                backend_kind=backend_kind,
                backend_cursor=resume_backend_cursor,
                case_id=resume_case_id,
            )
            if has_more
            else ""
        )
        return FinanceAnomalyCasePage(
            cases=tuple(cases),
            next_cursor=next_cursor,
            has_more=has_more,
            scanned_records=scanned,
        )

    def case_status_summary(self, *, scan_limit: int = 500) -> dict[str, Any]:
        """Count a hard-bounded scan while retaining no full case payloads."""

        if (
            isinstance(scan_limit, bool)
            or not isinstance(scan_limit, int)
            or not 1 <= scan_limit <= _MAX_CASE_SUMMARY_SCAN
        ):
            raise ValueError(
                f"case summary scan_limit must be between 1 and {_MAX_CASE_SUMMARY_SCAN}"
            )
        window = list(self._store.iter_record_ids(limit=scan_limit + 1))
        counts: dict[str, int] = {}
        total = 0
        for _position, case_id in window[:scan_limit]:
            value = self._store.get(case_id)
            if value is None:
                continue
            row = _validate_case(value)
            state = str(row["status"])
            counts[state] = counts.get(state, 0) + 1
            total += 1
        return {
            "total": total,
            "by_status": dict(sorted(counts.items())),
            "count_cap": scan_limit,
            "truncated": len(window) > scan_limit,
            "record_reads": min(len(window), scan_limit),
        }

    def record_disposition(
        self,
        case_id: str,
        *,
        outcome: str,
        rationale: str,
        human_actor: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        actor = _human(human_actor)
        decision = _text(outcome, "outcome", 64).lower()
        if decision not in _DISPOSITIONS:
            raise ValueError("unsupported finance anomaly disposition")
        reason = _text(rationale, "rationale", 4096)
        now = float(self._store.authoritative_time())

        def _mutate(current: dict[str, Any]) -> None:
            _validate_case(current)
            if current["status"] == "closed":
                raise FinanceAnomalyStateError("closed finance anomaly cases are immutable")
            history = current["disposition_history"]
            if len(history) >= _MAX_DISPOSITIONS:
                raise FinanceAnomalyStateError("finance anomaly disposition history is full")
            history.append(
                {
                    "outcome": decision,
                    "rationale": reason,
                    "human_actor": actor,
                    "actor_type": "human",
                    "decided_at": now,
                }
            )
            current["status"] = "dispositioned" if decision in _FINAL_DISPOSITIONS else "in_review"
            current["closure"] = None

        saved = self._store.update(
            _text(case_id, "case_id", 63),
            _mutate,
            expected_revision=expected_revision,
            action="human_disposition",
            actor=actor,
        )
        if saved is None:
            raise FinanceAnomalyStateError("finance anomaly case does not exist")
        return _validate_case(saved)

    def close_case(
        self,
        case_id: str,
        *,
        rationale: str,
        human_actor: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        actor = _human(human_actor)
        reason = _text(rationale, "closure rationale", 4096)
        now = float(self._store.authoritative_time())

        def _mutate(current: dict[str, Any]) -> None:
            _validate_case(current)
            if current["status"] != "dispositioned":
                raise FinanceAnomalyStateError(
                    "case must have a final human disposition before closure"
                )
            disposition_actor = str(current["disposition_history"][-1]["human_actor"])
            four_eyes_required = current["severity"] in {"high", "critical"}
            if four_eyes_required and actor.casefold() == disposition_actor.casefold():
                raise FourEyesRequired(
                    "a different human must approve high-severity case closure"
                )
            current["status"] = "closed"
            current["closure"] = {
                "closed_by": actor,
                "actor_type": "human",
                "rationale": reason,
                "closed_at": now,
                "four_eyes_required": four_eyes_required,
                "four_eyes_satisfied": not four_eyes_required
                or actor.casefold() != disposition_actor.casefold(),
                "disposition_actor": disposition_actor,
            }

        saved = self._store.update(
            _text(case_id, "case_id", 63),
            _mutate,
            expected_revision=expected_revision,
            action="close",
            actor=actor,
        )
        if saved is None:
            raise FinanceAnomalyStateError("finance anomaly case does not exist")
        return _validate_case(saved)


__all__ = [
    "ApprovalThreshold",
    "BENFORD_RULE_ID",
    "CASE_PAGE_SCHEMA",
    "CASE_SCHEMA",
    "DUPLICATE_RULE_ID",
    "FINDING_SCHEMA",
    "FinanceAnomalyCasePage",
    "FinanceAnomalyCaseQueue",
    "FinanceAnomalyConfig",
    "FinanceAnomalyError",
    "FinanceAnomalyFinding",
    "FinanceAnomalyInputLimit",
    "FinanceAnomalyReport",
    "FinanceAnomalyStateError",
    "FinanceTransaction",
    "FourEyesRequired",
    "JUST_UNDER_RULE_ID",
    "OFF_HOURS_RULE_ID",
    "RULE_VERSION",
    "RuleEvaluation",
    "SCREENING_NOTICE",
    "SPLIT_PAYMENT_RULE_ID",
    "enabled",
    "finding_to_signal",
    "scan_transactions",
    "with_configured_materiality",
]
