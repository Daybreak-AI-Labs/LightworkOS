"""Bounded inputs for the deterministic finance-operations API."""
from __future__ import annotations

import json
from datetime import datetime, time
from decimal import Decimal
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

REGULATORY_FEED_BYTES = 5 * 1024 * 1024
AML_LIST_BYTES = 16 * 1024 * 1024
_SHA256 = r"^(?:sha256:)?[0-9a-fA-F]{64}$"
_SOURCE_KEY = r"^[a-z0-9][a-z0-9._-]{0,127}$"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _bounded_utf8(value: str, *, label: str, maximum: int) -> str:
    if not value:
        raise ValueError(f"{label} is required")
    if len(value.encode("utf-8")) > maximum:
        raise ValueError(f"{label} exceeds the {maximum}-byte limit")
    return value


def _validate_https(value: str, *, label: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(f"{label} must be an https URL with a host")
    return value


def _bounded_strings(values: list[str], *, label: str, maximum: int = 128) -> list[str]:
    normalized: list[str] = []
    for index, item in enumerate(values):
        value = item.strip().lower()
        if not value:
            raise ValueError(f"{label} {index} is empty")
        if len(value) > maximum:
            raise ValueError(f"{label} {index} exceeds {maximum} characters")
        normalized.append(value)
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{label} values must be unique")
    return normalized


class RegulatorySourceIn(_StrictModel):
    key: str = Field(..., pattern=_SOURCE_KEY)
    name: str = Field(..., min_length=1, max_length=200)
    jurisdiction: str = Field(..., pattern=r"^[A-Za-z0-9][A-Za-z0-9-]{1,31}$")
    url: str = Field(..., min_length=9, max_length=2048)
    format: str = Field(..., pattern=r"^(federal_register_json|json|rss|atom)$")
    default_regimes: list[str] = Field(default_factory=list, max_length=128)
    default_domains: list[str] = Field(default_factory=list, max_length=128)
    field_map: dict[str, str] = Field(default_factory=dict, max_length=32)

    @field_validator("url")
    @classmethod
    def official_https_source(cls, value: str) -> str:
        return _validate_https(value, label="source url")

    @field_validator("default_regimes", "default_domains")
    @classmethod
    def bounded_scopes(cls, value: list[str], info) -> list[str]:
        return _bounded_strings(value, label=info.field_name)

    @field_validator("field_map")
    @classmethod
    def bounded_field_map(cls, value: dict[str, str]) -> dict[str, str]:
        for key, path in value.items():
            if not key.strip() or not path.strip():
                raise ValueError("field_map keys and paths must be non-empty")
            if len(key) > 64 or len(path) > 256:
                raise ValueError("field_map keys or paths exceed their bounds")
        return value


class RegulatoryFeedIngestIn(_StrictModel):
    source: RegulatorySourceIn
    payload: str
    enabled_regimes: list[str] = Field(default_factory=list, max_length=128)
    enabled_domains: list[str] = Field(default_factory=list, max_length=128)

    @field_validator("payload")
    @classmethod
    def bounded_payload(cls, value: str) -> str:
        return _bounded_utf8(
            value,
            label="regulatory feed payload",
            maximum=REGULATORY_FEED_BYTES,
        )

    @field_validator("enabled_regimes", "enabled_domains")
    @classmethod
    def bounded_scopes(cls, value: list[str], info) -> list[str]:
        return _bounded_strings(value, label=info.field_name)

class RegulatoryAlertReviewIn(_StrictModel):
    status: str = Field(..., pattern=r"^(in_review|accepted|dismissed)$")
    note: str = Field("", max_length=10_000)
    expected_revision: int = Field(..., ge=1)


class ApprovalThresholdIn(_StrictModel):
    threshold_id: str = Field(..., min_length=1, max_length=128)
    currency: str = Field(..., pattern=r"^[A-Za-z]{3}$")
    amount: Decimal = Field(..., gt=0, max_digits=24, decimal_places=8)
    policy_ref: str = Field(..., min_length=1, max_length=1024)


class FinanceAnomalyConfigIn(_StrictModel):
    max_transactions: int = Field(5_000, ge=1, le=10_000)
    max_findings: int = Field(1_000, ge=1, le=5_000)
    duplicate_window_hours: int = Field(72, ge=1, le=744)
    benford_population_eligible: bool = False
    benford_min_sample: int = Field(100, ge=50, le=10_000)
    benford_min_orders: int = Field(3, ge=2, le=10)
    benford_mad_threshold: Decimal = Field(
        Decimal("0.015"), ge=Decimal("0.001"), le=Decimal("0.100")
    )
    approval_thresholds: list[ApprovalThresholdIn] = Field(
        default_factory=list, max_length=128
    )
    threshold_near_fraction: Decimal = Field(
        Decimal("0.95"), ge=Decimal("0.01"), lt=1
    )
    threshold_split_min_fraction: Decimal = Field(
        Decimal("0.20"), ge=Decimal("0.01"), lt=1
    )
    threshold_window_hours: int = Field(24, ge=1, le=744)
    business_timezone: str = Field("UTC", min_length=1, max_length=128)
    business_start: time = time(8, 0)
    business_end: time = time(18, 0)
    business_days: list[int] = Field(default_factory=lambda: [0, 1, 2, 3, 4], max_length=7)

    @model_validator(mode="after")
    def coherent_thresholds_and_calendar(self):
        if self.threshold_split_min_fraction > self.threshold_near_fraction:
            raise ValueError(
                "threshold_split_min_fraction cannot exceed threshold_near_fraction"
            )
        if len(set(self.business_days)) != len(self.business_days):
            raise ValueError("business_days must be unique")
        if any(day < 0 or day > 6 for day in self.business_days):
            raise ValueError("business_days values must be between 0 and 6")
        return self


class FinanceTransactionIn(_StrictModel):
    transaction_id: str = Field(..., min_length=1, max_length=200)
    amount: Decimal = Field(..., max_digits=24, decimal_places=8)
    currency: str = Field(..., pattern=r"^[A-Za-z]{3}$")
    posted_at: datetime
    source_system: str = Field(..., min_length=1, max_length=128)
    source_record_id: str = Field(..., min_length=1, max_length=256)
    counterparty_id: str = Field("", max_length=256)
    counterparty_name: str = Field("", max_length=512)
    invoice_id: str = Field("", max_length=256)
    reference: str = Field("", max_length=512)
    source_uri: str = Field("", max_length=2048)
    source_sha256: str = Field("", pattern=rf"^(?:{_SHA256[1:-1]})?$")

    @field_validator("posted_at")
    @classmethod
    def timezone_aware_posting(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("posted_at must include a timezone offset")
        return value


class FinanceAnomalyScanIn(_StrictModel):
    transactions: list[FinanceTransactionIn] = Field(..., min_length=1, max_length=10_000)
    config: FinanceAnomalyConfigIn = Field(default_factory=FinanceAnomalyConfigIn)
    enqueue_findings: bool = True

    @model_validator(mode="after")
    def declared_scan_bound_covers_payload(self):
        if len(self.transactions) > self.config.max_transactions:
            raise ValueError("transactions exceed config.max_transactions")
        return self


class FinanceCaseDispositionIn(_StrictModel):
    outcome: str = Field(
        ...,
        pattern=r"^(confirmed|false_positive|accepted_risk|needs_information|escalated)$",
    )
    rationale: str = Field(..., min_length=1, max_length=4096)
    expected_revision: int = Field(..., ge=1)


class FinanceCaseClosureIn(_StrictModel):
    rationale: str = Field(..., min_length=1, max_length=4096)
    expected_revision: int = Field(..., ge=1)


class AMLListIngestIn(_StrictModel):
    list_kind: str = Field(..., pattern=r"^(sanctions|pep|internal_watchlist|kyc)$")
    source_name: str = Field(..., min_length=1, max_length=200)
    source_ref: str = Field(..., min_length=1, max_length=2000)
    version: str = Field(..., min_length=1, max_length=128)
    payload: str
    published_at: datetime | float | None = None
    retrieved_at: datetime | float | None = None
    data_format: str = Field("auto", pattern=r"^(auto|text|json|csv|xml)$")
    expected_sha256: str = Field("", pattern=rf"^(?:{_SHA256[1:-1]})?$")

    @field_validator("source_ref")
    @classmethod
    def cited_source(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme == "urn" and parsed.path:
            return value
        return _validate_https(value, label="source_ref")

    @field_validator("payload")
    @classmethod
    def bounded_payload(cls, value: str) -> str:
        return _bounded_utf8(value, label="AML list payload", maximum=AML_LIST_BYTES)

    @field_validator("published_at", "retrieved_at")
    @classmethod
    def timezone_aware_list_dates(cls, value: datetime | float | None):
        if isinstance(value, datetime) and (
            value.tzinfo is None or value.utcoffset() is None
        ):
            raise ValueError("list timestamps must include a timezone offset")
        return value


class AMLScreenIn(_StrictModel):
    subject_name: str = Field(..., min_length=1, max_length=256)
    subject_ref: str = Field("", max_length=256)
    list_ids: list[str] = Field(default_factory=list, max_length=16)

    @field_validator("list_ids")
    @classmethod
    def bounded_ids(cls, value: list[str]) -> list[str]:
        normalized: list[str] = []
        for index, item in enumerate(value):
            identifier = item.strip()
            if not identifier:
                raise ValueError(f"list_ids {index} is empty")
            if len(identifier) > 64:
                raise ValueError(f"list_ids {index} exceeds 64 characters")
            normalized.append(identifier)
        if len(set(normalized)) != len(normalized):
            raise ValueError("list_ids values must be unique")
        return normalized


class AMLCaseDispositionIn(_StrictModel):
    decision: str = Field(..., pattern=r"^(clear|escalate)$")
    rationale: str = Field(..., min_length=1, max_length=4000)
    expected_revision: int = Field(..., ge=1)


class ControlCycleTriggerIn(_StrictModel):
    observations: list[dict[str, Any]] | None = Field(None, min_length=1, max_length=64)

    @model_validator(mode="after")
    def bound_observations(self):
        if self.observations is None:
            return self
        for index, row in enumerate(self.observations):
            if len(row) > 16:
                raise ValueError(f"observation {index} has too many fields")
            citations = row.get("citations")
            if not isinstance(citations, list) or not citations or len(citations) > 20:
                raise ValueError(f"observation {index} requires 1 to 20 citations")
            try:
                encoded = json.dumps(
                    row,
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                ).encode("utf-8")
            except (TypeError, ValueError) as exc:
                raise ValueError(f"observation {index} must be finite JSON") from exc
            if len(encoded) > 16_000:
                raise ValueError(f"observation {index} exceeds its size bound")
        return self


__all__ = [
    "AMLCaseDispositionIn",
    "AMLListIngestIn",
    "AMLScreenIn",
    "ApprovalThresholdIn",
    "ControlCycleTriggerIn",
    "FinanceAnomalyConfigIn",
    "FinanceAnomalyScanIn",
    "FinanceCaseClosureIn",
    "FinanceCaseDispositionIn",
    "FinanceTransactionIn",
    "RegulatoryAlertReviewIn",
    "RegulatoryFeedIngestIn",
    "RegulatorySourceIn",
]
