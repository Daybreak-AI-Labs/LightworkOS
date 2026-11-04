"""Governed enterprise AI cost and assumption-labelled ROI evidence.

The existing Lightwork usage ledger measures Lightwork's own model calls.  It
does not establish what an enterprise paid AWS, Azure, GCP, OpenAI, or another
AI provider.  This module is the deliberately separate admission boundary for
those provider billing facts.

Collectors remain provider-specific and read-only.  They return typed,
normalized rows plus a source-manifest citation; they never give this core a
credential, URL to call, or raw provider payload.  Admission is append-only:
the provider line identity is deterministic, exact replays are idempotent, and
a changed amount under the same identity is rejected in favour of an explicit
correction line.  A batch receipt is written only after every row was admitted,
so reports never count a half-ingested collection.

All money is stored as validated decimal text and currencies are never
converted or conflated.  Measured provider cost and operator-authored benefit
assumptions live in separate governed namespaces.  Reports label both and bind
them to source citations, collection receipts, registry snapshots, and CAS
revisions; they do not claim that an assumption is measured value.

This is a core service, not a live provider integration.  Production collectors,
configuration, scheduling, API/UI surfaces, and installer wiring are separate
integration work.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation, localcontext
from enum import Enum
from typing import Any, Protocol
from urllib.parse import urlsplit

from .governed_records import GovernedRecordStore

OBSERVATION_SCHEMA = "lightwork.ai-provider-cost-observation.v1"
RECEIPT_SCHEMA = "lightwork.ai-provider-cost-collection-receipt.v1"
ASSUMPTION_SCHEMA = "lightwork.ai-roi-assumption.v1"
REPORT_SCHEMA = "lightwork.ai-cost-roi-report.v1"

_OBSERVATIONS = GovernedRecordStore(
    "ai_provider_cost_observations",
    "ACO",
    "ai_provider_cost_observation",
)
_RECEIPTS = GovernedRecordStore(
    "ai_provider_cost_receipts",
    "ACR",
    "ai_provider_cost_collection_receipt",
)
_ASSUMPTIONS = GovernedRecordStore(
    "ai_roi_assumptions",
    "ARA",
    "ai_roi_assumption",
)

_DIGEST_RE = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z")
_CURRENCY_RE = re.compile(r"[A-Z]{3}\Z")
_ASSET_RE = re.compile(r"MAA-[0-9a-f]{32}\Z")
_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.:/-]{0,127}\Z")
_MAX_BATCH_RECORDS = 1_000
_MAX_NAMESPACE_RECORDS = 10_000
_MAX_REPORT_ROWS = 500
_MAX_ALLOCATIONS = 32
_MAX_USAGE_ITEMS = 32
_MAX_CITATIONS = 500
_MONEY_QUANTUM = Decimal("0.000000001")
_SOURCE_PAYLOAD_FIELDS = (
    "provider",
    "source_account_id",
    "source_record_id",
    "period_start",
    "period_end",
    "currency",
    "source_cost",
    "usage",
    "service",
    "resource_id",
    "region",
    "registry_asset_id",
    "correction_of_source_record_id",
    "correction_reason",
    "citation",
)


class AICostError(RuntimeError):
    """Base error for AI provider-cost admission and reporting."""


class AICostProtocolError(AICostError):
    """A collector or source record violated the typed contract."""


class AICostStateError(AICostError):
    """The governed cost state is missing, inconsistent, or over its bound."""


class AICostIdempotencyConflict(AICostError):
    """A stable source identity was reused for different content."""


class AICostConfigError(AICostError):
    """The AI cost and ROI capability is disabled or misconfigured."""


class BillingProvider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    OPENAI = "openai"


def _required(value: object, label: str, maximum: int = 512) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{label} is required")
    if len(text) > maximum or any(ord(char) < 32 for char in text):
        raise ValueError(f"{label} is invalid or exceeds {maximum} characters")
    return text


def _optional(value: object, label: str, maximum: int = 512) -> str:
    if value in (None, ""):
        return ""
    return _required(value, label, maximum)


def _token(value: object, label: str) -> str:
    text = _required(value, label, 128)
    if not _TOKEN_RE.fullmatch(text):
        raise ValueError(f"{label} must be a stable token")
    return text


def _digest(value: object, label: str) -> str:
    text = _required(value, label, 71).lower()
    if not _DIGEST_RE.fullmatch(text):
        raise ValueError(f"{label} must be a SHA-256 digest")
    return text.removeprefix("sha256:")


def _sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _decimal(value: object, label: str, *, allow_negative: bool = True) -> Decimal:
    if isinstance(value, bool) or isinstance(value, float):
        raise ValueError(f"{label} must be exact decimal text, Decimal, or integer")
    try:
        number = Decimal(str(value).strip())
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{label} must be a finite decimal") from exc
    if not number.is_finite():
        raise ValueError(f"{label} must be a finite decimal")
    if not allow_negative and number < 0:
        raise ValueError(f"{label} must not be negative")
    if len(number.as_tuple().digits) > 38 or abs(number) > Decimal("1e24"):
        raise ValueError(f"{label} exceeds the supported precision or magnitude")
    return Decimal(0) if number == 0 else number


def _decimal_text(value: object, label: str, *, allow_negative: bool = True) -> str:
    number = _decimal(value, label, allow_negative=allow_negative)
    text = format(number, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def _currency(value: object) -> str:
    code = _required(value, "currency", 3).upper()
    if not _CURRENCY_RE.fullmatch(code):
        raise ValueError("currency must be an ISO-style three-letter code")
    return code


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be a positive finite timestamp")
    try:
        stamp = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"{label} must be a positive finite timestamp") from exc
    if not math.isfinite(stamp) or stamp <= 0:
        raise ValueError(f"{label} must be a positive finite timestamp")
    return stamp


def _instant(value: object, label: str) -> str:
    """Canonicalize an offset-aware timestamp to UTC without losing precision."""
    text = _required(value, label, 64)
    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a UTC offset")
    canonical = parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return canonical


def _instant_value(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _period(start: object, end: object) -> tuple[str, str]:
    period_start = _instant(start, "period_start")
    period_end = _instant(end, "period_end")
    if _instant_value(period_end) <= _instant_value(period_start):
        raise ValueError("period_end must be after period_start")
    return period_start, period_end


def _report_scope(scope_kind: object, scope_id: object) -> tuple[str, str]:
    kind = str(scope_kind or "").strip().lower()
    if kind not in {"portfolio", "department", "asset"}:
        raise ValueError("scope_kind must be portfolio, department, or asset")
    identity = _optional(scope_id, "scope id", 256)
    if kind == "portfolio" and identity:
        raise ValueError("portfolio reports must not specify scope_id")
    if kind != "portfolio" and not identity:
        raise ValueError(f"{kind} reports require scope_id")
    if kind == "asset" and not _ASSET_RE.fullmatch(identity):
        raise ValueError("asset report scope is not a model-risk asset id")
    return kind, identity


def _provider(value: BillingProvider | str) -> BillingProvider:
    try:
        return value if isinstance(value, BillingProvider) else BillingProvider(value)
    except ValueError as exc:
        raise ValueError("provider must be aws, azure, gcp, or openai") from exc


def _tenant_ref() -> str:
    from .paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise AICostStateError("AI cost operations require an explicit tenant")
    return "TEN-" + hashlib.sha256(tenant.encode("utf-8")).hexdigest()[:24]


def _record_id(prefix: str, *parts: object) -> str:
    return f"{prefix}-{_sha256(list(parts))[:32]}"


@dataclass(frozen=True)
class SourceCitation:
    """Stable citation to a provider export or API response manifest.

    Query strings, fragments, and embedded user information are rejected so a
    signed export URL or bearer credential cannot accidentally become evidence.
    """

    uri: str
    sha256: str
    row_ref: str = ""

    def __post_init__(self) -> None:
        uri = _required(self.uri, "citation uri", 2048)
        parsed = urlsplit(uri)
        if parsed.scheme.lower() not in {"https", "s3", "gs", "azure", "urn"}:
            raise ValueError("citation uri uses an unsupported scheme")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("citation uri must not contain credentials, query, or fragment")
        if parsed.scheme.lower() != "urn" and not parsed.netloc:
            raise ValueError("citation uri must name a source authority")
        object.__setattr__(self, "uri", uri)
        object.__setattr__(self, "sha256", _digest(self.sha256, "citation digest"))
        object.__setattr__(self, "row_ref", _optional(self.row_ref, "citation row", 256))

    def to_dict(self) -> dict[str, str]:
        return {"uri": self.uri, "sha256": self.sha256, "row_ref": self.row_ref}


@dataclass(frozen=True)
class UsageQuantity:
    metric: str
    quantity: str
    unit: str

    def __post_init__(self) -> None:
        # Provider meter labels are evidence, not Lightwork identifiers.  Keep
        # their exact bounded spelling (Azure commonly emits spaces) instead
        # of inventing a lossy slug.
        object.__setattr__(self, "metric", _required(self.metric, "usage metric", 256))
        object.__setattr__(
            self,
            "quantity",
            _decimal_text(self.quantity, "usage quantity"),
        )
        object.__setattr__(self, "unit", _required(self.unit, "usage unit", 128))

    def to_dict(self) -> dict[str, str]:
        return {"metric": self.metric, "quantity": self.quantity, "unit": self.unit}


@dataclass(frozen=True)
class NormalizedBillingRecord:
    """Provider-neutral immutable billing fact returned by collectors."""

    provider: BillingProvider
    source_account_id: str
    source_record_id: str
    period_start: str
    period_end: str
    currency: str
    cost: str
    usage: tuple[UsageQuantity, ...]
    service: str
    resource_id: str
    citation: SourceCitation
    region: str = ""
    registry_asset_id: str = ""
    correction_of_source_record_id: str = ""
    correction_reason: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", _provider(self.provider))
        object.__setattr__(
            self,
            "source_account_id",
            _required(self.source_account_id, "source account id", 256),
        )
        object.__setattr__(
            self,
            "source_record_id",
            _required(self.source_record_id, "source record id", 512),
        )
        start, end = _period(self.period_start, self.period_end)
        object.__setattr__(self, "period_start", start)
        object.__setattr__(self, "period_end", end)
        object.__setattr__(self, "currency", _currency(self.currency))
        object.__setattr__(self, "cost", _decimal_text(self.cost, "source cost"))
        usage = tuple(self.usage)
        if not usage or len(usage) > _MAX_USAGE_ITEMS:
            raise ValueError(f"usage must contain between 1 and {_MAX_USAGE_ITEMS} items")
        if any(not isinstance(item, UsageQuantity) for item in usage):
            raise TypeError("usage entries must be UsageQuantity values")
        keys = [(item.metric, item.unit) for item in usage]
        if len(set(keys)) != len(keys):
            raise ValueError("usage metric/unit bindings must be unique")
        object.__setattr__(self, "usage", usage)
        object.__setattr__(self, "service", _required(self.service, "service", 256))
        object.__setattr__(
            self,
            "resource_id",
            _required(self.resource_id, "resource id", 1024),
        )
        if not isinstance(self.citation, SourceCitation):
            raise TypeError("citation must be a SourceCitation")
        object.__setattr__(self, "region", _optional(self.region, "region", 128))
        asset = _optional(self.registry_asset_id, "registry asset id", 36)
        if asset and not _ASSET_RE.fullmatch(asset):
            raise ValueError("registry_asset_id is not a model-risk asset identity")
        object.__setattr__(self, "registry_asset_id", asset)
        correction = _optional(
            self.correction_of_source_record_id,
            "correction source record id",
            512,
        )
        reason = _optional(self.correction_reason, "correction reason", 1000)
        if bool(correction) != bool(reason):
            raise ValueError("corrections require both a source identity and reason")
        if correction == self.source_record_id:
            raise ValueError("a provider line cannot correct itself")
        object.__setattr__(self, "correction_of_source_record_id", correction)
        object.__setattr__(self, "correction_reason", reason)

    @property
    def source_payload(self) -> dict[str, Any]:
        return {
            "provider": self.provider.value,
            "source_account_id": self.source_account_id,
            "source_record_id": self.source_record_id,
            "period_start": self.period_start,
            "period_end": self.period_end,
            "currency": self.currency,
            "source_cost": self.cost,
            "usage": [item.to_dict() for item in self.usage],
            "service": self.service,
            "resource_id": self.resource_id,
            "region": self.region,
            "registry_asset_id": self.registry_asset_id,
            "correction_of_source_record_id": self.correction_of_source_record_id,
            "correction_reason": self.correction_reason,
            "citation": self.citation.to_dict(),
        }

    @property
    def payload_sha256(self) -> str:
        return _sha256(self.source_payload)


@dataclass(frozen=True)
class AWSBillingRecord:
    payer_account_id: str
    line_item_id: str
    usage_start: str
    usage_end: str
    currency: str
    unblended_cost: str
    usage_type: str
    usage_amount: str
    usage_unit: str
    resource_arn: str
    product_code: str
    citation: SourceCitation
    region: str = ""
    registry_asset_id: str = ""
    correction_of_line_item_id: str = ""
    correction_reason: str = ""

    def normalize(self) -> NormalizedBillingRecord:
        return NormalizedBillingRecord(
            provider=BillingProvider.AWS,
            source_account_id=self.payer_account_id,
            source_record_id=self.line_item_id,
            period_start=self.usage_start,
            period_end=self.usage_end,
            currency=self.currency,
            cost=self.unblended_cost,
            usage=(UsageQuantity(self.usage_type, self.usage_amount, self.usage_unit),),
            service=self.product_code,
            resource_id=self.resource_arn,
            region=self.region,
            registry_asset_id=self.registry_asset_id,
            correction_of_source_record_id=self.correction_of_line_item_id,
            correction_reason=self.correction_reason,
            citation=self.citation,
        )


@dataclass(frozen=True)
class AzureBillingRecord:
    billing_account_id: str
    charge_id: str
    usage_start: str
    usage_end: str
    billing_currency: str
    cost_in_billing_currency: str
    meter_name: str
    quantity: str
    unit_of_measure: str
    resource_id: str
    service_name: str
    citation: SourceCitation
    region: str = ""
    registry_asset_id: str = ""
    correction_of_charge_id: str = ""
    correction_reason: str = ""

    def normalize(self) -> NormalizedBillingRecord:
        return NormalizedBillingRecord(
            provider=BillingProvider.AZURE,
            source_account_id=self.billing_account_id,
            source_record_id=self.charge_id,
            period_start=self.usage_start,
            period_end=self.usage_end,
            currency=self.billing_currency,
            cost=self.cost_in_billing_currency,
            usage=(UsageQuantity(self.meter_name, self.quantity, self.unit_of_measure),),
            service=self.service_name,
            resource_id=self.resource_id,
            region=self.region,
            registry_asset_id=self.registry_asset_id,
            correction_of_source_record_id=self.correction_of_charge_id,
            correction_reason=self.correction_reason,
            citation=self.citation,
        )


@dataclass(frozen=True)
class GCPBillingRecord:
    billing_account_id: str
    export_row_id: str
    usage_start: str
    usage_end: str
    currency: str
    cost: str
    sku_id: str
    usage_amount: str
    usage_unit: str
    resource_name: str
    service_description: str
    citation: SourceCitation
    region: str = ""
    registry_asset_id: str = ""
    correction_of_export_row_id: str = ""
    correction_reason: str = ""

    def normalize(self) -> NormalizedBillingRecord:
        return NormalizedBillingRecord(
            provider=BillingProvider.GCP,
            source_account_id=self.billing_account_id,
            source_record_id=self.export_row_id,
            period_start=self.usage_start,
            period_end=self.usage_end,
            currency=self.currency,
            cost=self.cost,
            usage=(UsageQuantity(self.sku_id, self.usage_amount, self.usage_unit),),
            service=self.service_description,
            resource_id=self.resource_name,
            region=self.region,
            registry_asset_id=self.registry_asset_id,
            correction_of_source_record_id=self.correction_of_export_row_id,
            correction_reason=self.correction_reason,
            citation=self.citation,
        )


@dataclass(frozen=True)
class OpenAIBillingRecord:
    organization_id: str
    line_item_id: str
    usage_start: str
    usage_end: str
    currency: str
    cost: str
    usage_type: str
    usage_amount: str
    usage_unit: str
    project_id: str
    model: str
    citation: SourceCitation
    registry_asset_id: str = ""
    correction_of_line_item_id: str = ""
    correction_reason: str = ""

    def normalize(self) -> NormalizedBillingRecord:
        return NormalizedBillingRecord(
            provider=BillingProvider.OPENAI,
            source_account_id=self.organization_id,
            source_record_id=self.line_item_id,
            period_start=self.usage_start,
            period_end=self.usage_end,
            currency=self.currency,
            cost=self.cost,
            usage=(UsageQuantity(self.usage_type, self.usage_amount, self.usage_unit),),
            service=f"OpenAI {self.model}",
            resource_id=self.project_id,
            registry_asset_id=self.registry_asset_id,
            correction_of_source_record_id=self.correction_of_line_item_id,
            correction_reason=self.correction_reason,
            citation=self.citation,
        )


@dataclass(frozen=True)
class CollectionRequest:
    period_start: str
    period_end: str
    max_records: int = _MAX_BATCH_RECORDS

    def __post_init__(self) -> None:
        start, end = _period(self.period_start, self.period_end)
        object.__setattr__(self, "period_start", start)
        object.__setattr__(self, "period_end", end)
        if (
            isinstance(self.max_records, bool)
            or not isinstance(self.max_records, int)
            or not 1 <= self.max_records <= _MAX_BATCH_RECORDS
        ):
            raise ValueError(f"max_records must be between 1 and {_MAX_BATCH_RECORDS}")


@dataclass(frozen=True)
class BillingCollection:
    provider: BillingProvider
    collector_id: str
    source_account_id: str
    batch_id: str
    period_start: str
    period_end: str
    collected_at: float
    manifest_citation: SourceCitation
    records: tuple[NormalizedBillingRecord, ...]

    def __post_init__(self) -> None:
        provider = _provider(self.provider)
        object.__setattr__(self, "provider", provider)
        object.__setattr__(self, "collector_id", _token(self.collector_id, "collector id"))
        account = _required(self.source_account_id, "source account id", 256)
        object.__setattr__(self, "source_account_id", account)
        object.__setattr__(self, "batch_id", _required(self.batch_id, "batch id", 512))
        start, end = _period(self.period_start, self.period_end)
        object.__setattr__(self, "period_start", start)
        object.__setattr__(self, "period_end", end)
        object.__setattr__(self, "collected_at", _timestamp(self.collected_at, "collected_at"))
        if not isinstance(self.manifest_citation, SourceCitation):
            raise TypeError("manifest_citation must be a SourceCitation")
        records = tuple(self.records)
        if not records or len(records) > _MAX_BATCH_RECORDS:
            raise ValueError(
                f"collection must contain between 1 and {_MAX_BATCH_RECORDS} records"
            )
        identities: set[str] = set()
        for record in records:
            if not isinstance(record, NormalizedBillingRecord):
                raise TypeError("collection rows must be NormalizedBillingRecord values")
            if record.provider != provider or record.source_account_id != account:
                raise ValueError("collection row provider/account does not match its batch")
            if (
                _instant_value(record.period_start) < _instant_value(start)
                or _instant_value(record.period_end) > _instant_value(end)
            ):
                raise ValueError("collection row lies outside the requested source period")
            if record.source_record_id in identities:
                raise ValueError("collection contains a duplicate source record identity")
            identities.add(record.source_record_id)
        object.__setattr__(self, "records", records)


class BillingCollector(Protocol):
    """Read-only provider collector contract; credentials remain inside adapters."""

    provider: BillingProvider
    collector_id: str

    def collect(self, request: CollectionRequest) -> BillingCollection: ...


@dataclass(frozen=True)
class RegistryAllocation:
    """Verified snapshot of a cost allocation authority."""

    kind: str
    fraction: str
    department: str
    owner: str = ""
    asset_id: str = ""
    asset_revision: int = 0
    asset_digest: str = ""
    basis: str = ""

    def __post_init__(self) -> None:
        kind = str(self.kind or "").strip().lower()
        if kind not in {"asset", "shared"}:
            raise ValueError("allocation kind must be asset or shared")
        object.__setattr__(self, "kind", kind)
        fraction = _decimal(self.fraction, "allocation fraction", allow_negative=False)
        if fraction <= 0 or fraction > 1:
            raise ValueError("allocation fraction must be greater than zero and at most one")
        object.__setattr__(self, "fraction", _decimal_text(fraction, "allocation fraction"))
        object.__setattr__(
            self,
            "department",
            _required(self.department, "allocation department", 256),
        )
        object.__setattr__(self, "basis", _required(self.basis, "allocation basis", 256))
        if kind == "asset":
            if not _ASSET_RE.fullmatch(str(self.asset_id or "")):
                raise ValueError("asset allocation requires a model-risk asset id")
            if (
                isinstance(self.asset_revision, bool)
                or not isinstance(self.asset_revision, int)
                or self.asset_revision < 1
            ):
                raise ValueError("asset allocation requires a positive registry revision")
            object.__setattr__(self, "owner", _required(self.owner, "asset owner", 256))
            object.__setattr__(
                self,
                "asset_digest",
                _digest(self.asset_digest, "asset snapshot digest"),
            )
        else:
            if self.asset_id or self.asset_revision or self.asset_digest:
                raise ValueError("shared allocations cannot impersonate registry assets")
            object.__setattr__(self, "owner", _optional(self.owner, "shared owner", 256))


class AllocationResolver(Protocol):
    def resolve(self, record: NormalizedBillingRecord) -> Sequence[RegistryAllocation]: ...


class ModelRiskRegistryResolver:
    """Resolve an explicit asset hint against the governed model-risk registry.

    This adapter does not infer identities from similar names.  A collector must
    supply an exact ``MAA-...`` hint, and both an observation and declaration
    must exist.  Department comes from the declaration's bounded risk context;
    absent department metadata is retained as ``(unassigned)`` rather than
    silently allocating the cost to a guessed business unit.
    """

    def resolve(self, record: NormalizedBillingRecord) -> Sequence[RegistryAllocation]:
        if not record.registry_asset_id:
            return ()
        from . import model_risk_assurance as model_risk

        observation = model_risk.get_observation(record.registry_asset_id)
        declaration = model_risk.get_declaration(record.registry_asset_id)
        if observation is None or declaration is None:
            raise AICostStateError(
                "registry allocation requires an observed and declared AI asset"
            )
        owner = _required(declaration.get("owner"), "registry owner", 256)
        context = declaration.get("risk_context")
        if not isinstance(context, Mapping):
            context = {}
        department = str(
            context.get("department")
            or context.get("business_unit")
            or "(unassigned)"
        )
        snapshot = {
            "observation_id": observation.get("id"),
            "observation_revision": observation.get("revision"),
            "observation_snapshot_sha256": observation.get("snapshot_sha256"),
            "declaration_id": declaration.get("id"),
            "declaration_revision": declaration.get("revision"),
            "owner": owner,
            "department": department,
        }
        return (
            RegistryAllocation(
                kind="asset",
                fraction="1",
                asset_id=record.registry_asset_id,
                asset_revision=int(declaration.get("revision") or 0),
                asset_digest=_sha256(snapshot),
                owner=owner,
                department=department,
                basis="explicit_asset_id_verified_against_model_risk_registry",
            ),
        )


class _NoAllocationResolver:
    def resolve(self, _record: NormalizedBillingRecord) -> Sequence[RegistryAllocation]:
        return ()


def _allocation_rows(
    cost_text: str,
    allocations: Sequence[RegistryAllocation],
) -> list[dict[str, Any]]:
    values = tuple(allocations)
    if len(values) > _MAX_ALLOCATIONS:
        raise ValueError(f"allocation resolver exceeds {_MAX_ALLOCATIONS} entries")
    if any(not isinstance(value, RegistryAllocation) for value in values):
        raise TypeError("allocation resolver returned an untyped value")
    identities = [
        (value.kind, value.asset_id, value.department, value.owner) for value in values
    ]
    if len(set(identities)) != len(identities):
        raise ValueError("allocation resolver returned duplicate targets")
    fractions = [_decimal(value.fraction, "allocation fraction") for value in values]
    total_fraction = sum(fractions, Decimal(0))
    if total_fraction > 1:
        raise ValueError("allocation fractions exceed one")
    expanded: list[tuple[str, Decimal, RegistryAllocation | None]] = [
        (value.kind, fraction, value)
        for value, fraction in zip(values, fractions, strict=True)
    ]
    if total_fraction < 1:
        expanded.append(("unallocated", Decimal(1) - total_fraction, None))
    cost = _decimal(cost_text, "source cost")
    allocated = Decimal(0)
    rows: list[dict[str, Any]] = []
    with localcontext() as context:
        context.prec = 48
        for index, (kind, fraction, value) in enumerate(expanded):
            if index == len(expanded) - 1:
                amount = cost - allocated
            else:
                amount = (cost * fraction).quantize(
                    _MONEY_QUANTUM,
                    rounding=ROUND_HALF_EVEN,
                )
                allocated += amount
            row: dict[str, Any] = {
                "kind": kind,
                "fraction": _decimal_text(fraction, "allocation fraction"),
                "allocated_cost": _decimal_text(amount, "allocated cost"),
                "asset_id": "",
                "asset_revision": 0,
                "asset_digest": "",
                "owner": "",
                "department": "(unallocated)",
                "basis": "no_verified_registry_allocation",
            }
            if value is not None:
                row.update(
                    {
                        "asset_id": value.asset_id,
                        "asset_revision": value.asset_revision,
                        "asset_digest": value.asset_digest,
                        "owner": value.owner,
                        "department": value.department,
                        "basis": value.basis,
                    }
                )
            rows.append(row)
    if sum((_decimal(row["allocated_cost"], "allocated cost") for row in rows), Decimal(0)) != cost:
        raise AICostStateError("allocated costs do not reconcile to the source cost")
    return rows


def _bounded(store: GovernedRecordStore, label: str) -> list[dict[str, Any]]:
    rows = store.list(limit=_MAX_NAMESPACE_RECORDS + 1)
    if len(rows) > _MAX_NAMESPACE_RECORDS:
        raise AICostStateError(f"{label} exceeds its {_MAX_NAMESPACE_RECORDS}-record bound")
    return rows


def _verified_existing(
    existing: Mapping[str, Any],
    *,
    tenant_ref: str,
    payload_sha256: str,
    label: str,
) -> dict[str, Any]:
    if existing.get("tenant_ref") != tenant_ref:
        raise AICostStateError(f"{label} tenant binding is inconsistent")
    if existing.get("payload_sha256") != payload_sha256:
        raise AICostIdempotencyConflict(
            f"{label} identity was reused for different content; record a correction"
        )
    return dict(existing)


def _receipt_bindings(receipt: Mapping[str, Any]) -> dict[str, tuple[str, str]]:
    ids = receipt.get("observation_ids")
    bindings = receipt.get("observation_bindings")
    if (
        not isinstance(ids, list)
        or not isinstance(bindings, list)
        or not ids
        or len(ids) > _MAX_BATCH_RECORDS
        or len(bindings) != len(ids)
    ):
        raise AICostStateError("AI cost receipt observation binding is invalid")
    result: dict[str, tuple[str, str]] = {}
    ordered_ids: list[str] = []
    for item in bindings:
        if not isinstance(item, Mapping):
            raise AICostStateError("AI cost receipt observation binding is invalid")
        observation_id = _required(item.get("observation_id"), "observation id", 64)
        source_digest = _digest(
            item.get("source_payload_sha256"),
            "observation source payload digest",
        )
        allocation_digest = _digest(
            item.get("allocation_sha256"),
            "observation allocation digest",
        )
        if observation_id in result:
            raise AICostStateError("AI cost receipt contains a duplicate observation")
        result[observation_id] = (source_digest, allocation_digest)
        ordered_ids.append(observation_id)
    if ordered_ids != [str(item) for item in ids]:
        raise AICostStateError("AI cost receipt identities do not match their bindings")
    return result


def _validate_observation(
    row: Mapping[str, Any],
    expected_source_digest: str,
    expected_allocation_digest: str,
) -> None:
    if row.get("schema") != OBSERVATION_SCHEMA or row.get("status") != "admitted":
        raise AICostStateError("provider billing observation schema or status is invalid")
    persisted_digest = _digest(
        row.get("source_payload_sha256"),
        "observation source payload digest",
    )
    if (
        persisted_digest != expected_source_digest
        or row.get("payload_sha256") != persisted_digest
    ):
        raise AICostStateError("provider billing observation receipt digest is inconsistent")
    source_payload = {field: row.get(field) for field in _SOURCE_PAYLOAD_FIELDS}
    if _sha256(source_payload) != persisted_digest:
        raise AICostStateError("provider billing observation payload digest is inconsistent")
    allocations = row.get("allocations")
    if not isinstance(allocations, list) or not allocations:
        raise AICostStateError("AI cost allocation binding is invalid")
    try:
        allocated = sum(
            (
                _decimal(item.get("allocated_cost"), "allocated cost")
                for item in allocations
                if isinstance(item, Mapping)
            ),
            Decimal(0),
        )
    except (TypeError, ValueError) as exc:
        raise AICostStateError("AI cost allocation binding is invalid") from exc
    if any(not isinstance(item, Mapping) for item in allocations):
        raise AICostStateError("AI cost allocation binding is invalid")
    allocation_digest = _digest(
        row.get("allocation_sha256"),
        "observation allocation digest",
    )
    if allocation_digest != expected_allocation_digest or _sha256(allocations) != allocation_digest:
        raise AICostStateError("AI cost allocation digest is inconsistent")
    if allocated != _decimal(row.get("source_cost"), "source cost"):
        raise AICostStateError("AI cost allocations do not reconcile to source cost")


class AICostROIService:
    """Tenant-scoped admission, correction, assumption, and report service."""

    def __init__(
        self,
        *,
        observations: GovernedRecordStore | None = None,
        receipts: GovernedRecordStore | None = None,
        assumptions: GovernedRecordStore | None = None,
        allocation_resolver: AllocationResolver | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._observations = observations or _OBSERVATIONS
        self._receipts = receipts or _RECEIPTS
        self._assumptions = assumptions or _ASSUMPTIONS
        self._resolver = allocation_resolver or _NoAllocationResolver()
        self._clock = clock

    def _now(self) -> float:
        source = self._clock or self._receipts.authoritative_time
        return _timestamp(source(), "authority time")

    @staticmethod
    def _observation_id(record: NormalizedBillingRecord) -> str:
        return _record_id(
            "ACO",
            record.provider.value,
            record.source_account_id,
            record.source_record_id,
        )

    @staticmethod
    def _receipt_id(batch: BillingCollection) -> str:
        return _record_id(
            "ACR",
            batch.provider.value,
            batch.collector_id,
            batch.source_account_id,
            batch.batch_id,
        )

    def collect_and_ingest(
        self,
        collector: BillingCollector,
        request: CollectionRequest,
        *,
        actor: str,
    ) -> dict[str, Any]:
        _tenant_ref()
        provider = _provider(getattr(collector, "provider", ""))
        collector_id = _token(getattr(collector, "collector_id", ""), "collector id")
        try:
            batch = collector.collect(request)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise AICostProtocolError(
                f"billing collector failed without a receipt ({type(exc).__name__})"
            ) from exc
        if not isinstance(batch, BillingCollection):
            raise AICostProtocolError("collector did not return a BillingCollection")
        if batch.provider != provider or batch.collector_id != collector_id:
            raise AICostProtocolError("collector identity does not match its returned batch")
        if (
            batch.period_start != request.period_start
            or batch.period_end != request.period_end
        ):
            raise AICostProtocolError("collector did not cover the exact requested period")
        if len(batch.records) > request.max_records:
            raise AICostProtocolError("collector exceeded the requested record bound")
        return self.ingest(batch, actor=actor)

    def _completed_observation_ids(self) -> set[str]:
        tenant = _tenant_ref()
        result: set[str] = set()
        for receipt in _bounded(self._receipts, "AI cost receipt namespace"):
            if receipt.get("tenant_ref") != tenant:
                raise AICostStateError("AI cost receipt tenant binding is inconsistent")
            if receipt.get("status") != "complete":
                continue
            result.update(_receipt_bindings(receipt))
            if len(result) > _MAX_NAMESPACE_RECORDS:
                raise AICostStateError("completed observation set exceeds its report bound")
        return result

    def _ingest_observation(
        self,
        record: NormalizedBillingRecord,
        *,
        actor: str,
        tenant: str,
        completed: set[str],
    ) -> dict[str, Any]:
        from .privacy_ops import RecordConflict

        observation_id = self._observation_id(record)
        existing = self._observations.get(observation_id)
        if existing is not None:
            return _verified_existing(
                existing,
                tenant_ref=tenant,
                payload_sha256=record.payload_sha256,
                label="provider billing observation",
            )

        corrects_id = ""
        if record.correction_of_source_record_id:
            corrected = NormalizedBillingRecord(
                provider=record.provider,
                source_account_id=record.source_account_id,
                source_record_id=record.correction_of_source_record_id,
                period_start=record.period_start,
                period_end=record.period_end,
                currency=record.currency,
                cost="0",
                usage=(UsageQuantity("correction_lookup", "0", "unit"),),
                service=record.service,
                resource_id=record.resource_id,
                citation=record.citation,
            )
            corrects_id = self._observation_id(corrected)
            original = self._observations.get(corrects_id)
            if original is None or corrects_id not in completed:
                raise AICostStateError("a correction requires a completed original observation")
            if original.get("correction_of_observation_id"):
                raise ValueError("corrections must refer to an original provider line")
            for field, expected in (
                ("provider", record.provider.value),
                ("source_account_id", record.source_account_id),
                ("period_start", record.period_start),
                ("period_end", record.period_end),
                ("currency", record.currency),
                ("service", record.service),
                ("resource_id", record.resource_id),
                ("registry_asset_id", record.registry_asset_id),
            ):
                if original.get(field) != expected:
                    raise ValueError(f"correction {field} does not match the original")
            allocations = [dict(row) for row in original.get("allocations") or []]
            if not allocations:
                raise AICostStateError("original observation has no allocation binding")
        else:
            allocation_inputs = tuple(self._resolver.resolve(record))
            allocations = _allocation_rows(record.cost, allocation_inputs)

        if corrects_id:
            # Preserve the original dimension bindings, but recompute exact
            # amounts for this signed delta.
            rebound: list[RegistryAllocation] = []
            for row in allocations:
                if row.get("kind") == "unallocated":
                    continue
                rebound.append(
                    RegistryAllocation(
                        kind=str(row["kind"]),
                        fraction=str(row["fraction"]),
                        department=str(row["department"]),
                        owner=str(row.get("owner") or ""),
                        asset_id=str(row.get("asset_id") or ""),
                        asset_revision=int(row.get("asset_revision") or 0),
                        asset_digest=str(row.get("asset_digest") or ""),
                        basis=str(row.get("basis") or ""),
                    )
                )
            allocations = _allocation_rows(record.cost, rebound)

        row = {
            "id": observation_id,
            "schema": OBSERVATION_SCHEMA,
            "tenant_ref": tenant,
            **record.source_payload,
            "source_payload_sha256": record.payload_sha256,
            "payload_sha256": record.payload_sha256,
            "correction_of_observation_id": corrects_id,
            "allocations": allocations,
            "allocation_sha256": _sha256(allocations),
            "status": "admitted",
        }
        try:
            return self._observations.create(
                row,
                action=("record_ai_cost_correction" if corrects_id else "admit_ai_cost"),
                actor=_required(actor, "actor", 4096),
                max_records=_MAX_NAMESPACE_RECORDS,
            )
        except RecordConflict:
            concurrent = self._observations.get(observation_id)
            if concurrent is None:
                raise
            return _verified_existing(
                concurrent,
                tenant_ref=tenant,
                payload_sha256=record.payload_sha256,
                label="provider billing observation",
            )

    def ingest(self, batch: BillingCollection, *, actor: str) -> dict[str, Any]:
        """Admit a complete typed collection and return its durable receipt."""
        from .privacy_ops import RecordConflict

        if not isinstance(batch, BillingCollection):
            raise TypeError("batch must be a BillingCollection")
        tenant = _tenant_ref()
        actor_name = _required(actor, "actor", 4096)
        receipt_id = self._receipt_id(batch)
        normalized_digest = _sha256(
            [
                record.source_payload
                for record in sorted(
                    batch.records,
                    key=lambda item: item.source_record_id,
                )
            ]
        )
        receipt_payload = {
            "schema": RECEIPT_SCHEMA,
            "tenant_ref": tenant,
            "provider": batch.provider.value,
            "collector_id": batch.collector_id,
            "source_account_id": batch.source_account_id,
            "batch_id": batch.batch_id,
            "period_start": batch.period_start,
            "period_end": batch.period_end,
            "collected_at": batch.collected_at,
            "manifest_citation": batch.manifest_citation.to_dict(),
            "normalized_batch_sha256": normalized_digest,
            "record_count": len(batch.records),
        }
        # ``collected_at`` records when this process first admitted the stable
        # export batch.  It is intentionally outside the replay identity: a
        # retry may observe the same provider batch at a later wall-clock time
        # and must remain idempotent when its manifest and normalized rows are
        # unchanged.
        receipt_digest = _sha256(
            {
                key: value
                for key, value in receipt_payload.items()
                if key != "collected_at"
            }
        )
        existing_receipt = self._receipts.get(receipt_id)
        if existing_receipt is not None:
            return _verified_existing(
                existing_receipt,
                tenant_ref=tenant,
                payload_sha256=receipt_digest,
                label="provider billing collection receipt",
            )

        completed = self._completed_observation_ids()
        # A provider export may contain an original and its adjustment in the
        # same closed batch.  Admit originals first, then corrections, while
        # retaining source order in the receipt.  The receipt remains the
        # visibility gate, so neither row is reportable until both succeed.
        admitted_by_source_id: dict[str, dict[str, Any]] = {}
        ordered = sorted(
            batch.records,
            key=lambda item: bool(item.correction_of_source_record_id),
        )
        for record in ordered:
            admitted = self._ingest_observation(
                record,
                actor=actor_name,
                tenant=tenant,
                completed=completed,
            )
            admitted_by_source_id[record.source_record_id] = admitted
            completed.add(str(admitted["id"]))
        observations = [
            admitted_by_source_id[record.source_record_id] for record in batch.records
        ]
        observation_ids = [str(row["id"]) for row in observations]
        row = {
            "id": receipt_id,
            **receipt_payload,
            "payload_sha256": receipt_digest,
            "observation_ids": observation_ids,
            "observation_bindings": [
                {
                    "observation_id": item["id"],
                    "source_payload_sha256": item["source_payload_sha256"],
                    "allocation_sha256": item["allocation_sha256"],
                }
                for item in observations
            ],
            "completed_at": self._now(),
            "status": "complete",
        }
        try:
            return self._receipts.create(
                row,
                action="complete_ai_cost_collection",
                actor=actor_name,
                max_records=_MAX_NAMESPACE_RECORDS,
            )
        except RecordConflict:
            concurrent = self._receipts.get(receipt_id)
            if concurrent is None:
                raise
            return _verified_existing(
                concurrent,
                tenant_ref=tenant,
                payload_sha256=receipt_digest,
                label="provider billing collection receipt",
            )

    def get_observation(self, observation_id: str) -> dict[str, Any] | None:
        tenant = _tenant_ref()
        row = self._observations.get(_required(observation_id, "observation id", 64))
        if row is not None and row.get("tenant_ref") != tenant:
            raise AICostStateError("provider billing observation tenant binding is inconsistent")
        return row

    def list_receipts(self) -> list[dict[str, Any]]:
        tenant = _tenant_ref()
        rows = _bounded(self._receipts, "AI cost receipt namespace")
        if any(row.get("tenant_ref") != tenant for row in rows):
            raise AICostStateError("AI cost receipt tenant binding is inconsistent")
        return sorted(rows, key=lambda row: (str(row.get("period_start")), str(row.get("id"))))

    @staticmethod
    def _assumption_id(
        *,
        scenario: str,
        scope_kind: str,
        scope_id: str,
        period_start: str,
        period_end: str,
        currency: str,
    ) -> str:
        return _record_id(
            "ARA",
            scenario,
            scope_kind,
            scope_id,
            period_start,
            period_end,
            currency,
        )

    def upsert_roi_assumption(
        self,
        *,
        scenario: str,
        scope_kind: str,
        scope_id: str = "",
        period_start: str,
        period_end: str,
        currency: str,
        assumed_benefit: str,
        methodology: str,
        rationale: str,
        citations: Sequence[SourceCitation],
        idempotency_key: str,
        expected_revision: int,
        actor: str,
    ) -> dict[str, Any]:
        """Create or CAS-update a labelled benefit assumption.

        This namespace never accepts measured provider cost.  The resulting
        record is explicitly ``evidence_class=operator_assumption`` and reports
        preserve that label.
        """
        from .privacy_ops import RecordConflict

        tenant = _tenant_ref()
        scenario_name = _token(scenario, "scenario")
        kind = str(scope_kind or "").strip().lower()
        if kind not in {"portfolio", "department", "asset"}:
            raise ValueError("scope_kind must be portfolio, department, or asset")
        identity = _optional(scope_id, "scope id", 256)
        if kind == "portfolio" and identity:
            raise ValueError("portfolio assumptions must not specify scope_id")
        if kind != "portfolio" and not identity:
            raise ValueError(f"{kind} assumptions require scope_id")
        if kind == "asset" and not _ASSET_RE.fullmatch(identity):
            raise ValueError("asset assumption scope is not a model-risk asset id")
        start, end = _period(period_start, period_end)
        code = _currency(currency)
        benefit = _decimal_text(
            assumed_benefit,
            "assumed benefit",
            allow_negative=False,
        )
        method = _required(methodology, "methodology", 2000)
        reason = _required(rationale, "rationale", 4000)
        citation_values = tuple(citations)
        if not citation_values or len(citation_values) > 16:
            raise ValueError("ROI assumptions require between 1 and 16 citations")
        if any(not isinstance(item, SourceCitation) for item in citation_values):
            raise TypeError("ROI assumption citations must be SourceCitation values")
        key = _required(idempotency_key, "idempotency key", 256)
        if (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision < 0
        ):
            raise ValueError("expected_revision must be a non-negative integer")
        assumption_id = self._assumption_id(
            scenario=scenario_name,
            scope_kind=kind,
            scope_id=identity,
            period_start=start,
            period_end=end,
            currency=code,
        )
        payload = {
            "schema": ASSUMPTION_SCHEMA,
            "tenant_ref": tenant,
            "scenario": scenario_name,
            "scope_kind": kind,
            "scope_id": identity,
            "period_start": start,
            "period_end": end,
            "currency": code,
            "assumed_benefit": benefit,
            "methodology": method,
            "rationale": reason,
            "citations": [item.to_dict() for item in citation_values],
            "evidence_class": "operator_assumption",
        }
        request_digest = _sha256({**payload, "idempotency_key": key})
        current = self._assumptions.get(assumption_id)
        if current is None:
            if expected_revision != 0:
                raise RecordConflict("stale AI ROI assumption revision")
            try:
                return self._assumptions.create(
                    {
                        "id": assumption_id,
                        **payload,
                        "idempotency_key": key,
                        "request_sha256": request_digest,
                        "payload_sha256": _sha256(payload),
                        "status": "active",
                    },
                    action="create_ai_roi_assumption",
                    actor=_required(actor, "actor", 4096),
                    max_records=_MAX_NAMESPACE_RECORDS,
                )
            except RecordConflict:
                current = self._assumptions.get(assumption_id)
                if current is None:
                    raise
        if current.get("idempotency_key") == key:
            if current.get("request_sha256") != request_digest:
                raise AICostIdempotencyConflict(
                    "ROI assumption idempotency key was reused for different content"
                )
            return dict(current)

        def mutate(row: dict[str, Any]) -> None:
            prior_digest = str(row.get("payload_sha256") or "")
            row.update(payload)
            row["prior_payload_sha256"] = prior_digest
            row["idempotency_key"] = key
            row["request_sha256"] = request_digest
            row["payload_sha256"] = _sha256(payload)
            row["status"] = "active"

        saved = self._assumptions.update(
            assumption_id,
            mutate,
            expected_revision=expected_revision,
            action="update_ai_roi_assumption",
            actor=_required(actor, "actor", 4096),
        )
        if saved is None:
            raise AICostStateError("ROI assumption disappeared during CAS update")
        return saved

    def _report_observations(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        tenant = _tenant_ref()
        receipts = self.list_receipts()
        observation_bindings: dict[str, tuple[str, str]] = {}
        for receipt in receipts:
            if receipt.get("status") == "complete":
                for observation_id, digests in _receipt_bindings(receipt).items():
                    prior = observation_bindings.setdefault(observation_id, digests)
                    if prior != digests:
                        raise AICostStateError(
                            "completed receipts disagree on an observation digest"
                        )
        if len(observation_bindings) > _MAX_NAMESPACE_RECORDS:
            raise AICostStateError("AI cost report exceeds its observation scan bound")
        observations: list[dict[str, Any]] = []
        for observation_id in sorted(observation_bindings):
            row = self._observations.get(observation_id)
            if row is None:
                raise AICostStateError("completed receipt refers to a missing observation")
            if row.get("tenant_ref") != tenant:
                raise AICostStateError("provider billing observation tenant binding is inconsistent")
            _validate_observation(row, *observation_bindings[observation_id])
            observations.append(row)
        return observations, receipts

    @staticmethod
    def _scope_matches(allocation: Mapping[str, Any], kind: str, identity: str) -> bool:
        if kind == "portfolio":
            return True
        if kind == "department":
            return allocation.get("department") == identity
        return allocation.get("kind") == "asset" and allocation.get("asset_id") == identity

    @classmethod
    def _matching_allocations(
        cls,
        row: Mapping[str, Any],
        kind: str,
        identity: str,
    ) -> list[Mapping[str, Any]]:
        raw_allocations = row.get("allocations")
        if not isinstance(raw_allocations, list) or not raw_allocations:
            raise AICostStateError("AI cost allocation binding is invalid")
        if any(not isinstance(item, Mapping) for item in raw_allocations):
            raise AICostStateError("AI cost allocation binding is invalid")
        return [
            item
            for item in raw_allocations
            if cls._scope_matches(item, kind, identity)
        ]

    def report(
        self,
        *,
        scope_kind: str,
        scope_id: str = "",
        period_start: str,
        period_end: str,
        scenario: str | None = None,
        row_limit: int = 100,
    ) -> dict[str, Any]:
        """Build a bounded, currency-separated measured-cost/assumption report."""
        tenant = _tenant_ref()
        kind, identity = _report_scope(scope_kind, scope_id)
        start, end = _period(period_start, period_end)
        if (
            isinstance(row_limit, bool)
            or not isinstance(row_limit, int)
            or not 1 <= row_limit <= _MAX_REPORT_ROWS
        ):
            raise ValueError(f"row_limit must be between 1 and {_MAX_REPORT_ROWS}")
        scenario_name = "" if scenario is None else _token(scenario, "scenario")

        observations, receipts = self._report_observations()
        currency_buckets: dict[str, dict[str, Any]] = {}
        evidence_rows: list[dict[str, Any]] = []
        partial_periods = 0
        for row in observations:
            matching_allocations = self._matching_allocations(row, kind, identity)
            if not matching_allocations:
                continue
            row_start = _instant_value(str(row["period_start"]))
            row_end = _instant_value(str(row["period_end"]))
            report_start = _instant_value(start)
            report_end = _instant_value(end)
            overlaps = row_start < report_end and row_end > report_start
            contained = row_start >= report_start and row_end <= report_end
            if overlaps and not contained:
                partial_periods += 1
                continue
            if not contained:
                continue
            for allocation in matching_allocations:
                code = _currency(row.get("currency"))
                bucket = currency_buckets.setdefault(
                    code,
                    {
                        "currency": code,
                        "measured_cost": Decimal(0),
                        "original_cost": Decimal(0),
                        "correction_delta": Decimal(0),
                        "shared_cost": Decimal(0),
                        "unallocated_cost": Decimal(0),
                        "line_item_ids": set(),
                        "rows": {},
                        "assumed_benefit": Decimal(0),
                        "assumption_bindings": [],
                    },
                )
                amount = _decimal(allocation.get("allocated_cost"), "allocated cost")
                bucket["measured_cost"] += amount
                if row.get("correction_of_observation_id"):
                    bucket["correction_delta"] += amount
                else:
                    bucket["original_cost"] += amount
                allocation_kind = str(allocation.get("kind") or "")
                if allocation_kind == "shared":
                    bucket["shared_cost"] += amount
                if allocation_kind == "unallocated":
                    bucket["unallocated_cost"] += amount
                bucket["line_item_ids"].add(row["id"])
                row_key = (
                    allocation_kind,
                    str(allocation.get("asset_id") or ""),
                    str(allocation.get("department") or ""),
                    str(allocation.get("owner") or ""),
                )
                breakdown = bucket["rows"].setdefault(
                    row_key,
                    {
                        "kind": allocation_kind,
                        "asset_id": row_key[1],
                        "department": row_key[2],
                        "owner": row_key[3],
                        "measured_cost": Decimal(0),
                        "line_item_ids": set(),
                    },
                )
                breakdown["measured_cost"] += amount
                breakdown["line_item_ids"].add(row["id"])
                evidence_rows.append(
                    {
                        "observation_id": row["id"],
                        "source_payload_sha256": row["source_payload_sha256"],
                        "allocation_sha256": row["allocation_sha256"],
                        "citation": row["citation"],
                    }
                )

        assumptions = _bounded(self._assumptions, "AI ROI assumption namespace")
        matching_scenarios = {
            assumption.get("scenario") for assumption in assumptions
            if assumption.get("tenant_ref") == tenant
            and assumption.get("status") == "active"
            and assumption.get("scope_kind") == kind
            and assumption.get("scope_id") == identity
            and assumption.get("period_start") == start
            and assumption.get("period_end") == end
        }
        if not scenario_name and len(matching_scenarios) > 1:
            raise ValueError("Multiple ROI scenarios match; select a scenario before comparing benefits and costs")
        for assumption in assumptions:
            if assumption.get("tenant_ref") != tenant:
                raise AICostStateError("ROI assumption tenant binding is inconsistent")
            if assumption.get("status") != "active":
                continue
            if scenario_name and assumption.get("scenario") != scenario_name:
                continue
            if assumption.get("scope_kind") != kind or assumption.get("scope_id") != identity:
                continue
            if assumption.get("period_start") != start or assumption.get("period_end") != end:
                continue
            code = _currency(assumption.get("currency"))
            bucket = currency_buckets.setdefault(
                code,
                {
                    "currency": code,
                    "measured_cost": Decimal(0),
                    "original_cost": Decimal(0),
                    "correction_delta": Decimal(0),
                    "shared_cost": Decimal(0),
                    "unallocated_cost": Decimal(0),
                    "line_item_ids": set(),
                    "rows": {},
                    "assumed_benefit": Decimal(0),
                    "assumption_bindings": [],
                },
            )
            bucket["assumed_benefit"] += _decimal(
                assumption.get("assumed_benefit"),
                "assumed benefit",
                allow_negative=False,
            )
            bucket["assumption_bindings"].append(
                {
                    "assumption_id": assumption["id"],
                    "scenario": assumption["scenario"],
                    "revision": assumption["revision"],
                    "payload_sha256": assumption["payload_sha256"],
                    "evidence_class": "operator_assumption",
                }
            )

        evidence_unique = {
            (
                row["observation_id"],
                row["source_payload_sha256"],
                row["allocation_sha256"],
            ): row
            for row in evidence_rows
        }
        evidence_sorted = [evidence_unique[key] for key in sorted(evidence_unique)]
        relevant_observation_ids = {
            row["observation_id"] for row in evidence_sorted
        }
        completed_receipt_ids = sorted(
            str(receipt["id"])
            for receipt in receipts
            if receipt.get("status") == "complete"
            and relevant_observation_ids.intersection(receipt["observation_ids"])
        )
        rendered_citations = evidence_sorted[: min(row_limit, _MAX_CITATIONS)]
        currency_rows: list[dict[str, Any]] = []
        for code in sorted(currency_buckets):
            bucket = currency_buckets[code]
            measured = bucket["measured_cost"]
            benefit = bucket["assumed_benefit"]
            breakdowns = sorted(
                bucket["rows"].values(),
                key=lambda item: (
                    -abs(item["measured_cost"]),
                    item["kind"],
                    item["asset_id"],
                    item["department"],
                ),
            )
            report_rows = [
                {
                    "kind": item["kind"],
                    "asset_id": item["asset_id"],
                    "department": item["department"],
                    "owner": item["owner"],
                    "measured_cost": _decimal_text(item["measured_cost"], "measured cost"),
                    "line_item_count": len(item["line_item_ids"]),
                }
                for item in breakdowns[:row_limit]
            ]
            ratio = None
            roi_percent = None
            if measured > 0 and bucket["assumption_bindings"]:
                ratio = _decimal_text(benefit / measured, "benefit cost ratio")
                roi_percent = _decimal_text(
                    ((benefit - measured) / measured) * 100,
                    "assumption ROI percentage",
                )
            currency_rows.append(
                {
                    "currency": code,
                    "measured_cost": _decimal_text(measured, "measured cost"),
                    "original_cost": _decimal_text(bucket["original_cost"], "original cost"),
                    "correction_delta": _decimal_text(
                        bucket["correction_delta"],
                        "correction delta",
                    ),
                    "shared_cost": _decimal_text(bucket["shared_cost"], "shared cost"),
                    "unallocated_cost": _decimal_text(
                        bucket["unallocated_cost"],
                        "unallocated cost",
                    ),
                    "line_item_count": len(bucket["line_item_ids"]),
                    "assumed_benefit": _decimal_text(benefit, "assumed benefit"),
                    "benefit_evidence_class": (
                        "operator_assumption" if bucket["assumption_bindings"] else "none"
                    ),
                    "benefit_cost_ratio": ratio,
                    "assumption_roi_percent": roi_percent,
                    "assumption_bindings": sorted(
                        bucket["assumption_bindings"],
                        key=lambda item: item["assumption_id"],
                    ),
                    "breakdown": report_rows,
                    "breakdown_truncated": len(breakdowns) > row_limit,
                }
            )
        evidence_digest = _sha256(
            {
                "observations": [
                    [
                        row["observation_id"],
                        row["source_payload_sha256"],
                        row["allocation_sha256"],
                    ]
                    for row in evidence_sorted
                ],
                "assumptions": [
                    binding
                    for row in currency_rows
                    for binding in row["assumption_bindings"]
                ],
            }
        )
        return {
            "schema": REPORT_SCHEMA,
            "tenant_ref": tenant,
            "scope": {"kind": kind, "id": identity},
            "period": {"start": start, "end": end},
            "scenario": scenario_name,
            "measurement_basis": "completed_provider_billing_collection_receipts",
            "benefit_basis": "operator_assumptions_only",
            "currency_conversion": "not_performed",
            "currencies": currency_rows,
            "receipt_count": len(completed_receipt_ids),
            "receipt_ids": completed_receipt_ids[:row_limit],
            "receipt_ids_truncated": len(completed_receipt_ids) > row_limit,
            "citations": rendered_citations,
            "citations_truncated": len(evidence_sorted) > len(rendered_citations),
            "partial_period_observations_excluded": partial_periods,
            "evidence_sha256": evidence_digest,
        }

    def portfolio_report(self, **kwargs: Any) -> dict[str, Any]:
        return self.report(scope_kind="portfolio", **kwargs)

    def department_report(self, department: str, **kwargs: Any) -> dict[str, Any]:
        return self.report(scope_kind="department", scope_id=department, **kwargs)

    def asset_report(self, asset_id: str, **kwargs: Any) -> dict[str, Any]:
        return self.report(scope_kind="asset", scope_id=asset_id, **kwargs)


def enabled() -> bool:
    """Return whether this tenant explicitly enabled AI cost and ROI."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    section = config.get("ai_cost_roi")
    return isinstance(section, Mapping) and section.get("enable") is True


def require_enabled() -> None:
    if not enabled():
        raise AICostConfigError(
            "AI cost and ROI is disabled; set [ai_cost_roi] enable = true"
        )


default_service = AICostROIService(
    allocation_resolver=ModelRiskRegistryResolver(),
)


__all__ = [
    "AICostConfigError",
    "AICostError",
    "AICostIdempotencyConflict",
    "AICostProtocolError",
    "AICostROIService",
    "AICostStateError",
    "AllocationResolver",
    "AWSBillingRecord",
    "AzureBillingRecord",
    "BillingCollection",
    "BillingCollector",
    "BillingProvider",
    "CollectionRequest",
    "GCPBillingRecord",
    "ModelRiskRegistryResolver",
    "NormalizedBillingRecord",
    "OpenAIBillingRecord",
    "RegistryAllocation",
    "SourceCitation",
    "UsageQuantity",
    "default_service",
    "enabled",
    "require_enabled",
]
