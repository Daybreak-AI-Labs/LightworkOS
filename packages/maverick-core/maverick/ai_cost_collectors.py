"""Fail-closed live collectors for governed enterprise AI billing evidence.

The collectors in :mod:`maverick.ai_cost_roi` intentionally define only the
normalization and admission boundary.  This module supplies four production
adapters whose network and SDK surfaces are fixed by the provider:

* AWS Cost Explorer ``GetCostAndUsage``;
* Azure Cost Management's subscription-scoped Query API; and
* Google Cloud's detailed Cloud Billing export in BigQuery; and
* OpenAI's organization Costs API through a separately bounded adapter.

Every adapter is disabled unless its constructor receives ``enabled=True``.
Callers provide account and service scopes, never URLs or credentials.  Live
credentials are resolved at collection time from a named environment/secret
reference and are not attached to returned rows, citations, batch identities,
or exception messages.  Pagination is consumed completely within explicit
page and row budgets; a partial, estimated, truncated, or cyclic result never
becomes a :class:`~maverick.ai_cost_roi.BillingCollection`.

OpenAI cost collection uses complete UTC-day buckets from the fixed official
Costs endpoint. It deliberately does not fabricate a model-level join to the
separate Usage API when the provider does not expose a lossless relationship.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

from .ai_cost_roi import (
    AICostError,
    AWSBillingRecord,
    AzureBillingRecord,
    BillingCollection,
    BillingCollector,
    BillingProvider,
    CollectionRequest,
    GCPBillingRecord,
    NormalizedBillingRecord,
    SourceCitation,
)

if TYPE_CHECKING:
    from .ai_cost_openai import (
        OpenAIOrganizationBillingCollector,
        OpenAIOrganizationCostCollector,
    )

_MAX_PROVIDER_PAGES = 50
_MAX_PROVIDER_RECORDS = 1_000
_MAX_PERIOD_DAYS = 366
_MAX_SERVICE_FILTERS = 32
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_MAX_PAGINATION_TOKEN = 8_192
_AWS_CE_ENDPOINT = "https://ce.us-east-1.amazonaws.com"
_AWS_STS_ENDPOINT = "https://sts.us-east-1.amazonaws.com"
_AZURE_HOST = "management.azure.com"
_AZURE_API_VERSION = "2026-06-01"
_ENV_NAME_RE = re.compile(r"[A-Z][A-Z0-9_]{1,127}\Z")
_AWS_ACCOUNT_RE = re.compile(r"[0-9]{12}\Z")
_AZURE_SUBSCRIPTION_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z"
)
_GCP_PROJECT_RE = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]\Z")
_GCP_DATASET_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,1023}\Z")
_GCP_BILLING_ACCOUNT_RE = re.compile(r"[0-9A-F]{6}-[0-9A-F]{6}-[0-9A-F]{6}\Z")

_AI_COST_KEYS = frozenset(
    {
        "enable",
        "collector_poll_seconds",
        "collector_lookback_days",
        "collector_limits",
        "aws",
        "azure",
        "gcp",
        "openai",
    }
)
_COLLECTOR_LIMIT_KEYS = frozenset(
    {
        "timeout_seconds",
        "page_cap",
        "record_cap",
        "max_period_days",
        "page_size",
        "max_bytes_billed",
    }
)
_PROVIDER_KEYS = {
    "aws": frozenset(
        {"enable", "payer_account_id", "services", "credential_ref_env"}
    ),
    "azure": frozenset({"enable", "subscription_id", "services", "token_env"}),
    "gcp": frozenset(
        {
            "enable",
            "project_id",
            "dataset_id",
            "billing_account_id",
            "services",
            "credential_ref_env",
        }
    ),
    "openai": frozenset(
        {
            "enable",
            "organization_ref",
            "admin_key_env",
            "response_byte_cap",
            "total_byte_cap",
        }
    ),
}
_DEFAULT_COLLECTOR_POLL_SECONDS = 24 * 60 * 60.0
_MIN_COLLECTOR_POLL_SECONDS = 5 * 60.0
_MAX_COLLECTOR_POLL_SECONDS = 7 * 24 * 60 * 60.0
_DEFAULT_COLLECTOR_LOOKBACK_DAYS = 1


class AICostCollectorError(AICostError):
    """Base error for a provider billing collection attempt."""


class AICostCollectorConfigError(AICostCollectorError):
    """A collector is disabled, unsafe, or missing a credential reference."""


class AICostCollectorTransportError(AICostCollectorError):
    """A provider transport failed before a complete collection existed."""


class AICostCollectorProtocolError(AICostCollectorError):
    """A provider response did not satisfy the complete typed contract."""


class AICostCollectorLimitError(AICostCollectorProtocolError):
    """A provider result exceeded a page, row, period, or response bound."""


class AICostCollectorNoData(AICostCollectorProtocolError):
    """A complete provider query contained no billable rows."""


class AICostCollectorUnsupportedError(AICostCollectorConfigError):
    """A provider path is intentionally unsupported until separately validated."""


@dataclass(frozen=True)
class CollectorLimits:
    """Hard bounds applied before any live provider collection is admitted."""

    timeout_seconds: float = 20.0
    page_cap: int = 20
    record_cap: int = _MAX_PROVIDER_RECORDS
    max_period_days: int = 93
    page_size: int = 200
    max_bytes_billed: int = 1_000_000_000

    def __post_init__(self) -> None:
        timeout = self.timeout_seconds
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise ValueError("timeout_seconds must be a finite number")
        if not math.isfinite(float(timeout)) or not 1 <= float(timeout) <= 60:
            raise ValueError("timeout_seconds must be between 1 and 60")
        for name, value, maximum in (
            ("page_cap", self.page_cap, _MAX_PROVIDER_PAGES),
            ("record_cap", self.record_cap, _MAX_PROVIDER_RECORDS),
            ("max_period_days", self.max_period_days, _MAX_PERIOD_DAYS),
            ("page_size", self.page_size, _MAX_PROVIDER_RECORDS),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
                raise ValueError(f"{name} must be between 1 and {maximum}")
        if (
            isinstance(self.max_bytes_billed, bool)
            or not isinstance(self.max_bytes_billed, int)
            or not 1_000_000 <= self.max_bytes_billed <= 100_000_000_000
        ):
            raise ValueError("max_bytes_billed must be between 1000000 and 100000000000")


@dataclass(frozen=True)
class CollectorSchedule:
    """Bounded cadence and complete-day lookback for background collection."""

    poll_seconds: float = _DEFAULT_COLLECTOR_POLL_SECONDS
    lookback_days: int = _DEFAULT_COLLECTOR_LOOKBACK_DAYS

    def __post_init__(self) -> None:
        poll = self.poll_seconds
        if isinstance(poll, bool) or not isinstance(poll, (int, float)):
            raise ValueError("collector_poll_seconds must be a finite number")
        normalized_poll = float(poll)
        if (
            not math.isfinite(normalized_poll)
            or normalized_poll < _MIN_COLLECTOR_POLL_SECONDS
            or normalized_poll > _MAX_COLLECTOR_POLL_SECONDS
        ):
            raise ValueError(
                "collector_poll_seconds must be between 300 and 604800"
            )
        lookback = self.lookback_days
        if (
            isinstance(lookback, bool)
            or not isinstance(lookback, int)
            or not 1 <= lookback <= _MAX_PERIOD_DAYS
        ):
            raise ValueError("collector_lookback_days must be between 1 and 366")
        object.__setattr__(self, "poll_seconds", normalized_poll)


def _config_table(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise AICostCollectorConfigError(f"{label} must be a table")
    return dict(value)


def _reject_config_keys(
    table: Mapping[str, Any],
    allowed: frozenset[str],
    label: str,
) -> None:
    unknown = sorted(str(key)[:128] for key in table if key not in allowed)
    if unknown:
        raise AICostCollectorConfigError(
            f"{label} contains unknown key(s): {', '.join(unknown)}"
        )


def _config_enable(table: Mapping[str, Any], label: str) -> bool:
    enabled = table.get("enable", False)
    if not isinstance(enabled, bool):
        raise AICostCollectorConfigError(f"{label}.enable must be true or false")
    return enabled


def _provider_table(section: Mapping[str, Any], provider: str) -> dict[str, Any]:
    value = section.get(provider, {})
    table = _config_table(value, f"ai_cost_roi.{provider}")
    _reject_config_keys(table, _PROVIDER_KEYS[provider], f"ai_cost_roi.{provider}")
    _config_enable(table, f"ai_cost_roi.{provider}")
    return table


def _strict_ai_cost_section(section: object) -> dict[str, Any]:
    table = _config_table(section, "ai_cost_roi")
    _reject_config_keys(table, _AI_COST_KEYS, "ai_cost_roi")
    _config_enable(table, "ai_cost_roi")
    for provider in _PROVIDER_KEYS:
        _provider_table(table, provider)
    return table


def configured_collector_limits(section: Mapping[str, Any]) -> CollectorLimits:
    """Build the shared hard limits after rejecting every unknown config key."""

    table = _strict_ai_cost_section(section)
    raw = table.get("collector_limits", {})
    limits = _config_table(raw, "ai_cost_roi.collector_limits")
    _reject_config_keys(
        limits,
        _COLLECTOR_LIMIT_KEYS,
        "ai_cost_roi.collector_limits",
    )
    try:
        return CollectorLimits(**limits)
    except (TypeError, ValueError) as exc:
        raise AICostCollectorConfigError(
            f"ai_cost_roi.collector_limits is invalid: {exc}"
        ) from exc


def configured_collector_schedule(section: Mapping[str, Any]) -> CollectorSchedule:
    """Build a bounded schedule for whole UTC-day collection windows."""

    table = _strict_ai_cost_section(section)
    limits = configured_collector_limits(table)
    try:
        schedule = CollectorSchedule(
            poll_seconds=table.get(
                "collector_poll_seconds",
                _DEFAULT_COLLECTOR_POLL_SECONDS,
            ),
            lookback_days=table.get(
                "collector_lookback_days",
                _DEFAULT_COLLECTOR_LOOKBACK_DAYS,
            ),
        )
    except (TypeError, ValueError) as exc:
        raise AICostCollectorConfigError(f"ai_cost_roi schedule is invalid: {exc}") from exc
    if schedule.lookback_days > limits.max_period_days:
        raise AICostCollectorConfigError(
            "collector_lookback_days must not exceed collector_limits.max_period_days"
        )
    return schedule


def _required(value: object, label: str, maximum: int = 512) -> str:
    text = str(value or "").strip()
    if not text or len(text) > maximum or any(ord(char) < 32 for char in text):
        raise ValueError(f"{label} is missing, invalid, or exceeds {maximum} characters")
    return text


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AICostCollectorProtocolError(f"{label} must be an object")
    return value


def _sequence(value: object, label: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise AICostCollectorProtocolError(f"{label} must be an array")
    return value


def _sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _stable_id(prefix: str, *parts: object) -> str:
    return f"{prefix}-{_sha256(list(parts))}"


def _env_name(value: object, label: str) -> str:
    name = _required(value, label, 128)
    if not _ENV_NAME_RE.fullmatch(name):
        raise AICostCollectorConfigError(f"{label} must name an environment secret reference")
    return name


def _secret(reference: str) -> str:
    value = os.environ.get(reference, "")
    if not value.strip():
        raise AICostCollectorConfigError(
            f"required credential reference is unavailable: {reference}"
        )
    return value


def _services(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes, bytearray)):
        raise TypeError("services must be a sequence of exact provider service names")
    normalized = tuple(_required(value, "provider service", 256) for value in values)
    if not normalized or len(normalized) > _MAX_SERVICE_FILTERS:
        raise ValueError(f"services must contain between 1 and {_MAX_SERVICE_FILTERS} values")
    if len(set(normalized)) != len(normalized):
        raise ValueError("provider service filters must be unique")
    return normalized


def _request(value: object) -> CollectionRequest:
    if not isinstance(value, CollectionRequest):
        raise TypeError("request must be a CollectionRequest")
    return value


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _bounded_period(
    request: CollectionRequest,
    limits: CollectorLimits,
) -> tuple[datetime, datetime]:
    start = _instant(request.period_start)
    end = _instant(request.period_end)
    if start.tzinfo is None or end.tzinfo is None:
        raise AICostCollectorProtocolError("collection periods must be offset-aware")
    if (
        start.utcoffset() != timezone.utc.utcoffset(start)
        or end.utcoffset() != timezone.utc.utcoffset(end)
    ):
        raise AICostCollectorProtocolError("collection periods must canonicalize to UTC")
    if any((start.hour, start.minute, start.second, start.microsecond)) or any(
        (end.hour, end.minute, end.second, end.microsecond)
    ):
        raise AICostCollectorConfigError(
            "live billing collection periods must use UTC midnight boundaries"
        )
    days = (end - start).days
    if days < 1 or days > limits.max_period_days:
        raise AICostCollectorLimitError(
            f"collection period must be between 1 and {limits.max_period_days} days"
        )
    return start, end


def _record_cap(request: CollectionRequest, limits: CollectorLimits) -> int:
    return min(request.max_records, limits.record_cap)


def _exact_decimal_text(value: object, label: str) -> str:
    if isinstance(value, bool) or isinstance(value, float):
        raise AICostCollectorProtocolError(
            f"{label} must be exact decimal text, Decimal, or integer"
        )
    try:
        number = Decimal(str(value).strip())
    except (InvalidOperation, ValueError) as exc:
        raise AICostCollectorProtocolError(f"{label} must be a finite decimal") from exc
    if not number.is_finite() or len(number.as_tuple().digits) > 38:
        raise AICostCollectorProtocolError(f"{label} must be a bounded finite decimal")
    text = format(number, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def _clock_value(clock: Callable[[], float]) -> float:
    value = clock()
    if isinstance(value, bool):
        raise AICostCollectorProtocolError("collector clock returned an invalid timestamp")
    try:
        stamp = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise AICostCollectorProtocolError("collector clock returned an invalid timestamp") from exc
    if not math.isfinite(stamp) or stamp <= 0:
        raise AICostCollectorProtocolError("collector clock returned an invalid timestamp")
    return stamp


def _complete_collection(
    *,
    provider: BillingProvider,
    collector_id: str,
    source_account_id: str,
    request: CollectionRequest,
    citation_uri: str,
    rows: Sequence[Mapping[str, Any]],
    records: Callable[[SourceCitation], tuple[NormalizedBillingRecord, ...]],
    clock: Callable[[], float],
) -> BillingCollection:
    if not rows:
        raise AICostCollectorNoData("provider query returned no billable rows")
    canonical_rows = sorted((dict(row) for row in rows), key=_sha256)
    manifest = {
        "provider": provider.value,
        "collector_id": collector_id,
        "source_account_id": source_account_id,
        "period_start": request.period_start,
        "period_end": request.period_end,
        "row_count": len(canonical_rows),
        "rows": canonical_rows,
    }
    digest = _sha256(manifest)
    citation = SourceCitation(uri=citation_uri, sha256=digest)
    normalized = records(citation)
    return BillingCollection(
        provider=provider,
        collector_id=collector_id,
        source_account_id=source_account_id,
        batch_id=f"{collector_id}:{digest}",
        period_start=request.period_start,
        period_end=request.period_end,
        collected_at=_clock_value(clock),
        manifest_citation=citation,
        records=normalized,
    )


class AWSCostExplorerClient(Protocol):
    def get_cost_and_usage(self, **_kwargs: Any) -> Mapping[str, Any]: ...


class AWSIdentityClient(Protocol):
    def get_caller_identity(self) -> Mapping[str, Any]: ...


class AWSCostExplorerCollector:
    """Daily AI service aggregates from AWS Cost Explorer.

    A live client is created only when collection begins.  The client uses a
    named AWS profile reference and the fixed Cost Explorer service in
    ``us-east-1``; the constructor has no endpoint or plaintext-secret input.
    """

    provider = BillingProvider.AWS
    collector_id = "aws_cost_explorer_v1"

    def __init__(
        self,
        *,
        payer_account_id: str,
        services: Sequence[str],
        enabled: bool = False,
        client: AWSCostExplorerClient | None = None,
        identity_client: AWSIdentityClient | None = None,
        credential_ref_env: str = "AWS_PROFILE",
        limits: CollectorLimits | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(enabled, bool):
            raise TypeError("enabled must be a boolean")
        account = _required(payer_account_id, "AWS payer account id", 12)
        if not _AWS_ACCOUNT_RE.fullmatch(account):
            raise AICostCollectorConfigError("AWS payer account id must contain 12 digits")
        self.payer_account_id = account
        self.services = _services(services)
        self.enabled = enabled
        self._client = client
        self._identity_client = identity_client
        self.credential_ref_env = _env_name(
            credential_ref_env,
            "AWS credential reference",
        )
        self.limits = limits or CollectorLimits()
        self._clock = clock

    def _live_clients(self) -> tuple[AWSCostExplorerClient, AWSIdentityClient]:
        if self._client is not None and self._identity_client is not None:
            return self._client, self._identity_client
        if self._client is not None or self._identity_client is not None:
            raise AICostCollectorConfigError(
                "AWS injected collection requires both Cost Explorer and STS identity clients"
            )
        profile = _secret(self.credential_ref_env).strip()
        if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", profile):
            raise AICostCollectorConfigError(
                "AWS credential reference did not resolve to a safe profile name"
            )
        try:
            import boto3  # type: ignore[import-not-found]
        except ImportError as exc:
            raise AICostCollectorConfigError(
                "AWS Cost Explorer collection requires boto3 or an injected client"
            ) from exc
        try:
            session = boto3.Session(profile_name=profile, region_name="us-east-1")
            self._client = session.client(
                "ce",
                region_name="us-east-1",
                endpoint_url=_AWS_CE_ENDPOINT,
            )
            self._identity_client = session.client(
                "sts",
                region_name="us-east-1",
                endpoint_url=_AWS_STS_ENDPOINT,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise AICostCollectorConfigError(
                f"AWS Cost Explorer client initialization failed ({type(exc).__name__})"
            ) from exc
        return self._client, self._identity_client

    def _verify_identity(self, identity_client: AWSIdentityClient) -> None:
        try:
            identity = _mapping(
                identity_client.get_caller_identity(),
                "AWS caller identity",
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except AICostCollectorError:
            raise
        except Exception as exc:
            kind = type(exc).__name__
            if isinstance(exc, TimeoutError) or "timeout" in kind.lower():
                raise AICostCollectorTransportError("AWS STS request timed out") from None
            raise AICostCollectorTransportError(
                f"AWS STS request failed ({kind})"
            ) from None
        account = _required(identity.get("Account"), "AWS caller account", 12)
        if account != self.payer_account_id:
            raise AICostCollectorProtocolError(
                "AWS caller identity does not match the configured payer account"
            )

    @staticmethod
    def _result_rows(page: Mapping[str, Any]) -> Sequence[Any]:
        return _sequence(page.get("ResultsByTime"), "AWS ResultsByTime")

    def collect(self, request: CollectionRequest) -> BillingCollection:
        request = _request(request)
        if not self.enabled:
            raise AICostCollectorConfigError("AWS Cost Explorer collector is disabled")
        start, end = _bounded_period(request, self.limits)
        client, identity_client = self._live_clients()
        self._verify_identity(identity_client)
        token = ""
        seen_tokens: set[str] = set()
        pages = 0
        cap = _record_cap(request, self.limits)
        rows: list[dict[str, str]] = []
        while True:
            if token in seen_tokens:
                raise AICostCollectorProtocolError("AWS pagination token cycle detected")
            seen_tokens.add(token)
            pages += 1
            if pages > self.limits.page_cap:
                raise AICostCollectorLimitError("AWS provider page cap exceeded")
            arguments: dict[str, Any] = {
                "TimePeriod": {
                    "Start": start.date().isoformat(),
                    "End": end.date().isoformat(),
                },
                "Granularity": "DAILY",
                "Metrics": ["UnblendedCost", "UsageQuantity"],
                "GroupBy": [
                    {"Type": "DIMENSION", "Key": "SERVICE"},
                    {"Type": "DIMENSION", "Key": "USAGE_TYPE"},
                ],
                "Filter": {
                    "Dimensions": {
                        "Key": "SERVICE",
                        "Values": list(self.services),
                    }
                },
            }
            if token:
                arguments["NextPageToken"] = token
            try:
                page = _mapping(
                    client.get_cost_and_usage(**arguments),
                    "AWS Cost Explorer page",
                )
            except (KeyboardInterrupt, SystemExit):
                raise
            except AICostCollectorError:
                raise
            except Exception as exc:
                kind = type(exc).__name__
                if isinstance(exc, TimeoutError) or "timeout" in kind.lower():
                    raise AICostCollectorTransportError(
                        "AWS Cost Explorer request timed out"
                    ) from None
                raise AICostCollectorTransportError(
                    f"AWS Cost Explorer request failed ({kind})"
                ) from None
            for result_value in self._result_rows(page):
                result = _mapping(result_value, "AWS daily result")
                if result.get("Estimated") is True:
                    raise AICostCollectorProtocolError(
                        "AWS Cost Explorer returned estimated, non-final cost data"
                    )
                period = _mapping(result.get("TimePeriod"), "AWS result TimePeriod")
                period_start = _required(period.get("Start"), "AWS period start", 10)
                period_end = _required(period.get("End"), "AWS period end", 10)
                for group_value in _sequence(result.get("Groups"), "AWS result Groups"):
                    group = _mapping(group_value, "AWS result group")
                    keys = _sequence(group.get("Keys"), "AWS group Keys")
                    if len(keys) != 2:
                        raise AICostCollectorProtocolError(
                            "AWS group did not preserve SERVICE and USAGE_TYPE bindings"
                        )
                    service = _required(keys[0], "AWS service", 256)
                    usage_type = _required(keys[1], "AWS usage type", 256)
                    if service not in self.services:
                        raise AICostCollectorProtocolError(
                            "AWS result escaped the configured service filter"
                        )
                    metrics = _mapping(group.get("Metrics"), "AWS group Metrics")
                    cost = _mapping(metrics.get("UnblendedCost"), "AWS UnblendedCost")
                    usage = _mapping(metrics.get("UsageQuantity"), "AWS UsageQuantity")
                    currency = _required(cost.get("Unit"), "AWS cost currency", 3).upper()
                    row = {
                        "line_item_id": _stable_id(
                            "aws-ce",
                            self.payer_account_id,
                            period_start,
                            period_end,
                            service,
                            usage_type,
                            currency,
                        ),
                        "usage_start": f"{period_start}T00:00:00Z",
                        "usage_end": f"{period_end}T00:00:00Z",
                        "currency": currency,
                        "unblended_cost": _exact_decimal_text(
                            cost.get("Amount"),
                            "AWS unblended cost",
                        ),
                        "usage_type": usage_type,
                        "usage_amount": _exact_decimal_text(
                            usage.get("Amount"),
                            "AWS usage quantity",
                        ),
                        "usage_unit": _required(
                            usage.get("Unit"),
                            "AWS usage unit",
                            128,
                        ),
                        "product_code": service,
                        "resource_arn": (
                            f"urn:aws:cost-explorer:group:{self.payer_account_id}:"
                            f"{_sha256([service, usage_type])[:32]}"
                        ),
                    }
                    rows.append(row)
                    if len(rows) > cap:
                        raise AICostCollectorLimitError(
                            "AWS result exceeded the complete collection record cap"
                        )
            next_value = page.get("NextPageToken")
            if next_value in (None, ""):
                break
            token = _required(next_value, "AWS next page token", _MAX_PAGINATION_TOKEN)
            if pages >= self.limits.page_cap or len(rows) >= cap:
                raise AICostCollectorLimitError(
                    "AWS result would be partial at the configured collection bound"
                )

        citation_uri = f"urn:aws:cost-explorer:{self.payer_account_id}"

        def normalize(citation: SourceCitation) -> tuple[NormalizedBillingRecord, ...]:
            return tuple(
                AWSBillingRecord(
                    payer_account_id=self.payer_account_id,
                    line_item_id=row["line_item_id"],
                    usage_start=row["usage_start"],
                    usage_end=row["usage_end"],
                    currency=row["currency"],
                    unblended_cost=row["unblended_cost"],
                    usage_type=row["usage_type"],
                    usage_amount=row["usage_amount"],
                    usage_unit=row["usage_unit"],
                    resource_arn=row["resource_arn"],
                    product_code=row["product_code"],
                    citation=SourceCitation(
                        uri=citation.uri,
                        sha256=_sha256(row),
                        row_ref=row["line_item_id"],
                    ),
                ).normalize()
                for row in rows
            )

        return _complete_collection(
            provider=self.provider,
            collector_id=self.collector_id,
            source_account_id=self.payer_account_id,
            request=request,
            citation_uri=citation_uri,
            rows=rows,
            records=normalize,
            clock=self._clock,
        )


class AzureHttpResponse(Protocol):
    status_code: int
    headers: Mapping[str, str]

    def json(self) -> Any: ...


class AzureHttpTransport(Protocol):
    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        json_body: Mapping[str, Any],
        timeout: float,
    ) -> AzureHttpResponse: ...


@dataclass(frozen=True)
class _AzureJsonResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"), parse_float=Decimal)


class _DefaultAzureHttpTransport:
    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        json_body: Mapping[str, Any],
        timeout: float,
    ) -> AzureHttpResponse:
        import urllib.error
        import urllib.request

        payload = json.dumps(
            json_body,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=payload,
            headers=dict(headers),
            method="POST",
        )
        try:
            response = urllib.request.urlopen(request, timeout=timeout)  # noqa: S310
        except urllib.error.HTTPError as exc:
            body = exc.read(_MAX_RESPONSE_BYTES + 1)
            if len(body) > _MAX_RESPONSE_BYTES:
                raise AICostCollectorLimitError("Azure response body exceeded its bound") from exc
            return _AzureJsonResponse(int(exc.code), dict(exc.headers), body)
        with response:
            body = response.read(_MAX_RESPONSE_BYTES + 1)
            if len(body) > _MAX_RESPONSE_BYTES:
                raise AICostCollectorLimitError("Azure response body exceeded its bound")
            return _AzureJsonResponse(
                int(response.status),
                dict(response.headers),
                body,
            )


def _safe_azure_next_link(next_link: object, expected_path: str) -> str:
    value = _required(next_link, "Azure nextLink", _MAX_PAGINATION_TOKEN)
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise AICostCollectorProtocolError("Azure nextLink contains an invalid port") from exc
    if (
        parsed.scheme.lower() != "https"
        or (parsed.hostname or "").lower() != _AZURE_HOST
        or port not in (None, 443)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.path.lower() != expected_path.lower()
    ):
        raise AICostCollectorProtocolError("Azure nextLink crossed its fixed provider scope")
    query = parse_qsl(parsed.query, keep_blank_values=True)
    keys = [key for key, _ in query]
    if (
        not query
        or len(keys) != len(set(keys))
        or any(key not in {"api-version", "$skiptoken"} for key in keys)
        or "$skiptoken" not in keys
        or any(not value for _, value in query)
    ):
        raise AICostCollectorProtocolError("Azure nextLink query is not an allowed cursor")
    return urlunsplit(("https", _AZURE_HOST, parsed.path, parsed.query, ""))


def _azure_day(value: object) -> tuple[str, str]:
    if isinstance(value, bool) or isinstance(value, float):
        raise AICostCollectorProtocolError("Azure UsageDate must be an exact date")
    text = str(value or "").strip()
    if re.fullmatch(r"[0-9]{8}", text):
        parsed = datetime.strptime(text, "%Y%m%d").replace(tzinfo=timezone.utc)
    else:
        try:
            candidate = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise AICostCollectorProtocolError("Azure UsageDate is invalid") from exc
        if candidate.tzinfo is None:
            candidate = candidate.replace(tzinfo=timezone.utc)
        parsed = candidate.astimezone(timezone.utc).replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0,
        )
    end = parsed + timedelta(days=1)
    return (
        parsed.isoformat().replace("+00:00", "Z"),
        end.isoformat().replace("+00:00", "Z"),
    )


class AzureCostManagementCollector:
    """Daily ActualCost aggregates for one fixed Azure subscription scope."""

    provider = BillingProvider.AZURE
    collector_id = "azure_cost_management_v1"

    def __init__(
        self,
        *,
        subscription_id: str,
        services: Sequence[str],
        enabled: bool = False,
        token_env: str = "AZURE_COST_MANAGEMENT_TOKEN",
        transport: AzureHttpTransport | None = None,
        limits: CollectorLimits | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(enabled, bool):
            raise TypeError("enabled must be a boolean")
        subscription = _required(subscription_id, "Azure subscription id", 36).lower()
        if not _AZURE_SUBSCRIPTION_RE.fullmatch(subscription):
            raise AICostCollectorConfigError("Azure subscription id must be a UUID")
        self.subscription_id = subscription
        self.services = _services(services)
        self.enabled = enabled
        self.token_env = _env_name(token_env, "Azure token reference")
        self._transport = transport or _DefaultAzureHttpTransport()
        self.limits = limits or CollectorLimits()
        self._clock = clock
        self._path = (
            f"/subscriptions/{self.subscription_id}/providers/"
            "Microsoft.CostManagement/query"
        )
        self._url = f"https://{_AZURE_HOST}{self._path}?api-version={_AZURE_API_VERSION}"

    def _post(
        self,
        url: str,
        body: Mapping[str, Any],
        token: str,
    ) -> Mapping[str, Any] | None:
        try:
            response = self._transport.post(
                url,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                json_body=body,
                timeout=float(self.limits.timeout_seconds),
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except AICostCollectorError:
            raise
        except Exception as exc:
            kind = type(exc).__name__
            if isinstance(exc, TimeoutError) or "timeout" in kind.lower():
                raise AICostCollectorTransportError(
                    "Azure Cost Management request timed out"
                ) from None
            raise AICostCollectorTransportError(
                f"Azure Cost Management request failed ({kind})"
            ) from None
        status = int(response.status_code)
        if status == 204:
            return None
        if status != 200:
            raise AICostCollectorTransportError(
                f"Azure Cost Management request failed with HTTP {status}"
            )
        try:
            return _mapping(response.json(), "Azure Cost Management response")
        except AICostCollectorError:
            raise
        except (TypeError, ValueError, UnicodeError) as exc:
            raise AICostCollectorProtocolError(
                "Azure Cost Management response was not valid JSON"
            ) from exc

    @staticmethod
    def _column_indexes(properties: Mapping[str, Any]) -> dict[str, int]:
        columns = _sequence(properties.get("columns"), "Azure columns")
        indexes: dict[str, int] = {}
        for index, column_value in enumerate(columns):
            column = _mapping(column_value, "Azure column")
            name = _required(column.get("name"), "Azure column name", 128).lower()
            if name in indexes:
                raise AICostCollectorProtocolError("Azure response repeated a column name")
            indexes[name] = index
        required = {
            "service": ("servicename",),
            "resource": ("resourceid",),
            "date": ("usagedate",),
            "currency": ("currency", "billingcurrency"),
            "cost": ("totalcost", "pretaxcost", "costinbillingcurrency"),
        }
        resolved: dict[str, int] = {}
        for label, candidates in required.items():
            matches = [indexes[name] for name in candidates if name in indexes]
            if len(matches) != 1:
                raise AICostCollectorProtocolError(
                    f"Azure response did not provide one bound {label} column"
                )
            resolved[label] = matches[0]
        resolved["width"] = len(columns)
        return resolved

    def collect(self, request: CollectionRequest) -> BillingCollection:
        request = _request(request)
        if not self.enabled:
            raise AICostCollectorConfigError("Azure Cost Management collector is disabled")
        start, end = _bounded_period(request, self.limits)
        token = _secret(self.token_env)
        inclusive_end = (end - timedelta(microseconds=1)).isoformat().replace("+00:00", "Z")
        body: Mapping[str, Any] = {
            "type": "ActualCost",
            "timeframe": "Custom",
            "timePeriod": {
                "from": start.isoformat().replace("+00:00", "Z"),
                "to": inclusive_end,
            },
            "dataset": {
                "granularity": "Daily",
                "aggregation": {
                    "totalCost": {
                        "name": "PreTaxCost",
                        "function": "Sum",
                    }
                },
                "grouping": [
                    {"type": "Dimension", "name": "ServiceName"},
                    {"type": "Dimension", "name": "ResourceId"},
                ],
                "filter": {
                    "dimensions": {
                        "name": "ServiceName",
                        "operator": "In",
                        "values": list(self.services),
                    }
                },
            },
        }
        url = self._url
        seen: set[str] = set()
        pages = 0
        cap = _record_cap(request, self.limits)
        rows: list[dict[str, str]] = []
        while True:
            marker = _sha256(url)
            if marker in seen:
                raise AICostCollectorProtocolError("Azure pagination cursor cycle detected")
            seen.add(marker)
            pages += 1
            if pages > self.limits.page_cap:
                raise AICostCollectorLimitError("Azure provider page cap exceeded")
            page = self._post(url, body, token)
            if page is None:
                if pages == 1:
                    raise AICostCollectorNoData(
                        "Azure Cost Management returned no billable rows"
                    )
                raise AICostCollectorProtocolError(
                    "Azure pagination ended with an unexpected empty response"
                )
            response_id = _required(
                page.get("id"),
                "Azure query result id",
                2048,
            ).lower()
            expected_id_prefix = (
                f"/subscriptions/{self.subscription_id}/providers/"
                "microsoft.costmanagement/query/"
            )
            if not response_id.startswith(expected_id_prefix):
                raise AICostCollectorProtocolError(
                    "Azure response escaped the configured subscription scope"
                )
            properties = _mapping(page.get("properties"), "Azure properties")
            if properties.get("partial") is True or properties.get("isPartial") is True:
                raise AICostCollectorProtocolError(
                    "Azure Cost Management marked the collection partial"
                )
            indexes = self._column_indexes(properties)
            for row_value in _sequence(properties.get("rows"), "Azure rows"):
                values = _sequence(row_value, "Azure row")
                if len(values) != indexes["width"]:
                    raise AICostCollectorProtocolError(
                        "Azure row width did not match its column bindings"
                    )
                service = _required(values[indexes["service"]], "Azure service", 256)
                if service not in self.services:
                    raise AICostCollectorProtocolError(
                        "Azure result escaped the configured service filter"
                    )
                resource = _required(
                    values[indexes["resource"]],
                    "Azure resource id",
                    1024,
                )
                usage_start, usage_end = _azure_day(values[indexes["date"]])
                currency = _required(
                    values[indexes["currency"]],
                    "Azure billing currency",
                    3,
                ).upper()
                charge_id = _stable_id(
                    "azure-cost",
                    self.subscription_id,
                    usage_start,
                    service,
                    resource,
                    currency,
                )
                rows.append(
                    {
                        "charge_id": charge_id,
                        "usage_start": usage_start,
                        "usage_end": usage_end,
                        "billing_currency": currency,
                        "cost_in_billing_currency": _exact_decimal_text(
                            values[indexes["cost"]],
                            "Azure actual cost",
                        ),
                        "meter_name": "Azure Cost Management actual-cost aggregate",
                        "quantity": "1",
                        "unit_of_measure": "aggregate",
                        "resource_id": resource,
                        "service_name": service,
                    }
                )
                if len(rows) > cap:
                    raise AICostCollectorLimitError(
                        "Azure result exceeded the complete collection record cap"
                    )
            next_link = properties.get("nextLink")
            if next_link in (None, ""):
                break
            if pages >= self.limits.page_cap or len(rows) >= cap:
                raise AICostCollectorLimitError(
                    "Azure result would be partial at the configured collection bound"
                )
            url = _safe_azure_next_link(next_link, self._path)

        citation_uri = f"https://{_AZURE_HOST}{self._path}"

        def normalize(citation: SourceCitation) -> tuple[NormalizedBillingRecord, ...]:
            return tuple(
                AzureBillingRecord(
                    billing_account_id=self.subscription_id,
                    charge_id=row["charge_id"],
                    usage_start=row["usage_start"],
                    usage_end=row["usage_end"],
                    billing_currency=row["billing_currency"],
                    cost_in_billing_currency=row["cost_in_billing_currency"],
                    meter_name=row["meter_name"],
                    quantity=row["quantity"],
                    unit_of_measure=row["unit_of_measure"],
                    resource_id=row["resource_id"],
                    service_name=row["service_name"],
                    citation=SourceCitation(
                        uri=citation.uri,
                        sha256=_sha256(row),
                        row_ref=row["charge_id"],
                    ),
                ).normalize()
                for row in rows
            )

        return _complete_collection(
            provider=self.provider,
            collector_id=self.collector_id,
            source_account_id=self.subscription_id,
            request=request,
            citation_uri=citation_uri,
            rows=rows,
            records=normalize,
            clock=self._clock,
        )


@dataclass(frozen=True)
class GCPBillingQueryResult:
    """Fully consumed BigQuery job result returned by an injected client."""

    job_id: str
    pages: tuple[tuple[Mapping[str, Any], ...], ...]
    complete: bool
    total_rows: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "job_id", _required(self.job_id, "BigQuery job id", 256))
        if not isinstance(self.complete, bool):
            raise TypeError("BigQuery complete must be a boolean")
        pages = tuple(tuple(page) for page in self.pages)
        for page in pages:
            if any(not isinstance(row, Mapping) for row in page):
                raise TypeError("BigQuery result rows must be mappings")
        object.__setattr__(self, "pages", pages)
        if self.total_rows is not None and (
            isinstance(self.total_rows, bool)
            or not isinstance(self.total_rows, int)
            or self.total_rows < 0
        ):
            raise ValueError("BigQuery total_rows must be a non-negative integer")


class GCPBillingQueryClient(Protocol):
    def query_billing_export(
        self,
        sql: str,
        *,
        parameters: Mapping[str, Any],
        timeout_seconds: float,
        page_size: int,
        page_cap: int,
        record_cap: int,
        max_bytes_billed: int,
    ) -> GCPBillingQueryResult: ...


class _DefaultGCPBillingQueryClient:
    def __init__(self, project_id: str, credential_ref_env: str) -> None:
        self.project_id = project_id
        self.credential_ref_env = credential_ref_env

    def query_billing_export(
        self,
        sql: str,
        *,
        parameters: Mapping[str, Any],
        timeout_seconds: float,
        page_size: int,
        page_cap: int,
        record_cap: int,
        max_bytes_billed: int,
    ) -> GCPBillingQueryResult:
        _secret(self.credential_ref_env)
        if os.environ.get("BIGQUERY_EMULATOR_HOST", "").strip():
            raise AICostCollectorConfigError(
                "GCP billing collection refuses BigQuery endpoint overrides"
            )
        try:
            from google.cloud import bigquery  # type: ignore[import-not-found]
        except ImportError as exc:
            raise AICostCollectorConfigError(
                "GCP billing export collection requires google-cloud-bigquery "
                "or an injected client"
            ) from exc
        config = bigquery.QueryJobConfig(
            use_legacy_sql=False,
            maximum_bytes_billed=max_bytes_billed,
            query_parameters=[
                bigquery.ScalarQueryParameter(
                    "period_start",
                    "TIMESTAMP",
                    parameters["period_start"],
                ),
                bigquery.ScalarQueryParameter(
                    "period_end",
                    "TIMESTAMP",
                    parameters["period_end"],
                ),
                bigquery.ScalarQueryParameter(
                    "billing_account_id",
                    "STRING",
                    parameters["billing_account_id"],
                ),
                bigquery.ArrayQueryParameter(
                    "services",
                    "STRING",
                    parameters["services"],
                ),
            ],
        )
        client = bigquery.Client(project=self.project_id)
        job = client.query(sql, job_config=config, timeout=timeout_seconds)
        iterator = job.result(
            timeout=timeout_seconds,
            page_size=page_size,
            max_results=record_cap + 1,
        )
        pages: list[tuple[Mapping[str, Any], ...]] = []
        count = 0
        for page in iterator.pages:
            if len(pages) >= page_cap:
                try:
                    job.cancel()
                finally:
                    raise AICostCollectorLimitError("GCP provider page cap exceeded")
            converted = tuple(dict(row.items()) for row in page)
            pages.append(converted)
            count += len(converted)
            if count > record_cap:
                try:
                    job.cancel()
                finally:
                    raise AICostCollectorLimitError(
                        "GCP result exceeded the complete collection record cap"
                    )
        total = getattr(iterator, "total_rows", None)
        if total is not None and int(total) != count:
            raise AICostCollectorLimitError(
                "GCP query result would be partial at the configured record cap"
            )
        return GCPBillingQueryResult(
            job_id=str(job.job_id),
            pages=tuple(pages),
            complete=bool(job.done()),
            total_rows=count,
        )


class GCPBillingExportCollector:
    """Detailed Google Cloud Billing export rows queried from fixed BigQuery SQL."""

    provider = BillingProvider.GCP
    collector_id = "gcp_billing_export_v1"

    def __init__(
        self,
        *,
        project_id: str,
        dataset_id: str,
        billing_account_id: str,
        services: Sequence[str],
        enabled: bool = False,
        client: GCPBillingQueryClient | None = None,
        credential_ref_env: str = "GOOGLE_APPLICATION_CREDENTIALS",
        limits: CollectorLimits | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(enabled, bool):
            raise TypeError("enabled must be a boolean")
        project = _required(project_id, "GCP project id", 30)
        if not _GCP_PROJECT_RE.fullmatch(project):
            raise AICostCollectorConfigError("GCP project id is malformed")
        dataset = _required(dataset_id, "GCP dataset id", 1024)
        if not _GCP_DATASET_RE.fullmatch(dataset):
            raise AICostCollectorConfigError("GCP dataset id is malformed")
        account = _required(billing_account_id, "GCP billing account id", 20).upper()
        if not _GCP_BILLING_ACCOUNT_RE.fullmatch(account):
            raise AICostCollectorConfigError("GCP billing account id is malformed")
        self.project_id = project
        self.dataset_id = dataset
        self.billing_account_id = account
        self.services = _services(services)
        self.enabled = enabled
        self.credential_ref_env = _env_name(
            credential_ref_env,
            "GCP credential reference",
        )
        self.limits = limits or CollectorLimits()
        self._client = client
        self._clock = clock
        table_suffix = account.replace("-", "_")
        self.table_id = f"gcp_billing_export_resource_v1_{table_suffix}"

    @property
    def table_fqn(self) -> str:
        return f"{self.project_id}.{self.dataset_id}.{self.table_id}"

    def _live_client(self) -> GCPBillingQueryClient:
        if self._client is None:
            self._client = _DefaultGCPBillingQueryClient(
                self.project_id,
                self.credential_ref_env,
            )
        return self._client

    def _sql(self) -> str:
        table = self.table_fqn
        return f"""
WITH scoped AS (
  SELECT
    billing_account_id,
    usage_start_time,
    usage_end_time,
    currency,
    cost + IFNULL((SELECT SUM(credit.amount) FROM UNNEST(credits) AS credit), 0)
      AS net_cost,
    COALESCE(sku.id, 'unattributed-sku') AS sku_id,
    COALESCE(resource.global_name, resource.name, project.id, 'unattributed')
      AS resource_name,
    service.description AS service_description,
    COALESCE(location.location, '') AS region,
    COALESCE(cost_type, 'unspecified') AS cost_type
  FROM `{table}`
  WHERE usage_start_time >= @period_start
    AND usage_end_time <= @period_end
    AND billing_account_id = @billing_account_id
    AND service.description IN UNNEST(@services)
)
SELECT
  billing_account_id,
  TO_HEX(SHA256(CONCAT(
    billing_account_id, '|', CAST(usage_start_time AS STRING), '|',
    CAST(usage_end_time AS STRING), '|', service_description, '|', sku_id, '|',
    resource_name, '|', region, '|',
    currency, '|', cost_type
  ))) AS export_row_id,
  usage_start_time,
  usage_end_time,
  currency,
  CAST(SUM(net_cost) AS STRING) AS net_cost,
  sku_id,
  CAST(COUNT(*) AS STRING) AS usage_amount,
  'billing_rows' AS usage_unit,
  resource_name,
  service_description,
  region
FROM scoped
GROUP BY
  billing_account_id,
  usage_start_time,
  usage_end_time,
  currency,
  sku_id,
  resource_name,
  service_description,
  region,
  cost_type
ORDER BY usage_start_time, export_row_id
""".strip()

    def collect(self, request: CollectionRequest) -> BillingCollection:
        request = _request(request)
        if not self.enabled:
            raise AICostCollectorConfigError("GCP billing export collector is disabled")
        _bounded_period(request, self.limits)
        cap = _record_cap(request, self.limits)
        parameters = {
            "period_start": request.period_start,
            "period_end": request.period_end,
            "billing_account_id": self.billing_account_id,
            "services": self.services,
        }
        try:
            result = self._live_client().query_billing_export(
                self._sql(),
                parameters=parameters,
                timeout_seconds=float(self.limits.timeout_seconds),
                page_size=self.limits.page_size,
                page_cap=self.limits.page_cap,
                record_cap=cap,
                max_bytes_billed=self.limits.max_bytes_billed,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except AICostCollectorError:
            raise
        except Exception as exc:
            kind = type(exc).__name__
            if isinstance(exc, TimeoutError) or "timeout" in kind.lower():
                raise AICostCollectorTransportError(
                    "GCP billing export request timed out"
                ) from None
            raise AICostCollectorTransportError(
                f"GCP billing export request failed ({kind})"
            ) from None
        if not isinstance(result, GCPBillingQueryResult):
            raise AICostCollectorProtocolError(
                "GCP client did not return a GCPBillingQueryResult"
            )
        if not result.complete:
            raise AICostCollectorProtocolError(
                "GCP billing export job did not produce a complete result"
            )
        if len(result.pages) > self.limits.page_cap:
            raise AICostCollectorLimitError("GCP provider page cap exceeded")
        row_values = [row for page in result.pages for row in page]
        if len(row_values) > cap:
            raise AICostCollectorLimitError(
                "GCP result exceeded the complete collection record cap"
            )
        if result.total_rows is not None and result.total_rows != len(row_values):
            raise AICostCollectorProtocolError(
                "GCP billing export total_rows proves the returned batch was partial"
            )
        rows: list[dict[str, str]] = []
        for row_value in row_values:
            row = _mapping(row_value, "GCP billing export row")
            account = _required(row.get("billing_account_id"), "GCP row account", 20).upper()
            if account != self.billing_account_id:
                raise AICostCollectorProtocolError(
                    "GCP row escaped the configured billing account scope"
                )
            service = _required(
                row.get("service_description"),
                "GCP service description",
                256,
            )
            if service not in self.services:
                raise AICostCollectorProtocolError(
                    "GCP result escaped the configured service filter"
                )
            rows.append(
                {
                    "export_row_id": _required(
                        row.get("export_row_id"),
                        "GCP export row id",
                        512,
                    ),
                    "usage_start": _required(
                        row.get("usage_start_time"),
                        "GCP usage start",
                        64,
                    ),
                    "usage_end": _required(
                        row.get("usage_end_time"),
                        "GCP usage end",
                        64,
                    ),
                    "currency": _required(row.get("currency"), "GCP currency", 3).upper(),
                    "cost": _exact_decimal_text(row.get("net_cost"), "GCP net cost"),
                    "sku_id": _required(row.get("sku_id"), "GCP SKU id", 256),
                    "usage_amount": _exact_decimal_text(
                        row.get("usage_amount"),
                        "GCP usage amount",
                    ),
                    "usage_unit": _required(
                        row.get("usage_unit"),
                        "GCP usage unit",
                        128,
                    ),
                    "resource_name": _required(
                        row.get("resource_name"),
                        "GCP resource name",
                        1024,
                    ),
                    "service_description": service,
                    "region": str(row.get("region") or "").strip(),
                }
            )

        citation_uri = (
            f"urn:google:cloud-billing-export:{quote(self.project_id, safe='')}:"
            f"{quote(self.dataset_id, safe='')}:{quote(self.table_id, safe='')}"
        )

        def normalize(citation: SourceCitation) -> tuple[NormalizedBillingRecord, ...]:
            return tuple(
                GCPBillingRecord(
                    billing_account_id=self.billing_account_id,
                    export_row_id=row["export_row_id"],
                    usage_start=row["usage_start"],
                    usage_end=row["usage_end"],
                    currency=row["currency"],
                    cost=row["cost"],
                    sku_id=row["sku_id"],
                    usage_amount=row["usage_amount"],
                    usage_unit=row["usage_unit"],
                    resource_name=row["resource_name"],
                    service_description=row["service_description"],
                    region=row["region"],
                    citation=SourceCitation(
                        uri=citation.uri,
                        sha256=_sha256(row),
                        row_ref=row["export_row_id"],
                    ),
                ).normalize()
                for row in rows
            )

        return _complete_collection(
            provider=self.provider,
            collector_id=self.collector_id,
            source_account_id=self.billing_account_id,
            request=request,
            citation_uri=citation_uri,
            rows=rows,
            records=normalize,
            clock=self._clock,
        )


def _provider_value(table: Mapping[str, Any], provider: str, key: str) -> Any:
    if key not in table:
        raise AICostCollectorConfigError(
            f"ai_cost_roi.{provider}.{key} is required when the collector is enabled"
        )
    return table[key]


def configured_collectors(
    section: Mapping[str, Any],
) -> tuple[BillingCollector, ...]:
    """Build explicitly enabled collectors from one strict ``ai_cost_roi`` table.

    The capability and every provider are independently default-off.  Provider
    constructors receive only named credential references and the shared,
    bounded :class:`CollectorLimits`; this factory never resolves credentials.
    """

    table = _strict_ai_cost_section(section)
    capability_enabled = _config_enable(table, "ai_cost_roi")
    limits = configured_collector_limits(table)
    collectors: list[BillingCollector] = []

    aws = _provider_table(table, "aws")
    if _config_enable(aws, "ai_cost_roi.aws"):
        collectors.append(
            AWSCostExplorerCollector(
                payer_account_id=_provider_value(
                    aws,
                    "aws",
                    "payer_account_id",
                ),
                services=_provider_value(aws, "aws", "services"),
                credential_ref_env=aws.get("credential_ref_env", "AWS_PROFILE"),
                enabled=True,
                limits=limits,
            )
        )

    azure = _provider_table(table, "azure")
    if _config_enable(azure, "ai_cost_roi.azure"):
        collectors.append(
            AzureCostManagementCollector(
                subscription_id=_provider_value(
                    azure,
                    "azure",
                    "subscription_id",
                ),
                services=_provider_value(azure, "azure", "services"),
                token_env=azure.get(
                    "token_env",
                    "AZURE_COST_MANAGEMENT_TOKEN",
                ),
                enabled=True,
                limits=limits,
            )
        )

    gcp = _provider_table(table, "gcp")
    if _config_enable(gcp, "ai_cost_roi.gcp"):
        collectors.append(
            GCPBillingExportCollector(
                project_id=_provider_value(gcp, "gcp", "project_id"),
                dataset_id=_provider_value(gcp, "gcp", "dataset_id"),
                billing_account_id=_provider_value(
                    gcp,
                    "gcp",
                    "billing_account_id",
                ),
                services=_provider_value(gcp, "gcp", "services"),
                credential_ref_env=gcp.get(
                    "credential_ref_env",
                    "GOOGLE_APPLICATION_CREDENTIALS",
                ),
                enabled=True,
                limits=limits,
            )
        )

    openai = _provider_table(table, "openai")
    if _config_enable(openai, "ai_cost_roi.openai"):
        from .ai_cost_openai import OpenAIOrganizationCostCollector

        collectors.append(
            OpenAIOrganizationCostCollector(
                organization_ref=_provider_value(
                    openai,
                    "openai",
                    "organization_ref",
                ),
                admin_key_env=openai.get("admin_key_env", "OPENAI_ADMIN_KEY"),
                response_byte_cap=openai.get(
                    "response_byte_cap",
                    4 * 1024 * 1024,
                ),
                total_byte_cap=openai.get(
                    "total_byte_cap",
                    16 * 1024 * 1024,
                ),
                enabled=True,
                limits=limits,
            )
        )

    if not capability_enabled:
        return ()
    return tuple(collectors)


configured_schedule = configured_collector_schedule


def __getattr__(name: str):
    """Lazily re-export the OpenAI collector without a circular import."""

    if name in {
        "OpenAIOrganizationBillingCollector",
        "OpenAIOrganizationCostCollector",
    }:
        from .ai_cost_openai import (
            OpenAIOrganizationBillingCollector,
            OpenAIOrganizationCostCollector,
        )

        return {
            "OpenAIOrganizationBillingCollector": OpenAIOrganizationBillingCollector,
            "OpenAIOrganizationCostCollector": OpenAIOrganizationCostCollector,
        }[name]
    raise AttributeError(name)


__all__ = [
    "AICostCollectorConfigError",
    "AICostCollectorError",
    "AICostCollectorLimitError",
    "AICostCollectorNoData",
    "AICostCollectorProtocolError",
    "AICostCollectorTransportError",
    "AICostCollectorUnsupportedError",
    "AWSCostExplorerClient",
    "AWSCostExplorerCollector",
    "AWSIdentityClient",
    "AzureCostManagementCollector",
    "AzureHttpResponse",
    "AzureHttpTransport",
    "CollectorLimits",
    "CollectorSchedule",
    "GCPBillingExportCollector",
    "GCPBillingQueryClient",
    "GCPBillingQueryResult",
    "OpenAIOrganizationBillingCollector",
    "OpenAIOrganizationCostCollector",
    "configured_collector_limits",
    "configured_collector_schedule",
    "configured_collectors",
    "configured_schedule",
]
