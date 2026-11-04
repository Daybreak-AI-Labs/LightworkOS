"""Bounded OpenAI organization-cost collection.

This adapter reads only OpenAI's organization Costs API and normalizes complete
daily buckets into :mod:`maverick.ai_cost_roi` billing records.  The official
contract is documented at:

* https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/usage/methods/costs
* https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/usage/methods/completions

The Costs endpoint is the financial source of truth.  Although the Usage API
offers product-specific counters, its results cannot be joined losslessly to
cost line items and the OpenAI documentation warns that usage may not reconcile
perfectly with costs.  This collector therefore uses the provider-reported
``quantity`` when present and otherwise carries the exact reported cost as its
required normalized quantity.  It never fabricates model attribution.

The constructor accepts neither an endpoint nor a plaintext credential.  The
admin key is resolved from a named environment/secret reference immediately
before each read.  Redirects are disabled, the HTTPS authority and path are
fixed, pagination and response bytes are bounded, provider identifiers are
pseudonymized, and raw payloads are never returned or retained.
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
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .ai_cost_collectors import (
    AICostCollectorConfigError,
    AICostCollectorError,
    AICostCollectorLimitError,
    AICostCollectorNoData,
    AICostCollectorProtocolError,
    AICostCollectorTransportError,
    CollectorLimits,
)
from .ai_cost_roi import (
    BillingCollection,
    BillingProvider,
    CollectionRequest,
    NormalizedBillingRecord,
    SourceCitation,
    UsageQuantity,
)

OPENAI_COSTS_DOCUMENTATION_URL = (
    "https://developers.openai.com/api/reference/resources/admin/subresources/"
    "organization/subresources/usage/methods/costs"
)
OPENAI_USAGE_DOCUMENTATION_URL = (
    "https://developers.openai.com/api/reference/resources/admin/subresources/"
    "organization/subresources/usage/methods/completions"
)
OPENAI_COSTS_ENDPOINT = "https://api.openai.com/v1/organization/costs"
OPENAI_MODEL_ATTRIBUTION_UNSUPPORTED = (
    "unsupported-by-openai-organization-costs-api"
)

_OPENAI_HOST = "api.openai.com"
_OPENAI_PATH = "/v1/organization/costs"
_COLLECTOR_ID = "openai_organization_costs_v1"
_MAX_API_BUCKETS = 180
_DEFAULT_RESPONSE_BYTE_CAP = 4 * 1024 * 1024
_DEFAULT_TOTAL_BYTE_CAP = 16 * 1024 * 1024
_MAX_RESPONSE_BYTE_CAP = 16 * 1024 * 1024
_MAX_TOTAL_BYTE_CAP = 64 * 1024 * 1024
_MAX_CURSOR_BYTES = 8_192
_ENV_NAME_RE = re.compile(r"[A-Z][A-Z0-9_]{1,127}\Z")
_CURRENCY_RE = re.compile(r"[a-z]{3}\Z")
_QUANTITY_UNITS = frozenset(
    {
        "tokens",
        "1000_tokens",
        "duration_seconds",
        "duration_minutes",
        "duration_hours",
        "gibibyte_hours",
        "images",
        "characters",
    }
)
_BASE_QUERY_KEYS = frozenset(
    {"start_time", "end_time", "bucket_width", "limit", "group_by"}
)


class OpenAIHttpResponse(Protocol):
    """Minimal bounded response returned by an injected read-only transport."""

    status_code: int
    headers: Mapping[str, str]
    body: bytes
    url: str


class OpenAIHttpTransport(Protocol):
    """Injected GET transport; implementations must honor redirect and byte caps."""

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout: float,
        allow_redirects: bool,
        max_response_bytes: int,
    ) -> OpenAIHttpResponse: ...


@dataclass(frozen=True)
class _OpenAIBytesResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes
    url: str


class _NoRedirectHandler:
    """Factory wrapper that keeps urllib imports off the module import path."""

    @staticmethod
    def opener() -> Any:
        import urllib.request

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(
                self,
                _req: Any,
                _fp: Any,
                _code: int,
                _msg: str,
                _headers: Mapping[str, str],
                _newurl: str,
            ) -> None:
                return None

        return urllib.request.build_opener(NoRedirect())


class _DefaultOpenAIHttpTransport:
    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout: float,
        allow_redirects: bool,
        max_response_bytes: int,
    ) -> OpenAIHttpResponse:
        import urllib.error
        import urllib.request

        if allow_redirects:
            raise ValueError("OpenAI billing transport must not follow redirects")
        request = urllib.request.Request(url, headers=dict(headers), method="GET")
        opener = _NoRedirectHandler.opener()
        try:
            response = opener.open(request, timeout=timeout)  # noqa: S310
        except urllib.error.HTTPError as exc:
            body = exc.read(max_response_bytes + 1)
            return _OpenAIBytesResponse(
                status_code=int(exc.code),
                headers=dict(exc.headers),
                body=body,
                url=str(exc.geturl()),
            )
        with response:
            body = response.read(max_response_bytes + 1)
            return _OpenAIBytesResponse(
                status_code=int(response.status),
                headers=dict(response.headers),
                body=body,
                url=str(response.geturl()),
            )


def _sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _required_text(value: object, label: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise AICostCollectorProtocolError(f"{label} must be text")
    text = value.strip()
    if not text or len(text) > maximum or any(ord(char) < 32 for char in text):
        raise AICostCollectorProtocolError(
            f"{label} is missing, invalid, or exceeds {maximum} characters"
        )
    return text


def _config_text(value: object, label: str, maximum: int) -> str:
    try:
        return _required_text(value, label, maximum)
    except AICostCollectorProtocolError as exc:
        raise AICostCollectorConfigError(str(exc)) from exc


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise AICostCollectorProtocolError(f"{label} must be a positive integer")
    return value


def _exact_decimal(value: object, label: str, *, nonnegative: bool = False) -> str:
    if isinstance(value, bool) or isinstance(value, float):
        raise AICostCollectorProtocolError(
            f"{label} must be an exact JSON number or decimal text"
        )
    try:
        number = value if isinstance(value, Decimal) else Decimal(str(value).strip())
    except (InvalidOperation, ValueError) as exc:
        raise AICostCollectorProtocolError(f"{label} must be a finite decimal") from exc
    if (
        not number.is_finite()
        or len(number.as_tuple().digits) > 38
        or abs(number) > Decimal("1e24")
        or (nonnegative and number < 0)
    ):
        raise AICostCollectorProtocolError(f"{label} is outside its decimal bound")
    text = format(number, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def _utc_instant(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _request_window(
    request: CollectionRequest,
    limits: CollectorLimits,
    collected_at: float,
) -> tuple[datetime, datetime]:
    if not isinstance(request, CollectionRequest):
        raise TypeError("request must be a CollectionRequest")
    start = datetime.fromisoformat(request.period_start.replace("Z", "+00:00"))
    end = datetime.fromisoformat(request.period_end.replace("Z", "+00:00"))
    if start.utcoffset() != timezone.utc.utcoffset(start) or end.utcoffset() != timezone.utc.utcoffset(end):
        raise AICostCollectorConfigError("OpenAI cost periods must canonicalize to UTC")
    if any((start.hour, start.minute, start.second, start.microsecond)) or any(
        (end.hour, end.minute, end.second, end.microsecond)
    ):
        raise AICostCollectorConfigError(
            "OpenAI cost periods must use complete UTC-day boundaries"
        )
    days = (end - start).days
    if days < 1 or days > limits.max_period_days:
        raise AICostCollectorLimitError(
            f"OpenAI cost period must be between 1 and {limits.max_period_days} days"
        )
    now = datetime.fromtimestamp(collected_at, tz=timezone.utc)
    completed_through = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if end > completed_through:
        raise AICostCollectorProtocolError(
            "OpenAI cost period includes an incomplete UTC day"
        )
    return start, end


def _clock_timestamp(clock: Callable[[], float]) -> float:
    value = clock()
    if isinstance(value, bool):
        raise AICostCollectorProtocolError("collector clock returned an invalid timestamp")
    try:
        stamp = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise AICostCollectorProtocolError(
            "collector clock returned an invalid timestamp"
        ) from exc
    if not math.isfinite(stamp) or stamp <= 0:
        raise AICostCollectorProtocolError("collector clock returned an invalid timestamp")
    return stamp


def _header(headers: Mapping[str, str], name: str) -> str:
    lowered = name.lower()
    matches = [str(value).strip() for key, value in headers.items() if str(key).lower() == lowered]
    if len(matches) > 1:
        raise AICostCollectorProtocolError(f"OpenAI response repeated {name}")
    return matches[0] if matches else ""


def _safe_url(url: str, *, expect_page: bool) -> str:
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise AICostCollectorProtocolError("OpenAI URL contains an invalid port") from exc
    if (
        parsed.scheme.lower() != "https"
        or (parsed.hostname or "").lower() != _OPENAI_HOST
        or port not in (None, 443)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != _OPENAI_PATH
        or parsed.fragment
    ):
        raise AICostCollectorProtocolError(
            "OpenAI request crossed its fixed HTTPS host or path"
        )
    try:
        query = parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=8,
        )
    except ValueError as exc:
        raise AICostCollectorProtocolError("OpenAI request query is malformed") from exc
    counts: dict[str, int] = {}
    for key, value in query:
        counts[key] = counts.get(key, 0) + 1
        if not value:
            raise AICostCollectorProtocolError("OpenAI request query has a blank value")
    allowed = _BASE_QUERY_KEYS | ({"page"} if expect_page else set())
    if any(key not in allowed for key in counts):
        raise AICostCollectorProtocolError("OpenAI request query expanded its allowed scope")
    if any(counts.get(key) != 1 for key in ("start_time", "end_time", "bucket_width", "limit")):
        raise AICostCollectorProtocolError("OpenAI request query omitted a fixed parameter")
    group_values = [value for key, value in query if key == "group_by"]
    if group_values != ["project_id", "line_item"]:
        raise AICostCollectorProtocolError("OpenAI request changed its fixed grouping")
    if counts.get("page", 0) != (1 if expect_page else 0):
        raise AICostCollectorProtocolError("OpenAI request has an invalid page cursor")
    return urlunsplit(("https", _OPENAI_HOST, _OPENAI_PATH, parsed.query, ""))


def _unique_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AICostCollectorProtocolError(
                "OpenAI response contained a duplicate JSON field"
            )
        result[key] = value
    return result


def _invalid_constant(_value: str) -> None:
    raise AICostCollectorProtocolError("OpenAI response contained a non-finite number")


def _json_object(body: bytes) -> Mapping[str, Any]:
    try:
        decoded = body.decode("utf-8", errors="strict")
        value = json.loads(
            decoded,
            parse_float=Decimal,
            parse_int=int,
            parse_constant=_invalid_constant,
            object_pairs_hook=_unique_object,
        )
    except AICostCollectorError:
        raise
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise AICostCollectorProtocolError(
            "OpenAI response was not valid bounded JSON"
        ) from exc
    if not isinstance(value, Mapping):
        raise AICostCollectorProtocolError("OpenAI response must be a JSON object")
    return value


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AICostCollectorProtocolError(f"{label} must be an object")
    return value


def _sequence(value: object, label: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise AICostCollectorProtocolError(f"{label} must be an array")
    return value


def _partial_marker(value: Mapping[str, Any], label: str) -> None:
    for key in ("partial", "is_partial", "incomplete"):
        if key in value and value[key] is not False:
            raise AICostCollectorProtocolError(f"{label} was marked partial")


def _pseudonym(prefix: str, *parts: str) -> str:
    return f"{prefix}-{_sha256(list(parts))[:24]}"


def _response_byte_cap(value: object, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 64 <= value <= maximum:
        raise ValueError(f"{label} must be between 64 and {maximum}")
    return value


class OpenAIOrganizationCostCollector:
    """Read-only, complete-window collector for OpenAI organization costs."""

    provider = BillingProvider.OPENAI
    collector_id = _COLLECTOR_ID

    def __init__(
        self,
        *,
        organization_ref: str,
        enabled: bool = False,
        admin_key_env: str = "OPENAI_ADMIN_KEY",
        transport: OpenAIHttpTransport | None = None,
        limits: CollectorLimits | None = None,
        response_byte_cap: int = _DEFAULT_RESPONSE_BYTE_CAP,
        total_byte_cap: int = _DEFAULT_TOTAL_BYTE_CAP,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(enabled, bool):
            raise TypeError("enabled must be a boolean")
        organization = _config_text(organization_ref, "OpenAI organization reference", 256)
        secret_ref = _config_text(admin_key_env, "OpenAI admin key reference", 128)
        if not _ENV_NAME_RE.fullmatch(secret_ref):
            raise AICostCollectorConfigError(
                "OpenAI admin key reference must name an environment secret"
            )
        if not callable(clock):
            raise TypeError("clock must be callable")
        self.source_account_id = _pseudonym("OPENAI-ORG", organization)
        self.enabled = enabled
        self.admin_key_env = secret_ref
        self._transport = transport or _DefaultOpenAIHttpTransport()
        self.limits = limits or CollectorLimits()
        self.response_byte_cap = _response_byte_cap(
            response_byte_cap,
            "response_byte_cap",
            _MAX_RESPONSE_BYTE_CAP,
        )
        self.total_byte_cap = _response_byte_cap(
            total_byte_cap,
            "total_byte_cap",
            _MAX_TOTAL_BYTE_CAP,
        )
        if self.total_byte_cap < self.response_byte_cap:
            raise ValueError("total_byte_cap must not be smaller than response_byte_cap")
        self._clock = clock

    def _admin_key(self) -> str:
        value = os.environ.get(self.admin_key_env, "")
        if (
            not value.strip()
            or len(value) > 8_192
            or any(ord(char) < 32 for char in value)
        ):
            raise AICostCollectorConfigError(
                f"required OpenAI admin credential reference is unavailable: {self.admin_key_env}"
            )
        return value

    @staticmethod
    def _cursor(value: object) -> str:
        cursor = _required_text(value, "OpenAI next_page", _MAX_CURSOR_BYTES)
        try:
            encoded = cursor.encode("ascii")
        except UnicodeEncodeError as exc:
            raise AICostCollectorProtocolError(
                "OpenAI next_page must be an ASCII opaque cursor"
            ) from exc
        if len(encoded) > _MAX_CURSOR_BYTES:
            raise AICostCollectorLimitError("OpenAI next_page exceeded its byte bound")
        return cursor

    def _url(self, start: datetime, end: datetime, cursor: str = "") -> str:
        parameters: list[tuple[str, str]] = [
            ("start_time", str(int(start.timestamp()))),
            ("end_time", str(int(end.timestamp()))),
            ("bucket_width", "1d"),
            ("limit", str(min(self.limits.page_size, _MAX_API_BUCKETS))),
            ("group_by", "project_id"),
            ("group_by", "line_item"),
        ]
        if cursor:
            parameters.append(("page", cursor))
        return _safe_url(
            f"{OPENAI_COSTS_ENDPOINT}?{urlencode(parameters)}",
            expect_page=bool(cursor),
        )

    def _get(self, url: str, admin_key: str) -> tuple[Mapping[str, Any], int]:
        safe_url = _safe_url(url, expect_page="page=" in urlsplit(url).query)
        try:
            response = self._transport.get(
                safe_url,
                headers={
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                    "Authorization": f"Bearer {admin_key}",
                    "User-Agent": "Lightwork-OpenAI-Cost-Collector/1",
                },
                timeout=float(self.limits.timeout_seconds),
                allow_redirects=False,
                max_response_bytes=self.response_byte_cap,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except AICostCollectorError:
            raise
        except Exception as exc:
            kind = type(exc).__name__
            if isinstance(exc, TimeoutError) or "timeout" in kind.lower():
                raise AICostCollectorTransportError(
                    "OpenAI organization costs request timed out"
                ) from None
            raise AICostCollectorTransportError(
                f"OpenAI organization costs request failed ({kind})"
            ) from None

        status = getattr(response, "status_code", None)
        if isinstance(status, bool) or not isinstance(status, int):
            raise AICostCollectorProtocolError("OpenAI response status was invalid")
        body = getattr(response, "body", None)
        if not isinstance(body, bytes):
            raise AICostCollectorProtocolError("OpenAI response body must be bytes")
        if len(body) > self.response_byte_cap:
            raise AICostCollectorLimitError(
                "OpenAI response body exceeded its byte bound"
            )
        if 300 <= status < 400:
            raise AICostCollectorProtocolError("OpenAI response attempted a redirect")
        if status == 429:
            raise AICostCollectorTransportError(
                "OpenAI organization costs request was rate limited (HTTP 429)"
            )
        if status != 200:
            raise AICostCollectorTransportError(
                f"OpenAI organization costs request failed with HTTP {status}"
            )
        final_url = getattr(response, "url", None)
        if not isinstance(final_url, str) or _safe_url(
            final_url,
            expect_page="page=" in urlsplit(safe_url).query,
        ) != safe_url:
            raise AICostCollectorProtocolError(
                "OpenAI response crossed its fixed request authority"
            )
        headers = getattr(response, "headers", None)
        if not isinstance(headers, Mapping):
            raise AICostCollectorProtocolError("OpenAI response headers were invalid")
        encoding = _header(headers, "Content-Encoding").lower()
        if encoding not in {"", "identity"}:
            raise AICostCollectorProtocolError(
                "OpenAI response used an unsupported content encoding"
            )
        content_type = _header(headers, "Content-Type").lower()
        if not content_type.startswith("application/json"):
            raise AICostCollectorProtocolError(
                "OpenAI response did not use application/json"
            )
        length = _header(headers, "Content-Length")
        if length:
            if not length.isdigit():
                raise AICostCollectorProtocolError(
                    "OpenAI response Content-Length was invalid"
                )
            if int(length) > self.response_byte_cap:
                raise AICostCollectorLimitError(
                    "OpenAI response body exceeded its byte bound"
                )
        return _json_object(body), len(body)

    def _safe_result(
        self,
        result_value: object,
        *,
        bucket_start: datetime,
        bucket_end: datetime,
    ) -> dict[str, str]:
        result = _mapping(result_value, "OpenAI cost result")
        _partial_marker(result, "OpenAI cost result")
        if result.get("object") != "organization.costs.result":
            raise AICostCollectorProtocolError(
                "OpenAI cost result object discriminator was invalid"
            )
        if result.get("api_key_id") not in (None, ""):
            raise AICostCollectorProtocolError(
                "OpenAI cost result exposed an unrequested API-key identifier"
            )
        amount = _mapping(result.get("amount"), "OpenAI cost amount")
        cost = _exact_decimal(amount.get("value"), "OpenAI cost amount")
        currency = _required_text(amount.get("currency"), "OpenAI cost currency", 3)
        if not _CURRENCY_RE.fullmatch(currency):
            raise AICostCollectorProtocolError(
                "OpenAI cost currency must be lowercase ISO-4217 text"
            )

        raw_line_item = result.get("line_item")
        line_item = (
            _required_text(raw_line_item, "OpenAI line item", 160)
            if raw_line_item not in (None, "")
            else "line-item-unavailable"
        )
        raw_project = result.get("project_id")
        if raw_project in (None, ""):
            project_ref = "OPENAI-PROJECT-UNATTRIBUTED"
        else:
            project_id = _required_text(raw_project, "OpenAI project id", 256)
            project_ref = _pseudonym(
                "OPENAI-PROJECT",
                self.source_account_id,
                project_id,
            )

        quantity_value = result.get("quantity")
        quantity_unit = result.get("quantity_unit")
        if (quantity_value is None) != (quantity_unit is None):
            raise AICostCollectorProtocolError(
                "OpenAI cost quantity and quantity_unit must both be present or null"
            )
        if quantity_value is None:
            usage_metric = "provider-reported-cost; quantity-unsupported"
            usage_amount = cost
            usage_unit = currency.upper()
        else:
            usage_amount = _exact_decimal(
                quantity_value,
                "OpenAI cost quantity",
                nonnegative=True,
            )
            usage_unit = _required_text(
                quantity_unit,
                "OpenAI cost quantity_unit",
                32,
            )
            if usage_unit not in _QUANTITY_UNITS:
                raise AICostCollectorProtocolError(
                    "OpenAI cost quantity_unit is not in the documented allowlist"
                )
            usage_metric = line_item

        service = (
            f"OpenAI {line_item}; model={OPENAI_MODEL_ATTRIBUTION_UNSUPPORTED}"
        )
        row = {
            "period_start": _utc_instant(bucket_start),
            "period_end": _utc_instant(bucket_end),
            "currency": currency.upper(),
            "cost": cost,
            "usage_metric": usage_metric,
            "usage_amount": usage_amount,
            "usage_unit": usage_unit,
            "service": service,
            "resource_id": project_ref,
            "region": "unsupported-by-openai-organization-costs-api",
        }
        row["source_record_id"] = f"openai-cost-{_sha256(row)[:40]}"
        return row

    def _next_cursor(self, payload: Mapping[str, Any]) -> str:
        has_more = payload.get("has_more")
        if not isinstance(has_more, bool):
            raise AICostCollectorProtocolError("OpenAI has_more must be a boolean")
        next_value = payload.get("next_page")
        if not has_more:
            if next_value is not None:
                raise AICostCollectorProtocolError(
                    "OpenAI terminal page must have a null next_page"
                )
            return ""
        return self._cursor(next_value)

    def collect(self, request: CollectionRequest) -> BillingCollection:
        if not self.enabled:
            raise AICostCollectorConfigError("OpenAI organization cost collector is disabled")
        collected_at = _clock_timestamp(self._clock)
        start, end = _request_window(request, self.limits, collected_at)
        admin_key = self._admin_key()
        record_cap = min(request.max_records, self.limits.record_cap)
        rows: list[dict[str, str]] = []
        buckets: list[tuple[datetime, datetime]] = []
        cursor = ""
        seen_cursors: set[str] = set()
        pages = 0
        total_bytes = 0

        while True:
            pages += 1
            if pages > self.limits.page_cap:
                raise AICostCollectorLimitError(
                    "OpenAI pagination exceeded its page cap; collection is partial"
                )
            payload, response_bytes = self._get(self._url(start, end, cursor), admin_key)
            total_bytes += response_bytes
            if total_bytes > self.total_byte_cap:
                raise AICostCollectorLimitError(
                    "OpenAI pagination exceeded its total byte cap; collection is partial"
                )
            _partial_marker(payload, "OpenAI costs page")
            if payload.get("object") != "page":
                raise AICostCollectorProtocolError(
                    "OpenAI costs page object discriminator was invalid"
                )
            data = _sequence(payload.get("data"), "OpenAI costs data")
            for bucket_value in data:
                bucket = _mapping(bucket_value, "OpenAI cost bucket")
                _partial_marker(bucket, "OpenAI cost bucket")
                if bucket.get("object") != "bucket":
                    raise AICostCollectorProtocolError(
                        "OpenAI cost bucket object discriminator was invalid"
                    )
                bucket_start_seconds = _positive_int(
                    bucket.get("start_time"),
                    "OpenAI bucket start_time",
                )
                bucket_end_seconds = _positive_int(
                    bucket.get("end_time"),
                    "OpenAI bucket end_time",
                )
                bucket_start = datetime.fromtimestamp(
                    bucket_start_seconds,
                    tz=timezone.utc,
                )
                bucket_end = datetime.fromtimestamp(
                    bucket_end_seconds,
                    tz=timezone.utc,
                )
                if (
                    bucket_start.timestamp() % 86_400 != 0
                    or bucket_end.timestamp() % 86_400 != 0
                    or (bucket_end - bucket_start).total_seconds() != 86_400
                    or bucket_start < start
                    or bucket_end > end
                ):
                    raise AICostCollectorProtocolError(
                        "OpenAI cost bucket is not one complete requested UTC day"
                    )
                buckets.append((bucket_start, bucket_end))
                results = _sequence(bucket.get("results"), "OpenAI cost bucket results")
                for result_value in results:
                    if len(rows) >= record_cap:
                        raise AICostCollectorLimitError(
                            "OpenAI results exceeded the record cap; collection is partial"
                        )
                    rows.append(
                        self._safe_result(
                            result_value,
                            bucket_start=bucket_start,
                            bucket_end=bucket_end,
                        )
                    )

            next_cursor = self._next_cursor(payload)
            if not next_cursor:
                break
            if next_cursor in seen_cursors:
                raise AICostCollectorProtocolError(
                    "OpenAI pagination cursor cycle detected"
                )
            seen_cursors.add(next_cursor)
            cursor = next_cursor

        ordered_buckets = sorted(buckets)
        expected_start = start
        for bucket_start, bucket_end in ordered_buckets:
            if bucket_start != expected_start:
                raise AICostCollectorProtocolError(
                    "OpenAI costs response did not cover the complete requested period"
                )
            expected_start = bucket_end
        if expected_start != end:
            raise AICostCollectorProtocolError(
                "OpenAI costs response did not cover the complete requested period"
            )
        if len(set(ordered_buckets)) != len(ordered_buckets):
            raise AICostCollectorProtocolError(
                "OpenAI costs response repeated a daily bucket"
            )
        if not rows:
            raise AICostCollectorNoData(
                "OpenAI returned a complete period with no billable cost rows"
            )
        rows.sort(key=lambda row: row["source_record_id"])
        identities = [row["source_record_id"] for row in rows]
        if len(set(identities)) != len(identities):
            raise AICostCollectorProtocolError(
                "OpenAI costs response repeated a normalized cost identity"
            )

        manifest = {
            "provider": self.provider.value,
            "collector_id": self.collector_id,
            "source_account_id": self.source_account_id,
            "period_start": request.period_start,
            "period_end": request.period_end,
            "endpoint": OPENAI_COSTS_ENDPOINT,
            "rows": rows,
        }
        manifest_digest = _sha256(manifest)
        manifest_citation = SourceCitation(
            uri=OPENAI_COSTS_ENDPOINT,
            sha256=manifest_digest,
        )
        records = tuple(
            NormalizedBillingRecord(
                provider=self.provider,
                source_account_id=self.source_account_id,
                source_record_id=row["source_record_id"],
                period_start=row["period_start"],
                period_end=row["period_end"],
                currency=row["currency"],
                cost=row["cost"],
                usage=(
                    UsageQuantity(
                        metric=row["usage_metric"],
                        quantity=row["usage_amount"],
                        unit=row["usage_unit"],
                    ),
                ),
                service=row["service"],
                resource_id=row["resource_id"],
                region=row["region"],
                citation=SourceCitation(
                    uri=OPENAI_COSTS_ENDPOINT,
                    sha256=_sha256(row),
                    row_ref=row["source_record_id"],
                ),
            )
            for row in rows
        )
        return BillingCollection(
            provider=self.provider,
            collector_id=self.collector_id,
            source_account_id=self.source_account_id,
            batch_id=f"{self.collector_id}:{manifest_digest}",
            period_start=request.period_start,
            period_end=request.period_end,
            collected_at=collected_at,
            manifest_citation=manifest_citation,
            records=records,
        )


OpenAIOrganizationBillingCollector = OpenAIOrganizationCostCollector


__all__ = [
    "OPENAI_COSTS_DOCUMENTATION_URL",
    "OPENAI_COSTS_ENDPOINT",
    "OPENAI_MODEL_ATTRIBUTION_UNSUPPORTED",
    "OPENAI_USAGE_DOCUMENTATION_URL",
    "OpenAIHttpResponse",
    "OpenAIHttpTransport",
    "OpenAIOrganizationBillingCollector",
    "OpenAIOrganizationCostCollector",
]
