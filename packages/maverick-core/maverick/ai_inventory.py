"""Read-only discovery of AI assets that live outside Lightwork.

This module is deliberately not an agent Tool.  Inventory is an authority
boundary: fixed provider list operations produce typed facts, and the core
normalizer admits those facts into Model Risk observations.  An LLM never
chooses a URL, API operation, identity, version digest, or owner.

The feature is off unless ``[ai_inventory] enable = true``.  Credentials are
resolved only at request time from provider SDK configuration or named
environment variables.  Provider responses, authorization headers, and raw
configuration blobs are never written to governed records.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Literal, Protocol
from urllib.parse import quote, urlencode, urljoin, urlsplit, urlunsplit

from .governed_records import GovernedRecordStore

BindingStrength = Literal[
    "exact_artifact",
    "immutable_provider_revision",
    "observed_snapshot",
]

_BINDING_STRENGTHS = frozenset(
    {"exact_artifact", "immutable_provider_revision", "observed_snapshot"}
)
_ASSET_TYPES = frozenset({"model", "agent", "tool", "dataset", "provider"})
_CONNECTORS = (
    "agentforce",
    "azure_ai_foundry",
    "aws_sagemaker",
    "bedrock",
    "copilot_studio",
    "databricks_unity_catalog",
    "hugging_face",
    "huggingface",
    "mlflow",
    "openai",
    "replicate",
    "salesforce_agentforce",
    "sagemaker",
    "snowflake",
    "snowflake_cortex",
    "vertex_ai",
)
_RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})
_SENSITIVE_KEY = re.compile(
    r"(?:^|[_-])(?:api[_-]?key|authorization|client[_-]?secret|credential|password|"
    r"private[_-]?key|refresh[_-]?token|secret|token)(?:$|[_-])",
    re.IGNORECASE,
)
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SLUG = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_MAX_PAGE_BYTES = 2 * 1024 * 1024
_MAX_PAGE_NODES = 25_000
_MAX_DEPTH = 12
_MAX_RECORDS = 5_000
_MAX_RUNS = 5_000
_MAX_RETRY_AFTER = 60.0


class AIInventoryError(RuntimeError):
    """Base error for fail-closed inventory operations."""


class AIInventoryConfigError(AIInventoryError):
    """The feature or a connector is not configured safely."""


class DiscoveryProtocolError(AIInventoryError):
    """A provider returned a malformed or unbounded response."""


class DiscoveryTransportError(AIInventoryError):
    """A fixed provider request failed without exposing its response body."""


class DiscoveryLimitError(AIInventoryError):
    """A configured page or record limit was reached."""


class DiscoverySyncError(AIInventoryError):
    """A sync did not reach its complete-run reconciliation point."""


@dataclass(frozen=True)
class DiscoveryLimits:
    """Hard bounds shared by every adapter in one discovery call."""

    page_cap: int = 100
    record_cap: int = _MAX_RECORDS
    retry_attempts: int = 3
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        _bounded_int(self.page_cap, "page_cap", minimum=1, maximum=1_000)
        _bounded_int(self.record_cap, "record_cap", minimum=1, maximum=_MAX_RECORDS)
        _bounded_int(self.retry_attempts, "retry_attempts", minimum=1, maximum=10)
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(float(self.timeout_seconds))
            or not 0.1 <= float(self.timeout_seconds) <= 300.0
        ):
            raise ValueError("timeout_seconds must be between 0.1 and 300")


@dataclass(frozen=True)
class DiscoveredAsset:
    """One provider fact normalized for Model Risk admission."""

    asset_type: str
    source: str
    source_id: str
    display_name: str
    version_digest: str
    binding_strength: BindingStrength
    owner: str
    platform: str
    model: str
    last_seen: float
    source_url: str
    metadata: Mapping[str, Any] = field(default_factory=dict)
    dependencies: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.asset_type not in _ASSET_TYPES:
            raise ValueError("unsupported AI inventory asset_type")
        _required_text(self.source, "source", 64)
        _required_text(self.source_id, "source_id", 256)
        _required_text(self.display_name, "display_name", 256)
        if not _HEX_DIGEST.fullmatch(self.version_digest):
            raise ValueError("version_digest must be a lowercase SHA-256 digest")
        if self.binding_strength not in _BINDING_STRENGTHS:
            raise ValueError("unsupported binding_strength")
        _required_text(self.owner, "owner", 256)
        _required_text(self.platform, "platform", 128)
        _required_text(self.model, "model", 1024)
        _positive_timestamp(self.last_seen, "last_seen")
        _safe_source_url(self.source_url)
        _bounded_json(dict(self.metadata), "metadata", max_nodes=2_048)
        _assert_no_sensitive_keys(self.metadata)
        if len(self.dependencies) > 128:
            raise ValueError("dependencies exceeds 128 entries")
        for dependency in self.dependencies:
            _required_text(dependency, "dependency", 256)


@dataclass(frozen=True)
class DiscoveryResult:
    """A fully consumed provider listing; partial listings are never returned."""

    assets: tuple[DiscoveredAsset, ...]
    pages: int


class InventoryAdapter(Protocol):
    name: str
    source: str
    limits: DiscoveryLimits

    def discover(self) -> DiscoveryResult: ...


class HttpResponse(Protocol):
    status_code: int
    headers: Mapping[str, str]

    def json(self) -> Any: ...


class HttpSqlTransport(Protocol):
    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        params: Mapping[str, Any] | None,
        timeout: float,
    ) -> HttpResponse: ...

    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        json: Mapping[str, Any],
        timeout: float,
    ) -> HttpResponse: ...


class HttpTransport(Protocol):
    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        params: Mapping[str, Any] | None,
        timeout: float,
    ) -> HttpResponse: ...


class BedrockControlClient(Protocol):
    def list_custom_models(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def list_imported_models(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def list_provisioned_model_throughputs(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def list_tags_for_resource(self, **kwargs: Any) -> Mapping[str, Any]: ...


class BedrockAgentClient(Protocol):
    def list_agents(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def get_agent(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def list_tags_for_resource(self, **kwargs: Any) -> Mapping[str, Any]: ...


class ModelRiskObserver(Protocol):
    def get_observation(self, asset_id: str) -> dict[str, Any] | None: ...

    def observe_asset(self, **kwargs: Any) -> dict[str, Any]: ...


@dataclass
class _PaginationBudget:
    limits: DiscoveryLimits
    pages: int = 0
    records: int = 0

    def page(self) -> None:
        self.pages += 1
        if self.pages > self.limits.page_cap:
            raise DiscoveryLimitError("provider page cap exceeded")

    def add_records(self, count: int) -> None:
        self.records += count
        if self.records > self.limits.record_cap:
            raise DiscoveryLimitError("provider record cap exceeded")


class _DefaultHttpTransport:
    """SSRF- and enterprise-egress-aware transport used outside tests."""

    def __init__(self, connector: str) -> None:
        self._connector = connector

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        params: Mapping[str, Any] | None,
        timeout: float,
    ) -> HttpResponse:
        from .enterprise import enterprise_egress_denial
        from .tools._ssrf import BlockedHost, safe_client

        full_url = _url_with_params(url, params)
        denial = enterprise_egress_denial(full_url, tool=f"ai_inventory.{self._connector}")
        if denial:
            raise DiscoveryTransportError("provider request blocked by enterprise egress policy")
        try:
            with safe_client(full_url, timeout=timeout) as client:
                response = client.get(full_url, headers=dict(headers))
                content_length = response.headers.get("content-length")
                if content_length:
                    try:
                        declared_length = int(content_length)
                    except ValueError as exc:
                        raise DiscoveryProtocolError(
                            "provider returned an invalid Content-Length"
                        ) from exc
                    if declared_length > _MAX_PAGE_BYTES:
                        raise DiscoveryProtocolError("provider response exceeds its byte bound")
                if len(response.content) > _MAX_PAGE_BYTES:
                    raise DiscoveryProtocolError("provider response exceeds its byte bound")
                return response
        except BlockedHost as exc:
            raise DiscoveryTransportError("provider request blocked by SSRF policy") from exc

    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        json: Mapping[str, Any],
        timeout: float,
    ) -> HttpResponse:
        from .enterprise import enterprise_egress_denial
        from .tools._ssrf import BlockedHost, safe_client

        denial = enterprise_egress_denial(url, tool=f"ai_inventory.{self._connector}")
        if denial:
            raise DiscoveryTransportError("provider request blocked by enterprise egress policy")
        try:
            with safe_client(url, timeout=timeout) as client:
                response = client.post(url, headers=dict(headers), json=dict(json))
                if len(response.content) > _MAX_PAGE_BYTES:
                    raise DiscoveryProtocolError("provider response exceeds its byte bound")
                return response
        except BlockedHost as exc:
            raise DiscoveryTransportError("provider request blocked by SSRF policy") from exc


def _bounded_int(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be an integer from {minimum} to {maximum}")
    return value


def _required_text(value: Any, label: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise DiscoveryProtocolError(f"{label} must be a string")
    text = value.strip()
    if not text or len(text) > maximum or any(ord(char) < 32 for char in text):
        raise DiscoveryProtocolError(f"{label} is missing or exceeds its bound")
    return text


def _optional_text(value: Any, maximum: int, fallback: str = "unknown") -> str:
    if value is None or value == "":
        return fallback
    return _required_text(value, "provider text", maximum)


def _positive_timestamp(value: Any, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) <= 0
    ):
        raise DiscoveryProtocolError(f"{label} must be a positive timestamp")
    return float(value)


def _timestamp(value: Any, *, fallback: float) -> float:
    if value is None or value == "":
        return _positive_timestamp(fallback, "fallback timestamp")
    if isinstance(value, datetime):
        current = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        return _positive_timestamp(current.timestamp(), "provider timestamp")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = float(value)
        if number > 10_000_000_000:
            number /= 1_000.0
        return _positive_timestamp(number, "provider timestamp")
    if isinstance(value, str):
        raw = value.strip()
        if len(raw) > 128:
            raise DiscoveryProtocolError("provider timestamp exceeds its bound")
        try:
            numeric = float(raw)
        except ValueError:
            numeric = 0.0
        if numeric > 0 and math.isfinite(numeric):
            if numeric > 10_000_000_000:
                numeric /= 1_000.0
            return _positive_timestamp(numeric, "provider timestamp")
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError as exc:
            raise DiscoveryProtocolError("provider timestamp is malformed") from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return _positive_timestamp(parsed.timestamp(), "provider timestamp")
    raise DiscoveryProtocolError("provider timestamp has an unsupported type")


def _sha256(value: Any) -> str:
    body = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def _bounded_json(
    value: Any,
    label: str,
    *,
    max_nodes: int = _MAX_PAGE_NODES,
    max_depth: int = _MAX_DEPTH,
) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes or depth > max_depth:
            raise DiscoveryProtocolError(f"{label} exceeds structural bounds")
        if isinstance(current, Mapping):
            if len(current) > 2_048:
                raise DiscoveryProtocolError(f"{label} mapping is too large")
            for key, child in current.items():
                if not isinstance(key, str) or len(key) > 256:
                    raise DiscoveryProtocolError(f"{label} has an invalid key")
                stack.append((child, depth + 1))
        elif isinstance(current, (list, tuple)):
            if len(current) > _MAX_RECORDS:
                raise DiscoveryProtocolError(f"{label} array is too large")
            stack.extend((child, depth + 1) for child in current)
        elif isinstance(current, str):
            if len(current) > _MAX_PAGE_BYTES:
                raise DiscoveryProtocolError(f"{label} string is too large")
        elif current is not None and not isinstance(current, (bool, int, float, datetime)):
            raise DiscoveryProtocolError(f"{label} contains an unsupported value")
    try:
        encoded = json.dumps(value, default=str, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise DiscoveryProtocolError(f"{label} is not valid JSON") from exc
    if len(encoded) > _MAX_PAGE_BYTES:
        raise DiscoveryProtocolError(f"{label} exceeds {_MAX_PAGE_BYTES} bytes")


def _assert_no_sensitive_keys(value: Any) -> None:
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, Mapping):
            for key, child in current.items():
                if _SENSITIVE_KEY.search(str(key)):
                    raise DiscoveryProtocolError("normalized metadata contains a sensitive key")
                stack.append(child)
        elif isinstance(current, (list, tuple)):
            stack.extend(current)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise DiscoveryProtocolError(f"{label} must be an object")
    _bounded_json(value, label)
    return value


def _items(page: Mapping[str, Any], key: str) -> list[Mapping[str, Any]]:
    raw = page.get(key)
    if not isinstance(raw, list):
        raise DiscoveryProtocolError(f"provider page requires a {key} array")
    out: list[Mapping[str, Any]] = []
    for item in raw:
        if not isinstance(item, Mapping):
            raise DiscoveryProtocolError(f"provider {key} entry must be an object")
        out.append(item)
    return out


def _first_items(page: Mapping[str, Any], keys: Sequence[str]) -> list[Mapping[str, Any]]:
    for key in keys:
        if key in page:
            return _items(page, key)
    raise DiscoveryProtocolError(f"provider page requires one of: {', '.join(keys)}")


def _safe_base_url(value: str, label: str) -> str:
    raw = _required_text(value, label, 2_048).rstrip("/")
    parsed = urlsplit(raw)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise AIInventoryConfigError(f"{label} must be a credential-free HTTPS URL")
    return urlunsplit(("https", parsed.netloc, parsed.path.rstrip("/"), "", ""))


def _safe_source_url(value: str) -> str:
    return _safe_base_url(value, "source_url")


def _same_origin_next(
    base_url: str,
    candidate: Any,
    *,
    expected_path: str = "",
    expected_prefix: str = "",
) -> str:
    if bool(expected_path) == bool(expected_prefix):
        raise ValueError("provide exactly one of expected_path or expected_prefix")
    raw = _required_text(candidate, "provider next link", 8_192)
    resolved = urljoin(f"{base_url}/", raw)
    base = urlsplit(base_url)
    parsed = urlsplit(resolved)
    try:
        cross_port = parsed.port != base.port
    except ValueError as exc:
        raise DiscoveryProtocolError("provider next link has an invalid port") from exc
    path_ok = (
        parsed.path == expected_path
        if expected_path
        else parsed.path.startswith(expected_prefix)
    )
    if (
        parsed.scheme.lower() != "https"
        or parsed.hostname != base.hostname
        or cross_port
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or not path_ok
    ):
        raise DiscoveryProtocolError("provider next link crossed the configured origin")
    return resolved


def _url_with_params(url: str, params: Mapping[str, Any] | None) -> str:
    if not params:
        return url
    parsed = urlsplit(url)
    query = urlencode([(str(key), str(value)) for key, value in params.items()])
    combined = "&".join(part for part in (parsed.query, query) if part)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, combined, parsed.fragment))


def _credential(env_name: str) -> str:
    name = _required_text(env_name, "credential environment name", 128)
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{1,127}", name):
        raise AIInventoryConfigError("credential reference must be an environment name")
    value = os.environ.get(name, "")
    if not value:
        raise AIInventoryConfigError(f"required credential reference is unavailable: {name}")
    return value


def _retry_after(headers: Mapping[str, str], *, now: Callable[[], float]) -> float | None:
    raw = next((value for key, value in headers.items() if key.lower() == "retry-after"), None)
    if raw is None:
        return None
    text = str(raw).strip()
    try:
        delay = float(text)
    except ValueError:
        try:
            parsed = parsedate_to_datetime(text)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            delay = parsed.timestamp() - now()
        except (TypeError, ValueError, OverflowError):
            return None
    if not math.isfinite(delay):
        return None
    return max(0.0, min(delay, _MAX_RETRY_AFTER))


def _sleep_delay(
    attempt: int,
    headers: Mapping[str, str],
    *,
    sleep: Callable[[float], None],
    now: Callable[[], float],
) -> None:
    requested = _retry_after(headers, now=now)
    delay = requested if requested is not None else min(float(2 ** attempt), 8.0)
    sleep(delay)


def _http_json_with_headers(
    transport: HttpTransport,
    url: str,
    *,
    token_env: str,
    limits: DiscoveryLimits,
    sleep: Callable[[float], None],
    now: Callable[[], float],
    params: Mapping[str, Any] | None = None,
    extra_headers: Mapping[str, str] | None = None,
) -> tuple[Any, Mapping[str, str]]:
    """One retried, bearer-authenticated GET; the raw JSON plus headers."""
    token = _credential(token_env)
    headers = {"Accept": "application/json", "Authorization": f"Bearer {token}"}
    headers.update(dict(extra_headers or {}))
    for attempt in range(limits.retry_attempts):
        try:
            response = transport.get(
                url,
                headers=headers,
                params=params,
                timeout=float(limits.timeout_seconds),
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            if attempt + 1 >= limits.retry_attempts:
                raise DiscoveryTransportError(
                    f"provider request failed ({type(exc).__name__})"
                ) from exc
            _sleep_delay(attempt, {}, sleep=sleep, now=now)
            continue
        status = int(response.status_code)
        if status in _RETRYABLE_STATUS and attempt + 1 < limits.retry_attempts:
            _sleep_delay(attempt, response.headers, sleep=sleep, now=now)
            continue
        if not 200 <= status < 300:
            raise DiscoveryTransportError(f"provider request failed with HTTP {status}")
        try:
            page = response.json()
        except (TypeError, ValueError) as exc:
            raise DiscoveryProtocolError("provider response was not JSON") from exc
        return page, {str(key): str(value) for key, value in response.headers.items()}
    raise DiscoveryTransportError("provider retry budget exhausted")


def _http_json(
    transport: HttpTransport,
    url: str,
    *,
    token_env: str,
    limits: DiscoveryLimits,
    sleep: Callable[[float], None],
    now: Callable[[], float],
    params: Mapping[str, Any] | None = None,
    extra_headers: Mapping[str, str] | None = None,
) -> Mapping[str, Any]:
    page, _headers = _http_json_with_headers(
        transport,
        url,
        token_env=token_env,
        limits=limits,
        sleep=sleep,
        now=now,
        params=params,
        extra_headers=extra_headers,
    )
    return _mapping(page, "provider page")


def _owner_from_tags(value: Any) -> str:
    if isinstance(value, Mapping):
        candidates = value.items()
    elif isinstance(value, list):
        candidates = (
            (item.get("key"), item.get("value"))
            for item in value
            if isinstance(item, Mapping)
        )
    else:
        return "unknown"
    preferred = {"owner", "lightwork:owner", "team", "responsible_owner"}
    for key, candidate in candidates:
        if str(key).strip().lower() in preferred and candidate:
            return _optional_text(candidate, 256)
    return "unknown"


def _selected_metadata(**values: Any) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    for key, value in values.items():
        if value is None or value == "" or value == [] or value == {}:
            continue
        if _SENSITIVE_KEY.search(key):
            raise DiscoveryProtocolError("connector attempted to normalize a sensitive field")
        metadata[key] = value
    _bounded_json(metadata, "normalized provider metadata", max_nodes=2_048)
    _assert_no_sensitive_keys(metadata)
    return metadata


def _asset(
    *,
    asset_type: str,
    source: str,
    source_id: Any,
    display_name: Any,
    version_authority: Any,
    binding_strength: BindingStrength,
    owner: Any,
    platform: str,
    model: Any,
    last_seen: Any,
    fallback_time: float,
    source_url: str,
    metadata: Mapping[str, Any] | None = None,
    dependencies: Sequence[str] = (),
) -> DiscoveredAsset:
    identity = _required_text(source_id, "provider source id", 256)
    name = _required_text(display_name, "provider display name", 256)
    model_name = _optional_text(model, 1_024)
    authority = version_authority
    if binding_strength == "exact_artifact":
        if not isinstance(authority, str) or not _HEX_DIGEST.fullmatch(
            authority.strip().lower()
        ):
            raise DiscoveryProtocolError(
                "exact_artifact binding requires a provider SHA-256 digest"
            )
        digest = authority.strip().lower()
    else:
        digest = _sha256(authority)
    return DiscoveredAsset(
        asset_type=asset_type,
        source=source,
        source_id=identity,
        display_name=name,
        version_digest=digest,
        binding_strength=binding_strength,
        owner=_optional_text(owner, 256),
        platform=platform,
        model=model_name,
        last_seen=_timestamp(last_seen, fallback=fallback_time),
        source_url=_safe_source_url(source_url),
        metadata=dict(metadata or {}),
        dependencies=tuple(_required_text(item, "dependency", 256) for item in dependencies),
    )


class _HttpAdapter:
    name = "http"
    source = "http"

    def __init__(
        self,
        *,
        base_url: str,
        token_env: str,
        transport: HttpTransport | None,
        limits: DiscoveryLimits | None,
        sleep: Callable[[float], None],
        clock: Callable[[], float],
    ) -> None:
        self.base_url = _safe_base_url(base_url, f"{self.name} base URL")
        self.token_env = _required_text(token_env, "token environment name", 128)
        self.transport = transport or _DefaultHttpTransport(self.name)
        self.limits = limits or DiscoveryLimits()
        self._sleep = sleep
        self._clock = clock

    def _get(
        self,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        extra_headers: Mapping[str, str] | None = None,
    ) -> Mapping[str, Any]:
        return _http_json(
            self.transport,
            url,
            token_env=self.token_env,
            limits=self.limits,
            sleep=self._sleep,
            now=self._clock,
            params=params,
            extra_headers=extra_headers,
        )


def _sdk_exception_details(exc: Exception) -> tuple[int, str, Mapping[str, str]]:
    response = getattr(exc, "response", None)
    if not isinstance(response, Mapping):
        return 0, "", {}
    metadata = response.get("ResponseMetadata")
    error = response.get("Error")
    status = 0
    headers: Mapping[str, str] = {}
    code = ""
    if isinstance(metadata, Mapping):
        raw_status = metadata.get("HTTPStatusCode")
        if isinstance(raw_status, int) and not isinstance(raw_status, bool):
            status = raw_status
        raw_headers = metadata.get("HTTPHeaders")
        if isinstance(raw_headers, Mapping):
            headers = {str(key): str(value) for key, value in raw_headers.items()}
    if isinstance(error, Mapping):
        code = str(error.get("Code") or "")[:128]
    return status, code, headers


def _sdk_call(
    method: Callable[..., Mapping[str, Any]],
    kwargs: Mapping[str, Any],
    *,
    limits: DiscoveryLimits,
    sleep: Callable[[float], None],
    now: Callable[[], float],
) -> Mapping[str, Any]:
    for attempt in range(limits.retry_attempts):
        try:
            return _mapping(method(**dict(kwargs)), "Bedrock page")
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            status, code, headers = _sdk_exception_details(exc)
            retryable = (
                status in _RETRYABLE_STATUS
                or code
                in {
                    "InternalServerException",
                    "ServiceUnavailableException",
                    "ThrottlingException",
                    "TooManyRequestsException",
                }
                or not status
            )
            if not retryable or attempt + 1 >= limits.retry_attempts:
                detail = code or type(exc).__name__
                raise DiscoveryTransportError(f"Bedrock operation failed ({detail})") from exc
            _sleep_delay(attempt, headers, sleep=sleep, now=now)
    raise DiscoveryTransportError("Bedrock retry budget exhausted")


class BedrockInventoryAdapter:
    """AWS Bedrock customer-owned models, provisioned models, and agents.

    The global foundation-model catalogue is intentionally excluded: it is not
    the customer's deployed estate.  SDK clients are injected in tests and may
    be omitted in production, where boto3 is imported lazily and uses its
    standard environment/profile/role credential references.
    """

    name = "bedrock"
    source = "aws_bedrock"

    def __init__(
        self,
        *,
        control_client: BedrockControlClient | None = None,
        agent_client: BedrockAgentClient | None = None,
        region: str | None = None,
        limits: DiscoveryLimits | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._control_client = control_client
        self._agent_client = agent_client
        self.region = (
            region
            or os.environ.get("AWS_REGION")
            or os.environ.get("AWS_DEFAULT_REGION")
            or ""
        ).strip()
        if self.region and not re.fullmatch(r"[a-z0-9-]{2,32}", self.region):
            raise AIInventoryConfigError("AWS region is malformed")
        self.limits = limits or DiscoveryLimits()
        self._sleep = sleep
        self._clock = clock

    def _clients(self) -> tuple[BedrockControlClient, BedrockAgentClient]:
        if self._control_client is not None and self._agent_client is not None:
            return self._control_client, self._agent_client
        try:
            import boto3  # type: ignore[import-not-found]
        except ImportError as exc:
            raise AIInventoryConfigError(
                "Bedrock inventory requires boto3 or injected Bedrock clients"
            ) from exc
        profile = os.environ.get("AWS_PROFILE", "").strip() or None
        session = boto3.Session(profile_name=profile, region_name=self.region or None)
        self._control_client = self._control_client or session.client("bedrock")
        self._agent_client = self._agent_client or session.client("bedrock-agent")
        return self._control_client, self._agent_client

    def _pages(
        self,
        method: Callable[..., Mapping[str, Any]],
        item_key: str,
        budget: _PaginationBudget,
    ) -> list[Mapping[str, Any]]:
        token = ""
        seen: set[str] = set()
        out: list[Mapping[str, Any]] = []
        while True:
            if token in seen:
                raise DiscoveryProtocolError("Bedrock pagination token cycle detected")
            seen.add(token)
            budget.page()
            kwargs: dict[str, Any] = {"maxResults": 100}
            if token:
                kwargs["nextToken"] = token
            page = _sdk_call(
                method,
                kwargs,
                limits=self.limits,
                sleep=self._sleep,
                now=self._clock,
            )
            rows = _items(page, item_key)
            budget.add_records(len(rows))
            out.extend(rows)
            raw_token = page.get("nextToken")
            if raw_token in (None, ""):
                return out
            token = _required_text(raw_token, "Bedrock nextToken", 4_096)

    def _tags(self, client: Any, arn: str, *, agent: bool = False) -> Any:
        method = getattr(client, "list_tags_for_resource", None)
        if not callable(method):
            return {}
        key = "resourceArn" if agent else "resourceARN"
        page = _sdk_call(
            method,
            {key: arn},
            limits=self.limits,
            sleep=self._sleep,
            now=self._clock,
        )
        return page.get("tags") or page.get("Tags") or {}

    def _console_url(self, kind: str, identifier: str) -> str:
        region = self.region or "us-east-1"
        safe_id = quote(identifier, safe="")
        return f"https://console.aws.amazon.com/bedrock/home/{region}/{kind}/{safe_id}"

    def _custom_asset(self, row: Mapping[str, Any], control: Any, now: float) -> DiscoveredAsset:
        arn = _required_text(row.get("modelArn"), "Bedrock custom model ARN", 256)
        owner = _owner_from_tags(self._tags(control, arn))
        base_model = row.get("baseModelArn") or row.get("baseModelName") or "unknown"
        return _asset(
            asset_type="model",
            source=self.source,
            source_id=arn,
            display_name=row.get("modelName") or arn.rsplit("/", 1)[-1],
            version_authority={"kind": "custom_model", "arn": arn},
            binding_strength="immutable_provider_revision",
            owner=owner,
            platform="AWS Bedrock",
            model=base_model,
            last_seen=row.get("lastModifiedTime") or row.get("creationTime"),
            fallback_time=now,
            source_url=self._console_url("custom-models", arn),
            metadata=_selected_metadata(
                resource_kind="custom_model",
                status=row.get("modelStatus"),
                region=self.region or None,
            ),
            dependencies=() if base_model == "unknown" else (str(base_model),),
        )

    def _imported_asset(
        self,
        row: Mapping[str, Any],
        control: Any,
        now: float,
    ) -> DiscoveredAsset:
        arn = _required_text(row.get("modelArn"), "Bedrock imported model ARN", 256)
        return _asset(
            asset_type="model",
            source=self.source,
            source_id=arn,
            display_name=row.get("modelName") or arn.rsplit("/", 1)[-1],
            version_authority={"kind": "imported_model", "arn": arn},
            binding_strength="immutable_provider_revision",
            owner=_owner_from_tags(self._tags(control, arn)),
            platform="AWS Bedrock",
            model=row.get("modelArchitecture") or row.get("modelName") or "unknown",
            last_seen=row.get("lastModifiedTime") or row.get("creationTime"),
            fallback_time=now,
            source_url=self._console_url("imported-models", arn),
            metadata=_selected_metadata(
                resource_kind="imported_model",
                status=row.get("modelStatus"),
                architecture=row.get("modelArchitecture"),
                region=self.region or None,
            ),
        )

    def _provisioned_asset(
        self,
        row: Mapping[str, Any],
        control: Any,
        now: float,
    ) -> DiscoveredAsset:
        arn = _required_text(
            row.get("provisionedModelArn"),
            "Bedrock provisioned model ARN",
            256,
        )
        model_arn = row.get("modelArn") or row.get("desiredModelArn") or "unknown"
        authority = {
            "kind": "provisioned_model",
            "arn": arn,
            "model": model_arn,
            "units": row.get("modelUnits"),
        }
        return _asset(
            asset_type="model",
            source=self.source,
            source_id=arn,
            display_name=row.get("provisionedModelName") or arn.rsplit("/", 1)[-1],
            version_authority=authority,
            binding_strength="observed_snapshot",
            owner=_owner_from_tags(self._tags(control, arn)),
            platform="AWS Bedrock",
            model=model_arn,
            last_seen=row.get("lastModifiedTime") or row.get("creationTime"),
            fallback_time=now,
            source_url=self._console_url("provisioned-throughput", arn),
            metadata=_selected_metadata(
                resource_kind="provisioned_model",
                status=row.get("status"),
                region=self.region or None,
                model_units=row.get("modelUnits"),
            ),
            dependencies=() if model_arn == "unknown" else (str(model_arn),),
        )

    def _agent_asset(self, row: Mapping[str, Any], agent: Any, now: float) -> DiscoveredAsset:
        agent_id = _required_text(row.get("agentId"), "Bedrock agent id", 256)
        detail: Mapping[str, Any] = {}
        get_agent = getattr(agent, "get_agent", None)
        if callable(get_agent):
            detail_page = _sdk_call(
                get_agent,
                {"agentId": agent_id},
                limits=self.limits,
                sleep=self._sleep,
                now=self._clock,
            )
            raw_detail = detail_page.get("agent")
            if raw_detail is not None:
                detail = _mapping(raw_detail, "Bedrock agent detail")
        version = (
            row.get("latestAgentVersion")
            or row.get("agentVersion")
            or detail.get("agentVersion")
        )
        arn = row.get("agentArn") or detail.get("agentArn")
        owner = _owner_from_tags(self._tags(agent, str(arn), agent=True)) if arn else "unknown"
        authority = (
            {"agent_id": agent_id, "version": version}
            if version not in (None, "")
            else {
                "agent_id": agent_id,
                "updated_at": str(row.get("updatedAt") or ""),
                "status": row.get("agentStatus"),
            }
        )
        strength: BindingStrength = (
            "immutable_provider_revision" if version not in (None, "") else "observed_snapshot"
        )
        return _asset(
            asset_type="agent",
            source=self.source,
            source_id=agent_id,
            display_name=row.get("agentName") or agent_id,
            version_authority=authority,
            binding_strength=strength,
            owner=owner,
            platform="AWS Bedrock",
            model=(
                row.get("foundationModel")
                or detail.get("foundationModel")
                or row.get("modelId")
                or "unknown"
            ),
            last_seen=row.get("updatedAt") or row.get("createdAt"),
            fallback_time=now,
            source_url=self._console_url("agents", agent_id),
            metadata=_selected_metadata(
                resource_kind="agent",
                status=row.get("agentStatus"),
                version=version,
                region=self.region or None,
            ),
        )

    def discover(self) -> DiscoveryResult:
        control, agent = self._clients()
        budget = _PaginationBudget(self.limits)
        now = self._clock()
        assets: list[DiscoveredAsset] = []
        custom = self._pages(control.list_custom_models, "modelSummaries", budget)
        assets.extend(self._custom_asset(row, control, now) for row in custom)
        imported = self._pages(control.list_imported_models, "modelSummaries", budget)
        assets.extend(self._imported_asset(row, control, now) for row in imported)
        provisioned = self._pages(
            control.list_provisioned_model_throughputs,
            "provisionedModelSummaries",
            budget,
        )
        assets.extend(self._provisioned_asset(row, control, now) for row in provisioned)
        agents = self._pages(agent.list_agents, "agentSummaries", budget)
        assets.extend(self._agent_asset(row, agent, now) for row in agents)
        return DiscoveryResult(tuple(assets), budget.pages)


def _nested(mapping: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = mapping.get(key)
    return value if isinstance(value, Mapping) else {}


class AzureAIFoundryInventoryAdapter(_HttpAdapter):
    """Foundry project v1 agents and deployments."""

    name = "azure_ai_foundry"
    source = "azure_ai_foundry"

    def __init__(
        self,
        *,
        endpoint: str | None = None,
        endpoint_env: str = "AZURE_AI_FOUNDRY_ENDPOINT",
        token_env: str = "AZURE_AI_FOUNDRY_TOKEN",
        transport: HttpTransport | None = None,
        limits: DiscoveryLimits | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        resolved = endpoint or os.environ.get(endpoint_env, "")
        if not resolved:
            raise AIInventoryConfigError(f"Foundry endpoint reference is unavailable: {endpoint_env}")
        super().__init__(
            base_url=resolved,
            token_env=token_env,
            transport=transport,
            limits=limits,
            sleep=sleep,
            clock=clock,
        )
        self._project_key = _sha256(self.base_url)[:16]

    def _pages(
        self,
        operation: str,
        budget: _PaginationBudget,
    ) -> list[Mapping[str, Any]]:
        url = f"{self.base_url}/{operation}"
        params: Mapping[str, Any] | None = {"api-version": "v1", "limit": 100}
        seen: set[str] = set()
        out: list[Mapping[str, Any]] = []
        while True:
            marker = _sha256({"url": url, "params": params})
            if marker in seen:
                raise DiscoveryProtocolError("Foundry pagination cycle detected")
            seen.add(marker)
            budget.page()
            page = self._get(url, params=params)
            rows = _first_items(page, ("data", "value"))
            budget.add_records(len(rows))
            out.extend(rows)
            next_link = page.get("next_link") or page.get("nextLink")
            if next_link:
                expected_path = urlsplit(f"{self.base_url}/{operation}").path
                url = _same_origin_next(
                    self.base_url,
                    next_link,
                    expected_path=expected_path,
                )
                params = None
                continue
            if page.get("has_more") is True:
                cursor = page.get("last_id") or (rows[-1].get("id") if rows else None)
                if not cursor:
                    raise DiscoveryProtocolError("Foundry has_more page omitted a cursor")
                params = {
                    "api-version": "v1",
                    "limit": 100,
                    "after": _required_text(cursor, "Foundry cursor", 4_096),
                }
                url = f"{self.base_url}/{operation}"
                continue
            return out

    @staticmethod
    def _owner(row: Mapping[str, Any]) -> str:
        metadata = _nested(row, "metadata")
        system = _nested(row, "systemData") or _nested(row, "system_data")
        return _optional_text(
            metadata.get("owner")
            or system.get("lastModifiedBy")
            or system.get("createdBy")
            or row.get("created_by"),
            256,
        )

    def _agent(self, row: Mapping[str, Any], now: float) -> DiscoveredAsset:
        identifier = _required_text(row.get("id"), "Foundry agent id", 220)
        definition = _nested(row, "definition")
        version = row.get("version") or definition.get("version")
        model = (
            row.get("model")
            or definition.get("model")
            or definition.get("model_deployment_name")
            or "unknown"
        )
        authority = (
            {"project": self._project_key, "agent": identifier, "version": version}
            if version
            else {
                "project": self._project_key,
                "agent": identifier,
                "updated_at": row.get("updated_at"),
                "definition_kind": definition.get("kind"),
            }
        )
        strength: BindingStrength = (
            "immutable_provider_revision" if version else "observed_snapshot"
        )
        return _asset(
            asset_type="agent",
            source=self.source,
            source_id=f"{self._project_key}:{identifier}",
            display_name=row.get("name") or identifier,
            version_authority=authority,
            binding_strength=strength,
            owner=self._owner(row),
            platform="Azure AI Foundry",
            model=model,
            last_seen=row.get("updated_at") or row.get("created_at"),
            fallback_time=now,
            source_url=f"{self.base_url}/agents/{quote(identifier, safe='')}",
            metadata=_selected_metadata(
                resource_kind="agent",
                kind=row.get("kind") or definition.get("kind"),
                status=row.get("status"),
                version=version,
                project_key=self._project_key,
            ),
            dependencies=() if model == "unknown" else (str(model),),
        )

    def _deployment(self, row: Mapping[str, Any], now: float) -> DiscoveredAsset:
        properties = _nested(row, "properties")
        identifier = _required_text(
            row.get("id") or row.get("name") or properties.get("deploymentId"),
            "Foundry deployment id",
            220,
        )
        model = (
            row.get("model")
            or properties.get("model")
            or properties.get("modelName")
            or "unknown"
        )
        version = row.get("version") or properties.get("modelVersion")
        authority = {
            "project": self._project_key,
            "deployment": identifier,
            "model": model,
            "version": version,
            "agents": properties.get("agents") or [],
        }
        return _asset(
            asset_type="model",
            source=self.source,
            source_id=f"{self._project_key}:{identifier}",
            display_name=properties.get("displayName") or row.get("name") or identifier,
            version_authority=authority,
            binding_strength=("immutable_provider_revision" if version else "observed_snapshot"),
            owner=self._owner(row),
            platform="Azure AI Foundry",
            model=model,
            last_seen=(
                _nested(row, "systemData").get("lastModifiedAt")
                or row.get("updated_at")
                or row.get("created_at")
            ),
            fallback_time=now,
            source_url=f"{self.base_url}/deployments/{quote(identifier, safe='')}",
            metadata=_selected_metadata(
                resource_kind="deployment",
                status=properties.get("provisioningState") or row.get("status"),
                version=version,
                deployment_type=properties.get("deploymentType"),
                project_key=self._project_key,
            ),
            dependencies=() if model == "unknown" else (str(model),),
        )

    def discover(self) -> DiscoveryResult:
        budget = _PaginationBudget(self.limits)
        now = self._clock()
        agents = [self._agent(row, now) for row in self._pages("agents", budget)]
        deployments = [
            self._deployment(row, now) for row in self._pages("deployments", budget)
        ]
        return DiscoveryResult(tuple(agents + deployments), budget.pages)


class VertexAIInventoryAdapter(_HttpAdapter):
    """Vertex models, endpoints/deployed models, and reasoning engines."""

    name = "vertex_ai"
    source = "google_vertex_ai"

    def __init__(
        self,
        *,
        project: str | None = None,
        location: str | None = None,
        project_env: str = "VERTEX_PROJECT",
        location_env: str = "VERTEX_LOCATION",
        token_env: str = "VERTEX_ACCESS_TOKEN",
        transport: HttpTransport | None = None,
        limits: DiscoveryLimits | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.project = (project or os.environ.get(project_env, "")).strip()
        self.location = (location or os.environ.get(location_env, "")).strip()
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", self.project):
            raise AIInventoryConfigError(f"Vertex project reference is unavailable: {project_env}")
        if not re.fullmatch(r"[a-z0-9-]{2,32}", self.location):
            raise AIInventoryConfigError(f"Vertex location reference is unavailable: {location_env}")
        base = (
            f"https://{self.location}-aiplatform.googleapis.com/v1/projects/"
            f"{quote(self.project, safe='')}/locations/{quote(self.location, safe='')}"
        )
        super().__init__(
            base_url=base,
            token_env=token_env,
            transport=transport,
            limits=limits,
            sleep=sleep,
            clock=clock,
        )

    def _pages(
        self,
        operation: str,
        item_key: str,
        budget: _PaginationBudget,
    ) -> list[Mapping[str, Any]]:
        token = ""
        seen: set[str] = set()
        out: list[Mapping[str, Any]] = []
        while True:
            if token in seen:
                raise DiscoveryProtocolError("Vertex pagination token cycle detected")
            seen.add(token)
            budget.page()
            params: dict[str, Any] = {"pageSize": 100}
            if token:
                params["pageToken"] = token
            page = self._get(f"{self.base_url}/{operation}", params=params)
            rows = _items(page, item_key)
            budget.add_records(len(rows))
            out.extend(rows)
            raw_token = page.get("nextPageToken")
            if raw_token in (None, ""):
                return out
            token = _required_text(raw_token, "Vertex nextPageToken", 4_096)

    @staticmethod
    def _owner(row: Mapping[str, Any]) -> str:
        labels = _nested(row, "labels")
        return _optional_text(
            labels.get("owner") or labels.get("team") or row.get("owner"),
            256,
        )

    def _model(self, row: Mapping[str, Any], now: float) -> DiscoveredAsset:
        name = _required_text(row.get("name"), "Vertex model name", 256)
        version = row.get("versionId")
        checksum = row.get("artifactSha256") or _nested(row, "artifact").get("sha256")
        strength: BindingStrength
        authority: Any
        if checksum:
            strength = "exact_artifact"
            authority = checksum
        elif version:
            strength = "immutable_provider_revision"
            authority = {"resource": name, "version_id": version}
        else:
            strength = "observed_snapshot"
            authority = {
                "resource": name,
                "updated_at": row.get("updateTime"),
                "container": _nested(row, "containerSpec").get("imageUri"),
            }
        source_info = _nested(row, "modelSourceInfo")
        model_label = (
            source_info.get("sourceType")
            or source_info.get("copy")
            or row.get("displayName")
            or name
        )
        return _asset(
            asset_type="model",
            source=self.source,
            source_id=name,
            display_name=row.get("displayName") or name.rsplit("/", 1)[-1],
            version_authority=authority,
            binding_strength=strength,
            owner=self._owner(row),
            platform="Google Vertex AI",
            model=model_label,
            last_seen=row.get("updateTime") or row.get("createTime"),
            fallback_time=now,
            source_url=f"{self.base_url}/models/{quote(name.rsplit('/', 1)[-1], safe='')}",
            metadata=_selected_metadata(
                resource_kind="model",
                version=version,
                location=self.location,
                project=self.project,
            ),
        )

    def _endpoint(self, row: Mapping[str, Any], now: float) -> DiscoveredAsset:
        name = _required_text(row.get("name"), "Vertex endpoint name", 256)
        deployed = row.get("deployedModels") or []
        if not isinstance(deployed, list):
            raise DiscoveryProtocolError("Vertex deployedModels must be an array")
        model_ids = []
        selected = []
        for entry in deployed:
            if not isinstance(entry, Mapping):
                raise DiscoveryProtocolError("Vertex deployed model must be an object")
            model_id = entry.get("model") or entry.get("id")
            if model_id:
                model_ids.append(_required_text(model_id, "Vertex deployed model", 256))
            selected.append(
                {
                    "id": entry.get("id"),
                    "model": model_id,
                    "model_version_id": entry.get("modelVersionId"),
                }
            )
        return _asset(
            asset_type="model",
            source=self.source,
            source_id=name,
            display_name=row.get("displayName") or name.rsplit("/", 1)[-1],
            version_authority={"endpoint": name, "deployed_models": selected},
            binding_strength="observed_snapshot",
            owner=self._owner(row),
            platform="Google Vertex AI",
            model=", ".join(model_ids) or "unknown",
            last_seen=row.get("updateTime") or row.get("createTime"),
            fallback_time=now,
            source_url=f"{self.base_url}/endpoints/{quote(name.rsplit('/', 1)[-1], safe='')}",
            metadata=_selected_metadata(
                resource_kind="endpoint",
                location=self.location,
                project=self.project,
                deployed_model_count=len(model_ids),
            ),
            dependencies=tuple(model_ids),
        )

    def _reasoning_engine(self, row: Mapping[str, Any], now: float) -> DiscoveredAsset:
        name = _required_text(row.get("name"), "Vertex reasoning engine name", 256)
        version = row.get("versionId") or row.get("revisionId")
        model = row.get("model") or _nested(row, "spec").get("model") or "unknown"
        authority = (
            {"resource": name, "version": version}
            if version
            else {"resource": name, "updated_at": row.get("updateTime"), "model": model}
        )
        return _asset(
            asset_type="agent",
            source=self.source,
            source_id=name,
            display_name=row.get("displayName") or name.rsplit("/", 1)[-1],
            version_authority=authority,
            binding_strength=("immutable_provider_revision" if version else "observed_snapshot"),
            owner=self._owner(row),
            platform="Google Vertex AI",
            model=model,
            last_seen=row.get("updateTime") or row.get("createTime"),
            fallback_time=now,
            source_url=(
                f"{self.base_url}/reasoningEngines/"
                f"{quote(name.rsplit('/', 1)[-1], safe='')}"
            ),
            metadata=_selected_metadata(
                resource_kind="reasoning_engine",
                version=version,
                location=self.location,
                project=self.project,
            ),
            dependencies=() if model == "unknown" else (str(model),),
        )

    def discover(self) -> DiscoveryResult:
        budget = _PaginationBudget(self.limits)
        now = self._clock()
        models = [self._model(row, now) for row in self._pages("models", "models", budget)]
        endpoints = [
            self._endpoint(row, now) for row in self._pages("endpoints", "endpoints", budget)
        ]
        engines = [
            self._reasoning_engine(row, now)
            for row in self._pages("reasoningEngines", "reasoningEngines", budget)
        ]
        return DiscoveryResult(tuple(models + endpoints + engines), budget.pages)


class DatabricksUnityCatalogInventoryAdapter(_HttpAdapter):
    """Unity Catalog registered models and immutable model versions."""

    name = "databricks_unity_catalog"
    source = "databricks_unity_catalog"

    def __init__(
        self,
        *,
        host: str | None = None,
        host_env: str = "DATABRICKS_HOST",
        token_env: str = "DATABRICKS_TOKEN",
        transport: HttpTransport | None = None,
        limits: DiscoveryLimits | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        resolved = host or os.environ.get(host_env, "")
        if not resolved:
            raise AIInventoryConfigError(f"Databricks host reference is unavailable: {host_env}")
        super().__init__(
            base_url=resolved,
            token_env=token_env,
            transport=transport,
            limits=limits,
            sleep=sleep,
            clock=clock,
        )
        self._workspace_key = _sha256(self.base_url)[:16]

    def _token_pages(
        self,
        url: str,
        item_key: str,
        budget: _PaginationBudget,
    ) -> list[Mapping[str, Any]]:
        token = ""
        seen: set[str] = set()
        out: list[Mapping[str, Any]] = []
        while True:
            if token in seen:
                raise DiscoveryProtocolError("Databricks pagination token cycle detected")
            seen.add(token)
            budget.page()
            params: dict[str, Any] = {"max_results": 100}
            if token:
                params["page_token"] = token
            page = self._get(url, params=params)
            rows = _items(page, item_key)
            budget.add_records(len(rows))
            out.extend(rows)
            raw_token = page.get("next_page_token")
            if raw_token in (None, ""):
                return out
            token = _required_text(raw_token, "Databricks next_page_token", 4_096)

    def _root_model(self, row: Mapping[str, Any], now: float) -> DiscoveredAsset:
        full_name = _required_text(row.get("full_name"), "Unity Catalog model name", 256)
        return _asset(
            asset_type="model",
            source=self.source,
            source_id=f"{self._workspace_key}:{full_name}",
            display_name=row.get("name") or full_name,
            version_authority={
                "workspace": self._workspace_key,
                "model": full_name,
                "updated_at": row.get("updated_at"),
            },
            binding_strength="observed_snapshot",
            owner=row.get("owner"),
            platform="Databricks Unity Catalog",
            model=full_name,
            last_seen=row.get("updated_at") or row.get("created_at"),
            fallback_time=now,
            source_url=f"{self.base_url}/explore/data/models/{quote(full_name, safe='')}",
            metadata=_selected_metadata(
                resource_kind="registered_model",
                catalog=row.get("catalog_name"),
                schema=row.get("schema_name"),
                workspace_key=self._workspace_key,
            ),
        )

    def _version(
        self,
        row: Mapping[str, Any],
        *,
        model: Mapping[str, Any],
        now: float,
    ) -> DiscoveredAsset:
        full_name = _required_text(model.get("full_name"), "Unity Catalog model name", 220)
        raw_version = row.get("version")
        if isinstance(raw_version, bool) or not isinstance(raw_version, (str, int)):
            raise DiscoveryProtocolError("Unity Catalog model version must be a string or integer")
        version = _required_text(str(raw_version), "Unity Catalog model version", 32)
        source_id = f"{self._workspace_key}:{full_name}:{version}"
        source_ref = row.get("source") or row.get("storage_location") or "unknown"
        return _asset(
            asset_type="model",
            source=self.source,
            source_id=source_id,
            display_name=f"{full_name} v{version}",
            version_authority={
                "workspace": self._workspace_key,
                "model": full_name,
                "version": version,
                "source": source_ref,
            },
            binding_strength="immutable_provider_revision",
            owner=row.get("owner") or row.get("created_by") or model.get("owner"),
            platform="Databricks Unity Catalog",
            model=full_name,
            last_seen=row.get("updated_at") or row.get("created_at"),
            fallback_time=now,
            source_url=(
                f"{self.base_url}/explore/data/models/{quote(full_name, safe='')}/"
                f"versions/{quote(version, safe='')}"
            ),
            metadata=_selected_metadata(
                resource_kind="model_version",
                version=version,
                status=row.get("status"),
                workspace_key=self._workspace_key,
            ),
            dependencies=(f"{self._workspace_key}:{full_name}",),
        )

    def discover(self) -> DiscoveryResult:
        budget = _PaginationBudget(self.limits)
        now = self._clock()
        model_url = f"{self.base_url}/api/2.1/unity-catalog/models"
        models = self._token_pages(model_url, "registered_models", budget)
        assets: list[DiscoveredAsset] = []
        for model in models:
            assets.append(self._root_model(model, now))
            full_name = _required_text(model.get("full_name"), "Unity Catalog model name", 256)
            version_url = (
                f"{self.base_url}/api/2.1/unity-catalog/models/"
                f"{quote(full_name, safe='')}/versions"
            )
            versions = self._token_pages(version_url, "model_versions", budget)
            assets.extend(self._version(row, model=model, now=now) for row in versions)
        return DiscoveryResult(tuple(assets), budget.pages)


def _find_model_in_configuration(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return "unknown"
    if len(value) > _MAX_PAGE_BYTES:
        raise DiscoveryProtocolError("Copilot configuration exceeds its bound")
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return "unknown"
    _bounded_json(parsed, "Copilot configuration")
    wanted = {"gptmodel", "model", "modelid", "modelname"}
    stack = [parsed]
    while stack:
        current = stack.pop()
        if isinstance(current, Mapping):
            for key, child in current.items():
                if str(key).lower().replace("_", "") in wanted and isinstance(child, str):
                    return _optional_text(child, 1_024)
                stack.append(child)
        elif isinstance(current, list):
            stack.extend(current)
    return "unknown"


class CopilotStudioInventoryAdapter(_HttpAdapter):
    """Copilot Studio agents from the Dataverse ``bots`` entity set."""

    name = "copilot_studio"
    source = "microsoft_copilot_studio"

    def __init__(
        self,
        *,
        dataverse_url: str | None = None,
        dataverse_url_env: str = "COPILOT_STUDIO_DATAVERSE_URL",
        token_env: str = "COPILOT_STUDIO_TOKEN",
        transport: HttpTransport | None = None,
        limits: DiscoveryLimits | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        resolved = dataverse_url or os.environ.get(dataverse_url_env, "")
        if not resolved:
            raise AIInventoryConfigError(
                f"Copilot Studio Dataverse reference is unavailable: {dataverse_url_env}"
            )
        super().__init__(
            base_url=resolved,
            token_env=token_env,
            transport=transport,
            limits=limits,
            sleep=sleep,
            clock=clock,
        )
        self._environment_key = _sha256(self.base_url)[:16]

    def _pages(self, budget: _PaginationBudget) -> list[Mapping[str, Any]]:
        url = f"{self.base_url}/api/data/v9.2/bots"
        params: Mapping[str, Any] | None = {
            "$select": (
                "botid,name,versionnumber,modifiedon,createdon,statecode,statuscode,"
                "_ownerid_value,configuration"
            )
        }
        seen: set[str] = set()
        out: list[Mapping[str, Any]] = []
        while True:
            marker = _sha256({"url": url, "params": params})
            if marker in seen:
                raise DiscoveryProtocolError("Dataverse pagination cycle detected")
            seen.add(marker)
            budget.page()
            page = self._get(url, params=params)
            rows = _items(page, "value")
            budget.add_records(len(rows))
            out.extend(rows)
            next_link = page.get("@odata.nextLink")
            if not next_link:
                return out
            url = _same_origin_next(
                self.base_url,
                next_link,
                expected_path=urlsplit(
                    f"{self.base_url}/api/data/v9.2/bots"
                ).path,
            )
            params = None

    def _bot(self, row: Mapping[str, Any], now: float) -> DiscoveredAsset:
        bot_id = _required_text(row.get("botid"), "Copilot botid", 128)
        version = row.get("versionnumber")
        model = _find_model_in_configuration(row.get("configuration"))
        owner = (
            row.get("_ownerid_value@OData.Community.Display.V1.FormattedValue")
            or row.get("_ownerid_value")
        )
        authority = (
            {"environment": self._environment_key, "bot": bot_id, "version": version}
            if version not in (None, "")
            else {
                "environment": self._environment_key,
                "bot": bot_id,
                "modified_on": row.get("modifiedon"),
                "model": model,
                "status": row.get("statuscode"),
            }
        )
        strength: BindingStrength = (
            "immutable_provider_revision"
            if version not in (None, "")
            else "observed_snapshot"
        )
        return _asset(
            asset_type="agent",
            source=self.source,
            source_id=f"{self._environment_key}:{bot_id}",
            display_name=row.get("name") or bot_id,
            version_authority=authority,
            binding_strength=strength,
            owner=owner,
            platform="Microsoft Copilot Studio",
            model=model,
            last_seen=row.get("modifiedon") or row.get("createdon"),
            fallback_time=now,
            source_url=f"{self.base_url}/api/data/v9.2/bots({quote(bot_id, safe='')})",
            metadata=_selected_metadata(
                resource_kind="copilot",
                version=str(version) if version not in (None, "") else None,
                state=row.get("statecode"),
                status=row.get("statuscode"),
                environment_key=self._environment_key,
            ),
        )

    def discover(self) -> DiscoveryResult:
        budget = _PaginationBudget(self.limits)
        now = self._clock()
        assets = tuple(self._bot(row, now) for row in self._pages(budget))
        return DiscoveryResult(assets, budget.pages)


_RUNS = GovernedRecordStore(
    "ai_inventory_runs",
    "AIR",
    "ai_inventory_discovery_run",
)
_STATUSES = GovernedRecordStore(
    "ai_inventory_status",
    "AIS",
    "ai_inventory_connector_status",
)
_ASSET_STATES = GovernedRecordStore(
    "ai_inventory_assets",
    "AIA",
    "ai_inventory_asset_state",
)
_THREAD_LOCKS: dict[tuple[str, str], threading.RLock] = {}
_THREAD_LOCKS_GUARD = threading.Lock()
_PENDING_TO_PUBLIC = {
    "asset_id": "pending_asset_id",
    "display_name": "pending_display_name",
    "version_digest": "pending_version_digest",
    "binding_strength": "pending_binding_strength",
    "owner": "pending_owner",
    "platform": "pending_platform",
    "model": "pending_model",
    "source_url": "pending_source_url",
    "provider_last_seen_at": "pending_provider_last_seen_at",
    "last_seen_at": "pending_last_seen_at",
    "last_seen_sequence": "pending_seen_sequence",
    "last_run_id": "pending_run_id",
    "observation_revision": "pending_observation_revision",
    "observation_snapshot_sha256": "pending_observation_snapshot_sha256",
}
#: Connector name -> the source authority its adapter stamps on records.
#: EVERY registered connector must appear here: the read-side projections
#: refuse persisted records whose connector is absent, so a missing entry
#: makes a connector's successful sync unreadable afterwards (and one such
#: record poisons the whole inventory listing).
_CONNECTOR_SOURCES = {
    "agentforce": "salesforce_agentforce",
    "azure_ai_foundry": "azure_ai_foundry",
    "aws_sagemaker": "aws_sagemaker",
    "bedrock": "aws_bedrock",
    "copilot_studio": "microsoft_copilot_studio",
    "databricks_unity_catalog": "databricks_unity_catalog",
    "hugging_face": "hugging_face_hub",
    "huggingface": "huggingface",
    "mlflow": "mlflow_model_registry",
    "openai": "openai",
    "replicate": "replicate",
    "salesforce_agentforce": "salesforce_agentforce",
    "sagemaker": "aws_sagemaker",
    "snowflake": "snowflake",
    "snowflake_cortex": "snowflake_cortex",
    "vertex_ai": "google_vertex_ai",
}
def _dependency_token(value: object) -> str:
    """Normalize an adapter dependency reference to a model-risk token.

    Adapters emit source-native references — dotted Unity Catalog names,
    Bedrock model ARNs, deployment model names — while the model-risk
    dependency validator accepts only ``[a-z][a-z0-9_:-]{0,63}``. Without
    this mapping a single realistic dependency string fails the whole
    sync. Lossy by design; the original reference stays in the asset
    metadata/source_id, this token only links graph edges.
    """

    text = re.sub(r"[^a-z0-9_:-]", "_", str(value or "").strip().lower())[:64]
    if not text or not text[0].isalpha():
        text = ("d" + text)[:64]
    return text


_STATUS_STATES = frozenset({"running", "complete", "partial", "failed"})
_ASSET_STATE_STATUSES = frozenset({"staged", "present"})
_RUN_ID = re.compile(r"AIR-[0-9a-f]{32}\Z")
_ASSET_ID = re.compile(r"MAA-[0-9a-f]{32}\Z")
_MAX_PERSISTED_REVISION = (2**63) - 1


class SageMakerClient(Protocol):
    def list_models(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def list_endpoints(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def list_tags(self, **kwargs: Any) -> Mapping[str, Any]: ...


class SageMakerInventoryAdapter:
    """SageMaker customer-owned models and serving endpoints.

    Fixed list operations only; no describe calls, no artifact downloads.
    The SDK client is injected in tests and may be omitted in production,
    where boto3 is imported lazily with its standard credential references.
    """

    name = "sagemaker"
    source = "aws_sagemaker"

    def __init__(
        self,
        *,
        sagemaker_client: SageMakerClient | None = None,
        region: str | None = None,
        limits: DiscoveryLimits | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._client = sagemaker_client
        self.region = (
            region
            or os.environ.get("AWS_REGION")
            or os.environ.get("AWS_DEFAULT_REGION")
            or ""
        ).strip()
        if self.region and not re.fullmatch(r"[a-z0-9-]{2,32}", self.region):
            raise AIInventoryConfigError("AWS region is malformed")
        self.limits = limits or DiscoveryLimits()
        self._sleep = sleep
        self._clock = clock

    def _resolved_client(self) -> SageMakerClient:
        if self._client is not None:
            return self._client
        try:
            import boto3  # type: ignore[import-not-found]
        except ImportError as exc:
            raise AIInventoryConfigError(
                "SageMaker inventory requires boto3 or an injected client"
            ) from exc
        profile = os.environ.get("AWS_PROFILE", "").strip() or None
        session = boto3.Session(profile_name=profile, region_name=self.region or None)
        self._client = session.client("sagemaker")
        return self._client

    def _pages(
        self,
        method: Callable[..., Mapping[str, Any]],
        item_key: str,
        budget: _PaginationBudget,
    ) -> list[Mapping[str, Any]]:
        token = ""
        seen: set[str] = set()
        out: list[Mapping[str, Any]] = []
        while True:
            if token in seen:
                raise DiscoveryProtocolError("SageMaker pagination token cycle detected")
            seen.add(token)
            budget.page()
            kwargs: dict[str, Any] = {"MaxResults": 100}
            if token:
                kwargs["NextToken"] = token
            page = _sdk_call(
                method,
                kwargs,
                limits=self.limits,
                sleep=self._sleep,
                now=self._clock,
            )
            rows = _items(page, item_key)
            budget.add_records(len(rows))
            out.extend(rows)
            raw_token = page.get("NextToken")
            if raw_token in (None, ""):
                return out
            token = _required_text(raw_token, "SageMaker NextToken", 4_096)

    def _owner(self, client: SageMakerClient, arn: str) -> str:
        method = getattr(client, "list_tags", None)
        if not callable(method):
            return "unknown"
        page = _sdk_call(
            method,
            {"ResourceArn": arn, "MaxResults": 50},
            limits=self.limits,
            sleep=self._sleep,
            now=self._clock,
        )
        tags = page.get("Tags")
        if not isinstance(tags, list):
            return "unknown"
        normalized = [
            {"key": row.get("Key"), "value": row.get("Value")}
            for row in tags
            if isinstance(row, Mapping)
        ]
        return _owner_from_tags(normalized)

    def _console_url(self, kind: str, identifier: str) -> str:
        region = self.region or "us-east-1"
        safe_id = quote(identifier, safe="")
        return f"https://console.aws.amazon.com/sagemaker/home/{region}/{kind}/{safe_id}"

    def _model_asset(
        self, row: Mapping[str, Any], client: SageMakerClient, now: float,
    ) -> DiscoveredAsset:
        arn = _required_text(row.get("ModelArn"), "SageMaker model ARN", 2_048)
        model_name = _required_text(row.get("ModelName"), "SageMaker model name", 256)
        return _asset(
            asset_type="model",
            source=self.source,
            source_id=arn,
            display_name=model_name,
            version_authority={"arn": arn, "created_at": str(row.get("CreationTime"))},
            binding_strength="observed_snapshot",
            owner=self._owner(client, arn),
            platform="Amazon SageMaker",
            model=model_name,
            last_seen=row.get("CreationTime"),
            fallback_time=now,
            source_url=self._console_url("models", model_name),
            metadata=_selected_metadata(
                resource_kind="model",
                region=self.region,
            ),
        )

    def _endpoint_asset(
        self, row: Mapping[str, Any], client: SageMakerClient, now: float,
    ) -> DiscoveredAsset:
        arn = _required_text(row.get("EndpointArn"), "SageMaker endpoint ARN", 2_048)
        endpoint_name = _required_text(
            row.get("EndpointName"), "SageMaker endpoint name", 256,
        )
        return _asset(
            asset_type="model",
            source=self.source,
            source_id=arn,
            display_name=endpoint_name,
            version_authority={
                "arn": arn,
                "modified_at": str(row.get("LastModifiedTime")),
                "status": row.get("EndpointStatus"),
            },
            binding_strength="observed_snapshot",
            owner=self._owner(client, arn),
            platform="Amazon SageMaker",
            model="unknown",
            last_seen=row.get("LastModifiedTime") or row.get("CreationTime"),
            fallback_time=now,
            source_url=self._console_url("endpoints", endpoint_name),
            metadata=_selected_metadata(
                resource_kind="endpoint",
                status=row.get("EndpointStatus"),
                region=self.region,
            ),
        )

    def discover(self) -> DiscoveryResult:
        client = self._resolved_client()
        budget = _PaginationBudget(self.limits)
        now = self._clock()
        assets = [
            self._model_asset(row, client, now)
            for row in self._pages(client.list_models, "Models", budget)
        ]
        assets.extend(
            self._endpoint_asset(row, client, now)
            for row in self._pages(client.list_endpoints, "Endpoints", budget)
        )
        return DiscoveryResult(tuple(assets), budget.pages)


def _millis_timestamp(value: Any, *, fallback: float) -> Any:
    """MLflow reports epoch milliseconds; convert without guessing units twice."""

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return fallback
    number = float(value)
    return number / 1_000.0 if number > 1e11 else number


class MLflowInventoryAdapter(_HttpAdapter):
    """MLflow tracking-server registered models and their latest versions."""

    name = "mlflow"
    source = "mlflow_model_registry"

    def __init__(
        self,
        *,
        tracking_uri: str | None = None,
        tracking_uri_env: str = "MLFLOW_TRACKING_URI",
        token_env: str = "MLFLOW_TRACKING_TOKEN",
        transport: HttpTransport | None = None,
        limits: DiscoveryLimits | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        resolved = tracking_uri or os.environ.get(tracking_uri_env, "")
        if not resolved:
            raise AIInventoryConfigError(
                f"MLflow tracking URI reference is unavailable: {tracking_uri_env}"
            )
        super().__init__(
            base_url=resolved,
            token_env=token_env,
            transport=transport,
            limits=limits,
            sleep=sleep,
            clock=clock,
        )
        self._server_key = _sha256(self.base_url)[:16]

    def _registered_models(self, budget: _PaginationBudget) -> list[Mapping[str, Any]]:
        url = f"{self.base_url}/api/2.0/mlflow/registered-models/search"
        token = ""
        seen: set[str] = set()
        out: list[Mapping[str, Any]] = []
        while True:
            if token in seen:
                raise DiscoveryProtocolError("MLflow pagination token cycle detected")
            seen.add(token)
            budget.page()
            params: dict[str, Any] = {"max_results": 100}
            if token:
                params["page_token"] = token
            page = self._get(url, params=params)
            rows = _items(page, "registered_models")
            budget.add_records(len(rows))
            out.extend(rows)
            raw_token = page.get("next_page_token")
            if raw_token in (None, ""):
                return out
            token = _required_text(raw_token, "MLflow next_page_token", 4_096)

    def _root_model(self, row: Mapping[str, Any], now: float) -> DiscoveredAsset:
        model_name = _required_text(row.get("name"), "MLflow model name", 256)
        return _asset(
            asset_type="model",
            source=self.source,
            source_id=f"{self._server_key}:{model_name}",
            display_name=model_name,
            version_authority={
                "server": self._server_key,
                "model": model_name,
                "updated_at": row.get("last_updated_timestamp"),
            },
            binding_strength="observed_snapshot",
            owner=_owner_from_tags(row.get("tags")) if row.get("tags") else _optional_text(row.get("user_id"), 256),
            platform="MLflow",
            model=model_name,
            last_seen=_millis_timestamp(
                row.get("last_updated_timestamp") or row.get("creation_timestamp"),
                fallback=now,
            ),
            fallback_time=now,
            source_url=f"{self.base_url}/models/{quote(model_name, safe='')}",
            metadata=_selected_metadata(
                resource_kind="registered_model",
                server_key=self._server_key,
            ),
        )

    def _version(
        self,
        row: Mapping[str, Any],
        *,
        model_name: str,
        now: float,
    ) -> DiscoveredAsset:
        raw_version = row.get("version")
        if isinstance(raw_version, bool) or not isinstance(raw_version, (str, int)):
            raise DiscoveryProtocolError("MLflow model version must be a string or integer")
        version = _required_text(str(raw_version), "MLflow model version", 32)
        source_id = f"{self._server_key}:{model_name}:{version}"
        return _asset(
            asset_type="model",
            source=self.source,
            source_id=source_id,
            display_name=f"{model_name} v{version}",
            version_authority={
                "server": self._server_key,
                "model": model_name,
                "version": version,
                "run_id": row.get("run_id"),
                "source": row.get("source"),
            },
            binding_strength="immutable_provider_revision",
            owner=_optional_text(row.get("user_id"), 256),
            platform="MLflow",
            model=model_name,
            last_seen=_millis_timestamp(
                row.get("last_updated_timestamp") or row.get("creation_timestamp"),
                fallback=now,
            ),
            fallback_time=now,
            source_url=(
                f"{self.base_url}/models/{quote(model_name, safe='')}/"
                f"versions/{quote(version, safe='')}"
            ),
            metadata=_selected_metadata(
                resource_kind="model_version",
                version=version,
                stage=row.get("current_stage"),
                status=row.get("status"),
                server_key=self._server_key,
            ),
            dependencies=(f"{self._server_key}:{model_name}",),
        )

    def discover(self) -> DiscoveryResult:
        budget = _PaginationBudget(self.limits)
        now = self._clock()
        assets: list[DiscoveredAsset] = []
        for row in self._registered_models(budget):
            assets.append(self._root_model(row, now))
            model_name = _required_text(row.get("name"), "MLflow model name", 256)
            versions = row.get("latest_versions")
            if isinstance(versions, list):
                budget.add_records(len(versions))
                assets.extend(
                    self._version(item, model_name=model_name, now=now)
                    for item in versions
                    if isinstance(item, Mapping)
                )
        return DiscoveryResult(tuple(assets), budget.pages)


_LINK_NEXT = re.compile(r'<([^>]+)>\s*;\s*rel="next"')


class HuggingFaceInventoryAdapter(_HttpAdapter):
    """Hugging Face Hub models owned by one organization.

    Scoped to the configured author only -- the public Hub catalogue is not
    the customer's estate. Cursor pagination follows the RFC 5988 ``Link``
    header and every next URL is same-origin enforced.
    """

    name = "huggingface"
    source = "huggingface"

    def __init__(
        self,
        *,
        organization: str | None = None,
        organization_env: str = "HUGGINGFACE_ORG",
        endpoint: str = "https://huggingface.co",
        token_env: str = "HUGGINGFACE_TOKEN",
        transport: HttpTransport | None = None,
        limits: DiscoveryLimits | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        resolved = organization or os.environ.get(organization_env, "")
        if not resolved:
            raise AIInventoryConfigError(
                f"Hugging Face organization reference is unavailable: {organization_env}"
            )
        super().__init__(
            base_url=endpoint,
            token_env=token_env,
            transport=transport,
            limits=limits,
            sleep=sleep,
            clock=clock,
        )
        self.organization = _required_text(resolved, "Hugging Face organization", 96)

    def _model_rows(self, budget: _PaginationBudget) -> list[Mapping[str, Any]]:
        url = f"{self.base_url}/api/models"
        params: Mapping[str, Any] | None = {
            "author": self.organization,
            "limit": 100,
            "full": "true",
        }
        seen: set[str] = set()
        out: list[Mapping[str, Any]] = []
        while True:
            marker = _sha256({"url": url, "params": params})
            if marker in seen:
                raise DiscoveryProtocolError("Hugging Face pagination cycle detected")
            seen.add(marker)
            budget.page()
            page, headers = _http_json_with_headers(
                self.transport,
                url,
                token_env=self.token_env,
                limits=self.limits,
                sleep=self._sleep,
                now=self._clock,
                params=params,
            )
            if not isinstance(page, list):
                raise DiscoveryProtocolError("Hugging Face model page must be a list")
            rows = [row for row in page if isinstance(row, Mapping)]
            if len(rows) != len(page):
                raise DiscoveryProtocolError("Hugging Face model rows must be objects")
            budget.add_records(len(rows))
            out.extend(rows)
            link_header = next(
                (value for key, value in headers.items() if key.lower() == "link"),
                "",
            )
            match = _LINK_NEXT.search(link_header)
            if not match:
                return out
            url = _same_origin_next(
                self.base_url,
                match.group(1),
                expected_path="/api/models",
            )
            params = None

    def _model_asset(self, row: Mapping[str, Any], now: float) -> DiscoveredAsset:
        repo_id = _required_text(
            row.get("id") or row.get("modelId"), "Hugging Face repo id", 256,
        )
        owner_prefix = repo_id.split("/", 1)[0] if "/" in repo_id else self.organization
        if owner_prefix != self.organization:
            raise DiscoveryProtocolError(
                "Hugging Face listing returned a repo outside the configured organization"
            )
        revision = row.get("sha")
        authority = (
            {"repo": repo_id, "sha": revision}
            if revision
            else {"repo": repo_id, "last_modified": row.get("lastModified")}
        )
        strength: BindingStrength = (
            "immutable_provider_revision" if revision else "observed_snapshot"
        )
        return _asset(
            asset_type="model",
            source=self.source,
            source_id=repo_id,
            display_name=repo_id,
            version_authority=authority,
            binding_strength=strength,
            owner=self.organization,
            platform="Hugging Face Hub",
            model=repo_id,
            last_seen=row.get("lastModified") or row.get("createdAt"),
            fallback_time=now,
            source_url=f"{self.base_url}/{repo_id}",
            metadata=_selected_metadata(
                resource_kind="model_repo",
                pipeline_tag=row.get("pipeline_tag"),
                private=row.get("private"),
                library=row.get("library_name"),
                revision=revision,
            ),
        )

    def discover(self) -> DiscoveryResult:
        budget = _PaginationBudget(self.limits)
        now = self._clock()
        assets = [self._model_asset(row, now) for row in self._model_rows(budget)]
        return DiscoveryResult(tuple(assets), budget.pages)


class OpenAIInventoryAdapter(_HttpAdapter):
    """OpenAI models visible to one organization's API key.

    A single fixed list operation (``GET /v1/models``): the listing carries
    the organization's fine-tuned models alongside the vendor models it may
    invoke, and ``owned_by`` distinguishes them. The endpoint documents no
    pagination; the one page is still budgeted and bounded.
    """

    name = "openai"
    source = "openai"

    def __init__(
        self,
        *,
        endpoint: str = "https://api.openai.com",
        token_env: str = "OPENAI_API_KEY",
        transport: HttpTransport | None = None,
        limits: DiscoveryLimits | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        super().__init__(
            base_url=endpoint,
            token_env=token_env,
            transport=transport,
            limits=limits,
            sleep=sleep,
            clock=clock,
        )

    def _model_asset(self, row: Mapping[str, Any], now: float) -> DiscoveredAsset:
        model_id = _required_text(row.get("id"), "OpenAI model id", 256)
        owned_by = _optional_text(row.get("owned_by"), 256)
        created = row.get("created")
        return _asset(
            asset_type="model",
            source=self.source,
            source_id=model_id,
            display_name=model_id,
            version_authority={"model": model_id, "created": created},
            binding_strength="observed_snapshot",
            owner=owned_by,
            platform="OpenAI",
            model=model_id,
            last_seen=created,
            fallback_time=now,
            source_url=f"{self.base_url}/v1/models/{model_id}",
            metadata=_selected_metadata(
                resource_kind="model",
                owned_by=owned_by,
                fine_tuned=model_id.startswith("ft:"),
                shutdown_date=row.get("shutdown_date"),
            ),
        )

    def discover(self) -> DiscoveryResult:
        budget = _PaginationBudget(self.limits)
        now = self._clock()
        budget.page()
        page = self._get(f"{self.base_url}/v1/models")
        rows = _items(page, "data")
        budget.add_records(len(rows))
        assets = [self._model_asset(row, now) for row in rows]
        return DiscoveryResult(tuple(assets), budget.pages)


class ReplicateInventoryAdapter(_HttpAdapter):
    """Replicate deployments owned by the current account.

    ``GET /v1/deployments`` is account-scoped by the provider ("deployments
    associated with the current account"), so the estate never mixes with
    the public model catalogue. Each row's ``current_release`` pins a
    64-character model version id — an immutable provider revision. Cursor
    pagination follows the ``next`` URL, same-origin enforced.
    """

    name = "replicate"
    source = "replicate"

    def __init__(
        self,
        *,
        endpoint: str = "https://api.replicate.com",
        token_env: str = "REPLICATE_API_TOKEN",
        transport: HttpTransport | None = None,
        limits: DiscoveryLimits | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        super().__init__(
            base_url=endpoint,
            token_env=token_env,
            transport=transport,
            limits=limits,
            sleep=sleep,
            clock=clock,
        )

    def _deployment_rows(self, budget: _PaginationBudget) -> list[Mapping[str, Any]]:
        url = f"{self.base_url}/v1/deployments"
        seen: set[str] = set()
        out: list[Mapping[str, Any]] = []
        while True:
            if url in seen:
                raise DiscoveryProtocolError("Replicate pagination cycle detected")
            seen.add(url)
            budget.page()
            page = self._get(url)
            rows = _items(page, "results")
            budget.add_records(len(rows))
            out.extend(rows)
            next_url = page.get("next")
            if not next_url:
                return out
            url = _same_origin_next(
                self.base_url,
                str(next_url),
                expected_path="/v1/deployments",
            )

    def _deployment_asset(self, row: Mapping[str, Any], now: float) -> DiscoveredAsset:
        owner = _required_text(row.get("owner"), "Replicate deployment owner", 256)
        name = _required_text(row.get("name"), "Replicate deployment name", 256)
        release = row.get("current_release")
        release_map: Mapping[str, Any] = release if isinstance(release, Mapping) else {}
        version = str(release_map.get("version") or "").strip()
        model = _optional_text(release_map.get("model"), 1_024)
        deployment_id = f"{owner}/{name}"
        authority: Mapping[str, Any] = (
            {"deployment": deployment_id, "version": version}
            if version
            else {"deployment": deployment_id, "release": release_map.get("number")}
        )
        strength: BindingStrength = (
            "immutable_provider_revision" if version else "observed_snapshot"
        )
        return _asset(
            asset_type="model",
            source=self.source,
            source_id=deployment_id,
            display_name=deployment_id,
            version_authority=authority,
            binding_strength=strength,
            owner=owner,
            platform="Replicate",
            model=model,
            last_seen=release_map.get("created_at"),
            fallback_time=now,
            source_url=f"https://replicate.com/deployments/{deployment_id}",
            metadata=_selected_metadata(
                resource_kind="deployment",
                release_number=release_map.get("number"),
                model=model,
                version=version or None,
            ),
        )

    def discover(self) -> DiscoveryResult:
        budget = _PaginationBudget(self.limits)
        now = self._clock()
        assets = [
            self._deployment_asset(row, now)
            for row in self._deployment_rows(budget)
        ]
        return DiscoveryResult(tuple(assets), budget.pages)


def _http_post_json(
    transport: HttpSqlTransport,
    url: str,
    *,
    token_env: str,
    limits: DiscoveryLimits,
    sleep: Callable[[float], None],
    now: Callable[[], float],
    json_body: Mapping[str, Any],
    extra_headers: Mapping[str, str] | None = None,
) -> Mapping[str, Any]:
    """One retried, bearer-authenticated POST of a fixed JSON body."""

    token = _credential(token_env)
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    headers.update(dict(extra_headers or {}))
    for attempt in range(limits.retry_attempts):
        try:
            response = transport.post(
                url,
                headers=headers,
                json=json_body,
                timeout=float(limits.timeout_seconds),
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            if attempt + 1 >= limits.retry_attempts:
                raise DiscoveryTransportError(
                    f"provider request failed ({type(exc).__name__})"
                ) from exc
            _sleep_delay(attempt, {}, sleep=sleep, now=now)
            continue
        status = int(response.status_code)
        if status in _RETRYABLE_STATUS and attempt + 1 < limits.retry_attempts:
            _sleep_delay(attempt, response.headers, sleep=sleep, now=now)
            continue
        if status == 202:
            raise DiscoveryTransportError(
                "provider deferred the statement; asynchronous execution is not supported"
            )
        if not 200 <= status < 300:
            raise DiscoveryTransportError(f"provider request failed with HTTP {status}")
        try:
            page = response.json()
        except (TypeError, ValueError) as exc:
            raise DiscoveryProtocolError("provider response was not JSON") from exc
        return _mapping(page, "provider page")
    raise DiscoveryTransportError("provider retry budget exhausted")


_SNOWFLAKE_TOKEN_TYPES = frozenset({"OAUTH", "KEYPAIR_JWT"})
_STATEMENT_HANDLE_RE = re.compile(r"[0-9a-fA-F-]{8,128}\Z")


class SnowflakeInventoryAdapter:
    """Snowflake Model Registry models via one fixed read-only statement.

    The only statement ever sent is ``SHOW MODELS IN ACCOUNT`` -- no caller
    input reaches the SQL text. Rows are labeled by the response's own
    ``resultSetMetaData.rowType`` names, additional result partitions are
    fetched by handle, and an asynchronous (202) response fails closed.
    """

    name = "snowflake"
    source = "snowflake"
    _STATEMENT = "SHOW MODELS IN ACCOUNT"

    def __init__(
        self,
        *,
        account_url: str | None = None,
        account_url_env: str = "SNOWFLAKE_ACCOUNT_URL",
        token_env: str = "SNOWFLAKE_TOKEN",
        token_type_env: str = "SNOWFLAKE_TOKEN_TYPE",
        transport: HttpSqlTransport | None = None,
        limits: DiscoveryLimits | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        resolved = account_url or os.environ.get(account_url_env, "")
        if not resolved:
            raise AIInventoryConfigError(
                f"Snowflake account URL reference is unavailable: {account_url_env}"
            )
        self.base_url = _safe_base_url(resolved, "snowflake account URL")
        self.token_env = _required_text(token_env, "token environment name", 128)
        token_type = os.environ.get(token_type_env, "OAUTH").strip().upper() or "OAUTH"
        if token_type not in _SNOWFLAKE_TOKEN_TYPES:
            raise AIInventoryConfigError(
                "Snowflake token type must be OAUTH or KEYPAIR_JWT"
            )
        self.token_type = token_type
        self.transport: HttpSqlTransport = transport or _DefaultHttpTransport(self.name)
        self.limits = limits or DiscoveryLimits()
        self._sleep = sleep
        self._clock = clock
        self._account_key = _sha256(self.base_url)[:16]

    def _headers(self) -> dict[str, str]:
        return {"X-Snowflake-Authorization-Token-Type": self.token_type}

    def _statement_rows(self, budget: _PaginationBudget) -> list[dict[str, Any]]:
        url = f"{self.base_url}/api/v2/statements"
        budget.page()
        page = _http_post_json(
            self.transport,
            url,
            token_env=self.token_env,
            limits=self.limits,
            sleep=self._sleep,
            now=self._clock,
            json_body={
                "statement": self._STATEMENT,
                "timeout": int(self.limits.timeout_seconds),
            },
            extra_headers=self._headers(),
        )
        metadata = _mapping(page.get("resultSetMetaData"), "Snowflake result metadata")
        row_type = metadata.get("rowType")
        if not isinstance(row_type, list) or not row_type:
            raise DiscoveryProtocolError("Snowflake result metadata omitted rowType")
        columns = [
            _required_text(_mapping(entry, "Snowflake column").get("name"),
                           "Snowflake column name", 128).lower()
            for entry in row_type
        ]
        partitions = metadata.get("partitionInfo")
        if not isinstance(partitions, list) or not partitions:
            raise DiscoveryProtocolError("Snowflake result metadata omitted partitionInfo")
        rows = self._labeled_rows(page, columns, budget)
        if len(partitions) > 1:
            handle = _required_text(
                page.get("statementHandle"), "Snowflake statement handle", 128,
            )
            if not _STATEMENT_HANDLE_RE.fullmatch(handle):
                raise DiscoveryProtocolError("Snowflake statement handle is malformed")
            for index in range(1, len(partitions)):
                budget.page()
                partition = _http_json(
                    self.transport,
                    f"{self.base_url}/api/v2/statements/{quote(handle, safe='')}",
                    token_env=self.token_env,
                    limits=self.limits,
                    sleep=self._sleep,
                    now=self._clock,
                    params={"partition": index},
                    extra_headers=self._headers(),
                )
                rows.extend(self._labeled_rows(partition, columns, budget))
        return rows

    @staticmethod
    def _labeled_rows(
        page: Mapping[str, Any],
        columns: list[str],
        budget: _PaginationBudget,
    ) -> list[dict[str, Any]]:
        data = page.get("data")
        if not isinstance(data, list):
            raise DiscoveryProtocolError("Snowflake result omitted its data rows")
        budget.add_records(len(data))
        rows: list[dict[str, Any]] = []
        for entry in data:
            if not isinstance(entry, list) or len(entry) != len(columns):
                raise DiscoveryProtocolError("Snowflake result row shape is invalid")
            rows.append(dict(zip(columns, entry, strict=True)))
        return rows

    def _versions(self, row: Mapping[str, Any]) -> list[str]:
        raw = row.get("versions")
        if raw in (None, ""):
            return []
        try:
            parsed = json.loads(raw) if isinstance(raw, str) else raw
        except ValueError as exc:
            raise DiscoveryProtocolError("Snowflake model versions are malformed") from exc
        if not isinstance(parsed, list):
            raise DiscoveryProtocolError("Snowflake model versions must be a list")
        if len(parsed) > 256:
            raise DiscoveryLimitError("Snowflake model version list exceeds its bound")
        return [
            _required_text(item, "Snowflake model version", 128) for item in parsed
        ]

    def _model_assets(
        self, row: Mapping[str, Any], now: float, budget: _PaginationBudget,
    ) -> list[DiscoveredAsset]:
        model_name = _required_text(row.get("name"), "Snowflake model name", 256)
        database = _required_text(row.get("database_name"), "Snowflake database", 256)
        schema = _required_text(row.get("schema_name"), "Snowflake schema", 256)
        fqn = f"{database}.{schema}.{model_name}"
        versions = self._versions(row)
        root = _asset(
            asset_type="model",
            source=self.source,
            source_id=f"{self._account_key}:{fqn}",
            display_name=fqn,
            version_authority={
                "account": self._account_key,
                "model": fqn,
                "default_version": row.get("default_version_name"),
                "versions": versions,
            },
            binding_strength="observed_snapshot",
            owner=row.get("owner"),
            platform="Snowflake Model Registry",
            model=fqn,
            last_seen=row.get("created_on"),
            fallback_time=now,
            source_url=f"{self.base_url}/models/{quote(fqn, safe='')}",
            metadata=_selected_metadata(
                resource_kind="registered_model",
                model_type=row.get("model_type"),
                default_version=row.get("default_version_name"),
                account_key=self._account_key,
            ),
        )
        out = [root]
        budget.add_records(len(versions))
        for version in versions:
            out.append(
                _asset(
                    asset_type="model",
                    source=self.source,
                    source_id=f"{self._account_key}:{fqn}:{version}",
                    display_name=f"{fqn} {version}",
                    version_authority={
                        "account": self._account_key,
                        "model": fqn,
                        "version": version,
                    },
                    binding_strength="immutable_provider_revision",
                    owner=row.get("owner"),
                    platform="Snowflake Model Registry",
                    model=fqn,
                    last_seen=row.get("created_on"),
                    fallback_time=now,
                    source_url=(
                        f"{self.base_url}/models/{quote(fqn, safe='')}/"
                        f"versions/{quote(version, safe='')}"
                    ),
                    metadata=_selected_metadata(
                        resource_kind="model_version",
                        version=version,
                        account_key=self._account_key,
                    ),
                    dependencies=(f"{self._account_key}:{fqn}",),
                )
            )
        return out

    def discover(self) -> DiscoveryResult:
        budget = _PaginationBudget(self.limits)
        now = self._clock()
        assets: list[DiscoveredAsset] = []
        for row in self._statement_rows(budget):
            assets.extend(self._model_assets(row, now, budget))
        return DiscoveryResult(tuple(assets), budget.pages)


_SALESFORCE_API_VERSION = "v61.0"
_AGENTFORCE_SOQL = (
    "SELECT Id, DeveloperName, MasterLabel, CreatedDate, LastModifiedDate "
    "FROM BotDefinition ORDER BY Id"
)


def _salesforce_instant(value: Any) -> Any:
    """Normalize Salesforce's ``+0000`` offset for pre-3.11 fromisoformat."""

    if isinstance(value, str) and re.search(r"[+-][0-9]{4}\Z", value):
        return f"{value[:-2]}:{value[-2:]}"
    return value


class AgentforceInventoryAdapter(_HttpAdapter):
    """Salesforce Agentforce / Einstein Bot definitions via one fixed SOQL read.

    ``BotDefinition`` is the standard object for both agent generations
    (API v60.0+). The query text is a constant -- no caller input reaches
    SOQL -- and ``nextRecordsUrl`` pages are same-origin enforced.
    """

    name = "agentforce"
    source = "salesforce_agentforce"

    def __init__(
        self,
        *,
        instance_url: str | None = None,
        instance_url_env: str = "SALESFORCE_INSTANCE_URL",
        token_env: str = "SALESFORCE_TOKEN",
        transport: HttpTransport | None = None,
        limits: DiscoveryLimits | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        resolved = instance_url or os.environ.get(instance_url_env, "")
        if not resolved:
            raise AIInventoryConfigError(
                f"Salesforce instance URL reference is unavailable: {instance_url_env}"
            )
        super().__init__(
            base_url=resolved,
            token_env=token_env,
            transport=transport,
            limits=limits,
            sleep=sleep,
            clock=clock,
        )
        self._org_key = _sha256(self.base_url)[:16]

    def _records(self, budget: _PaginationBudget) -> list[Mapping[str, Any]]:
        url = f"{self.base_url}/services/data/{_SALESFORCE_API_VERSION}/query"
        params: Mapping[str, Any] | None = {"q": _AGENTFORCE_SOQL}
        seen: set[str] = set()
        out: list[Mapping[str, Any]] = []
        while True:
            marker = _sha256({"url": url, "params": params})
            if marker in seen:
                raise DiscoveryProtocolError("Salesforce pagination cycle detected")
            seen.add(marker)
            budget.page()
            page = self._get(url, params=params)
            records = _items(page, "records")
            budget.add_records(len(records))
            out.extend(records)
            if page.get("done") is True:
                return out
            next_url = page.get("nextRecordsUrl")
            if not next_url:
                raise DiscoveryProtocolError(
                    "Salesforce page was not done and omitted nextRecordsUrl"
                )
            url = _same_origin_next(
                self.base_url,
                next_url,
                expected_prefix=f"/services/data/{_SALESFORCE_API_VERSION}/query/",
            )
            params = None

    def _agent(self, row: Mapping[str, Any], now: float) -> DiscoveredAsset:
        identifier = _required_text(row.get("Id"), "Salesforce agent id", 64)
        developer_name = _optional_text(row.get("DeveloperName"), 256)
        modified = _salesforce_instant(
            row.get("LastModifiedDate") or row.get("CreatedDate")
        )
        return _asset(
            asset_type="agent",
            source=self.source,
            source_id=f"{self._org_key}:{identifier}",
            display_name=row.get("MasterLabel") or developer_name or identifier,
            version_authority={
                "org": self._org_key,
                "id": identifier,
                "developer_name": developer_name,
                "modified_at": row.get("LastModifiedDate"),
            },
            binding_strength="observed_snapshot",
            owner="unknown",
            platform="Salesforce Agentforce",
            model="unknown",
            last_seen=modified,
            fallback_time=now,
            source_url=(
                f"{self.base_url}/services/data/{_SALESFORCE_API_VERSION}/"
                f"sobjects/BotDefinition/{quote(identifier, safe='')}"
            ),
            metadata=_selected_metadata(
                resource_kind="agent_definition",
                developer_name=developer_name,
                org_key=self._org_key,
            ),
        )

    def discover(self) -> DiscoveryResult:
        budget = _PaginationBudget(self.limits)
        now = self._clock()
        assets = [self._agent(row, now) for row in self._records(budget)]
        return DiscoveryResult(tuple(assets), budget.pages)


def _persisted_record(value: Any, kind: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise DiscoveryProtocolError(
            f"persisted AI inventory {kind} record must be an object"
        )
    _bounded_json(value, f"persisted AI inventory {kind} record", max_nodes=4_096)
    return value


def _persisted_text(
    record: Mapping[str, Any],
    key: str,
    *,
    maximum: int,
    kind: str,
    optional: bool = False,
) -> str:
    value = record.get(key)
    if optional and value in (None, ""):
        return ""
    try:
        text = _required_text(value, f"persisted {kind} {key}", maximum)
    except DiscoveryProtocolError as exc:
        raise DiscoveryProtocolError(
            f"persisted AI inventory {kind} record is malformed ({key})"
        ) from exc
    if text != value:
        raise DiscoveryProtocolError(
            f"persisted AI inventory {kind} record is non-canonical ({key})"
        )
    return text


def _persisted_int(
    record: Mapping[str, Any],
    key: str,
    *,
    minimum: int,
    maximum: int,
    kind: str,
) -> int:
    value = record.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise DiscoveryProtocolError(
            f"persisted AI inventory {kind} record is malformed ({key})"
        )
    if not minimum <= value <= maximum:
        raise DiscoveryProtocolError(
            f"persisted AI inventory {kind} record is out of bounds ({key})"
        )
    return value


def _persisted_timestamp(
    record: Mapping[str, Any],
    key: str,
    *,
    kind: str,
) -> float:
    try:
        return _positive_timestamp(record.get(key), f"persisted {kind} {key}")
    except DiscoveryProtocolError as exc:
        raise DiscoveryProtocolError(
            f"persisted AI inventory {kind} record is malformed ({key})"
        ) from exc


def _persisted_store_metadata(
    record: Mapping[str, Any],
    *,
    kind: str,
) -> dict[str, Any]:
    created_at = _persisted_timestamp(record, "created_at", kind=kind)
    updated_at = _persisted_timestamp(record, "updated_at", kind=kind)
    if updated_at < created_at:
        raise DiscoveryProtocolError(
            f"persisted AI inventory {kind} record has invalid timestamps"
        )
    return {
        "revision": _persisted_int(
            record,
            "revision",
            minimum=1,
            maximum=_MAX_PERSISTED_REVISION,
            kind=kind,
        ),
        "created_at": created_at,
        "updated_at": updated_at,
    }


def _persisted_digest(
    record: Mapping[str, Any],
    key: str,
    *,
    kind: str,
) -> str:
    value = _persisted_text(record, key, maximum=64, kind=kind)
    if not _HEX_DIGEST.fullmatch(value):
        raise DiscoveryProtocolError(
            f"persisted AI inventory {kind} record has an invalid digest ({key})"
        )
    return value


def _persisted_run_id(
    record: Mapping[str, Any],
    key: str,
    *,
    kind: str,
) -> str:
    value = _persisted_text(record, key, maximum=64, kind=kind)
    if not _RUN_ID.fullmatch(value):
        raise DiscoveryProtocolError(
            f"persisted AI inventory {kind} record has an invalid run id ({key})"
        )
    return value


def _status_projection(
    value: Any,
    *,
    expected_connector: str | None = None,
) -> dict[str, Any]:
    record = _persisted_record(value, "connector status")
    kind = "connector status"
    connector = _persisted_text(record, "connector", maximum=64, kind=kind)
    if connector not in _CONNECTOR_SOURCES or (
        expected_connector is not None and connector != expected_connector
    ):
        raise DiscoveryProtocolError(
            "persisted AI inventory connector status has invalid authority"
        )
    source = _persisted_text(record, "source", maximum=64, kind=kind)
    if source != _CONNECTOR_SOURCES[connector]:
        raise DiscoveryProtocolError(
            "persisted AI inventory connector status has invalid source authority"
        )
    record_id = _persisted_text(record, "id", maximum=64, kind=kind)
    if record_id != _status_id(connector):
        raise DiscoveryProtocolError(
            "persisted AI inventory connector status has invalid identity"
        )
    if record.get("schema") != "lightwork.ai-inventory-connector-status.v1":
        raise DiscoveryProtocolError(
            "persisted AI inventory connector status has an unsupported schema"
        )
    state = _persisted_text(record, "state", maximum=16, kind=kind)
    if state not in _STATUS_STATES:
        raise DiscoveryProtocolError(
            "persisted AI inventory connector status has an invalid state"
        )
    projection = {
        "id": record_id,
        "schema": "lightwork.ai-inventory-connector-status.v1",
        "connector": connector,
        "source": source,
        "state": state,
        "completed_sequence": _persisted_int(
            record,
            "completed_sequence",
            minimum=0,
            maximum=_MAX_PERSISTED_REVISION,
            kind=kind,
        ),
        **_persisted_store_metadata(record, kind=kind),
    }
    optional_run_ids = ("last_attempt_id", "last_completed_id")
    for key in optional_run_ids:
        if record.get(key) not in (None, ""):
            projection[key] = _persisted_run_id(record, key, kind=kind)
    for key in ("last_attempt_at", "last_completed_at"):
        if record.get(key) not in (None, ""):
            projection[key] = _persisted_timestamp(record, key, kind=kind)
    if record.get("last_asset_count") is not None:
        projection["last_asset_count"] = _persisted_int(
            record,
            "last_asset_count",
            minimum=0,
            maximum=_MAX_RECORDS,
            kind=kind,
        )
    if record.get("last_identity_digest") not in (None, ""):
        projection["last_identity_digest"] = _persisted_digest(
            record,
            "last_identity_digest",
            kind=kind,
        )
    if "last_error_type" in record:
        error_type = _persisted_text(
            record,
            "last_error_type",
            maximum=128,
            kind=kind,
            optional=True,
        )
        if error_type and not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,127}", error_type):
            raise DiscoveryProtocolError(
                "persisted AI inventory connector status has an invalid error type"
            )
        projection["last_error_type"] = error_type
    if state in {"running", "partial", "failed"} and not {
        "last_attempt_id",
        "last_attempt_at",
    }.issubset(projection):
        raise DiscoveryProtocolError(
            "persisted AI inventory connector status lacks attempt authority"
        )
    if state == "complete" and (
        projection["completed_sequence"] < 1
        or not {
            "last_completed_id",
            "last_completed_at",
            "last_asset_count",
            "last_identity_digest",
        }.issubset(projection)
    ):
        raise DiscoveryProtocolError(
            "persisted AI inventory connector status lacks completion authority"
        )
    if state in {"partial", "failed"} and not projection.get("last_error_type"):
        raise DiscoveryProtocolError(
            "persisted AI inventory connector status lacks failure authority"
        )
    return projection


def _asset_state_projection(
    value: Any,
    *,
    completed_sequence: int,
    completed_run_id: str,
    missing_grace_runs: int,
) -> dict[str, Any] | None:
    record = _persisted_record(value, "asset state")
    kind = "asset state"
    connector = _persisted_text(record, "connector", maximum=64, kind=kind)
    if connector not in _CONNECTOR_SOURCES:
        raise DiscoveryProtocolError(
            "persisted AI inventory asset state has an invalid connector"
        )
    source = _persisted_text(record, "source", maximum=64, kind=kind)
    if source != _CONNECTOR_SOURCES[connector]:
        raise DiscoveryProtocolError(
            "persisted AI inventory asset state has invalid source authority"
        )
    source_id = _persisted_text(record, "source_id", maximum=256, kind=kind)
    record_id = _persisted_text(record, "id", maximum=64, kind=kind)
    if record_id != _asset_state_id(connector, source, source_id):
        raise DiscoveryProtocolError(
            "persisted AI inventory asset state has invalid identity"
        )
    if record.get("schema") != "lightwork.ai-inventory-asset-state.v1":
        raise DiscoveryProtocolError(
            "persisted AI inventory asset state has an unsupported schema"
        )
    asset_type = _persisted_text(record, "asset_type", maximum=64, kind=kind)
    if asset_type not in _ASSET_TYPES:
        raise DiscoveryProtocolError(
            "persisted AI inventory asset state has an invalid asset type"
        )
    persisted_status = _persisted_text(record, "status", maximum=16, kind=kind)
    if persisted_status not in _ASSET_STATE_STATUSES:
        raise DiscoveryProtocolError(
            "persisted AI inventory asset state has an invalid lifecycle state"
        )
    projection = {
        "id": record_id,
        "schema": "lightwork.ai-inventory-asset-state.v1",
        "connector": connector,
        "source": source,
        "source_id": source_id,
        "asset_type": asset_type,
        "first_seen_at": _persisted_timestamp(record, "first_seen_at", kind=kind),
        **_persisted_store_metadata(record, kind=kind),
    }
    current = dict(record)
    if completed_run_id and record.get("pending_run_id") == completed_run_id:
        for public, staged in _PENDING_TO_PUBLIC.items():
            current[public] = record.get(staged)
    last_seen_sequence = _persisted_int(
        current,
        "last_seen_sequence",
        minimum=0,
        maximum=_MAX_PERSISTED_REVISION,
        kind=kind,
    )
    if last_seen_sequence <= 0:
        return None
    if last_seen_sequence > completed_sequence:
        raise DiscoveryProtocolError(
            "persisted AI inventory asset state exceeds completed-run authority"
        )
    asset_id = _persisted_text(current, "asset_id", maximum=64, kind=kind)
    if not _ASSET_ID.fullmatch(asset_id):
        raise DiscoveryProtocolError(
            "persisted AI inventory asset state has an invalid asset id"
        )
    binding_strength = _persisted_text(
        current,
        "binding_strength",
        maximum=64,
        kind=kind,
    )
    if binding_strength not in _BINDING_STRENGTHS:
        raise DiscoveryProtocolError(
            "persisted AI inventory asset state has an invalid binding strength"
        )
    source_url = _persisted_text(current, "source_url", maximum=2_048, kind=kind)
    try:
        _safe_source_url(source_url)
    except (AIInventoryConfigError, DiscoveryProtocolError, ValueError) as exc:
        raise DiscoveryProtocolError(
            "persisted AI inventory asset state has an invalid source URL"
        ) from exc
    missing_count = max(0, completed_sequence - last_seen_sequence)
    if missing_count == 0:
        discovery_status = "present"
    elif missing_count >= missing_grace_runs:
        discovery_status = "missing"
    else:
        discovery_status = "grace"
    projection.update(
        {
            "asset_id": asset_id,
            "display_name": _persisted_text(
                current, "display_name", maximum=256, kind=kind
            ),
            "version_digest": _persisted_digest(
                current, "version_digest", kind=kind
            ),
            "binding_strength": binding_strength,
            "owner": _persisted_text(current, "owner", maximum=256, kind=kind),
            "platform": _persisted_text(
                current, "platform", maximum=128, kind=kind
            ),
            "model": _persisted_text(current, "model", maximum=1_024, kind=kind),
            "source_url": source_url,
            "provider_last_seen_at": _persisted_timestamp(
                current, "provider_last_seen_at", kind=kind
            ),
            "last_seen_at": _persisted_timestamp(
                current, "last_seen_at", kind=kind
            ),
            "last_seen_sequence": last_seen_sequence,
            "last_run_id": _persisted_run_id(current, "last_run_id", kind=kind),
            "observation_revision": _persisted_int(
                current,
                "observation_revision",
                minimum=1,
                maximum=_MAX_PERSISTED_REVISION,
                kind=kind,
            ),
            "observation_snapshot_sha256": _persisted_digest(
                current,
                "observation_snapshot_sha256",
                kind=kind,
            ),
            "missing_count": missing_count,
            "discovery_status": discovery_status,
            "status": discovery_status,
        }
    )
    return projection


def get_ai_inventory_config() -> dict[str, Any]:
    """Return a validated ``[ai_inventory]`` policy with fail-closed defaults."""

    try:
        from .config import config_source_errors, load_global_config

        errors = config_source_errors(include_tenant=False)
        root = load_global_config()
    except Exception as exc:
        raise AIInventoryConfigError("AI inventory configuration is unavailable") from exc
    if errors:
        raise AIInventoryConfigError("AI inventory configuration is unreadable")
    if not isinstance(root, Mapping):
        raise AIInventoryConfigError("configuration root must be a table")
    raw = root.get("ai_inventory")
    if raw is None:
        raw = {}
    if not isinstance(raw, Mapping):
        raise AIInventoryConfigError("ai_inventory must be a table")
    for key in raw:
        normalized_key = str(key).strip().lower()
        if _SENSITIVE_KEY.search(normalized_key) or normalized_key in {
            "credentials",
            "client_credentials",
        }:
            raise AIInventoryConfigError(
                "ai_inventory accepts credential references, not credential values"
            )
    flag = raw.get("enable", False)
    if not isinstance(flag, bool):
        raise AIInventoryConfigError("ai_inventory.enable must be a boolean")
    connector_value = raw.get("connectors", [])
    if isinstance(connector_value, str):
        connectors = [item.strip().lower() for item in connector_value.split(",") if item.strip()]
    elif isinstance(connector_value, list):
        connectors = []
        for item in connector_value:
            if not isinstance(item, str):
                raise AIInventoryConfigError("ai_inventory.connectors must contain strings")
            name = item.strip().lower()
            if name:
                connectors.append(name)
    else:
        raise AIInventoryConfigError("ai_inventory.connectors must be an array or CSV string")
    connectors = list(dict.fromkeys(connectors))
    unknown = sorted(set(connectors) - set(_CONNECTORS))
    if unknown:
        raise AIInventoryConfigError(
            f"unknown AI inventory connector: {', '.join(unknown)}"
        )
    page_cap = raw.get("page_cap", 100)
    record_cap = raw.get("record_cap", _MAX_RECORDS)
    retry_attempts = raw.get("retry_attempts", 3)
    timeout_seconds = raw.get("timeout_seconds", 30.0)
    missing_grace = raw.get("missing_grace_runs", 2)
    if any(
        isinstance(value, bool) or not isinstance(value, int)
        for value in (page_cap, record_cap, retry_attempts, missing_grace)
    ):
        raise AIInventoryConfigError(
            "ai_inventory page, record, retry, and grace bounds must be integers"
        )
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
    ):
        raise AIInventoryConfigError("ai_inventory.timeout_seconds must be numeric")
    try:
        limits = DiscoveryLimits(
            page_cap=page_cap,
            record_cap=record_cap,
            retry_attempts=retry_attempts,
            timeout_seconds=float(timeout_seconds),
        )
        _bounded_int(
            missing_grace,
            "missing_grace_runs",
            minimum=1,
            maximum=100,
        )
    except (TypeError, ValueError) as exc:
        raise AIInventoryConfigError(str(exc)) from exc
    return {
        "enable": flag,
        "connectors": connectors,
        "limits": limits,
        "missing_grace_runs": missing_grace,
    }


def enabled() -> bool:
    """True only for a literal, readable ``[ai_inventory] enable = true``."""

    try:
        return get_ai_inventory_config()["enable"] is True
    except AIInventoryConfigError:
        return False


def require_enabled() -> dict[str, Any]:
    config = get_ai_inventory_config()
    if config["enable"] is not True:
        raise AIInventoryConfigError("AI inventory is disabled ([ai_inventory] enable)")
    return config


def available_connectors() -> list[str]:
    return list(_CONNECTORS)


def build_configured_adapter(
    name: str,
    *,
    transport: HttpTransport | None = None,
    control_client: BedrockControlClient | None = None,
    agent_client: BedrockAgentClient | None = None,
    sagemaker_client: SageMakerClient | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.time,
) -> InventoryAdapter:
    """Construct one fixed-operation adapter from safe env references."""

    config = require_enabled()
    connector = str(name or "").strip().lower()
    if connector not in config["connectors"]:
        raise AIInventoryConfigError(f"AI inventory connector is not enabled: {connector}")
    limits = config["limits"]
    if connector == "bedrock":
        return BedrockInventoryAdapter(
            control_client=control_client,
            agent_client=agent_client,
            limits=limits,
            sleep=sleep,
            clock=clock,
        )
    if connector in {
        "aws_sagemaker",
        "hugging_face",
        "mlflow",
        "salesforce_agentforce",
        "snowflake_cortex",
    }:
        from .ai_inventory_connectors import build_second_wave_adapter

        return build_second_wave_adapter(
            connector,
            enabled_connectors=config["connectors"],
            transport=transport,
            sagemaker_client=sagemaker_client,
            limits=limits,
            sleep=sleep,
            clock=clock,
        )
    if connector == "sagemaker":
        return SageMakerInventoryAdapter(
            sagemaker_client=sagemaker_client,
            limits=limits,
            sleep=sleep,
            clock=clock,
        )
    factories: dict[str, Callable[..., InventoryAdapter]] = {
        "agentforce": AgentforceInventoryAdapter,
        "azure_ai_foundry": AzureAIFoundryInventoryAdapter,
        "copilot_studio": CopilotStudioInventoryAdapter,
        "databricks_unity_catalog": DatabricksUnityCatalogInventoryAdapter,
        "huggingface": HuggingFaceInventoryAdapter,
        "openai": OpenAIInventoryAdapter,
        "replicate": ReplicateInventoryAdapter,
        "snowflake": SnowflakeInventoryAdapter,
        "vertex_ai": VertexAIInventoryAdapter,
    }
    factory = factories.get(connector)
    if factory is None:
        raise AIInventoryConfigError(f"unsupported AI inventory connector: {connector}")
    return factory(transport=transport, limits=limits, sleep=sleep, clock=clock)


def _status_id(connector: str) -> str:
    return f"AIS-{_sha256(connector)[:24]}"


def _asset_state_id(connector: str, source: str, source_id: str) -> str:
    return f"AIA-{_sha256([connector, source, source_id])[:24]}"


def _tenant() -> str:
    from .paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise AIInventoryConfigError("AI inventory requires an active tenant")
    return _required_text(tenant, "tenant", 256)


def _thread_lock(tenant: str, connector: str) -> threading.RLock:
    key = (tenant, connector)
    with _THREAD_LOCKS_GUARD:
        lock = _THREAD_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _THREAD_LOCKS[key] = lock
        return lock


def _lock_target(connector: str) -> Path:
    from .file_lock import ensure_private_directory
    from .paths import data_dir

    directory = data_dir("ai_inventory", "locks")
    ensure_private_directory(directory)
    return directory / f"{connector}.sync"


def _safe_error_type(exc: BaseException) -> str:
    name = type(exc).__name__
    return name if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,127}", name) else "InventoryError"


def _upsert(
    store: GovernedRecordStore,
    record_id: str,
    *,
    initial: Mapping[str, Any],
    changes: Mapping[str, Any],
    action: str,
    actor: str,
    max_records: int | None = None,
) -> dict[str, Any]:
    from .privacy_ops import RecordConflict

    for _attempt in range(3):
        current = store.get(record_id)
        if current is None:
            record = {"id": record_id, **dict(initial), **dict(changes)}
            try:
                return store.create(
                    record,
                    action=action,
                    actor=actor,
                    max_records=max_records,
                )
            except RecordConflict:
                continue

        def mutate(row: dict[str, Any]) -> None:
            row.update(dict(changes))

        try:
            saved = store.update(
                record_id,
                mutate,
                expected_revision=int(current.get("revision") or 0),
                action=action,
                actor=actor,
            )
        except RecordConflict:
            continue
        if saved is None:
            continue
        return saved
    raise DiscoverySyncError(f"governed {action} CAS retry budget exhausted")


class DiscoveryService:
    """Tenant-scoped, complete-run-before-missing discovery coordinator."""

    def __init__(
        self,
        *,
        runs: GovernedRecordStore | None = None,
        statuses: GovernedRecordStore | None = None,
        asset_states: GovernedRecordStore | None = None,
        observer: ModelRiskObserver | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._runs = runs or _RUNS
        self._statuses = statuses or _STATUSES
        self._asset_states = asset_states or _ASSET_STATES
        if observer is None:
            from . import model_risk_assurance

            observer = model_risk_assurance
        self._observer = observer
        self._clock = clock

    def _now(self) -> float:
        source = self._clock or self._runs.authoritative_time
        return _positive_timestamp(float(source()), "authority time")

    @staticmethod
    def _normalize_result(
        adapter: InventoryAdapter,
        result: DiscoveryResult,
    ) -> list[DiscoveredAsset]:
        if not isinstance(result, DiscoveryResult):
            raise DiscoveryProtocolError("adapter did not return a complete DiscoveryResult")
        if result.pages < 0 or result.pages > adapter.limits.page_cap:
            raise DiscoveryProtocolError("adapter reported an invalid page count")
        if len(result.assets) > adapter.limits.record_cap:
            raise DiscoveryLimitError("normalized asset cap exceeded")
        deduplicated: dict[tuple[str, str, str], DiscoveredAsset] = {}
        for asset in result.assets:
            if not isinstance(asset, DiscoveredAsset):
                raise DiscoveryProtocolError("adapter returned an untyped asset")
            if asset.source != adapter.source:
                raise DiscoveryProtocolError("adapter returned an unexpected source namespace")
            key = (asset.asset_type, asset.source, asset.source_id)
            prior = deduplicated.get(key)
            if prior is not None and prior != asset:
                raise DiscoveryProtocolError("provider returned conflicting duplicate identities")
            deduplicated[key] = asset
        return [deduplicated[key] for key in sorted(deduplicated)]

    def _observe(self, asset: DiscoveredAsset, *, actor: str) -> dict[str, Any]:
        from .model_risk_assurance import stable_asset_id
        from .privacy_ops import RecordConflict

        asset_id = stable_asset_id(asset.asset_type, asset.source, asset.source_id)
        metadata = {
            "record_origin": "discovered",
            "platform": asset.platform,
            "model": asset.model,
            "discovered_owner": asset.owner,
            "source_url": asset.source_url,
            "binding_strength": asset.binding_strength,
            **dict(asset.metadata),
        }
        _bounded_json(metadata, "observation metadata", max_nodes=2_048)
        _assert_no_sensitive_keys(metadata)
        for _attempt in range(3):
            current = self._observer.get_observation(asset_id)
            expected = int((current or {}).get("revision") or 0)
            try:
                return self._observer.observe_asset(
                    asset_type=asset.asset_type,
                    source=asset.source,
                    source_id=asset.source_id,
                    display_name=asset.display_name,
                    version_digest=asset.version_digest,
                    actor=actor,
                    expected_revision=expected,
                    observed_at=asset.last_seen,
                    metadata=metadata,
                    dependencies=[
                        _dependency_token(item) for item in asset.dependencies
                    ],
                )
            except RecordConflict:
                continue
        raise DiscoverySyncError("model-risk observation CAS retry budget exhausted")

    def _record_asset_state(
        self,
        adapter: InventoryAdapter,
        asset: DiscoveredAsset,
        observation: Mapping[str, Any],
        *,
        run_id: str,
        sequence: int,
        prior_completed_run_id: str,
        seen_at: float,
        actor: str,
    ) -> dict[str, Any]:
        from .privacy_ops import RecordConflict

        record_id = _asset_state_id(adapter.name, asset.source, asset.source_id)
        pending = {
            "pending_asset_id": observation.get("asset_id"),
            "pending_display_name": asset.display_name,
            "pending_version_digest": asset.version_digest,
            "pending_binding_strength": asset.binding_strength,
            "pending_owner": asset.owner,
            "pending_platform": asset.platform,
            "pending_model": asset.model,
            "pending_source_url": asset.source_url,
            "pending_provider_last_seen_at": asset.last_seen,
            "pending_last_seen_at": seen_at,
            "pending_seen_sequence": sequence,
            "pending_run_id": run_id,
            "pending_observation_revision": observation.get("revision"),
            "pending_observation_snapshot_sha256": observation.get("snapshot_sha256"),
        }
        for _attempt in range(3):
            current = self._asset_states.get(record_id)
            if current is None:
                record = {
                    "id": record_id,
                    "schema": "lightwork.ai-inventory-asset-state.v1",
                    "connector": adapter.name,
                    "source": asset.source,
                    "source_id": asset.source_id,
                    "asset_type": asset.asset_type,
                    "first_seen_at": seen_at,
                    "last_seen_sequence": 0,
                    "status": "staged",
                    **pending,
                }
                try:
                    return self._asset_states.create(
                        record,
                        action="stage_inventory_asset",
                        actor=actor,
                        max_records=_MAX_RECORDS,
                    )
                except RecordConflict:
                    continue

            def mutate(row: dict[str, Any]) -> None:
                if (
                    prior_completed_run_id
                    and row.get("pending_run_id") == prior_completed_run_id
                ):
                    for target, staged in _PENDING_TO_PUBLIC.items():
                        row[target] = row.get(staged)
                row.update(pending)
                row["status"] = "staged"

            try:
                saved = self._asset_states.update(
                    record_id,
                    mutate,
                    expected_revision=int(current.get("revision") or 0),
                    action="stage_inventory_asset",
                    actor=actor,
                )
            except RecordConflict:
                continue
            if saved is not None:
                return saved
        raise DiscoverySyncError("inventory asset-state CAS retry budget exhausted")

    def _finalize_prior_sightings(
        self,
        adapter: InventoryAdapter,
        *,
        completed_run_id: str,
        actor: str,
    ) -> None:
        """Promote only sightings authorized by the last completed run."""

        if not completed_run_id:
            return
        from .privacy_ops import RecordConflict

        rows = self._asset_states.list(limit=_MAX_RECORDS + 1)
        if len(rows) > _MAX_RECORDS:
            raise DiscoveryLimitError("AI inventory state namespace exceeds its bound")
        for snapshot in rows:
            if (
                snapshot.get("connector") != adapter.name
                or snapshot.get("pending_run_id") != completed_run_id
            ):
                continue

            def mutate(row: dict[str, Any]) -> None:
                if row.get("pending_run_id") != completed_run_id:
                    raise RecordConflict("inventory sighting changed during finalization")
                for target, staged in _PENDING_TO_PUBLIC.items():
                    row[target] = row.get(staged)
                row["status"] = "present"

            self._asset_states.update(
                str(snapshot["id"]),
                mutate,
                expected_revision=int(snapshot.get("revision") or 0),
                action="finalize_inventory_sighting",
                actor=actor,
            )

    def _begin_status(
        self,
        adapter: InventoryAdapter,
        *,
        run_id: str,
        at: float,
        actor: str,
    ) -> dict[str, Any]:
        return _upsert(
            self._statuses,
            _status_id(adapter.name),
            initial={
                "schema": "lightwork.ai-inventory-connector-status.v1",
                "connector": adapter.name,
                "source": adapter.source,
                "completed_sequence": 0,
            },
            changes={
                "state": "running",
                "last_attempt_id": run_id,
                "last_attempt_at": at,
                "last_error_type": "",
            },
            action="start_inventory_sync",
            actor=actor,
            max_records=len(_CONNECTORS),
        )

    def _complete_status(
        self,
        adapter: InventoryAdapter,
        *,
        run_id: str,
        sequence: int,
        at: float,
        asset_count: int,
        identity_digest: str,
        actor: str,
    ) -> dict[str, Any]:
        return _upsert(
            self._statuses,
            _status_id(adapter.name),
            initial={
                "schema": "lightwork.ai-inventory-connector-status.v1",
                "connector": adapter.name,
                "source": adapter.source,
            },
            changes={
                "state": "complete",
                "completed_sequence": sequence,
                "last_completed_id": run_id,
                "last_completed_at": at,
                "last_asset_count": asset_count,
                "last_identity_digest": identity_digest,
                "last_error_type": "",
            },
            action="complete_inventory_sync",
            actor=actor,
            max_records=len(_CONNECTORS),
        )

    def _fail_status(
        self,
        adapter: InventoryAdapter,
        *,
        run_id: str,
        state: str,
        at: float,
        exc: BaseException,
        actor: str,
    ) -> None:
        try:
            _upsert(
                self._statuses,
                _status_id(adapter.name),
                initial={
                    "schema": "lightwork.ai-inventory-connector-status.v1",
                    "connector": adapter.name,
                    "source": adapter.source,
                    "completed_sequence": 0,
                },
                changes={
                    "state": state,
                    "last_attempt_id": run_id,
                    "last_attempt_at": at,
                    "last_error_type": _safe_error_type(exc),
                },
                action="fail_inventory_sync",
                actor=actor,
                max_records=len(_CONNECTORS),
            )
        except Exception:
            pass

    def _finish_run(
        self,
        run: Mapping[str, Any],
        *,
        changes: Mapping[str, Any],
        action: str,
        actor: str,
    ) -> dict[str, Any]:
        current = self._runs.get(str(run["id"])) or dict(run)

        def mutate(row: dict[str, Any]) -> None:
            row.update(dict(changes))

        saved = self._runs.update(
            str(run["id"]),
            mutate,
            expected_revision=int(current.get("revision") or 0),
            action=action,
            actor=actor,
        )
        if saved is None:
            raise DiscoverySyncError("discovery run disappeared")
        return saved

    def sync(
        self,
        adapter: InventoryAdapter,
        *,
        actor: str,
        require_feature: bool = True,
    ) -> dict[str, Any]:  # noqa: C901 - one fail-closed transaction narrative
        if require_feature:
            require_enabled()
        operator = _required_text(actor, "actor", 256)
        connector = _required_text(adapter.name, "connector name", 64)
        source = _required_text(adapter.source, "connector source", 64)
        if not _SLUG.fullmatch(connector) or connector not in _CONNECTORS:
            raise AIInventoryConfigError("adapter connector name is not registered")
        tenant = _tenant()
        from .file_lock import cross_process_lock

        local_lock = _thread_lock(tenant, connector)
        with local_lock, cross_process_lock(_lock_target(connector), strict=True):
            started = self._now()
            run_id = f"AIR-{uuid.uuid4().hex}"
            run = self._runs.create(
                {
                    "id": run_id,
                    "schema": "lightwork.ai-inventory-discovery-run.v1",
                    "connector": connector,
                    "source": source,
                    "tenant": tenant,
                    "status": "running",
                    "started_at": started,
                    "page_cap": adapter.limits.page_cap,
                    "record_cap": adapter.limits.record_cap,
                },
                action="start_inventory_discovery_run",
                actor=operator,
                max_records=_MAX_RUNS,
            )
            status = self._begin_status(
                adapter,
                run_id=run_id,
                at=started,
                actor=operator,
            )
            sequence = int(status.get("completed_sequence") or 0) + 1
            prior_completed_run_id = str(status.get("last_completed_id") or "")
            admitted = 0
            try:
                self._finalize_prior_sightings(
                    adapter,
                    completed_run_id=prior_completed_run_id,
                    actor=operator,
                )
                result = adapter.discover()
                assets = self._normalize_result(adapter, result)
                identities = [
                    {
                        "asset_type": asset.asset_type,
                        "source": asset.source,
                        "source_id": asset.source_id,
                        "version_digest": asset.version_digest,
                    }
                    for asset in assets
                ]
                identity_digest = _sha256(identities)
                for asset in assets:
                    observation = self._observe(asset, actor=operator)
                    self._record_asset_state(
                        adapter,
                        asset,
                        observation,
                        run_id=run_id,
                        sequence=sequence,
                        prior_completed_run_id=prior_completed_run_id,
                        seen_at=started,
                        actor=operator,
                    )
                    admitted += 1
                completed = self._now()
                self._complete_status(
                    adapter,
                    run_id=run_id,
                    sequence=sequence,
                    at=completed,
                    asset_count=len(assets),
                    identity_digest=identity_digest,
                    actor=operator,
                )
                finished = self._finish_run(
                    run,
                    changes={
                        "status": "complete",
                        "completed_at": completed,
                        "completed_sequence": sequence,
                        "pages": result.pages,
                        "asset_count": len(assets),
                        "identity_digest": identity_digest,
                    },
                    action="complete_inventory_discovery_run",
                    actor=operator,
                )
                return self._summary(finished)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                failed_at = self._now()
                state = "partial" if admitted else "failed"
                self._fail_status(
                    adapter,
                    run_id=run_id,
                    state=state,
                    at=failed_at,
                    exc=exc,
                    actor=operator,
                )
                try:
                    self._finish_run(
                        run,
                        changes={
                            "status": state,
                            "completed_at": failed_at,
                            "admitted_count": admitted,
                            "error_type": _safe_error_type(exc),
                        },
                        action="fail_inventory_discovery_run",
                        actor=operator,
                    )
                except Exception:
                    pass
                raise DiscoverySyncError(
                    f"{connector} inventory sync did not complete ({_safe_error_type(exc)})"
                ) from exc

    @staticmethod
    def _summary(run: Mapping[str, Any]) -> dict[str, Any]:
        return {
            key: run.get(key)
            for key in (
                "id",
                "connector",
                "source",
                "status",
                "started_at",
                "completed_at",
                "completed_sequence",
                "pages",
                "asset_count",
                "identity_digest",
                "revision",
            )
        }

    def status(self, connector: str) -> dict[str, Any] | None:
        _tenant()
        name = _required_text(connector, "connector", 64)
        row = self._statuses.get(_status_id(name))
        return None if row is None else _status_projection(row, expected_connector=name)

    def list_runs(self, *, connector: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        _tenant()
        count = _bounded_int(limit, "limit", minimum=1, maximum=500)
        rows = self._runs.list(limit=_MAX_RUNS + 1)
        if len(rows) > _MAX_RUNS:
            raise DiscoveryLimitError("discovery run namespace exceeds its bound")
        if connector:
            name = _required_text(connector, "connector", 64)
            rows = [row for row in rows if row.get("connector") == name]
        rows.sort(key=lambda row: float(row.get("started_at") or 0), reverse=True)
        return [self._summary(row) | {"error_type": row.get("error_type", "")} for row in rows[:count]]

    def list_asset_states(
        self,
        *,
        connector: str | None = None,
        missing_grace_runs: int | None = None,
    ) -> list[dict[str, Any]]:
        _tenant()
        if missing_grace_runs is None:
            grace = int(get_ai_inventory_config()["missing_grace_runs"])
        else:
            grace = _bounded_int(
                missing_grace_runs,
                "missing_grace_runs",
                minimum=1,
                maximum=100,
            )
        states = self._asset_states.list(limit=_MAX_RECORDS + 1)
        if len(states) > _MAX_RECORDS:
            raise DiscoveryLimitError("AI inventory state namespace exceeds its bound")
        selected = connector.strip().lower() if connector else ""
        status_cache: dict[str, tuple[int, str]] = {}
        out: list[dict[str, Any]] = []
        for state in states:
            raw_state = _persisted_record(state, "asset state")
            name = _persisted_text(
                raw_state,
                "connector",
                maximum=64,
                kind="asset state",
            )
            if selected and name != selected:
                continue
            if name not in status_cache:
                raw_status = self._statuses.get(_status_id(name))
                if raw_status is None:
                    raise DiscoveryProtocolError(
                        "persisted AI inventory asset state lacks connector authority"
                    )
                status = _status_projection(
                    raw_status,
                    expected_connector=name,
                )
                status_cache[name] = (
                    status["completed_sequence"],
                    str(status.get("last_completed_id") or ""),
                )
            completed, completed_run_id = status_cache[name]
            projected = _asset_state_projection(
                raw_state,
                completed_sequence=completed,
                completed_run_id=completed_run_id,
                missing_grace_runs=grace,
            )
            if projected is not None:
                out.append(projected)
        out.sort(key=lambda row: (str(row.get("connector")), str(row.get("asset_id"))))
        return out


_DEFAULT = DiscoveryService()


def sync_adapter(
    adapter: InventoryAdapter,
    *,
    actor: str,
    require_feature: bool = True,
) -> dict[str, Any]:
    return _DEFAULT.sync(adapter, actor=actor, require_feature=require_feature)


def sync_connector(
    name: str,
    *,
    actor: str,
    transport: HttpTransport | None = None,
    control_client: BedrockControlClient | None = None,
    agent_client: BedrockAgentClient | None = None,
    sagemaker_client: SageMakerClient | None = None,
) -> dict[str, Any]:
    adapter = build_configured_adapter(
        name,
        transport=transport,
        control_client=control_client,
        agent_client=agent_client,
        sagemaker_client=sagemaker_client,
    )
    return _DEFAULT.sync(adapter, actor=actor)


def connector_status(name: str) -> dict[str, Any] | None:
    return _DEFAULT.status(name)


def list_discovery_runs(
    *,
    connector: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    return _DEFAULT.list_runs(connector=connector, limit=limit)


def list_discovered_assets(
    *,
    connector: str | None = None,
    missing_grace_runs: int | None = None,
) -> list[dict[str, Any]]:
    return _DEFAULT.list_asset_states(
        connector=connector,
        missing_grace_runs=missing_grace_runs,
    )


__all__ = [
    "AIInventoryConfigError",
    "AIInventoryError",
    "AzureAIFoundryInventoryAdapter",
    "BedrockInventoryAdapter",
    "CopilotStudioInventoryAdapter",
    "DatabricksUnityCatalogInventoryAdapter",
    "DiscoveredAsset",
    "DiscoveryLimitError",
    "DiscoveryLimits",
    "DiscoveryProtocolError",
    "DiscoveryResult",
    "DiscoveryService",
    "DiscoverySyncError",
    "DiscoveryTransportError",
    "VertexAIInventoryAdapter",
    "available_connectors",
    "build_configured_adapter",
    "connector_status",
    "enabled",
    "get_ai_inventory_config",
    "list_discovered_assets",
    "list_discovery_runs",
    "require_enabled",
    "sync_adapter",
    "sync_connector",
]
