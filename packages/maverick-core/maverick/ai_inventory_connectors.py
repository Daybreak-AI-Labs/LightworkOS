"""Bounded second-wave connectors for :mod:`maverick.ai_inventory`.

These adapters deliberately expose only fixed, read-only provider list and
describe operations.  They never accept a caller-selected URL, SOQL statement,
or SDK method.  Connector construction is default-deny through
``build_second_wave_adapter``; the caller must pass the already validated set
of enabled connector names from the tenant-scoped inventory configuration.

Credentials are environment-variable *references*.  Values are resolved only
for a request and are never copied into normalized assets.  A pagination cap,
record cap, retry cap, and request timeout are applied to every discovery run.
Any malformed completion marker, missing continuation token, token cycle, or
limit hit raises instead of returning a partial ``DiscoveryResult``.
"""
from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import parse_qs, quote, urlencode, urljoin, urlsplit

from .ai_inventory import (
    AIInventoryConfigError,
    DiscoveredAsset,
    DiscoveryLimitError,
    DiscoveryLimits,
    DiscoveryProtocolError,
    DiscoveryResult,
    DiscoveryTransportError,
    HttpTransport,
    _asset,
    _bounded_json,
    _credential,
    _DefaultHttpTransport,
    _items,
    _mapping,
    _optional_text,
    _PaginationBudget,
    _required_text,
    _safe_base_url,
    _selected_metadata,
    _sha256,
    _sleep_delay,
)

SECOND_WAVE_CONNECTORS = (
    "mlflow",
    "aws_sagemaker",
    "snowflake_cortex",
    "salesforce_agentforce",
    "hugging_face",
)
_FIRST_WAVE_CONNECTORS = frozenset(
    {
        "azure_ai_foundry",
        "bedrock",
        "copilot_studio",
        "databricks_unity_catalog",
        "vertex_ai",
    }
)
_CONFIGURED_CONNECTORS = _FIRST_WAVE_CONNECTORS | frozenset(SECOND_WAVE_CONNECTORS)

_ENV_REFERENCE = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")
_REGION = re.compile(r"^[a-z0-9-]{2,32}$")
_SALESFORCE_API_VERSION = re.compile(r"^v(?:[6-9][0-9])\.0$")
_HF_NAMESPACE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,94}[A-Za-z0-9])?$")
_HF_REVISION = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})
_RETRYABLE_SDK_CODES = frozenset(
    {
        "InternalFailure",
        "InternalServerException",
        "RequestLimitExceeded",
        "ServiceUnavailable",
        "ServiceUnavailableException",
        "Throttling",
        "ThrottlingException",
        "TooManyRequestsException",
    }
)
_MAX_SCOPES = 64
_HF_EXPAND = (
    "author",
    "sha",
    "lastModified",
    "private",
    "gated",
    "pipeline_tag",
    "library_name",
)

_MLFLOW_REGISTERED_MODELS_PATH = "/api/2.0/mlflow/registered-models/search"
_MLFLOW_MODEL_VERSIONS_PATH = "/api/2.0/mlflow/model-versions/search"
_SALESFORCE_AGENT_QUERY = (
    "SELECT Id,DeveloperName,MasterLabel,Type,AgentType,CreatedById,"
    "CreatedDate,LastModifiedById,LastModifiedDate FROM BotDefinition "
    "WHERE Type != 'Bot' ORDER BY Id"
)
_SALESFORCE_VERSION_QUERY = (
    "SELECT Id,BotDefinitionId,VersionNumber,Status,CreatedDate,"
    "LastModifiedDate FROM BotVersion WHERE BotDefinition.Type != 'Bot' ORDER BY Id"
)


class SageMakerClient(Protocol):
    """The only SageMaker control-plane operations this connector may invoke."""

    def list_models(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def list_endpoints(self, **kwargs: Any) -> Mapping[str, Any]: ...


def _env_reference(value: str, label: str) -> str:
    if not isinstance(value, str) or not _ENV_REFERENCE.fullmatch(value.strip()):
        raise AIInventoryConfigError(f"{label} must be an environment-variable name")
    return value.strip()


def _env_value(reference: str, label: str) -> str:
    name = _env_reference(reference, f"{label} reference")
    value = os.environ.get(name, "").strip()
    if not value:
        raise AIInventoryConfigError(f"{label} reference is unavailable: {name}")
    return value


def _config_text(value: Any, label: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise AIInventoryConfigError(f"{label} must be a string")
    text = value.strip()
    if not text or len(text) > maximum or any(ord(char) < 32 for char in text):
        raise AIInventoryConfigError(f"{label} is missing or exceeds its bound")
    return text


def _headers(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise DiscoveryProtocolError("provider response headers must be a mapping")
    headers: dict[str, str] = {}
    for key, item in value.items():
        name = str(key)
        text = str(item)
        if len(name) > 256 or len(text) > 16_384:
            raise DiscoveryProtocolError("provider response header exceeds its bound")
        headers[name] = text
    return headers


def _header(headers: Mapping[str, str], name: str) -> str | None:
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return value
    return None


def _request_json(
    transport: HttpTransport,
    url: str,
    *,
    connector: str,
    token_env: str,
    limits: DiscoveryLimits,
    sleep: Callable[[float], None],
    clock: Callable[[], float],
    params: Mapping[str, Any] | None = None,
    extra_headers: Mapping[str, str] | None = None,
) -> tuple[Any, Mapping[str, str]]:
    token = _credential(_env_reference(token_env, f"{connector} token reference"))
    request_headers = {"Accept": "application/json", "Authorization": f"Bearer {token}"}
    request_headers.update(dict(extra_headers or {}))
    for attempt in range(limits.retry_attempts):
        try:
            response = transport.get(
                url,
                headers=request_headers,
                params=params,
                timeout=float(limits.timeout_seconds),
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except (DiscoveryProtocolError, DiscoveryTransportError):
            raise
        except Exception as exc:
            if attempt + 1 >= limits.retry_attempts:
                raise DiscoveryTransportError(
                    f"{connector} request failed ({type(exc).__name__})"
                ) from exc
            _sleep_delay(attempt, {}, sleep=sleep, now=clock)
            continue
        response_headers = _headers(response.headers)
        try:
            status = int(response.status_code)
        except (TypeError, ValueError) as exc:
            raise DiscoveryProtocolError("provider response status is malformed") from exc
        if status in _RETRYABLE_STATUS and attempt + 1 < limits.retry_attempts:
            _sleep_delay(attempt, response_headers, sleep=sleep, now=clock)
            continue
        if not 200 <= status < 300:
            raise DiscoveryTransportError(f"{connector} request failed with HTTP {status}")
        try:
            payload = response.json()
        except (TypeError, ValueError) as exc:
            raise DiscoveryProtocolError(f"{connector} response was not JSON") from exc
        _bounded_json(payload, f"{connector} response")
        return payload, response_headers
    raise DiscoveryTransportError(f"{connector} retry budget exhausted")


def _sdk_exception_details(exc: Exception) -> tuple[int, str, Mapping[str, str]]:
    response = getattr(exc, "response", None)
    if not isinstance(response, Mapping):
        return 0, "", {}
    metadata = response.get("ResponseMetadata")
    error = response.get("Error")
    status = 0
    code = ""
    headers: Mapping[str, str] = {}
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


def _sdk_json_call(
    method: Callable[..., Mapping[str, Any]],
    kwargs: Mapping[str, Any],
    *,
    connector: str,
    operation: str,
    limits: DiscoveryLimits,
    sleep: Callable[[float], None],
    clock: Callable[[], float],
) -> Mapping[str, Any]:
    for attempt in range(limits.retry_attempts):
        try:
            return _mapping(method(**dict(kwargs)), f"{connector} {operation} page")
        except (KeyboardInterrupt, SystemExit):
            raise
        except DiscoveryProtocolError:
            raise
        except Exception as exc:
            status, code, headers = _sdk_exception_details(exc)
            retryable = status in _RETRYABLE_STATUS or code in _RETRYABLE_SDK_CODES or not status
            if not retryable or attempt + 1 >= limits.retry_attempts:
                detail = code or type(exc).__name__
                raise DiscoveryTransportError(
                    f"{connector} {operation} failed ({detail})"
                ) from exc
            _sleep_delay(attempt, headers, sleep=sleep, now=clock)
    raise DiscoveryTransportError(f"{connector} {operation} retry budget exhausted")


def _continuation_token(
    page: Mapping[str, Any],
    key: str,
    *,
    connector: str,
) -> str:
    raw = page.get(key)
    token = "" if raw in (None, "") else _required_text(raw, f"{connector} {key}", 8_192)
    for marker in (
        "truncated",
        "is_truncated",
        "isTruncated",
        "IsTruncated",
        "has_more",
        "hasMore",
        "incomplete",
    ):
        if marker not in page:
            continue
        flag = page[marker]
        if not isinstance(flag, bool):
            raise DiscoveryProtocolError(f"{connector} {marker} marker must be boolean")
        if flag and not token:
            raise DiscoveryProtocolError(
                f"{connector} reported a partial page without a continuation token"
            )
    return token


def _optional_mapping(row: Mapping[str, Any], key: str, label: str) -> Mapping[str, Any]:
    value = row.get(key)
    if value in (None, ""):
        return {}
    return _mapping(value, label)


def _owner_from_tags(value: Any, fallback: Any = None) -> str:
    if isinstance(value, Mapping):
        candidates = value.items()
    elif isinstance(value, list):
        candidates = (
            (item.get("key"), item.get("value"))
            for item in value
            if isinstance(item, Mapping)
        )
    else:
        candidates = ()
    wanted = {"owner", "team", "responsible_owner", "lightwork:owner"}
    for key, item in candidates:
        if str(key).strip().lower() in wanted and item not in (None, ""):
            return _optional_text(item, 256)
    return _optional_text(fallback, 256)


class _BearerHttpAdapter:
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
        self.token_env = _env_reference(token_env, f"{self.name} token reference")
        self.transport = transport or _DefaultHttpTransport(self.name)
        self.limits = limits or DiscoveryLimits()
        self._sleep = sleep
        self._clock = clock
        self._authority_key = _sha256(self.base_url)[:16]

    def _request(
        self,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        extra_headers: Mapping[str, str] | None = None,
    ) -> tuple[Any, Mapping[str, str]]:
        return _request_json(
            self.transport,
            url,
            connector=self.name,
            token_env=self.token_env,
            limits=self.limits,
            sleep=self._sleep,
            clock=self._clock,
            params=params,
            extra_headers=extra_headers,
        )


class MLflowInventoryAdapter(_BearerHttpAdapter):
    """MLflow registered models and every registry model version."""

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
        resolved = tracking_uri or _env_value(tracking_uri_env, "MLflow tracking URI")
        super().__init__(
            base_url=resolved,
            token_env=token_env,
            transport=transport,
            limits=limits,
            sleep=sleep,
            clock=clock,
        )

    def _pages(
        self,
        path: str,
        item_key: str,
        budget: _PaginationBudget,
    ) -> list[Mapping[str, Any]]:
        token = ""
        seen: set[str] = set()
        rows: list[Mapping[str, Any]] = []
        while True:
            if token in seen:
                raise DiscoveryProtocolError("MLflow pagination token cycle detected")
            seen.add(token)
            budget.page()
            params: dict[str, Any] = {"max_results": 100}
            if token:
                params["page_token"] = token
            payload, _headers_value = self._request(f"{self.base_url}{path}", params=params)
            page = _mapping(payload, "MLflow page")
            current = _items(page, item_key)
            budget.add_records(len(current))
            rows.extend(current)
            token = _continuation_token(
                page,
                "next_page_token",
                connector="MLflow",
            )
            if not token:
                return rows

    def _root_asset(
        self,
        row: Mapping[str, Any],
        versions: Sequence[Mapping[str, Any]],
        now: float,
    ) -> DiscoveredAsset:
        name = _required_text(row.get("name"), "MLflow registered model name", 256)
        source_id = f"{self._authority_key}:model:{_sha256(name)[:24]}"
        version_summary = sorted(
            (
                {
                    "version": str(item.get("version")),
                    "status": item.get("status"),
                    "stage": item.get("current_stage"),
                    "source": _sha256(item.get("source")),
                }
                for item in versions
            ),
            key=lambda item: item["version"],
        )
        return _asset(
            asset_type="model",
            source=self.source,
            source_id=source_id,
            display_name=name,
            version_authority={
                "registry": self._authority_key,
                "name": name,
                "updated_at": row.get("last_updated_timestamp"),
                "versions": version_summary,
            },
            binding_strength="observed_snapshot",
            owner=_owner_from_tags(row.get("tags"), row.get("user_id")),
            platform="MLflow Model Registry",
            model=name,
            last_seen=row.get("last_updated_timestamp") or row.get("creation_timestamp"),
            fallback_time=now,
            source_url=self.base_url,
            metadata=_selected_metadata(
                resource_kind="registered_model",
                registry_key=self._authority_key,
                version_count=len(versions),
                deployment_state=row.get("deployment_job_state"),
            ),
        )

    def _version_asset(
        self,
        row: Mapping[str, Any],
        root_id: str,
        now: float,
    ) -> DiscoveredAsset:
        name = _required_text(row.get("name"), "MLflow model version name", 256)
        raw_version = row.get("version")
        if isinstance(raw_version, bool) or not isinstance(raw_version, (str, int)):
            raise DiscoveryProtocolError("MLflow model version must be a string or integer")
        version = _required_text(str(raw_version), "MLflow model version", 64)
        display = f"{name} v{version}"
        if len(display) > 256:
            display = name
        return _asset(
            asset_type="model",
            source=self.source,
            source_id=f"{root_id}:v:{_sha256(version)[:16]}",
            display_name=display,
            version_authority={
                "registry": self._authority_key,
                "name": name,
                "version": version,
                "source": _sha256(row.get("source")),
                "run_id": row.get("run_id"),
            },
            binding_strength="immutable_provider_revision",
            owner=_owner_from_tags(row.get("tags"), row.get("user_id")),
            platform="MLflow Model Registry",
            model=name,
            last_seen=row.get("last_updated_timestamp") or row.get("creation_timestamp"),
            fallback_time=now,
            source_url=self.base_url,
            metadata=_selected_metadata(
                resource_kind="model_version",
                version=version,
                status=row.get("status"),
                stage=row.get("current_stage"),
                run_id=row.get("run_id"),
                registry_key=self._authority_key,
            ),
            dependencies=(root_id,),
        )

    def discover(self) -> DiscoveryResult:
        budget = _PaginationBudget(self.limits)
        registered = self._pages(
            _MLFLOW_REGISTERED_MODELS_PATH,
            "registered_models",
            budget,
        )
        versions = self._pages(_MLFLOW_MODEL_VERSIONS_PATH, "model_versions", budget)
        by_name: dict[str, list[Mapping[str, Any]]] = {}
        for row in versions:
            name = _required_text(row.get("name"), "MLflow model version name", 256)
            by_name.setdefault(name, []).append(row)
        roots: dict[str, str] = {}
        now = self._clock()
        assets: list[DiscoveredAsset] = []
        for row in registered:
            name = _required_text(row.get("name"), "MLflow registered model name", 256)
            if name in roots:
                raise DiscoveryProtocolError("MLflow returned a duplicate registered model")
            root = self._root_asset(row, by_name.get(name, ()), now)
            roots[name] = root.source_id
            assets.append(root)
        unknown = sorted(set(by_name) - set(roots))
        if unknown:
            raise DiscoveryProtocolError("MLflow returned versions without registered models")
        for name, rows in by_name.items():
            assets.extend(self._version_asset(row, roots[name], now) for row in rows)
        return DiscoveryResult(tuple(assets), budget.pages)


class SageMakerInventoryAdapter:
    """AWS SageMaker model definitions and hosted inference endpoints."""

    name = "aws_sagemaker"
    source = "aws_sagemaker"

    def __init__(
        self,
        *,
        client: SageMakerClient | None = None,
        region: str | None = None,
        limits: DiscoveryLimits | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._client_value = client
        self.region = (
            region
            or os.environ.get("AWS_REGION")
            or os.environ.get("AWS_DEFAULT_REGION")
            or ""
        ).strip()
        if self.region and not _REGION.fullmatch(self.region):
            raise AIInventoryConfigError("AWS SageMaker region is malformed")
        self.limits = limits or DiscoveryLimits()
        self._sleep = sleep
        self._clock = clock

    def _client(self) -> SageMakerClient:
        if self._client_value is not None:
            return self._client_value
        try:
            import boto3  # type: ignore[import-not-found]
            from botocore.config import Config  # type: ignore[import-not-found]
        except ImportError as exc:
            raise AIInventoryConfigError(
                "SageMaker inventory requires boto3 or an injected SageMaker client"
            ) from exc
        profile = os.environ.get("AWS_PROFILE", "").strip() or None
        session = boto3.Session(profile_name=profile, region_name=self.region or None)
        timeout = float(self.limits.timeout_seconds)
        self._client_value = session.client(
            "sagemaker",
            config=Config(
                connect_timeout=timeout,
                read_timeout=timeout,
                retries={"max_attempts": 0},
            ),
        )
        return self._client_value

    def _pages(
        self,
        method: Callable[..., Mapping[str, Any]],
        item_key: str,
        operation: str,
        budget: _PaginationBudget,
    ) -> list[Mapping[str, Any]]:
        token = ""
        seen: set[str] = set()
        rows: list[Mapping[str, Any]] = []
        while True:
            if token in seen:
                raise DiscoveryProtocolError("SageMaker pagination token cycle detected")
            seen.add(token)
            budget.page()
            kwargs: dict[str, Any] = {"MaxResults": 100}
            if token:
                kwargs["NextToken"] = token
            page = _sdk_json_call(
                method,
                kwargs,
                connector="SageMaker",
                operation=operation,
                limits=self.limits,
                sleep=self._sleep,
                clock=self._clock,
            )
            current = _items(page, item_key)
            budget.add_records(len(current))
            rows.extend(current)
            token = _continuation_token(page, "NextToken", connector="SageMaker")
            if not token:
                return rows

    def _model_asset(self, row: Mapping[str, Any], now: float) -> DiscoveredAsset:
        name = _required_text(row.get("ModelName"), "SageMaker model name", 256)
        arn = _required_text(row.get("ModelArn"), "SageMaker model ARN", 256)
        return _asset(
            asset_type="model",
            source=self.source,
            source_id=arn,
            display_name=name,
            version_authority={
                "arn": arn,
                "created_at": row.get("CreationTime"),
            },
            binding_strength="observed_snapshot",
            owner="unknown",
            platform="AWS SageMaker",
            model=name,
            last_seen=row.get("CreationTime"),
            fallback_time=now,
            source_url="https://console.aws.amazon.com/sagemaker/home",
            metadata=_selected_metadata(
                resource_kind="model",
                region=self.region or None,
            ),
        )

    def _endpoint_asset(self, row: Mapping[str, Any], now: float) -> DiscoveredAsset:
        name = _required_text(row.get("EndpointName"), "SageMaker endpoint name", 256)
        arn = _required_text(row.get("EndpointArn"), "SageMaker endpoint ARN", 256)
        return _asset(
            asset_type="model",
            source=self.source,
            source_id=arn,
            display_name=name,
            version_authority={
                "arn": arn,
                "status": row.get("EndpointStatus"),
                "updated_at": row.get("LastModifiedTime"),
            },
            binding_strength="observed_snapshot",
            owner="unknown",
            platform="AWS SageMaker",
            model="unknown",
            last_seen=row.get("LastModifiedTime") or row.get("CreationTime"),
            fallback_time=now,
            source_url="https://console.aws.amazon.com/sagemaker/home",
            metadata=_selected_metadata(
                resource_kind="endpoint",
                status=row.get("EndpointStatus"),
                region=self.region or None,
            ),
        )

    def discover(self) -> DiscoveryResult:
        client = self._client()
        if not callable(getattr(client, "list_models", None)) or not callable(
            getattr(client, "list_endpoints", None)
        ):
            raise AIInventoryConfigError("injected SageMaker client lacks fixed list operations")
        budget = _PaginationBudget(self.limits)
        models = self._pages(client.list_models, "Models", "ListModels", budget)
        endpoints = self._pages(client.list_endpoints, "Endpoints", "ListEndpoints", budget)
        now = self._clock()
        assets = [self._model_asset(row, now) for row in models]
        assets.extend(self._endpoint_asset(row, now) for row in endpoints)
        return DiscoveryResult(tuple(assets), budget.pages)


@dataclass(frozen=True)
class SnowflakeCortexScope:
    """One explicitly admitted Snowflake database/schema discovery scope."""

    database: str
    schema: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "database", _config_text(self.database, "database", 255))
        object.__setattr__(self, "schema", _config_text(self.schema, "schema", 255))


def _scope(value: Any) -> SnowflakeCortexScope:
    if isinstance(value, SnowflakeCortexScope):
        return value
    if isinstance(value, Mapping):
        unknown = set(value) - {"database", "schema"}
        if unknown:
            raise AIInventoryConfigError("Snowflake Cortex scope has unsupported fields")
        return SnowflakeCortexScope(
            database=value.get("database"),
            schema=value.get("schema"),
        )
    if isinstance(value, (list, tuple)) and len(value) == 2:
        return SnowflakeCortexScope(database=value[0], schema=value[1])
    raise AIInventoryConfigError("Snowflake Cortex scope must contain database and schema")


def _snowflake_scopes(value: Sequence[Any] | None, reference: str) -> tuple[SnowflakeCortexScope, ...]:
    raw: Any = value
    if raw is None:
        encoded = _env_value(reference, "Snowflake Cortex scopes")
        try:
            raw = json.loads(encoded)
        except (TypeError, ValueError) as exc:
            raise AIInventoryConfigError("Snowflake Cortex scopes must be valid JSON") from exc
        try:
            _bounded_json(raw, "Snowflake Cortex scopes", max_nodes=512)
        except DiscoveryProtocolError as exc:
            raise AIInventoryConfigError("Snowflake Cortex scopes exceed their bound") from exc
    if isinstance(raw, (str, bytes)) or not isinstance(raw, Sequence):
        raise AIInventoryConfigError("Snowflake Cortex scopes must be an array")
    if not 1 <= len(raw) <= _MAX_SCOPES:
        raise AIInventoryConfigError(f"Snowflake Cortex scopes must contain 1-{_MAX_SCOPES} entries")
    scopes = tuple(_scope(item) for item in raw)
    identities = [(item.database.casefold(), item.schema.casefold()) for item in scopes]
    if len(set(identities)) != len(identities):
        raise AIInventoryConfigError("Snowflake Cortex scopes must be unique")
    return scopes


def _link_entries(headers: Mapping[str, str], connector: str) -> list[tuple[str, set[str]]]:
    raw = _header(headers, "Link")
    if raw is None or not raw.strip():
        return []
    entries: list[tuple[str, set[str]]] = []
    for part in raw.split(","):
        match = re.fullmatch(r"\s*<([^<>]+)>\s*((?:;[^;]*)*)\s*", part)
        if match is None:
            raise DiscoveryProtocolError(f"{connector} Link header is malformed")
        relations: set[str] = set()
        for parameter in match.group(2).split(";"):
            parameter = parameter.strip()
            if not parameter or "=" not in parameter:
                continue
            key, item = parameter.split("=", 1)
            if key.strip().lower() == "rel":
                relations.update(item.strip().strip('"').lower().split())
        if not relations:
            raise DiscoveryProtocolError(f"{connector} Link entry lacks a relation")
        entries.append((match.group(1), relations))
    return entries


def _next_link(headers: Mapping[str, str], connector: str) -> str:
    candidates = [url for url, relations in _link_entries(headers, connector) if "next" in relations]
    if len(candidates) > 1:
        raise DiscoveryProtocolError(f"{connector} returned multiple next links")
    return candidates[0] if candidates else ""


def _same_origin_path(base_url: str, candidate: str, *, expected_path: str) -> str:
    resolved = urljoin(f"{base_url}/", _required_text(candidate, "provider next link", 16_384))
    base = urlsplit(base_url)
    parsed = urlsplit(resolved)
    try:
        cross_port = parsed.port != base.port
    except ValueError as exc:
        raise DiscoveryProtocolError("provider next link has an invalid port") from exc
    if (
        parsed.scheme.lower() != "https"
        or parsed.hostname != base.hostname
        or cross_port
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.path != expected_path
    ):
        raise DiscoveryProtocolError("provider next link crossed its fixed API surface")
    return resolved


def _same_origin_prefix(base_url: str, candidate: str, *, expected_prefix: str) -> str:
    resolved = urljoin(f"{base_url}/", _required_text(candidate, "provider next link", 16_384))
    base = urlsplit(base_url)
    parsed = urlsplit(resolved)
    try:
        cross_port = parsed.port != base.port
    except ValueError as exc:
        raise DiscoveryProtocolError("provider next link has an invalid port") from exc
    if (
        parsed.scheme.lower() != "https"
        or parsed.hostname != base.hostname
        or cross_port
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or not parsed.path.startswith(expected_prefix)
        or not re.fullmatch(r"[A-Za-z0-9_-]{1,2048}", parsed.path.removeprefix(expected_prefix))
        or parsed.query
    ):
        raise DiscoveryProtocolError("provider next link crossed its fixed API surface")
    return resolved


def _snowflake_spec(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return _mapping(value, "Snowflake Cortex agent specification")
    if not isinstance(value, str) or not value.strip():
        raise DiscoveryProtocolError("Snowflake Cortex describe response omitted agent_spec")
    if len(value.encode("utf-8")) > 2 * 1024 * 1024:
        raise DiscoveryProtocolError("Snowflake Cortex agent_spec exceeds its byte bound")
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError) as exc:
        raise DiscoveryProtocolError("Snowflake Cortex agent_spec is not valid JSON") from exc
    return _mapping(parsed, "Snowflake Cortex agent specification")


def _snowflake_tools(spec: Mapping[str, Any]) -> list[dict[str, str]]:
    value = spec.get("tools", [])
    if not isinstance(value, list):
        raise DiscoveryProtocolError("Snowflake Cortex tools must be an array")
    if len(value) > 128:
        raise DiscoveryLimitError("Snowflake Cortex agent exceeds its tool cap")
    tools: list[dict[str, str]] = []
    for item in value:
        row = _mapping(item, "Snowflake Cortex tool")
        tool = _optional_mapping(row, "tool_spec", "Snowflake Cortex tool_spec") or row
        tools.append(
            {
                "name": _required_text(tool.get("name"), "Snowflake Cortex tool name", 256),
                "type": _optional_text(tool.get("type"), 128),
            }
        )
    return sorted(tools, key=lambda item: (item["name"], item["type"]))


class SnowflakeCortexInventoryAdapter(_BearerHttpAdapter):
    """Snowflake Cortex agents in explicitly enumerated database/schema scopes."""

    name = "snowflake_cortex"
    source = "snowflake_cortex"

    def __init__(
        self,
        *,
        account_url: str | None = None,
        account_url_env: str = "SNOWFLAKE_ACCOUNT_URL",
        token_env: str = "SNOWFLAKE_TOKEN",
        scopes: Sequence[Any] | None = None,
        scopes_env: str = "SNOWFLAKE_CORTEX_SCOPES",
        role_env: str = "SNOWFLAKE_ROLE",
        transport: HttpTransport | None = None,
        limits: DiscoveryLimits | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        resolved = account_url or _env_value(account_url_env, "Snowflake account URL")
        super().__init__(
            base_url=resolved,
            token_env=token_env,
            transport=transport,
            limits=limits,
            sleep=sleep,
            clock=clock,
        )
        self.scopes = _snowflake_scopes(scopes, scopes_env)
        self.role_env = _env_reference(role_env, "Snowflake role reference")

    def _extra_headers(self) -> Mapping[str, str]:
        headers = {"Content-Type": "application/json"}
        role = os.environ.get(self.role_env, "").strip()
        if role:
            headers["X-Snowflake-Role"] = _config_text(role, "Snowflake role", 255)
        return headers

    def _scope_rows(
        self,
        scope: SnowflakeCortexScope,
        budget: _PaginationBudget,
    ) -> list[Mapping[str, Any]]:
        path = (
            f"/api/v2/databases/{quote(scope.database, safe='')}/schemas/"
            f"{quote(scope.schema, safe='')}/agents"
        )
        url = f"{self.base_url}{path}"
        params: Mapping[str, Any] | None = {"showLimit": 100}
        seen: set[str] = set()
        rows: list[Mapping[str, Any]] = []
        while True:
            marker = _sha256({"url": url, "params": params})
            if marker in seen:
                raise DiscoveryProtocolError("Snowflake Cortex pagination cycle detected")
            seen.add(marker)
            budget.page()
            payload, headers = self._request(
                url,
                params=params,
                extra_headers=self._extra_headers(),
            )
            if not isinstance(payload, list):
                raise DiscoveryProtocolError("Snowflake Cortex list response must be an array")
            current: list[Mapping[str, Any]] = []
            for item in payload:
                current.append(_mapping(item, "Snowflake Cortex agent"))
            budget.add_records(len(current))
            rows.extend(current)
            next_url = _next_link(headers, "Snowflake Cortex")
            if not next_url:
                return rows
            if not current:
                raise DiscoveryProtocolError("Snowflake Cortex returned an empty continued page")
            url = _same_origin_path(self.base_url, next_url, expected_path=path)
            query = parse_qs(urlsplit(url).query, keep_blank_values=True)
            if set(query) - {"showLimit", "fromName"}:
                raise DiscoveryProtocolError(
                    "Snowflake Cortex next link added unsupported query fields"
                )
            if query.get("showLimit") != ["100"]:
                raise DiscoveryProtocolError("Snowflake Cortex next link changed the page size")
            cursors = query.get("fromName")
            if cursors is None or len(cursors) != 1 or not cursors[0] or len(cursors[0]) > 255:
                raise DiscoveryProtocolError("Snowflake Cortex next link omitted its cursor")
            params = None

    def _agent_asset(
        self,
        row: Mapping[str, Any],
        scope: SnowflakeCortexScope,
        budget: _PaginationBudget,
        now: float,
    ) -> DiscoveredAsset:
        name = _required_text(row.get("name"), "Snowflake Cortex agent name", 255)
        database = _optional_text(row.get("database") or row.get("database_name"), 255)
        schema = _optional_text(row.get("schema") or row.get("schema_name"), 255)
        if database != "unknown" and database.casefold() != scope.database.casefold():
            raise DiscoveryProtocolError("Snowflake Cortex agent crossed its database scope")
        if schema != "unknown" and schema.casefold() != scope.schema.casefold():
            raise DiscoveryProtocolError("Snowflake Cortex agent crossed its schema scope")
        path = (
            f"/api/v2/databases/{quote(scope.database, safe='')}/schemas/"
            f"{quote(scope.schema, safe='')}/agents/{quote(name, safe='')}"
        )
        budget.page()
        payload, _headers_value = self._request(
            f"{self.base_url}{path}",
            extra_headers=self._extra_headers(),
        )
        detail = _mapping(payload, "Snowflake Cortex agent detail")
        detail_name = _required_text(detail.get("name"), "Snowflake Cortex detail name", 255)
        if detail_name.casefold() != name.casefold():
            raise DiscoveryProtocolError("Snowflake Cortex describe response changed agent identity")
        detail_database = detail.get("database") or detail.get("database_name")
        detail_schema = detail.get("schema") or detail.get("schema_name")
        if detail_database not in (None, "") and _required_text(
            detail_database,
            "Snowflake Cortex detail database",
            255,
        ).casefold() != scope.database.casefold():
            raise DiscoveryProtocolError("Snowflake Cortex describe crossed its database scope")
        if detail_schema not in (None, "") and _required_text(
            detail_schema,
            "Snowflake Cortex detail schema",
            255,
        ).casefold() != scope.schema.casefold():
            raise DiscoveryProtocolError("Snowflake Cortex describe crossed its schema scope")
        spec = _snowflake_spec(detail.get("agent_spec"))
        models = _optional_mapping(spec, "models", "Snowflake Cortex models")
        orchestration = _optional_text(models.get("orchestration"), 1_024, "auto")
        tools = _snowflake_tools(spec)
        budget.add_records(len(tools))
        source_id = (
            f"{self._authority_key}:"
            f"{_sha256([scope.database, scope.schema, name])[:32]}"
        )
        profile = _optional_mapping(row, "profile", "Snowflake Cortex profile")
        display_name = profile.get("display_name") or name
        tool_types = sorted({item["type"] for item in tools})
        return _asset(
            asset_type="agent",
            source=self.source,
            source_id=source_id,
            display_name=display_name,
            version_authority={
                "account": self._authority_key,
                "database": scope.database,
                "schema": scope.schema,
                "agent": name,
                "spec_digest": _sha256(spec),
                "tools": tools,
            },
            binding_strength="observed_snapshot",
            owner=detail.get("owner") or row.get("owner"),
            platform="Snowflake Cortex",
            model=orchestration,
            last_seen=detail.get("created_on") or row.get("created_on"),
            fallback_time=now,
            source_url=f"{self.base_url}{path}",
            metadata=_selected_metadata(
                resource_kind="cortex_agent",
                account_key=self._authority_key,
                database=scope.database,
                schema=scope.schema,
                tool_count=len(tools),
                tool_types=tool_types,
            ),
            dependencies=() if orchestration in {"auto", "unknown"} else (orchestration,),
        )

    def discover(self) -> DiscoveryResult:
        budget = _PaginationBudget(self.limits)
        now = self._clock()
        assets: list[DiscoveredAsset] = []
        for scope in self.scopes:
            rows = self._scope_rows(scope, budget)
            assets.extend(self._agent_asset(row, scope, budget, now) for row in rows)
        return DiscoveryResult(tuple(assets), budget.pages)


class SalesforceAgentforceInventoryAdapter(_BearerHttpAdapter):
    """Committed Agentforce BotDefinition objects and all BotVersion records."""

    name = "salesforce_agentforce"
    source = "salesforce_agentforce"

    def __init__(
        self,
        *,
        instance_url: str | None = None,
        instance_url_env: str = "SALESFORCE_INSTANCE_URL",
        token_env: str = "SALESFORCE_ACCESS_TOKEN",
        api_version: str | None = None,
        api_version_env: str = "SALESFORCE_API_VERSION",
        transport: HttpTransport | None = None,
        limits: DiscoveryLimits | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        resolved = instance_url or _env_value(instance_url_env, "Salesforce instance URL")
        super().__init__(
            base_url=resolved,
            token_env=token_env,
            transport=transport,
            limits=limits,
            sleep=sleep,
            clock=clock,
        )
        selected_version = (
            api_version or os.environ.get(_env_reference(api_version_env, "Salesforce API version reference"), "") or "v65.0"
        ).strip()
        if selected_version and selected_version[0].isdigit():
            selected_version = f"v{selected_version}"
        if not _SALESFORCE_API_VERSION.fullmatch(selected_version):
            raise AIInventoryConfigError("Salesforce API version must be v60.0-v99.0")
        self.api_version = selected_version
        self._query_path = f"/services/data/{self.api_version}/query"

    def _query(self, soql: str, budget: _PaginationBudget) -> list[Mapping[str, Any]]:
        url = f"{self.base_url}{self._query_path}"
        params: Mapping[str, Any] | None = {"q": soql}
        seen: set[str] = set()
        rows: list[Mapping[str, Any]] = []
        expected_total: int | None = None
        while True:
            marker = _sha256({"url": url, "params": params})
            if marker in seen:
                raise DiscoveryProtocolError("Salesforce query pagination cycle detected")
            seen.add(marker)
            budget.page()
            payload, _headers_value = self._request(url, params=params)
            page = _mapping(payload, "Salesforce query page")
            current = _items(page, "records")
            budget.add_records(len(current))
            rows.extend(current)
            total = page.get("totalSize")
            if isinstance(total, bool) or not isinstance(total, int) or total < 0:
                raise DiscoveryProtocolError("Salesforce query totalSize is malformed")
            if expected_total is None:
                expected_total = total
            elif expected_total != total:
                raise DiscoveryProtocolError("Salesforce query totalSize changed during pagination")
            done = page.get("done")
            if not isinstance(done, bool):
                raise DiscoveryProtocolError("Salesforce query done marker must be boolean")
            raw_next = page.get("nextRecordsUrl")
            if done:
                if raw_next not in (None, ""):
                    raise DiscoveryProtocolError("Salesforce completed page included a next URL")
                if len(rows) != expected_total:
                    raise DiscoveryProtocolError("Salesforce query completed with a partial result")
                return rows
            if raw_next in (None, ""):
                raise DiscoveryProtocolError("Salesforce partial page omitted nextRecordsUrl")
            url = _same_origin_prefix(
                self.base_url,
                _required_text(raw_next, "Salesforce nextRecordsUrl", 16_384),
                expected_prefix=f"{self._query_path}/",
            )
            params = None

    def _agent_asset(
        self,
        row: Mapping[str, Any],
        versions: Sequence[Mapping[str, Any]],
        now: float,
    ) -> DiscoveredAsset:
        agent_id = _required_text(row.get("Id"), "Agentforce BotDefinition id", 32)
        developer_name = _required_text(
            row.get("DeveloperName"),
            "Agentforce developer name",
            80,
        )
        agent_type = _optional_text(row.get("Type"), 255)
        if agent_type.casefold() == "bot":
            raise DiscoveryProtocolError("Salesforce returned a non-Agentforce BotDefinition")
        selected_versions: list[dict[str, Any]] = []
        active_version = None
        for version_row in versions:
            version_id = _required_text(version_row.get("Id"), "Agentforce version id", 32)
            raw_number = version_row.get("VersionNumber")
            if isinstance(raw_number, bool) or not isinstance(raw_number, (str, int, float)):
                raise DiscoveryProtocolError("Agentforce version number is malformed")
            status = _optional_text(version_row.get("Status"), 128)
            if status.casefold() == "active":
                if active_version is not None:
                    raise DiscoveryProtocolError("Agentforce agent has multiple active versions")
                active_version = str(raw_number)
            selected_versions.append(
                {
                    "id": version_id,
                    "version": str(raw_number),
                    "status": status,
                    "updated_at": version_row.get("LastModifiedDate"),
                }
            )
        selected_versions.sort(key=lambda item: item["id"])
        source_id = f"{self._authority_key}:{agent_id}"
        return _asset(
            asset_type="agent",
            source=self.source,
            source_id=source_id,
            display_name=row.get("MasterLabel") or developer_name,
            version_authority={
                "org": self._authority_key,
                "bot_definition": agent_id,
                "updated_at": row.get("LastModifiedDate"),
                "versions": selected_versions,
            },
            binding_strength="observed_snapshot",
            owner=row.get("LastModifiedById") or row.get("CreatedById"),
            platform="Salesforce Agentforce",
            model="unknown",
            last_seen=row.get("LastModifiedDate") or row.get("CreatedDate"),
            fallback_time=now,
            source_url=(
                f"{self.base_url}/lightning/setup/EinsteinCopilot/"
                f"{quote(agent_id, safe='')}/edit"
            ),
            metadata=_selected_metadata(
                resource_kind="agentforce_agent",
                org_key=self._authority_key,
                developer_name=developer_name,
                type=agent_type,
                agent_type=row.get("AgentType"),
                active_version=active_version,
                version_count=len(selected_versions),
                api_version=self.api_version,
            ),
        )

    def discover(self) -> DiscoveryResult:
        budget = _PaginationBudget(self.limits)
        agents = self._query(_SALESFORCE_AGENT_QUERY, budget)
        versions = self._query(_SALESFORCE_VERSION_QUERY, budget)
        by_parent: dict[str, list[Mapping[str, Any]]] = {}
        for row in versions:
            parent = _required_text(
                row.get("BotDefinitionId"),
                "Agentforce BotDefinition parent id",
                32,
            )
            by_parent.setdefault(parent, []).append(row)
        known: set[str] = set()
        now = self._clock()
        assets: list[DiscoveredAsset] = []
        for row in agents:
            agent_id = _required_text(row.get("Id"), "Agentforce BotDefinition id", 32)
            if agent_id in known:
                raise DiscoveryProtocolError("Salesforce returned a duplicate BotDefinition")
            known.add(agent_id)
            assets.append(self._agent_asset(row, by_parent.get(agent_id, ()), now))
        if set(by_parent) - known:
            raise DiscoveryProtocolError("Salesforce returned orphan Agentforce versions")
        return DiscoveryResult(tuple(assets), budget.pages)


class HuggingFaceInventoryAdapter(_BearerHttpAdapter):
    """Models in one explicitly configured Hugging Face user or org namespace."""

    name = "hugging_face"
    source = "hugging_face_hub"

    def __init__(
        self,
        *,
        namespace: str | None = None,
        namespace_env: str = "HUGGING_FACE_NAMESPACE",
        endpoint: str | None = None,
        endpoint_env: str = "HUGGING_FACE_ENDPOINT",
        token_env: str = "HF_TOKEN",
        transport: HttpTransport | None = None,
        limits: DiscoveryLimits | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        resolved_endpoint = endpoint or os.environ.get(
            _env_reference(endpoint_env, "Hugging Face endpoint reference"),
            "",
        ).strip() or "https://huggingface.co"
        super().__init__(
            base_url=resolved_endpoint,
            token_env=token_env,
            transport=transport,
            limits=limits,
            sleep=sleep,
            clock=clock,
        )
        resolved_namespace = namespace or _env_value(namespace_env, "Hugging Face namespace")
        self.namespace = _config_text(resolved_namespace, "Hugging Face namespace", 96)
        if not _HF_NAMESPACE.fullmatch(self.namespace):
            raise AIInventoryConfigError("Hugging Face namespace is malformed")
        query = urlencode(
            [
                ("author", self.namespace),
                ("limit", "100"),
                *(("expand", value) for value in _HF_EXPAND),
            ]
        )
        self._initial_url = f"{self.base_url}/api/models?{query}"

    def _validate_page_url(self, candidate: str) -> str:
        url = _same_origin_path(self.base_url, candidate, expected_path="/api/models")
        query = parse_qs(urlsplit(url).query, keep_blank_values=True)
        allowed = {"author", "limit", "expand", "cursor"}
        if set(query) - allowed:
            raise DiscoveryProtocolError("Hugging Face next link added unsupported query fields")
        if query.get("author") != [self.namespace] or query.get("limit") != ["100"]:
            raise DiscoveryProtocolError("Hugging Face next link changed the namespace or page size")
        if query.get("expand") != list(_HF_EXPAND):
            raise DiscoveryProtocolError("Hugging Face next link changed the selected fields")
        cursors = query.get("cursor")
        if cursors is not None and (
            len(cursors) != 1 or not cursors[0] or len(cursors[0]) > 8_192
        ):
            raise DiscoveryProtocolError("Hugging Face cursor is malformed")
        return url

    def _model_asset(self, row: Mapping[str, Any], now: float) -> DiscoveredAsset:
        repo_id = _required_text(row.get("id"), "Hugging Face model id", 256)
        author = _required_text(row.get("author"), "Hugging Face model author", 96)
        if author.casefold() != self.namespace.casefold() or not repo_id.casefold().startswith(
            f"{self.namespace.casefold()}/"
        ):
            raise DiscoveryProtocolError("Hugging Face model crossed its configured namespace")
        revision = _required_text(row.get("sha"), "Hugging Face model revision", 64).lower()
        if not _HF_REVISION.fullmatch(revision):
            raise DiscoveryProtocolError("Hugging Face model revision is not an immutable commit")
        return _asset(
            asset_type="model",
            source=self.source,
            source_id=repo_id,
            display_name=repo_id.rsplit("/", 1)[-1],
            version_authority={
                "repository": repo_id,
                "revision": revision,
            },
            binding_strength="immutable_provider_revision",
            owner=author,
            platform="Hugging Face Hub",
            model=repo_id,
            last_seen=row.get("lastModified"),
            fallback_time=now,
            source_url=f"{self.base_url}/{quote(repo_id, safe='/')}",
            metadata=_selected_metadata(
                resource_kind="model_repository",
                namespace=self.namespace,
                revision=revision,
                private=row.get("private"),
                gated=row.get("gated"),
                pipeline_tag=row.get("pipeline_tag"),
                library=row.get("library_name"),
            ),
        )

    def discover(self) -> DiscoveryResult:
        budget = _PaginationBudget(self.limits)
        url = self._initial_url
        seen: set[str] = set()
        assets: list[DiscoveredAsset] = []
        now = self._clock()
        while True:
            url = self._validate_page_url(url)
            marker = _sha256(url)
            if marker in seen:
                raise DiscoveryProtocolError("Hugging Face pagination cycle detected")
            seen.add(marker)
            budget.page()
            payload, headers = self._request(url)
            if not isinstance(payload, list):
                raise DiscoveryProtocolError("Hugging Face model list must be an array")
            rows = [_mapping(item, "Hugging Face model") for item in payload]
            budget.add_records(len(rows))
            assets.extend(self._model_asset(row, now) for row in rows)
            next_url = _next_link(headers, "Hugging Face")
            if not next_url:
                return DiscoveryResult(tuple(assets), budget.pages)
            if not rows:
                raise DiscoveryProtocolError("Hugging Face returned an empty continued page")
            url = next_url


def available_second_wave_connectors() -> list[str]:
    """Return the fixed connector IDs supported by this module."""

    return list(SECOND_WAVE_CONNECTORS)


def build_second_wave_adapter(
    name: str,
    *,
    enabled_connectors: Sequence[str] = (),
    transport: HttpTransport | None = None,
    sagemaker_client: SageMakerClient | None = None,
    limits: DiscoveryLimits | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.time,
) -> (
    MLflowInventoryAdapter
    | SageMakerInventoryAdapter
    | SnowflakeCortexInventoryAdapter
    | SalesforceAgentforceInventoryAdapter
    | HuggingFaceInventoryAdapter
):
    """Build one connector only when its validated ID is explicitly enabled.

    The empty default is intentional: merely importing or installing the
    connector package cannot trigger provider discovery.
    """

    connector = str(name or "").strip().lower()
    if connector not in SECOND_WAVE_CONNECTORS:
        raise AIInventoryConfigError(f"unsupported second-wave connector: {connector}")
    enabled: list[str] = []
    for item in enabled_connectors:
        if not isinstance(item, str):
            raise AIInventoryConfigError("enabled connector IDs must be strings")
        normalized = item.strip().lower()
        if normalized not in _CONFIGURED_CONNECTORS:
            raise AIInventoryConfigError(f"unknown AI inventory connector: {normalized}")
        enabled.append(normalized)
    if connector not in set(enabled):
        raise AIInventoryConfigError(f"second-wave connector is not enabled: {connector}")
    common = {"limits": limits, "sleep": sleep, "clock": clock}
    if connector == "mlflow":
        return MLflowInventoryAdapter(transport=transport, **common)
    if connector == "aws_sagemaker":
        return SageMakerInventoryAdapter(client=sagemaker_client, **common)
    if connector == "snowflake_cortex":
        return SnowflakeCortexInventoryAdapter(transport=transport, **common)
    if connector == "salesforce_agentforce":
        return SalesforceAgentforceInventoryAdapter(transport=transport, **common)
    return HuggingFaceInventoryAdapter(transport=transport, **common)


__all__ = [
    "HuggingFaceInventoryAdapter",
    "MLflowInventoryAdapter",
    "SECOND_WAVE_CONNECTORS",
    "SageMakerClient",
    "SageMakerInventoryAdapter",
    "SalesforceAgentforceInventoryAdapter",
    "SnowflakeCortexInventoryAdapter",
    "SnowflakeCortexScope",
    "available_second_wave_connectors",
    "build_second_wave_adapter",
]
