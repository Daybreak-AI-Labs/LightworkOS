"""Bounded, read-only identity and data-governance discovery connectors.

This module is intentionally a narrow evidence-ingestion seam, not a general
provider client.  It supports three documented read surfaces:

* Microsoft Graph ``servicePrincipals`` and their app-role assignments;
* Okta applications and application-user assignments; and
* Microsoft Purview Data Map discovery search (a read-only HTTP ``POST``).

Callers cannot choose methods, paths, query keys, request bodies, or headers.
Every connector is tenant scoped, default-off, finite, and requires an injected
HTTP transport.  Credential *references* are retained in private configuration;
secret values are resolved only at request time.  Returned snapshots contain
salted identifiers and closed taxonomy values -- never tokens, names, email
addresses, provider identifiers, or provider payloads.

These adapters provide bounded normalized snapshots only.  They do not prove
live provider acceptance, continuous coverage, or a complete identity/data
inventory, and they expose no administrative mutation operation.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Protocol
from urllib.parse import parse_qs, quote, urlencode, urlsplit, urlunsplit

Provider = Literal["entra", "okta", "purview"]
IdentityKind = Literal[
    "agent_identity",
    "application",
    "managed_identity",
    "legacy_application",
]
GrantKind = Literal["application_role", "application_assignment"]
SubjectKind = Literal["user", "group", "service_principal", "unknown"]

PROVIDERS: tuple[Provider, ...] = ("entra", "okta", "purview")
#: The configuration table the dashboard and the scheduler select for these
#: connectors (``configured_connectors`` receives that table).
CONFIG_SECTION = "ai_identity_governance_connectors"
# The credential names the installer writes; used when a provider has only a
# key saved (sealed) on the dashboard and names no credential of its own.
_DEFAULT_SECRET_REFERENCES = {
    "entra": "ENTRA_IDENTITY_GOVERNANCE_TOKEN",  # pragma: allowlist secret
    "okta": "OKTA_IDENTITY_GOVERNANCE_TOKEN",  # pragma: allowlist secret
    "purview": "PURVIEW_IDENTITY_GOVERNANCE_TOKEN",  # pragma: allowlist secret
}
_RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})
_SECRET_REFERENCE = re.compile(r"[A-Z][A-Z0-9_]{1,127}\Z")
_GUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z"
)
_OKTA_ID = re.compile(r"[A-Za-z0-9_-]{8,128}\Z")
_CODE = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}\Z")
_MAX_SECRET_BYTES = 16_384
_MAX_URL_BYTES = 4_096
_MAX_CURSOR_BYTES = 4_096

_ENTRA_HOSTS = frozenset(
    {
        "graph.microsoft.com",
        "graph.microsoft.us",
        "dod-graph.microsoft.us",
        "microsoftgraph.chinacloudapi.cn",
    }
)
_OKTA_SUFFIXES = (".okta.com", ".okta-emea.com", ".oktapreview.com")
_PURVIEW_SUFFIXES = (".purview.azure.com", ".purview.azure.us")

_ENTRA_IDENTITIES_PATH = "/v1.0/servicePrincipals"
_ENTRA_IDENTITY_SELECT = (
    "id,accountEnabled,servicePrincipalType,appRoleAssignmentRequired"
)
_ENTRA_GRANT_SELECT = "id,principalId,resourceId,appRoleId,principalType"
_OKTA_APPS_PATH = "/api/v1/apps"
_PURVIEW_SEARCH_PATH = "/datamap/api/search/query"
_PURVIEW_API_VERSION = "2023-09-01"


class IdentityGovernanceConnectorError(RuntimeError):
    """Base error that never includes provider response or credential text."""


class IdentityGovernanceConfigError(IdentityGovernanceConnectorError):
    """Connector configuration is missing, disabled, or outside its scope."""


class IdentityGovernanceUnsupportedError(IdentityGovernanceConfigError):
    """A bounded transport or explicitly supported provider is unavailable."""


class IdentityGovernanceTransportError(IdentityGovernanceConnectorError):
    """A provider request failed without returning a usable response."""

    def __init__(self, category: str, *, retryable: bool) -> None:
        super().__init__(category)
        self.category = category
        self.retryable = retryable


class IdentityGovernanceProtocolError(IdentityGovernanceConnectorError):
    """A provider response violated the closed normalization contract."""


class IdentityGovernanceLimitError(IdentityGovernanceProtocolError):
    """A response, page, record, or cursor bound was exceeded."""


@dataclass(frozen=True)
class ConnectorLimits:
    """Finite request and collection limits."""

    timeout_seconds: float = 15.0
    max_pages: int = 50
    max_records: int = 2_000
    max_response_bytes: int = 256 * 1_024
    page_size: int = 100
    retry_attempts: int = 3

    def __post_init__(self) -> None:
        timeout = self.timeout_seconds
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(float(timeout))
            or not 1.0 <= float(timeout) <= 60.0
        ):
            raise IdentityGovernanceConfigError("connector_timeout_invalid")
        for name, value, lower, upper in (
            ("max_pages", self.max_pages, 1, 500),
            ("max_records", self.max_records, 1, 50_000),
            ("max_response_bytes", self.max_response_bytes, 1_024, 1_048_576),
            ("page_size", self.page_size, 1, 200),
            ("retry_attempts", self.retry_attempts, 1, 5),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise IdentityGovernanceConfigError(f"connector_{name}_invalid")
            if not lower <= value <= upper:
                raise IdentityGovernanceConfigError(f"connector_{name}_invalid")
        object.__setattr__(self, "timeout_seconds", float(timeout))


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def _sha256(value: object) -> str:
    payload = value if isinstance(value, bytes) else _canonical_json(value)
    return hashlib.sha256(payload).hexdigest()


def _tenant_sha256(tenant_id: str) -> str:
    return _sha256(b"lightwork-identity-governance-tenant-v1\0" + tenant_id.encode())


def _scoped_id(prefix: str, tenant_sha256: str, provider: str, raw_id: str) -> str:
    digest = _sha256(
        b"lightwork-identity-governance-id-v1\0"
        + tenant_sha256.encode()
        + b"\0"
        + provider.encode()
        + b"\0"
        + raw_id.encode()
    )
    return f"{prefix}_{digest[:32]}"


def _private_or_special_host(host: str) -> bool:
    lowered = host.rstrip(".").lower()
    if (
        lowered == "localhost"
        or lowered.endswith(".localhost")
        or lowered.endswith(".local")
    ):
        return True
    try:
        return not ipaddress.ip_address(lowered).is_global
    except ValueError:
        return False


def _safe_base_url(provider: Provider, value: object) -> str:
    if not isinstance(value, str):
        raise IdentityGovernanceConfigError("connector_base_url_invalid")
    raw = value.strip().rstrip("/")
    if not raw or len(raw) > _MAX_URL_BYTES:
        raise IdentityGovernanceConfigError("connector_base_url_invalid")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError:
        raise IdentityGovernanceConfigError("connector_base_url_invalid") from None
    host = (parsed.hostname or "").rstrip(".").lower()
    if (
        parsed.scheme.lower() != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or port not in {None, 443}
        or _private_or_special_host(host)
    ):
        raise IdentityGovernanceConfigError("connector_base_url_invalid")
    if provider == "entra":
        admitted = host in _ENTRA_HOSTS
    elif provider == "okta":
        admitted = any(host.endswith(suffix) for suffix in _OKTA_SUFFIXES)
    else:
        admitted = any(host.endswith(suffix) for suffix in _PURVIEW_SUFFIXES)
    if not admitted:
        raise IdentityGovernanceConfigError("connector_provider_host_not_allowed")
    netloc = host if port is None else f"{host}:443"
    return urlunsplit(("https", netloc, "", "", ""))


def _required_text(value: object, category: str, maximum: int = 512) -> str:
    if not isinstance(value, str):
        raise IdentityGovernanceProtocolError(category)
    text = value.strip()
    if not text or len(text) > maximum or any(ord(char) < 32 for char in text):
        raise IdentityGovernanceProtocolError(category)
    return text


def _config_text(value: object, category: str, maximum: int = 512) -> str:
    if not isinstance(value, str):
        raise IdentityGovernanceConfigError(category)
    text = value.strip()
    if not text or len(text) > maximum or any(ord(char) < 32 for char in text):
        raise IdentityGovernanceConfigError(category)
    return text


def _secret_reference(value: object) -> str:
    reference = _config_text(value, "connector_secret_reference_invalid", 128)
    if not _SECRET_REFERENCE.fullmatch(reference):
        raise IdentityGovernanceConfigError("connector_secret_reference_invalid")
    return reference


@dataclass(frozen=True, repr=False)
class ConnectorConfig:
    """Private operator configuration; repr is disabled by design."""

    provider: Provider
    enable: bool
    tenant_id: str
    base_url: str
    credential_secret_ref: str
    limits: ConnectorLimits = ConnectorLimits()

    def __post_init__(self) -> None:
        if self.provider not in PROVIDERS:
            raise IdentityGovernanceConfigError("connector_provider_unsupported")
        if not isinstance(self.enable, bool):
            raise IdentityGovernanceConfigError("connector_enable_invalid")
        tenant_id = _config_text(self.tenant_id, "connector_tenant_invalid", 256)
        base_url = _safe_base_url(self.provider, self.base_url)
        reference = _secret_reference(self.credential_secret_ref)
        if not isinstance(self.limits, ConnectorLimits):
            raise IdentityGovernanceConfigError("connector_limits_invalid")
        object.__setattr__(self, "tenant_id", tenant_id)
        object.__setattr__(self, "base_url", base_url)
        object.__setattr__(self, "credential_secret_ref", reference)

    @property
    def tenant_sha256(self) -> str:
        return _tenant_sha256(self.tenant_id)

    @property
    def configuration_sha256(self) -> str:
        return _sha256(
            {
                "schema": "lightwork.identity_governance_connector.config.v1",
                "provider": self.provider,
                "enable": self.enable,
                "tenant_id": self.tenant_id,
                "base_url": self.base_url,
                "credential_secret_ref": self.credential_secret_ref,
                "limits": {
                    "timeout_seconds": self.limits.timeout_seconds,
                    "max_pages": self.limits.max_pages,
                    "max_records": self.limits.max_records,
                    "max_response_bytes": self.limits.max_response_bytes,
                    "page_size": self.limits.page_size,
                    "retry_attempts": self.limits.retry_attempts,
                },
            }
        )


@dataclass(frozen=True, repr=False)
class BoundedHTTPResponse:
    """Response seam whose body and final URL can be bounded and verified."""

    status_code: int
    headers: Mapping[str, str]
    body: bytes
    final_url: str


class ReadOnlyHTTPTransport(Protocol):
    """Injected transport.  Implementations must disable automatic redirects."""

    def request(
        self,
        method: Literal["GET", "POST"],
        url: str,
        *,
        headers: Mapping[str, str],
        json_body: Mapping[str, object] | None,
        timeout: float,
        max_response_bytes: int,
    ) -> BoundedHTTPResponse: ...


SecretResolver = Callable[[str], str | None]


def _with_saved_credential(resolver: SecretResolver, saved: str) -> SecretResolver:
    """Resolve on the server first; fall back to the dashboard-saved key."""

    def resolve(reference: str) -> str | None:
        return resolver(reference) or saved

    return resolve


@dataclass(frozen=True)
class IdentityObservation:
    observation_id: str
    identity_kind: IdentityKind
    enabled: bool
    assignment_required: bool | None
    source_sha256: str


@dataclass(frozen=True)
class GrantObservation:
    observation_id: str
    subject_id: str
    resource_id: str
    grant_kind: GrantKind
    subject_kind: SubjectKind
    permission_id: str
    source_sha256: str


@dataclass(frozen=True)
class DataClassificationObservation:
    observation_id: str
    asset_id: str
    entity_type: str
    classification_codes: tuple[str, ...]
    label_codes: tuple[str, ...]
    source_sha256: str


@dataclass(frozen=True)
class IdentityGovernanceSnapshot:
    schema: str
    provider: Provider
    tenant_sha256: str
    configuration_sha256: str
    observed_at: str
    source_sha256: str
    identities: tuple[IdentityObservation, ...]
    grants: tuple[GrantObservation, ...]
    data_classifications: tuple[DataClassificationObservation, ...]
    coverage: Literal["bounded_read_only_snapshot"] = "bounded_read_only_snapshot"
    live_acceptance_verified: bool = False
    complete_inventory_claimed: bool = False


class _Budget:
    def __init__(self, limits: ConnectorLimits) -> None:
        self._limits = limits
        self._pages = 0
        self._records = 0
        self._cursors: set[str] = set()

    def page(self, key: str) -> None:
        if key in self._cursors:
            raise IdentityGovernanceProtocolError("connector_pagination_cycle")
        self._cursors.add(key)
        self._pages += 1
        if self._pages > self._limits.max_pages:
            raise IdentityGovernanceLimitError("connector_page_limit_exceeded")

    def records(self, count: int) -> None:
        self._records += count
        if self._records > self._limits.max_records:
            raise IdentityGovernanceLimitError("connector_record_limit_exceeded")


def retry_classification(status_code: int) -> Literal[
    "success", "retryable", "redirect_rejected", "terminal"
]:
    """Return the closed retry category used by all HTTP adapters."""

    if isinstance(status_code, bool) or not isinstance(status_code, int):
        raise IdentityGovernanceProtocolError("connector_status_invalid")
    if 200 <= status_code < 300:
        return "success"
    if 300 <= status_code < 400:
        return "redirect_rejected"
    if status_code in _RETRYABLE_STATUS:
        return "retryable"
    return "terminal"


def _pairs_no_duplicates(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise IdentityGovernanceProtocolError("connector_json_duplicate_key")
        result[key] = value
    return result


def _decode_json(body: bytes, maximum: int) -> object:
    if not isinstance(body, bytes):
        raise IdentityGovernanceProtocolError("connector_response_body_invalid")
    if len(body) > maximum:
        raise IdentityGovernanceLimitError("connector_response_too_large")
    try:
        return json.loads(body.decode("utf-8"), object_pairs_hook=_pairs_no_duplicates)
    except IdentityGovernanceProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise IdentityGovernanceProtocolError("connector_response_json_invalid") from None


def _response_headers(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise IdentityGovernanceProtocolError("connector_response_headers_invalid")
    result: dict[str, str] = {}
    for raw_name, raw_value in value.items():
        if not isinstance(raw_name, str) or not isinstance(raw_value, str):
            raise IdentityGovernanceProtocolError(
                "connector_response_headers_invalid"
            )
        name = raw_name
        item = raw_value
        if len(name) > 256 or len(item) > 16_384:
            raise IdentityGovernanceLimitError("connector_response_header_too_large")
        result[name.lower()] = item
    return result


def _mapping(value: object, category: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise IdentityGovernanceProtocolError(category)
    return value


def _sequence(value: object, category: str) -> Sequence[Any]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise IdentityGovernanceProtocolError(category)
    return value


def _closed_code(value: object, category: str) -> str:
    text = _required_text(value, category, 128)
    if not _CODE.fullmatch(text):
        raise IdentityGovernanceProtocolError(category)
    return text


def _guid(value: object, category: str) -> str:
    text = _required_text(value, category, 36)
    if not _GUID.fullmatch(text):
        raise IdentityGovernanceProtocolError(category)
    return text.lower()


def _okta_id(value: object, category: str) -> str:
    text = _required_text(value, category, 128)
    if not _OKTA_ID.fullmatch(text):
        raise IdentityGovernanceProtocolError(category)
    return text


def _utc_now(clock: Callable[[], float]) -> str:
    try:
        timestamp = float(clock())
    except (TypeError, ValueError, OverflowError):
        raise IdentityGovernanceProtocolError("connector_clock_invalid") from None
    if not math.isfinite(timestamp):
        raise IdentityGovernanceProtocolError("connector_clock_invalid")
    try:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
    except (OverflowError, OSError, ValueError):
        raise IdentityGovernanceProtocolError("connector_clock_invalid") from None


class _ReadOnlyAdapter:
    provider: Provider

    def __init__(
        self,
        config: ConnectorConfig,
        *,
        transport: ReadOnlyHTTPTransport,
        secret_resolver: SecretResolver,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if config.provider != self.provider:
            raise IdentityGovernanceConfigError("connector_provider_mismatch")
        if transport is None:
            raise IdentityGovernanceUnsupportedError("connector_transport_required")
        if not callable(secret_resolver):
            raise IdentityGovernanceConfigError("connector_secret_resolver_invalid")
        self._config = config
        self._transport = transport
        self._secret_resolver = secret_resolver
        self._sleep = sleep
        self._clock = clock

    def _require_enabled(self) -> None:
        if not self._config.enable:
            raise IdentityGovernanceConfigError("connector_disabled")

    def _url(self, path: str, query: Mapping[str, object]) -> str:
        if not path.startswith("/") or ".." in path or "//" in path:
            raise IdentityGovernanceConfigError("connector_path_invalid")
        encoded = urlencode([(key, str(value)) for key, value in query.items()])
        return f"{self._config.base_url}{path}" + (f"?{encoded}" if encoded else "")

    def _credential(self) -> str:
        try:
            value = self._secret_resolver(self._config.credential_secret_ref)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise IdentityGovernanceConfigError(
                "connector_secret_resolution_failed"
            ) from None
        if not isinstance(value, str):
            raise IdentityGovernanceConfigError("connector_secret_unavailable")
        secret = value.strip()
        if (
            not secret
            or len(secret.encode("utf-8")) > _MAX_SECRET_BYTES
            or any(character in secret for character in "\r\n\x00")
        ):
            raise IdentityGovernanceConfigError("connector_secret_unavailable")
        return secret

    def _request_json(
        self,
        method: Literal["GET", "POST"],
        path: str,
        *,
        query: Mapping[str, object],
        json_body: Mapping[str, object] | None = None,
    ) -> tuple[object, Mapping[str, str]]:
        url = self._url(path, query)
        secret = self._credential()
        scheme = "SSWS" if self.provider == "okta" else "Bearer"
        headers = {
            "Accept": "application/json",
            "Authorization": f"{scheme} {secret}",
        }
        if method == "POST":
            headers["Content-Type"] = "application/json"
        for attempt in range(self._config.limits.retry_attempts):
            try:
                response = self._transport.request(
                    method,
                    url,
                    headers=headers,
                    json_body=json_body,
                    timeout=self._config.limits.timeout_seconds,
                    max_response_bytes=self._config.limits.max_response_bytes,
                )
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                if attempt + 1 >= self._config.limits.retry_attempts:
                    raise IdentityGovernanceTransportError(
                        "connector_transport_failed", retryable=True
                    ) from None
                self._sleep(min(2**attempt, 8))
                continue
            if not isinstance(response, BoundedHTTPResponse):
                raise IdentityGovernanceProtocolError("connector_response_invalid")
            if response.final_url != url:
                raise IdentityGovernanceProtocolError("connector_redirect_rejected")
            category = retry_classification(response.status_code)
            if category == "retryable" and attempt + 1 < self._config.limits.retry_attempts:
                self._sleep(min(2**attempt, 8))
                continue
            if category == "redirect_rejected":
                raise IdentityGovernanceProtocolError("connector_redirect_rejected")
            if category != "success":
                raise IdentityGovernanceTransportError(
                    "connector_http_failed", retryable=category == "retryable"
                )
            response_headers = _response_headers(response.headers)
            return (
                _decode_json(response.body, self._config.limits.max_response_bytes),
                response_headers,
            )
        raise IdentityGovernanceTransportError(
            "connector_retry_budget_exhausted", retryable=True
        )

    def _snapshot(
        self,
        identities: Sequence[IdentityObservation],
        grants: Sequence[GrantObservation],
        classifications: Sequence[DataClassificationObservation],
    ) -> IdentityGovernanceSnapshot:
        payload = {
            "provider": self.provider,
            "tenant_sha256": self._config.tenant_sha256,
            "configuration_sha256": self._config.configuration_sha256,
            "identities": [item.__dict__ for item in identities],
            "grants": [item.__dict__ for item in grants],
            "data_classifications": [item.__dict__ for item in classifications],
        }
        return IdentityGovernanceSnapshot(
            schema="lightwork.identity_governance.snapshot.v1",
            provider=self.provider,
            tenant_sha256=self._config.tenant_sha256,
            configuration_sha256=self._config.configuration_sha256,
            observed_at=_utc_now(self._clock),
            source_sha256=_sha256(payload),
            identities=tuple(identities),
            grants=tuple(grants),
            data_classifications=tuple(classifications),
        )


def _graph_next_token(
    value: object,
    *,
    config: ConnectorConfig,
    expected_path: str,
    expected_select: str,
) -> str | None:
    if value is None:
        return None
    next_link = _required_text(value, "entra_next_link_invalid", _MAX_URL_BYTES)
    parsed = urlsplit(next_link)
    base = urlsplit(config.base_url)
    if (
        parsed.scheme.lower() != "https"
        or parsed.netloc.lower() != base.netloc.lower()
        or parsed.path != expected_path
        or parsed.fragment
    ):
        raise IdentityGovernanceProtocolError("entra_next_link_scope_invalid")
    try:
        query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        raise IdentityGovernanceProtocolError("entra_next_link_query_invalid") from None
    if set(query) - {"$select", "$top", "$skiptoken"}:
        raise IdentityGovernanceProtocolError("entra_next_link_query_invalid")
    if query.get("$select", [expected_select]) != [expected_select]:
        raise IdentityGovernanceProtocolError("entra_next_link_query_invalid")
    if query.get("$top", [str(config.limits.page_size)]) != [
        str(config.limits.page_size)
    ]:
        raise IdentityGovernanceProtocolError("entra_next_link_query_invalid")
    tokens = query.get("$skiptoken")
    if tokens is None or len(tokens) != 1:
        raise IdentityGovernanceProtocolError("entra_next_link_cursor_invalid")
    return _required_text(tokens[0], "entra_next_link_cursor_invalid", _MAX_CURSOR_BYTES)


def _entra_identity_kind(value: object) -> IdentityKind:
    raw = _required_text(value, "entra_service_principal_type_invalid", 64)
    mapping: dict[str, IdentityKind] = {
        "ServiceIdentity": "agent_identity",
        "Application": "application",
        "ManagedIdentity": "managed_identity",
        "Legacy": "legacy_application",
    }
    try:
        return mapping[raw]
    except KeyError:
        raise IdentityGovernanceProtocolError(
            "entra_service_principal_type_unsupported"
        ) from None


def _subject_kind(value: object) -> SubjectKind:
    if value is None:
        return "unknown"
    raw = _required_text(value, "entra_principal_type_invalid", 64)
    return {
        "User": "user",
        "Group": "group",
        "ServicePrincipal": "service_principal",
    }.get(raw, "unknown")


class EntraIdentityGovernanceAdapter(_ReadOnlyAdapter):
    """Read Microsoft Entra workload/service/agent identities and grants."""

    provider: Provider = "entra"

    def collect(self) -> IdentityGovernanceSnapshot:
        self._require_enabled()
        budget = _Budget(self._config.limits)
        identities: list[IdentityObservation] = []
        grants: list[GrantObservation] = []
        principals: list[str] = []
        token: str | None = None
        while True:
            budget.page(f"identities:{token or '<first>'}")
            query: dict[str, object] = {
                "$select": _ENTRA_IDENTITY_SELECT,
                "$top": self._config.limits.page_size,
            }
            if token is not None:
                query["$skiptoken"] = token
            payload, _headers = self._request_json(
                "GET", _ENTRA_IDENTITIES_PATH, query=query
            )
            page = _mapping(payload, "entra_identity_page_invalid")
            rows = _sequence(page.get("value"), "entra_identity_rows_invalid")
            budget.records(len(rows))
            for value in rows:
                row = _mapping(value, "entra_identity_invalid")
                raw_id = _guid(row.get("id"), "entra_identity_id_invalid")
                enabled = row.get("accountEnabled")
                assignment_required = row.get("appRoleAssignmentRequired")
                if not isinstance(enabled, bool) or not isinstance(
                    assignment_required, bool
                ):
                    raise IdentityGovernanceProtocolError("entra_identity_state_invalid")
                kind = _entra_identity_kind(row.get("servicePrincipalType"))
                observation_id = _scoped_id(
                    "idn", self._config.tenant_sha256, self.provider, raw_id
                )
                source = {
                    "id_sha256": _sha256(raw_id),
                    "identity_kind": kind,
                    "enabled": enabled,
                    "assignment_required": assignment_required,
                }
                identities.append(
                    IdentityObservation(
                        observation_id=observation_id,
                        identity_kind=kind,
                        enabled=enabled,
                        assignment_required=assignment_required,
                        source_sha256=_sha256(source),
                    )
                )
                principals.append(raw_id)
            token = _graph_next_token(
                page.get("@odata.nextLink"),
                config=self._config,
                expected_path=_ENTRA_IDENTITIES_PATH,
                expected_select=_ENTRA_IDENTITY_SELECT,
            )
            if token is None:
                break

        for principal_id in principals:
            path = (
                f"/v1.0/servicePrincipals/{quote(principal_id, safe='')}"
                "/appRoleAssignedTo"
            )
            token = None
            while True:
                budget.page(f"grants:{principal_id}:{token or '<first>'}")
                query = {
                    "$select": _ENTRA_GRANT_SELECT,
                    "$top": self._config.limits.page_size,
                }
                if token is not None:
                    query["$skiptoken"] = token
                payload, _headers = self._request_json("GET", path, query=query)
                page = _mapping(payload, "entra_grant_page_invalid")
                rows = _sequence(page.get("value"), "entra_grant_rows_invalid")
                budget.records(len(rows))
                for value in rows:
                    row = _mapping(value, "entra_grant_invalid")
                    raw_id = _guid(row.get("id"), "entra_grant_id_invalid")
                    subject = _guid(row.get("principalId"), "entra_subject_id_invalid")
                    resource = _guid(row.get("resourceId"), "entra_resource_id_invalid")
                    permission = _guid(row.get("appRoleId"), "entra_permission_id_invalid")
                    normalized = {
                        "grant_id_sha256": _sha256(raw_id),
                        "subject_id": _scoped_id(
                            "sub", self._config.tenant_sha256, self.provider, subject
                        ),
                        "resource_id": _scoped_id(
                            "res", self._config.tenant_sha256, self.provider, resource
                        ),
                        "permission_id": _scoped_id(
                            "prm", self._config.tenant_sha256, self.provider, permission
                        ),
                        "subject_kind": _subject_kind(row.get("principalType")),
                    }
                    grants.append(
                        GrantObservation(
                            observation_id=_scoped_id(
                                "grt", self._config.tenant_sha256, self.provider, raw_id
                            ),
                            subject_id=normalized["subject_id"],
                            resource_id=normalized["resource_id"],
                            grant_kind="application_role",
                            subject_kind=normalized["subject_kind"],
                            permission_id=normalized["permission_id"],
                            source_sha256=_sha256(normalized),
                        )
                    )
                token = _graph_next_token(
                    page.get("@odata.nextLink"),
                    config=self._config,
                    expected_path=path,
                    expected_select=_ENTRA_GRANT_SELECT,
                )
                if token is None:
                    break
        return self._snapshot(identities, grants, ())


def _okta_next_after(
    link_header: str | None, *, config: ConnectorConfig, expected_path: str
) -> str | None:
    if not link_header:
        return None
    if len(link_header) > 16_384:
        raise IdentityGovernanceLimitError("okta_link_header_too_large")
    matches = re.findall(r'<([^>]+)>\s*;\s*rel="?([^";,]+)"?', link_header)
    links = [url for url, relation in matches if relation.strip().lower() == "next"]
    if len(links) > 1:
        raise IdentityGovernanceProtocolError("okta_next_link_ambiguous")
    if not links:
        return None
    parsed = urlsplit(links[0])
    base = urlsplit(config.base_url)
    if (
        parsed.scheme.lower() != "https"
        or parsed.netloc.lower() != base.netloc.lower()
        or parsed.path != expected_path
        or parsed.fragment
    ):
        raise IdentityGovernanceProtocolError("okta_next_link_scope_invalid")
    try:
        query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        raise IdentityGovernanceProtocolError("okta_next_link_query_invalid") from None
    if set(query) - {"limit", "after"}:
        raise IdentityGovernanceProtocolError("okta_next_link_query_invalid")
    if query.get("limit", [str(config.limits.page_size)]) != [
        str(config.limits.page_size)
    ]:
        raise IdentityGovernanceProtocolError("okta_next_link_query_invalid")
    after = query.get("after")
    if after is None or len(after) != 1:
        raise IdentityGovernanceProtocolError("okta_next_link_cursor_invalid")
    return _required_text(after[0], "okta_next_link_cursor_invalid", _MAX_CURSOR_BYTES)


class OktaIdentityGovernanceAdapter(_ReadOnlyAdapter):
    """Read Okta applications and their assignments without profile fields."""

    provider: Provider = "okta"

    def collect(self) -> IdentityGovernanceSnapshot:
        self._require_enabled()
        budget = _Budget(self._config.limits)
        identities: list[IdentityObservation] = []
        grants: list[GrantObservation] = []
        applications: list[str] = []
        after: str | None = None
        while True:
            budget.page(f"applications:{after or '<first>'}")
            query: dict[str, object] = {"limit": self._config.limits.page_size}
            if after is not None:
                query["after"] = after
            payload, headers = self._request_json("GET", _OKTA_APPS_PATH, query=query)
            rows = _sequence(payload, "okta_application_rows_invalid")
            budget.records(len(rows))
            for value in rows:
                row = _mapping(value, "okta_application_invalid")
                raw_id = _okta_id(row.get("id"), "okta_application_id_invalid")
                status = _required_text(row.get("status"), "okta_status_invalid", 32)
                if status not in {"ACTIVE", "INACTIVE"}:
                    raise IdentityGovernanceProtocolError("okta_status_unsupported")
                normalized = {
                    "id_sha256": _sha256(raw_id),
                    "identity_kind": "application",
                    "enabled": status == "ACTIVE",
                }
                identities.append(
                    IdentityObservation(
                        observation_id=_scoped_id(
                            "idn", self._config.tenant_sha256, self.provider, raw_id
                        ),
                        identity_kind="application",
                        enabled=status == "ACTIVE",
                        assignment_required=None,
                        source_sha256=_sha256(normalized),
                    )
                )
                applications.append(raw_id)
            after = _okta_next_after(
                headers.get("link"), config=self._config, expected_path=_OKTA_APPS_PATH
            )
            if after is None:
                break

        for application_id in applications:
            path = f"/api/v1/apps/{quote(application_id, safe='')}/users"
            after = None
            while True:
                budget.page(f"assignments:{application_id}:{after or '<first>'}")
                query = {"limit": self._config.limits.page_size}
                if after is not None:
                    query["after"] = after
                payload, headers = self._request_json("GET", path, query=query)
                rows = _sequence(payload, "okta_assignment_rows_invalid")
                budget.records(len(rows))
                for value in rows:
                    row = _mapping(value, "okta_assignment_invalid")
                    subject = _okta_id(row.get("id"), "okta_subject_id_invalid")
                    scope = _required_text(row.get("scope"), "okta_scope_invalid", 32)
                    if scope not in {"USER", "GROUP"}:
                        raise IdentityGovernanceProtocolError("okta_scope_unsupported")
                    subject_kind: SubjectKind = (
                        "user" if scope == "USER" else "group"
                    )
                    normalized = {
                        "subject_id": _scoped_id(
                            "sub", self._config.tenant_sha256, self.provider, subject
                        ),
                        "resource_id": _scoped_id(
                            "res",
                            self._config.tenant_sha256,
                            self.provider,
                            application_id,
                        ),
                        "subject_kind": subject_kind,
                        "permission_id": _scoped_id(
                            "prm", self._config.tenant_sha256, self.provider, scope
                        ),
                    }
                    grants.append(
                        GrantObservation(
                            observation_id=_scoped_id(
                                "grt",
                                self._config.tenant_sha256,
                                self.provider,
                                f"{application_id}\0{subject}",
                            ),
                            subject_id=normalized["subject_id"],
                            resource_id=normalized["resource_id"],
                            grant_kind="application_assignment",
                            subject_kind=subject_kind,
                            permission_id=normalized["permission_id"],
                            source_sha256=_sha256(normalized),
                        )
                    )
                after = _okta_next_after(
                    headers.get("link"), config=self._config, expected_path=path
                )
                if after is None:
                    break
        return self._snapshot(identities, grants, ())


def _codes(value: object, category: str) -> tuple[str, ...]:
    rows = _sequence(value, category)
    if len(rows) > 128:
        raise IdentityGovernanceLimitError("purview_classification_limit_exceeded")
    return tuple(sorted({_closed_code(item, category) for item in rows}))


class PurviewGovernanceAdapter(_ReadOnlyAdapter):
    """Read Purview Data Map classification posture through discovery search."""

    provider: Provider = "purview"

    def collect(self) -> IdentityGovernanceSnapshot:
        self._require_enabled()
        budget = _Budget(self._config.limits)
        classifications: list[DataClassificationObservation] = []
        token: str | None = None
        while True:
            budget.page(f"search:{token or '<first>'}")
            body: dict[str, object] = {
                "keywords": None,
                "limit": self._config.limits.page_size,
            }
            if token is not None:
                body["continuationToken"] = token
            payload, _headers = self._request_json(
                "POST",
                _PURVIEW_SEARCH_PATH,
                query={"api-version": _PURVIEW_API_VERSION},
                json_body=body,
            )
            page = _mapping(payload, "purview_search_page_invalid")
            rows = _sequence(page.get("value"), "purview_search_rows_invalid")
            budget.records(len(rows))
            for value in rows:
                row = _mapping(value, "purview_search_result_invalid")
                raw_id = _guid(row.get("id"), "purview_asset_id_invalid")
                entity_type = _closed_code(
                    row.get("entityType"), "purview_entity_type_invalid"
                )
                codes = _codes(
                    row.get("classification", ()), "purview_classification_invalid"
                )
                labels = _codes(row.get("label", ()), "purview_label_invalid")
                normalized = {
                    "asset_id_sha256": _sha256(raw_id),
                    "entity_type": entity_type,
                    "classification_codes": codes,
                    "label_codes": labels,
                }
                classifications.append(
                    DataClassificationObservation(
                        observation_id=_scoped_id(
                            "cls", self._config.tenant_sha256, self.provider, raw_id
                        ),
                        asset_id=_scoped_id(
                            "ast", self._config.tenant_sha256, self.provider, raw_id
                        ),
                        entity_type=entity_type,
                        classification_codes=codes,
                        label_codes=labels,
                        source_sha256=_sha256(normalized),
                    )
                )
            raw_token = page.get("continuationToken")
            if raw_token is None:
                break
            token = _required_text(
                raw_token, "purview_continuation_token_invalid", _MAX_CURSOR_BYTES
            )
        return self._snapshot((), (), classifications)


def enabled(section: object) -> bool:
    """Return true only for an explicit top-level ``enable = true``."""

    if section is None:
        return False
    if not isinstance(section, Mapping):
        raise IdentityGovernanceConfigError("connector_section_invalid")
    value = section.get("enable", False)
    if not isinstance(value, bool):
        raise IdentityGovernanceConfigError("connector_enable_invalid")
    return value


def _limits_from_table(table: Mapping[str, Any]) -> ConnectorLimits:
    defaults = ConnectorLimits()
    return ConnectorLimits(
        timeout_seconds=table.get("timeout_seconds", defaults.timeout_seconds),
        max_pages=table.get("max_pages", defaults.max_pages),
        max_records=table.get("max_records", defaults.max_records),
        max_response_bytes=table.get(
            "max_response_bytes", defaults.max_response_bytes
        ),
        page_size=table.get("page_size", defaults.page_size),
        retry_attempts=table.get("retry_attempts", defaults.retry_attempts),
    )


def configured_connectors(
    section: object,
    *,
    transports: Mapping[str, ReadOnlyHTTPTransport],
    secret_resolver: SecretResolver,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.time,
) -> tuple[_ReadOnlyAdapter, ...]:
    """Build only explicitly enabled provider adapters from a strict section.

    The input is the already-selected ``[ai_identity_governance_connectors]``
    table.  A missing/disabled table returns no connectors and does not resolve
    or validate provider credentials.
    """

    if not enabled(section):
        return ()
    assert isinstance(section, Mapping)
    if set(section) - {"enable", *PROVIDERS}:
        raise IdentityGovernanceConfigError("connector_section_key_unsupported")
    factories = {
        "entra": EntraIdentityGovernanceAdapter,
        "okta": OktaIdentityGovernanceAdapter,
        "purview": PurviewGovernanceAdapter,
    }
    result: list[_ReadOnlyAdapter] = []
    for provider in PROVIDERS:
        raw = section.get(provider)
        if raw is None:
            continue
        if not isinstance(raw, Mapping):
            raise IdentityGovernanceConfigError("connector_provider_section_invalid")
        allowed = {
            "enable",
            "tenant_id",
            "base_url",
            "credential_secret_ref",
            "credential",
            "timeout_seconds",
            "max_pages",
            "max_records",
            "max_response_bytes",
            "page_size",
            "retry_attempts",
        }
        if set(raw) - allowed:
            raise IdentityGovernanceConfigError("connector_provider_key_unsupported")
        provider_enable = raw.get("enable", False)
        if not isinstance(provider_enable, bool):
            raise IdentityGovernanceConfigError("connector_enable_invalid")
        if not provider_enable:
            continue
        transport = transports.get(provider)
        if transport is None:
            raise IdentityGovernanceUnsupportedError("connector_transport_required")
        # A key saved on the dashboard is only a fallback: the credential the
        # server holds under the provider's reference always wins.
        saved = raw.get("credential")
        if saved is not None and (not isinstance(saved, str) or not saved.strip()):
            raise IdentityGovernanceConfigError("connector_credential_invalid")
        config = ConnectorConfig(
            provider=provider,
            enable=True,
            tenant_id=raw.get("tenant_id", ""),
            base_url=raw.get("base_url", ""),
            credential_secret_ref=raw.get(
                "credential_secret_ref",
                _DEFAULT_SECRET_REFERENCES[provider] if saved else "",
            ),
            limits=_limits_from_table(raw),
        )
        result.append(
            factories[provider](
                config,
                transport=transport,
                secret_resolver=(
                    _with_saved_credential(secret_resolver, saved) if saved else secret_resolver
                ),
                sleep=sleep,
                clock=clock,
            )
        )
    return tuple(result)


__all__ = [
    "BoundedHTTPResponse",
    "CONFIG_SECTION",
    "ConnectorConfig",
    "ConnectorLimits",
    "DataClassificationObservation",
    "EntraIdentityGovernanceAdapter",
    "GrantObservation",
    "IdentityGovernanceConfigError",
    "IdentityGovernanceConnectorError",
    "IdentityGovernanceLimitError",
    "IdentityGovernanceProtocolError",
    "IdentityGovernanceSnapshot",
    "IdentityGovernanceTransportError",
    "IdentityGovernanceUnsupportedError",
    "IdentityObservation",
    "OktaIdentityGovernanceAdapter",
    "PROVIDERS",
    "PurviewGovernanceAdapter",
    "ReadOnlyHTTPTransport",
    "configured_connectors",
    "enabled",
    "retry_classification",
]
