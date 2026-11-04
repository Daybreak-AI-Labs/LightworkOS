"""Native, bounded provider-audit readers for Snowflake and Databricks.

Only server-generated SELECT statements are submitted.  Provider identifiers,
query text, principals, origins, statement IDs, and log payloads remain
ephemeral; the returned core contract contains closed codes and SHA-256
digests.  Live provider interoperability and delivery completeness still
require operator acceptance.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from datetime import datetime
from typing import Any
from urllib.parse import quote, urlsplit

from maverick.constant_time import text_equals
from maverick.data_use_provider_adapters import (
    DataUseProviderError,
    DataUseProviderProtocolError,
    DataUseProviderRequestNotSent,
    DataUseProviderTransportAmbiguous,
    ProviderBindingStore,
    ProviderHttpResponse,
    ProviderHttpTransport,
    ProviderLimits,
)
from maverick.data_use_provider_audit import (
    AUDIT_BATCH_SCHEMA,
    DatabricksAuditEvent,
    DataUseProviderAuditConfigError,
    DataUseProviderAuditPermanent,
    DataUseProviderAuditRetryable,
    ProviderAuditAcceptedWatermark,
    ProviderAuditBatch,
    ProviderAuditCredentialLease,
    ProviderAuditCursor,
    ProviderAuditReadRequest,
    ProviderAuditStatementBinding,
    ProviderAuditTransport,
    SnowflakeAuditEvent,
    accepted_watermark_sha256,
)
from maverick.paths import canonical_tenant_id

from .data_use_provider_runtime import (
    PinnedProviderHttpTransport,
    provider_limits,
    provider_section,
)

_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_CHANGE_KINDS = frozenset({"grant", "masking_policy", "revoke", "row_filter", "state_anchor"})
_TRANSIENT_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})
_SNOWFLAKE_MINIMUM_LATENCY_SECONDS = 10_800
_SNOWFLAKE_SOURCE_RETENTION_SECONDS = 31_536_000
_MAX_SQL_BYTES = 64 * 1024
_MAX_ROWS = 501
_MAX_POLL_DELAY_SECONDS = 5.0


WatermarkAuthorityResolver = Callable[[str, str, float], ProviderAuditAcceptedWatermark | None]
CredentialLeaseResolver = Callable[..., ProviderAuditCredentialLease]


def _canonical(value: object, *, maximum: int = 1024 * 1024) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise DataUseProviderAuditPermanent("provider_audit_contract_invalid") from exc
    if not 1 <= len(encoded) <= maximum:
        raise DataUseProviderAuditPermanent("provider_audit_contract_invalid")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _digest(value: object) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise DataUseProviderAuditPermanent("provider_audit_contract_invalid")
    return value


def _bounded_int(value: object, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise DataUseProviderAuditConfigError("provider audit bound is invalid")
    return value


def _provider_count(value: object, *, maximum: int) -> int:
    if isinstance(value, bool):
        raise DataUseProviderAuditPermanent("provider_response_malformed")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,8}", value):
        result = int(value)
    else:
        raise DataUseProviderAuditPermanent("provider_response_malformed")
    if not 0 <= result <= maximum:
        raise DataUseProviderAuditPermanent("provider_response_malformed")
    return result


def _timestamp(value: object) -> float:
    if isinstance(value, bool):
        raise DataUseProviderAuditPermanent("provider_audit_payload_invalid")
    if isinstance(value, (int, float)):
        result = float(value)
    elif isinstance(value, str) and 1 <= len(value) <= 64:
        try:
            result = datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            try:
                result = float(value)
            except ValueError as exc:
                raise DataUseProviderAuditPermanent("provider_audit_payload_invalid") from exc
    else:
        raise DataUseProviderAuditPermanent("provider_audit_payload_invalid")
    if not math.isfinite(result) or result < 0:
        raise DataUseProviderAuditPermanent("provider_audit_payload_invalid")
    return result


def _token(value: object) -> str:
    if not isinstance(value, str) or not _TOKEN_RE.fullmatch(value) or _CONTROL_RE.search(value):
        raise DataUseProviderAuditPermanent("provider_audit_payload_invalid")
    return value


def _origin(provider_id: str, value: object) -> str:
    if not isinstance(value, str) or len(value) > 512:
        raise DataUseProviderAuditPermanent("provider_binding_invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise DataUseProviderAuditPermanent("provider_binding_invalid") from None
    host = (parsed.hostname or "").lower().rstrip(".")
    suffixes = (
        (".snowflakecomputing.com",)
        if provider_id == "snowflake"
        else (
            ".cloud.databricks.com",
            ".azuredatabricks.net",
            ".gcp.databricks.com",
        )
    )
    if (
        parsed.scheme != "https"
        or not any(host.endswith(suffix) and host != suffix[1:] for suffix in suffixes)
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise DataUseProviderAuditPermanent("provider_binding_invalid")
    return f"https://{host}"


def _audit_config(config: Mapping[str, Any]) -> Mapping[str, Any]:
    root = config.get("data_use_governance") if isinstance(config, Mapping) else None
    audit = root.get("provider_audit") if isinstance(root, Mapping) else None
    if (
        not isinstance(root, Mapping)
        or root.get("enable") is not True
        or not isinstance(audit, Mapping)
        or audit.get("enable") is not True
    ):
        raise DataUseProviderAuditConfigError("provider audit is disabled")
    return audit


@dataclass(frozen=True, slots=True)
class NativeProviderAuditLimits:
    overlap_seconds: int = 300
    max_pages_per_read: int = 20
    snowflake_latency_watermark_seconds: int | None = None
    retention_seconds: int = 31_536_000


def _native_limits(config: Mapping[str, Any]) -> NativeProviderAuditLimits:
    audit = _audit_config(config)
    overlap = _bounded_int(audit.get("cursor_overlap_seconds", 300), minimum=60, maximum=3600)
    pages = _bounded_int(audit.get("max_pages_per_read", 20), minimum=1, maximum=100)
    raw_latency = audit.get("snowflake_latency_watermark_seconds")
    latency = (
        None if raw_latency is None else _bounded_int(raw_latency, minimum=10_800, maximum=604_800)
    )
    retention = _bounded_int(
        audit.get("retention_seconds", 31_536_000),
        minimum=60,
        maximum=316_224_000,
    )
    return NativeProviderAuditLimits(overlap, pages, latency, retention)


def _validated_provider_limits(config: Mapping[str, Any], provider_id: str) -> ProviderLimits:
    try:
        limits = provider_limits(config, provider_id)
    except DataUseProviderError as exc:
        raise DataUseProviderAuditConfigError("native provider audit limits are invalid") from exc
    if provider_id == "databricks" and not 5.0 <= limits.timeout_seconds <= 50.0:
        raise DataUseProviderAuditConfigError(
            "Databricks provider audit HTTP timeout must be between 5 and 50 seconds"
        )
    return limits


class OperatorWatermarkAuthority:
    """Config/operator-owned coverage authority shared with the core store."""

    def __init__(
        self,
        *,
        tenant_id: str,
        binding_store: ProviderBindingStore,
        config: Mapping[str, Any],
        databricks_resolver: WatermarkAuthorityResolver | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._tenant_id = canonical_tenant_id(tenant_id)
        self._tenant_sha256 = _text_sha256(self._tenant_id)
        self._bindings = binding_store
        self._limits = _native_limits(config)
        self._databricks_resolver = databricks_resolver
        self._clock = clock

    def resolve(
        self, provider_id: str, binding_id: str, covered_until: float
    ) -> ProviderAuditAcceptedWatermark | None:
        covered = _timestamp(covered_until)
        binding = self._bindings.get_binding(self._tenant_id, binding_id)
        if (
            not isinstance(binding, Mapping)
            or binding.get("revoked") is not False
            or binding.get("provider_id") != provider_id
        ):
            return None
        if provider_id == "databricks":
            if not callable(self._databricks_resolver):
                return None
            value = self._databricks_resolver(provider_id, binding_id, covered)
            return value if type(value) is ProviderAuditAcceptedWatermark else None
        if provider_id != "snowflake":
            return None
        latency = self._limits.snowflake_latency_watermark_seconds
        if latency is None:
            return None
        now = _timestamp(self._clock())
        if covered > now - latency:
            return None
        candidate = ProviderAuditAcceptedWatermark(
            tenant_sha256=self._tenant_sha256,
            watermark_kind="snowflake_configured_latency",
            provider_id="snowflake",
            binding_id=str(binding["binding_id"]),
            binding_revision=int(binding["revision"]),
            binding_sha256=_digest(binding["binding_sha256"]),
            covered_until=covered,
            authority_sha256="0" * 64,
            expires_at=covered
            + min(
                self._limits.retention_seconds,
                _SNOWFLAKE_SOURCE_RETENTION_SECONDS,
            ),
            revoked=False,
        )
        if candidate.expires_at <= now:
            return None
        return replace(
            candidate,
            authority_sha256=accepted_watermark_sha256(candidate),
        )


def build_operator_watermark_authority(
    *,
    tenant_id: str,
    binding_store: ProviderBindingStore,
    config: Mapping[str, Any],
    databricks_resolver: WatermarkAuthorityResolver | None = None,
    clock: Callable[[], float] = time.time,
) -> OperatorWatermarkAuthority:
    return OperatorWatermarkAuthority(
        tenant_id=tenant_id,
        binding_store=binding_store,
        config=config,
        databricks_resolver=databricks_resolver,
        clock=clock,
    )


class NativeProviderAuditTransport:
    """Typed native reader over an injected pinned byte transport."""

    def __init__(
        self,
        *,
        tenant_id: str,
        binding_store: ProviderBindingStore,
        config: Mapping[str, Any],
        watermark_authority_resolver: WatermarkAuthorityResolver,
        credential_lease_resolver: CredentialLeaseResolver | None = None,
        http_transport: ProviderHttpTransport | None = None,
        clock: Callable[[], float] = time.time,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        _audit_config(config)
        if not isinstance(binding_store, ProviderBindingStore):
            raise DataUseProviderAuditConfigError("provider binding store is unavailable")
        if not callable(watermark_authority_resolver):
            raise DataUseProviderAuditConfigError(
                "provider audit watermark authority is unavailable"
            )
        selected_http = http_transport or PinnedProviderHttpTransport()
        if not callable(getattr(selected_http, "request", None)):
            raise DataUseProviderAuditConfigError("provider HTTP transport is unavailable")
        self._tenant_id = canonical_tenant_id(tenant_id)
        self._bindings = binding_store
        self._config = config
        self._limits = _native_limits(config)
        root = config.get("data_use_governance")
        if isinstance(root, Mapping):
            for provider_id in ("snowflake", "databricks"):
                section = root.get(provider_id)
                if isinstance(section, Mapping) and section.get("enable") is True:
                    _validated_provider_limits(config, provider_id)
        self._watermark_authority_resolver = watermark_authority_resolver
        if credential_lease_resolver is not None and not callable(credential_lease_resolver):
            raise DataUseProviderAuditConfigError(
                "provider audit credential renewal authority is invalid"
            )
        self._credential_lease_resolver = credential_lease_resolver
        self._http = selected_http
        self._clock = clock
        self._sleep = sleeper

    @staticmethod
    def _request_material(request: ProviderAuditReadRequest) -> dict[str, Any]:
        return {
            "schema": request.schema,
            "provider_id": request.provider_id,
            "binding_id": request.binding_id,
            "binding_revision": request.binding_revision,
            "binding_sha256": request.binding_sha256,
            "operation_idempotency_sha256": request.operation_idempotency_sha256,
            "correlation_sha256": request.correlation_sha256,
            "object_sha256": request.object_sha256,
            "statement_bindings": [asdict(item) for item in request.statement_bindings],
            "cursor": asdict(request.cursor),
            "audit_deadline": request.audit_deadline,
            "event_limit": request.event_limit,
        }

    def _validate_request(self, request: object) -> ProviderAuditReadRequest:
        if type(request) is not ProviderAuditReadRequest or request.schema != AUDIT_BATCH_SCHEMA:
            raise DataUseProviderAuditPermanent("provider_audit_contract_invalid")
        if request.provider_id not in {"snowflake", "databricks"}:
            raise DataUseProviderAuditPermanent("provider_audit_contract_invalid")
        _token(request.binding_id)
        if (
            isinstance(request.binding_revision, bool)
            or not isinstance(request.binding_revision, int)
            or not 1 <= request.binding_revision <= 2**31 - 1
            or type(request.cursor) is not ProviderAuditCursor
            or not isinstance(request.statement_bindings, tuple)
            or not 1 <= request.event_limit <= 500
        ):
            raise DataUseProviderAuditPermanent("provider_audit_contract_invalid")
        for value in (
            request.binding_sha256,
            request.operation_idempotency_sha256,
            request.correlation_sha256,
            request.object_sha256,
            request.cursor.event_id_sha256,
            request.request_sha256,
        ):
            _digest(value)
        _timestamp(request.cursor.occurred_at)
        _timestamp(request.audit_deadline)
        if request.request_sha256 != _sha256(self._request_material(request)):
            raise DataUseProviderAuditPermanent("provider_audit_contract_invalid")
        for item in request.statement_bindings:
            if type(item) is not ProviderAuditStatementBinding:
                raise DataUseProviderAuditPermanent("provider_audit_contract_invalid")
            _digest(item.provider_statement_sha256)
            _digest(item.control_sha256)
            _digest(item.object_sha256)
            if item.change_kind not in _CHANGE_KINDS:
                raise DataUseProviderAuditPermanent("provider_audit_contract_invalid")
            if (item.change_kind == "state_anchor") != (item.state_sha256 is not None):
                raise DataUseProviderAuditPermanent("provider_audit_contract_invalid")
            if item.state_sha256 is not None:
                _digest(item.state_sha256)
        return request

    def _binding(self, request: ProviderAuditReadRequest) -> dict[str, Any]:
        try:
            _validated_provider_limits(self._config, request.provider_id)
            section = provider_section(self._config, request.provider_id)
            raw = self._bindings.get_binding(self._tenant_id, request.binding_id)
        except DataUseProviderError as exc:
            raise DataUseProviderAuditPermanent("provider_binding_invalid") from exc
        if not isinstance(raw, Mapping):
            raise DataUseProviderAuditPermanent("provider_binding_missing")
        binding = dict(raw)
        if (
            binding.get("tenant_id") != self._tenant_id
            or binding.get("provider_id") != request.provider_id
            or binding.get("binding_id") != request.binding_id
            or binding.get("revision") != request.binding_revision
            or not hmac.compare_digest(
                str(binding.get("binding_sha256") or ""), request.binding_sha256
            )
            or binding.get("revoked") is not False
        ):
            raise DataUseProviderAuditPermanent("provider_binding_changed")
        configured_origin = _origin(request.provider_id, section.get("origin"))
        enrolled_origin = _origin(request.provider_id, binding.get("origin"))
        if not text_equals(configured_origin, enrolled_origin):
            raise DataUseProviderAuditPermanent("provider_binding_changed")
        for key in (
            "account_or_workspace_id",
            "catalog",
            "schema_name",
            "table",
            "compute_id",
        ):
            _token(binding.get(key))
        return binding

    def _credential(
        self,
        request: ProviderAuditReadRequest,
        binding: Mapping[str, Any],
        credential: object,
    ) -> ProviderAuditCredentialLease:
        if type(credential) is not ProviderAuditCredentialLease:
            raise DataUseProviderAuditPermanent("provider_credential_invalid")
        now = _timestamp(self._clock())
        if (
            credential.revoked is not False
            or not isinstance(credential.authorization, str)
            or not 1 <= len(credential.authorization) <= 8192
            or _CONTROL_RE.search(credential.authorization)
            or not hmac.compare_digest(
                credential.credential_key_id_sha256,
                str(binding.get("credential_key_id_sha256") or ""),
            )
            or credential.credential_revision != binding.get("credential_revision")
            or not hmac.compare_digest(
                credential.credential_authority_sha256,
                str(binding.get("credential_authority_sha256") or ""),
            )
        ):
            raise DataUseProviderAuditPermanent("provider_credential_invalid")
        if credential.expires_at <= now:
            raise DataUseProviderAuditRetryable("provider_credential_expired")
        return credential

    def _credential_for_io(
        self,
        request: ProviderAuditReadRequest,
        binding: Mapping[str, Any],
        credential: ProviderAuditCredentialLease,
        *,
        required_until: float,
    ) -> ProviderAuditCredentialLease:
        try:
            active = self._credential(request, binding, credential)
        except DataUseProviderAuditRetryable:
            active = credential
        if type(active) is ProviderAuditCredentialLease and active.expires_at > required_until:
            return active
        if not callable(self._credential_lease_resolver):
            raise DataUseProviderAuditRetryable("provider_credential_expired")
        try:
            renewed = self._credential_lease_resolver(
                provider_id=request.provider_id,
                tenant_id=self._tenant_id,
                binding_id=request.binding_id,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise DataUseProviderAuditRetryable("provider_credential_renewal_unavailable") from exc
        selected = self._credential(request, binding, renewed)
        if selected.expires_at <= required_until:
            raise DataUseProviderAuditRetryable("provider_credential_expired")
        return selected

    def _bounded_sleep(self, delay: float, read_deadline: float | None) -> None:
        bounded = float(delay)
        if read_deadline is not None and _timestamp(self._clock()) + bounded + 0.1 >= read_deadline:
            raise DataUseProviderAuditRetryable("provider_audit_read_deadline")
        self._sleep(bounded)

    @staticmethod
    def _response_json(response: ProviderHttpResponse, maximum: int) -> dict[str, Any]:
        if len(response.body) > maximum:
            raise DataUseProviderAuditPermanent("provider_response_oversized")
        try:
            value = json.loads(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise DataUseProviderAuditPermanent("provider_response_malformed") from exc
        if not isinstance(value, dict):
            raise DataUseProviderAuditPermanent("provider_response_malformed")
        return value

    def _http_request(
        self,
        *,
        request: ProviderAuditReadRequest,
        binding: Mapping[str, Any],
        credential: ProviderAuditCredentialLease,
        limits: ProviderLimits,
        method: str,
        path: str,
        body: Mapping[str, Any] | None,
        request_id_sha256: str,
        read_deadline: float | None,
    ) -> tuple[ProviderHttpResponse, list[dict[str, Any]]]:
        if method not in {"GET", "POST"} or not path.startswith("/") or len(path) > 1024:
            raise DataUseProviderAuditPermanent("provider_audit_contract_invalid")
        if "#" in path or "@" in path:
            raise DataUseProviderAuditPermanent("provider_audit_contract_invalid")
        encoded = None if body is None else _canonical(body, maximum=_MAX_SQL_BYTES)
        receipts: list[dict[str, Any]] = []
        active_credential = credential
        for attempt in range(1, limits.max_attempts + 1):
            active_path = path
            if (
                request.provider_id == "snowflake"
                and method == "POST"
                and attempt > 1
                and "retry=true" not in active_path
            ):
                active_path = f"{active_path}&retry=true"
            current = self._binding(request)
            now = _timestamp(self._clock())
            request_timeout = limits.timeout_seconds
            if read_deadline is not None:
                remaining = read_deadline - now - 0.25
                if remaining < 0.1:
                    raise DataUseProviderAuditRetryable("provider_audit_read_deadline")
                request_timeout = min(request_timeout, remaining)
            active_credential = self._credential_for_io(
                request,
                current,
                active_credential,
                required_until=now + request_timeout + 0.25,
            )
            origin = _origin(request.provider_id, current["origin"])
            receipt = {
                "method": method,
                "path_sha256": _text_sha256(active_path),
                "body_sha256": None if encoded is None else _sha256_bytes(encoded),
                "request_id_sha256": request_id_sha256,
                "attempt": attempt,
            }
            try:
                response = self._http.request(
                    method,
                    f"{origin}{active_path}",
                    headers={
                        "Accept": "application/json",
                        "Authorization": active_credential.authorization,
                        "Content-Type": "application/json",
                        "Idempotency-Key": request_id_sha256,
                        "User-Agent": "Lightwork-Provider-Audit/1",
                    },
                    body=encoded,
                    timeout=request_timeout,
                    max_response_bytes=limits.max_response_bytes,
                    allow_redirects=False,
                )
            except (KeyboardInterrupt, SystemExit):
                raise
            except (DataUseProviderRequestNotSent, DataUseProviderTransportAmbiguous):
                receipts.append({**receipt, "dispatch": "unavailable"})
                if attempt < limits.max_attempts:
                    self._bounded_sleep(
                        min(0.25 * 2 ** (attempt - 1), 1.0),
                        read_deadline,
                    )
                    continue
                raise DataUseProviderAuditRetryable("provider_audit_read_unavailable") from None
            except DataUseProviderProtocolError as exc:
                raise DataUseProviderAuditPermanent("provider_transport_rejected") from exc
            except Exception:
                receipts.append({**receipt, "dispatch": "unavailable"})
                if attempt < limits.max_attempts:
                    self._bounded_sleep(
                        min(0.25 * 2 ** (attempt - 1), 1.0),
                        read_deadline,
                    )
                    continue
                raise DataUseProviderAuditRetryable("provider_audit_read_unavailable") from None
            if type(response) is not ProviderHttpResponse:
                raise DataUseProviderAuditPermanent("provider_response_malformed")
            receipts.append(
                {
                    **receipt,
                    "status_code": response.status_code,
                    "response_sha256": _sha256_bytes(response.body),
                    "response_bytes": len(response.body),
                }
            )
            if 300 <= response.status_code <= 399:
                raise DataUseProviderAuditPermanent("provider_redirect_rejected")
            if response.status_code in _TRANSIENT_STATUS:
                if attempt < limits.max_attempts:
                    self._bounded_sleep(
                        min(0.25 * 2 ** (attempt - 1), 1.0),
                        read_deadline,
                    )
                    continue
                raise DataUseProviderAuditRetryable("provider_audit_read_unavailable")
            if not 200 <= response.status_code <= 299:
                raise DataUseProviderAuditPermanent("provider_audit_read_rejected")
            return response, receipts
        raise DataUseProviderAuditRetryable("provider_audit_read_unavailable")

    @staticmethod
    def _poll_delay(response: ProviderHttpResponse, index: int) -> float:
        raw = next(
            (value for key, value in response.headers.items() if str(key).lower() == "retry-after"),
            None,
        )
        if isinstance(raw, str):
            try:
                parsed = float(raw)
            except ValueError:
                parsed = -1.0
            if math.isfinite(parsed) and 0.1 <= parsed <= _MAX_POLL_DELAY_SECONDS:
                return parsed
        return min(0.25 * 2 ** (index - 1), 2.0)

    def _execute_statement(  # noqa: C901 - bounded provider response state machine
        self,
        *,
        request: ProviderAuditReadRequest,
        binding: Mapping[str, Any],
        credential: ProviderAuditCredentialLease,
        limits: ProviderLimits,
        statement: str,
        phase: str,
        expected_columns: int | None = None,
        read_deadline: float | None = None,
    ) -> tuple[list[list[Any]], list[dict[str, Any]]]:
        if not isinstance(statement, str) or not 1 <= len(statement.encode()) <= _MAX_SQL_BYTES:
            raise DataUseProviderAuditPermanent("provider_audit_contract_invalid")
        seed = hashlib.sha256(f"{request.request_sha256}:{phase}".encode()).hexdigest()
        request_uuid = str(uuid.UUID(seed[:32]))
        if request.provider_id == "snowflake":
            path = "/api/v2/statements?requestId=" + quote(request_uuid, safe="")
            body = {
                "statement": statement,
                "timeout": max(1, math.ceil(limits.timeout_seconds)),
                "database": binding["catalog"],
                "schema": binding["schema_name"],
                "warehouse": binding["compute_id"],
            }
        else:
            if expected_columns not in {1, 4}:
                raise DataUseProviderAuditPermanent("provider_audit_contract_invalid")
            path = "/api/2.0/sql/statements"
            body = {
                "statement": statement,
                "warehouse_id": binding["compute_id"],
                "wait_timeout": "0s",
                "on_wait_timeout": "CONTINUE",
                "format": "JSON_ARRAY",
                "disposition": "INLINE",
            }
        response, receipts = self._http_request(
            request=request,
            binding=binding,
            credential=credential,
            limits=limits,
            method="POST",
            path=path,
            body=body,
            request_id_sha256=seed,
            read_deadline=read_deadline,
        )
        handle: str | None = None
        payload: dict[str, Any]
        for poll_index in range(limits.max_polls + 1):
            payload = self._response_json(response, limits.max_response_bytes)
            raw_handle = (
                payload.get("statementHandle")
                if request.provider_id == "snowflake"
                else payload.get("statement_id")
            )
            observed_handle = None if raw_handle is None else _token(raw_handle)
            if handle is None:
                handle = observed_handle
            elif observed_handle is not None and not hmac.compare_digest(handle, observed_handle):
                raise DataUseProviderAuditPermanent("provider_statement_identity_changed")
            if request.provider_id == "snowflake":
                data = payload.get("data")
                if isinstance(data, list):
                    break
                pending = handle is not None and response.status_code in {200, 201, 202}
            else:
                status = payload.get("status")
                state = status.get("state") if isinstance(status, Mapping) else None
                if state == "SUCCEEDED":
                    result = payload.get("result")
                    if not isinstance(result, Mapping) or "external_links" in result:
                        raise DataUseProviderAuditPermanent("provider_response_malformed")
                    data = result.get("data_array", [])
                    if not isinstance(data, list):
                        raise DataUseProviderAuditPermanent("provider_response_malformed")
                    break
                if state in {"FAILED", "CANCELED", "CLOSED"}:
                    raise DataUseProviderAuditPermanent("provider_audit_query_failed")
                pending = state in {"PENDING", "RUNNING"} and handle is not None
            if not pending or handle is None:
                raise DataUseProviderAuditPermanent("provider_response_malformed")
            if poll_index >= limits.max_polls:
                raise DataUseProviderAuditRetryable("provider_audit_poll_incomplete")
            self._bounded_sleep(
                self._poll_delay(response, poll_index + 1),
                read_deadline,
            )
            poll_path = (
                "/api/v2/statements/" + quote(handle, safe="")
                if request.provider_id == "snowflake"
                else "/api/2.0/sql/statements/" + quote(handle, safe="")
            )
            response, polled = self._http_request(
                request=request,
                binding=binding,
                credential=credential,
                limits=limits,
                method="GET",
                path=poll_path,
                body=None,
                request_id_sha256=_text_sha256(f"{seed}:poll:{poll_index + 1}"),
                read_deadline=read_deadline,
            )
            receipts.extend(polled)
        else:  # pragma: no cover - bounded loop exits above
            raise DataUseProviderAuditRetryable("provider_audit_poll_incomplete")
        if handle is None:
            raise DataUseProviderAuditPermanent("provider_statement_identity_missing")
        statement_sha = _text_sha256(handle)
        for item in reversed(receipts):
            if "status_code" in item:
                item["provider_statement_sha256"] = statement_sha
                break
        rows = self._rows(data)
        if request.provider_id == "snowflake":
            metadata = payload.get("resultSetMetaData")
            if not isinstance(metadata, Mapping):
                raise DataUseProviderAuditPermanent("provider_partition_invalid")
            row_type = metadata.get("rowType")
            partition_info = metadata.get("partitionInfo")
            if (
                metadata.get("format") != "jsonv2"
                or not isinstance(row_type, list)
                or len(row_type) != 5
                or not all(isinstance(column, Mapping) for column in row_type)
                or not isinstance(partition_info, list)
                or not 1 <= len(partition_info) <= self._limits.max_pages_per_read
            ):
                raise DataUseProviderAuditPermanent("provider_partition_invalid")
            num_rows = _provider_count(
                metadata.get("numRows"),
                maximum=request.event_limit + 1,
            )
            partition_counts: list[int] = []
            for info in partition_info:
                if not isinstance(info, Mapping):
                    raise DataUseProviderAuditPermanent("provider_partition_invalid")
                partition_counts.append(
                    _provider_count(
                        info.get("rowCount"),
                        maximum=request.event_limit + 1,
                    )
                )
            if sum(partition_counts) != num_rows or len(rows) != partition_counts[0]:
                raise DataUseProviderAuditPermanent("provider_partition_invalid")
            for partition in range(1, len(partition_info)):
                page_response, page_receipts = self._http_request(
                    request=request,
                    binding=binding,
                    credential=credential,
                    limits=limits,
                    method="GET",
                    path=(
                        "/api/v2/statements/" + quote(handle, safe="") + f"?partition={partition}"
                    ),
                    body=None,
                    request_id_sha256=_text_sha256(f"{seed}:partition:{partition}"),
                    read_deadline=read_deadline,
                )
                receipts.extend(page_receipts)
                page = self._response_json(page_response, limits.max_response_bytes)
                page_handle = page.get("statementHandle")
                if page_handle is not None and _token(page_handle) != handle:
                    raise DataUseProviderAuditPermanent("provider_statement_identity_changed")
                if "data" not in page:
                    raise DataUseProviderAuditPermanent("provider_partition_invalid")
                page_rows = self._rows(page["data"])
                if len(page_rows) != partition_counts[partition]:
                    raise DataUseProviderAuditPermanent("provider_partition_invalid")
                rows.extend(page_rows)
            if len(rows) != num_rows:
                raise DataUseProviderAuditPermanent("provider_partition_invalid")
        else:
            result = payload.get("result")
            manifest = payload.get("manifest")
            if not isinstance(result, Mapping) or not isinstance(manifest, Mapping):
                raise DataUseProviderAuditPermanent("provider_manifest_invalid")
            schema = manifest.get("schema")
            columns = schema.get("columns") if isinstance(schema, Mapping) else None
            column_count = schema.get("column_count") if isinstance(schema, Mapping) else None
            total_rows = manifest.get("total_row_count")
            total_chunks = manifest.get("total_chunk_count")
            if (
                manifest.get("format") != "JSON_ARRAY"
                or manifest.get("truncated") is not False
                or isinstance(column_count, bool)
                or column_count != expected_columns
                or not isinstance(columns, list)
                or len(columns) != expected_columns
                or not all(isinstance(column, Mapping) for column in columns)
                or isinstance(total_rows, bool)
                or not isinstance(total_rows, int)
                or not 0 <= total_rows <= _MAX_ROWS
                or isinstance(total_chunks, bool)
                or not isinstance(total_chunks, int)
                or not 0 <= total_chunks <= self._limits.max_pages_per_read
            ):
                raise DataUseProviderAuditPermanent("provider_manifest_invalid")
            if total_rows == 0:
                if (
                    total_chunks != 0
                    or rows
                    or set(result) - {"data_array"}
                    or result.get("data_array", []) != []
                ):
                    raise DataUseProviderAuditPermanent("provider_manifest_invalid")
                next_chunk = None
                fetched_chunks = 0
            else:
                if (
                    total_chunks < 1
                    or "data_array" not in result
                    or result.get("chunk_index") != 0
                    or result.get("row_offset") != 0
                    or result.get("row_count") != len(rows)
                ):
                    raise DataUseProviderAuditPermanent("provider_manifest_invalid")
                next_chunk = result.get("next_chunk_index")
                fetched_chunks = 1
            while fetched_chunks < total_chunks:
                if next_chunk != fetched_chunks:
                    raise DataUseProviderAuditPermanent("provider_chunk_invalid")
                page_response, page_receipts = self._http_request(
                    request=request,
                    binding=binding,
                    credential=credential,
                    limits=limits,
                    method="GET",
                    path=(
                        "/api/2.0/sql/statements/"
                        + quote(handle, safe="")
                        + "/result/chunks/"
                        + str(next_chunk)
                    ),
                    body=None,
                    request_id_sha256=_text_sha256(f"{seed}:chunk:{next_chunk}"),
                    read_deadline=read_deadline,
                )
                receipts.extend(page_receipts)
                page = self._response_json(page_response, limits.max_response_bytes)
                if "external_links" in page or "data_array" not in page:
                    raise DataUseProviderAuditPermanent("provider_chunk_invalid")
                page_rows = self._rows(page["data_array"])
                if (
                    page.get("chunk_index") != fetched_chunks
                    or page.get("row_offset") != len(rows)
                    or page.get("row_count") != len(page_rows)
                    or len(rows) + len(page_rows) > total_rows
                ):
                    raise DataUseProviderAuditPermanent("provider_chunk_invalid")
                rows.extend(page_rows)
                next_chunk = page.get("next_chunk_index")
                fetched_chunks += 1
            if next_chunk is not None or fetched_chunks != total_chunks or len(rows) != total_rows:
                raise DataUseProviderAuditPermanent("provider_manifest_invalid")
        if len(rows) > _MAX_ROWS:
            raise DataUseProviderAuditPermanent("provider_row_bound_exceeded")
        return rows, receipts

    @staticmethod
    def _rows(value: object) -> list[list[Any]]:
        if not isinstance(value, list):
            raise DataUseProviderAuditPermanent("provider_response_malformed")
        if len(value) > _MAX_ROWS:
            raise DataUseProviderAuditPermanent("provider_row_bound_exceeded")
        result: list[list[Any]] = []
        for row in value:
            if not isinstance(row, list) or not 1 <= len(row) <= 8:
                raise DataUseProviderAuditPermanent("provider_response_malformed")
            if len(_canonical(row, maximum=64 * 1024)) > 64 * 1024:
                raise DataUseProviderAuditPermanent("provider_response_malformed")
            result.append(row)
        return result

    @staticmethod
    def _quote_literal(value: str) -> str:
        if not isinstance(value, str) or "'" in value or _CONTROL_RE.search(value):
            raise DataUseProviderAuditPermanent("provider_binding_invalid")
        return "'" + value + "'"

    def _snowflake_sql(
        self,
        binding: Mapping[str, Any],
        request: ProviderAuditReadRequest,
        start: float,
        end: float,
    ) -> str:
        target = ".".join(
            (str(binding["catalog"]), str(binding["schema_name"]), str(binding["table"]))
        )
        start_micros = int(round(start * 1_000_000))
        end_micros = int(round(end * 1_000_000))
        cursor_micros = int(round(request.cursor.occurred_at * 1_000_000))
        return (
            "SELECT q.QUERY_ID, DATE_PART(EPOCH_MICROSECOND, q.START_TIME) / 1000000.0, q.QUERY_TAG, "
            "q.EXECUTION_STATUS, EXISTS(SELECT 1 FROM SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY a "
            "WHERE a.QUERY_ID = q.QUERY_ID "
            f'AND a.OBJECT_MODIFIED_BY_DDL:"objectName"::STRING = {self._quote_literal(target)}) '
            "FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY q "
            f"WHERE q.START_TIME >= TO_TIMESTAMP_LTZ({start_micros}, 6) "
            f"AND q.START_TIME <= TO_TIMESTAMP_LTZ({end_micros}, 6) "
            f"AND (DATE_PART(EPOCH_MICROSECOND, q.START_TIME) > {cursor_micros} "
            f"OR (DATE_PART(EPOCH_MICROSECOND, q.START_TIME) = {cursor_micros} "
            f"AND LOWER(SHA2(q.QUERY_ID, 256)) > {self._quote_literal(request.cursor.event_id_sha256)})) "
            f"AND q.QUERY_TAG LIKE {self._quote_literal('lw2:' + request.correlation_sha256 + ':%')} "
            "ORDER BY DATE_PART(EPOCH_MICROSECOND, q.START_TIME), LOWER(SHA2(q.QUERY_ID, 256)) "
            f"LIMIT {request.event_limit + 1}"
        )

    def _databricks_query_sql(
        self, request: ProviderAuditReadRequest, start: float, end: float
    ) -> str:
        start_micros = int(round(start * 1_000_000))
        end_micros = int(round(end * 1_000_000))
        cursor_micros = int(round(request.cursor.occurred_at * 1_000_000))
        return (
            "SELECT statement_id, unix_micros(start_time) / 1000000.0, query_tags, execution_status "
            "FROM system.query.history "
            f"WHERE start_time >= timestamp_micros({start_micros}) "
            f"AND start_time <= timestamp_micros({end_micros}) "
            f"AND (unix_micros(start_time) > {cursor_micros} "
            f"OR (unix_micros(start_time) = {cursor_micros} "
            f"AND sha2(statement_id, 256) > {self._quote_literal(request.cursor.event_id_sha256)})) "
            f"AND query_tags['lw_corr'] = {self._quote_literal(request.correlation_sha256)} "
            "ORDER BY unix_micros(start_time), sha2(statement_id, 256) "
            f"LIMIT {request.event_limit + 1}"
        )

    @staticmethod
    def _databricks_access_sql(start: float, end: float) -> str:
        start_micros = int(round(start * 1_000_000))
        end_micros = int(round(end * 1_000_000))
        return (
            "SELECT COUNT(*) FROM system.access.audit "
            f"WHERE event_time >= timestamp_micros({start_micros}) "
            f"AND event_time <= timestamp_micros({end_micros})"
        )

    @staticmethod
    def _snowflake_tag(value: object) -> tuple[str, str, str, str, str | None]:
        if not isinstance(value, str) or len(value) > 512:
            raise DataUseProviderAuditPermanent("provider_audit_tag_invalid")
        parts = value.split(":")
        if len(parts) != 6 or parts[0] != "lw2" or parts[2] not in _CHANGE_KINDS:
            raise DataUseProviderAuditPermanent("provider_audit_tag_invalid")
        correlation, kind, control, object_sha, raw_state = parts[1:]
        state = None if raw_state == "-" else _digest(raw_state)
        if (kind == "state_anchor") != (state is not None):
            raise DataUseProviderAuditPermanent("provider_audit_tag_invalid")
        return _digest(correlation), kind, _digest(control), _digest(object_sha), state

    @staticmethod
    def _databricks_tags(value: object) -> tuple[str, str, str, str, str | None]:
        if isinstance(value, str) and len(value) <= 4096:
            try:
                value = json.loads(value)
            except json.JSONDecodeError as exc:
                raise DataUseProviderAuditPermanent("provider_audit_tag_invalid") from exc
        if not isinstance(value, Mapping):
            raise DataUseProviderAuditPermanent("provider_audit_tag_invalid")
        required = {"lw_corr", "lw_kind", "lw_ctrl", "lw_obj", "lw_state"}
        if not required <= set(value) or value.get("lw_kind") not in _CHANGE_KINDS:
            raise DataUseProviderAuditPermanent("provider_audit_tag_invalid")
        kind = str(value["lw_kind"])
        raw_state = value["lw_state"]
        state = None if raw_state == "-" else _digest(raw_state)
        if (kind == "state_anchor") != (state is not None):
            raise DataUseProviderAuditPermanent("provider_audit_tag_invalid")
        return (
            _digest(value["lw_corr"]),
            kind,
            _digest(value["lw_ctrl"]),
            _digest(value["lw_obj"]),
            state,
        )

    def _snowflake_events(self, rows: Sequence[list[Any]]) -> tuple[SnowflakeAuditEvent, ...]:
        events: list[SnowflakeAuditEvent] = []
        for row in rows:
            if len(row) != 5:
                raise DataUseProviderAuditPermanent("provider_response_malformed")
            raw_corroborated = row[4]
            if isinstance(raw_corroborated, bool):
                corroborated = raw_corroborated
            elif isinstance(raw_corroborated, str) and raw_corroborated.lower() in {
                "true",
                "false",
            }:
                corroborated = raw_corroborated.lower() == "true"
            else:
                raise DataUseProviderAuditPermanent("provider_response_malformed")
            query_id = _token(row[0])
            occurred = _timestamp(row[1])
            correlation, kind, control, object_sha, state = self._snowflake_tag(row[2])
            status = str(row[3] or "").upper()
            outcome = "succeeded" if status in {"SUCCESS", "SUCCEEDED"} else "failed"
            query_sha = _text_sha256(query_id)
            events.append(
                SnowflakeAuditEvent(
                    source_view="query_history",
                    event_id_sha256=query_sha,
                    query_id_sha256=query_sha,
                    occurred_at=occurred,
                    correlation_sha256=correlation,
                    object_sha256=object_sha,
                    change_kind=kind,
                    control_sha256=control,
                    outcome=outcome,
                    state_sha256=state,
                    object_change_corroborated=corroborated,
                )
            )
        return tuple(events)

    def _databricks_events(self, rows: Sequence[list[Any]]) -> tuple[DatabricksAuditEvent, ...]:
        events: list[DatabricksAuditEvent] = []
        for row in rows:
            if len(row) != 4:
                raise DataUseProviderAuditPermanent("provider_response_malformed")
            statement_id = _token(row[0])
            occurred = _timestamp(row[1])
            correlation, kind, control, object_sha, state = self._databricks_tags(row[2])
            status = str(row[3] or "").upper()
            outcome = "succeeded" if status in {"FINISHED", "SUCCEEDED"} else "failed"
            statement_sha = _text_sha256(statement_id)
            events.append(
                DatabricksAuditEvent(
                    source_table="system.query.history",
                    event_id_sha256=statement_sha,
                    request_id_sha256=None,
                    statement_id_sha256=statement_sha,
                    occurred_at=occurred,
                    correlation_sha256=correlation,
                    object_sha256=object_sha,
                    change_kind=kind,
                    control_sha256=control,
                    outcome=outcome,
                    state_sha256=state,
                )
            )
        return tuple(events)

    @staticmethod
    def _canonical_events(
        events: Sequence[SnowflakeAuditEvent | DatabricksAuditEvent],
        request: ProviderAuditReadRequest,
    ) -> tuple[SnowflakeAuditEvent | DatabricksAuditEvent, ...]:
        dedup: dict[str, SnowflakeAuditEvent | DatabricksAuditEvent] = {}
        for event in events:
            previous = dedup.get(event.event_id_sha256)
            if previous is not None and previous != event:
                raise DataUseProviderAuditPermanent("provider_event_ambiguous")
            dedup[event.event_id_sha256] = event
        ordered = tuple(
            sorted(dedup.values(), key=lambda item: (item.occurred_at, item.event_id_sha256))
        )
        if len(ordered) > request.event_limit + 1:
            raise DataUseProviderAuditPermanent("provider_row_bound_exceeded")
        return ordered

    def _accepted_watermark(
        self,
        request: ProviderAuditReadRequest,
        binding: Mapping[str, Any],
        covered_until: float,
    ) -> ProviderAuditAcceptedWatermark | None:
        try:
            candidate = self._watermark_authority_resolver(
                request.provider_id,
                request.binding_id,
                covered_until,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            return None
        if type(candidate) is not ProviderAuditAcceptedWatermark:
            return None
        now = _timestamp(self._clock())
        if (
            candidate.tenant_sha256 != _text_sha256(self._tenant_id)
            or candidate.provider_id != request.provider_id
            or candidate.binding_id != request.binding_id
            or candidate.binding_revision != request.binding_revision
            or not hmac.compare_digest(
                candidate.binding_sha256,
                request.binding_sha256,
            )
            or candidate.revoked is not False
            or candidate.covered_until != covered_until
            or candidate.expires_at <= now
            or candidate.watermark_kind
            != (
                "snowflake_configured_latency"
                if request.provider_id == "snowflake"
                else "databricks_accepted_delivery"
            )
            or not hmac.compare_digest(
                accepted_watermark_sha256(candidate),
                candidate.authority_sha256,
            )
            or binding.get("revoked") is not False
        ):
            return None
        return candidate

    @staticmethod
    def _noop_batch(
        request: ProviderAuditReadRequest,
        *,
        disposition: str,
    ) -> ProviderAuditBatch:
        return ProviderAuditBatch(
            events=(),
            next_cursor=request.cursor,
            covered_until=request.cursor.occurred_at,
            complete=False,
            provider_receipt_sha256=_sha256(
                {
                    "request_sha256": request.request_sha256,
                    "disposition": disposition,
                }
            ),
        )

    def _preflight(
        self,
        request: ProviderAuditReadRequest,
    ) -> (
        ProviderAuditBatch
        | tuple[
            ProviderAuditReadRequest,
            dict[str, Any],
            float,
            float,
            ProviderAuditAcceptedWatermark,
        ]
    ):
        _audit_config(self._config)
        selected = self._validate_request(request)
        binding = self._binding(selected)
        if os.getenv("MAVERICK_FETCH_ALLOW_PRIVATE", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }:
            raise DataUseProviderAuditPermanent("provider_private_fetch_override_rejected")
        now = _timestamp(self._clock())
        start = max(0.001, selected.cursor.occurred_at - self._limits.overlap_seconds)
        if selected.provider_id == "snowflake":
            latency = (
                self._limits.snowflake_latency_watermark_seconds
                or _SNOWFLAKE_MINIMUM_LATENCY_SECONDS
            )
            end = min(selected.audit_deadline, max(0.001, now - latency))
            if start < max(0.001, now - _SNOWFLAKE_SOURCE_RETENTION_SECONDS):
                return self._noop_batch(
                    selected,
                    disposition="source_retention_exceeded",
                )
        else:
            end = min(selected.audit_deadline, now)
        if end < start:
            return self._noop_batch(selected, disposition="watermark_not_mature")
        watermark = self._accepted_watermark(selected, binding, end)
        if watermark is None:
            return self._noop_batch(selected, disposition="watermark_not_accepted")
        return selected, binding, start, end, watermark

    def read_without_credential(
        self,
        request: ProviderAuditReadRequest,
    ) -> ProviderAuditBatch | None:
        """Return an authority no-op before a worker resolves any secret."""

        plan = self._preflight(request)
        return plan if type(plan) is ProviderAuditBatch else None

    def _read(
        self,
        request: ProviderAuditReadRequest,
        credential: ProviderAuditCredentialLease,
        *,
        read_deadline: float | None,
    ) -> ProviderAuditBatch:
        plan = self._preflight(request)
        if type(plan) is ProviderAuditBatch:
            return plan
        selected, binding, start, end, watermark = plan
        lease = self._credential(selected, binding, credential)
        limits = _validated_provider_limits(self._config, selected.provider_id)
        receipts: list[dict[str, Any]] = []
        if selected.provider_id == "snowflake":
            rows, primary_receipts = self._execute_statement(
                request=selected,
                binding=binding,
                credential=lease,
                limits=limits,
                statement=self._snowflake_sql(binding, selected, start, end),
                phase="snowflake-query-access-history",
                read_deadline=read_deadline,
            )
            receipts.extend(primary_receipts)
            events = self._snowflake_events(rows)
        else:
            rows, primary_receipts = self._execute_statement(
                request=selected,
                binding=binding,
                credential=lease,
                limits=limits,
                statement=self._databricks_query_sql(selected, start, end),
                phase="databricks-query-history",
                expected_columns=4,
                read_deadline=read_deadline,
            )
            receipts.extend(primary_receipts)
            events = self._databricks_events(rows)
            _supplemental_rows, supplemental_receipts = self._execute_statement(
                request=selected,
                binding=binding,
                credential=lease,
                limits=limits,
                statement=self._databricks_access_sql(start, end),
                phase="databricks-access-audit-supplemental",
                expected_columns=1,
                read_deadline=read_deadline,
            )
            receipts.extend(supplemental_receipts)
        start_micros = int(round(start * 1_000_000))
        end_micros = int(round(end * 1_000_000))
        cursor_pair = (
            int(round(selected.cursor.occurred_at * 1_000_000)),
            selected.cursor.event_id_sha256,
        )
        for event in events:
            event_micros = int(round(event.occurred_at * 1_000_000))
            if (
                event_micros < start_micros
                or event_micros > end_micros
                or (event_micros, event.event_id_sha256) <= cursor_pair
            ):
                raise DataUseProviderAuditPermanent("provider_event_outside_accepted_window")
        all_canonical = self._canonical_events(events, selected)
        truncated = len(all_canonical) > selected.event_limit
        canonical = all_canonical[: selected.event_limit]
        next_cursor = selected.cursor
        if canonical:
            last = canonical[-1]
            pair = (last.occurred_at, last.event_id_sha256)
            if pair > (next_cursor.occurred_at, next_cursor.event_id_sha256):
                next_cursor = ProviderAuditCursor(*pair)
        covered_until = next_cursor.occurred_at if truncated else max(end, next_cursor.occurred_at)
        if truncated:
            watermark = None
        else:
            if read_deadline is not None and _timestamp(self._clock()) + 0.1 >= read_deadline:
                raise DataUseProviderAuditRetryable("provider_audit_read_deadline")
            current_binding = self._binding(selected)
            watermark = self._accepted_watermark(selected, current_binding, end)
        complete = watermark is not None and covered_until >= selected.audit_deadline
        return ProviderAuditBatch(
            events=canonical,
            next_cursor=next_cursor,
            covered_until=covered_until,
            complete=complete,
            provider_receipt_sha256=_sha256(
                {
                    "request_sha256": selected.request_sha256,
                    "http_receipts": receipts,
                    "event_integrity_sha256": _sha256([asdict(item) for item in canonical]),
                    "covered_until": covered_until,
                    "truncated": truncated,
                    "watermark_authority_sha256": (
                        None if watermark is None else watermark.authority_sha256
                    ),
                    "live_provider_acceptance_verified": False,
                }
            ),
            watermark=watermark,
        )

    def read(
        self,
        request: ProviderAuditReadRequest,
        credential: ProviderAuditCredentialLease,
    ) -> ProviderAuditBatch:
        return self._read(request, credential, read_deadline=None)

    def read_with_deadline(
        self,
        request: ProviderAuditReadRequest,
        credential: ProviderAuditCredentialLease,
        *,
        deadline: float,
    ) -> ProviderAuditBatch:
        selected_deadline = _timestamp(deadline)
        if selected_deadline <= _timestamp(self._clock()) + 0.1:
            raise DataUseProviderAuditRetryable("provider_audit_read_deadline")
        return self._read(
            request,
            credential,
            read_deadline=selected_deadline,
        )


def build_native_provider_audit_transport(
    *,
    tenant_id: str,
    binding_store: ProviderBindingStore,
    config: Mapping[str, Any],
    watermark_authority_resolver: WatermarkAuthorityResolver,
    credential_lease_resolver: CredentialLeaseResolver | None = None,
    http_transport: ProviderHttpTransport | None = None,
    clock: Callable[[], float] = time.time,
    sleeper: Callable[[float], None] = time.sleep,
) -> ProviderAuditTransport:
    """Construct the shipped transport without binding, secret, or network I/O."""

    return NativeProviderAuditTransport(
        tenant_id=tenant_id,
        binding_store=binding_store,
        config=config,
        watermark_authority_resolver=watermark_authority_resolver,
        credential_lease_resolver=credential_lease_resolver,
        http_transport=http_transport,
        clock=clock,
        sleeper=sleeper,
    )


__all__ = [
    "CredentialLeaseResolver",
    "NativeProviderAuditLimits",
    "NativeProviderAuditTransport",
    "OperatorWatermarkAuthority",
    "WatermarkAuthorityResolver",
    "build_native_provider_audit_transport",
    "build_operator_watermark_authority",
]
