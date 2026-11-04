"""Hardened vendor transports for semantic GRC outbound synchronization.

The governed core in :mod:`maverick.grc_outbound_sync` deliberately stops at
an HTTP-free transport seam.  This module implements that seam for exactly two
admitted targets:

* ServiceNow IRM through three fixed Now Table API tables; and
* Archer through one fixed ``Lightwork_GRC_Sync`` Content API application.

Neither an API caller nor an :class:`~maverick.grc_outbound_sync.OutboundRequest`
can select a URL, table, application alias, method, or header.  Operator config
supplies only the vendor origin, the *name* of a secret, and bounded transport
limits.  Secret values are resolved immediately before each call and are never
stored on a transport object or copied into an exception.

Remote idempotency is not assumed from a non-standard header.  Both transports
write a dedicated Lightwork idempotency field and read it before and after a
mutation.  A retry after a response-lost timeout therefore recovers the record
instead of creating it again.  The ServiceNow tables must expose the ``u_*``
fields listed in :data:`SERVICENOW_REQUIRED_FIELDS`; the Archer instance must
provision the fixed application/fields listed in :data:`ARCHER_REQUIRED_FIELDS`
and make ``Lightwork_Idempotency_Key`` unique.  Those are explicit deployment
requirements, not caller-controlled schema choices.  Both vendor-side
idempotency fields must be indexed unique to close simultaneous create races.
"""
from __future__ import annotations

import ipaddress
import json
import math
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

from .grc_outbound_sync import (
    GRCSystem,
    GRCTransportConflict,
    GRCTransportFailure,
    OutboundRequest,
    OutboundResponse,
    SourceKind,
)

_MAX_CONFIG_URL = 2_048
_MAX_SECRET = 8_192
_MAX_REQUEST_BYTES = 512 * 1_024
_MIN_RESPONSE_BYTES = 1_024
_MAX_RESPONSE_BYTES = 1_024 * 1_024
_MIN_TIMEOUT_SECONDS = 1.0
_MAX_TIMEOUT_SECONDS = 60.0

_SECRET_REF_RE = re.compile(r"[A-Z][A-Z0-9_]{1,127}\Z")
_HEADER_SECRET_RE = re.compile(r"[\r\n\x00]")
_SN_SYS_ID_RE = re.compile(r"[0-9a-fA-F]{32}\Z")
_ARCHER_ID_RE = re.compile(r"[1-9][0-9]{0,18}\Z")

_SN_TABLES: dict[str, tuple[SourceKind, str]] = {
    "servicenow_irm.upsert_issue": (SourceKind.FINDING, "sn_grc_issue"),
    "servicenow_irm.upsert_risk_response": (
        SourceKind.RISK_ACCEPTANCE,
        "sn_risk_response_task",
    ),
    "servicenow_irm.upsert_risk_event": (
        SourceKind.AI_INCIDENT,
        "sn_risk_advanced_event",
    ),
}
_ARCHER_OPERATIONS: dict[str, SourceKind] = {
    "archer.upsert_finding": SourceKind.FINDING,
    "archer.upsert_risk_acceptance": SourceKind.RISK_ACCEPTANCE,
    "archer.upsert_ai_incident": SourceKind.AI_INCIDENT,
}

SERVICENOW_REQUIRED_FIELDS = frozenset(
    {
        "u_lightwork_idempotency_key",
        "u_lightwork_payload_sha256",
        "u_lightwork_source_revision",
        "u_lightwork_source_digest",
        "u_lightwork_tenant_sha256",
    }
)

ARCHER_APPLICATION_ALIAS = "Lightwork_GRC_Sync"
ARCHER_REQUIRED_FIELDS = frozenset(
    {
        "Lightwork_GRC_Sync_Id",
        "Record_Name",
        "Lightwork_Operation",
        "Lightwork_Source_Kind",
        "Lightwork_Source_Id",
        "Lightwork_Source_Revision",
        "Lightwork_Source_Digest",
        "Lightwork_Tenant_SHA256",
        "Lightwork_Idempotency_Key",
        "Lightwork_Payload_SHA256",
        "Lightwork_Payload_JSON",
    }
)

_SN_READ_FIELDS = ",".join(
    (
        "sys_id",
        "sys_mod_count",
        "sys_updated_on",
        "u_lightwork_idempotency_key",
        "u_lightwork_payload_sha256",
        "u_lightwork_source_revision",
        "u_lightwork_source_digest",
        "u_lightwork_tenant_sha256",
    )
)


class GRCVendorConfigError(GRCTransportFailure):
    """A fixed vendor transport is missing or has unsafe configuration."""

    def __init__(self, category: str = "vendor_config_invalid") -> None:
        super().__init__(category, retryable=False)


class GRCVendorProtocolError(GRCTransportFailure):
    """A credentialed vendor response violated the bounded contract."""

    def __init__(self, category: str = "invalid_vendor_response") -> None:
        super().__init__(category, retryable=False)


@dataclass(frozen=True)
class VendorTransportLimits:
    """Finite request limits shared by the two vendor transports."""

    timeout_seconds: float = 15.0
    max_response_bytes: int = 256 * 1_024

    def __post_init__(self) -> None:
        timeout = self.timeout_seconds
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(float(timeout))
            or not _MIN_TIMEOUT_SECONDS <= float(timeout) <= _MAX_TIMEOUT_SECONDS
        ):
            raise GRCVendorConfigError("vendor_timeout_invalid")
        size = self.max_response_bytes
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not _MIN_RESPONSE_BYTES <= size <= _MAX_RESPONSE_BYTES
        ):
            raise GRCVendorConfigError("vendor_response_bound_invalid")
        object.__setattr__(self, "timeout_seconds", float(timeout))


@dataclass(frozen=True, repr=False)
class VendorHTTPResponse:
    """Small response value used by the injectable HTTP seam.

    ``repr=False`` is intentional: even though production filters headers,
    test or alternate clients may return a credential-shaped header or body.
    """

    status_code: int
    headers: Mapping[str, str]
    body: bytes

    def __post_init__(self) -> None:
        if (
            isinstance(self.status_code, bool)
            or not isinstance(self.status_code, int)
            or not 100 <= self.status_code <= 599
        ):
            raise GRCVendorProtocolError("vendor_status_invalid")
        if not isinstance(self.headers, Mapping):
            raise GRCVendorProtocolError("vendor_headers_invalid")
        if not isinstance(self.body, bytes):
            raise GRCVendorProtocolError("vendor_body_invalid")


class VendorHTTPClient(Protocol):
    """Injectable, typed HTTP seam used for deterministic tests."""

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        json_body: Mapping[str, object] | None,
        timeout: float,
        max_response_bytes: int,
    ) -> VendorHTTPResponse: ...


SecretResolver = Callable[[str], str | None]


def _default_secret_resolver(name: str) -> str | None:
    from .secret_provider import get_secret

    return get_secret(name)


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


def _base_url(value: object, *, target: GRCSystem) -> str:
    if not isinstance(value, str):
        raise GRCVendorConfigError("vendor_base_url_invalid")
    raw = value.strip().rstrip("/")
    if not raw or len(raw) > _MAX_CONFIG_URL:
        raise GRCVendorConfigError("vendor_base_url_invalid")
    try:
        parsed = urlsplit(raw)
        _ = parsed.port
    except ValueError:
        raise GRCVendorConfigError("vendor_base_url_invalid") from None
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or _private_or_special_host(parsed.hostname)
    ):
        raise GRCVendorConfigError("vendor_base_url_invalid")

    path = parsed.path.rstrip("/")
    if target is GRCSystem.SERVICENOW_IRM:
        if path:
            raise GRCVendorConfigError("servicenow_origin_required")
        normalized_path = ""
    else:
        lowered = path.lower()
        if lowered == "":
            normalized_path = "/rsaarcher"
        elif lowered in {"/archer", "/rsaarcher"}:
            normalized_path = path
        elif lowered in {
            "/archer/api",
            "/archer/platformapi",
            "/rsaarcher/api",
            "/rsaarcher/platformapi",
        }:
            normalized_path = path.rsplit("/", 1)[0]
        else:
            raise GRCVendorConfigError("archer_origin_path_invalid")
    return urlunsplit(("https", parsed.netloc, normalized_path, "", ""))


def _secret_reference(value: object) -> str:
    if not isinstance(value, str) or not _SECRET_REF_RE.fullmatch(value.strip()):
        raise GRCVendorConfigError("credential_secret_ref_invalid")
    return value.strip()


def _credential(reference: str, resolver: SecretResolver, *, archer: bool) -> str:
    try:
        value = resolver(reference)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise GRCVendorConfigError("credential_resolution_failed") from None
    if not isinstance(value, str) or not value or len(value) > _MAX_SECRET:
        raise GRCVendorConfigError("credential_unavailable")
    if _HEADER_SECRET_RE.search(value) or any(ord(char) < 32 for char in value):
        raise GRCVendorConfigError("credential_header_invalid")
    if archer and not re.fullmatch(r"[A-Za-z0-9._~-]{8,512}", value):
        raise GRCVendorConfigError("credential_header_invalid")
    return value


def _compact_json(value: object) -> str:
    try:
        text = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError):
        raise GRCVendorProtocolError("vendor_request_not_json") from None
    if len(text.encode("utf-8")) > _MAX_REQUEST_BYTES:
        raise GRCVendorProtocolError("vendor_request_too_large")
    return text


def _json_object(response: VendorHTTPResponse) -> Mapping[str, Any]:
    if not response.body:
        raise GRCVendorProtocolError("vendor_response_empty")
    try:
        value = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise GRCVendorProtocolError("vendor_response_not_json") from None
    if not isinstance(value, Mapping):
        raise GRCVendorProtocolError("vendor_response_not_object")
    return value


def _header(headers: Mapping[str, str], name: str) -> str | None:
    wanted = name.lower()
    for key, value in headers.items():
        if str(key).lower() == wanted:
            return str(value)
    return None


def _classify_http(status: int, *, update: bool) -> None:
    if 200 <= status < 300:
        return
    if 300 <= status < 400:
        raise GRCTransportFailure("vendor_redirect_rejected", retryable=False)
    if status in {408, 425, 429, 500, 502, 503, 504}:
        category = "vendor_rate_limited" if status == 429 else "vendor_unavailable"
        raise GRCTransportFailure(category, retryable=True)
    if status in {401, 403}:
        raise GRCTransportFailure("vendor_authentication_rejected", retryable=False)
    if status in {409, 412}:
        raise GRCTransportConflict("external_revision_conflict")
    if status == 404 and update:
        raise GRCTransportConflict("external_record_missing")
    if status == 404:
        raise GRCTransportFailure("vendor_endpoint_missing", retryable=False)
    if 400 <= status < 500:
        raise GRCTransportFailure("vendor_request_rejected", retryable=False)
    raise GRCTransportFailure("vendor_http_failure", retryable=True)


class _PinnedVendorHTTPClient:
    """SSRF-pinned, redirect-disabled, enterprise-egress-aware HTTP client."""

    def __init__(self, target: GRCSystem) -> None:
        self._target = target

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        json_body: Mapping[str, object] | None,
        timeout: float,
        max_response_bytes: int,
    ) -> VendorHTTPResponse:
        from .enterprise import enterprise_egress_denial
        from .tools._ssrf import BlockedHost, safe_client

        denial = enterprise_egress_denial(
            url,
            tool=f"grc_outbound_sync.{self._target.value}",
        )
        if denial:
            raise GRCTransportFailure("enterprise_egress_denied", retryable=False)
        try:
            with safe_client(url, timeout=timeout) as client:
                with client.stream(
                    method,
                    url,
                    headers=dict(headers),
                    json=dict(json_body) if json_body is not None else None,
                ) as response:
                    declared = response.headers.get("content-length")
                    if declared is not None:
                        try:
                            declared_size = int(declared)
                        except ValueError:
                            raise GRCVendorProtocolError(
                                "vendor_content_length_invalid"
                            ) from None
                        if declared_size < 0 or declared_size > max_response_bytes:
                            raise GRCVendorProtocolError("vendor_response_too_large")
                    chunks: list[bytes] = []
                    observed = 0
                    for chunk in response.iter_bytes():
                        observed += len(chunk)
                        if observed > max_response_bytes:
                            raise GRCVendorProtocolError("vendor_response_too_large")
                        chunks.append(chunk)
                    selected_headers = {
                        key: value
                        for key, value in response.headers.items()
                        if key.lower()
                        in {"content-length", "etag", "last-modified", "retry-after"}
                    }
                    return VendorHTTPResponse(
                        status_code=int(response.status_code),
                        headers=selected_headers,
                        body=b"".join(chunks),
                    )
        except BlockedHost:
            raise GRCTransportFailure("vendor_ssrf_blocked", retryable=False) from None


class _VendorTransportBase:
    __slots__ = (
        "_base_url",
        "_credential_secret_ref",
        "_http",
        "_limits",
        "_secret_resolver",
        "_target",
    )

    def __init__(
        self,
        *,
        target: GRCSystem,
        base_url: str,
        credential_secret_ref: str,
        limits: VendorTransportLimits | None,
        http: VendorHTTPClient | None,
        secret_resolver: SecretResolver | None,
    ) -> None:
        self._target = target
        self._base_url = _base_url(base_url, target=target)
        self._credential_secret_ref = _secret_reference(credential_secret_ref)
        self._limits = limits or VendorTransportLimits()
        if not isinstance(self._limits, VendorTransportLimits):
            raise GRCVendorConfigError("vendor_limits_invalid")
        self._http = http or _PinnedVendorHTTPClient(target)
        if not hasattr(self._http, "request") or not callable(self._http.request):
            raise GRCVendorConfigError("vendor_http_client_invalid")
        self._secret_resolver = secret_resolver or _default_secret_resolver
        if not callable(self._secret_resolver):
            raise GRCVendorConfigError("credential_resolver_invalid")

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(target={self._target.value!r}, "
            f"base_url={self._base_url!r}, "
            f"credential_secret_ref={self._credential_secret_ref!r}, "
            f"limits={self._limits!r})"
        )

    def _headers(self, request: OutboundRequest) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Idempotency-Key": request.idempotency_key,
            "X-Lightwork-Idempotency-Key": request.idempotency_key,
            "X-Lightwork-Payload-SHA256": request.payload_sha256,
            "X-Lightwork-Source-Digest": request.source_digest,
            "X-Lightwork-Source-Revision": str(request.source_revision),
            "X-Lightwork-Tenant-SHA256": request.tenant_sha256,
        }

    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: Mapping[str, object] | None = None,
        update: bool = False,
    ) -> VendorHTTPResponse:
        if body is not None:
            _compact_json(body)
        try:
            response = self._http.request(
                method,
                url,
                headers=headers,
                json_body=body,
                timeout=self._limits.timeout_seconds,
                max_response_bytes=self._limits.max_response_bytes,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except GRCTransportFailure:
            raise
        except Exception as exc:
            error_name = type(exc).__name__.lower()
            category = (
                "vendor_transport_timeout"
                if "timeout" in error_name
                else "vendor_transport_exception"
            )
            raise GRCTransportFailure(category, retryable=True) from None
        if not isinstance(response, VendorHTTPResponse):
            raise GRCVendorProtocolError("vendor_http_response_untyped")
        declared = _header(response.headers, "content-length")
        if declared is not None:
            try:
                declared_size = int(declared)
            except ValueError:
                raise GRCVendorProtocolError("vendor_content_length_invalid") from None
            if declared_size < 0 or declared_size > self._limits.max_response_bytes:
                raise GRCVendorProtocolError("vendor_response_too_large")
        if len(response.body) > self._limits.max_response_bytes:
            raise GRCVendorProtocolError("vendor_response_too_large")
        _classify_http(response.status_code, update=update)
        return response

    @staticmethod
    def _response(
        request: OutboundRequest,
        *,
        external_id: str,
        external_url: str,
        external_revision: str,
    ) -> OutboundResponse:
        return OutboundResponse(
            idempotency_key=request.idempotency_key,
            source_revision=request.source_revision,
            source_digest=request.source_digest,
            external_id=external_id,
            external_url=external_url,
            external_revision=external_revision,
        )


class ServiceNowIRMTransport(_VendorTransportBase):
    """Fixed-table ServiceNow IRM transport with remote retry recovery."""

    def __init__(
        self,
        *,
        base_url: str,
        credential_secret_ref: str = "SERVICENOW_TOKEN",
        limits: VendorTransportLimits | None = None,
        http: VendorHTTPClient | None = None,
        secret_resolver: SecretResolver | None = None,
    ) -> None:
        super().__init__(
            target=GRCSystem.SERVICENOW_IRM,
            base_url=base_url,
            credential_secret_ref=credential_secret_ref,
            limits=limits,
            http=http,
            secret_resolver=secret_resolver,
        )

    def _auth_headers(self, request: OutboundRequest) -> dict[str, str]:
        token = _credential(
            self._credential_secret_ref,
            self._secret_resolver,
            archer=False,
        )
        return {**self._headers(request), "Authorization": f"Bearer {token}"}

    @staticmethod
    def _validate_request(request: OutboundRequest) -> str:
        if not isinstance(request, OutboundRequest):
            raise GRCVendorProtocolError("outbound_request_untyped")
        if request.target is not GRCSystem.SERVICENOW_IRM:
            raise GRCVendorProtocolError("vendor_target_mismatch")
        binding = _SN_TABLES.get(request.operation)
        if binding is None or binding[0] is not request.source_kind:
            raise GRCVendorProtocolError("vendor_operation_mismatch")
        return binding[1]

    def _table_url(self, table: str) -> str:
        return f"{self._base_url}/api/now/table/{table}"

    def _record_link(self, table: str, sys_id: str) -> str:
        target = quote(f"{table}.do?sys_id={sys_id}", safe="._-")
        return f"{self._base_url}/now/nav/ui/classic/params/target/{target}"

    @staticmethod
    def _revision(row: Mapping[str, Any]) -> str:
        raw = row.get("sys_mod_count")
        if raw is None or raw == "":
            raw = row.get("sys_updated_on")
        if isinstance(raw, bool) or not isinstance(raw, (str, int, float)):
            raise GRCVendorProtocolError("servicenow_revision_missing")
        value = str(raw).strip()
        if not value or len(value) > 256 or any(ord(char) < 32 for char in value):
            raise GRCVendorProtocolError("servicenow_revision_invalid")
        return value

    def _row_response(
        self,
        request: OutboundRequest,
        table: str,
        row: Mapping[str, Any],
        *,
        require_idempotency: bool = True,
    ) -> OutboundResponse:
        raw_id = row.get("sys_id")
        if not isinstance(raw_id, str) or not _SN_SYS_ID_RE.fullmatch(raw_id):
            raise GRCVendorProtocolError("servicenow_record_id_invalid")
        if require_idempotency:
            observed = row.get("u_lightwork_idempotency_key")
            if observed != request.idempotency_key:
                raise GRCTransportConflict("external_idempotency_conflict")
        digest = row.get("u_lightwork_source_digest")
        if digest != request.source_digest:
            raise GRCTransportConflict("external_source_digest_conflict")
        if row.get("u_lightwork_payload_sha256") != request.payload_sha256:
            raise GRCTransportConflict("external_payload_digest_conflict")
        if row.get("u_lightwork_tenant_sha256") != request.tenant_sha256:
            raise GRCTransportConflict("external_tenant_binding_conflict")
        remote_revision = row.get("u_lightwork_source_revision")
        if str(remote_revision).strip() != str(request.source_revision):
            raise GRCTransportConflict("external_source_revision_conflict")
        return self._response(
            request,
            external_id=raw_id.lower(),
            external_url=self._record_link(table, raw_id.lower()),
            external_revision=self._revision(row),
        )

    def _lookup_by_idempotency(
        self,
        request: OutboundRequest,
        table: str,
        headers: Mapping[str, str],
    ) -> OutboundResponse | None:
        query = urlencode(
            {
                "sysparm_query": (
                    "u_lightwork_idempotency_key=" + request.idempotency_key
                ),
                "sysparm_limit": "2",
                "sysparm_fields": _SN_READ_FIELDS,
            }
        )
        response = self._request(
            "GET",
            f"{self._table_url(table)}?{query}",
            headers=headers,
        )
        result = _json_object(response).get("result")
        if not isinstance(result, list):
            raise GRCVendorProtocolError("servicenow_query_result_invalid")
        if len(result) > 1:
            raise GRCTransportConflict("external_idempotency_not_unique")
        if not result:
            return None
        row = result[0]
        if not isinstance(row, Mapping):
            raise GRCVendorProtocolError("servicenow_record_invalid")
        return self._row_response(request, table, row)

    def _get_record(
        self,
        request: OutboundRequest,
        table: str,
        sys_id: str,
        headers: Mapping[str, str],
        *,
        postflight: bool,
    ) -> Mapping[str, Any] | None:
        query = urlencode({"sysparm_fields": _SN_READ_FIELDS})
        try:
            response = self._request(
                "GET",
                f"{self._table_url(table)}/{sys_id}?{query}",
                headers=headers,
                update=True,
            )
        except GRCTransportConflict as exc:
            if exc.category == "external_record_missing" and postflight:
                return None
            raise
        result = _json_object(response).get("result")
        if not isinstance(result, Mapping):
            raise GRCVendorProtocolError("servicenow_record_invalid")
        return result

    @staticmethod
    def _body(request: OutboundRequest) -> dict[str, object]:
        return {
            **dict(request.payload),
            "u_lightwork_idempotency_key": request.idempotency_key,
            "u_lightwork_payload_sha256": request.payload_sha256,
            "u_lightwork_source_revision": request.source_revision,
            "u_lightwork_source_digest": request.source_digest,
            "u_lightwork_tenant_sha256": request.tenant_sha256,
        }

    def send(self, request: OutboundRequest) -> OutboundResponse:
        table = self._validate_request(request)
        headers = self._auth_headers(request)
        body = self._body(request)
        reference = request.external_reference

        if reference is None:
            recovered = self._lookup_by_idempotency(request, table, headers)
            if recovered is not None:
                return recovered
            query = urlencode({"sysparm_fields": _SN_READ_FIELDS})
            try:
                self._request(
                    "POST",
                    f"{self._table_url(table)}?{query}",
                    headers=headers,
                    body=body,
                )
            except GRCTransportConflict:
                recovered = self._lookup_by_idempotency(request, table, headers)
                if recovered is not None:
                    return recovered
                raise
            recovered = self._lookup_by_idempotency(request, table, headers)
            if recovered is None:
                raise GRCTransportFailure("vendor_receipt_unavailable", retryable=True)
            return recovered

        sys_id = reference.external_id
        if not _SN_SYS_ID_RE.fullmatch(sys_id):
            raise GRCVendorProtocolError("servicenow_record_id_invalid")
        prior = self._get_record(
            request,
            table,
            sys_id,
            headers,
            postflight=False,
        )
        assert prior is not None
        if prior.get("u_lightwork_idempotency_key") == request.idempotency_key:
            return self._row_response(request, table, prior)
        if self._revision(prior) != reference.external_revision:
            raise GRCTransportConflict("external_revision_conflict")
        update_headers = {**headers, "If-Match": reference.external_revision}
        query = urlencode({"sysparm_fields": _SN_READ_FIELDS})
        self._request(
            "PATCH",
            f"{self._table_url(table)}/{sys_id}?{query}",
            headers=update_headers,
            body=body,
            update=True,
        )
        current = self._get_record(
            request,
            table,
            sys_id,
            headers,
            postflight=True,
        )
        if current is None:
            raise GRCTransportFailure("vendor_receipt_unavailable", retryable=True)
        return self._row_response(request, table, current)


class ArcherTransport(_VendorTransportBase):
    """Fixed-application Archer Content API transport.

    The instance must provision the ``Lightwork_GRC_Sync`` application alias
    with :data:`ARCHER_REQUIRED_FIELDS`.  A unique constraint on
    ``Lightwork_Idempotency_Key`` closes concurrent duplicate-create races.
    """

    def __init__(
        self,
        *,
        base_url: str,
        credential_secret_ref: str = "ARCHER_GRC_TOKEN",
        limits: VendorTransportLimits | None = None,
        http: VendorHTTPClient | None = None,
        secret_resolver: SecretResolver | None = None,
    ) -> None:
        super().__init__(
            target=GRCSystem.ARCHER,
            base_url=base_url,
            credential_secret_ref=credential_secret_ref,
            limits=limits,
            http=http,
            secret_resolver=secret_resolver,
        )

    def _auth_headers(self, request: OutboundRequest) -> dict[str, str]:
        token = _credential(
            self._credential_secret_ref,
            self._secret_resolver,
            archer=True,
        )
        return {
            **self._headers(request),
            "Cookie": f"ArcherSessionCookie={token}",
        }

    @staticmethod
    def _validate_request(request: OutboundRequest) -> None:
        if not isinstance(request, OutboundRequest):
            raise GRCVendorProtocolError("outbound_request_untyped")
        if request.target is not GRCSystem.ARCHER:
            raise GRCVendorProtocolError("vendor_target_mismatch")
        expected = _ARCHER_OPERATIONS.get(request.operation)
        if expected is None or expected is not request.source_kind:
            raise GRCVendorProtocolError("vendor_operation_mismatch")

    def _content_url(self) -> str:
        return f"{self._base_url}/contentapi/{ARCHER_APPLICATION_ALIAS}"

    def _record_link(self, external_id: str) -> str:
        return f"{self._content_url()}/{external_id}"

    @staticmethod
    def _external_revision(row: Mapping[str, Any]) -> str:
        revision = row.get("Lightwork_Source_Revision")
        digest = row.get("Lightwork_Source_Digest")
        if isinstance(revision, bool) or not isinstance(revision, (int, str)):
            raise GRCVendorProtocolError("archer_revision_missing")
        revision_text = str(revision).strip()
        if not revision_text.isdigit() or int(revision_text) < 1:
            raise GRCVendorProtocolError("archer_revision_invalid")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise GRCVendorProtocolError("archer_digest_invalid")
        return f"lw-{int(revision_text)}-{digest[:16]}"

    def _row_response(
        self,
        request: OutboundRequest,
        row: Mapping[str, Any],
    ) -> OutboundResponse:
        raw_id = row.get("Lightwork_GRC_Sync_Id")
        if raw_id is None:
            raw_id = row.get("Id", row.get("ContentId"))
        external_id = str(raw_id).strip()
        if not _ARCHER_ID_RE.fullmatch(external_id):
            raise GRCVendorProtocolError("archer_record_id_invalid")
        if row.get("Lightwork_Idempotency_Key") != request.idempotency_key:
            raise GRCTransportConflict("external_idempotency_conflict")
        if row.get("Lightwork_Source_Digest") != request.source_digest:
            raise GRCTransportConflict("external_source_digest_conflict")
        if row.get("Lightwork_Payload_SHA256") != request.payload_sha256:
            raise GRCTransportConflict("external_payload_digest_conflict")
        if row.get("Lightwork_Tenant_SHA256") != request.tenant_sha256:
            raise GRCTransportConflict("external_tenant_binding_conflict")
        if str(row.get("Lightwork_Source_Revision")).strip() != str(
            request.source_revision
        ):
            raise GRCTransportConflict("external_source_revision_conflict")
        if row.get("Lightwork_Source_Kind") != request.source_kind.value:
            raise GRCTransportConflict("external_source_kind_conflict")
        if row.get("Lightwork_Source_Id") != request.source_id:
            raise GRCTransportConflict("external_source_id_conflict")
        if row.get("Lightwork_Operation") != request.operation:
            raise GRCTransportConflict("external_operation_conflict")
        return self._response(
            request,
            external_id=external_id,
            external_url=self._record_link(external_id),
            external_revision=self._external_revision(row),
        )

    def _query(
        self,
        request: OutboundRequest,
        headers: Mapping[str, str],
        *,
        field: str,
        value: str,
    ) -> list[Mapping[str, Any]]:
        if field == "Lightwork_GRC_Sync_Id":
            expression = f"{field} eq {value}"
        else:
            escaped = value.replace("'", "''")
            expression = f"{field} eq '{escaped}'"
        query = urlencode({"$filter": expression, "$top": "2"})
        response = self._request(
            "GET",
            f"{self._content_url()}?{query}",
            headers=headers,
        )
        values = _json_object(response).get("value")
        if not isinstance(values, list):
            raise GRCVendorProtocolError("archer_query_result_invalid")
        if len(values) > 1:
            raise GRCTransportConflict("external_idempotency_not_unique")
        if any(not isinstance(row, Mapping) for row in values):
            raise GRCVendorProtocolError("archer_record_invalid")
        return values

    @staticmethod
    def _body(
        request: OutboundRequest,
        *,
        external_id: str | None,
    ) -> dict[str, object]:
        record_name = request.payload.get("record_name")
        if not isinstance(record_name, str) or not record_name.strip():
            record_name = f"Lightwork {request.source_kind.value}: {request.source_id}"
        body: dict[str, object] = {
            "Lightwork_GRC_Sync_Id": int(external_id or "0"),
            "Record_Name": record_name[:255],
            "Lightwork_Operation": request.operation,
            "Lightwork_Source_Kind": request.source_kind.value,
            "Lightwork_Source_Id": request.source_id,
            "Lightwork_Source_Revision": request.source_revision,
            "Lightwork_Source_Digest": request.source_digest,
            "Lightwork_Tenant_SHA256": request.tenant_sha256,
            "Lightwork_Idempotency_Key": request.idempotency_key,
            "Lightwork_Payload_SHA256": request.payload_sha256,
            "Lightwork_Payload_JSON": _compact_json(dict(request.payload)),
        }
        _compact_json(body)
        return body

    def send(self, request: OutboundRequest) -> OutboundResponse:
        self._validate_request(request)
        headers = self._auth_headers(request)
        reference = request.external_reference
        if reference is None:
            rows = self._query(
                request,
                headers,
                field="Lightwork_Idempotency_Key",
                value=request.idempotency_key,
            )
            if rows:
                return self._row_response(request, rows[0])
            try:
                self._request(
                    "POST",
                    self._content_url(),
                    headers=headers,
                    body=self._body(request, external_id=None),
                )
            except GRCTransportConflict:
                rows = self._query(
                    request,
                    headers,
                    field="Lightwork_Idempotency_Key",
                    value=request.idempotency_key,
                )
                if rows:
                    return self._row_response(request, rows[0])
                raise
            rows = self._query(
                request,
                headers,
                field="Lightwork_Idempotency_Key",
                value=request.idempotency_key,
            )
            if not rows:
                raise GRCTransportFailure("vendor_receipt_unavailable", retryable=True)
            return self._row_response(request, rows[0])

        external_id = reference.external_id
        if not _ARCHER_ID_RE.fullmatch(external_id):
            raise GRCVendorProtocolError("archer_record_id_invalid")
        rows = self._query(
            request,
            headers,
            field="Lightwork_GRC_Sync_Id",
            value=external_id,
        )
        if not rows:
            raise GRCTransportConflict("external_record_missing")
        prior = rows[0]
        if prior.get("Lightwork_Idempotency_Key") == request.idempotency_key:
            return self._row_response(request, prior)
        if self._external_revision(prior) != reference.external_revision:
            raise GRCTransportConflict("external_revision_conflict")
        self._request(
            "POST",
            self._content_url(),
            headers=headers,
            body=self._body(request, external_id=external_id),
            update=True,
        )
        rows = self._query(
            request,
            headers,
            field="Lightwork_GRC_Sync_Id",
            value=external_id,
        )
        if not rows:
            raise GRCTransportFailure("vendor_receipt_unavailable", retryable=True)
        return self._row_response(request, rows[0])


_TRANSPORT_CONFIG_KEYS = frozenset(
    {
        "base_url",
        "credential_secret_ref",
        "credential",
        "timeout_seconds",
        "max_response_bytes",
    }
)
# Config table of each vendor under [grc_outbound_sync].
_TRANSPORT_SECTIONS = {
    GRCSystem.SERVICENOW_IRM: "servicenow_irm",
    GRCSystem.ARCHER: "archer",
}


def _with_saved_credential(resolver: SecretResolver, saved: str) -> SecretResolver:
    """Resolve on the server first; fall back to the dashboard-saved key."""

    def resolve(reference: str) -> str | None:
        return resolver(reference) or saved

    return resolve


def _environment_value(environ: Mapping[str, str], names: tuple[str, ...]) -> str:
    for name in names:
        value = environ.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def transport_from_config(
    target: GRCSystem,
    *,
    config: Mapping[str, Any] | None = None,
    environ: Mapping[str, str] | None = None,
    http: VendorHTTPClient | None = None,
    secret_resolver: SecretResolver | None = None,
) -> ServiceNowIRMTransport | ArcherTransport:
    """Build one strict vendor transport without resolving its credential.

    Config lives in ``[grc_outbound_sync.servicenow_irm]`` or
    ``[grc_outbound_sync.archer]``.  Known deployment environment variables
    are fallbacks for the base URL and the non-secret credential reference.
    Unknown nested keys are rejected so a typo cannot silently weaken a limit
    or smuggle an alternate path/header into the transport.
    """

    if not isinstance(target, GRCSystem):
        raise GRCVendorConfigError("vendor_target_invalid")
    if config is None:
        try:
            from .config import config_source_errors, load_config

            if config_source_errors():
                raise GRCVendorConfigError("vendor_config_unreadable")
            config = load_config()
        except GRCTransportFailure:
            raise
        except Exception:
            raise GRCVendorConfigError("vendor_config_unavailable") from None
    if not isinstance(config, Mapping):
        raise GRCVendorConfigError("vendor_config_invalid")
    root = config.get("grc_outbound_sync", {})
    if not isinstance(root, Mapping):
        raise GRCVendorConfigError("vendor_config_invalid")
    section = root.get(_TRANSPORT_SECTIONS[target], {})
    if not isinstance(section, Mapping):
        raise GRCVendorConfigError("vendor_config_invalid")
    if set(section) - _TRANSPORT_CONFIG_KEYS:
        raise GRCVendorConfigError("vendor_config_unknown_key")

    environment = os.environ if environ is None else environ
    if target is GRCSystem.SERVICENOW_IRM:
        base_envs = ("SERVICENOW_INSTANCE_URL",)
        ref_envs = ("MAVERICK_GRC_SERVICENOW_SECRET_REF",)
        default_ref = "SERVICENOW_TOKEN"
    else:
        base_envs = ("ARCHER_GRC_BASE_URL", "ARCHER_BASE_URL")
        ref_envs = ("MAVERICK_GRC_ARCHER_SECRET_REF",)
        default_ref = "ARCHER_GRC_TOKEN"
    base_url = (
        section["base_url"]
        if "base_url" in section
        else _environment_value(environment, base_envs)
    )
    reference = (
        section["credential_secret_ref"]
        if "credential_secret_ref" in section
        else (_environment_value(environment, ref_envs) or default_ref)
    )
    limits = VendorTransportLimits(
        timeout_seconds=section.get("timeout_seconds", 15.0),
        max_response_bytes=section.get("max_response_bytes", 256 * 1_024),
    )
    # A key saved (sealed) on the dashboard is only a fallback: the credential
    # the server holds under the reference always wins.
    saved = section.get("credential")
    if saved is not None and (not isinstance(saved, str) or not saved.strip()):
        raise GRCVendorConfigError("credential_invalid")
    if saved:
        secret_resolver = _with_saved_credential(
            secret_resolver or _default_secret_resolver, saved,
        )
    kwargs = {
        "base_url": base_url,
        "credential_secret_ref": reference,
        "limits": limits,
        "http": http,
        "secret_resolver": secret_resolver,
    }
    if target is GRCSystem.SERVICENOW_IRM:
        return ServiceNowIRMTransport(**kwargs)
    return ArcherTransport(**kwargs)


__all__ = [
    "ARCHER_APPLICATION_ALIAS",
    "ARCHER_REQUIRED_FIELDS",
    "ArcherTransport",
    "GRCVendorConfigError",
    "GRCVendorProtocolError",
    "SERVICENOW_REQUIRED_FIELDS",
    "ServiceNowIRMTransport",
    "VendorHTTPClient",
    "VendorHTTPResponse",
    "VendorTransportLimits",
    "transport_from_config",
]
