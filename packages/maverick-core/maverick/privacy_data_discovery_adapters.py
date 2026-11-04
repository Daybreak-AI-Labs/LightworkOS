"""Stock, bounded provider adapters for privacy data discovery.

The discovery authority deliberately owns no provider credentials or network
client.  This module supplies a production transport and six closed readers:

* AWS S3 object content;
* Azure Blob object content;
* Google Cloud Storage object content;
* Snowflake ``information_schema.columns`` metadata;
* ServiceNow CMDB configuration-item metadata; and
* Microsoft Entra device/application/service-principal metadata.

Every reader is constrained to the exact HTTPS origin enrolled in
``EnrolledSource`` and to fixed provider paths and query keys.  The production
transport resolves the *named* credential only for the duration of a request,
checks the enterprise egress policy, pins DNS through ``safe_client``, refuses
redirects, bounds response bytes and retries only read-only requests (or the
same Snowflake request id).  Provider response bodies are transient and never
appear in exceptions, descriptors, registry state or reprs.

These adapters prove local contract behavior, not estate completeness, legal
compliance, live-provider acceptance, credential correctness, or scale.
"""

from __future__ import annotations

import base64
import email.utils
import hashlib
import hmac
import json
import math
import os
import re
import time
import uuid
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Protocol
from urllib.parse import parse_qs, quote, unquote, urlsplit

from .privacy_data_discovery import (
    EnrolledSource,
    PrivacyDataDiscoveryAdapterError,
    ScanLimits,
    StructuredRecord,
    UnstructuredDocument,
)

AWS_S3 = "aws_s3"
AZURE_BLOB = "azure_blob"
GOOGLE_CLOUD_STORAGE = "google_cloud_storage"
SNOWFLAKE_METADATA = "snowflake_metadata"
SERVICENOW_CMDB = "servicenow_cmdb"
ENTRA_ASSETS = "entra_assets"

STOCK_PROVIDERS = frozenset(
    {
        AWS_S3,
        AZURE_BLOB,
        GOOGLE_CLOUD_STORAGE,
        SNOWFLAKE_METADATA,
        SERVICENOW_CMDB,
        ENTRA_ASSETS,
    }
)
STOCK_STRUCTURED_PROVIDERS = frozenset(
    {SNOWFLAKE_METADATA, SERVICENOW_CMDB, ENTRA_ASSETS}
)
STOCK_UNSTRUCTURED_PROVIDERS = frozenset(
    {AWS_S3, AZURE_BLOB, GOOGLE_CLOUD_STORAGE}
)

_ENV_RE = re.compile(r"[A-Z][A-Z0-9_]{1,127}\Z")
_HOST_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
    r"[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
    r"[A-Za-z0-9])?\Z"
)
_HEADER_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_OBJECT_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_BUCKET_RE = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\Z")
_CONTAINER_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?\Z")
_SNOWFLAKE_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_$]{0,254}\Z")
_SNOWFLAKE_HANDLE_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\Z"
)
_AWS_ACCESS_KEY_RE = re.compile(r"[A-Z0-9]{16,128}\Z")
_AWS_REGION_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
_MAX_SECRET_BYTES = 32 * 1024
_MAX_JSON_DEPTH = 32
_MAX_OBJECT_NAME_BYTES = 4 * 1024
_MAX_PROVIDER_FIELDS = 64
_TEXT_MEDIA_TYPES = frozenset(
    {
        "application/json",
        "application/ld+json",
        "application/xml",
        "text/csv",
        "text/html",
        "text/plain",
        "text/xml",
    }
)


class DiscoveryAdapterConfigError(PrivacyDataDiscoveryAdapterError):
    """Stock adapter configuration is absent or outside its closed contract."""


class DiscoveryAdapterProtocolError(PrivacyDataDiscoveryAdapterError):
    """A provider returned a malformed, oversized or out-of-scope response."""


class DiscoveryTransportError(PrivacyDataDiscoveryAdapterError):
    """Sanitized transport failure with retry and ambiguity classification."""

    def __init__(
        self,
        code: str,
        *,
        retryable: bool,
        ambiguous: bool = False,
    ) -> None:
        self.code = _token(code, "transport error")
        self.retryable = bool(retryable)
        self.ambiguous = bool(ambiguous)
        super().__init__(self.code)


def _token(value: object, label: str) -> str:
    if not isinstance(value, str) or not _OBJECT_REF_RE.fullmatch(value):
        raise DiscoveryAdapterConfigError(f"{label} is not a bounded identifier")
    return value


def _positive_int(value: object, label: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise DiscoveryAdapterConfigError(f"{label} is outside its bound")
    return value


def _positive_float(value: object, label: str, minimum: float, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not minimum <= float(value) <= maximum
    ):
        raise DiscoveryAdapterConfigError(f"{label} is outside its bound")
    return float(value)


def _exact_origin(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 2_048:
        raise DiscoveryAdapterConfigError("provider origin must be exact HTTPS")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise DiscoveryAdapterConfigError(
            "provider origin must be exact HTTPS"
        ) from None
    host = (parsed.hostname or "").lower().rstrip(".")
    if (
        parsed.scheme != "https"
        or not _HOST_RE.fullmatch(host)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or (port is not None and port != 443)
    ):
        raise DiscoveryAdapterConfigError("provider origin must be exact HTTPS")
    return f"https://{host}"


def _credential_env(value: object) -> str:
    from .privacy_discovery_credentials import validate_reference

    try:
        return validate_reference(value)
    except ValueError as exc:
        raise DiscoveryAdapterConfigError("credential reference is invalid") from exc


def _path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or value.startswith("//")
        or len(value) > 8_192
        or "?" in value
        or "#" in value
        or "\\" in value
        or _HEADER_CONTROL_RE.search(value)
    ):
        raise DiscoveryAdapterConfigError("provider path is outside its contract")
    return value


def _query_pair(value: tuple[object, object]) -> tuple[str, str]:
    if not isinstance(value, tuple) or len(value) != 2:
        raise DiscoveryAdapterConfigError("provider query pair is invalid")
    key, item = value
    if (
        not isinstance(key, str)
        or not 1 <= len(key) <= 128
        or not isinstance(item, str)
        or len(item) > 8_192
        or _HEADER_CONTROL_RE.search(key)
        or _HEADER_CONTROL_RE.search(item)
    ):
        raise DiscoveryAdapterConfigError("provider query pair is invalid")
    return key, item


def _encoded_query(query: Sequence[tuple[str, str]]) -> str:
    return "&".join(
        f"{quote(key, safe='-_.~')}={quote(value, safe='-_.~')}"
        for key, value in sorted(query)
    )


def _url(origin: str, path: str, query: Sequence[tuple[str, str]]) -> str:
    exact = _exact_origin(origin)
    fixed_path = _path(path)
    encoded = _encoded_query(query)
    result = exact + fixed_path + (f"?{encoded}" if encoded else "")
    parsed = urlsplit(result)
    if f"{parsed.scheme}://{parsed.hostname}" != exact:
        raise DiscoveryAdapterConfigError("provider URL crossed its exact origin")
    return result


def _json_value(body: bytes) -> object:
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise DiscoveryAdapterProtocolError(
            "provider_response_not_bounded_json"
        ) from None

    def check(item: object, depth: int = 0) -> None:
        if depth > _MAX_JSON_DEPTH:
            raise DiscoveryAdapterProtocolError("provider_json_too_deep")
        if isinstance(item, Mapping):
            if len(item) > 20_000:
                raise DiscoveryAdapterProtocolError("provider_json_too_wide")
            for key, child in item.items():
                if not isinstance(key, str) or len(key) > 4_096:
                    raise DiscoveryAdapterProtocolError("provider_json_key_invalid")
                check(child, depth + 1)
        elif isinstance(item, list):
            if len(item) > 100_001:
                raise DiscoveryAdapterProtocolError("provider_json_too_wide")
            for child in item:
                check(child, depth + 1)
        elif isinstance(item, str):
            if len(item.encode("utf-8")) > 8 * 1024 * 1024:
                raise DiscoveryAdapterProtocolError("provider_json_string_too_large")
        elif isinstance(item, float) and not math.isfinite(item):
            raise DiscoveryAdapterProtocolError("provider_json_value_invalid")
        elif item is not None and not isinstance(item, (bool, int, float)):
            raise DiscoveryAdapterProtocolError("provider_json_value_invalid")

    check(value)
    return value


def _json_object(body: bytes) -> Mapping[str, Any]:
    value = _json_value(body)
    if not isinstance(value, Mapping):
        raise DiscoveryAdapterProtocolError("provider_response_not_object")
    return value


def _xml_root(body: bytes) -> ET.Element:
    if b"<!DOCTYPE" in body.upper() or b"<!ENTITY" in body.upper():
        raise DiscoveryAdapterProtocolError("provider_xml_doctype_rejected")
    try:
        return ET.fromstring(body)
    except ET.ParseError:
        raise DiscoveryAdapterProtocolError("provider_response_not_xml") from None


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_text(element: ET.Element, name: str) -> str | None:
    for child in element:
        if _local_name(child.tag) == name:
            return child.text or ""
    return None


def _body_media_type(headers: Mapping[str, str], fallback: str) -> str:
    for key, value in headers.items():
        if key.lower() == "content-type":
            media = value.split(";", 1)[0].strip().lower()
            if 1 <= len(media) <= 127 and "/" in media:
                return media
    return fallback


def _content_length(headers: Mapping[str, str]) -> int | None:
    for key, value in headers.items():
        if key.lower() != "content-length":
            continue
        try:
            result = int(value)
        except (TypeError, ValueError):
            raise DiscoveryAdapterProtocolError(
                "provider_content_length_invalid"
            ) from None
        if result < 0:
            raise DiscoveryAdapterProtocolError("provider_content_length_invalid")
        return result
    return None


def _etag(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 512
        or _HEADER_CONTROL_RE.search(value)
    ):
        raise DiscoveryAdapterProtocolError(f"{label}_etag_invalid")
    return value


def _opaque_ref(provider: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"{provider}-{digest[:48]}"


def _object_name(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise DiscoveryAdapterProtocolError("provider_object_name_invalid")
    if len(value.encode("utf-8")) > _MAX_OBJECT_NAME_BYTES or "\x00" in value:
        raise DiscoveryAdapterProtocolError("provider_object_name_invalid")
    return value


def _encoded_object_path(value: str) -> str:
    return "/".join(quote(part, safe="-_.~") for part in value.split("/"))


def _media_from_name(name: str) -> str:
    lowered = name.lower()
    for suffix, media in (
        (".json", "application/json"),
        (".jsonld", "application/ld+json"),
        (".xml", "application/xml"),
        (".csv", "text/csv"),
        (".html", "text/html"),
        (".htm", "text/html"),
        (".txt", "text/plain"),
        (".log", "text/plain"),
        (".md", "text/plain"),
    ):
        if lowered.endswith(suffix):
            return media
    return "application/octet-stream"


@dataclass(frozen=True, slots=True)
class DiscoveryAdapterLimits:
    """Finite per-request and per-pagination limits for stock adapters."""

    timeout_seconds: float = 15.0
    max_response_bytes: int = 8 * 1024 * 1024
    page_size: int = 250
    max_pages: int = 500
    max_attempts: int = 3
    max_polls: int = 8

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "timeout_seconds",
            _positive_float(self.timeout_seconds, "timeout_seconds", 0.1, 60.0),
        )
        _positive_int(
            self.max_response_bytes,
            "max_response_bytes",
            1_024,
            64 * 1024 * 1024,
        )
        _positive_int(self.page_size, "page_size", 1, 1_000)
        _positive_int(self.max_pages, "max_pages", 1, 10_000)
        _positive_int(self.max_attempts, "max_attempts", 1, 5)
        _positive_int(self.max_polls, "max_polls", 1, 100)


@dataclass(frozen=True, slots=True, repr=False)
class DiscoveryHTTPRequest:
    """Credential-reference-only request passed to the transport boundary."""

    provider: str
    origin: str
    method: str
    path: str
    query: tuple[tuple[str, str], ...]
    credential_env: str
    deadline: float
    timeout_seconds: float
    max_response_bytes: int
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes | None = field(default=None, repr=False)
    idempotency_key: str | None = None

    def __post_init__(self) -> None:
        if self.provider not in STOCK_PROVIDERS:
            raise DiscoveryAdapterConfigError("request provider is not admitted")
        object.__setattr__(self, "origin", _exact_origin(self.origin))
        if self.method not in {"GET", "HEAD", "POST"}:
            raise DiscoveryAdapterConfigError("request method is not admitted")
        object.__setattr__(self, "path", _path(self.path))
        object.__setattr__(
            self, "query", tuple(_query_pair(pair) for pair in self.query)
        )
        object.__setattr__(self, "credential_env", _credential_env(self.credential_env))
        _positive_float(self.deadline, "deadline", 0.001, 100_000_000_000.0)
        _positive_float(self.timeout_seconds, "timeout_seconds", 0.1, 60.0)
        _positive_int(
            self.max_response_bytes,
            "max_response_bytes",
            0,
            64 * 1024 * 1024,
        )
        if not isinstance(self.headers, Mapping) or len(self.headers) > 32:
            raise DiscoveryAdapterConfigError("request headers are invalid")
        for key, value in self.headers.items():
            if (
                not isinstance(key, str)
                or not isinstance(value, str)
                or not 1 <= len(key) <= 128
                or len(value) > 4_096
                or _HEADER_CONTROL_RE.search(key)
                or _HEADER_CONTROL_RE.search(value)
                or key.lower() in {"authorization", "cookie", "host"}
            ):
                raise DiscoveryAdapterConfigError("request header is invalid")
        if self.body is not None and (
            not isinstance(self.body, bytes) or len(self.body) > 256 * 1024
        ):
            raise DiscoveryAdapterConfigError("request body is invalid")
        if self.idempotency_key is not None:
            _token(self.idempotency_key, "request idempotency key")

    @property
    def url(self) -> str:
        return _url(self.origin, self.path, self.query)


@dataclass(frozen=True, slots=True, repr=False)
class DiscoveryHTTPResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            isinstance(self.status_code, bool)
            or not isinstance(self.status_code, int)
            or not 100 <= self.status_code <= 599
        ):
            raise DiscoveryAdapterProtocolError("provider_status_invalid")
        if not isinstance(self.headers, Mapping) or not isinstance(self.body, bytes):
            raise DiscoveryAdapterProtocolError("provider_response_invalid")


class DiscoveryHTTPTransport(Protocol):
    """Transport owns credential resolution and must not follow redirects."""

    def request(self, request: DiscoveryHTTPRequest) -> DiscoveryHTTPResponse: ...


CredentialResolver = Callable[[str], str | None]


def _default_credential_resolver(name: str) -> str | None:
    return os.environ.get(name)


def credential_reference_present(name: str) -> bool:
    """Check reference availability; credential values stay transport-owned."""

    if isinstance(name, str) and name.startswith("connection:"):
        from .privacy_discovery_credentials import connection_present

        return connection_present(name)
    return isinstance(name, str) and _ENV_RE.fullmatch(name) is not None and name in os.environ


def _credential(reference: str, resolver: CredentialResolver) -> str:
    try:
        value = resolver(reference)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise DiscoveryTransportError(
            "credential_resolution_failed", retryable=False
        ) from None
    if not isinstance(value, str):
        raise DiscoveryTransportError("credential_unavailable", retryable=False)
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise DiscoveryTransportError("credential_invalid", retryable=False) from None
    if (
        not 1 <= len(encoded) <= _MAX_SECRET_BYTES
        or _HEADER_CONTROL_RE.search(value)
    ):
        raise DiscoveryTransportError("credential_invalid", retryable=False)
    return value


def _credential_object(value: str) -> Mapping[str, Any]:
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, RecursionError):
        raise DiscoveryTransportError("credential_invalid", retryable=False) from None
    if not isinstance(parsed, Mapping) or len(parsed) > 8:
        raise DiscoveryTransportError("credential_invalid", retryable=False)
    return parsed


def _bearer(value: str) -> str:
    token: object = value
    if value.lstrip().startswith("{"):
        parsed = _credential_object(value)
        if set(parsed) - {"bearer_token"}:
            raise DiscoveryTransportError("credential_invalid", retryable=False)
        token = parsed.get("bearer_token")
    if (
        not isinstance(token, str)
        or not 8 <= len(token) <= 16_384
        or _HEADER_CONTROL_RE.search(token)
    ):
        raise DiscoveryTransportError("credential_invalid", retryable=False)
    return "Bearer " + token


def _servicenow_authorization(value: str) -> str:
    if not value.lstrip().startswith("{"):
        return _bearer(value)
    parsed = _credential_object(value)
    if set(parsed) == {"bearer_token"}:
        return _bearer(value)
    if set(parsed) != {"username", "password"}:
        raise DiscoveryTransportError("credential_invalid", retryable=False)
    username = parsed.get("username")
    password = parsed.get("password")
    if (
        not isinstance(username, str)
        or not isinstance(password, str)
        or not 1 <= len(username) <= 512
        or not 1 <= len(password) <= 8_192
        or _HEADER_CONTROL_RE.search(username)
        or _HEADER_CONTROL_RE.search(password)
    ):
        raise DiscoveryTransportError("credential_invalid", retryable=False)
    encoded = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
    return "Basic " + encoded


def _aws_headers(
    request: DiscoveryHTTPRequest,
    secret_value: str,
    *,
    now: float,
) -> Mapping[str, str]:
    parsed = _credential_object(secret_value)
    admitted = {"access_key_id", "secret_access_key", "session_token", "region"}
    if set(parsed) - admitted or not {"access_key_id", "secret_access_key", "region"} <= set(parsed):
        raise DiscoveryTransportError("credential_invalid", retryable=False)
    access = parsed.get("access_key_id")
    secret = parsed.get("secret_access_key")
    region = parsed.get("region")
    session = parsed.get("session_token")
    if (
        not isinstance(access, str)
        or _AWS_ACCESS_KEY_RE.fullmatch(access) is None
        or not isinstance(secret, str)
        or not 16 <= len(secret) <= 256
        or _HEADER_CONTROL_RE.search(secret)
        or not isinstance(region, str)
        or _AWS_REGION_RE.fullmatch(region) is None
        or (
            session is not None
            and (
                not isinstance(session, str)
                or not 8 <= len(session) <= 16_384
                or _HEADER_CONTROL_RE.search(session)
            )
        )
    ):
        raise DiscoveryTransportError("credential_invalid", retryable=False)
    try:
        moment = time.gmtime(now)
        amz_date = time.strftime("%Y%m%dT%H%M%SZ", moment)
        date_stamp = time.strftime("%Y%m%d", moment)
    except (OverflowError, OSError, ValueError):
        raise DiscoveryTransportError("transport_clock_invalid", retryable=False) from None
    parsed_url = urlsplit(request.url)
    host = parsed_url.hostname or ""
    payload_hash = hashlib.sha256(request.body or b"").hexdigest()
    signed = {
        "host": host,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_date,
    }
    if session is not None:
        signed["x-amz-security-token"] = session
    signed_names = ";".join(sorted(signed))
    canonical_headers = "".join(
        f"{key}:{' '.join(signed[key].strip().split())}\n" for key in sorted(signed)
    )
    canonical_request = "\n".join(
        (
            request.method,
            parsed_url.path or "/",
            parsed_url.query,
            canonical_headers,
            signed_names,
            payload_hash,
        )
    )
    scope = f"{date_stamp}/{region}/s3/aws4_request"
    string_to_sign = "\n".join(
        (
            "AWS4-HMAC-SHA256",
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        )
    )

    def sign(key: bytes, message: str) -> bytes:
        return hmac.new(key, message.encode(), hashlib.sha256).digest()

    date_key = sign(("AWS4" + secret).encode(), date_stamp)
    region_key = sign(date_key, region)
    service_key = sign(region_key, "s3")
    signing_key = sign(service_key, "aws4_request")
    signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    return {
        **{key.title(): value for key, value in signed.items()},
        "Authorization": (
            f"AWS4-HMAC-SHA256 Credential={access}/{scope}, "
            f"SignedHeaders={signed_names}, Signature={signature}"
        ),
    }


class PinnedDiscoveryHTTPTransport:
    """Production DNS-pinned, redirect-free, bounded credential owner."""

    def __init__(
        self,
        *,
        credential_resolver: CredentialResolver | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._resolver = credential_resolver or _default_credential_resolver
        self._clock = clock
        if not callable(self._resolver) or not callable(self._clock):
            raise DiscoveryAdapterConfigError("transport authority is invalid")

    def __repr__(self) -> str:
        return "PinnedDiscoveryHTTPTransport(credential_owner='ephemeral')"

    def _headers(self, request: DiscoveryHTTPRequest) -> dict[str, str]:
        if request.credential_env.startswith("connection:"):
            from .privacy_discovery_credentials import resolve_connection

            def resolver(reference):
                return resolve_connection(reference, provider=request.provider, origin=request.origin)["token"]
        else:
            resolver = self._resolver
        secret = _credential(request.credential_env, resolver)
        if request.provider == AWS_S3:
            try:
                now = float(self._clock())
            except (TypeError, ValueError, OverflowError):
                raise DiscoveryTransportError(
                    "transport_clock_invalid", retryable=False
                ) from None
            if not math.isfinite(now) or now <= 0:
                raise DiscoveryTransportError(
                    "transport_clock_invalid", retryable=False
                )
            authorization = dict(_aws_headers(request, secret, now=now))
        elif request.provider == SERVICENOW_CMDB:
            authorization = {"Authorization": _servicenow_authorization(secret)}
        else:
            authorization = {"Authorization": _bearer(secret)}
        if request.provider == AZURE_BLOB:
            try:
                now = float(self._clock())
                if not math.isfinite(now) or now <= 0:
                    raise ValueError
                authorization["x-ms-date"] = email.utils.formatdate(
                    now,
                    usegmt=True,
                )
            except (TypeError, ValueError, OverflowError, OSError):
                raise DiscoveryTransportError(
                    "transport_clock_invalid",
                    retryable=False,
                ) from None
        return {
            "Accept": "application/json, application/xml, text/*",
            "User-Agent": "Lightwork-Privacy-Discovery/1",
            **dict(request.headers),
            **authorization,
        }

    def request(self, request: DiscoveryHTTPRequest) -> DiscoveryHTTPResponse:
        if not isinstance(request, DiscoveryHTTPRequest):
            raise DiscoveryAdapterConfigError("transport request is invalid")
        try:
            now = float(self._clock())
        except (TypeError, ValueError, OverflowError):
            raise DiscoveryTransportError(
                "transport_clock_invalid",
                retryable=False,
            ) from None
        remaining = request.deadline - now
        if not math.isfinite(remaining) or remaining <= 0:
            raise DiscoveryTransportError("provider_deadline_exhausted", retryable=False)
        timeout = min(request.timeout_seconds, remaining)
        url = request.url
        headers = self._headers(request)
        try:
            from .enterprise import enterprise_egress_denial
            from .tools._ssrf import BlockedHost, safe_client

            denial = enterprise_egress_denial(
                url,
                tool=f"privacy_data_discovery.{request.provider}",
            )
            if denial:
                raise DiscoveryTransportError(
                    "enterprise_egress_denied", retryable=False
                )
            with safe_client(url, timeout=timeout) as client:
                with client.stream(
                    request.method,
                    url,
                    headers=headers,
                    content=request.body,
                    follow_redirects=False,
                ) as response:
                    if 300 <= response.status_code < 400:
                        raise DiscoveryTransportError(
                            "provider_redirect_rejected", retryable=False
                        )
                    declared = response.headers.get("content-length")
                    if declared is not None:
                        try:
                            declared_size = int(declared)
                        except ValueError:
                            raise DiscoveryAdapterProtocolError(
                                "provider_content_length_invalid"
                            ) from None
                        if declared_size < 0 or (
                            request.method != "HEAD"
                            and declared_size > request.max_response_bytes
                        ):
                            raise DiscoveryAdapterProtocolError(
                                "provider_response_too_large"
                            )
                    chunks: list[bytes] = []
                    observed = 0
                    if request.method != "HEAD":
                        for chunk in response.iter_bytes():
                            observed += len(chunk)
                            if observed > request.max_response_bytes:
                                raise DiscoveryAdapterProtocolError(
                                    "provider_response_too_large"
                                )
                            chunks.append(chunk)
                    kept_headers = {
                        key.lower(): value
                        for key, value in response.headers.items()
                        if key.lower()
                        in {
                            "content-length",
                            "content-type",
                            "etag",
                            "retry-after",
                            "x-total-count",
                        }
                    }
                    return DiscoveryHTTPResponse(
                        int(response.status_code),
                        kept_headers,
                        b"".join(chunks),
                    )
        except (KeyboardInterrupt, SystemExit):
            raise
        except (DiscoveryTransportError, DiscoveryAdapterProtocolError):
            raise
        except BlockedHost:
            raise DiscoveryTransportError("provider_ssrf_blocked", retryable=False) from None
        except Exception as exc:
            try:
                import httpx

                timeout_error = isinstance(exc, httpx.TimeoutException)
                network_error = isinstance(exc, httpx.TransportError)
            except Exception:
                timeout_error = "timeout" in type(exc).__name__.lower()
                network_error = timeout_error
            code = "provider_timeout" if timeout_error else "provider_transport_failure"
            raise DiscoveryTransportError(
                code,
                retryable=bool(network_error),
                ambiguous=request.method == "POST",
            ) from None


class _AdapterBase:
    provider: str

    def __init__(
        self,
        *,
        transport: DiscoveryHTTPTransport | None = None,
        limits: DiscoveryAdapterLimits | None = None,
        clock: Callable[[], float] = time.time,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self._transport = transport or PinnedDiscoveryHTTPTransport(clock=clock)
        self._limits = limits or DiscoveryAdapterLimits()
        self._clock = clock
        self._sleeper = sleeper
        if not callable(getattr(self._transport, "request", None)):
            raise DiscoveryAdapterConfigError("provider transport is invalid")
        if not isinstance(self._limits, DiscoveryAdapterLimits):
            raise DiscoveryAdapterConfigError("provider limits are invalid")
        if not callable(clock) or not callable(sleeper):
            raise DiscoveryAdapterConfigError("provider timing authority is invalid")

    def __repr__(self) -> str:
        return f"{type(self).__name__}(provider={self.provider!r}, limits={self._limits!r})"

    def _source(self, source: EnrolledSource, credential_env: str, kind: str) -> None:
        if not isinstance(source, EnrolledSource):
            raise DiscoveryAdapterConfigError("enrolled source contract is invalid")
        if (
            source.provider != self.provider
            or source.kind != kind
            or source.state != "active"
            or source.credential_env != credential_env
        ):
            raise DiscoveryAdapterConfigError("enrolled source binding is invalid")
        _exact_origin(source.origin)
        _credential_env(credential_env)

    def _remaining(self, deadline: float) -> float:
        try:
            remaining = deadline - float(self._clock())
        except (TypeError, ValueError, OverflowError):
            raise DiscoveryTransportError(
                "transport_clock_invalid",
                retryable=False,
            ) from None
        if not math.isfinite(remaining) or remaining <= 0:
            raise DiscoveryTransportError(
                "provider_deadline_exhausted",
                retryable=False,
            )
        return remaining

    def _request(
        self,
        source: EnrolledSource,
        *,
        method: str,
        path: str,
        query: Sequence[tuple[str, str]] = (),
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        deadline: float,
        max_response_bytes: int | None = None,
        idempotency_key: str | None = None,
    ) -> DiscoveryHTTPResponse:
        request = DiscoveryHTTPRequest(
            provider=self.provider,
            origin=source.origin,
            method=method,
            path=path,
            query=tuple(query),
            credential_env=source.credential_env,
            deadline=deadline,
            timeout_seconds=self._limits.timeout_seconds,
            max_response_bytes=(
                self._limits.max_response_bytes
                if max_response_bytes is None
                else min(max_response_bytes, self._limits.max_response_bytes)
            ),
            headers=headers or {},
            body=body,
            idempotency_key=idempotency_key,
        )
        last_error: DiscoveryTransportError | None = None
        for attempt in range(1, self._limits.max_attempts + 1):
            self._remaining(deadline)
            try:
                response = self._transport.request(request)
            except DiscoveryTransportError as exc:
                last_error = exc
                if not exc.retryable or attempt >= self._limits.max_attempts:
                    raise
            else:
                status = response.status_code
                if 200 <= status < 300:
                    if (
                        request.method != "HEAD"
                        and len(response.body) > request.max_response_bytes
                    ):
                        raise DiscoveryAdapterProtocolError(
                            "provider_response_too_large"
                        )
                    return response
                if 300 <= status < 400:
                    raise DiscoveryTransportError(
                        "provider_redirect_rejected", retryable=False
                    )
                retryable = status in {408, 425, 429, 500, 502, 503, 504}
                if not retryable:
                    code = (
                        "provider_authentication_rejected"
                        if status in {401, 403}
                        else "provider_request_rejected"
                    )
                    raise DiscoveryTransportError(code, retryable=False)
                last_error = DiscoveryTransportError(
                    "provider_temporarily_unavailable",
                    retryable=True,
                    ambiguous=method == "POST",
                )
                if attempt >= self._limits.max_attempts:
                    raise last_error
            remaining = self._remaining(deadline)
            delay = min(0.25 * (2 ** (attempt - 1)), 2.0, max(0.0, remaining))
            self._sleeper(delay)
        if last_error is not None:  # pragma: no cover - loop always returns/raises
            raise last_error
        raise DiscoveryTransportError("provider_transport_failure", retryable=False)

    def _body_bound(self, limits: ScanLimits) -> int:
        return min(
            self._limits.max_response_bytes,
            limits.max_document_bytes,
            limits.max_bytes,
        )


class AwsS3DiscoveryAdapter(_AdapterBase):
    provider = AWS_S3

    def iter_documents(
        self,
        *,
        source: EnrolledSource,
        credential_env: str,
        limits: ScanLimits,
        deadline: float,
    ) -> Iterator[UnstructuredDocument]:
        self._source(source, credential_env, "unstructured")
        scan = limits.validated()
        bucket = source.resource_ref
        if _BUCKET_RE.fullmatch(bucket) is None:
            raise DiscoveryAdapterConfigError("S3 resource_ref must be one bucket")
        token: str | None = None
        yielded = 0
        for _page in range(self._limits.max_pages):
            remaining = max(1, min(self._limits.page_size, scan.max_files + 1 - yielded))
            query = [
                ("encoding-type", "url"),
                ("list-type", "2"),
                ("max-keys", str(remaining)),
            ]
            if token is not None:
                query.append(("continuation-token", token))
            response = self._request(
                source,
                method="GET",
                path=f"/{quote(bucket, safe='-_.~')}",
                query=query,
                headers={"Accept": "application/xml"},
                deadline=deadline,
            )
            root = _xml_root(response.body)
            contents = [item for item in root.iter() if _local_name(item.tag) == "Contents"]
            for item in contents:
                encoded_name = _child_text(item, "Key")
                size_text = _child_text(item, "Size")
                etag_text = _child_text(item, "ETag")
                if encoded_name is None or size_text is None or etag_text is None:
                    raise DiscoveryAdapterProtocolError("s3_list_contract_invalid")
                name = _object_name(unquote(encoded_name))
                etag = _etag(etag_text, "s3")
                try:
                    size = int(size_text)
                except ValueError:
                    raise DiscoveryAdapterProtocolError("s3_size_invalid") from None
                if size < 0:
                    raise DiscoveryAdapterProtocolError("s3_size_invalid")
                ref = _opaque_ref("s3", name)
                if yielded >= scan.max_files:
                    yield UnstructuredDocument(ref, "application/octet-stream", b"")
                    return
                yielded += 1
                inferred = _media_from_name(name)
                if size > scan.max_document_bytes or size > scan.max_bytes:
                    yield UnstructuredDocument(
                        ref,
                        "application/x-lightwork-object-too-large",
                        b"",
                    )
                    continue
                object_path = (
                    f"/{quote(bucket, safe='-_.~')}/{_encoded_object_path(name)}"
                )
                head = self._request(
                    source,
                    method="HEAD",
                    path=object_path,
                    headers={"If-Match": etag},
                    deadline=deadline,
                    max_response_bytes=0,
                )
                media = _body_media_type(head.headers, inferred)
                declared = _content_length(head.headers)
                if declared is not None and declared != size:
                    raise DiscoveryAdapterProtocolError("s3_object_size_drift")
                if media not in _TEXT_MEDIA_TYPES:
                    yield UnstructuredDocument(ref, media, b"")
                    continue
                body = self._request(
                    source,
                    method="GET",
                    path=object_path,
                    headers={"If-Match": etag},
                    deadline=deadline,
                    max_response_bytes=self._body_bound(scan),
                )
                yield UnstructuredDocument(
                    ref,
                    _body_media_type(body.headers, media),
                    body.body,
                )
            truncated = (_child_text(root, "IsTruncated") or "").lower() == "true"
            next_token = _child_text(root, "NextContinuationToken")
            if not truncated:
                return
            if not next_token or len(next_token) > 8_192:
                raise DiscoveryAdapterProtocolError("s3_continuation_invalid")
            token = next_token
        raise DiscoveryAdapterProtocolError("provider_pagination_bound_exhausted")


class AzureBlobDiscoveryAdapter(_AdapterBase):
    provider = AZURE_BLOB

    def iter_documents(
        self,
        *,
        source: EnrolledSource,
        credential_env: str,
        limits: ScanLimits,
        deadline: float,
    ) -> Iterator[UnstructuredDocument]:
        self._source(source, credential_env, "unstructured")
        scan = limits.validated()
        container = source.resource_ref
        if _CONTAINER_RE.fullmatch(container) is None or not 3 <= len(container) <= 63:
            raise DiscoveryAdapterConfigError(
                "Azure resource_ref must be one container"
            )
        marker: str | None = None
        yielded = 0
        for _page in range(self._limits.max_pages):
            remaining = max(1, min(self._limits.page_size, scan.max_files + 1 - yielded))
            query = [
                ("comp", "list"),
                ("maxresults", str(remaining)),
                ("restype", "container"),
            ]
            if marker is not None:
                query.append(("marker", marker))
            response = self._request(
                source,
                method="GET",
                path=f"/{quote(container, safe='-_.~')}",
                query=query,
                headers={"x-ms-version": "2023-11-03"},
                deadline=deadline,
            )
            root = _xml_root(response.body)
            blobs = [item for item in root.iter() if _local_name(item.tag) == "Blob"]
            for blob in blobs:
                name = _object_name(_child_text(blob, "Name"))
                properties = next(
                    (child for child in blob if _local_name(child.tag) == "Properties"),
                    None,
                )
                if properties is None:
                    raise DiscoveryAdapterProtocolError("azure_blob_contract_invalid")
                size_text = _child_text(properties, "Content-Length")
                media = _child_text(properties, "Content-Type") or _media_from_name(name)
                etag = _etag(_child_text(properties, "Etag"), "azure_blob")
                try:
                    size = int(size_text or "")
                except ValueError:
                    raise DiscoveryAdapterProtocolError("azure_blob_size_invalid") from None
                if size < 0:
                    raise DiscoveryAdapterProtocolError("azure_blob_size_invalid")
                ref = _opaque_ref("azblob", name)
                if yielded >= scan.max_files:
                    yield UnstructuredDocument(ref, "application/octet-stream", b"")
                    return
                yielded += 1
                normalized_media = media.split(";", 1)[0].strip().lower()
                if (
                    size > scan.max_document_bytes
                    or size > scan.max_bytes
                    or normalized_media not in _TEXT_MEDIA_TYPES
                ):
                    yield UnstructuredDocument(
                        ref,
                        (
                            "application/x-lightwork-object-too-large"
                            if size > scan.max_document_bytes or size > scan.max_bytes
                            else normalized_media
                        ),
                        b"",
                    )
                    continue
                body = self._request(
                    source,
                    method="GET",
                    path=(
                        f"/{quote(container, safe='-_.~')}/"
                        f"{_encoded_object_path(name)}"
                    ),
                    headers={
                        "If-Match": etag,
                        "x-ms-version": "2023-11-03",
                    },
                    deadline=deadline,
                    max_response_bytes=self._body_bound(scan),
                )
                yield UnstructuredDocument(
                    ref,
                    _body_media_type(body.headers, normalized_media),
                    body.body,
                )
            next_marker = next(
                (
                    item.text or ""
                    for item in root.iter()
                    if _local_name(item.tag) == "NextMarker"
                ),
                "",
            )
            if not next_marker:
                return
            if len(next_marker) > 8_192:
                raise DiscoveryAdapterProtocolError("azure_marker_invalid")
            marker = next_marker
        raise DiscoveryAdapterProtocolError("provider_pagination_bound_exhausted")


class GoogleCloudStorageDiscoveryAdapter(_AdapterBase):
    provider = GOOGLE_CLOUD_STORAGE

    def iter_documents(
        self,
        *,
        source: EnrolledSource,
        credential_env: str,
        limits: ScanLimits,
        deadline: float,
    ) -> Iterator[UnstructuredDocument]:
        self._source(source, credential_env, "unstructured")
        scan = limits.validated()
        bucket = source.resource_ref
        if (
            bucket != bucket.lower()
            or _BUCKET_RE.fullmatch(bucket) is None
            or len(bucket) > 63
        ):
            raise DiscoveryAdapterConfigError("GCS resource_ref must be one bucket")
        token: str | None = None
        yielded = 0
        bucket_path = quote(bucket, safe="-_.~")
        for _page in range(self._limits.max_pages):
            remaining = max(1, min(self._limits.page_size, scan.max_files + 1 - yielded))
            query = [
                (
                    "fields",
                    "items(name,size,contentType,generation),nextPageToken",
                ),
                ("maxResults", str(remaining)),
            ]
            if token is not None:
                query.append(("pageToken", token))
            response = self._request(
                source,
                method="GET",
                path=f"/storage/v1/b/{bucket_path}/o",
                query=query,
                deadline=deadline,
            )
            payload = _json_object(response.body)
            items = payload.get("items", [])
            if not isinstance(items, list):
                raise DiscoveryAdapterProtocolError("gcs_items_invalid")
            for item in items:
                if not isinstance(item, Mapping):
                    raise DiscoveryAdapterProtocolError("gcs_item_invalid")
                name = _object_name(item.get("name"))
                try:
                    size = int(item.get("size"))
                except (TypeError, ValueError):
                    raise DiscoveryAdapterProtocolError("gcs_size_invalid") from None
                if size < 0:
                    raise DiscoveryAdapterProtocolError("gcs_size_invalid")
                media_value = item.get("contentType")
                generation = item.get("generation")
                if (
                    not isinstance(generation, str)
                    or not generation.isdigit()
                    or not 1 <= len(generation) <= 32
                ):
                    raise DiscoveryAdapterProtocolError("gcs_generation_invalid")
                media = (
                    media_value.split(";", 1)[0].strip().lower()
                    if isinstance(media_value, str)
                    else _media_from_name(name)
                )
                ref = _opaque_ref("gcs", name)
                if yielded >= scan.max_files:
                    yield UnstructuredDocument(ref, "application/octet-stream", b"")
                    return
                yielded += 1
                if (
                    size > scan.max_document_bytes
                    or size > scan.max_bytes
                    or media not in _TEXT_MEDIA_TYPES
                ):
                    yield UnstructuredDocument(
                        ref,
                        (
                            "application/x-lightwork-object-too-large"
                            if size > scan.max_document_bytes or size > scan.max_bytes
                            else media
                        ),
                        b"",
                    )
                    continue
                body = self._request(
                    source,
                    method="GET",
                    path=(
                        f"/download/storage/v1/b/{bucket_path}/o/"
                        f"{quote(name, safe='-_.~')}"
                    ),
                    query=(("alt", "media"), ("ifGenerationMatch", generation)),
                    deadline=deadline,
                    max_response_bytes=self._body_bound(scan),
                )
                yield UnstructuredDocument(
                    ref,
                    _body_media_type(body.headers, media),
                    body.body,
                )
            next_token = payload.get("nextPageToken")
            if next_token is None:
                return
            if not isinstance(next_token, str) or not 1 <= len(next_token) <= 8_192:
                raise DiscoveryAdapterProtocolError("gcs_page_token_invalid")
            token = next_token
        raise DiscoveryAdapterProtocolError("provider_pagination_bound_exhausted")


_CMDB_TABLES = frozenset(
    {
        "cmdb_ci",
        "cmdb_ci_appl",
        "cmdb_ci_cloud_service_account",
        "cmdb_ci_computer",
        "cmdb_ci_database",
        "cmdb_ci_server",
    }
)
_CMDB_FIELDS = (
    "sys_id",
    "name",
    "sys_class_name",
    "asset_tag",
    "serial_number",
    "ip_address",
    "owned_by",
    "assigned_to",
    "location",
    "company",
    "manufacturer",
    "model_id",
    "operational_status",
    "install_status",
)


class ServiceNowCmdbDiscoveryAdapter(_AdapterBase):
    provider = SERVICENOW_CMDB

    def iter_rows(
        self,
        *,
        source: EnrolledSource,
        credential_env: str,
        limits: ScanLimits,
        deadline: float,
    ) -> Iterator[StructuredRecord]:
        self._source(source, credential_env, "structured")
        scan = limits.validated()
        table = source.resource_ref
        if table not in _CMDB_TABLES:
            raise DiscoveryAdapterConfigError("ServiceNow CMDB table is not admitted")
        yielded = 0
        offset = 0
        for _page in range(self._limits.max_pages):
            page_size = max(
                1,
                min(self._limits.page_size, scan.max_records + 1 - yielded),
            )
            response = self._request(
                source,
                method="GET",
                path=f"/api/now/table/{table}",
                query=(
                    ("sysparm_display_value", "false"),
                    ("sysparm_exclude_reference_link", "true"),
                    ("sysparm_fields", ",".join(_CMDB_FIELDS)),
                    ("sysparm_limit", str(page_size)),
                    ("sysparm_offset", str(offset)),
                    ("sysparm_query", "ORDERBYsys_id"),
                ),
                deadline=deadline,
            )
            payload = _json_object(response.body)
            rows = payload.get("result")
            if not isinstance(rows, list):
                raise DiscoveryAdapterProtocolError("servicenow_result_invalid")
            for row in rows:
                if not isinstance(row, Mapping) or len(row) > _MAX_PROVIDER_FIELDS:
                    raise DiscoveryAdapterProtocolError("servicenow_row_invalid")
                sys_id = row.get("sys_id")
                identity = (
                    sys_id
                    if isinstance(sys_id, str) and 1 <= len(sys_id) <= 256
                    else json.dumps(row, sort_keys=True, default=str)[:8_192]
                )
                ref = _opaque_ref("sncmdb", identity)
                fields = {
                    field_name: row.get(field_name)
                    for field_name in _CMDB_FIELDS
                    if field_name != "sys_id" and field_name in row
                }
                yield StructuredRecord(ref, fields)
                yielded += 1
                if yielded > scan.max_records:
                    return
            if len(rows) < page_size:
                return
            offset += len(rows)
        raise DiscoveryAdapterProtocolError("provider_pagination_bound_exhausted")


_ENTRA_RESOURCES: Mapping[str, tuple[str, tuple[str, ...]]] = MappingProxyType(
    {
        "applications": (
            "/v1.0/applications",
            (
                "id",
                "appId",
                "displayName",
                "publisherDomain",
                "signInAudience",
                "createdDateTime",
                "disabledByMicrosoftStatus",
            ),
        ),
        "devices": (
            "/v1.0/devices",
            (
                "id",
                "deviceId",
                "displayName",
                "accountEnabled",
                "operatingSystem",
                "operatingSystemVersion",
                "approximateLastSignInDateTime",
                "registrationDateTime",
                "trustType",
            ),
        ),
        "service_principals": (
            "/v1.0/servicePrincipals",
            (
                "id",
                "appId",
                "displayName",
                "accountEnabled",
                "servicePrincipalType",
                "appOwnerOrganizationId",
                "publisherName",
                "preferredSingleSignOnMode",
            ),
        ),
    }
)


def _entra_skip_token(
    value: object,
    *,
    origin: str,
    path: str,
    selected_fields: str,
) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 16_384:
        raise DiscoveryAdapterProtocolError("entra_next_link_invalid")
    parsed = urlsplit(value)
    expected = urlsplit(_exact_origin(origin))
    if (
        parsed.scheme != "https"
        or parsed.hostname != expected.hostname
        or parsed.port not in (None, 443)
        or parsed.path != path
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise DiscoveryAdapterProtocolError("entra_next_link_crossed_authority")
    query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    if set(query) - {"$select", "$top", "$skiptoken"}:
        raise DiscoveryAdapterProtocolError("entra_next_link_query_invalid")
    if query.get("$select", [selected_fields]) != [selected_fields]:
        raise DiscoveryAdapterProtocolError("entra_next_link_selection_drift")
    tokens = query.get("$skiptoken")
    if not tokens or len(tokens) != 1 or not 1 <= len(tokens[0]) <= 8_192:
        raise DiscoveryAdapterProtocolError("entra_skip_token_invalid")
    return tokens[0]


class EntraAssetDiscoveryAdapter(_AdapterBase):
    provider = ENTRA_ASSETS

    def iter_rows(
        self,
        *,
        source: EnrolledSource,
        credential_env: str,
        limits: ScanLimits,
        deadline: float,
    ) -> Iterator[StructuredRecord]:
        self._source(source, credential_env, "structured")
        scan = limits.validated()
        resource = _ENTRA_RESOURCES.get(source.resource_ref)
        if resource is None:
            raise DiscoveryAdapterConfigError("Entra asset resource is not admitted")
        path, fields = resource
        selected = ",".join(fields)
        skip_token: str | None = None
        yielded = 0
        for _page in range(self._limits.max_pages):
            page_size = max(
                1,
                min(self._limits.page_size, scan.max_records + 1 - yielded),
            )
            query = [("$select", selected), ("$top", str(page_size))]
            if skip_token is not None:
                query.append(("$skiptoken", skip_token))
            response = self._request(
                source,
                method="GET",
                path=path,
                query=query,
                deadline=deadline,
            )
            payload = _json_object(response.body)
            rows = payload.get("value")
            if not isinstance(rows, list):
                raise DiscoveryAdapterProtocolError("entra_result_invalid")
            for row in rows:
                if not isinstance(row, Mapping) or len(row) > _MAX_PROVIDER_FIELDS:
                    raise DiscoveryAdapterProtocolError("entra_row_invalid")
                item_id = row.get("id")
                if not isinstance(item_id, str) or not 1 <= len(item_id) <= 512:
                    raise DiscoveryAdapterProtocolError("entra_asset_id_invalid")
                yield StructuredRecord(
                    _opaque_ref("entra", item_id),
                    {
                        name: row.get(name)
                        for name in fields
                        if name != "id" and name in row
                    },
                )
                yielded += 1
                if yielded > scan.max_records:
                    return
            skip_token = _entra_skip_token(
                payload.get("@odata.nextLink"),
                origin=source.origin,
                path=path,
                selected_fields=selected,
            )
            if skip_token is None:
                return
        raise DiscoveryAdapterProtocolError("provider_pagination_bound_exhausted")


def _snowflake_ref(value: object) -> tuple[str, str, str]:
    if not isinstance(value, str):
        raise DiscoveryAdapterConfigError("Snowflake resource_ref is invalid")
    parts = value.split(":")
    if len(parts) != 3 or any(_SNOWFLAKE_IDENTIFIER_RE.fullmatch(part) is None for part in parts):
        raise DiscoveryAdapterConfigError(
            "Snowflake resource_ref must be warehouse:database:schema"
        )
    return parts[0], parts[1], parts[2]


def _quoted_snowflake_identifier(value: str) -> str:
    if _SNOWFLAKE_IDENTIFIER_RE.fullmatch(value) is None:
        raise DiscoveryAdapterConfigError("Snowflake identifier is invalid")
    return '"' + value.replace('"', '""') + '"'


def _snowflake_rows(payload: Mapping[str, Any]) -> list[object]:
    data = payload.get("data", [])
    if data is None:
        return []
    if not isinstance(data, list):
        raise DiscoveryAdapterProtocolError("snowflake_result_invalid")
    return data


class SnowflakeMetadataDiscoveryAdapter(_AdapterBase):
    provider = SNOWFLAKE_METADATA

    def _complete_statement(
        self,
        source: EnrolledSource,
        response: DiscoveryHTTPResponse,
        *,
        request_id: str,
        deadline: float,
    ) -> tuple[Mapping[str, Any], str]:
        payload = _json_object(response.body)
        handle_value = payload.get("statementHandle")
        handle = handle_value if isinstance(handle_value, str) else ""
        if response.status_code == 200:
            if handle and _SNOWFLAKE_HANDLE_RE.fullmatch(handle) is None:
                raise DiscoveryAdapterProtocolError("snowflake_handle_invalid")
            return payload, handle
        if response.status_code != 202 or _SNOWFLAKE_HANDLE_RE.fullmatch(handle) is None:
            raise DiscoveryAdapterProtocolError("snowflake_statement_response_invalid")
        for _poll in range(self._limits.max_polls):
            polled = self._request(
                source,
                method="GET",
                path=f"/api/v2/statements/{handle}",
                deadline=deadline,
                idempotency_key=request_id,
            )
            if polled.status_code == 202:
                continue
            if polled.status_code != 200:
                raise DiscoveryAdapterProtocolError("snowflake_poll_invalid")
            return _json_object(polled.body), handle
        raise DiscoveryAdapterProtocolError("snowflake_poll_bound_exhausted")

    def iter_rows(
        self,
        *,
        source: EnrolledSource,
        credential_env: str,
        limits: ScanLimits,
        deadline: float,
    ) -> Iterator[StructuredRecord]:
        self._source(source, credential_env, "structured")
        scan = limits.validated()
        warehouse, database, schema = _snowflake_ref(source.resource_ref)
        row_limit = min(scan.max_records + 1, 1_000_001)
        statement = (
            "SELECT table_catalog, table_schema, table_name, column_name, "
            "data_type, comment FROM "
            f"{_quoted_snowflake_identifier(database)}.information_schema.columns "
            f"WHERE table_schema = '{schema}' "
            "ORDER BY table_catalog, table_schema, table_name, ordinal_position "
            f"LIMIT {row_limit}"
        )
        request_id = "sfr-" + uuid.uuid4().hex
        body = json.dumps(
            {
                "database": database,
                "schema": schema,
                "statement": statement,
                "timeout": max(1, min(int(scan.max_seconds), 60)),
                "warehouse": warehouse,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        response = self._request(
            source,
            method="POST",
            path="/api/v2/statements",
            query=(
                ("async", "false"),
                ("requestId", request_id),
                ("retry", "true"),
            ),
            headers={"Content-Type": "application/json"},
            body=body,
            deadline=deadline,
            idempotency_key=request_id,
        )
        payload, handle = self._complete_statement(
            source,
            response,
            request_id=request_id,
            deadline=deadline,
        )
        pages: list[Mapping[str, Any]] = [payload]
        metadata = payload.get("resultSetMetaData")
        partition_count = 1
        if isinstance(metadata, Mapping):
            partitions = metadata.get("partitionInfo")
            if partitions is not None:
                if not isinstance(partitions, list) or len(partitions) > self._limits.max_pages:
                    raise DiscoveryAdapterProtocolError(
                        "snowflake_partition_bound_exhausted"
                    )
                partition_count = max(1, len(partitions))
        if partition_count > 1 and not handle:
            raise DiscoveryAdapterProtocolError("snowflake_partition_handle_missing")
        for partition in range(1, partition_count):
            page = self._request(
                source,
                method="GET",
                path=f"/api/v2/statements/{handle}",
                query=(("partition", str(partition)),),
                deadline=deadline,
                idempotency_key=request_id,
            )
            pages.append(_json_object(page.body))
        yielded = 0
        field_names = (
            "table_catalog",
            "table_schema",
            "table_name",
            "column_name",
            "data_type",
            "comment",
        )
        for page_payload in pages:
            for row in _snowflake_rows(page_payload):
                if not isinstance(row, list) or len(row) != len(field_names):
                    raise DiscoveryAdapterProtocolError("snowflake_row_invalid")
                identity = "\x00".join(str(item or "") for item in row[:4])
                yield StructuredRecord(
                    _opaque_ref("snowmeta", identity),
                    dict(zip(field_names, row, strict=True)),
                )
                yielded += 1
                if yielded > scan.max_records:
                    return


@dataclass(frozen=True, slots=True)
class StockAdapterDescriptor:
    provider: str
    kind: str
    resource_ref_contract: str
    network_io: bool = True
    writes_provider_data: bool = False
    raw_data_persisted: bool = False
    redirects_followed: bool = False
    dns_pinned: bool = True
    credential_value_persisted: bool = False
    estate_completeness_claimed: bool = False
    live_provider_acceptance_verified: bool = False


_DESCRIPTORS = (
    StockAdapterDescriptor(AWS_S3, "unstructured", "one_s3_bucket"),
    StockAdapterDescriptor(AZURE_BLOB, "unstructured", "one_blob_container"),
    StockAdapterDescriptor(
        GOOGLE_CLOUD_STORAGE,
        "unstructured",
        "one_gcs_bucket",
    ),
    StockAdapterDescriptor(
        SNOWFLAKE_METADATA,
        "structured",
        "warehouse:database:schema",
    ),
    StockAdapterDescriptor(
        SERVICENOW_CMDB,
        "structured",
        "one_admitted_cmdb_table",
    ),
    StockAdapterDescriptor(
        ENTRA_ASSETS,
        "structured",
        "devices|applications|service_principals",
    ),
)

_ADAPTER_CONFIG_KEYS = frozenset(
    {
        "enable",
        "enabled_providers",
        "timeout_seconds",
        "max_response_bytes",
        "page_size",
        "max_pages",
        "max_attempts",
        "max_polls",
    }
)


@dataclass(frozen=True, slots=True)
class StockDiscoveryAdapterRegistry:
    structured: Mapping[str, object]
    unstructured: Mapping[str, object]
    descriptors: tuple[StockAdapterDescriptor, ...]
    enabled: bool
    limitations: tuple[str, ...]

    def status(self) -> Mapping[str, object]:
        return {
            "schema": "lightwork.privacy-data-discovery-stock-adapters.v1",
            "enabled": self.enabled,
            "structured_providers": sorted(self.structured),
            "unstructured_providers": sorted(self.unstructured),
            "descriptors": [
                {
                    key: getattr(item, key)
                    for key in item.__dataclass_fields__
                }
                for item in self.descriptors
            ],
            "limitations": list(self.limitations),
            "credential_values_exposed": False,
            "live_provider_acceptance_verified": False,
        }


def _adapter_config(config: Mapping[str, object]) -> Mapping[str, object] | None:
    privacy = config.get("privacy_automation")
    if not isinstance(privacy, Mapping) or privacy.get("enable") is not True:
        return None
    discovery = privacy.get("data_discovery")
    if not isinstance(discovery, Mapping) or discovery.get("enable") is not True:
        return None
    adapters = discovery.get("adapters")
    if adapters is None:
        return None
    if not isinstance(adapters, Mapping):
        raise DiscoveryAdapterConfigError("stock adapters configuration is invalid")
    if set(adapters) - _ADAPTER_CONFIG_KEYS:
        raise DiscoveryAdapterConfigError(
            "stock adapters configuration contains an unknown key"
        )
    enabled = adapters.get("enable", False)
    if type(enabled) is not bool:
        raise DiscoveryAdapterConfigError("stock adapters enable must be boolean")
    if not enabled:
        return None
    return adapters


def _config_limits(config: Mapping[str, object]) -> DiscoveryAdapterLimits:
    values: dict[str, object] = {}
    for name in (
        "timeout_seconds",
        "max_response_bytes",
        "page_size",
        "max_pages",
        "max_attempts",
        "max_polls",
    ):
        if name in config:
            values[name] = config[name]
    try:
        return DiscoveryAdapterLimits(**values)  # type: ignore[arg-type]
    except TypeError:
        raise DiscoveryAdapterConfigError("adapter limits are invalid") from None


def _enabled_providers(config: Mapping[str, object]) -> frozenset[str]:
    values = config.get("enabled_providers")
    if not isinstance(values, list) or not values:
        raise DiscoveryAdapterConfigError(
            "enabled stock providers must be a non-empty list"
        )
    if (
        len(values) > len(STOCK_PROVIDERS)
        or any(not isinstance(item, str) for item in values)
        or len(set(values)) != len(values)
    ):
        raise DiscoveryAdapterConfigError("enabled stock providers are invalid")
    unknown = set(values) - STOCK_PROVIDERS
    if unknown:
        raise DiscoveryAdapterConfigError("enabled stock provider is not admitted")
    return frozenset(values)


def build_stock_discovery_adapter_registry(
    config: Mapping[str, object],
    *,
    transport: DiscoveryHTTPTransport | None = None,
    clock: Callable[[], float] = time.time,
    sleeper: Callable[[float], None] = time.sleep,
) -> StockDiscoveryAdapterRegistry:
    """Build the deployable registry from the closed config surface.

    The function returns an explicit disabled registry when any parent gate is
    off.  Once gates are on, malformed or unknown configuration fails closed.
    """

    if not isinstance(config, Mapping):
        raise DiscoveryAdapterConfigError("configuration root is invalid")
    selected_config = _adapter_config(config)
    limitations = (
        "scan_scope_is_only_each_exact_enrolled_resource",
        "provider_permissions_may_hide_assets_or_fields",
        "provider_pagination_is_not_a_transactional_snapshot",
        "object_readers_cover_only_supported_text_media",
        "snowflake_reader_classifies_metadata_not_table_values",
        "transfer_purpose_subject_and_recipient_facts_are_not_inferred",
        "provider_retention_and_deletion_are_not_controlled",
        "no_live_provider_or_estate_completeness_claim",
    )
    if selected_config is None:
        return StockDiscoveryAdapterRegistry(
            structured=MappingProxyType({}),
            unstructured=MappingProxyType({}),
            descriptors=(),
            enabled=False,
            limitations=limitations,
        )
    selected = _enabled_providers(selected_config)
    limits = _config_limits(selected_config)
    common = {
        "transport": transport,
        "limits": limits,
        "clock": clock,
        "sleeper": sleeper,
    }
    all_adapters: Mapping[str, object] = {
        AWS_S3: AwsS3DiscoveryAdapter(**common),
        AZURE_BLOB: AzureBlobDiscoveryAdapter(**common),
        GOOGLE_CLOUD_STORAGE: GoogleCloudStorageDiscoveryAdapter(**common),
        SNOWFLAKE_METADATA: SnowflakeMetadataDiscoveryAdapter(**common),
        SERVICENOW_CMDB: ServiceNowCmdbDiscoveryAdapter(**common),
        ENTRA_ASSETS: EntraAssetDiscoveryAdapter(**common),
    }
    structured = {
        provider: all_adapters[provider]
        for provider in sorted(selected & STOCK_STRUCTURED_PROVIDERS)
    }
    unstructured = {
        provider: all_adapters[provider]
        for provider in sorted(selected & STOCK_UNSTRUCTURED_PROVIDERS)
    }
    descriptors = tuple(item for item in _DESCRIPTORS if item.provider in selected)
    return StockDiscoveryAdapterRegistry(
        structured=MappingProxyType(structured),
        unstructured=MappingProxyType(unstructured),
        descriptors=descriptors,
        enabled=True,
        limitations=limitations,
    )


__all__ = [
    "AWS_S3",
    "AZURE_BLOB",
    "ENTRA_ASSETS",
    "GOOGLE_CLOUD_STORAGE",
    "SERVICENOW_CMDB",
    "SNOWFLAKE_METADATA",
    "STOCK_PROVIDERS",
    "STOCK_STRUCTURED_PROVIDERS",
    "STOCK_UNSTRUCTURED_PROVIDERS",
    "AwsS3DiscoveryAdapter",
    "AzureBlobDiscoveryAdapter",
    "DiscoveryAdapterConfigError",
    "DiscoveryAdapterLimits",
    "DiscoveryAdapterProtocolError",
    "DiscoveryHTTPRequest",
    "DiscoveryHTTPResponse",
    "DiscoveryHTTPTransport",
    "DiscoveryTransportError",
    "EntraAssetDiscoveryAdapter",
    "GoogleCloudStorageDiscoveryAdapter",
    "PinnedDiscoveryHTTPTransport",
    "ServiceNowCmdbDiscoveryAdapter",
    "SnowflakeMetadataDiscoveryAdapter",
    "StockAdapterDescriptor",
    "StockDiscoveryAdapterRegistry",
    "build_stock_discovery_adapter_registry",
    "credential_reference_present",
]
