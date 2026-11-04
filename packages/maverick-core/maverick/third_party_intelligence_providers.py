"""Closed read-only provider contracts for third-party intelligence feeds.

The adapters in this module are transport contracts, not proof of a live
provider integration.  A deployment injects a trusted GET-only transport and
an opaque credential binding.  Source metadata chooses only one of the closed
provider IDs below; it can never supply a URL, headers, method, or request
payload.  Raw provider pages and credential material are validated in memory
and are never returned in the normalized result.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlencode, urlparse

from .paths import canonical_tenant_id

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_CURSOR_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/+=-]{0,255}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_PAGE_BYTES = 512 * 1024
_MAX_TOTAL_BYTES = 4 * 1024 * 1024
_MAX_PAGES = 32
_MAX_PAGE_RECORDS = 500
_MAX_TOTAL_RECORDS = 5_000
_MAX_CITATIONS = 100
_MAX_QUERY_BYTES = 16 * 1024
_MAX_CREDENTIAL_BYTES = 16 * 1024
_HEADER_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_BEARER_TOKEN_RE = re.compile(r"[!-~]{8,16384}\Z")
_HOST_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
    r"[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\Z"
)

_PROVIDER_CONTRACTS: dict[str, tuple[str | None, str, str]] = {
    "riskrecon": (
        "api.riskrecon.com",
        "/api/v1/third-party-observations",
        "lightwork.riskrecon-observation-page.v1",
    ),
    "securityscorecard": (
        "api.securityscorecard.io",
        "/companies/observations",
        "lightwork.securityscorecard-observation-page.v1",
    ),
    "hacknotice": (
        "api.hacknotice.com",
        "/v1/vendor-observations",
        "lightwork.hacknotice-observation-page.v1",
    ),
    # These vendors advertise integrations but do not publish one canonical
    # public API authority for this normalized Lightwork contract.  A deployment
    # must therefore enroll the exact licensed gateway host rather than this
    # package guessing a vendor/customer-specific hostname.
    "supplywisdom": (
        None,
        "/v1/third-party-observations",
        "lightwork.supplywisdom-observation-page.v1",
    ),
    "iss_corporate_solutions": (
        None,
        "/v1/third-party-observations",
        "lightwork.iss-corporate-solutions-observation-page.v1",
    ),
}

_ENROLLED_HOST_PROVIDERS = frozenset(
    provider for provider, contract in _PROVIDER_CONTRACTS.items() if contract[0] is None
)


class ThirdPartyProviderError(RuntimeError):
    """Base provider-boundary error."""


class ThirdPartyProviderConfigError(ThirdPartyProviderError):
    """A trusted transport, provider, or credential binding is unavailable."""


class ThirdPartyProviderProtocolError(ThirdPartyProviderError):
    """A provider returned content outside its closed contract."""


class ThirdPartyProviderIncompleteError(ThirdPartyProviderError):
    """A provider explicitly reported incomplete coverage."""


class ThirdPartyProviderTransportError(ThirdPartyProviderError):
    """Sanitized provider I/O failure with retry and ambiguity semantics."""

    def __init__(
        self,
        code: str,
        *,
        retryable: bool,
        ambiguous: bool = False,
    ) -> None:
        self.code = _identifier(code, "provider transport error code")
        self.retryable = bool(retryable)
        self.ambiguous = bool(ambiguous)
        if self.ambiguous and not self.retryable:
            raise ThirdPartyProviderConfigError(
                "ambiguous provider transport errors must be retryable"
            )
        super().__init__(self.code)


class ThirdPartyProviderCredentialError(ThirdPartyProviderError):
    """An exact deployment credential enrollment is absent or revoked."""

    def __init__(
        self,
        code: str,
        *,
        revoked: bool = False,
        retryable: bool = False,
    ) -> None:
        self.code = _identifier(code, "provider credential error code")
        self.retryable = bool(retryable)
        self.ambiguous = False
        self.revoked = bool(revoked)
        super().__init__(self.code)


class ThirdPartyProviderTransport(Protocol):
    """Trusted GET-only transport; implementations own auth/header handling."""

    def get_json(
        self,
        *,
        host: str,
        path: str,
        query: Mapping[str, str],
        credential: object,
        maximum_response_bytes: int,  # noqa
        timeout_seconds: float,
    ) -> Mapping[str, object]: ...


@dataclass(frozen=True, slots=True)
class CredentialBinding:
    """Opaque transient credential plus the stable key authority it represents."""

    key_id: str
    secret: object = field(repr=False)

    def __post_init__(self) -> None:
        _identifier(self.key_id, "credential key_id")
        if self.secret is None:
            raise ThirdPartyProviderConfigError("credential binding has no secret")


@dataclass(frozen=True, slots=True, repr=False)
class ProviderBearerCredential:
    """Transient bearer material owned by the bundled HTTPS transport."""

    token: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.token, str):
            raise ThirdPartyProviderCredentialError("credential_invalid")
        try:
            size = len(self.token.encode("utf-8"))
        except UnicodeError:
            raise ThirdPartyProviderCredentialError("credential_invalid") from None
        if (
            not 8 <= size <= _MAX_CREDENTIAL_BYTES
            or _BEARER_TOKEN_RE.fullmatch(self.token) is None
        ):
            raise ThirdPartyProviderCredentialError("credential_invalid")

    def __repr__(self) -> str:
        return "ProviderBearerCredential(material='redacted')"


@dataclass(frozen=True, slots=True)
class ProviderCredentialEnrollment:
    """Deployment authority for one tenant/provider/source credential reference."""

    tenant_id: str
    provider: str
    source_id: str
    credential_ref: str = field(repr=False)
    key_id: str
    revision: int
    state: str = "active"

    def __post_init__(self) -> None:
        try:
            tenant = canonical_tenant_id(self.tenant_id)
        except (TypeError, ValueError) as exc:
            raise ThirdPartyProviderConfigError(
                "credential enrollment tenant is invalid"
            ) from exc
        if tenant != self.tenant_id:
            raise ThirdPartyProviderConfigError(
                "credential enrollment tenant must already be canonical"
            )
        _identifier(self.provider, "credential enrollment provider")
        _identifier(self.source_id, "credential enrollment source_id")
        _credential_reference(self.credential_ref)
        _identifier(self.key_id, "credential enrollment key_id")
        _integer(self.revision, "credential enrollment revision", 1, 2**31 - 1)
        if self.state not in {"active", "revoked"}:
            raise ThirdPartyProviderConfigError(
                "credential enrollment state must be active or revoked"
            )

    @property
    def authority_sha256(self) -> str:
        return _sha256(
            {
                "tenant_id": self.tenant_id,
                "provider": self.provider,
                "source_id": self.source_id,
                "credential_ref_sha256": hashlib.sha256(
                    self.credential_ref.encode("utf-8")
                ).hexdigest(),
                "key_id_sha256": hashlib.sha256(
                    self.key_id.encode("utf-8")
                ).hexdigest(),
                "revision": self.revision,
                "state": self.state,
            }
        )


@dataclass(frozen=True, slots=True)
class ProviderRequest:
    tenant_id: str
    provider: str
    source_id: str
    source_revision: int
    source_integrity_sha256: str
    kind: str
    capability: str
    key_id: str

    def __post_init__(self) -> None:
        try:
            canonical_tenant = canonical_tenant_id(self.tenant_id)
        except (TypeError, ValueError) as exc:
            raise ThirdPartyProviderProtocolError("tenant_id is invalid") from exc
        if canonical_tenant != self.tenant_id:
            raise ThirdPartyProviderProtocolError("tenant_id must already be canonical")
        _identifier(self.provider, "provider")
        _identifier(self.source_id, "source_id")
        _integer(self.source_revision, "source_revision", 1, 2**31 - 1)
        _digest(self.source_integrity_sha256, "source_integrity_sha256")
        _identifier(self.kind, "kind")
        if self.capability != "monitoring":
            raise ThirdPartyProviderConfigError("provider capability is not monitoring")
        _identifier(self.key_id, "key_id")


@dataclass(frozen=True, slots=True)
class ProviderCitation:
    citation_id: str
    title: str
    uri: str
    pinpoint: str


@dataclass(frozen=True, slots=True)
class ProviderFeedResult:
    provider: str
    source_id: str
    source_revision: int
    source_integrity_sha256: str
    capability: str
    key_id_sha256: str
    kind: str
    dataset_revision: str
    observed_at: float
    valid_until: float
    record_count: int
    cursor_count: int
    coverage_complete: bool
    observation_sha256: str
    evidence_sha256: str
    provider_receipt_sha256: str
    citations: tuple[ProviderCitation, ...]


def _canonical(value: object, *, maximum: int = _MAX_PAGE_BYTES) -> bytes:
    try:
        result = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ThirdPartyProviderProtocolError(
            "provider page is not finite canonical JSON"
        ) from exc
    if not 1 <= len(result) <= maximum:
        raise ThirdPartyProviderProtocolError("provider page exceeds its byte bound")
    return result


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value, maximum=_MAX_TOTAL_BYTES)).hexdigest()


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ThirdPartyProviderProtocolError(f"{label} is not a bounded identifier")
    return value


def _credential_reference(value: object) -> str:
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"[A-Z][A-Z0-9_]{1,127}", value)
    ):
        raise ThirdPartyProviderConfigError(
            "credential_ref must be a deployment-owned secret reference"
        )
    return value


def _host(value: object, label: str = "provider host") -> str:
    if not isinstance(value, str):
        raise ThirdPartyProviderConfigError(f"{label} is invalid")
    host = value.strip().lower()
    if host != value or _HOST_RE.fullmatch(host) is None:
        raise ThirdPartyProviderConfigError(f"{label} is invalid")
    return host


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ThirdPartyProviderProtocolError(f"{label} is not a SHA-256 digest")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ThirdPartyProviderProtocolError(f"{label} is outside its integer bound")
    return value


def _timestamp(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 < float(value) < 100_000_000_000.0
    ):
        raise ThirdPartyProviderProtocolError(f"{label} is not a finite timestamp")
    return float(value)


def _text(value: object, label: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ThirdPartyProviderProtocolError(f"{label} must be text")
    result = value.strip()
    if not result or len(result.encode("utf-8")) > maximum:
        raise ThirdPartyProviderProtocolError(f"{label} is outside its text bound")
    if any(ord(character) < 32 or ord(character) == 127 for character in result):
        raise ThirdPartyProviderProtocolError(f"{label} contains control characters")
    return result


def _https_uri(value: object, label: str) -> str:
    uri = _text(value, label, 2_048)
    parsed = urlparse(uri)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ThirdPartyProviderProtocolError(f"{label} is not credential-free HTTPS")
    return uri


def _citation(value: object) -> ProviderCitation:
    if not isinstance(value, Mapping) or set(value) != {
        "citation_id",
        "title",
        "uri",
        "pinpoint",
    }:
        raise ThirdPartyProviderProtocolError("provider citation schema is closed")
    uri = _https_uri(value["uri"], "citation uri")
    if urlparse(uri).query:
        raise ThirdPartyProviderProtocolError(
            "provider citation URI must not contain query parameters"
        )
    return ProviderCitation(
        citation_id=_identifier(value["citation_id"], "citation_id"),
        title=_text(value["title"], "citation title", 500),
        uri=uri,
        pinpoint=_text(value["pinpoint"], "citation pinpoint", 500),
    )


class DeploymentCredentialAuthority:
    """Resolve exact enrolled secret references without persisting material."""

    def __init__(
        self,
        enrollments: Sequence[ProviderCredentialEnrollment],
        *,
        secret_resolver: Callable[[str], str | None] | None = None,
    ) -> None:
        if isinstance(enrollments, (str, bytes)) or not isinstance(
            enrollments, Sequence
        ):
            raise ThirdPartyProviderConfigError(
                "credential enrollments must be a list"
            )
        if len(enrollments) > 10_000:
            raise ThirdPartyProviderConfigError(
                "credential enrollments exceed their bound"
            )
        selected: dict[
            tuple[str, str, str, str], ProviderCredentialEnrollment
        ] = {}
        for enrollment in enrollments:
            if not isinstance(enrollment, ProviderCredentialEnrollment):
                raise ThirdPartyProviderConfigError(
                    "credential enrollment contract is invalid"
                )
            if enrollment.provider not in {*_PROVIDER_CONTRACTS, "generic_approved"}:
                raise ThirdPartyProviderConfigError(
                    "credential enrollment provider is unsupported"
                )
            key = (
                enrollment.tenant_id,
                enrollment.credential_ref,
                enrollment.provider,
                enrollment.source_id,
            )
            if key in selected:
                raise ThirdPartyProviderConfigError(
                    "credential enrollment authority is ambiguous"
                )
            selected[key] = enrollment
        if secret_resolver is None:
            from .secret_provider import get_secret

            secret_resolver = get_secret
        if not callable(secret_resolver):
            raise ThirdPartyProviderConfigError(
                "deployment secret resolver is unavailable"
            )
        self._enrollments = selected
        self._secret_resolver = secret_resolver

    def _enrollment(
        self,
        tenant_id: str,
        credential_ref: str,
        provider: str,
        source_id: str,
    ) -> ProviderCredentialEnrollment:
        try:
            tenant = canonical_tenant_id(tenant_id)
        except (TypeError, ValueError) as exc:
            raise ThirdPartyProviderCredentialError(
                "credential_scope_invalid"
            ) from exc
        reference = _credential_reference(credential_ref)
        provider_id = _identifier(provider, "credential provider")
        source = _identifier(source_id, "credential source_id")
        enrollment = self._enrollments.get(
            (tenant, reference, provider_id, source)
        )
        if enrollment is None:
            raise ThirdPartyProviderCredentialError(
                "credential_not_enrolled"
            )
        if enrollment.state == "revoked":
            raise ThirdPartyProviderCredentialError(
                "credential_revoked",
                revoked=True,
            )
        return enrollment

    def resolve(
        self,
        tenant_id: str,
        credential_ref: str,
        provider: str,
        source_id: str,
    ) -> CredentialBinding:
        enrollment = self._enrollment(
            tenant_id,
            credential_ref,
            provider,
            source_id,
        )
        try:
            secret = self._secret_resolver(enrollment.credential_ref)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise ThirdPartyProviderCredentialError(
                "credential_resolution_failed",
                retryable=True,
            ) from None
        if not isinstance(secret, str) or not secret:
            raise ThirdPartyProviderCredentialError(
                "credential_unavailable",
                retryable=True,
            )
        return CredentialBinding(
            key_id=enrollment.key_id,
            secret=ProviderBearerCredential(secret),
        )

    def status(self) -> Mapping[str, object]:
        active = [
            enrollment
            for enrollment in self._enrollments.values()
            if enrollment.state == "active"
        ]
        revoked = len(self._enrollments) - len(active)
        return {
            "schema": "lightwork.third-party-provider-credential-authority-status.v1",
            "enrollment_count": len(self._enrollments),
            "active_enrollment_count": len(active),
            "revoked_enrollment_count": revoked,
            "providers_with_active_enrollments": sorted(
                {enrollment.provider for enrollment in active}
            ),
            "providers_with_enrollments": sorted(
                {enrollment.provider for enrollment in self._enrollments.values()}
            ),
            "tenant_scoped": True,
            "source_scoped": True,
            "deployment_secret_references": True,
            "secret_values_resolved": False,
            "secret_values_returned": False,
            "status_network_io": False,
        }

    def source_readiness(
        self,
        *,
        tenant_id: str,
        credential_ref: str,
        provider: str,
        source_id: str,
        verify_secret: bool = False,
    ) -> Mapping[str, object]:
        try:
            enrollment = self._enrollment(
                tenant_id,
                credential_ref,
                provider,
                source_id,
            )
        except ThirdPartyProviderCredentialError as exc:
            return {
                "schema": "lightwork.third-party-provider-source-readiness.v1",
                "configured": False,
                "credential_available": False,
                "ready": False,
                "error_code": exc.code,
                "secret_value_returned": False,
                "provider_network_io": False,
            }
        available: bool | None = None
        error_code: str | None = None
        if verify_secret:
            try:
                self.resolve(
                    tenant_id,
                    credential_ref,
                    provider,
                    source_id,
                )
            except ThirdPartyProviderCredentialError as exc:
                available = False
                error_code = exc.code
            else:
                available = True
        return {
            "schema": "lightwork.third-party-provider-source-readiness.v1",
            "configured": True,
            "credential_available": available,
            "ready": bool(available),
            "error_code": error_code,
            "authority_revision": enrollment.revision,
            "authority_sha256": enrollment.authority_sha256,
            "secret_value_returned": False,
            "provider_network_io": False,
        }


class ProductionThirdPartyHTTPSJSONTransport:
    """DNS-pinned, exact-endpoint, redirect-free bounded GET transport."""

    dns_pinned = True
    redirects_followed = False
    get_only = True

    def __init__(
        self,
        endpoints: Mapping[str, tuple[str, str]],
        *,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not isinstance(endpoints, Mapping):
            raise ThirdPartyProviderConfigError(
                "provider transport endpoints are unavailable"
            )
        selected: dict[str, tuple[str, str]] = {}
        for provider, endpoint in endpoints.items():
            provider_id = _identifier(provider, "provider endpoint ID")
            if provider_id not in {*_PROVIDER_CONTRACTS, "generic_approved"}:
                raise ThirdPartyProviderConfigError(
                    "provider transport endpoint ID is unsupported"
                )
            if (
                not isinstance(endpoint, tuple)
                or len(endpoint) != 2
                or not isinstance(endpoint[1], str)
            ):
                raise ThirdPartyProviderConfigError(
                    "provider transport endpoint is invalid"
                )
            host = _host(endpoint[0])
            path = endpoint[1]
            expected_path = (
                "/v1/third-party-observations"
                if provider_id == "generic_approved"
                else _PROVIDER_CONTRACTS[provider_id][1]
            )
            if (
                path != expected_path
                or "?" in path
                or "#" in path
                or len(path.encode("utf-8")) > 500
            ):
                raise ThirdPartyProviderConfigError(
                    "provider transport path is invalid"
                )
            fixed_host = (
                None
                if provider_id == "generic_approved"
                else _PROVIDER_CONTRACTS[provider_id][0]
            )
            if fixed_host is not None and host != fixed_host:
                raise ThirdPartyProviderConfigError(
                    "provider transport fixed host is invalid"
                )
            selected[provider_id] = (host, path)
        if not callable(monotonic):
            raise ThirdPartyProviderConfigError(
                "provider transport clock is unavailable"
            )
        self._endpoints = selected
        self._monotonic = monotonic

    def __repr__(self) -> str:
        return (
            "ProductionThirdPartyHTTPSJSONTransport("
            "dns_pinned=True, redirects_followed=False, credential_owner='ephemeral')"
        )

    @staticmethod
    def _decode(body: bytes) -> Mapping[str, object]:
        def closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ThirdPartyProviderProtocolError(
                        "provider JSON contains duplicate keys"
                    )
                result[key] = value
            return result

        def reject_constant(_value: str) -> object:
            raise ThirdPartyProviderProtocolError(
                "provider JSON contains a non-finite number"
            )

        try:
            decoded = body.decode("utf-8", errors="strict")
            value = json.loads(
                decoded,
                object_pairs_hook=closed_object,
                parse_constant=reject_constant,
            )
        except ThirdPartyProviderProtocolError:
            raise
        except (UnicodeError, json.JSONDecodeError, RecursionError):
            raise ThirdPartyProviderProtocolError(
                "provider response is not bounded canonical JSON"
            ) from None
        if not isinstance(value, Mapping):
            raise ThirdPartyProviderProtocolError(
                "provider response must be a JSON object"
            )
        return value

    @staticmethod
    def _query(
        query: Mapping[str, str],
    ) -> tuple[str, str]:
        required = {
            "tenant_id",
            "provider",
            "source_id",
            "source_revision",
            "source_integrity_sha256",
            "capability",
            "key_id",
            "kind",
        }
        if not isinstance(query, Mapping):
            raise ThirdPartyProviderProtocolError(
                "provider transport query schema is closed"
            )
        keys = frozenset(query)
        if keys not in {frozenset(required), frozenset({*required, "cursor"})}:
            raise ThirdPartyProviderProtocolError(
                "provider transport query schema is closed"
            )
        normalized: list[tuple[str, str]] = []
        for key in sorted(query):
            value = query[key]
            if (
                not isinstance(value, str)
                or len(value.encode("utf-8")) > 4_096
                or _HEADER_CONTROL_RE.search(value)
            ):
                raise ThirdPartyProviderProtocolError(
                    "provider transport query value is invalid"
                )
            normalized.append((key, value))
        encoded = urlencode(normalized, doseq=False, safe="")
        if not encoded or len(encoded.encode("ascii")) > _MAX_QUERY_BYTES:
            raise ThirdPartyProviderProtocolError(
                "provider transport query exceeds its byte bound"
            )
        return str(query["provider"]), encoded

    def _read_response(
        self,
        response: Any,
        *,
        maximum_response_bytes: int,
        timeout_seconds: float,
        started: float,
    ) -> Mapping[str, object]:
        status = int(response.status_code)
        if 300 <= status < 400:
            raise ThirdPartyProviderTransportError(
                "provider_redirect_rejected",
                retryable=False,
            )
        if status in {408, 425, 429} or 500 <= status <= 599:
            raise ThirdPartyProviderTransportError(
                "provider_retryable_http_error",
                retryable=True,
            )
        if status in {401, 403}:
            raise ThirdPartyProviderTransportError(
                "provider_credential_rejected",
                retryable=False,
            )
        if status != 200:
            raise ThirdPartyProviderTransportError(
                "provider_definitive_http_error",
                retryable=False,
            )
        content_type = response.headers.get("content-type", "")
        media_type = content_type.split(";", 1)[0].strip().lower()
        if not (
            media_type == "application/json" or media_type.endswith("+json")
        ):
            raise ThirdPartyProviderProtocolError(
                "provider response content type is not JSON"
            )
        declared = response.headers.get("content-length")
        if declared is not None:
            try:
                declared_size = int(declared)
            except ValueError:
                raise ThirdPartyProviderProtocolError(
                    "provider content length is invalid"
                ) from None
            if not 0 <= declared_size <= maximum_response_bytes:
                raise ThirdPartyProviderProtocolError(
                    "provider response exceeds its byte bound"
                )
        chunks: list[bytes] = []
        observed = 0
        for chunk in response.iter_bytes():
            if float(self._monotonic()) - started > timeout_seconds:
                raise ThirdPartyProviderTransportError(
                    "provider_elapsed_timeout",
                    retryable=True,
                    ambiguous=True,
                )
            observed += len(chunk)
            if observed > maximum_response_bytes:
                raise ThirdPartyProviderProtocolError(
                    "provider response exceeds its byte bound"
                )
            chunks.append(chunk)
        if not chunks:
            raise ThirdPartyProviderProtocolError(
                "provider returned an empty response"
            )
        return self._decode(b"".join(chunks))

    def get_json(
        self,
        *,
        host: str,
        path: str,
        query: Mapping[str, str],
        credential: object,
        maximum_response_bytes: int,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        provider, encoded_query = self._query(query)
        endpoint = self._endpoints.get(provider)
        if endpoint is None or endpoint != (host, path):
            raise ThirdPartyProviderConfigError(
                "provider request crossed its enrolled endpoint"
            )
        if not isinstance(credential, ProviderBearerCredential):
            raise ThirdPartyProviderCredentialError("credential_contract_invalid")
        if (
            isinstance(maximum_response_bytes, bool)
            or not isinstance(maximum_response_bytes, int)
            or not 1_024 <= maximum_response_bytes <= _MAX_PAGE_BYTES
            or isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(float(timeout_seconds))
            or not 1.0 <= float(timeout_seconds) <= 120.0
        ):
            raise ThirdPartyProviderConfigError(
                "provider transport bounds are invalid"
            )
        if os.getenv("MAVERICK_FETCH_ALLOW_PRIVATE", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }:
            raise ThirdPartyProviderTransportError(
                "provider_private_override_rejected",
                retryable=False,
            )
        url = f"https://{host}{path}?{encoded_query}"
        try:
            from .enterprise import enterprise_egress_denial
            from .tools._ssrf import BlockedHost, safe_client

            denial = enterprise_egress_denial(
                url,
                tool=f"third_party_intelligence.{provider}",
            )
            if denial:
                raise ThirdPartyProviderTransportError(
                    "provider_egress_denied",
                    retryable=False,
                )
            started = float(self._monotonic())
            with safe_client(
                url,
                timeout=float(timeout_seconds),
                follow_redirects=False,
            ) as client:
                with client.stream(
                    "GET",
                    url,
                    headers={
                        "Accept": "application/json",
                        "Authorization": f"Bearer {credential.token}",
                        "User-Agent": "Lightwork-Third-Party-Intelligence/1",
                    },
                    follow_redirects=False,
                ) as response:
                    return self._read_response(
                        response,
                        maximum_response_bytes=maximum_response_bytes,
                        timeout_seconds=float(timeout_seconds),
                        started=started,
                    )
        except (KeyboardInterrupt, SystemExit):
            raise
        except (
            ThirdPartyProviderConfigError,
            ThirdPartyProviderCredentialError,
            ThirdPartyProviderProtocolError,
            ThirdPartyProviderTransportError,
        ):
            raise
        except BlockedHost:
            raise ThirdPartyProviderTransportError(
                "provider_ssrf_blocked",
                retryable=False,
            ) from None
        except Exception as exc:
            try:
                import httpx

                retryable = isinstance(exc, httpx.TransportError)
            except Exception:
                retryable = "timeout" in type(exc).__name__.lower()
            raise ThirdPartyProviderTransportError(
                "provider_transport_ambiguous" if retryable else "provider_transport_failed",
                retryable=retryable,
                ambiguous=retryable,
            ) from None


class FixedHostThirdPartyFeedAdapter:
    """Parse one named provider's fixed-host, GET-only digest feed."""

    def __init__(
        self,
        *,
        provider: str,
        host: str,
        path: str,
        schema: str,
        transport: ThirdPartyProviderTransport,
        timeout_seconds: float = 20.0,
    ) -> None:
        self.provider = _identifier(provider, "provider")
        self.host = _text(host, "provider host", 253).lower()
        self.path = _text(path, "provider path", 500)
        self.schema = _text(schema, "provider schema", 200)
        if not self.path.startswith("/") or "?" in self.path or "#" in self.path:
            raise ThirdPartyProviderConfigError("provider path must be a fixed absolute path")
        if not callable(getattr(transport, "get_json", None)):
            raise ThirdPartyProviderConfigError("trusted GET transport is unavailable")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(float(timeout_seconds))
            or not 1.0 <= float(timeout_seconds) <= 120.0
        ):
            raise ThirdPartyProviderConfigError("provider timeout is outside its bound")
        self._transport = transport
        self._timeout_seconds = float(timeout_seconds)

    def collect(
        self,
        request: ProviderRequest,
        credential: CredentialBinding,
    ) -> ProviderFeedResult:
        if request.provider != self.provider or request.key_id != credential.key_id:
            raise ThirdPartyProviderConfigError("provider request binding is inconsistent")
        cursor: str | None = None
        cursors: set[str] = set()
        records: list[dict[str, Any]] = []
        record_ids: set[str] = set()
        citations: dict[str, ProviderCitation] = {}
        page_receipts: list[str] = []
        total_bytes = 0
        dataset_revision: str | None = None
        observed_at: float | None = None
        valid_until: float | None = None
        for _page_number in range(1, _MAX_PAGES + 1):
            query = {
                "tenant_id": request.tenant_id,
                "provider": request.provider,
                "source_id": request.source_id,
                "source_revision": str(request.source_revision),
                "source_integrity_sha256": request.source_integrity_sha256,
                "capability": request.capability,
                "key_id": request.key_id,
                "kind": request.kind,
            }
            if cursor is not None:
                query["cursor"] = cursor
            try:
                raw = self._transport.get_json(
                    host=self.host,
                    path=self.path,
                    query=query,
                    credential=credential.secret,
                    maximum_response_bytes=_MAX_PAGE_BYTES,
                    timeout_seconds=self._timeout_seconds,
                )
            except (KeyboardInterrupt, SystemExit):
                raise
            except ThirdPartyProviderError:
                raise
            except Exception:
                raise ThirdPartyProviderError("provider GET transport failed") from None
            if not isinstance(raw, Mapping):
                raise ThirdPartyProviderProtocolError("provider page must be an object")
            page_bytes = _canonical(raw)
            total_bytes += len(page_bytes)
            if total_bytes > _MAX_TOTAL_BYTES:
                raise ThirdPartyProviderProtocolError("provider feed exceeds its byte bound")
            parsed = self._parse_page(raw, request)
            if dataset_revision is None:
                dataset_revision = parsed["dataset_revision"]
                observed_at = parsed["observed_at"]
                valid_until = parsed["valid_until"]
            elif (
                parsed["dataset_revision"] != dataset_revision
                or parsed["observed_at"] != observed_at
                or parsed["valid_until"] != valid_until
            ):
                raise ThirdPartyProviderProtocolError("provider feed drifted across pages")
            for record in parsed["records"]:
                record_id = record["record_id"]
                if record_id in record_ids:
                    raise ThirdPartyProviderProtocolError("provider record IDs repeat")
                record_ids.add(record_id)
                records.append(record)
                citation = record["citation"]
                prior = citations.get(citation.citation_id)
                if prior is not None and prior != citation:
                    raise ThirdPartyProviderProtocolError("provider citation ID drifted")
                citations[citation.citation_id] = citation
            if len(records) > _MAX_TOTAL_RECORDS or len(citations) > _MAX_CITATIONS:
                raise ThirdPartyProviderProtocolError("provider feed exceeds its item bound")
            page_receipts.append(hashlib.sha256(page_bytes).hexdigest())
            next_cursor = self._continuation(parsed)
            if next_cursor is None:
                break
            if next_cursor in cursors:
                raise ThirdPartyProviderProtocolError("provider cursor cycle detected")
            cursors.add(next_cursor)
            cursor = next_cursor
        else:
            raise ThirdPartyProviderProtocolError("provider page bound was exhausted")
        if not records or dataset_revision is None or observed_at is None or valid_until is None:
            raise ThirdPartyProviderIncompleteError("provider returned no explicit observations")
        ordered = sorted(records, key=lambda item: item["record_id"])
        observation = _sha256(
            [
                {
                    "record_id": item["record_id"],
                    "observation_sha256": item["observation_sha256"],
                }
                for item in ordered
            ]
        )
        evidence = _sha256(
            [
                {
                    "record_id": item["record_id"],
                    "evidence_sha256": item["evidence_sha256"],
                }
                for item in ordered
            ]
        )
        receipt = _sha256(
            {
                "request": {
                    "tenant_id": request.tenant_id,
                    "provider": request.provider,
                    "source_id": request.source_id,
                    "source_revision": request.source_revision,
                    "source_integrity_sha256": request.source_integrity_sha256,
                    "capability": request.capability,
                    "key_id_sha256": hashlib.sha256(request.key_id.encode()).hexdigest(),
                    "kind": request.kind,
                },
                "dataset_revision": dataset_revision,
                "observed_at": observed_at,
                "valid_until": valid_until,
                "record_count": len(ordered),
                "page_receipts": page_receipts,
                "observation_sha256": observation,
                "evidence_sha256": evidence,
            }
        )
        return ProviderFeedResult(
            provider=request.provider,
            source_id=request.source_id,
            source_revision=request.source_revision,
            source_integrity_sha256=request.source_integrity_sha256,
            capability=request.capability,
            key_id_sha256=hashlib.sha256(request.key_id.encode()).hexdigest(),
            kind=request.kind,
            dataset_revision=dataset_revision,
            observed_at=observed_at,
            valid_until=valid_until,
            record_count=len(ordered),
            cursor_count=len(page_receipts),
            coverage_complete=True,
            observation_sha256=observation,
            evidence_sha256=evidence,
            provider_receipt_sha256=receipt,
            citations=tuple(citations[key] for key in sorted(citations)),
        )

    @staticmethod
    def _continuation(parsed: Mapping[str, Any]) -> str | None:
        next_cursor = parsed["next_cursor"]
        reasons = parsed["incomplete_reason_codes"]
        if parsed["complete"]:
            if next_cursor is not None or reasons:
                raise ThirdPartyProviderProtocolError(
                    "complete provider page has contradictory coverage markers"
                )
            return None
        if reasons:
            raise ThirdPartyProviderIncompleteError(reasons[0])
        if next_cursor is None:
            raise ThirdPartyProviderIncompleteError("provider_reported_incomplete")
        return str(next_cursor)

    def _parse_page(
        self,
        raw: Mapping[str, object],
        request: ProviderRequest,
    ) -> dict[str, Any]:
        expected_keys = {
            "schema",
            "tenant_id",
            "provider",
            "source_id",
            "source_revision",
            "source_integrity_sha256",
            "capability",
            "key_id",
            "kind",
            "dataset_revision",
            "observed_at",
            "valid_until",
            "complete",
            "incomplete_reason_codes",
            "next_cursor",
            "records",
        }
        if set(raw) != expected_keys or raw.get("schema") != self.schema:
            raise ThirdPartyProviderProtocolError("provider page schema is closed")
        pins = {
            "tenant_id": request.tenant_id,
            "provider": request.provider,
            "source_id": request.source_id,
            "source_revision": request.source_revision,
            "source_integrity_sha256": request.source_integrity_sha256,
            "capability": request.capability,
            "key_id": request.key_id,
            "kind": request.kind,
        }
        if any(raw.get(key) != value for key, value in pins.items()):
            raise ThirdPartyProviderProtocolError("provider response pins do not match")
        dataset = _identifier(raw["dataset_revision"], "dataset_revision")
        observed = _timestamp(raw["observed_at"], "observed_at")
        valid = _timestamp(raw["valid_until"], "valid_until")
        if valid <= observed:
            raise ThirdPartyProviderProtocolError("provider validity window is inverted")
        complete = raw["complete"]
        if not isinstance(complete, bool):
            raise ThirdPartyProviderProtocolError("provider complete marker must be boolean")
        reasons_value = raw["incomplete_reason_codes"]
        if isinstance(reasons_value, (str, bytes)) or not isinstance(reasons_value, Sequence):
            raise ThirdPartyProviderProtocolError("incomplete reason codes must be a list")
        if len(reasons_value) > 20:
            raise ThirdPartyProviderProtocolError("too many incomplete reason codes")
        reasons = tuple(_identifier(item, "incomplete reason code") for item in reasons_value)
        cursor_value = raw["next_cursor"]
        if cursor_value is not None and (
            not isinstance(cursor_value, str) or not _CURSOR_RE.fullmatch(cursor_value)
        ):
            raise ThirdPartyProviderProtocolError("provider cursor is invalid")
        rows = raw["records"]
        if isinstance(rows, (str, bytes)) or not isinstance(rows, Sequence):
            raise ThirdPartyProviderProtocolError("provider records must be a list")
        if len(rows) > _MAX_PAGE_RECORDS:
            raise ThirdPartyProviderProtocolError("provider page has too many records")
        records: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, Mapping) or set(row) != {
                "record_id",
                "observation_sha256",
                "evidence_sha256",
                "citation",
            }:
                raise ThirdPartyProviderProtocolError("provider record schema is closed")
            records.append(
                {
                    "record_id": _identifier(row["record_id"], "record_id"),
                    "observation_sha256": _digest(row["observation_sha256"], "observation_sha256"),
                    "evidence_sha256": _digest(row["evidence_sha256"], "evidence_sha256"),
                    "citation": _citation(row["citation"]),
                }
            )
        return {
            "dataset_revision": dataset,
            "observed_at": observed,
            "valid_until": valid,
            "complete": complete,
            "incomplete_reason_codes": reasons,
            "next_cursor": cursor_value,
            "records": records,
        }


class ThirdPartyProviderFactory:
    """Build only explicitly enabled, fixed-host provider adapters."""

    def __init__(
        self,
        *,
        transport: ThirdPartyProviderTransport,
        enabled_providers: Sequence[str],
        generic_approved_host: str | None = None,
        named_provider_hosts: Mapping[str, str] | None = None,
        timeout_seconds: float = 20.0,
    ) -> None:
        if not callable(getattr(transport, "get_json", None)):
            raise ThirdPartyProviderConfigError(
                "trusted GET transport is unavailable"
            )
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(float(timeout_seconds))
            or not 1.0 <= float(timeout_seconds) <= 120.0
        ):
            raise ThirdPartyProviderConfigError(
                "provider timeout is outside its bound"
            )
        if isinstance(enabled_providers, (str, bytes)) or not isinstance(
            enabled_providers, Sequence
        ):
            raise ThirdPartyProviderConfigError("enabled providers must be a list")
        enabled = tuple(_identifier(value, "enabled provider") for value in enabled_providers)
        if len(enabled) != len(set(enabled)):
            raise ThirdPartyProviderConfigError("enabled providers contain duplicates")
        known = {*_PROVIDER_CONTRACTS, "generic_approved"}
        if not set(enabled).issubset(known):
            raise ThirdPartyProviderConfigError("enabled provider ID is not supported")
        raw_named_hosts = named_provider_hosts or {}
        if not isinstance(raw_named_hosts, Mapping):
            raise ThirdPartyProviderConfigError(
                "named provider hosts must be a table"
            )
        if not set(raw_named_hosts).issubset(_ENROLLED_HOST_PROVIDERS):
            raise ThirdPartyProviderConfigError(
                "named provider host enrollment is unsupported"
            )
        if set(raw_named_hosts) - set(enabled):
            raise ThirdPartyProviderConfigError(
                "named provider host was enrolled for a disabled provider"
            )
        selected_named_hosts = {
            provider: _host(host, f"{provider} host")
            for provider, host in raw_named_hosts.items()
        }
        missing_named_hosts = _ENROLLED_HOST_PROVIDERS.intersection(enabled) - set(
            selected_named_hosts
        )
        if missing_named_hosts:
            raise ThirdPartyProviderConfigError(
                "named provider requires one exact deployment-enrolled host"
            )
        if "generic_approved" in enabled:
            if generic_approved_host is None:
                raise ThirdPartyProviderConfigError(
                    "generic approved provider requires a trusted fixed host"
                )
            generic_approved_host = _host(
                generic_approved_host,
                "generic provider host",
            )
        elif generic_approved_host is not None:
            raise ThirdPartyProviderConfigError(
                "generic provider host was enrolled while its provider is disabled"
            )
        self._transport = transport
        self._enabled = frozenset(enabled)
        self._generic_host = generic_approved_host
        self._named_hosts = selected_named_hosts
        self._timeout_seconds = timeout_seconds

    @property
    def enabled_providers(self) -> tuple[str, ...]:
        return tuple(sorted(self._enabled))

    @property
    def resolved_endpoints(self) -> Mapping[str, tuple[str, str]]:
        result: dict[str, tuple[str, str]] = {}
        for provider in sorted(self._enabled):
            host, path, _schema = self._contract(provider)
            result[provider] = (host, path)
        return result

    def _contract(self, provider_id: str) -> tuple[str, str, str]:
        if provider_id == "generic_approved":
            if self._generic_host is None:  # pragma: no cover - constructor invariant
                raise ThirdPartyProviderConfigError(
                    "generic provider host is unavailable"
                )
            return (
                self._generic_host,
                "/v1/third-party-observations",
                "lightwork.generic-approved-observation-page.v1",
            )
        contract_host, path, schema = _PROVIDER_CONTRACTS[provider_id]
        host = contract_host or self._named_hosts.get(provider_id)
        if host is None:  # pragma: no cover - constructor invariant
            raise ThirdPartyProviderConfigError(
                "named provider host is unavailable"
            )
        return host, path, schema

    def create(self, provider: str, provenance_uri: str) -> FixedHostThirdPartyFeedAdapter:
        provider_id = _identifier(provider, "provider")
        if provider_id not in self._enabled:
            raise ThirdPartyProviderConfigError("provider adapter is not enabled")
        contract = self._contract(provider_id)
        provenance = urlparse(_https_uri(provenance_uri, "source provenance_uri"))
        if provenance.query:
            raise ThirdPartyProviderConfigError(
                "source provenance URI must not contain query parameters"
            )
        try:
            port = provenance.port
        except ValueError:
            raise ThirdPartyProviderConfigError(
                "source provenance authority is invalid"
            ) from None
        if port is not None or (provenance.hostname or "").lower() != contract[0]:
            raise ThirdPartyProviderConfigError(
                "source provenance authority does not match the fixed provider host"
            )
        return FixedHostThirdPartyFeedAdapter(
            provider=provider_id,
            host=contract[0],
            path=contract[1],
            schema=contract[2],
            transport=self._transport,
            timeout_seconds=self._timeout_seconds,
        )


class ThirdPartyProviderComposition:
    """Bundled provider factory, HTTPS transport, and credential authority."""

    def __init__(
        self,
        *,
        enabled_providers: Sequence[str],
        credential_enrollments: Sequence[ProviderCredentialEnrollment],
        generic_approved_host: str | None = None,
        named_provider_hosts: Mapping[str, str] | None = None,
        timeout_seconds: float = 20.0,
        secret_resolver: Callable[[str], str | None] | None = None,
        transport: ThirdPartyProviderTransport | None = None,
    ) -> None:
        # Resolve the exact endpoints through the same closed factory rules
        # before constructing the bundled transport.  The bootstrap seam is
        # never exposed after initialization.
        class _BootstrapTransport:
            def get_json(self, **_kwargs: object) -> Mapping[str, object]:
                raise ThirdPartyProviderConfigError(
                    "provider composition bootstrap transport cannot dispatch"
                )

        bootstrap = ThirdPartyProviderFactory(
            transport=_BootstrapTransport(),
            enabled_providers=enabled_providers,
            generic_approved_host=generic_approved_host,
            named_provider_hosts=named_provider_hosts,
            timeout_seconds=timeout_seconds,
        )
        selected_transport = transport or ProductionThirdPartyHTTPSJSONTransport(
            bootstrap.resolved_endpoints
        )
        self.provider_factory = ThirdPartyProviderFactory(
            transport=selected_transport,
            enabled_providers=enabled_providers,
            generic_approved_host=generic_approved_host,
            named_provider_hosts=named_provider_hosts,
            timeout_seconds=timeout_seconds,
        )
        self.credential_authority = DeploymentCredentialAuthority(
            credential_enrollments,
            secret_resolver=secret_resolver,
        )
        credential_providers = set(
            self.credential_authority.status()["providers_with_enrollments"]
        )
        if not credential_providers.issubset(
            self.provider_factory.enabled_providers
        ):
            raise ThirdPartyProviderConfigError(
                "credential enrollment was supplied for a disabled provider"
            )
        self.transport = selected_transport

    @property
    def credential_resolver(
        self,
    ) -> Callable[[str, str, str, str], CredentialBinding]:
        return self.credential_authority.resolve

    def readiness(self) -> Mapping[str, object]:
        credential_status = self.credential_authority.status()
        enabled = self.provider_factory.enabled_providers
        providers_with_credentials = set(
            credential_status["providers_with_active_enrollments"]
        )
        hardened = (
            getattr(self.transport, "dns_pinned", None) is True
            and getattr(self.transport, "redirects_followed", None) is False
            and getattr(self.transport, "get_only", None) is True
        )
        configured = bool(enabled) and set(enabled).issubset(providers_with_credentials)
        configuration_ready = configured and hardened
        return {
            "schema": "lightwork.third-party-provider-composition-readiness.v1",
            "enabled_providers": list(enabled),
            "resolved_endpoints": {
                provider: f"https://{host}{path}"
                for provider, (host, path) in self.provider_factory.resolved_endpoints.items()
            },
            "configured": configured,
            "configuration_ready": configuration_ready,
            "transport_hardened": hardened,
            # A side-effect-free composition probe cannot claim a mounted vault
            # secret or licensed provider is reachable.  Operators obtain an
            # exact source result through source_readiness(verify_secret=True).
            "ready": False,
            "ready_requires_source_credential_check": configuration_ready,
            "dns_pinned": getattr(self.transport, "dns_pinned", False) is True,
            "redirects_followed": getattr(
                self.transport,
                "redirects_followed",
                None,
            ),
            "get_only": getattr(self.transport, "get_only", False) is True,
            "bounded_pages": True,
            "bounded_bytes": True,
            "bounded_elapsed_time": True,
            "tenant_source_revision_binding": True,
            "minimized_receipts": True,
            "retryable_get_replay_safe": True,
            "ambiguous_get_replay_safe": True,
            "source_authority_revocation_rechecked_after_io": True,
            "credential_authority": credential_status,
            "readiness_resolved_secret": False,
            "readiness_provider_network_io": False,
            "licensed_provider_credential_verified": False,
            "live_provider_acceptance_verified": False,
        }


def available_provider_concepts() -> tuple[str, ...]:
    return tuple(sorted({*_PROVIDER_CONTRACTS, "generic_approved"}))


__all__ = [
    "CredentialBinding",
    "DeploymentCredentialAuthority",
    "FixedHostThirdPartyFeedAdapter",
    "ProductionThirdPartyHTTPSJSONTransport",
    "ProviderBearerCredential",
    "ProviderCitation",
    "ProviderCredentialEnrollment",
    "ProviderFeedResult",
    "ProviderRequest",
    "ThirdPartyProviderComposition",
    "ThirdPartyProviderConfigError",
    "ThirdPartyProviderCredentialError",
    "ThirdPartyProviderError",
    "ThirdPartyProviderFactory",
    "ThirdPartyProviderIncompleteError",
    "ThirdPartyProviderProtocolError",
    "ThirdPartyProviderTransport",
    "ThirdPartyProviderTransportError",
    "available_provider_concepts",
]
