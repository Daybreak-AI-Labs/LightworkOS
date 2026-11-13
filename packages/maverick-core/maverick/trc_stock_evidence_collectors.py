"""Deployment-bound stock collectors for continuous technical evidence.

The core continuous-evidence authority deliberately knows nothing about cloud
credentials or provider payloads.  This module supplies a closed production
boundary for seven high-value read-only sources:

* AWS Security Hub and AWS Config posture;
* Microsoft Defender for Cloud and Azure Policy posture;
* Google Cloud Security Command Center findings;
* GitHub code, secret, or dependency security alerts; and
* Okta policy posture.

Provider payloads and continuation tokens are transient.  Only normalized
status/reason pairs and SHA-256 digests cross the collector contract.  A
deployment manifest binds every source to one tenant, approved collector
definition, enrollment, credential *reference*, asset scope, provider origin,
and control-to-provider selector map.  The scheduler resolves that manifest at
execution time and the adapter rechecks the complete binding before I/O.

Most providers expose these list operations as HTTPS GET.  AWS Security Hub,
AWS Config, and Azure Policy use provider-defined POST query protocols; only
their exact, enumerated non-mutating operations are admitted here.  No adapter
contains a create, update, delete, remediate, acknowledge, or dismiss path.

These collectors report technical observations.  They do not infer legal
compliance, certification, estate completeness, or provider acceptance.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Protocol
from urllib.parse import parse_qsl, quote, urlsplit

from .paths import canonical_tenant_id
from .trc_evidence_collectors import (
    CollectionRequest,
    CollectorRegistry,
    ControlEvidence,
    EvidenceCollectorError,
    EvidenceCollectorValidationError,
    EvidencePage,
    LocalSoc2Collector,
    validate_request,
)

AWS_SECURITY_HUB = "aws_security_hub"
AWS_CONFIG = "aws_config"
AZURE_DEFENDER = "azure_defender"
AZURE_POLICY = "azure_policy"
GCP_SECURITY_COMMAND_CENTER = "gcp_security_command_center"
GITHUB_SECURITY = "github_security"
OKTA_POSTURE = "okta_posture"

AWS_SECURITY_HUB_COLLECTOR = "aws_security_hub_v1"
AWS_CONFIG_COLLECTOR = "aws_config_posture_v1"
AZURE_DEFENDER_COLLECTOR = "azure_defender_v1"
AZURE_POLICY_COLLECTOR = "azure_policy_posture_v1"
GCP_SCC_COLLECTOR = "gcp_security_command_center_v1"
GITHUB_SECURITY_COLLECTOR = "github_security_v1"
OKTA_POSTURE_COLLECTOR = "okta_posture_v1"

STOCK_PROVIDERS = frozenset(
    {
        AWS_SECURITY_HUB,
        AWS_CONFIG,
        AZURE_DEFENDER,
        AZURE_POLICY,
        GCP_SECURITY_COMMAND_CENTER,
        GITHUB_SECURITY,
        OKTA_POSTURE,
    }
)
STOCK_COLLECTOR_IDS = (
    AWS_CONFIG_COLLECTOR,
    AWS_SECURITY_HUB_COLLECTOR,
    AZURE_DEFENDER_COLLECTOR,
    AZURE_POLICY_COLLECTOR,
    GCP_SCC_COLLECTOR,
    GITHUB_SECURITY_COLLECTOR,
    OKTA_POSTURE_COLLECTOR,
)

NETWORK_IO = True
READ_ONLY = True
RAW_PROVIDER_PAYLOAD_PERSISTED = False
PROVIDER_CONTINUATION_PERSISTED = False
COMPLIANCE_INFERRED = False
CERTIFICATION_ASSERTED = False
LIVE_PROVIDER_ACCEPTANCE_VERIFIED = False

_PROVIDER_TO_COLLECTOR = {
    AWS_SECURITY_HUB: AWS_SECURITY_HUB_COLLECTOR,
    AWS_CONFIG: AWS_CONFIG_COLLECTOR,
    AZURE_DEFENDER: AZURE_DEFENDER_COLLECTOR,
    AZURE_POLICY: AZURE_POLICY_COLLECTOR,
    GCP_SECURITY_COMMAND_CENTER: GCP_SCC_COLLECTOR,
    GITHUB_SECURITY: GITHUB_SECURITY_COLLECTOR,
    OKTA_POSTURE: OKTA_POSTURE_COLLECTOR,
}
_AWS_PROVIDERS = frozenset({AWS_SECURITY_HUB, AWS_CONFIG})
_ENV_RE = re.compile(r"[A-Z][A-Z0-9_]{1,127}\Z")
_ID_RE = re.compile(r"[a-z][a-z0-9_.-]{0,95}\Z")
_CONTROL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_REGION_RE = re.compile(r"[a-z]{2}(?:-gov)?-[a-z]+-\d\Z")
_AWS_ACCOUNT_RE = re.compile(r"\d{12}\Z")
_AZURE_SUBSCRIPTION_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
_GCP_PARENT_RE = re.compile(
    r"(?:organizations/\d{1,32}|folders/\d{1,32}|projects/[a-z][a-z0-9-]{4,61}[a-z0-9])\Z"
)
_GITHUB_SCOPE_RE = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}[A-Za-z0-9])?"
    r"(?:/[A-Za-z0-9_.-]{1,100})?\Z"
)
_OKTA_SCOPE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_HOST_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
    r"[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
    r"[A-Za-z0-9])?\Z"
)
_HEADER_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_REASON_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_GITHUB_STREAMS = frozenset({"code_scanning", "dependabot", "secret_scanning"})
_OKTA_POLICY_TYPES = frozenset(
    {
        "ACCESS_POLICY",
        "IDP_DISCOVERY",
        "MFA_ENROLL",
        "OKTA_SIGN_ON",
        "PASSWORD",
    }
)
_MAX_SECRET_BYTES = 32 * 1024
_MAX_JSON_DEPTH = 32
_MAX_CURSOR_BYTES = 8 * 1024
_MAX_SOURCE_REF_BYTES = 2 * 1024
_MAX_CURSOR_STATES = 4_096
_MAX_PAGE_BYTES = 1024 * 1024
_MAX_TOTAL_BYTES = 16 * 1024 * 1024


class StockEvidenceCollectorError(EvidenceCollectorError):
    """Base sanitized stock-collector error."""


class StockEvidenceConfigurationError(StockEvidenceCollectorError, ValueError):
    """A deployment source or transport is not safely configured."""


class StockEvidenceProtocolError(StockEvidenceCollectorError):
    """A provider response violated the bounded read contract."""


class StockEvidenceAccessDenied(StockEvidenceCollectorError):
    """The deployment credential cannot read the configured source."""


class StockEvidenceUnavailable(StockEvidenceCollectorError):
    """The provider is unavailable or asked the scheduler to retry."""


def _canonical(value: object, *, maximum: int = _MAX_PAGE_BYTES) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise StockEvidenceProtocolError("provider_value_not_canonical") from exc
    if len(encoded) > maximum:
        raise StockEvidenceProtocolError("provider_value_too_large")
    return encoded


def _sha256(value: object, *, maximum: int = _MAX_PAGE_BYTES) -> str:
    return hashlib.sha256(_canonical(value, maximum=maximum)).hexdigest()


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise StockEvidenceConfigurationError(f"{label} is invalid")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise StockEvidenceConfigurationError(f"{label} is invalid")
    return value


def _control(value: object) -> str:
    if not isinstance(value, str) or _CONTROL_RE.fullmatch(value) is None:
        raise StockEvidenceConfigurationError("control_ref is invalid")
    return value


def _bounded_int(value: object, label: str, minimum: int, maximum: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= maximum
    ):
        raise StockEvidenceConfigurationError(f"{label} is outside its bound")
    return value


def _bounded_float(value: object, label: str, minimum: float, maximum: float) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or not minimum <= float(value) <= maximum
    ):
        raise StockEvidenceConfigurationError(f"{label} is outside its bound")
    return float(value)


def _source_ref(value: object) -> str:
    if not isinstance(value, str) or not value or _HEADER_CONTROL_RE.search(value):
        raise StockEvidenceConfigurationError("provider source reference is invalid")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise StockEvidenceConfigurationError(
            "provider source reference is invalid"
        ) from None
    if size > _MAX_SOURCE_REF_BYTES:
        raise StockEvidenceConfigurationError("provider source reference is invalid")
    return value


def _exact_origin(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 2_048:
        raise StockEvidenceConfigurationError("provider origin must be exact HTTPS")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise StockEvidenceConfigurationError(
            "provider origin must be exact HTTPS"
        ) from None
    host = (parsed.hostname or "").lower().rstrip(".")
    if (
        parsed.scheme != "https"
        or _HOST_RE.fullmatch(host) is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or (port is not None and port != 443)
    ):
        raise StockEvidenceConfigurationError("provider origin must be exact HTTPS")
    return f"https://{host}"


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
        raise StockEvidenceConfigurationError("provider path is invalid")
    return value


def _query(value: Sequence[tuple[str, str]]) -> tuple[tuple[str, str], ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence) or len(value) > 32:
        raise StockEvidenceConfigurationError("provider query is invalid")
    result: list[tuple[str, str]] = []
    for pair in value:
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise StockEvidenceConfigurationError("provider query is invalid")
        key, item = pair
        if (
            not isinstance(key, str)
            or not 1 <= len(key) <= 128
            or not isinstance(item, str)
            or len(item) > 8_192
            or _HEADER_CONTROL_RE.search(key)
            or _HEADER_CONTROL_RE.search(item)
        ):
            raise StockEvidenceConfigurationError("provider query is invalid")
        result.append((key, item))
    return tuple(result)


def _url(origin: str, path: str, query: Sequence[tuple[str, str]]) -> str:
    exact = _exact_origin(origin)
    fixed_path = _path(path)
    pairs = _query(query)
    encoded = "&".join(
        f"{quote(key, safe='-_.~')}={quote(value, safe='-_.~')}"
        for key, value in sorted(pairs)
    )
    result = exact + fixed_path + (f"?{encoded}" if encoded else "")
    parsed = urlsplit(result)
    if f"{parsed.scheme}://{parsed.hostname}" != exact:
        raise StockEvidenceConfigurationError("provider URL crossed its exact origin")
    return result


def stock_tenant_sha256(tenant_id: str) -> str:
    """Return the tenant digest used by ``ContinuousEvidenceStore``."""

    tenant = canonical_tenant_id(tenant_id)
    return _sha256(
        {
            "schema": "lightwork.trc-evidence-tenant.v1",
            "tenant_id": tenant,
        }
    )


@dataclass(frozen=True, slots=True)
class ProviderControlBinding:
    """Exact control-to-provider selector mapping approved by deployment."""

    control_ref: str
    source_ref: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "control_ref", _control(self.control_ref))
        object.__setattr__(self, "source_ref", _source_ref(self.source_ref))


@dataclass(frozen=True, slots=True)
class StockCollectorLimits:
    """Finite page, response, record, and wall-time bounds."""

    timeout_seconds: float = 15.0
    max_elapsed_seconds: float = 120.0
    max_response_bytes: int = 256 * 1024
    page_size: int = 100
    max_pages: int = 50
    max_records: int = 10_000

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "timeout_seconds",
            _bounded_float(self.timeout_seconds, "timeout_seconds", 0.1, 60.0),
        )
        object.__setattr__(
            self,
            "max_elapsed_seconds",
            _bounded_float(
                self.max_elapsed_seconds,
                "max_elapsed_seconds",
                1.0,
                900.0,
            ),
        )
        _bounded_int(
            self.max_response_bytes,
            "max_response_bytes",
            1_024,
            _MAX_PAGE_BYTES,
        )
        _bounded_int(self.page_size, "page_size", 1, 100)
        _bounded_int(self.max_pages, "max_pages", 1, 50)
        # The final per-control digest includes every admitted record digest.
        # Ten thousand entries remain below EvidencePage's 1 MiB canonical
        # bound even when every record maps to one control.
        _bounded_int(self.max_records, "max_records", 1, 10_000)
        if self.max_pages * self.max_response_bytes > _MAX_TOTAL_BYTES:
            raise StockEvidenceConfigurationError(
                "page and response limits exceed the authority byte bound"
            )


def _validate_provider_origin(provider: str, origin: str, region: str | None) -> None:
    host = urlsplit(origin).hostname or ""
    if provider == AWS_SECURITY_HUB:
        expected = f"securityhub.{region}.amazonaws.com"
    elif provider == AWS_CONFIG:
        expected = f"config.{region}.amazonaws.com"
    elif provider in {AZURE_DEFENDER, AZURE_POLICY}:
        expected = "management.azure.com"
    elif provider == GCP_SECURITY_COMMAND_CENTER:
        expected = "securitycenter.googleapis.com"
    elif provider == GITHUB_SECURITY:
        expected = "api.github.com"
    else:
        okta_suffixes = (".okta.com", ".okta-emea.com", ".oktapreview.com")
        if not host.endswith(okta_suffixes) or host.count(".") < 2:
            raise StockEvidenceConfigurationError("Okta origin is not admitted")
        return
    if host != expected:
        raise StockEvidenceConfigurationError("provider origin is not admitted")


@dataclass(frozen=True, slots=True, repr=False)
class StockCollectorSource:
    """Deployment-held source manifest for one governed enrollment."""

    tenant_id: str = field(repr=False)
    enrollment_id: str
    definition_id: str
    definition_version: int
    definition_integrity_sha256: str
    collector_key_id: str
    capability_revision: int
    provider: str
    origin: str
    scope_ref: str = field(repr=False)
    credential_env: str
    bindings: tuple[ProviderControlBinding, ...]
    region: str | None = None
    stream: str | None = None
    limits: StockCollectorLimits = field(default_factory=StockCollectorLimits)
    authorizing_principal: str | None = field(default=None, repr=False)
    workspace_authority: str | None = None

    def __post_init__(self) -> None:  # noqa: C901 - closed provider option dispatch
        object.__setattr__(self, "tenant_id", canonical_tenant_id(self.tenant_id))
        object.__setattr__(self, "enrollment_id", _identifier(self.enrollment_id, "enrollment_id"))
        object.__setattr__(self, "definition_id", _identifier(self.definition_id, "definition_id"))
        _bounded_int(self.definition_version, "definition_version", 1, 2**31 - 1)
        _digest(self.definition_integrity_sha256, "definition_integrity_sha256")
        object.__setattr__(
            self,
            "collector_key_id",
            _identifier(self.collector_key_id, "collector_key_id"),
        )
        _bounded_int(self.capability_revision, "capability_revision", 1, 2**31 - 1)
        if self.provider not in STOCK_PROVIDERS:
            raise StockEvidenceConfigurationError("stock provider is invalid")
        object.__setattr__(self, "origin", _exact_origin(self.origin))
        from .privacy_discovery_credentials import CONNECTION_PATTERN

        saved = isinstance(self.credential_env, str) and re.fullmatch(CONNECTION_PATTERN, self.credential_env)
        if not isinstance(self.credential_env, str) or (_ENV_RE.fullmatch(self.credential_env) is None and not saved):
            raise StockEvidenceConfigurationError("credential env reference is invalid")
        if saved and (not isinstance(self.authorizing_principal, str) or
                      not 1 <= len(self.authorizing_principal) <= 256 or
                      any(ord(char) < 32 for char in self.authorizing_principal)):
            raise StockEvidenceConfigurationError("saved account requires its authorizing principal")
        if not saved and self.authorizing_principal is not None:
            raise StockEvidenceConfigurationError("legacy credentials cannot carry a saved account owner")
        if saved and self.workspace_authority not in {"principal_selection", "principal_isolation", "operator_floor"}:
            raise StockEvidenceConfigurationError("saved account workspace authority is invalid")
        if not saved and self.workspace_authority is not None:
            raise StockEvidenceConfigurationError("legacy credentials cannot carry saved workspace authority")
        if not isinstance(self.bindings, tuple) or not 1 <= len(self.bindings) <= 250:
            raise StockEvidenceConfigurationError("control bindings are outside their bound")
        if any(not isinstance(item, ProviderControlBinding) for item in self.bindings):
            raise StockEvidenceConfigurationError("control binding has the wrong type")
        controls = tuple(item.control_ref for item in self.bindings)
        sources = tuple(item.source_ref for item in self.bindings)
        if len(set(controls)) != len(controls) or len(set(sources)) != len(sources):
            raise StockEvidenceConfigurationError("control bindings must be unique")
        object.__setattr__(self, "bindings", tuple(sorted(self.bindings, key=lambda item: item.control_ref)))
        object.__setattr__(self, "scope_ref", _source_ref(self.scope_ref))
        if not isinstance(self.limits, StockCollectorLimits):
            raise StockEvidenceConfigurationError("collector limits are invalid")

        region = self.region
        stream = self.stream
        if self.provider in _AWS_PROVIDERS:
            if not isinstance(region, str) or _REGION_RE.fullmatch(region) is None:
                raise StockEvidenceConfigurationError("AWS region is invalid")
            if _AWS_ACCOUNT_RE.fullmatch(self.scope_ref) is None:
                raise StockEvidenceConfigurationError("AWS account scope is invalid")
            if stream is not None:
                raise StockEvidenceConfigurationError("AWS source stream is invalid")
            if self.provider == AWS_CONFIG and len(self.bindings) > 25:
                raise StockEvidenceConfigurationError(
                    "AWS Config admits at most 25 exact rule bindings"
                )
        elif self.provider in {AZURE_DEFENDER, AZURE_POLICY}:
            if region is not None or stream is not None:
                raise StockEvidenceConfigurationError("Azure source options are invalid")
            if _AZURE_SUBSCRIPTION_RE.fullmatch(self.scope_ref.lower()) is None:
                raise StockEvidenceConfigurationError("Azure subscription scope is invalid")
            object.__setattr__(self, "scope_ref", self.scope_ref.lower())
        elif self.provider == GCP_SECURITY_COMMAND_CENTER:
            if region is not None or stream is not None:
                raise StockEvidenceConfigurationError("GCP source options are invalid")
            if _GCP_PARENT_RE.fullmatch(self.scope_ref) is None:
                raise StockEvidenceConfigurationError("GCP SCC parent scope is invalid")
        elif self.provider == GITHUB_SECURITY:
            if region is not None or stream not in _GITHUB_STREAMS:
                raise StockEvidenceConfigurationError("GitHub source options are invalid")
            if _GITHUB_SCOPE_RE.fullmatch(self.scope_ref) is None:
                raise StockEvidenceConfigurationError("GitHub scope is invalid")
        else:
            if region is not None or stream not in _OKTA_POLICY_TYPES:
                raise StockEvidenceConfigurationError("Okta source options are invalid")
            if _OKTA_SCOPE_RE.fullmatch(self.scope_ref) is None:
                raise StockEvidenceConfigurationError("Okta scope is invalid")
        _validate_provider_origin(self.provider, self.origin, region)

    @property
    def collector_id(self) -> str:
        return _PROVIDER_TO_COLLECTOR[self.provider]

    @property
    def tenant_sha256(self) -> str:
        return stock_tenant_sha256(self.tenant_id)

    @property
    def asset_scope_sha256(self) -> str:
        return _sha256(
            {
                "schema": "lightwork.trc-stock-asset-scope.v1",
                "tenant_sha256": self.tenant_sha256,
                "provider": self.provider,
                "origin": self.origin,
                "scope_ref": self.scope_ref,
                "region": self.region,
                "stream": self.stream,
            }
        )

    @property
    def credential_profile_sha256(self) -> str:
        profile = {
                "schema": "lightwork.trc-stock-credential-profile.v1",
                "tenant_sha256": self.tenant_sha256,
                "provider": self.provider,
                "credential_env": self.credential_env,
            }
        if self.authorizing_principal is not None:
            profile["authorizing_principal"] = self.authorizing_principal
            profile["workspace_authority"] = self.workspace_authority
        return _sha256(profile)

    @property
    def source_revision_sha256(self) -> str:
        return _sha256(
            {
                "schema": "lightwork.trc-stock-source-revision.v1",
                "tenant_sha256": self.tenant_sha256,
                "enrollment_id": self.enrollment_id,
                "definition_id": self.definition_id,
                "definition_version": self.definition_version,
                "definition_integrity_sha256": self.definition_integrity_sha256,
                "collector_id": self.collector_id,
                "collector_key_id": self.collector_key_id,
                "capability_revision": self.capability_revision,
                "asset_scope_sha256": self.asset_scope_sha256,
                "credential_profile_sha256": self.credential_profile_sha256,
                "bindings": [asdict(item) for item in self.bindings],
                "limits": asdict(self.limits),
            }
        )


def managed_source_from_definition(tenant_id: str, definition: object) -> StockCollectorSource:
    """Project the exact manifest signed by the native collector definition."""
    manifest = getattr(definition, "source_manifest", None)
    keys = {"label", "provider", "origin", "scope_ref", "credential_env", "bindings",
            "region", "stream", "authorizing_principal", "background_authorized", "check_labels", "workspace_authority"}
    if (not isinstance(manifest, dict) or not keys.issubset(manifest) or set(manifest) - (keys | {"control_labels"}) or
            manifest.get("background_authorized") is not True or
            not isinstance(manifest.get("label"), str) or
            not 1 <= len(manifest["label"].strip()) <= 100 or
            any(ord(char) < 32 for char in manifest["label"])):
        raise StockEvidenceConfigurationError("managed source metadata is invalid")
    bindings = manifest["bindings"]
    if not isinstance(bindings, list) or any(not isinstance(item, dict) or
                                           set(item) != {"control_ref", "source_ref"} for item in bindings):
        raise StockEvidenceConfigurationError("managed source bindings are invalid")
    labels = manifest["check_labels"]
    if (not isinstance(labels, dict) or set(labels) != {item["source_ref"] for item in bindings} or
            any(not isinstance(label, str) or not 1 <= len(label) <= 200 or
                any(ord(char) < 32 for char in label) for label in labels.values())):
        raise StockEvidenceConfigurationError("managed source check labels are invalid")
    controls = manifest.get("control_labels")
    if controls is not None and (not isinstance(controls, dict) or
            set(controls) != {item["control_ref"] for item in bindings} or
            any(not isinstance(label, str) or not 1 <= len(label) <= 500 or
                any(ord(char) < 32 for char in label) for label in controls.values())):
        raise StockEvidenceConfigurationError("managed source control labels are invalid")
    from .privacy_discovery_credentials import CONNECTION_PATTERN

    if not isinstance(manifest["credential_env"], str) or not re.fullmatch(CONNECTION_PATTERN, manifest["credential_env"]):
        raise StockEvidenceConfigurationError("managed source requires a saved account")
    return StockCollectorSource(
        tenant_id=tenant_id,
        enrollment_id=f"{definition.definition_id}.v{definition.version}",
        definition_id=definition.definition_id, definition_version=definition.version,
        definition_integrity_sha256=definition.integrity_sha256,
        collector_key_id=definition.collector_key_id, capability_revision=definition.capability_revision,
        provider=manifest["provider"], origin=manifest["origin"], scope_ref=manifest["scope_ref"],
        credential_env=manifest["credential_env"],
        bindings=tuple(ProviderControlBinding(**item) for item in bindings),
        region=manifest["region"], stream=manifest["stream"],
        authorizing_principal=manifest["authorizing_principal"],
        workspace_authority=manifest["workspace_authority"],
    )


@dataclass(frozen=True, slots=True, repr=False)
class StockCollectorCredentialHandle:
    """Ephemeral, exact enrollment-revision authority passed by the scheduler."""

    source: StockCollectorSource = field(repr=False)
    enrollment_revision: int

    def __post_init__(self) -> None:
        if not isinstance(self.source, StockCollectorSource):
            raise StockEvidenceConfigurationError("stock source handle is invalid")
        _bounded_int(self.enrollment_revision, "enrollment_revision", 1, 2**31 - 1)


@dataclass(frozen=True, slots=True, repr=False)
class StockEvidenceHTTPRequest:
    """Credential-reference-only request accepted by the pinned transport."""

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
    aws_service: str | None = None
    aws_region: str | None = None
    authorizing_principal: str | None = field(default=None, repr=False)
    enrollment_id: str | None = None
    enrollment_revision: int | None = None
    source_revision_sha256: str | None = None

    def __post_init__(self) -> None:
        if self.provider not in STOCK_PROVIDERS:
            raise StockEvidenceConfigurationError("request provider is invalid")
        object.__setattr__(self, "origin", _exact_origin(self.origin))
        object.__setattr__(self, "path", _path(self.path))
        object.__setattr__(self, "query", _query(self.query))
        from .privacy_discovery_credentials import CONNECTION_PATTERN

        saved = isinstance(self.credential_env, str) and re.fullmatch(CONNECTION_PATTERN, self.credential_env)
        if not isinstance(self.credential_env, str) or (_ENV_RE.fullmatch(self.credential_env) is None and not saved):
            raise StockEvidenceConfigurationError("credential env reference is invalid")
        if saved and not self.authorizing_principal:
            raise StockEvidenceConfigurationError("saved account read lacks an authorizing principal")
        _bounded_float(self.deadline, "deadline", 0.001, 100_000_000_000.0)
        _bounded_float(self.timeout_seconds, "timeout_seconds", 0.1, 60.0)
        _bounded_int(
            self.max_response_bytes,
            "max_response_bytes",
            1_024,
            _MAX_PAGE_BYTES,
        )
        if not isinstance(self.headers, Mapping) or len(self.headers) > 16:
            raise StockEvidenceConfigurationError("request headers are invalid")
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
                raise StockEvidenceConfigurationError("request header is invalid")
        if self.body is not None and (
            not isinstance(self.body, bytes) or len(self.body) > 256 * 1024
        ):
            raise StockEvidenceConfigurationError("request body is invalid")

        if self.provider in _AWS_PROVIDERS:
            target = self.headers.get("X-Amz-Target")
            admitted = {
                AWS_SECURITY_HUB: "AWSSecurityHub_20180608.GetFindings",
                AWS_CONFIG: "StarlingDoveService.DescribeComplianceByConfigRule",
            }
            if (
                self.method != "POST"
                or self.path != "/"
                or target != admitted[self.provider]
                or self.aws_service
                != ("securityhub" if self.provider == AWS_SECURITY_HUB else "config")
                or not isinstance(self.aws_region, str)
                or _REGION_RE.fullmatch(self.aws_region) is None
                or self.body is None
            ):
                raise StockEvidenceConfigurationError("AWS read operation is not admitted")
        elif self.provider == AZURE_POLICY:
            expected_prefix = "/subscriptions/"
            expected_suffix = (
                "/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults"
            )
            if (
                self.method != "POST"
                or not self.path.startswith(expected_prefix)
                or not self.path.endswith(expected_suffix)
                or self.body is None
                or self.aws_service is not None
                or self.aws_region is not None
            ):
                raise StockEvidenceConfigurationError(
                    "Azure Policy read operation is not admitted"
                )
        elif (
            self.method != "GET"
            or self.body is not None
            or self.aws_service is not None
            or self.aws_region is not None
        ):
            raise StockEvidenceConfigurationError("provider operation must be GET-only")

    @property
    def url(self) -> str:
        return _url(self.origin, self.path, self.query)


@dataclass(frozen=True, slots=True, repr=False)
class StockEvidenceHTTPResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.status_code, int)
            or isinstance(self.status_code, bool)
            or not 100 <= self.status_code <= 599
            or not isinstance(self.headers, Mapping)
            or not isinstance(self.body, bytes)
        ):
            raise StockEvidenceProtocolError("provider_response_invalid")


class StockEvidenceHTTPTransport(Protocol):
    """Transport owns credential resolution and refuses redirects."""

    def request(self, request: StockEvidenceHTTPRequest) -> StockEvidenceHTTPResponse: ...


CredentialValueResolver = Callable[[str], str | None]


def _credential(reference: str, resolver: CredentialValueResolver) -> str:
    try:
        value = resolver(reference)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise StockEvidenceAccessDenied("credential_resolution_failed") from None
    if not isinstance(value, str):
        raise StockEvidenceAccessDenied("credential_unavailable")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise StockEvidenceAccessDenied("credential_invalid") from None
    if not 1 <= len(encoded) <= _MAX_SECRET_BYTES or _HEADER_CONTROL_RE.search(value):
        raise StockEvidenceAccessDenied("credential_invalid")
    return value


def _credential_object(value: str) -> Mapping[str, Any]:
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, RecursionError):
        raise StockEvidenceAccessDenied("credential_invalid") from None
    if not isinstance(parsed, Mapping) or len(parsed) > 8:
        raise StockEvidenceAccessDenied("credential_invalid")
    return parsed


def _token_credential(value: str, *, key: str = "bearer_token") -> str:
    token: object = value
    if value.lstrip().startswith("{"):
        parsed = _credential_object(value)
        if set(parsed) != {key}:
            raise StockEvidenceAccessDenied("credential_invalid")
        token = parsed.get(key)
    if (
        not isinstance(token, str)
        or not 8 <= len(token) <= 16_384
        or _HEADER_CONTROL_RE.search(token)
    ):
        raise StockEvidenceAccessDenied("credential_invalid")
    return token


def _aws_signing_headers(
    request: StockEvidenceHTTPRequest,
    credential: str,
    *,
    now: float,
) -> Mapping[str, str]:
    parsed = _credential_object(credential)
    allowed = {"access_key_id", "secret_access_key", "session_token"}
    if set(parsed) - allowed or not {
        "access_key_id",
        "secret_access_key",
    }.issubset(parsed):
        raise StockEvidenceAccessDenied("credential_invalid")
    access = parsed.get("access_key_id")
    secret = parsed.get("secret_access_key")
    session = parsed.get("session_token")
    if (
        not isinstance(access, str)
        or not 16 <= len(access) <= 128
        or not isinstance(secret, str)
        or not 16 <= len(secret) <= 512
        or _HEADER_CONTROL_RE.search(access)
        or _HEADER_CONTROL_RE.search(secret)
        or (
            session is not None
            and (
                not isinstance(session, str)
                or not 16 <= len(session) <= 8_192
                or _HEADER_CONTROL_RE.search(session)
            )
        )
    ):
        raise StockEvidenceAccessDenied("credential_invalid")
    if not math.isfinite(now) or now <= 0:
        raise StockEvidenceConfigurationError("transport clock is invalid")
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now))
    day = stamp[:8]
    host = urlsplit(request.origin).hostname or ""
    signed: dict[str, str] = {
        "content-type": request.headers.get("Content-Type", "application/x-amz-json-1.1"),
        "host": host,
        "x-amz-date": stamp,
        "x-amz-target": request.headers["X-Amz-Target"],
    }
    if session is not None:
        signed["x-amz-security-token"] = session
    signed_names = ";".join(sorted(signed))
    canonical_headers = "".join(f"{key}:{signed[key].strip()}\n" for key in sorted(signed))
    canonical_query = "&".join(
        f"{quote(key, safe='-_.~')}={quote(value, safe='-_.~')}"
        for key, value in sorted(request.query)
    )
    body = request.body or b""
    canonical_request = "\n".join(
        (
            request.method,
            request.path,
            canonical_query,
            canonical_headers,
            signed_names,
            hashlib.sha256(body).hexdigest(),
        )
    )
    service = request.aws_service or ""
    region = request.aws_region or ""
    scope = f"{day}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        (
            "AWS4-HMAC-SHA256",
            stamp,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        )
    )

    def sign(key: bytes, message: str) -> bytes:
        return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()

    date_key = sign(("AWS4" + secret).encode("utf-8"), day)
    region_key = sign(date_key, region)
    service_key = sign(region_key, service)
    signing_key = sign(service_key, "aws4_request")
    signature = hmac.new(
        signing_key,
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    result = {
        "Content-Type": signed["content-type"],
        "X-Amz-Date": stamp,
        "X-Amz-Target": signed["x-amz-target"],
        "Authorization": (
            f"AWS4-HMAC-SHA256 Credential={access}/{scope}, "
            f"SignedHeaders={signed_names}, Signature={signature}"
        ),
    }
    if session is not None:
        result["X-Amz-Security-Token"] = session
    return result


class PinnedStockEvidenceHTTPTransport:
    """DNS-pinned, redirect-free, bounded transport with ephemeral secrets."""

    def __init__(
        self,
        *,
        credential_resolver: CredentialValueResolver | None = None,
        clock: Callable[[], float] = time.time,
        authorize: Callable[[StockEvidenceHTTPRequest], None] | None = None,
        request_credential_resolver: Callable[[StockEvidenceHTTPRequest], str] | None = None,
    ) -> None:
        self._credential_resolver = credential_resolver or os.environ.get
        self._clock = clock
        self._authorize = authorize
        self._request_credential_resolver = request_credential_resolver
        if not callable(self._credential_resolver) or not callable(self._clock):
            raise StockEvidenceConfigurationError("transport dependencies are invalid")

    def __repr__(self) -> str:
        return "PinnedStockEvidenceHTTPTransport(credential_owner='ephemeral')"

    def _headers(self, request: StockEvidenceHTTPRequest, now: float) -> dict[str, str]:
        if request.credential_env.startswith("connection:"):
            if self._authorize is None or self._request_credential_resolver is None:
                raise StockEvidenceAccessDenied("saved_account_authority_unavailable")
            self._authorize(request)
            secret = self._request_credential_resolver(request)
        else:
            secret = _credential(request.credential_env, self._credential_resolver)
        if request.provider in _AWS_PROVIDERS:
            auth = dict(_aws_signing_headers(request, secret, now=now))
        elif request.provider == OKTA_POSTURE:
            auth = {"Authorization": "SSWS " + _token_credential(secret, key="api_token")}
        else:
            auth = {"Authorization": "Bearer " + _token_credential(secret)}
        return {
            "Accept": "application/json",
            "User-Agent": "Lightwork-TRC-Evidence/1",
            **dict(request.headers),
            **auth,
        }

    def _read_body(self, response, request: StockEvidenceHTTPRequest) -> bytes:
        chunks: list[bytes] = []
        observed = 0
        iterator = iter(response.iter_bytes())
        while True:
            self._admit(request)
            try:
                chunk = next(iterator)
            except StopIteration:
                break
            observed += len(chunk)
            if observed > request.max_response_bytes:
                raise StockEvidenceProtocolError("provider_response_too_large")
            chunks.append(chunk)
        return b"".join(chunks)

    def _admit(self, request: StockEvidenceHTTPRequest) -> None:
        if float(self._clock()) >= request.deadline:
            raise StockEvidenceUnavailable("provider_deadline_exhausted")
        if self._authorize is not None:
            self._authorize(request)
        if float(self._clock()) >= request.deadline:
            raise StockEvidenceUnavailable("provider_deadline_exhausted")

    def request(self, request: StockEvidenceHTTPRequest) -> StockEvidenceHTTPResponse:
        if not isinstance(request, StockEvidenceHTTPRequest):
            raise StockEvidenceConfigurationError("transport request is invalid")
        try:
            now = float(self._clock())
        except (TypeError, ValueError, OverflowError):
            raise StockEvidenceConfigurationError("transport clock is invalid") from None
        remaining = request.deadline - now
        if not math.isfinite(remaining) or remaining <= 0:
            raise StockEvidenceUnavailable("provider_deadline_exhausted")
        timeout = min(request.timeout_seconds, remaining)
        url = request.url
        self._admit(request)
        try:
            from .enterprise import enterprise_egress_denial
            from .tools._ssrf import BlockedHost, safe_client

            denial = enterprise_egress_denial(
                url,
                tool=f"trc_continuous_evidence.{request.provider}",
            )
            if denial:
                raise StockEvidenceAccessDenied("enterprise_egress_denied")
            self._admit(request)
            with safe_client(url, timeout=timeout, follow_redirects=False) as client:
                # DNS and connection admission may have waited. Read the exact
                # current account again before any credential leaves the process.
                self._admit(request)
                headers = self._headers(request, float(self._clock()))
                self._admit(request)
                with client.stream(
                    request.method,
                    url,
                    headers=headers,
                    content=request.body,
                    follow_redirects=False,
                    timeout=min(request.timeout_seconds, request.deadline - float(self._clock())),
                ) as response:
                    if 300 <= response.status_code < 400:
                        raise StockEvidenceProtocolError("provider_redirect_rejected")
                    declared = response.headers.get("content-length")
                    if declared is not None:
                        try:
                            size = int(declared)
                        except ValueError:
                            raise StockEvidenceProtocolError(
                                "provider_content_length_invalid"
                            ) from None
                        if size < 0 or size > request.max_response_bytes:
                            raise StockEvidenceProtocolError("provider_response_too_large")
                    body = self._read_body(response, request)
                    kept_headers = {
                        key.lower(): value
                        for key, value in response.headers.items()
                        if key.lower()
                        in {
                            "content-length",
                            "content-type",
                            "etag",
                            "link",
                            "retry-after",
                            "x-amzn-requestid",
                            "x-github-request-id",
                            "x-ms-request-id",
                        }
                    }
                    status = int(response.status_code)
        except (KeyboardInterrupt, SystemExit):
            raise
        except (StockEvidenceCollectorError, StockEvidenceConfigurationError):
            raise
        except BlockedHost:
            raise StockEvidenceAccessDenied("provider_ssrf_blocked") from None
        except Exception as exc:
            try:
                import httpx

                retryable = isinstance(exc, (httpx.TimeoutException, httpx.TransportError))
            except Exception:
                retryable = "timeout" in type(exc).__name__.lower()
            if retryable:
                raise StockEvidenceUnavailable("provider_transport_failure") from None
            raise StockEvidenceProtocolError("provider_transport_failure") from None
        if status in {401, 403}:
            raise StockEvidenceAccessDenied("provider_access_denied")
        if status in {408, 425, 429} or 500 <= status <= 599:
            raise StockEvidenceUnavailable("provider_retryable_response")
        if status != 200:
            raise StockEvidenceProtocolError("provider_response_rejected")
        self._admit(request)
        return StockEvidenceHTTPResponse(status, kept_headers, body)


def _json_value(body: bytes) -> object:
    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise StockEvidenceProtocolError("provider_json_duplicate_key")
            result[key] = value
        return result

    try:
        value = json.loads(body.decode("utf-8"), object_pairs_hook=object_pairs)
    except StockEvidenceProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise StockEvidenceProtocolError("provider_response_not_json") from None

    def check(item: object, depth: int = 0) -> None:
        if depth > _MAX_JSON_DEPTH:
            raise StockEvidenceProtocolError("provider_json_too_deep")
        if isinstance(item, Mapping):
            if len(item) > 20_000:
                raise StockEvidenceProtocolError("provider_json_too_wide")
            for key, child in item.items():
                if not isinstance(key, str) or len(key) > 4_096:
                    raise StockEvidenceProtocolError("provider_json_key_invalid")
                check(child, depth + 1)
        elif isinstance(item, list):
            if len(item) > 100_000:
                raise StockEvidenceProtocolError("provider_json_too_wide")
            for child in item:
                check(child, depth + 1)
        elif isinstance(item, str):
            if len(item.encode("utf-8")) > _MAX_PAGE_BYTES:
                raise StockEvidenceProtocolError("provider_json_string_too_large")
        elif isinstance(item, float) and not math.isfinite(item):
            raise StockEvidenceProtocolError("provider_json_value_invalid")
        elif item is not None and not isinstance(item, (bool, int, float)):
            raise StockEvidenceProtocolError("provider_json_value_invalid")

    check(value)
    return value


def _require_json_content_type(headers: Mapping[str, str]) -> None:
    value = headers.get("content-type")
    if not isinstance(value, str) or len(value) > 256:
        raise StockEvidenceProtocolError("provider_content_type_invalid")
    media_type = value.split(";", 1)[0].strip().lower()
    if media_type not in {
        "application/json",
        "application/x-amz-json-1.0",
        "application/x-amz-json-1.1",
    } and not media_type.endswith("+json"):
        raise StockEvidenceProtocolError("provider_content_type_invalid")


def _json_object(body: bytes) -> Mapping[str, Any]:
    value = _json_value(body)
    if not isinstance(value, Mapping):
        raise StockEvidenceProtocolError("provider_response_not_object")
    return value


def _json_array(body: bytes) -> list[Any]:
    value = _json_value(body)
    if not isinstance(value, list):
        raise StockEvidenceProtocolError("provider_response_not_array")
    return value


def _bounded_cursor(value: object) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or _HEADER_CONTROL_RE.search(value):
        raise StockEvidenceProtocolError("provider_cursor_invalid")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise StockEvidenceProtocolError("provider_cursor_invalid") from None
    if not 1 <= size <= _MAX_CURSOR_BYTES:
        raise StockEvidenceProtocolError("provider_cursor_invalid")
    return value


def _next_link(value: object, *, origin: str, path_prefix: str) -> str | None:
    raw = _bounded_cursor(value)
    if raw is None:
        return None
    parsed = urlsplit(raw)
    exact = _exact_origin(origin)
    if (
        f"{parsed.scheme}://{parsed.hostname}" != exact
        or not parsed.path.startswith(path_prefix)
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise StockEvidenceProtocolError("provider_next_link_crossed_scope")
    _path(parsed.path)
    _query(tuple(parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=32)))
    return raw


def _link_next(headers: Mapping[str, str], *, origin: str, path_prefix: str) -> str | None:
    value = headers.get("link")
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 16_384 or _HEADER_CONTROL_RE.search(value):
        raise StockEvidenceProtocolError("provider_link_header_invalid")
    for part in value.split(","):
        segments = [item.strip() for item in part.split(";")]
        if len(segments) < 2 or 'rel="next"' not in segments[1:]:
            continue
        first = segments[0]
        if not (first.startswith("<") and first.endswith(">")):
            raise StockEvidenceProtocolError("provider_link_header_invalid")
        return _next_link(first[1:-1], origin=origin, path_prefix=path_prefix)
    return None


@dataclass(frozen=True, slots=True)
class _ProviderFact:
    selector: str
    status: str
    reason_code: str
    evidence_sha256: str
    watermark: str
    label: str = ""

    def __post_init__(self) -> None:
        _source_ref(self.selector)
        if self.status not in {"failed", "observed", "unknown"}:
            raise StockEvidenceProtocolError("provider_status_invalid")
        if not isinstance(self.reason_code, str) or _REASON_RE.fullmatch(self.reason_code) is None:
            raise StockEvidenceProtocolError("provider_reason_invalid")
        _digest(self.evidence_sha256, "evidence_sha256")
        _source_ref(self.watermark)


@dataclass(frozen=True, slots=True)
class _ProviderResult:
    facts: tuple[_ProviderFact, ...]
    next_locator: str | None
    record_count: int
    response_revision_sha256: str


@dataclass(slots=True)
class _RunState:
    authority_sha256: str
    deadline: float
    provider_locator: str | None = None
    pages: int = 0
    records: int = 0
    bytes_read: int = 0
    facts: dict[str, list[_ProviderFact]] = field(default_factory=dict)
    page_artifacts: list[str] = field(default_factory=list)
    response_revisions: list[str] = field(default_factory=list)


class _CursorVault:
    """Bounded transient provider-continuation and aggregation custody."""

    def __init__(self, maximum: int = _MAX_CURSOR_STATES) -> None:
        self._maximum = _bounded_int(maximum, "cursor state maximum", 1, _MAX_CURSOR_STATES)
        self._lock = threading.Lock()
        self._states: dict[str, _RunState] = {}

    def put(self, state: _RunState) -> str:
        with self._lock:
            if len(self._states) >= self._maximum:
                raise StockEvidenceUnavailable("cursor_capacity_exhausted")
            token = secrets.token_urlsafe(24)
            while token in self._states:
                token = secrets.token_urlsafe(24)
            self._states[token] = state
            return token

    def take(self, token: str, authority_sha256: str) -> _RunState:
        with self._lock:
            state = self._states.pop(token, None)
        if state is None or not hmac.compare_digest(state.authority_sha256, authority_sha256):
            raise StockEvidenceProtocolError("collector_cursor_invalid")
        return state


def _request_authority(request: CollectionRequest, source: StockCollectorSource) -> str:
    return _sha256(
        {
            "schema": "lightwork.trc-stock-request-authority.v1",
            "tenant_sha256": request.tenant_sha256,
            "definition_id": request.definition_id,
            "definition_version": request.definition_version,
            "definition_integrity_sha256": request.definition_integrity_sha256,
            "collector_id": request.collector_id,
            "collector_schema_version": request.collector_schema_version,
            "collector_key_id": request.collector_key_id,
            "capability_revision": request.capability_revision,
            "enrollment_id": request.enrollment_id,
            "enrollment_revision": request.enrollment_revision,
            "enrollment_integrity_sha256": request.enrollment_integrity_sha256,
            "asset_scope_sha256": request.asset_scope_sha256,
            "control_refs": request.control_refs,
            "window_started_at": request.window_started_at,
            "window_ended_at": request.window_ended_at,
            "source_revision_sha256": source.source_revision_sha256,
        }
    )


def _validate_authority(
    request: CollectionRequest,
    collector_id: str,
) -> tuple[StockCollectorSource, str]:
    validate_request(request)
    if request.collector_id != collector_id:
        raise EvidenceCollectorValidationError("collector request id is invalid")
    handle = request.credential_handle
    if not isinstance(handle, StockCollectorCredentialHandle):
        raise StockEvidenceAccessDenied("stock_credential_handle_required")
    source = handle.source
    expected = {
        "tenant_sha256": source.tenant_sha256,
        "definition_id": source.definition_id,
        "definition_version": source.definition_version,
        "definition_integrity_sha256": source.definition_integrity_sha256,
        "collector_id": source.collector_id,
        "collector_schema_version": 1,
        "collector_key_id": source.collector_key_id,
        "capability_revision": source.capability_revision,
        "enrollment_id": source.enrollment_id,
        "enrollment_revision": handle.enrollment_revision,
        "asset_scope_sha256": source.asset_scope_sha256,
    }
    for key, value in expected.items():
        supplied = getattr(request, key)
        if supplied != value:
            raise StockEvidenceAccessDenied("collector_authority_mismatch")
    bindings = {item.control_ref for item in source.bindings}
    if not set(request.control_refs).issubset(bindings):
        raise StockEvidenceAccessDenied("collector_control_scope_mismatch")
    return source, _request_authority(request, source)


def _provider_call(
    source: StockCollectorSource,
    locator: str | None,
    *,
    deadline: float,
    enrollment_revision: int | None = None,
) -> StockEvidenceHTTPRequest:
    limit = str(source.limits.page_size)
    provider = source.provider
    origin = source.origin
    headers: dict[str, str] = {}
    body: bytes | None = None
    query: tuple[tuple[str, str], ...] = ()
    aws_service: str | None = None
    aws_region: str | None = None

    if provider == AWS_SECURITY_HUB:
        payload: dict[str, object] = {"MaxResults": source.limits.page_size}
        if locator is not None:
            payload["NextToken"] = locator
        body = _canonical(payload, maximum=256 * 1024)
        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSSecurityHub_20180608.GetFindings",
        }
        method, path = "POST", "/"
        aws_service, aws_region = "securityhub", source.region
    elif provider == AWS_CONFIG:
        payload = {
            "ConfigRuleNames": [item.source_ref for item in source.bindings],
            "Limit": source.limits.page_size,
        }
        if locator is not None:
            payload["NextToken"] = locator
        body = _canonical(payload, maximum=256 * 1024)
        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "StarlingDoveService.DescribeComplianceByConfigRule",
        }
        method, path = "POST", "/"
        aws_service, aws_region = "config", source.region
    elif provider == AZURE_DEFENDER:
        method = "GET"
        path = (
            f"/subscriptions/{source.scope_ref}"
            "/providers/Microsoft.Security/assessments"
        )
        query = (("$top", limit), ("api-version", "2021-06-01"))
    elif provider == AZURE_POLICY:
        method = "POST"
        path = (
            f"/subscriptions/{source.scope_ref}"
            "/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults"
        )
        query = (("api-version", "2019-10-01"),)
        body = _canonical({"options": {"$top": source.limits.page_size}})
        headers = {"Content-Type": "application/json"}
    elif provider == GCP_SECURITY_COMMAND_CENTER:
        method = "GET"
        path = f"/v2/{source.scope_ref}/sources/-/findings"
        query_values = [("pageSize", limit)]
        if locator is not None:
            query_values.append(("pageToken", locator))
        query = tuple(query_values)
    elif provider == GITHUB_SECURITY:
        method = "GET"
        segments = source.scope_ref.split("/", 1)
        root = f"/orgs/{segments[0]}" if len(segments) == 1 else f"/repos/{segments[0]}/{segments[1]}"
        endpoint = {
            "code_scanning": "code-scanning/alerts",
            "dependabot": "dependabot/alerts",
            "secret_scanning": "secret-scanning/alerts",
        }[source.stream or ""]
        path = f"{root}/{endpoint}"
        page = locator or "1"
        if not page.isdigit() or not 1 <= int(page) <= source.limits.max_pages:
            raise StockEvidenceProtocolError("provider_cursor_invalid")
        query = (("page", page), ("per_page", limit), ("state", "all"))
        headers = {"X-GitHub-Api-Version": "2022-11-28"}
    else:
        method = "GET"
        path = "/api/v1/policies"
        query_values = [("limit", limit), ("type", source.stream or "")]
        if locator is not None:
            parsed = urlsplit(locator)
            if f"{parsed.scheme}://{parsed.hostname}" != source.origin or parsed.path != path:
                raise StockEvidenceProtocolError("provider_next_link_crossed_scope")
            query_values = list(parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=32))
        query = tuple(query_values)

    if locator is not None and provider in {AZURE_DEFENDER, AZURE_POLICY}:
        parsed = urlsplit(locator)
        prefix = f"/subscriptions/{source.scope_ref}/providers/"
        checked = _next_link(locator, origin=origin, path_prefix=prefix)
        assert checked is not None
        path = parsed.path
        query = tuple(parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=32))
        if provider == AZURE_POLICY and path.endswith("/queryResults"):
            body = _canonical({"options": {"$top": source.limits.page_size}})

    return StockEvidenceHTTPRequest(
        provider=provider,
        origin=origin,
        method=method,
        path=path,
        query=query,
        credential_env=source.credential_env,
        deadline=deadline,
        timeout_seconds=source.limits.timeout_seconds,
        max_response_bytes=source.limits.max_response_bytes,
        headers=headers,
        body=body,
        aws_service=aws_service,
        aws_region=aws_region,
        authorizing_principal=source.authorizing_principal,
        enrollment_id=source.enrollment_id,
        enrollment_revision=enrollment_revision,
        source_revision_sha256=source.source_revision_sha256,
    )


def _fact(
    selector: object,
    status: str,
    reason: str,
    record: Mapping[str, object],
    watermark: object,
) -> _ProviderFact | None:
    if not isinstance(selector, str) or not selector:
        return None
    selected = _source_ref(selector)
    observed_watermark = watermark if isinstance(watermark, str) and watermark else "unknown"
    return _ProviderFact(
        selector=selected,
        status=status,
        reason_code=reason,
        evidence_sha256=_sha256(
            {
                "schema": "lightwork.trc-stock-provider-record.v1",
                "selector": selected,
                "status": status,
                "reason_code": reason,
                "record": record,
            }
        ),
        watermark=_source_ref(observed_watermark),
        label=_check_label(record, selected),
    )


def _check_label(record: Mapping[str, object], fallback: str) -> str:
    for value in (record.get("Title"), record.get("ConfigRuleName"), record.get("name"),
                  record.get("displayName"),
                  (record.get("properties") or {}).get("displayName") if isinstance(record.get("properties"), Mapping) else None,
                  (record.get("rule") or {}).get("description") if isinstance(record.get("rule"), Mapping) else None,
                  (record.get("security_advisory") or {}).get("summary") if isinstance(record.get("security_advisory"), Mapping) else None):
        if isinstance(value, str) and value.strip():
            return " ".join(value.split())[:200]
    return fallback.replace("_", " ").replace("-", " ")[:200]


def _parse_provider(  # noqa: C901 - one closed branch per admitted provider
    source: StockCollectorSource,
    response: StockEvidenceHTTPResponse,
    *,
    locator: str | None,
) -> _ProviderResult:
    _require_json_content_type(response.headers)
    provider = source.provider
    facts: list[_ProviderFact] = []
    next_locator: str | None = None

    if provider == AWS_SECURITY_HUB:
        payload = _json_object(response.body)
        records = payload.get("Findings", [])
        if not isinstance(records, list):
            raise StockEvidenceProtocolError("provider_records_invalid")
        for raw in records:
            if not isinstance(raw, Mapping):
                raise StockEvidenceProtocolError("provider_record_invalid")
            compliance = raw.get("Compliance")
            compliance = compliance if isinstance(compliance, Mapping) else {}
            selector = compliance.get("SecurityControlId") or raw.get("GeneratorId")
            value = compliance.get("Status")
            status, reason = {
                "FAILED": ("failed", "provider_control_failed"),
                "PASSED": ("observed", "provider_control_passed"),
            }.get(value, ("unknown", "provider_control_unknown"))
            item = _fact(
                selector,
                status,
                reason,
                {
                    "id": raw.get("Id"),
                    "product_arn": raw.get("ProductArn"),
                    "compliance": value,
                    "workflow": (
                        raw.get("Workflow", {}).get("Status")
                        if isinstance(raw.get("Workflow"), Mapping)
                        else None
                    ),
                    "updated_at": raw.get("UpdatedAt"),
                },
                raw.get("UpdatedAt"),
            )
            if item is not None:
                facts.append(item)
        next_locator = _bounded_cursor(payload.get("NextToken"))
    elif provider == AWS_CONFIG:
        payload = _json_object(response.body)
        records = payload.get("ComplianceByConfigRules", [])
        if not isinstance(records, list):
            raise StockEvidenceProtocolError("provider_records_invalid")
        for raw in records:
            if not isinstance(raw, Mapping):
                raise StockEvidenceProtocolError("provider_record_invalid")
            compliance = raw.get("Compliance")
            compliance = compliance if isinstance(compliance, Mapping) else {}
            value = compliance.get("ComplianceType")
            status, reason = {
                "COMPLIANT": ("observed", "provider_control_passed"),
                "NON_COMPLIANT": ("failed", "provider_control_failed"),
            }.get(value, ("unknown", "provider_control_unknown"))
            item = _fact(
                raw.get("ConfigRuleName"),
                status,
                reason,
                {
                    "rule": raw.get("ConfigRuleName"),
                    "compliance": value,
                    "counts": compliance.get("ComplianceContributorCount"),
                },
                response.headers.get("x-amzn-requestid", "unknown"),
            )
            if item is not None:
                facts.append(item)
        next_locator = _bounded_cursor(payload.get("NextToken"))
    elif provider == AZURE_DEFENDER:
        payload = _json_object(response.body)
        records = payload.get("value", [])
        if not isinstance(records, list):
            raise StockEvidenceProtocolError("provider_records_invalid")
        for raw in records:
            if not isinstance(raw, Mapping):
                raise StockEvidenceProtocolError("provider_record_invalid")
            properties = raw.get("properties")
            properties = properties if isinstance(properties, Mapping) else {}
            status_value = properties.get("status")
            status_value = status_value if isinstance(status_value, Mapping) else {}
            value = status_value.get("code")
            status, reason = {
                "Healthy": ("observed", "provider_control_passed"),
                "Unhealthy": ("failed", "provider_control_failed"),
            }.get(value, ("unknown", "provider_control_unknown"))
            item = _fact(
                raw.get("name"),
                status,
                reason,
                {
                    "name": raw.get("name"),
                    "status": value,
                    "assessment_type": (
                        properties.get("metadata", {}).get("assessmentType")
                        if isinstance(properties.get("metadata"), Mapping)
                        else None
                    ),
                },
                response.headers.get("x-ms-request-id", "unknown"),
            )
            if item is not None:
                facts.append(item)
        next_locator = _next_link(
            payload.get("nextLink"),
            origin=source.origin,
            path_prefix=f"/subscriptions/{source.scope_ref}/providers/",
        )
    elif provider == AZURE_POLICY:
        payload = _json_object(response.body)
        records = payload.get("value", [])
        if not isinstance(records, list):
            raise StockEvidenceProtocolError("provider_records_invalid")
        for raw in records:
            if not isinstance(raw, Mapping):
                raise StockEvidenceProtocolError("provider_record_invalid")
            selector = raw.get("policyDefinitionReferenceId") or raw.get("policyDefinitionId")
            value = raw.get("complianceState")
            status, reason = {
                "Compliant": ("observed", "provider_control_passed"),
                "NonCompliant": ("failed", "provider_control_failed"),
            }.get(value, ("unknown", "provider_control_unknown"))
            item = _fact(
                selector,
                status,
                reason,
                {
                    "policy_assignment_id": raw.get("policyAssignmentId"),
                    "policy_definition_id": raw.get("policyDefinitionId"),
                    "reference_id": raw.get("policyDefinitionReferenceId"),
                    "compliance": value,
                    "timestamp": raw.get("timestamp"),
                },
                raw.get("timestamp"),
            )
            if item is not None:
                facts.append(item)
        next_locator = _next_link(
            payload.get("@odata.nextLink") or payload.get("nextLink"),
            origin=source.origin,
            path_prefix=f"/subscriptions/{source.scope_ref}/providers/",
        )
    elif provider == GCP_SECURITY_COMMAND_CENTER:
        payload = _json_object(response.body)
        records = payload.get("listFindingsResults", [])
        if not isinstance(records, list):
            raise StockEvidenceProtocolError("provider_records_invalid")
        for result in records:
            if not isinstance(result, Mapping):
                raise StockEvidenceProtocolError("provider_record_invalid")
            raw = result.get("finding")
            if not isinstance(raw, Mapping):
                raise StockEvidenceProtocolError("provider_record_invalid")
            value = raw.get("state")
            status, reason = {
                "ACTIVE": ("failed", "provider_finding_active"),
                "INACTIVE": ("observed", "provider_finding_inactive"),
            }.get(value, ("unknown", "provider_control_unknown"))
            item = _fact(
                raw.get("category") or raw.get("name"),
                status,
                reason,
                {
                    "name": raw.get("name"),
                    "category": raw.get("category"),
                    "state": value,
                    "severity": raw.get("severity"),
                    "event_time": raw.get("eventTime"),
                },
                raw.get("eventTime") or raw.get("createTime"),
            )
            if item is not None:
                facts.append(item)
        next_locator = _bounded_cursor(payload.get("nextPageToken"))
    elif provider == GITHUB_SECURITY:
        records = _json_array(response.body)
        for raw in records:
            if not isinstance(raw, Mapping):
                raise StockEvidenceProtocolError("provider_record_invalid")
            if source.stream == "code_scanning":
                rule = raw.get("rule")
                rule = rule if isinstance(rule, Mapping) else {}
                selector = rule.get("id")
            elif source.stream == "secret_scanning":
                selector = raw.get("secret_type")
            else:
                advisory = raw.get("security_advisory")
                advisory = advisory if isinstance(advisory, Mapping) else {}
                dependency = raw.get("dependency")
                dependency = dependency if isinstance(dependency, Mapping) else {}
                package = dependency.get("package")
                package = package if isinstance(package, Mapping) else {}
                selector = advisory.get("ghsa_id") or package.get("name")
            value = raw.get("state")
            status, reason = {
                "open": ("failed", "provider_finding_active"),
                "dismissed": ("observed", "provider_finding_resolved"),
                "fixed": ("observed", "provider_finding_resolved"),
                "resolved": ("observed", "provider_finding_resolved"),
            }.get(value, ("unknown", "provider_control_unknown"))
            item = _fact(
                selector,
                status,
                reason,
                {
                    "number": raw.get("number"),
                    "state": value,
                    "created_at": raw.get("created_at"),
                    "updated_at": raw.get("updated_at") or raw.get("resolved_at"),
                    "selector": selector,
                },
                raw.get("updated_at") or raw.get("resolved_at") or raw.get("created_at"),
            )
            if item is not None:
                facts.append(item)
        current = int(locator or "1")
        next_locator = str(current + 1) if len(records) == source.limits.page_size else None
    else:
        records = _json_array(response.body)
        for raw in records:
            if not isinstance(raw, Mapping):
                raise StockEvidenceProtocolError("provider_record_invalid")
            value = raw.get("status")
            status, reason = {
                "ACTIVE": ("observed", "provider_policy_active"),
                "INACTIVE": ("failed", "provider_policy_inactive"),
            }.get(value, ("unknown", "provider_control_unknown"))
            item = _fact(
                raw.get("id") or raw.get("name"),
                status,
                reason,
                {
                    "id": raw.get("id"),
                    "name": raw.get("name"),
                    "status": value,
                    "type": raw.get("type"),
                    "last_updated": raw.get("lastUpdated"),
                },
                raw.get("lastUpdated"),
            )
            if item is not None:
                facts.append(item)
        next_locator = _link_next(
            response.headers,
            origin=source.origin,
            path_prefix="/api/v1/policies",
        )

    revision = _sha256(
        {
            "schema": "lightwork.trc-stock-provider-response-revision.v1",
            "provider": provider,
            "source_revision_sha256": source.source_revision_sha256,
            "watermarks": sorted(item.watermark for item in facts),
            "headers": dict(sorted(response.headers.items())),
            "body_sha256": hashlib.sha256(response.body).hexdigest(),
        }
    )
    return _ProviderResult(tuple(facts), next_locator, len(records), revision)


def _status_for_facts(facts: Sequence[_ProviderFact]) -> tuple[str, str]:
    if any(item.status == "failed" for item in facts):
        return "failed", "provider_control_failed"
    if facts and all(item.status == "observed" for item in facts):
        return "observed", "provider_control_observed"
    if facts:
        return "unknown", "provider_control_unknown"
    return "unknown", "provider_signal_absent"


def available_source_checks(source: StockCollectorSource, transport: StockEvidenceHTTPTransport,
                            *, clock: Callable[[], float] = time.time) -> dict[str, object]:
    """An explicit bounded setup read, without creating evidence or collector authority."""
    deadline = float(clock()) + min(source.limits.max_elapsed_seconds, 60.0)
    locator = None
    items: dict[str, str] = {}
    complete = False
    for _page in range(3):
        call = _provider_call(source, locator, deadline=deadline)
        if source.provider == AWS_CONFIG:
            payload = {"Limit": source.limits.page_size}
            if locator is not None:
                payload["NextToken"] = locator
            call = replace(call, body=_canonical(payload))
        response = transport.request(call)
        result = _parse_provider(source, response, locator=locator)
        labels = _available_check_labels(source, response)
        for fact in result.facts:
            items.setdefault(fact.selector, labels.get(fact.selector, fact.label))
            if len(items) >= 250:
                break
        if result.next_locator is None:
            complete = len(items) < 250
            break
        if len(items) >= 250:
            break
        locator = result.next_locator
    return {"items": [{"id": key, "label": label} for key, label in sorted(items.items())],
            "complete": complete, "limit": 250,
            "notice": ("Available checks in this bounded read; no evidence was collected."
                       if complete else "Only the first three pages or 250 checks are shown. Narrow the account scope to see other checks; no evidence was collected.")}


def _available_check_labels(source: StockCollectorSource, response: StockEvidenceHTTPResponse) -> dict[str, str]:
    payload = _json_value(response.body)
    if isinstance(payload, list):
        records = payload
    elif isinstance(payload, Mapping):
        key = {AWS_SECURITY_HUB: "Findings", AWS_CONFIG: "ComplianceByConfigRules",
               GCP_SECURITY_COMMAND_CENTER: "listFindingsResults"}.get(source.provider, "value")
        records = payload.get(key, [])
    else:
        return {}
    labels = {}
    for item in records:
        raw = item.get("finding", {}) if source.provider == GCP_SECURITY_COMMAND_CENTER else item
        if not isinstance(raw, Mapping):
            continue
        if source.provider == AWS_SECURITY_HUB:
            selector = (raw.get("Compliance") or {}).get("SecurityControlId") or raw.get("GeneratorId")
        elif source.provider == AWS_CONFIG:
            selector = raw.get("ConfigRuleName")
        elif source.provider == AZURE_POLICY:
            selector = raw.get("policyDefinitionReferenceId") or raw.get("policyDefinitionId")
        elif source.provider == GCP_SECURITY_COMMAND_CENTER:
            selector = raw.get("category") or raw.get("name")
        elif source.provider == GITHUB_SECURITY:
            selector = ((raw.get("rule") or {}).get("id") if source.stream == "code_scanning" else
                        raw.get("secret_type") if source.stream == "secret_scanning" else
                        (raw.get("security_advisory") or {}).get("ghsa_id") or
                        ((raw.get("dependency") or {}).get("package") or {}).get("name"))
        else:
            selector = raw.get("id") if source.provider == OKTA_POSTURE else raw.get("name")
        if isinstance(selector, str):
            labels[selector] = _check_label(raw, selector)
    return labels


class _StockCollector:
    collector_id: str

    def __init__(
        self,
        *,
        transport: StockEvidenceHTTPTransport | None = None,
        clock: Callable[[], float] = time.time,
        cursor_vault: _CursorVault | None = None,
    ) -> None:
        self._transport = transport or PinnedStockEvidenceHTTPTransport(clock=clock)
        self._clock = clock
        self._cursor_vault = cursor_vault or _CursorVault()
        if not callable(getattr(self._transport, "request", None)) or not callable(clock):
            raise StockEvidenceConfigurationError("collector dependencies are invalid")

    def __repr__(self) -> str:
        return f"{type(self).__name__}(read_only=True)"

    def fetch(self, request: CollectionRequest, cursor: str | None) -> EvidencePage:
        source, authority_sha256 = _validate_authority(request, self.collector_id)
        try:
            now = float(self._clock())
        except (TypeError, ValueError, OverflowError):
            raise StockEvidenceConfigurationError("collector clock is invalid") from None
        if not math.isfinite(now) or now <= 0:
            raise StockEvidenceConfigurationError("collector clock is invalid")
        if cursor is None:
            state = _RunState(
                authority_sha256=authority_sha256,
                deadline=now + source.limits.max_elapsed_seconds,
                facts={item.control_ref: [] for item in source.bindings},
            )
        else:
            state = self._cursor_vault.take(cursor, authority_sha256)
        if now >= state.deadline:
            raise StockEvidenceUnavailable("provider_deadline_exhausted")

        call = _provider_call(source, state.provider_locator, deadline=state.deadline,
                              enrollment_revision=request.enrollment_revision)
        response = self._transport.request(call)
        parsed = _parse_provider(source, response, locator=state.provider_locator)
        state.pages += 1
        remaining_records = max(0, source.limits.max_records - state.records)
        admitted_facts = parsed.facts[:remaining_records]
        state.records += parsed.record_count
        state.bytes_read += len(response.body)
        state.page_artifacts.append(hashlib.sha256(response.body).hexdigest())
        state.response_revisions.append(parsed.response_revision_sha256)

        by_selector = {item.source_ref: item.control_ref for item in source.bindings}
        for fact in admitted_facts:
            control_ref = by_selector.get(fact.selector)
            if control_ref is not None and control_ref in request.control_refs:
                state.facts[control_ref].append(fact)

        over_record_bound = state.records > source.limits.max_records
        has_more = parsed.next_locator is not None
        # Facts dropped by the record budget make the run incomplete even on
        # the provider's last page, where there is no further page to report.
        truncated = len(admitted_facts) < len(parsed.facts) or (
            has_more
            and (state.pages >= source.limits.max_pages or over_record_bound)
        )
        terminal = not has_more or truncated
        cumulative_revision = _sha256(
            {
                "schema": "lightwork.trc-stock-source-watermark.v1",
                "source_revision_sha256": source.source_revision_sha256,
                "request_authority_sha256": authority_sha256,
                "response_revisions": state.response_revisions,
                "pages": state.pages,
                "records": state.records,
                "terminal": terminal,
                "truncated": truncated,
            }
        )
        provider_request_sha256 = _sha256(
            {
                "schema": "lightwork.trc-stock-provider-request.v1",
                "authority_sha256": authority_sha256,
                "provider": call.provider,
                "method": call.method,
                "origin": call.origin,
                "path": call.path,
                "query": call.query,
                "body_sha256": (
                    hashlib.sha256(call.body).hexdigest() if call.body is not None else None
                ),
                "source_revision_sha256": source.source_revision_sha256,
                "page": state.pages,
            }
        )
        artifact_sha256 = _sha256(
            {
                "schema": "lightwork.trc-stock-page-artifact.v1",
                "page_artifact_sha256": state.page_artifacts[-1],
                "response_revision_sha256": parsed.response_revision_sha256,
                "records": parsed.record_count,
            }
        )
        if not terminal:
            state.provider_locator = parsed.next_locator
            next_cursor = self._cursor_vault.put(state)
            return EvidencePage(
                items=(),
                next_cursor=next_cursor,
                terminal=False,
                complete=False,
                incomplete_reason="coverage_unknown",
                source_revision_sha256=cumulative_revision,
                artifact_sha256=artifact_sha256,
                bytes_read=len(response.body),
                provider_request_sha256=provider_request_sha256,
            )

        items: list[ControlEvidence] = []
        binding_map = {item.control_ref: item for item in source.bindings}
        for control_ref in request.control_refs:
            facts = state.facts[control_ref]
            status, reason = _status_for_facts(facts)
            items.append(
                ControlEvidence(
                    control_ref=control_ref,
                    status=status,
                    reason_code=reason,
                    evidence_sha256=_sha256(
                        {
                            "schema": "lightwork.trc-stock-control-observation.v1",
                            "request_authority_sha256": authority_sha256,
                            "source_revision_sha256": source.source_revision_sha256,
                            "control_ref": control_ref,
                            "source_ref": binding_map[control_ref].source_ref,
                            "status": status,
                            "reason_code": reason,
                            "record_sha256": sorted(item.evidence_sha256 for item in facts),
                            "complete": not truncated,
                        }
                    ),
                    source_revision_sha256=cumulative_revision,
                )
            )
        return EvidencePage(
            items=tuple(items),
            next_cursor=None,
            terminal=True,
            complete=not truncated,
            incomplete_reason="provider_truncated" if truncated else None,
            source_revision_sha256=cumulative_revision,
            artifact_sha256=artifact_sha256,
            bytes_read=len(response.body),
            provider_request_sha256=provider_request_sha256,
        )


class AWSSecurityHubCollector(_StockCollector):
    collector_id = AWS_SECURITY_HUB_COLLECTOR


class AWSConfigPostureCollector(_StockCollector):
    collector_id = AWS_CONFIG_COLLECTOR


class AzureDefenderCollector(_StockCollector):
    collector_id = AZURE_DEFENDER_COLLECTOR


class AzurePolicyPostureCollector(_StockCollector):
    collector_id = AZURE_POLICY_COLLECTOR


class GCPSecurityCommandCenterCollector(_StockCollector):
    collector_id = GCP_SCC_COLLECTOR


class GitHubSecurityCollector(_StockCollector):
    collector_id = GITHUB_SECURITY_COLLECTOR


class OktaPostureCollector(_StockCollector):
    collector_id = OKTA_POSTURE_COLLECTOR


_COLLECTOR_TYPES = {
    AWS_CONFIG_COLLECTOR: AWSConfigPostureCollector,
    AWS_SECURITY_HUB_COLLECTOR: AWSSecurityHubCollector,
    AZURE_DEFENDER_COLLECTOR: AzureDefenderCollector,
    AZURE_POLICY_COLLECTOR: AzurePolicyPostureCollector,
    GCP_SCC_COLLECTOR: GCPSecurityCommandCenterCollector,
    GITHUB_SECURITY_COLLECTOR: GitHubSecurityCollector,
    OKTA_POSTURE_COLLECTOR: OktaPostureCollector,
}


class StockCollectorDirectory:
    """Tenant-private source directory and scheduler dependency pair."""

    def __init__(
        self,
        sources: Sequence[StockCollectorSource],
        *,
        transport_factory: Callable[[str], StockEvidenceHTTPTransport] | None = None,
        include_local_soc2: bool = True,
        credential_ref_present: Callable[[str], bool] | None = None,
    ) -> None:
        if isinstance(sources, (str, bytes)) or not isinstance(sources, Sequence):
            raise StockEvidenceConfigurationError("stock source directory is invalid")
        values = tuple(sources)
        if any(not isinstance(item, StockCollectorSource) for item in values):
            raise StockEvidenceConfigurationError("stock source directory is invalid")
        by_key: dict[tuple[str, str], StockCollectorSource] = {}
        for source in values:
            key = (source.tenant_sha256, source.enrollment_id)
            if key in by_key:
                raise StockEvidenceConfigurationError("stock enrollment source is duplicated")
            by_key[key] = source
        self._sources = by_key
        self._transport_factory = transport_factory or (
            lambda _tenant_id: PinnedStockEvidenceHTTPTransport()
        )
        self._include_local = bool(include_local_soc2)
        self._credential_ref_present = credential_ref_present or (
            lambda name: name in os.environ
        )
        if not callable(self._transport_factory) or not callable(self._credential_ref_present):
            raise StockEvidenceConfigurationError("stock directory dependencies are invalid")

    def _tenant_sources(self, tenant_id: str) -> tuple[StockCollectorSource, ...]:
        tenant_sha256 = stock_tenant_sha256(tenant_id)
        return tuple(
            sorted(
                (
                    source
                    for (candidate, _enrollment), source in self._sources.items()
                    if candidate == tenant_sha256
                ),
                key=lambda item: (item.collector_id, item.enrollment_id),
            )
        )

    def registry_for_tenant(self, tenant_id: str) -> CollectorRegistry:
        tenant = canonical_tenant_id(tenant_id)
        sources = self._tenant_sources(tenant)
        transport = self._transport_factory(tenant)
        if not callable(getattr(transport, "request", None)):
            raise StockEvidenceConfigurationError("stock transport factory is invalid")
        collectors: dict[str, object] = {}
        if self._include_local:
            local = LocalSoc2Collector()
            collectors[local.collector_id] = local
        vault = _CursorVault()
        for collector_id in sorted({item.collector_id for item in sources}):
            collectors[collector_id] = _COLLECTOR_TYPES[collector_id](
                transport=transport,
                cursor_vault=vault,
            )
        if not collectors:
            raise StockEvidenceConfigurationError("tenant has no installed collector")
        return CollectorRegistry(collectors)

    def resolve_credential(
        self,
        tenant_id: str,
        enrollment_id: str,
        enrollment_revision: int,
        credential_profile_sha256: str,
    ) -> StockCollectorCredentialHandle | None:
        tenant_sha256 = stock_tenant_sha256(tenant_id)
        enrollment = _identifier(enrollment_id, "enrollment_id")
        revision = _bounded_int(
            enrollment_revision,
            "enrollment_revision",
            1,
            2**31 - 1,
        )
        profile = _digest(credential_profile_sha256, "credential_profile_sha256")
        source = self._sources.get((tenant_sha256, enrollment))
        if source is None:
            if self._include_local:
                return None
            raise StockEvidenceAccessDenied("stock_source_not_enrolled")
        if not hmac.compare_digest(profile, source.credential_profile_sha256):
            raise StockEvidenceAccessDenied("stock_credential_profile_mismatch")
        return StockCollectorCredentialHandle(source, revision)

    def readiness(self, tenant_id: str) -> Mapping[str, object]:
        """Side-effect-free readiness; no credential value or provider is opened."""

        tenant = canonical_tenant_id(tenant_id)
        sources = self._tenant_sources(tenant)
        records = []
        for source in sources:
            try:
                reference_present = self._credential_ref_present(source.credential_env) is True
            except Exception:
                reference_present = False
            records.append(
                {
                    "collector_id": source.collector_id,
                    "provider": source.provider,
                    "enrollment_id_sha256": hashlib.sha256(
                        source.enrollment_id.encode("utf-8")
                    ).hexdigest(),
                    "source_revision_sha256": source.source_revision_sha256,
                    "asset_scope_sha256": source.asset_scope_sha256,
                    "credential_profile_sha256": source.credential_profile_sha256,
                    "credential_reference_present": reference_present,
                    "control_count": len(source.bindings),
                }
            )
        configured = bool(records)
        references_ready = configured and all(
            item["credential_reference_present"] is True for item in records
        )
        payload: dict[str, object] = {
            "schema": "lightwork.trc-stock-collector-readiness.v1",
            "tenant_sha256": stock_tenant_sha256(tenant),
            "configured": configured,
            "ready": references_ready,
            "sources": records,
            "local_soc2_included": self._include_local,
            "credential_values_resolved": False,
            "provider_io_performed": False,
            "read_only": True,
            "raw_provider_payload_persisted": False,
            "estate_completeness_claimed": False,
            "live_provider_acceptance_verified": False,
        }
        payload["readiness_sha256"] = _sha256(payload)
        return payload


__all__ = [
    "AWSConfigPostureCollector",
    "AWSSecurityHubCollector",
    "AWS_CONFIG",
    "AWS_CONFIG_COLLECTOR",
    "AWS_SECURITY_HUB",
    "AWS_SECURITY_HUB_COLLECTOR",
    "AzureDefenderCollector",
    "AzurePolicyPostureCollector",
    "AZURE_DEFENDER",
    "AZURE_DEFENDER_COLLECTOR",
    "AZURE_POLICY",
    "AZURE_POLICY_COLLECTOR",
    "CERTIFICATION_ASSERTED",
    "COMPLIANCE_INFERRED",
    "GCP_SECURITY_COMMAND_CENTER",
    "GCP_SCC_COLLECTOR",
    "GCPSecurityCommandCenterCollector",
    "GITHUB_SECURITY",
    "GITHUB_SECURITY_COLLECTOR",
    "GitHubSecurityCollector",
    "LIVE_PROVIDER_ACCEPTANCE_VERIFIED",
    "NETWORK_IO",
    "OKTA_POSTURE",
    "OKTA_POSTURE_COLLECTOR",
    "OktaPostureCollector",
    "PROVIDER_CONTINUATION_PERSISTED",
    "PinnedStockEvidenceHTTPTransport",
    "ProviderControlBinding",
    "RAW_PROVIDER_PAYLOAD_PERSISTED",
    "READ_ONLY",
    "STOCK_COLLECTOR_IDS",
    "STOCK_PROVIDERS",
    "StockCollectorCredentialHandle",
    "StockCollectorDirectory",
    "StockCollectorLimits",
    "StockCollectorSource",
    "StockEvidenceAccessDenied",
    "StockEvidenceCollectorError",
    "StockEvidenceConfigurationError",
    "StockEvidenceHTTPRequest",
    "StockEvidenceHTTPResponse",
    "StockEvidenceHTTPTransport",
    "StockEvidenceProtocolError",
    "StockEvidenceUnavailable",
    "stock_tenant_sha256",
]
