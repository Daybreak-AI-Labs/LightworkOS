"""Named, bounded consent-delivery adapters for enterprise destinations.

The generic :mod:`maverick.consent_delivery` runtime remains the delivery
authority.  This module accepts only its signed, lease-bound envelopes and
translates them into closed contracts for Salesforce, Marketo, Adobe
Experience Platform (AEP), and Snowflake.  It never accepts a provider URL,
statement, credential, profile, or consent body from an API caller.

Provider credentials are referenced by ``$ENV_NAME`` in configuration and are
resolved only inside the transport immediately before a request.  The
production HTTP seam pins DNS, refuses redirects and private-fetch overrides,
checks enterprise egress policy, and bounds elapsed time and response bytes.

The digest-only operation ledger makes a repeated completed delivery a local
no-change result.  A process or transport loss after dispatch is fail-closed as
ambiguous and requires an independently injected reconciliation probe before
dead-letter replay.  Local contracts do not establish live-provider
interoperability, permissions, completeness, or customer acceptance.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import math
import os
import re
import sqlite3
import time
import urllib.parse
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol

from . import consent_storage
from .consent_delivery import (
    DELIVERY_PATH,
    ConsentDeliveryRevoked,
    ConsentDeliveryTransportError,
    DeliveryResponse,
    SignedDeliveryRequest,
    _validated_request_headers,
)
from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id

SALESFORCE = "salesforce"
MARKETO = "marketo"
ADOBE_EXPERIENCE_PLATFORM = "adobe_experience_platform"
SNOWFLAKE = "snowflake"

STOCK_DESTINATION_PROVIDERS = frozenset(
    {SALESFORCE, MARKETO, ADOBE_EXPERIENCE_PLATFORM, SNOWFLAKE}
)
STOCK_RECONCILIATION_PROVIDERS = frozenset({SALESFORCE, MARKETO, SNOWFLAKE})

DESTINATION_EVENT_SCHEMA = "lightwork.consent-destination-event.v1"
DESTINATION_RECEIPT_SCHEMA = "lightwork.consent-destination-receipt.v1"
DESTINATION_RECONCILIATION_SCHEMA = (
    "lightwork.consent-destination-reconciliation.v1"
)

_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_SECRET_REF_RE = re.compile(
    r"\$(?:\{([A-Z][A-Z0-9_]{0,127})\}|([A-Z][A-Z0-9_]{0,127}))\Z"
)
_HOST_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
    r"[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
    r"[A-Za-z0-9])?\Z"
)
_PROVIDER_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_SALESFORCE_API_VERSION_RE = re.compile(r"v[0-9]{2}\.[0-9]\Z")
_AEP_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_AEP_ORG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{1,255}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

_MAX_BODY_BYTES = 256 * 1024
_MAX_RESPONSE_BYTES = 1024 * 1024
_MAX_SECRET_BYTES = 32 * 1024
_MAX_CONFIGURED_DESTINATIONS = 64
_PREPARING_LEASE_SECONDS = 60.0
_SAFE_RETRY_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})
_OPERATION_STATES = frozenset(
    {"preparing", "dispatching", "retryable", "completed", "rejected", "ambiguous", "revoked"}
)


class ConsentDestinationAdapterError(RuntimeError):
    """Base error for named consent destinations."""


class ConsentDestinationConfigError(ConsentDestinationAdapterError, ValueError):
    """A provider binding is absent or outside its closed contract."""


class ConsentDestinationCredentialError(ConsentDestinationAdapterError):
    """Deployment-held credential custody is unavailable or invalid."""


class ConsentDestinationProtocolError(ConsentDestinationAdapterError):
    """A provider request or response is outside its closed contract."""


class ConsentDestinationRequestNotSent(ConsentDestinationAdapterError):
    """A transport failure proves provider dispatch did not start."""


class ConsentDestinationTransportAmbiguous(ConsentDestinationAdapterError):
    """Provider dispatch may have occurred but its outcome is unavailable."""


class ConsentDestinationConflict(ConsentDestinationAdapterError):
    """A digest, revision, or idempotency binding changed."""


class ConsentDestinationReconciliationRequired(ConsentDestinationAdapterError):
    """An ambiguous provider mutation must be independently reconciled."""


def _canonical(value: object, *, maximum: int = _MAX_BODY_BYTES) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ConsentDestinationProtocolError(
            "destination data must be finite canonical JSON"
        ) from exc
    if not 1 <= len(encoded) <= maximum:
        raise ConsentDestinationProtocolError("destination data exceeds its byte bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ConsentDestinationProtocolError(f"{label} must be a SHA-256 digest")
    return value


def _token(value: object, label: str) -> str:
    if not isinstance(value, str) or _TOKEN_RE.fullmatch(value) is None:
        raise ConsentDestinationConfigError(
            f"{label} must be a bounded opaque identifier"
        )
    return value


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)
    except ValueError as exc:
        raise ConsentDestinationConfigError("tenant_id is invalid") from exc


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise ConsentDestinationConfigError(f"{label} is outside its bound")
    return value


def _number(value: object, label: str, minimum: float, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not minimum <= float(value) <= maximum
    ):
        raise ConsentDestinationConfigError(f"{label} is outside its bound")
    return float(value)


def _exact_origin(value: object, provider_id: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise ConsentDestinationConfigError("destination origin must be exact HTTPS")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ConsentDestinationConfigError(
            "destination origin must be exact HTTPS"
        ) from None
    host = (parsed.hostname or "").rstrip(".").lower()
    if (
        parsed.scheme != "https"
        or _HOST_RE.fullmatch(host) is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or (port is not None and port != 443)
    ):
        raise ConsentDestinationConfigError(
            "destination origin must be a credential-free HTTPS origin"
        )
    suffixes = {
        SALESFORCE: (".salesforce.com", ".force.com"),
        MARKETO: (".mktorest.com",),
        ADOBE_EXPERIENCE_PLATFORM: (".adobedc.net",),
        SNOWFLAKE: (".snowflakecomputing.com",),
    }[provider_id]
    if not any(host.endswith(suffix) and host != suffix[1:] for suffix in suffixes):
        raise ConsentDestinationConfigError(
            f"destination origin is not a recognized {provider_id} public origin"
        )
    return f"https://{host}"


def _secret_reference(value: object) -> tuple[str, str]:
    if not isinstance(value, str):
        raise ConsentDestinationConfigError(
            "credential_secret_ref must be an uppercase $ENV reference"
        )
    match = _SECRET_REF_RE.fullmatch(value)
    if match is None:
        raise ConsentDestinationConfigError(
            "credential_secret_ref must be an uppercase $ENV reference"
        )
    return value, match.group(1) or match.group(2)


def _provider_identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _PROVIDER_IDENTIFIER_RE.fullmatch(value) is None:
        raise ConsentDestinationConfigError(f"{label} is not a safe provider identifier")
    return value


def _aep_ref(value: object, label: str) -> str:
    if not isinstance(value, str) or _AEP_REF_RE.fullmatch(value) is None:
        raise ConsentDestinationConfigError(f"{label} is invalid")
    return value


def _closed_settings(provider_id: str, value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ConsentDestinationConfigError("provider settings must be a mapping")
    settings = dict(value)
    if provider_id == SALESFORCE:
        allowed = {
            "api_version",
            "object_api_name",
            "external_id_field",
            "payload_digest_field",
        }
        if set(settings) != allowed:
            raise ConsentDestinationConfigError("Salesforce settings are not closed")
        api_version = settings["api_version"]
        if (
            not isinstance(api_version, str)
            or _SALESFORCE_API_VERSION_RE.fullmatch(api_version) is None
        ):
            raise ConsentDestinationConfigError("Salesforce api_version is invalid")
        normalized = {
            "api_version": api_version,
            "object_api_name": _provider_identifier(
                settings["object_api_name"], "Salesforce object_api_name"
            ),
            "external_id_field": _provider_identifier(
                settings["external_id_field"], "Salesforce external_id_field"
            ),
            "payload_digest_field": _provider_identifier(
                settings["payload_digest_field"], "Salesforce payload_digest_field"
            ),
        }
    elif provider_id == MARKETO:
        required = {"custom_object_name", "dedupe_field", "payload_digest_field"}
        allowed = required | {"message_id_field"}
        if not required.issubset(settings) or set(settings) - allowed:
            raise ConsentDestinationConfigError("Marketo settings are not closed")
        normalized = {
            "custom_object_name": _provider_identifier(
                settings["custom_object_name"], "Marketo custom_object_name"
            ),
            "dedupe_field": _provider_identifier(
                settings["dedupe_field"], "Marketo dedupe_field"
            ),
            "payload_digest_field": _provider_identifier(
                settings["payload_digest_field"], "Marketo payload_digest_field"
            ),
            "message_id_field": _provider_identifier(
                settings.get("message_id_field", "lightworkMessageId"),
                "Marketo message_id_field",
            ),
        }
    elif provider_id == ADOBE_EXPERIENCE_PLATFORM:
        allowed = {
            "connection_id",
            "flow_id",
            "dataset_id",
            "schema_id",
            "ims_org_id",
        }
        if set(settings) != allowed:
            raise ConsentDestinationConfigError("AEP settings are not closed")
        ims_org_id = settings["ims_org_id"]
        if (
            not isinstance(ims_org_id, str)
            or _AEP_ORG_RE.fullmatch(ims_org_id) is None
        ):
            raise ConsentDestinationConfigError("AEP ims_org_id is invalid")
        normalized = {
            "connection_id": _aep_ref(
                settings["connection_id"], "AEP connection_id"
            ),
            "flow_id": _aep_ref(settings["flow_id"], "AEP flow_id"),
            "dataset_id": _aep_ref(settings["dataset_id"], "AEP dataset_id"),
            "schema_id": _aep_ref(settings["schema_id"], "AEP schema_id"),
            "ims_org_id": ims_org_id,
        }
    else:
        allowed = {"database", "schema", "table", "warehouse", "role"}
        if set(settings) != allowed:
            raise ConsentDestinationConfigError("Snowflake settings are not closed")
        normalized = {
            key: _provider_identifier(settings[key], f"Snowflake {key}")
            for key in sorted(allowed)
        }
    return MappingProxyType(normalized)


@dataclass(frozen=True, slots=True)
class ConsentDestinationBinding:
    """One tenant-exact destination binding containing no credential value."""

    tenant_id: str
    destination_id: str
    provider_id: str
    origin: str
    credential_secret_ref: str
    credential_revision: int
    settings: Mapping[str, object]

    def __post_init__(self) -> None:
        tenant = _tenant(self.tenant_id)
        destination = _token(self.destination_id, "destination_id")
        provider = str(self.provider_id or "").strip().lower()
        if provider not in STOCK_DESTINATION_PROVIDERS:
            raise ConsentDestinationConfigError("destination provider is unsupported")
        origin = _exact_origin(self.origin, provider)
        secret_ref, _ = _secret_reference(self.credential_secret_ref)
        revision = _integer(
            self.credential_revision, "credential_revision", 1, 2**31 - 1
        )
        settings = _closed_settings(provider, self.settings)
        object.__setattr__(self, "tenant_id", tenant)
        object.__setattr__(self, "destination_id", destination)
        object.__setattr__(self, "provider_id", provider)
        object.__setattr__(self, "origin", origin)
        object.__setattr__(self, "credential_secret_ref", secret_ref)
        object.__setattr__(self, "credential_revision", revision)
        object.__setattr__(self, "settings", settings)

    @property
    def credential_name(self) -> str:
        return _secret_reference(self.credential_secret_ref)[1]

    @property
    def authority_sha256(self) -> str:
        return _sha256(
            {
                "schema": "lightwork.consent-destination-binding.v1",
                "tenant_id": self.tenant_id,
                "destination_id": self.destination_id,
                "provider_id": self.provider_id,
                "origin": self.origin,
                "credential_name_sha256": hashlib.sha256(
                    self.credential_name.encode("ascii")
                ).hexdigest(),
                "credential_revision": self.credential_revision,
                "settings": dict(self.settings),
            }
        )


class ConsentDestinationRegistry:
    """Closed, tenant-private lookup for configured provider bindings."""

    def __init__(
        self,
        tenant_id: str,
        bindings: Sequence[ConsentDestinationBinding] = (),
        *,
        enabled: bool = False,
        timeout_seconds: float = 10.0,
        max_response_bytes: int = 64 * 1024,
    ) -> None:
        self.tenant_id = _tenant(tenant_id)
        if type(enabled) is not bool:
            raise ConsentDestinationConfigError("destination adapters enable is invalid")
        self.enabled = enabled
        self.timeout_seconds = _number(
            timeout_seconds, "destination timeout_seconds", 0.1, 60.0
        )
        self.max_response_bytes = _integer(
            max_response_bytes,
            "destination max_response_bytes",
            1024,
            _MAX_RESPONSE_BYTES,
        )
        if (
            isinstance(bindings, (str, bytes))
            or not isinstance(bindings, Sequence)
            or len(bindings) > _MAX_CONFIGURED_DESTINATIONS
        ):
            raise ConsentDestinationConfigError("destination binding list is invalid")
        by_id: dict[str, ConsentDestinationBinding] = {}
        for binding in bindings:
            if not isinstance(binding, ConsentDestinationBinding):
                raise ConsentDestinationConfigError("destination binding is invalid")
            if binding.tenant_id != self.tenant_id:
                raise ConsentDestinationConfigError("destination binding crossed its tenant")
            if binding.destination_id in by_id:
                raise ConsentDestinationConfigError("destination_id is duplicated")
            by_id[binding.destination_id] = binding
        if not enabled and by_id:
            raise ConsentDestinationConfigError(
                "disabled destination adapters cannot retain active bindings"
            )
        self._bindings = MappingProxyType(by_id)

    def binding(self, destination_id: str) -> ConsentDestinationBinding:
        if not self.enabled:
            raise ConsentDestinationConfigError("destination adapters are disabled")
        destination = _token(destination_id, "destination_id")
        try:
            return self._bindings[destination]
        except KeyError:
            raise ConsentDestinationConfigError(
                "destination has no named provider binding"
            ) from None

    def status(
        self,
        *,
        credential_reference_present: Callable[[str], bool] | None = None,
    ) -> Mapping[str, object]:
        present = credential_reference_present or (lambda _name: False)
        items = []
        for binding in sorted(self._bindings.values(), key=lambda item: item.destination_id):
            try:
                has_reference = bool(present(binding.credential_name))
            except Exception:
                has_reference = False
            items.append(
                {
                    "destination_id": binding.destination_id,
                    "provider_id": binding.provider_id,
                    "binding_authority_sha256": binding.authority_sha256,
                    "credential_revision": binding.credential_revision,
                    "credential_reference_present": has_reference,
                    "origin_sha256": hashlib.sha256(
                        binding.origin.encode("ascii")
                    ).hexdigest(),
                }
            )
        return {
            "schema": "lightwork.consent-destination-registry-status.v1",
            "tenant_id": self.tenant_id,
            "enabled": self.enabled,
            "configured": bool(items),
            "ready": self.enabled and bool(items) and all(
                item["credential_reference_present"] for item in items
            ),
            "providers": sorted({item["provider_id"] for item in items}),
            "destinations": items,
            "credential_values_resolved": False,
            "provider_session_opened": False,
            "live_provider_acceptance_verified": False,
        }


def build_consent_destination_registry(
    config: Mapping[str, Any], tenant_id: str
) -> ConsentDestinationRegistry:
    """Build the closed registry expected under delivery ``destinations`` config."""

    tenant = _tenant(tenant_id)
    consent = config.get("consent_preferences") if isinstance(config, Mapping) else None
    delivery = consent.get("delivery") if isinstance(consent, Mapping) else None
    section = delivery.get("destinations") if isinstance(delivery, Mapping) else None
    if section is None:
        return ConsentDestinationRegistry(tenant)
    if not isinstance(section, Mapping):
        raise ConsentDestinationConfigError("delivery destinations config is invalid")
    allowed = {
        "enable",
        "enabled_providers",
        "timeout_seconds",
        "max_response_bytes",
        *STOCK_DESTINATION_PROVIDERS,
    }
    if set(section) - allowed:
        raise ConsentDestinationConfigError("delivery destinations config is not closed")
    enabled = section.get("enable", False)
    if type(enabled) is not bool:
        raise ConsentDestinationConfigError("delivery destinations enable is invalid")
    raw_providers = section.get("enabled_providers", [])
    if (
        isinstance(raw_providers, (str, bytes))
        or not isinstance(raw_providers, Sequence)
        or len(raw_providers) > len(STOCK_DESTINATION_PROVIDERS)
    ):
        raise ConsentDestinationConfigError("enabled destination providers are invalid")
    providers = tuple(str(item or "").strip().lower() for item in raw_providers)
    if len(set(providers)) != len(providers) or any(
        provider not in STOCK_DESTINATION_PROVIDERS for provider in providers
    ):
        raise ConsentDestinationConfigError("enabled destination providers are invalid")
    if not enabled:
        # Off is a clean off: services still listed (for example by the
        # installer) are kept but not bound, so nothing is sent and the
        # registry reports disabled rather than a configuration error.
        return ConsentDestinationRegistry(
            tenant,
            enabled=False,
            timeout_seconds=section.get("timeout_seconds", 10.0),
            max_response_bytes=section.get("max_response_bytes", 64 * 1024),
        )
    bindings: list[ConsentDestinationBinding] = []
    for provider in providers:
        raw = section.get(provider)
        if not isinstance(raw, Mapping):
            raise ConsentDestinationConfigError(
                f"{provider} destination configuration is unavailable"
            )
        common = {
            "destination_id",
            "origin",
            "credential_secret_ref",
            "credential_revision",
        }
        provider_keys = {
            SALESFORCE: {
                "api_version",
                "object_api_name",
                "external_id_field",
                "payload_digest_field",
            },
            MARKETO: {
                "custom_object_name",
                "dedupe_field",
                "payload_digest_field",
                "message_id_field",
            },
            ADOBE_EXPERIENCE_PLATFORM: {
                "connection_id",
                "flow_id",
                "dataset_id",
                "schema_id",
                "ims_org_id",
            },
            SNOWFLAKE: {"database", "schema", "table", "warehouse", "role"},
        }[provider]
        required_keys = provider_keys - (
            {"message_id_field"} if provider == MARKETO else set()
        )
        if not (common | required_keys).issubset(raw) or set(raw) - (
            common | provider_keys
        ):
            raise ConsentDestinationConfigError(
                f"{provider} destination configuration is not closed"
            )
        bindings.append(
            ConsentDestinationBinding(
                tenant_id=tenant,
                destination_id=raw["destination_id"],
                provider_id=provider,
                origin=raw["origin"],
                credential_secret_ref=raw["credential_secret_ref"],
                credential_revision=raw["credential_revision"],
                settings={key: raw[key] for key in provider_keys if key in raw},
            )
        )
    if bool(bindings) != (enabled and bool(providers)):
        if enabled or bindings:
            raise ConsentDestinationConfigError(
                "enabled delivery destinations require at least one provider"
            )
    return ConsentDestinationRegistry(
        tenant,
        bindings,
        enabled=enabled,
        timeout_seconds=section.get("timeout_seconds", 10.0),
        max_response_bytes=section.get("max_response_bytes", 64 * 1024),
    )


@dataclass(frozen=True, slots=True, repr=False)
class DestinationCredentialLease:
    headers: Mapping[str, str] = field(repr=False)
    authority_sha256: str
    credential_revision: int

    def __post_init__(self) -> None:
        if not isinstance(self.headers, Mapping) or not 1 <= len(self.headers) <= 8:
            raise ConsentDestinationCredentialError("credential headers are invalid")
        for key, value in self.headers.items():
            if (
                not isinstance(key, str)
                or not isinstance(value, str)
                or not 1 <= len(key) <= 128
                or not 1 <= len(value) <= 16_384
                or _CONTROL_RE.search(key)
                or _CONTROL_RE.search(value)
            ):
                raise ConsentDestinationCredentialError("credential headers are invalid")
        _digest(self.authority_sha256, "credential authority_sha256")
        _integer(self.credential_revision, "credential revision", 1, 2**31 - 1)


SecretResolver = Callable[[str], str | None]


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    selected: dict[str, Any] = {}
    for key, value in pairs:
        if key in selected:
            raise ValueError("duplicate JSON object key")
        selected[key] = value
    return selected


def _secret_object(value: str) -> Mapping[str, Any]:
    try:
        parsed = json.loads(value, object_pairs_hook=_unique_json_object)
    except (ValueError, RecursionError):
        raise ConsentDestinationCredentialError("destination credential is invalid") from None
    if not isinstance(parsed, Mapping) or len(parsed) > 8:
        raise ConsentDestinationCredentialError("destination credential is invalid")
    return parsed


def _bearer(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 8 <= len(value) <= 16_384
        or _CONTROL_RE.search(value)
    ):
        raise ConsentDestinationCredentialError("destination credential is invalid")
    return value if value.startswith("Bearer ") else f"Bearer {value}"


class DeploymentConsentDestinationCredentialOwner:
    """Resolve a secret-provider reference for exactly one provider request."""

    def __init__(
        self,
        resolver: SecretResolver | None = None,
        *,
        reference_present: Callable[[str], bool] | None = None,
    ) -> None:
        self._resolver = resolver or os.environ.get
        self._reference_present = reference_present or (lambda name: name in os.environ)
        if not callable(self._resolver):
            raise ConsentDestinationConfigError("credential resolver is invalid")
        if not callable(self._reference_present):
            raise ConsentDestinationConfigError(
                "credential reference-presence authority is invalid"
            )

    def __repr__(self) -> str:
        return "DeploymentConsentDestinationCredentialOwner(custody='ephemeral')"

    def reference_present(self, name: str) -> bool:
        if not isinstance(name, str) or not name:
            return False
        try:
            value = self._reference_present(name)
        except Exception:
            return False
        return value is True

    def lease(self, binding: ConsentDestinationBinding) -> DestinationCredentialLease:
        if not isinstance(binding, ConsentDestinationBinding):
            raise ConsentDestinationCredentialError("destination binding is invalid")
        try:
            value = self._resolver(binding.credential_name)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise ConsentDestinationCredentialError(
                "destination credential resolution failed"
            ) from None
        if not isinstance(value, str):
            raise ConsentDestinationCredentialError(
                "destination credential is unavailable"
            )
        try:
            encoded = value.encode("utf-8")
        except UnicodeError:
            raise ConsentDestinationCredentialError(
                "destination credential is invalid"
            ) from None
        if not 8 <= len(encoded) <= _MAX_SECRET_BYTES or _CONTROL_RE.search(value):
            raise ConsentDestinationCredentialError("destination credential is invalid")
        if binding.provider_id == ADOBE_EXPERIENCE_PLATFORM:
            parsed = _secret_object(value)
            expected = {"bearer_token", "api_key", "ims_org_id", "sandbox_name"}
            if set(parsed) != expected:
                raise ConsentDestinationCredentialError(
                    "AEP credential bundle is invalid"
                )
            api_key = parsed.get("api_key")
            ims_org = parsed.get("ims_org_id")
            sandbox = parsed.get("sandbox_name")
            if any(
                not isinstance(item, str)
                or not 2 <= len(item) <= 1024
                or _CONTROL_RE.search(item)
                for item in (api_key, ims_org, sandbox)
            ):
                raise ConsentDestinationCredentialError(
                    "AEP credential bundle is invalid"
                )
            headers = {
                "Authorization": _bearer(parsed.get("bearer_token")),
                "x-api-key": api_key,
                "x-gw-ims-org-id": ims_org,
                "x-sandbox-name": sandbox,
            }
        else:
            token: object = value
            if value.lstrip().startswith("{"):
                parsed = _secret_object(value)
                if set(parsed) != {"bearer_token"}:
                    raise ConsentDestinationCredentialError(
                        "destination credential bundle is invalid"
                    )
                token = parsed.get("bearer_token")
            headers = {"Authorization": _bearer(token)}
        return DestinationCredentialLease(
            headers=MappingProxyType(headers),
            authority_sha256=_sha256(
                {
                    "schema": "lightwork.consent-destination-credential-authority.v1",
                    "tenant_id": binding.tenant_id,
                    "destination_id": binding.destination_id,
                    "provider_id": binding.provider_id,
                    "credential_name_sha256": hashlib.sha256(
                        binding.credential_name.encode("ascii")
                    ).hexdigest(),
                    "credential_revision": binding.credential_revision,
                }
            ),
            credential_revision=binding.credential_revision,
        )


@dataclass(frozen=True, slots=True, repr=False)
class DestinationHTTPRequest:
    provider_id: str
    origin: str
    method: str
    path: str
    query: tuple[tuple[str, str], ...]
    headers: Mapping[str, str] = field(repr=False)
    body: bytes = field(repr=False)
    timeout_seconds: float
    max_response_bytes: int

    def __post_init__(self) -> None:
        provider = str(self.provider_id or "").strip().lower()
        if provider not in STOCK_DESTINATION_PROVIDERS:
            raise ConsentDestinationProtocolError("request provider is unsupported")
        origin = _exact_origin(self.origin, provider)
        if self.method not in {"GET", "POST", "PATCH"}:
            raise ConsentDestinationProtocolError("request method is unsupported")
        if (
            not isinstance(self.path, str)
            or not self.path.startswith("/")
            or self.path.startswith("//")
            or len(self.path) > 8192
            or "?" in self.path
            or "#" in self.path
            or "\\" in self.path
            or _CONTROL_RE.search(self.path)
        ):
            raise ConsentDestinationProtocolError("request path is invalid")
        if not isinstance(self.query, tuple) or len(self.query) > 16:
            raise ConsentDestinationProtocolError("request query is invalid")
        for pair in self.query:
            if (
                not isinstance(pair, tuple)
                or len(pair) != 2
                or not all(isinstance(item, str) for item in pair)
                or any(_CONTROL_RE.search(item) or len(item) > 2048 for item in pair)
            ):
                raise ConsentDestinationProtocolError("request query is invalid")
        if not isinstance(self.headers, Mapping) or not 1 <= len(self.headers) <= 24:
            raise ConsentDestinationProtocolError("request headers are invalid")
        for key, value in self.headers.items():
            if (
                not isinstance(key, str)
                or not isinstance(value, str)
                or not 1 <= len(key) <= 128
                or not 1 <= len(value) <= 16_384
                or _CONTROL_RE.search(key)
                or _CONTROL_RE.search(value)
                or key.lower() in {"host", "cookie"}
            ):
                raise ConsentDestinationProtocolError("request headers are invalid")
        if (
            not isinstance(self.body, bytes)
            or len(self.body) > _MAX_BODY_BYTES
            or (self.method != "GET" and not self.body)
            or (self.method == "GET" and self.body)
        ):
            raise ConsentDestinationProtocolError("request body is invalid")
        _number(self.timeout_seconds, "request timeout", 0.1, 60.0)
        _integer(
            self.max_response_bytes,
            "request response byte bound",
            1024,
            _MAX_RESPONSE_BYTES,
        )
        object.__setattr__(self, "provider_id", provider)
        object.__setattr__(self, "origin", origin)

    @property
    def url(self) -> str:
        query = urllib.parse.urlencode(self.query, doseq=True, safe="")
        return self.origin + self.path + (f"?{query}" if query else "")


@dataclass(frozen=True, slots=True, repr=False)
class DestinationHTTPResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            isinstance(self.status_code, bool)
            or not isinstance(self.status_code, int)
            or not 100 <= self.status_code <= 599
            or not isinstance(self.headers, Mapping)
            or not isinstance(self.body, bytes)
            or len(self.body) > _MAX_RESPONSE_BYTES
            or len(self.headers) > 8
        ):
            raise ConsentDestinationProtocolError("provider response is invalid")
        for key, value in self.headers.items():
            if (
                not isinstance(key, str)
                or key.lower() not in {"content-type", "content-length", "retry-after"}
                or not isinstance(value, str)
                or len(value) > 4096
                or _CONTROL_RE.search(value)
            ):
                raise ConsentDestinationProtocolError("provider response is invalid")


class ConsentDestinationHTTPTransport(Protocol):
    def request(self, request: DestinationHTTPRequest) -> DestinationHTTPResponse: ...


class PinnedConsentDestinationHTTPTransport:
    """DNS-pinned, redirect-disabled, bounded provider HTTP transport."""

    def request(self, request: DestinationHTTPRequest) -> DestinationHTTPResponse:
        if not isinstance(request, DestinationHTTPRequest):
            raise ConsentDestinationProtocolError("provider request is invalid")
        if os.environ.get("MAVERICK_FETCH_ALLOW_PRIVATE", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }:
            raise ConsentDestinationRequestNotSent(
                "destination transport refuses the private-fetch override"
            )
        try:
            from .enterprise import enterprise_egress_denial
            from .tools._ssrf import BlockedHost, safe_client
        except ImportError as exc:
            raise ConsentDestinationRequestNotSent(
                "destination egress authority is unavailable"
            ) from exc

        try:
            started_at = time.monotonic()
            denial = enterprise_egress_denial(
                request.url,
                tool=f"consent_delivery.{request.provider_id}",
            )
            if denial:
                raise ConsentDestinationRequestNotSent(
                    "destination egress is denied"
                )
            with safe_client(
                request.url,
                timeout=request.timeout_seconds,
                follow_redirects=False,
            ) as client:
                with client.stream(
                    request.method,
                    request.url,
                    headers=dict(request.headers),
                    content=request.body,
                ) as response:
                    if time.monotonic() - started_at > request.timeout_seconds:
                        raise ConsentDestinationTransportAmbiguous(
                            "destination response exceeded its elapsed timeout"
                        )
                    if 300 <= int(response.status_code) < 400:
                        raise ConsentDestinationTransportAmbiguous(
                            "destination redirect was refused after dispatch"
                        )
                    declared = response.headers.get("content-length")
                    if declared is not None:
                        try:
                            declared_size = int(declared)
                        except ValueError:
                            raise ConsentDestinationTransportAmbiguous(
                                "destination response length is invalid"
                            ) from None
                        if not 0 <= declared_size <= request.max_response_bytes:
                            raise ConsentDestinationTransportAmbiguous(
                                "destination response exceeds its byte bound"
                            )
                    chunks: list[bytes] = []
                    observed = 0
                    for chunk in response.iter_bytes():
                        if time.monotonic() - started_at > request.timeout_seconds:
                            raise ConsentDestinationTransportAmbiguous(
                                "destination response exceeded its elapsed timeout"
                            )
                        observed += len(chunk)
                        if observed > request.max_response_bytes:
                            raise ConsentDestinationTransportAmbiguous(
                                "destination response exceeds its byte bound"
                            )
                        chunks.append(chunk)
                    safe_headers = {
                        key.lower(): value
                        for key, value in response.headers.items()
                        if key.lower()
                        in {"content-type", "content-length", "retry-after"}
                        and isinstance(value, str)
                        and len(value) <= 4096
                        and not _CONTROL_RE.search(value)
                    }
                    return DestinationHTTPResponse(
                        status_code=int(response.status_code),
                        headers=safe_headers,
                        body=b"".join(chunks),
                    )
        except ConsentDestinationAdapterError:
            raise
        except BlockedHost as exc:
            raise ConsentDestinationRequestNotSent(
                "destination host was blocked"
            ) from exc
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise ConsentDestinationTransportAmbiguous(
                "destination transport outcome is unavailable"
            ) from exc


def _operation_key(
    tenant_id: str, destination_id: str, message_id: str
) -> tuple[str, str, str]:
    return tuple(
        hashlib.sha256(value.encode("utf-8")).hexdigest()
        for value in (tenant_id, destination_id, message_id)
    )


class ConsentDestinationOperationStore:
    """Digest-only provider-operation state for replay and reconciliation."""

    def __init__(self, path: str | Path, *, clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path)
        self._clock = clock
        if not callable(clock):
            raise ConsentDestinationConfigError("operation clock is invalid")
        ensure_private_directory(self.path.parent)
        self._initialize()

    @contextlib.contextmanager
    def _connect(self):
        if consent_storage.shared():
            connection = consent_storage.connect(self.path, timeout=30)
        else:
            connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=30000")
        except BaseException:
            if isinstance(connection, sqlite3.Connection):
                connection.close()
            raise
        try:
            yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS consent_destination_operations("
                "tenant_sha256 TEXT NOT NULL,destination_sha256 TEXT NOT NULL,"
                "message_sha256 TEXT NOT NULL,provider_id TEXT NOT NULL,"
                "binding_sha256 TEXT NOT NULL,request_sha256 TEXT NOT NULL,"
                "payload_sha256 TEXT,expected_records INTEGER,provider_record_ref TEXT,"
                "state TEXT NOT NULL,attempts INTEGER NOT NULL,status_code INTEGER,"
                "receipt_sha256 TEXT,evidence_sha256 TEXT,revision INTEGER NOT NULL,"
                "created_at REAL NOT NULL,updated_at REAL NOT NULL,"
                "record_sha256 TEXT NOT NULL,PRIMARY KEY(tenant_sha256,"
                "destination_sha256,message_sha256))"
            )
            columns = {
                str(row[1])
                for row in connection.execute(
                    "PRAGMA table_info(consent_destination_operations)"
                )
            }
            if "payload_sha256" not in columns:
                connection.execute(
                    "ALTER TABLE consent_destination_operations "
                    "ADD COLUMN payload_sha256 TEXT"
                )
            if "expected_records" not in columns:
                connection.execute(
                    "ALTER TABLE consent_destination_operations "
                    "ADD COLUMN expected_records INTEGER"
                )
            if "provider_record_ref" not in columns:
                connection.execute(
                    "ALTER TABLE consent_destination_operations "
                    "ADD COLUMN provider_record_ref TEXT"
                )
        if not consent_storage.shared():
            ensure_private_file(self.path)

    def _now(self) -> float:
        try:
            value = float(self._clock())
        except (TypeError, ValueError, OverflowError):
            raise ConsentDestinationConfigError("operation clock is invalid") from None
        if not math.isfinite(value) or value <= 0:
            raise ConsentDestinationConfigError("operation clock is invalid")
        return value

    @staticmethod
    def _material(row: Mapping[str, Any]) -> dict[str, Any]:
        material = {
            key: row[key]
            for key in (
                "tenant_sha256",
                "destination_sha256",
                "message_sha256",
                "provider_id",
                "binding_sha256",
                "request_sha256",
                "state",
                "attempts",
                "status_code",
                "receipt_sha256",
                "evidence_sha256",
                "revision",
                "created_at",
                "updated_at",
            )
        }
        payload_sha256 = row["payload_sha256"]
        if payload_sha256 is not None:
            material["payload_sha256"] = payload_sha256
        expected_records = row["expected_records"]
        if expected_records is not None:
            material["expected_records"] = expected_records
        provider_record_ref = row["provider_record_ref"]
        if provider_record_ref is not None:
            material["provider_record_ref"] = provider_record_ref
        return material

    @classmethod
    def _record_sha256(cls, row: Mapping[str, Any]) -> str:
        return _sha256(cls._material(row))

    @classmethod
    def _assert_row(cls, row: sqlite3.Row) -> None:
        state = str(row["state"])
        digests = (
            row["tenant_sha256"],
            row["destination_sha256"],
            row["message_sha256"],
            row["binding_sha256"],
            row["request_sha256"],
            row["record_sha256"],
        )
        optional_digests = (
            row["payload_sha256"],
            row["receipt_sha256"],
            row["evidence_sha256"],
        )
        if (
            state not in _OPERATION_STATES
            or any(
                not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None
                for value in digests
            )
            or any(
                value is not None
                and (not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None)
                for value in optional_digests
            )
            or not isinstance(row["attempts"], int)
            or int(row["attempts"]) < 1
            or not isinstance(row["revision"], int)
            or int(row["revision"]) < 1
            or (
                row["expected_records"] is not None
                and (
                    not isinstance(row["expected_records"], int)
                    or not 1 <= int(row["expected_records"]) <= 128
                )
            )
            or (
                row["provider_record_ref"] is not None
                and (
                    not isinstance(row["provider_record_ref"], str)
                    or _TOKEN_RE.fullmatch(row["provider_record_ref"]) is None
                )
            )
            or (state == "completed" and row["receipt_sha256"] is None)
            or (state == "ambiguous" and row["evidence_sha256"] is None)
            or not hmac.compare_digest(
                cls._record_sha256(row), str(row["record_sha256"])
            )
        ):
            raise ConsentDestinationConflict("destination operation record changed")

    def _write(
        self,
        connection: sqlite3.Connection,
        row: Mapping[str, Any],
        *,
        expected_revision: int | None,
    ) -> None:
        material = dict(row)
        material["record_sha256"] = self._record_sha256(material)
        if expected_revision is None:
            connection.execute(
                "INSERT INTO consent_destination_operations(tenant_sha256,"
                "destination_sha256,message_sha256,provider_id,binding_sha256,"
                "request_sha256,payload_sha256,expected_records,provider_record_ref,"
                "state,attempts,"
                "status_code,receipt_sha256,"
                "evidence_sha256,revision,created_at,updated_at,record_sha256)"
                "VALUES(:tenant_sha256,:destination_sha256,:message_sha256,"
                ":provider_id,:binding_sha256,:request_sha256,:payload_sha256,"
                ":expected_records,:provider_record_ref,:state,:attempts,"
                ":status_code,:receipt_sha256,:evidence_sha256,:revision,"
                ":created_at,:updated_at,:record_sha256)",
                material,
            )
            return
        updated = connection.execute(
            "UPDATE consent_destination_operations SET provider_id=:provider_id,"
            "binding_sha256=:binding_sha256,request_sha256=:request_sha256,"
            "payload_sha256=:payload_sha256,expected_records=:expected_records,"
            "provider_record_ref=:provider_record_ref,"
            "state=:state,"
            "attempts=:attempts,status_code=:status_code,receipt_sha256=:receipt_sha256,"
            "evidence_sha256=:evidence_sha256,revision=:revision,updated_at=:updated_at,"
            "record_sha256=:record_sha256 WHERE tenant_sha256=:tenant_sha256 AND "
            "destination_sha256=:destination_sha256 AND message_sha256=:message_sha256 "
            "AND revision=:expected_revision",
            {**material, "expected_revision": expected_revision},
        )
        if updated.rowcount != 1:
            raise ConsentDestinationConflict("destination operation CAS failed")

    def begin(
        self,
        binding: ConsentDestinationBinding,
        *,
        message_id: str,
        request_sha256: str,
        payload_sha256: str,
        expected_records: int,
        provider_record_ref: str,
    ) -> Mapping[str, Any] | None:
        message = _token(message_id, "message_id")
        request_digest = _digest(request_sha256, "request_sha256")
        payload_digest = _digest(payload_sha256, "payload_sha256")
        expected = _integer(expected_records, "expected_records", 1, 128)
        provider_ref = _token(provider_record_ref, "provider_record_ref")
        tenant_digest, destination_digest, message_digest = _operation_key(
            binding.tenant_id, binding.destination_id, message
        )
        now = self._now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT * FROM consent_destination_operations WHERE "
                    "tenant_sha256=? AND destination_sha256=? AND message_sha256=?",
                    (tenant_digest, destination_digest, message_digest),
                ).fetchone()
                if row is None:
                    record = {
                        "tenant_sha256": tenant_digest,
                        "destination_sha256": destination_digest,
                        "message_sha256": message_digest,
                        "provider_id": binding.provider_id,
                        "binding_sha256": binding.authority_sha256,
                        "request_sha256": request_digest,
                        "payload_sha256": payload_digest,
                        "expected_records": expected,
                        "provider_record_ref": provider_ref,
                        "state": "preparing",
                        "attempts": 1,
                        "status_code": None,
                        "receipt_sha256": None,
                        "evidence_sha256": None,
                        "revision": 1,
                        "created_at": now,
                        "updated_at": now,
                    }
                    self._write(connection, record, expected_revision=None)
                    connection.execute("COMMIT")
                    return None
                self._assert_row(row)
                if (
                    row["provider_id"] != binding.provider_id
                    or row["request_sha256"] != request_digest
                    or row["payload_sha256"] not in {None, payload_digest}
                    or row["expected_records"] not in {None, expected}
                    or row["provider_record_ref"] not in {None, provider_ref}
                ):
                    raise ConsentDestinationConflict(
                        "destination operation authority changed"
                    )
                state = str(row["state"])
                if (
                    state in {"ambiguous", "dispatching", "revoked"}
                    and row["binding_sha256"] != binding.authority_sha256
                ):
                    raise ConsentDestinationConflict(
                        "destination operation authority changed"
                    )
                if state == "completed":
                    connection.execute("COMMIT")
                    return {
                        "state": state,
                        "status_code": int(row["status_code"] or 204),
                        "receipt_sha256": str(row["receipt_sha256"]),
                        "no_change": True,
                    }
                if state in {"ambiguous", "dispatching"}:
                    if state == "dispatching":
                        record = dict(row)
                        record.update(
                            payload_sha256=payload_digest,
                            expected_records=expected,
                            provider_record_ref=provider_ref,
                            state="ambiguous",
                            evidence_sha256=_sha256(
                                {
                                    "reason": "dispatch_interrupted",
                                    "request_sha256": request_digest,
                                }
                            ),
                            revision=int(row["revision"]) + 1,
                            updated_at=now,
                        )
                        self._write(
                            connection, record, expected_revision=int(row["revision"])
                        )
                    connection.execute("COMMIT")
                    raise ConsentDestinationReconciliationRequired(
                        "destination outcome is ambiguous; reconcile before replay"
                    )
                if state == "revoked":
                    raise ConsentDeliveryRevoked("destination operation is revoked")
                if (
                    state == "preparing"
                    and now - float(row["updated_at"]) <= _PREPARING_LEASE_SECONDS
                ):
                    raise ConsentDestinationConflict(
                        "destination operation preparation is already active"
                    )
                record = dict(row)
                record.update(
                    binding_sha256=binding.authority_sha256,
                    payload_sha256=payload_digest,
                    expected_records=expected,
                    provider_record_ref=provider_ref,
                    state="preparing",
                    attempts=int(row["attempts"]) + 1,
                    status_code=None,
                    receipt_sha256=None,
                    evidence_sha256=None,
                    revision=int(row["revision"]) + 1,
                    updated_at=now,
                )
                self._write(connection, record, expected_revision=int(row["revision"]))
                connection.execute("COMMIT")
                return None
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def transition(
        self,
        binding: ConsentDestinationBinding,
        *,
        message_id: str,
        request_sha256: str,
        from_states: frozenset[str],
        state: str,
        status_code: int | None = None,
        receipt_sha256: str | None = None,
        evidence_sha256: str | None = None,
    ) -> Mapping[str, Any]:
        if state not in _OPERATION_STATES:
            raise ConsentDestinationProtocolError("operation state is invalid")
        request_digest = _digest(request_sha256, "request_sha256")
        if receipt_sha256 is not None:
            _digest(receipt_sha256, "receipt_sha256")
        if evidence_sha256 is not None:
            _digest(evidence_sha256, "evidence_sha256")
        tenant_digest, destination_digest, message_digest = _operation_key(
            binding.tenant_id,
            binding.destination_id,
            _token(message_id, "message_id"),
        )
        now = self._now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT * FROM consent_destination_operations WHERE "
                    "tenant_sha256=? AND destination_sha256=? AND message_sha256=?",
                    (tenant_digest, destination_digest, message_digest),
                ).fetchone()
                if row is None:
                    raise ConsentDestinationConflict("destination operation is missing")
                self._assert_row(row)
                if (
                    row["binding_sha256"] != binding.authority_sha256
                    or row["request_sha256"] != request_digest
                    or row["state"] not in from_states
                ):
                    raise ConsentDestinationConflict(
                        "destination operation transition was refused"
                    )
                record = dict(row)
                record.update(
                    state=state,
                    status_code=status_code,
                    receipt_sha256=receipt_sha256,
                    evidence_sha256=evidence_sha256,
                    revision=int(row["revision"]) + 1,
                    updated_at=now,
                )
                self._write(connection, record, expected_revision=int(row["revision"]))
                connection.execute("COMMIT")
                return self._material(record)
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def ambiguous(
        self, tenant_id: str, destination_id: str, *, limit: int = 100
    ) -> list[dict[str, Any]]:
        tenant = _tenant(tenant_id)
        destination = _token(destination_id, "destination_id")
        bounded = _integer(limit, "ambiguous limit", 1, 500)
        tenant_digest, destination_digest, _ = _operation_key(
            tenant, destination, "placeholder"
        )
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM consent_destination_operations WHERE tenant_sha256=? "
                "AND destination_sha256=? AND state='ambiguous' ORDER BY updated_at "
                "LIMIT ?",
                (tenant_digest, destination_digest, bounded),
            ).fetchall()
        result = []
        for row in rows:
            self._assert_row(row)
            result.append(
                {
                    "provider_id": str(row["provider_id"]),
                    "message_sha256": str(row["message_sha256"]),
                    "binding_sha256": str(row["binding_sha256"]),
                    "request_sha256": str(row["request_sha256"]),
                    "payload_sha256": row["payload_sha256"],
                    "expected_records": row["expected_records"],
                    "evidence_sha256": row["evidence_sha256"],
                    "attempts": int(row["attempts"]),
                    "revision": int(row["revision"]),
                    "updated_at": float(row["updated_at"]),
                }
            )
        return result

    def operation(
        self,
        tenant_id: str,
        destination_id: str,
        message_sha256: str,
    ) -> Mapping[str, Any]:
        """Return one minimized operation receipt by its already-hashed key."""

        tenant = _tenant(tenant_id)
        destination = _token(destination_id, "destination_id")
        message_digest = _digest(message_sha256, "message_sha256")
        tenant_digest, destination_digest, _ = _operation_key(
            tenant, destination, "placeholder"
        )
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM consent_destination_operations WHERE "
                "tenant_sha256=? AND destination_sha256=? AND message_sha256=?",
                (tenant_digest, destination_digest, message_digest),
            ).fetchone()
        if row is None:
            raise ConsentDestinationConflict("destination operation is missing")
        self._assert_row(row)
        return {
            "schema": DESTINATION_RECEIPT_SCHEMA,
            "provider_id": str(row["provider_id"]),
            "message_sha256": message_digest,
            "binding_sha256": str(row["binding_sha256"]),
            "request_sha256": str(row["request_sha256"]),
            "payload_sha256": row["payload_sha256"],
            "expected_records": row["expected_records"],
            "state": str(row["state"]),
            "attempts": int(row["attempts"]),
            "status_code": row["status_code"],
            "receipt_sha256": row["receipt_sha256"],
            "evidence_sha256": row["evidence_sha256"],
            "revision": int(row["revision"]),
            "updated_at": float(row["updated_at"]),
            "completed_replay_is_no_change": row["state"] == "completed",
            "raw_provider_payload_returned": False,
            "credential_material_returned": False,
        }

    def reconciliation_candidate(
        self,
        tenant_id: str,
        destination_id: str,
        *,
        message_sha256: str,
        request_sha256: str,
    ) -> Mapping[str, Any]:
        """Resolve one exact ambiguous row, including its server-only read key."""

        tenant = _tenant(tenant_id)
        destination = _token(destination_id, "destination_id")
        message_digest = _digest(message_sha256, "message_sha256")
        request_digest = _digest(request_sha256, "request_sha256")
        tenant_digest, destination_digest, _ = _operation_key(
            tenant,
            destination,
            "placeholder",
        )
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM consent_destination_operations WHERE "
                "tenant_sha256=? AND destination_sha256=? AND message_sha256=?",
                (tenant_digest, destination_digest, message_digest),
            ).fetchone()
        if row is None:
            raise ConsentDestinationConflict("ambiguous operation is missing")
        self._assert_row(row)
        if row["state"] != "ambiguous" or row["request_sha256"] != request_digest:
            raise ConsentDestinationConflict("ambiguous operation authority changed")
        return {
            "provider_id": str(row["provider_id"]),
            "binding_sha256": str(row["binding_sha256"]),
            "message_sha256": message_digest,
            "request_sha256": request_digest,
            "payload_sha256": row["payload_sha256"],
            "expected_records": row["expected_records"],
            "provider_record_ref": row["provider_record_ref"],
            "prior_evidence_sha256": row["evidence_sha256"],
        }

    def reconcile_digest(
        self,
        binding: ConsentDestinationBinding,
        *,
        message_sha256: str,
        request_sha256: str,
        disposition: str,
        evidence_sha256: str,
    ) -> Mapping[str, Any]:
        message_digest = _digest(message_sha256, "message_sha256")
        request_digest = _digest(request_sha256, "request_sha256")
        evidence_digest = _digest(evidence_sha256, "evidence_sha256")
        if disposition not in {"applied", "not_applied", "revoked"}:
            raise ConsentDestinationProtocolError(
                "reconciliation disposition is invalid"
            )
        tenant_digest, destination_digest, _ = _operation_key(
            binding.tenant_id, binding.destination_id, "placeholder"
        )
        now = self._now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT * FROM consent_destination_operations WHERE "
                    "tenant_sha256=? AND destination_sha256=? AND message_sha256=?",
                    (tenant_digest, destination_digest, message_digest),
                ).fetchone()
                if row is None:
                    raise ConsentDestinationConflict("ambiguous operation is missing")
                self._assert_row(row)
                if any(
                    (
                        row["state"] != "ambiguous",
                        row["binding_sha256"] != binding.authority_sha256,
                        row["request_sha256"] != request_digest,
                    )
                ):
                    raise ConsentDestinationConflict(
                        "ambiguous operation authority changed"
                    )
                state = {
                    "applied": "completed",
                    "not_applied": "retryable",
                    "revoked": "revoked",
                }[disposition]
                receipt = evidence_digest if disposition == "applied" else None
                status = 204 if disposition == "applied" else None
                record = dict(row)
                record.update(
                    state=state,
                    status_code=status,
                    receipt_sha256=receipt,
                    evidence_sha256=evidence_digest,
                    revision=int(row["revision"]) + 1,
                    updated_at=now,
                )
                self._write(connection, record, expected_revision=int(row["revision"]))
                connection.execute("COMMIT")
                return {
                    "schema": DESTINATION_RECONCILIATION_SCHEMA,
                    "provider_id": binding.provider_id,
                    "destination_id": binding.destination_id,
                    "message_sha256": message_digest,
                    "request_sha256": request_digest,
                    "disposition": disposition,
                    "state": state,
                    "evidence_sha256": evidence_digest,
                    "revision": record["revision"],
                }
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def revoke_destination(
        self, binding: ConsentDestinationBinding, *, evidence_sha256: str
    ) -> Mapping[str, int]:
        evidence = _digest(evidence_sha256, "evidence_sha256")
        tenant_digest, destination_digest, _ = _operation_key(
            binding.tenant_id, binding.destination_id, "placeholder"
        )
        now = self._now()
        changed = 0
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                rows = connection.execute(
                    "SELECT * FROM consent_destination_operations WHERE "
                    "tenant_sha256=? AND destination_sha256=? AND state NOT IN "
                    "('completed','rejected','revoked')",
                    (tenant_digest, destination_digest),
                ).fetchall()
                for row in rows:
                    self._assert_row(row)
                    record = dict(row)
                    record.update(
                        state="revoked",
                        evidence_sha256=evidence,
                        revision=int(row["revision"]) + 1,
                        updated_at=now,
                    )
                    self._write(
                        connection, record, expected_revision=int(row["revision"])
                    )
                    changed += 1
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return {"revoked_operations": changed}

    def verify_integrity(self) -> Mapping[str, object]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM consent_destination_operations ORDER BY "
                "tenant_sha256,destination_sha256,message_sha256"
            ).fetchall()
        for row in rows:
            self._assert_row(row)
        return {
            "schema": "lightwork.consent-destination-operation-integrity.v1",
            "records": len(rows),
            "valid": True,
            "raw_payloads_persisted": False,
            "credential_material_persisted": False,
        }


@dataclass(frozen=True, slots=True)
class DestinationReconciliationProbe:
    tenant_id: str
    destination_id: str
    provider_id: str
    binding_sha256: str
    message_sha256: str
    request_sha256: str
    payload_sha256: str
    expected_records: int
    provider_record_ref: str
    prior_evidence_sha256: str | None

    def __post_init__(self) -> None:
        _tenant(self.tenant_id)
        _token(self.destination_id, "destination_id")
        if self.provider_id not in STOCK_DESTINATION_PROVIDERS:
            raise ConsentDestinationProtocolError("reconciliation provider is invalid")
        for value, label in (
            (self.binding_sha256, "binding_sha256"),
            (self.message_sha256, "message_sha256"),
            (self.request_sha256, "request_sha256"),
            (self.payload_sha256, "payload_sha256"),
        ):
            _digest(value, label)
        _integer(self.expected_records, "expected_records", 1, 128)
        _token(self.provider_record_ref, "provider_record_ref")
        if self.prior_evidence_sha256 is not None:
            _digest(self.prior_evidence_sha256, "prior_evidence_sha256")


@dataclass(frozen=True, slots=True)
class DestinationReconciliationResult:
    disposition: str
    provider_id: str
    binding_sha256: str
    message_sha256: str
    request_sha256: str
    payload_sha256: str
    expected_records: int
    provider_record_ref: str
    evidence_sha256: str

    def __post_init__(self) -> None:
        if self.disposition not in {"applied", "not_applied", "revoked"}:
            raise ConsentDestinationProtocolError(
                "reconciliation disposition is invalid"
            )
        if self.provider_id not in STOCK_DESTINATION_PROVIDERS:
            raise ConsentDestinationProtocolError("reconciliation provider is invalid")
        for value, label in (
            (self.binding_sha256, "binding_sha256"),
            (self.message_sha256, "message_sha256"),
            (self.request_sha256, "request_sha256"),
            (self.payload_sha256, "payload_sha256"),
            (self.evidence_sha256, "evidence_sha256"),
        ):
            _digest(value, label)
        _integer(self.expected_records, "expected_records", 1, 128)
        _token(self.provider_record_ref, "provider_record_ref")


class ConsentDestinationReconciliationAuthority(Protocol):
    def inspect(
        self, probe: DestinationReconciliationProbe
    ) -> DestinationReconciliationResult: ...


def _provider_ref(
    prefix: str,
    binding: ConsentDestinationBinding,
    value: object,
) -> str:
    if not isinstance(value, str) or _TOKEN_RE.fullmatch(value) is None:
        raise ConsentDestinationProtocolError("provider reference source is invalid")
    digest = _sha256(
        {
            "schema": "lightwork.consent-destination-provider-ref.v1",
            "tenant_id": binding.tenant_id,
            "destination_id": binding.destination_id,
            "kind": prefix,
            "source_ref": value,
        }
    )
    return f"lw-{prefix}-{digest}"


def _common_event(
    binding: ConsentDestinationBinding,
    envelope: Mapping[str, Any],
) -> Mapping[str, Any]:
    event = envelope.get("event")
    if not isinstance(event, Mapping):
        raise ConsentDestinationProtocolError("delivery event is invalid")
    required = {
        "schema",
        "event_id",
        "event_kind",
        "profile_id",
        "profile_revision",
        "receipt_id",
        "receipt_sha256",
        "policy_id",
        "policy_version",
        "policy_sha256",
        "choices",
        "occurred_at",
    }
    if set(event) != required:
        raise ConsentDestinationProtocolError("delivery event contract changed")
    common = {
        "schema": DESTINATION_EVENT_SCHEMA,
        "message_id": _provider_ref("message", binding, envelope["message_id"]),
        "event_id": _provider_ref("event", binding, event["event_id"]),
        "event_kind": event["event_kind"],
        "profile_id": _provider_ref("profile", binding, event["profile_id"]),
        "profile_revision": event["profile_revision"],
        "receipt_sha256": event["receipt_sha256"],
        "policy_id": _provider_ref("policy", binding, event["policy_id"]),
        "policy_version": event["policy_version"],
        "policy_sha256": event["policy_sha256"],
        "choices": event["choices"],
        "occurred_at": event["occurred_at"],
        "event_sha256": envelope["event_sha256"],
    }
    _canonical(common)
    return common


@dataclass(frozen=True, slots=True, repr=False)
class _ProviderPlan:
    method: str
    path: str
    query: tuple[tuple[str, str], ...]
    headers: Mapping[str, str]
    body: bytes = field(repr=False)


def _salesforce_plan(
    binding: ConsentDestinationBinding, common: Mapping[str, Any]
) -> _ProviderPlan:
    settings = binding.settings
    message = urllib.parse.quote(str(common["message_id"]), safe="")
    path = (
        f"/services/data/{settings['api_version']}/sobjects/"
        f"{settings['object_api_name']}/{settings['external_id_field']}/{message}"
    )
    common_bytes = _canonical(common)
    body = {
        "Lightwork_Profile_Id__c": common["profile_id"],
        "Lightwork_Profile_Revision__c": common["profile_revision"],
        "Lightwork_Event_Id__c": common["event_id"],
        "Lightwork_Event_Kind__c": common["event_kind"],
        "Lightwork_Receipt_SHA256__c": common["receipt_sha256"],
        "Lightwork_Policy_Id__c": common["policy_id"],
        "Lightwork_Policy_Version__c": common["policy_version"],
        "Lightwork_Policy_SHA256__c": common["policy_sha256"],
        "Lightwork_Choices_JSON__c": _canonical(common["choices"]).decode("ascii"),
        str(settings["payload_digest_field"]): hashlib.sha256(common_bytes).hexdigest(),
    }
    return _ProviderPlan(
        method="PATCH",
        path=path,
        query=(),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        body=_canonical(body),
    )


def _marketo_plan(
    binding: ConsentDestinationBinding, common: Mapping[str, Any]
) -> _ProviderPlan:
    settings = binding.settings
    common_bytes = _canonical(common)
    choices = common["choices"]
    if not isinstance(choices, list) or not 1 <= len(choices) <= 128:
        raise ConsentDestinationProtocolError("Marketo choices are invalid")
    items = []
    for choice in choices:
        if not isinstance(choice, Mapping):
            raise ConsentDestinationProtocolError("Marketo choice is invalid")
        choice_key = _sha256(
            {
                "message_id": common["message_id"],
                "purpose_id": choice.get("purpose_id"),
                "channel": choice.get("channel"),
                "vendor_id": choice.get("vendor_id"),
            }
        )
        items.append(
            {
                str(settings["dedupe_field"]): choice_key,
                str(settings["message_id_field"]): common["message_id"],
                "lightworkProfileId": common["profile_id"],
                "lightworkProfileRevision": common["profile_revision"],
                "lightworkEventId": common["event_id"],
                "lightworkEventKind": common["event_kind"],
                "lightworkPurposeId": choice.get("purpose_id"),
                "lightworkAction": choice.get("action"),
                "lightworkChannel": choice.get("channel"),
                "lightworkVendorId": choice.get("vendor_id"),
                "lightworkReceiptSha256": common["receipt_sha256"],
                "lightworkPolicyId": common["policy_id"],
                "lightworkPolicyVersion": common["policy_version"],
                "lightworkPolicySha256": common["policy_sha256"],
                str(settings["payload_digest_field"]): hashlib.sha256(
                    common_bytes
                ).hexdigest(),
            }
        )
    return _ProviderPlan(
        method="POST",
        path=f"/rest/v1/customobjects/{settings['custom_object_name']}.json",
        query=(),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        body=_canonical(
            {
                "action": "createOrUpdate",
                "dedupeBy": "dedupeFields",
                "input": items,
            }
        ),
    )


def _aep_plan(
    binding: ConsentDestinationBinding, common: Mapping[str, Any]
) -> _ProviderPlan:
    settings = binding.settings
    occurred = float(common["occurred_at"])
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(occurred))
    body = {
        "header": {
            "datasetId": settings["dataset_id"],
            "flowId": settings["flow_id"],
            "imsOrgId": settings["ims_org_id"],
            "schemaRef": {
                "id": settings["schema_id"],
                "contentType": "application/vnd.adobe.xed-full+json;version=1",
            },
        },
        "body": {
            "xdmMeta": {
                "schemaRef": {
                    "id": settings["schema_id"],
                    "contentType": "application/vnd.adobe.xed-full+json;version=1",
                }
            },
            "xdmEntity": {
                "_id": common["message_id"],
                "timestamp": timestamp,
                "eventType": "privacy.consentPreferences",
                "_lightwork": common,
            },
        },
    }
    return _ProviderPlan(
        method="POST",
        path=f"/collection/{urllib.parse.quote(str(settings['connection_id']), safe='')}",
        query=(),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        body=_canonical(body),
    )


def _quote_snowflake(value: object) -> str:
    identifier = _provider_identifier(value, "Snowflake identifier")
    return f'"{identifier}"'


def _snowflake_plan(
    binding: ConsentDestinationBinding,
    common: Mapping[str, Any],
    *,
    retry: bool,
) -> _ProviderPlan:
    settings = binding.settings
    table = ".".join(
        _quote_snowflake(settings[key]) for key in ("database", "schema", "table")
    )
    statement = (
        f"MERGE INTO {table} AS target USING (SELECT ? AS MESSAGE_ID, ? AS "
        "PROFILE_ID, ? AS PROFILE_REVISION, ? AS EVENT_ID, ? AS RECEIPT_SHA256, "
        "? AS POLICY_SHA256, ? AS PAYLOAD_SHA256, PARSE_JSON(?) AS CONSENT_EVENT) "
        "AS source ON target.MESSAGE_ID = source.MESSAGE_ID WHEN MATCHED AND "
        "target.PAYLOAD_SHA256 <> source.PAYLOAD_SHA256 THEN UPDATE SET "
        "PROFILE_ID=source.PROFILE_ID,PROFILE_REVISION=source.PROFILE_REVISION,"
        "EVENT_ID=source.EVENT_ID,RECEIPT_SHA256=source.RECEIPT_SHA256,"
        "POLICY_SHA256=source.POLICY_SHA256,PAYLOAD_SHA256=source.PAYLOAD_SHA256,"
        "CONSENT_EVENT=source.CONSENT_EVENT WHEN NOT MATCHED THEN INSERT "
        "(MESSAGE_ID,PROFILE_ID,PROFILE_REVISION,EVENT_ID,RECEIPT_SHA256,"
        "POLICY_SHA256,PAYLOAD_SHA256,CONSENT_EVENT) VALUES (source.MESSAGE_ID,"
        "source.PROFILE_ID,source.PROFILE_REVISION,source.EVENT_ID,"
        "source.RECEIPT_SHA256,source.POLICY_SHA256,source.PAYLOAD_SHA256,"
        "source.CONSENT_EVENT)"
    )
    common_bytes = _canonical(common)
    payload_digest = hashlib.sha256(common_bytes).hexdigest()
    values = (
        common["message_id"],
        common["profile_id"],
        common["profile_revision"],
        common["event_id"],
        common["receipt_sha256"],
        common["policy_sha256"],
        payload_digest,
        common_bytes.decode("ascii"),
    )
    bindings = {
        str(index): {
            "type": "FIXED" if isinstance(value, int) else "TEXT",
            "value": str(value),
        }
        for index, value in enumerate(values, start=1)
    }
    request_uuid = uuid.UUID(
        hashlib.sha256(str(common["message_id"]).encode("utf-8")).hexdigest()[:32]
    )
    body = {
        "statement": statement,
        "timeout": 60,
        "database": settings["database"],
        "schema": settings["schema"],
        "warehouse": settings["warehouse"],
        "role": settings["role"],
        "bindings": bindings,
        "parameters": {"QUERY_TAG": f"lightwork-consent:{common['message_id']}"},
    }
    query = [("requestId", str(request_uuid))]
    if retry:
        query.append(("retry", "true"))
    return _ProviderPlan(
        method="POST",
        path="/api/v2/statements",
        query=tuple(query),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        body=_canonical(body),
    )


def _provider_plan(
    binding: ConsentDestinationBinding,
    common: Mapping[str, Any],
    *,
    retry: bool,
) -> _ProviderPlan:
    builders = {
        SALESFORCE: _salesforce_plan,
        MARKETO: _marketo_plan,
        ADOBE_EXPERIENCE_PLATFORM: _aep_plan,
        SNOWFLAKE: _snowflake_plan,
    }
    if binding.provider_id == SNOWFLAKE:
        selected = _snowflake_plan(binding, common, retry=retry)
    else:
        selected = builders[binding.provider_id](binding, common)
    return _ProviderPlan(
        method=selected.method,
        path=selected.path,
        query=selected.query,
        headers={
            **dict(selected.headers),
            "User-Agent": "Lightwork-Consent-Destination/1.0",
        },
        body=selected.body,
    )


def _json_object(body: bytes) -> Mapping[str, Any]:
    try:
        value = json.loads(
            body.decode("utf-8"), object_pairs_hook=_unique_json_object
        )
    except (UnicodeError, ValueError, RecursionError):
        raise ConsentDestinationProtocolError(
            "provider response is not valid bounded JSON"
        ) from None
    if not isinstance(value, Mapping):
        raise ConsentDestinationProtocolError("provider response shape is invalid")
    return value


def _require_json_content_type(response: DestinationHTTPResponse) -> None:
    content_type = next(
        (
            value.lower()
            for key, value in response.headers.items()
            if key.lower() == "content-type"
        ),
        "",
    )
    if not content_type.startswith("application/json"):
        raise ConsentDestinationProtocolError(
            "provider JSON response content type is invalid"
        )


def _validate_success(
    binding: ConsentDestinationBinding, response: DestinationHTTPResponse
) -> None:
    provider_id = binding.provider_id
    if provider_id == SALESFORCE:
        if response.status_code not in {200, 201, 204}:
            raise ConsentDestinationProtocolError("Salesforce success status is invalid")
        if response.body:
            _require_json_content_type(response)
            _json_object(response.body)
    elif provider_id == MARKETO:
        if response.status_code != 200:
            raise ConsentDestinationProtocolError("Marketo success status is invalid")
        _require_json_content_type(response)
        body = _json_object(response.body)
        result = body.get("result")
        if body.get("success") is not True or not isinstance(result, list) or not result:
            raise ConsentDestinationProtocolError("Marketo success body is invalid")
        for item in result:
            if (
                not isinstance(item, Mapping)
                or item.get("status") not in {"created", "updated", "skipped"}
            ):
                raise ConsentDestinationProtocolError("Marketo result is invalid")
    elif provider_id == ADOBE_EXPERIENCE_PLATFORM:
        if response.status_code != 200:
            raise ConsentDestinationProtocolError("AEP success status is invalid")
        _require_json_content_type(response)
        body = _json_object(response.body)
        if (
            body.get("inletId") != binding.settings["connection_id"]
            or not isinstance(body.get("xactionId"), str)
            or not 1 <= len(body["xactionId"]) <= 512
            or _CONTROL_RE.search(body["xactionId"])
        ):
            raise ConsentDestinationProtocolError("AEP success body is invalid")
    else:
        if response.status_code != 200:
            raise ConsentDestinationProtocolError("Snowflake success status is invalid")
        _require_json_content_type(response)
        body = _json_object(response.body)
        if (
            body.get("sqlState") != "00000"
            or not isinstance(body.get("statementHandle"), str)
            or _AEP_REF_RE.fullmatch(body["statementHandle"]) is None
        ):
            raise ConsentDestinationProtocolError("Snowflake result reports an error")


def _retry_after(headers: Mapping[str, str]) -> float | None:
    value = headers.get("retry-after")
    if value is None:
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) and 0 <= parsed <= 86_400 else None


def _readback_plan(
    binding: ConsentDestinationBinding,
    probe: DestinationReconciliationProbe,
) -> _ProviderPlan:
    message_ref = probe.provider_record_ref
    settings = binding.settings
    if binding.provider_id == SALESFORCE:
        path = (
            f"/services/data/{settings['api_version']}/sobjects/"
            f"{settings['object_api_name']}/{settings['external_id_field']}/"
            f"{urllib.parse.quote(message_ref, safe='')}"
        )
        return _ProviderPlan(
            method="GET",
            path=path,
            query=(("fields", str(settings["payload_digest_field"])),),
            headers={"Accept": "application/json"},
            body=b"",
        )
    if binding.provider_id == MARKETO:
        fields = ",".join(
            (
                str(settings["message_id_field"]),
                str(settings["payload_digest_field"]),
            )
        )
        return _ProviderPlan(
            method="GET",
            path=f"/rest/v1/customobjects/{settings['custom_object_name']}.json",
            query=(
                ("filterType", str(settings["message_id_field"])),
                ("filterValues", message_ref),
                ("fields", fields),
            ),
            headers={"Accept": "application/json"},
            body=b"",
        )
    if binding.provider_id == SNOWFLAKE:
        table = ".".join(
            _quote_snowflake(settings[key])
            for key in ("database", "schema", "table")
        )
        statement = (
            f"SELECT PAYLOAD_SHA256 FROM {table} "
            "WHERE MESSAGE_ID = ? ORDER BY PAYLOAD_SHA256 LIMIT 2"
        )
        request_uuid = uuid.UUID(
            hashlib.sha256(
                f"readback:{probe.message_sha256}".encode("ascii")
            ).hexdigest()[:32]
        )
        body = {
            "statement": statement,
            "timeout": 60,
            "database": settings["database"],
            "schema": settings["schema"],
            "warehouse": settings["warehouse"],
            "role": settings["role"],
            "bindings": {"1": {"type": "TEXT", "value": message_ref}},
            "parameters": {"QUERY_TAG": f"lightwork-consent-readback:{message_ref}"},
        }
        return _ProviderPlan(
            method="POST",
            path="/api/v2/statements",
            query=(("requestId", str(request_uuid)),),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            body=_canonical(body),
        )
    raise ConsentDestinationConfigError(
        "AEP reconciliation requires a deployment-owned query authority"
    )


def _marketo_describe_plan(binding: ConsentDestinationBinding) -> _ProviderPlan:
    return _ProviderPlan(
        method="GET",
        path=(
            f"/rest/v1/customobjects/"
            f"{binding.settings['custom_object_name']}/describe.json"
        ),
        query=(),
        headers={"Accept": "application/json"},
        body=b"",
    )


def _salesforce_describe_plan(binding: ConsentDestinationBinding) -> _ProviderPlan:
    return _ProviderPlan(
        method="GET",
        path=(
            f"/services/data/{binding.settings['api_version']}/sobjects/"
            f"{binding.settings['object_api_name']}/describe"
        ),
        query=(),
        headers={"Accept": "application/json"},
        body=b"",
    )


def _validate_salesforce_readback_metadata(
    binding: ConsentDestinationBinding,
    response: DestinationHTTPResponse,
) -> None:
    if response.status_code != 200:
        raise ConsentDestinationProtocolError(
            "Salesforce describe status is outside its accepted contract"
        )
    _require_json_content_type(response)
    body = _json_object(response.body)
    fields = body.get("fields")
    if any(
        (
            body.get("name") != binding.settings["object_api_name"],
            body.get("queryable") is not True,
            body.get("updateable") is not True,
            not isinstance(fields, list),
            len(fields) > 1_024,
        )
    ):
        raise ConsentDestinationProtocolError(
            "Salesforce object metadata does not authorize readback"
        )
    by_name = {
        item.get("name"): item
        for item in fields
        if isinstance(item, Mapping) and isinstance(item.get("name"), str)
    }
    external = by_name.get(str(binding.settings["external_id_field"]))
    payload = by_name.get(str(binding.settings["payload_digest_field"]))
    if (
        not isinstance(external, Mapping)
        or external.get("externalId") is not True
        or external.get("createable") is not True
        or not isinstance(payload, Mapping)
        or payload.get("createable") is not True
        or payload.get("updateable") is not True
    ):
        raise ConsentDestinationProtocolError(
            "Salesforce fields do not authorize readback"
        )


def _snowflake_status_plan(response: DestinationHTTPResponse) -> _ProviderPlan:
    if response.status_code != 202:
        raise ConsentDestinationProtocolError("Snowflake status response is invalid")
    _require_json_content_type(response)
    body = _json_object(response.body)
    handle = body.get("statementHandle")
    status_path = body.get("statementStatusUrl")
    if (
        not isinstance(handle, str)
        or _AEP_REF_RE.fullmatch(handle) is None
        or status_path != f"/api/v2/statements/{handle}"
    ):
        raise ConsentDestinationProtocolError(
            "Snowflake status authority is invalid"
        )
    return _ProviderPlan(
        method="GET",
        path=status_path,
        query=(),
        headers={"Accept": "application/json"},
        body=b"",
    )


def _validate_marketo_readback_metadata(
    binding: ConsentDestinationBinding,
    response: DestinationHTTPResponse,
) -> None:
    if response.status_code != 200:
        raise ConsentDestinationProtocolError(
            "Marketo describe status is outside its accepted contract"
        )
    _require_json_content_type(response)
    body = _json_object(response.body)
    results = body.get("result")
    if body.get("success") is not True or not isinstance(results, list) or len(results) != 1:
        raise ConsentDestinationProtocolError("Marketo describe body is invalid")
    metadata = results[0]
    if not isinstance(metadata, Mapping):
        raise ConsentDestinationProtocolError("Marketo describe body is invalid")
    settings = binding.settings
    message_field = str(settings["message_id_field"])
    payload_field = str(settings["payload_digest_field"])
    dedupe_field = str(settings["dedupe_field"])
    searchable = metadata.get("searchableFields")
    fields = metadata.get("fields")
    dedupe = metadata.get("dedupeFields")
    if any(
        (
            metadata.get("name") != settings["custom_object_name"],
            not isinstance(searchable, list),
            [message_field] not in searchable,
            dedupe != [dedupe_field],
            not isinstance(fields, list),
        )
    ):
        raise ConsentDestinationProtocolError(
            "Marketo custom-object metadata does not authorize readback"
        )
    field_names = {
        item.get("name")
        for item in fields
        if isinstance(item, Mapping) and isinstance(item.get("name"), str)
    }
    if not {message_field, payload_field, dedupe_field}.issubset(field_names):
        raise ConsentDestinationProtocolError(
            "Marketo custom-object fields do not authorize readback"
        )


def _readback_disposition(
    binding: ConsentDestinationBinding,
    probe: DestinationReconciliationProbe,
    response: DestinationHTTPResponse,
) -> tuple[str, int]:
    if response.status_code == 404:
        return ("not_applied", 0)
    if response.status_code != 200:
        raise ConsentDestinationProtocolError(
            "provider readback status is outside its accepted contract"
        )
    _require_json_content_type(response)
    body = _json_object(response.body)
    payload_field = str(binding.settings.get("payload_digest_field", "PAYLOAD_SHA256"))
    if binding.provider_id == SALESFORCE:
        remote = body.get(payload_field)
        if not isinstance(remote, str) or _DIGEST_RE.fullmatch(remote) is None:
            raise ConsentDestinationProtocolError(
                "Salesforce readback digest is invalid"
            )
        return (
            "applied" if hmac.compare_digest(remote, probe.payload_sha256) else "not_applied",
            1,
        )
    if binding.provider_id == MARKETO:
        items = body.get("result")
        if body.get("success") is not True or not isinstance(items, list):
            raise ConsentDestinationProtocolError("Marketo readback body is invalid")
        if len(items) > 128:
            raise ConsentDestinationProtocolError("Marketo readback exceeds its bound")
        message_ref = probe.provider_record_ref
        matches = []
        for item in items:
            if not isinstance(item, Mapping):
                raise ConsentDestinationProtocolError("Marketo readback item is invalid")
            remote_message = item.get(str(binding.settings["message_id_field"]))
            remote_digest = item.get(payload_field)
            if remote_message != message_ref:
                raise ConsentDestinationProtocolError(
                    "Marketo readback identity is invalid"
                )
            if not isinstance(remote_digest, str) or _DIGEST_RE.fullmatch(
                remote_digest
            ) is None:
                raise ConsentDestinationProtocolError(
                    "Marketo readback digest is invalid"
                )
            matches.append(remote_digest)
        applied = len(matches) == probe.expected_records and all(
            hmac.compare_digest(value, probe.payload_sha256) for value in matches
        )
        return ("applied" if applied else "not_applied", len(matches))
    data = body.get("data")
    if body.get("sqlState") != "00000" or not isinstance(data, list):
        raise ConsentDestinationProtocolError("Snowflake readback body is invalid")
    if len(data) > 2:
        raise ConsentDestinationProtocolError("Snowflake readback exceeds its bound")
    values: list[str] = []
    for row in data:
        if (
            not isinstance(row, list)
            or len(row) != 1
            or not isinstance(row[0], str)
            or _DIGEST_RE.fullmatch(row[0]) is None
        ):
            raise ConsentDestinationProtocolError("Snowflake readback row is invalid")
        values.append(row[0])
    applied = len(values) == probe.expected_records and all(
        hmac.compare_digest(value, probe.payload_sha256) for value in values
    )
    return ("applied" if applied else "not_applied", len(values))


class StockConsentDestinationReconciliationAuthority:
    """Provider-specific, read-only reconciliation for supported stock sinks."""

    def __init__(
        self,
        registry: ConsentDestinationRegistry,
        *,
        credential_owner: DeploymentConsentDestinationCredentialOwner,
        http_transport: ConsentDestinationHTTPTransport,
    ) -> None:
        if not isinstance(registry, ConsentDestinationRegistry):
            raise ConsentDestinationConfigError("reconciliation registry is invalid")
        if not isinstance(
            credential_owner, DeploymentConsentDestinationCredentialOwner
        ):
            raise ConsentDestinationConfigError(
                "reconciliation credential owner is invalid"
            )
        if not callable(getattr(http_transport, "request", None)):
            raise ConsentDestinationConfigError("reconciliation transport is invalid")
        self.registry = registry
        self._credentials = credential_owner
        self._http = http_transport

    @staticmethod
    def supports(provider_id: str) -> bool:
        return provider_id in STOCK_RECONCILIATION_PROVIDERS

    def inspect(
        self,
        probe: DestinationReconciliationProbe,
    ) -> DestinationReconciliationResult:
        if not isinstance(probe, DestinationReconciliationProbe):
            raise ConsentDestinationProtocolError("reconciliation probe is invalid")
        binding = self.registry.binding(probe.destination_id)
        if any(
            (
                probe.tenant_id != self.registry.tenant_id,
                binding.tenant_id != probe.tenant_id,
                binding.provider_id != probe.provider_id,
                binding.authority_sha256 != probe.binding_sha256,
            )
        ):
            raise ConsentDestinationConflict(
                "reconciliation probe crossed its exact destination authority"
            )
        if not self.supports(binding.provider_id):
            raise ConsentDestinationConfigError(
                "AEP reconciliation requires a deployment-owned query authority"
            )
        lease = self._credentials.lease(binding)
        expected_credential_authority = _sha256(
            {
                "schema": "lightwork.consent-destination-credential-authority.v1",
                "tenant_id": binding.tenant_id,
                "destination_id": binding.destination_id,
                "provider_id": binding.provider_id,
                "credential_name_sha256": hashlib.sha256(
                    binding.credential_name.encode("ascii")
                ).hexdigest(),
                "credential_revision": binding.credential_revision,
            }
        )
        if (
            lease.credential_revision != binding.credential_revision
            or not hmac.compare_digest(
                lease.authority_sha256,
                expected_credential_authority,
            )
        ):
            raise ConsentDestinationCredentialError(
                "reconciliation credential authority changed"
            )
        metadata_sha256: str | None = None
        if binding.provider_id in {SALESFORCE, MARKETO}:
            describe = (
                _salesforce_describe_plan(binding)
                if binding.provider_id == SALESFORCE
                else _marketo_describe_plan(binding)
            )
            describe_response = self._http.request(
                DestinationHTTPRequest(
                    provider_id=binding.provider_id,
                    origin=binding.origin,
                    method=describe.method,
                    path=describe.path,
                    query=describe.query,
                    headers={
                        **dict(describe.headers),
                        "User-Agent": "Lightwork-Consent-Reconciliation/1.0",
                        **dict(lease.headers),
                    },
                    body=describe.body,
                    timeout_seconds=self.registry.timeout_seconds,
                    max_response_bytes=self.registry.max_response_bytes,
                )
            )
            if not isinstance(describe_response, DestinationHTTPResponse):
                raise ConsentDestinationProtocolError(
                    "Marketo describe response is invalid"
                )
            if binding.provider_id == SALESFORCE:
                _validate_salesforce_readback_metadata(binding, describe_response)
            else:
                _validate_marketo_readback_metadata(binding, describe_response)
            metadata_sha256 = hashlib.sha256(describe_response.body).hexdigest()
        plan = _readback_plan(binding, probe)
        request = DestinationHTTPRequest(
            provider_id=binding.provider_id,
            origin=binding.origin,
            method=plan.method,
            path=plan.path,
            query=plan.query,
            headers={
                **dict(plan.headers),
                "User-Agent": "Lightwork-Consent-Reconciliation/1.0",
                **dict(lease.headers),
            },
            body=plan.body,
            timeout_seconds=self.registry.timeout_seconds,
            max_response_bytes=self.registry.max_response_bytes,
        )
        response = self._http.request(request)
        if not isinstance(response, DestinationHTTPResponse):
            raise ConsentDestinationProtocolError("provider readback response is invalid")
        if binding.provider_id == SNOWFLAKE and response.status_code == 202:
            status = _snowflake_status_plan(response)
            response = self._http.request(
                DestinationHTTPRequest(
                    provider_id=binding.provider_id,
                    origin=binding.origin,
                    method=status.method,
                    path=status.path,
                    query=status.query,
                    headers={
                        **dict(status.headers),
                        "User-Agent": "Lightwork-Consent-Reconciliation/1.0",
                        **dict(lease.headers),
                    },
                    body=status.body,
                    timeout_seconds=self.registry.timeout_seconds,
                    max_response_bytes=self.registry.max_response_bytes,
                )
            )
            if not isinstance(response, DestinationHTTPResponse):
                raise ConsentDestinationProtocolError(
                    "Snowflake status response is invalid"
                )
        disposition, matched_records = _readback_disposition(binding, probe, response)
        evidence_sha256 = _sha256(
            {
                "schema": DESTINATION_RECONCILIATION_SCHEMA,
                "provider_id": binding.provider_id,
                "binding_sha256": binding.authority_sha256,
                "message_sha256": probe.message_sha256,
                "request_sha256": probe.request_sha256,
                "payload_sha256": probe.payload_sha256,
                "expected_records": probe.expected_records,
                "provider_record_ref_sha256": hashlib.sha256(
                    probe.provider_record_ref.encode("ascii")
                ).hexdigest(),
                "matched_records": matched_records,
                "disposition": disposition,
                "status_code": response.status_code,
                "response_body_sha256": hashlib.sha256(response.body).hexdigest(),
                "provider_metadata_sha256": metadata_sha256,
                "credential_material_recorded": False,
                "raw_provider_payload_recorded": False,
            }
        )
        return DestinationReconciliationResult(
            disposition=disposition,
            provider_id=binding.provider_id,
            binding_sha256=binding.authority_sha256,
            message_sha256=probe.message_sha256,
            request_sha256=probe.request_sha256,
            payload_sha256=probe.payload_sha256,
            expected_records=probe.expected_records,
            provider_record_ref=probe.provider_record_ref,
            evidence_sha256=evidence_sha256,
        )


class ConsentDestinationRouterTransport:
    """Route signed generic deliveries to one exact named provider binding."""

    def __init__(
        self,
        registry: ConsentDestinationRegistry,
        operation_store: ConsentDestinationOperationStore,
        *,
        destination_authority: Callable[[str, str], Mapping[str, Any]],
        credential_owner: DeploymentConsentDestinationCredentialOwner | None = None,
        http_transport: ConsentDestinationHTTPTransport | None = None,
        reconciliation_authority: ConsentDestinationReconciliationAuthority | None = None,
    ) -> None:
        if not isinstance(registry, ConsentDestinationRegistry):
            raise ConsentDestinationConfigError("destination registry is invalid")
        if not isinstance(operation_store, ConsentDestinationOperationStore):
            raise ConsentDestinationConfigError("destination operation store is invalid")
        if not callable(destination_authority):
            raise ConsentDestinationConfigError("destination authority is invalid")
        self.registry = registry
        self.operation_store = operation_store
        self._destination_authority = destination_authority
        self._credentials = credential_owner or DeploymentConsentDestinationCredentialOwner()
        self._http = http_transport or PinnedConsentDestinationHTTPTransport()
        self._reconciler = reconciliation_authority
        if not callable(getattr(self._credentials, "lease", None)):
            raise ConsentDestinationConfigError("credential owner is invalid")
        if not callable(getattr(self._http, "request", None)):
            raise ConsentDestinationConfigError("destination HTTP transport is invalid")
        if reconciliation_authority is not None and not callable(
            getattr(reconciliation_authority, "inspect", None)
        ):
            raise ConsentDestinationConfigError("reconciliation authority is invalid")

    @staticmethod
    def _envelope(request: SignedDeliveryRequest) -> Mapping[str, Any]:
        _validated_request_headers(request)
        try:
            envelope = json.loads(
                request.body.decode("ascii"), object_pairs_hook=_unique_json_object
            )
        except (UnicodeError, ValueError):
            raise ConsentDestinationProtocolError("delivery envelope is invalid") from None
        if not isinstance(envelope, Mapping):
            raise ConsentDestinationProtocolError("delivery envelope is invalid")
        return envelope

    def _authorize(
        self, request: SignedDeliveryRequest, binding: ConsentDestinationBinding
    ) -> None:
        if request.tenant_id != self.registry.tenant_id or any(
            (
                binding.tenant_id != request.tenant_id,
                binding.destination_id != request.destination_id,
                request.url != binding.origin + DELIVERY_PATH,
            )
        ):
            raise ConsentDeliveryRevoked("destination binding crossed its authority")
        try:
            authority = self._destination_authority(
                request.tenant_id, request.destination_id
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise ConsentDeliveryRevoked(
                "destination authority is unavailable"
            ) from exc
        if not isinstance(authority, Mapping) or any(
            (
                authority.get("destination_id") != binding.destination_id,
                authority.get("origin") != binding.origin,
                authority.get("status") != "active",
            )
        ):
            raise ConsentDeliveryRevoked("destination is no longer authorized")
        try:
            envelope = self._envelope(request)
            destination_revision = int(envelope["destination_revision"])
        except (KeyError, TypeError, ValueError):
            raise ConsentDeliveryRevoked("destination revision is invalid") from None
        if any(
            (
                authority.get("revision") != destination_revision,
                authority.get("active_key_id") != request.key_id,
            )
        ):
            raise ConsentDeliveryRevoked("destination revision or key changed")

    @staticmethod
    def _provider_receipt(
        binding: ConsentDestinationBinding,
        request_sha256: str,
        response: DestinationHTTPResponse,
    ) -> str:
        return _sha256(
            {
                "schema": DESTINATION_RECEIPT_SCHEMA,
                "provider_id": binding.provider_id,
                "binding_sha256": binding.authority_sha256,
                "request_sha256": request_sha256,
                "status_code": response.status_code,
                "response_body_sha256": hashlib.sha256(response.body).hexdigest(),
                "retry_after_seconds": _retry_after(response.headers),
                "credential_material_recorded": False,
            }
        )

    def _release_preparing(
        self,
        binding: ConsentDestinationBinding,
        *,
        message_id: str,
        request_sha256: str,
        reason: str,
    ) -> None:
        try:
            self.operation_store.transition(
                binding,
                message_id=message_id,
                request_sha256=request_sha256,
                from_states=frozenset({"preparing"}),
                state="retryable",
                evidence_sha256=_sha256(
                    {
                        "state": "proved_not_sent",
                        "reason": reason,
                        "request_sha256": request_sha256,
                    }
                ),
            )
        except ConsentDestinationAdapterError:
            pass

    def post(
        self,
        request: SignedDeliveryRequest,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> DeliveryResponse:
        """Translate and dispatch one already-authorized delivery claim."""

        try:
            envelope = self._envelope(request)
            binding = self.registry.binding(request.destination_id)
            self._authorize(request, binding)
            common = _common_event(binding, envelope)
            delivery_attempt = envelope.get("attempt")
            if (
                isinstance(delivery_attempt, bool)
                or not isinstance(delivery_attempt, int)
                or not 1 <= delivery_attempt <= 20
            ):
                raise ConsentDestinationProtocolError(
                    "delivery attempt binding is invalid"
                )
            plan = _provider_plan(
                binding,
                common,
                retry=delivery_attempt > 1,
            )
            payload_sha256 = hashlib.sha256(_canonical(common)).hexdigest()
            expected_records = (
                len(common["choices"])
                if binding.provider_id == MARKETO
                else 1
            )
            bounded_timeout = min(
                _number(timeout_seconds, "dispatcher timeout", 0.1, 60.0),
                self.registry.timeout_seconds,
            )
            bounded_response = min(
                _integer(
                    max_response_bytes,
                    "dispatcher max_response_bytes",
                    1024,
                    _MAX_RESPONSE_BYTES,
                ),
                self.registry.max_response_bytes,
            )
            request_sha256 = _sha256(
                {
                    "provider_id": binding.provider_id,
                    "tenant_sha256": hashlib.sha256(
                        binding.tenant_id.encode("utf-8")
                    ).hexdigest(),
                    "destination_id": binding.destination_id,
                    "origin": binding.origin,
                    "method": plan.method,
                    "path": plan.path,
                    "query": [pair for pair in plan.query if pair[0] != "retry"],
                    "headers": dict(plan.headers),
                    "body_sha256": hashlib.sha256(plan.body).hexdigest(),
                }
            )
            try:
                replay = self.operation_store.begin(
                    binding,
                    message_id=request.message_id,
                    request_sha256=request_sha256,
                    payload_sha256=payload_sha256,
                    expected_records=expected_records,
                    provider_record_ref=str(common["message_id"]),
                )
            except ConsentDestinationReconciliationRequired:
                return DeliveryResponse(
                    status_code=409,
                    response_sha256=_sha256(
                        {
                            "state": "reconciliation_required",
                            "request_sha256": request_sha256,
                        }
                    ),
                )
            if replay is not None:
                return DeliveryResponse(
                    status_code=int(replay["status_code"]),
                    response_sha256=str(replay["receipt_sha256"]),
                )
            try:
                lease = self._credentials.lease(binding)
            except ConsentDestinationCredentialError:
                self.operation_store.transition(
                    binding,
                    message_id=request.message_id,
                    request_sha256=request_sha256,
                    from_states=frozenset({"preparing"}),
                    state="retryable",
                    status_code=401,
                    receipt_sha256=_sha256(
                        {"state": "credential_rejected", "request_sha256": request_sha256}
                    ),
                )
                return DeliveryResponse(
                    status_code=401,
                    response_sha256=_sha256(
                        {"state": "credential_rejected", "request_sha256": request_sha256}
                    ),
                )
            try:
                if (
                    lease.credential_revision != binding.credential_revision
                    or lease.authority_sha256
                    != _sha256(
                        {
                            "schema": "lightwork.consent-destination-credential-authority.v1",
                            "tenant_id": binding.tenant_id,
                            "destination_id": binding.destination_id,
                            "provider_id": binding.provider_id,
                            "credential_name_sha256": hashlib.sha256(
                                binding.credential_name.encode("ascii")
                            ).hexdigest(),
                            "credential_revision": binding.credential_revision,
                        }
                    )
                ):
                    raise ConsentDestinationCredentialError(
                        "credential lease authority changed"
                    )
                if (
                    binding.provider_id == ADOBE_EXPERIENCE_PLATFORM
                    and lease.headers.get("x-gw-ims-org-id")
                    != binding.settings["ims_org_id"]
                ):
                    raise ConsentDestinationCredentialError(
                        "AEP credential organization does not match the binding"
                    )
                provider_request = DestinationHTTPRequest(
                    provider_id=binding.provider_id,
                    origin=binding.origin,
                    method=plan.method,
                    path=plan.path,
                    query=plan.query,
                    headers={**dict(plan.headers), **dict(lease.headers)},
                    body=plan.body,
                    timeout_seconds=bounded_timeout,
                    max_response_bytes=bounded_response,
                )
                self._authorize(request, binding)
            except BaseException:
                self._release_preparing(
                    binding,
                    message_id=request.message_id,
                    request_sha256=request_sha256,
                    reason="pre_dispatch_validation_failed",
                )
                raise
            self.operation_store.transition(
                binding,
                message_id=request.message_id,
                request_sha256=request_sha256,
                from_states=frozenset({"preparing"}),
                state="dispatching",
            )
            try:
                response = self._http.request(provider_request)
            except ConsentDestinationRequestNotSent as exc:
                self.operation_store.transition(
                    binding,
                    message_id=request.message_id,
                    request_sha256=request_sha256,
                    from_states=frozenset({"dispatching"}),
                    state="retryable",
                    evidence_sha256=_sha256(
                        {"state": "proved_not_sent", "request_sha256": request_sha256}
                    ),
                )
                raise ConsentDeliveryTransportError(
                    "destination request was not sent"
                ) from exc
            except Exception as exc:
                evidence = _sha256(
                    {"state": "ambiguous", "request_sha256": request_sha256}
                )
                self.operation_store.transition(
                    binding,
                    message_id=request.message_id,
                    request_sha256=request_sha256,
                    from_states=frozenset({"dispatching"}),
                    state="ambiguous",
                    evidence_sha256=evidence,
                )
                raise ConsentDeliveryTransportError(
                    "destination outcome is ambiguous"
                ) from exc
            if not isinstance(response, DestinationHTTPResponse):
                raise ConsentDestinationProtocolError("provider response is invalid")
            if len(response.body) > bounded_response:
                evidence = _sha256(
                    {
                        "state": "response_too_large",
                        "request_sha256": request_sha256,
                    }
                )
                self.operation_store.transition(
                    binding,
                    message_id=request.message_id,
                    request_sha256=request_sha256,
                    from_states=frozenset({"dispatching"}),
                    state="ambiguous",
                    evidence_sha256=evidence,
                )
                return DeliveryResponse(status_code=409, response_sha256=evidence)
            receipt = self._provider_receipt(binding, request_sha256, response)
            if binding.provider_id == SNOWFLAKE and response.status_code == 202:
                self.operation_store.transition(
                    binding,
                    message_id=request.message_id,
                    request_sha256=request_sha256,
                    from_states=frozenset({"dispatching"}),
                    state="retryable",
                    status_code=202,
                    evidence_sha256=receipt,
                )
                return DeliveryResponse(
                    status_code=503,
                    retry_after_seconds=_retry_after(response.headers),
                    response_sha256=receipt,
                )
            if 200 <= response.status_code < 300:
                try:
                    _validate_success(binding, response)
                except ConsentDestinationProtocolError:
                    self.operation_store.transition(
                        binding,
                        message_id=request.message_id,
                        request_sha256=request_sha256,
                        from_states=frozenset({"dispatching"}),
                        state="ambiguous",
                        evidence_sha256=receipt,
                    )
                    return DeliveryResponse(status_code=409, response_sha256=receipt)
                self.operation_store.transition(
                    binding,
                    message_id=request.message_id,
                    request_sha256=request_sha256,
                    from_states=frozenset({"dispatching"}),
                    state="completed",
                    status_code=response.status_code,
                    receipt_sha256=receipt,
                )
            elif response.status_code in _SAFE_RETRY_STATUSES:
                self.operation_store.transition(
                    binding,
                    message_id=request.message_id,
                    request_sha256=request_sha256,
                    from_states=frozenset({"dispatching"}),
                    state="retryable",
                    status_code=response.status_code,
                    evidence_sha256=receipt,
                )
            elif 300 <= response.status_code < 400:
                self.operation_store.transition(
                    binding,
                    message_id=request.message_id,
                    request_sha256=request_sha256,
                    from_states=frozenset({"dispatching"}),
                    state="ambiguous",
                    evidence_sha256=receipt,
                )
                return DeliveryResponse(status_code=409, response_sha256=receipt)
            else:
                self.operation_store.transition(
                    binding,
                    message_id=request.message_id,
                    request_sha256=request_sha256,
                    from_states=frozenset({"dispatching"}),
                    state="retryable",
                    status_code=response.status_code,
                    receipt_sha256=receipt,
                )
            return DeliveryResponse(
                status_code=response.status_code,
                retry_after_seconds=_retry_after(response.headers),
                response_sha256=receipt,
            )
        except (ConsentDeliveryRevoked, ConsentDeliveryTransportError):
            raise
        except ConsentDestinationAdapterError as exc:
            raise ConsentDeliveryTransportError(
                "named destination adapter rejected the delivery"
            ) from exc

    def reconcile(
        self,
        *,
        destination_id: str,
        message_sha256: str,
        request_sha256: str,
    ) -> Mapping[str, Any]:
        """Use an injected independent authority to resolve one ambiguity."""

        if self._reconciler is None:
            raise ConsentDestinationConfigError(
                "destination reconciliation authority is unavailable"
            )
        binding = self.registry.binding(destination_id)
        try:
            authority = self._destination_authority(
                binding.tenant_id,
                binding.destination_id,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise ConsentDeliveryRevoked(
                "destination authority is unavailable"
            ) from exc
        if not isinstance(authority, Mapping) or any(
            (
                authority.get("status") != "active",
                authority.get("origin") != binding.origin,
                authority.get("destination_id") != binding.destination_id,
            )
        ):
            evidence = _sha256(
                {
                    "state": "destination_revoked",
                    "binding_sha256": binding.authority_sha256,
                }
            )
            self.operation_store.revoke_destination(
                binding,
                evidence_sha256=evidence,
            )
            raise ConsentDeliveryRevoked(
                "destination was revoked before reconciliation"
            )
        match = self.operation_store.reconciliation_candidate(
            binding.tenant_id,
            binding.destination_id,
            message_sha256=message_sha256,
            request_sha256=request_sha256,
        )
        if (
            match.get("payload_sha256") is None
            or match.get("expected_records") is None
            or match.get("provider_record_ref") is None
        ):
            raise ConsentDestinationReconciliationRequired(
                "ambiguous operation predates provider readback authority"
            )
        probe = DestinationReconciliationProbe(
            tenant_id=binding.tenant_id,
            destination_id=binding.destination_id,
            provider_id=binding.provider_id,
            binding_sha256=binding.authority_sha256,
            message_sha256=message_sha256,
            request_sha256=request_sha256,
            payload_sha256=str(match["payload_sha256"]),
            expected_records=int(match["expected_records"]),
            provider_record_ref=str(match["provider_record_ref"]),
            prior_evidence_sha256=match.get("prior_evidence_sha256"),
        )
        try:
            result = self._reconciler.inspect(probe)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise ConsentDestinationReconciliationRequired(
                "destination reconciliation probe failed"
            ) from exc
        if not isinstance(result, DestinationReconciliationResult) or any(
            (
                result.provider_id != probe.provider_id,
                result.binding_sha256 != probe.binding_sha256,
                result.message_sha256 != probe.message_sha256,
                result.request_sha256 != probe.request_sha256,
                result.payload_sha256 != probe.payload_sha256,
                result.expected_records != probe.expected_records,
                result.provider_record_ref != probe.provider_record_ref,
            )
        ):
            raise ConsentDestinationConflict(
                "destination reconciliation result is not exactly bound"
            )
        before_authority = (
            authority.get("destination_id"),
            authority.get("origin"),
            authority.get("status"),
            authority.get("revision"),
            authority.get("active_key_id"),
        )
        try:
            current_authority = self._destination_authority(
                binding.tenant_id,
                binding.destination_id,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise ConsentDestinationReconciliationRequired(
                "destination authority could not be rechecked after readback"
            ) from exc
        if not isinstance(current_authority, Mapping):
            raise ConsentDestinationReconciliationRequired(
                "destination authority could not be rechecked after readback"
            )
        after_authority = (
            current_authority.get("destination_id"),
            current_authority.get("origin"),
            current_authority.get("status"),
            current_authority.get("revision"),
            current_authority.get("active_key_id"),
        )
        if before_authority != after_authority:
            if current_authority.get("status") != "active":
                self.operation_store.revoke_destination(
                    binding,
                    evidence_sha256=_sha256(
                        {
                            "state": "destination_revoked_during_reconciliation",
                            "binding_sha256": binding.authority_sha256,
                        }
                    ),
                )
                raise ConsentDeliveryRevoked(
                    "destination was revoked during reconciliation"
                )
            raise ConsentDestinationReconciliationRequired(
                "destination authority changed during reconciliation"
            )
        return self.operation_store.reconcile_digest(
            binding,
            message_sha256=result.message_sha256,
            request_sha256=result.request_sha256,
            disposition=result.disposition,
            evidence_sha256=result.evidence_sha256,
        )

    def readiness(self) -> Mapping[str, object]:
        status = self.registry.status(
            credential_reference_present=self._credentials.reference_present
        )
        reconciliation_installed = self._reconciler is not None
        providers = tuple(str(item) for item in status["providers"])
        supports = getattr(self._reconciler, "supports", None)
        reconciliation_supported = {
            provider: bool(supports(provider)) if callable(supports) else True
            for provider in providers
        } if reconciliation_installed else dict.fromkeys(providers, False)
        reconciliation_complete = reconciliation_installed and all(
            reconciliation_supported.values()
        )
        return {
            **dict(status),
            "ready": bool(status["ready"]) and reconciliation_complete,
            "operation_integrity": self.operation_store.verify_integrity(),
            "reconciliation_authority_installed": reconciliation_installed,
            "reconciliation_supported": reconciliation_supported,
            "reconciliation_complete": reconciliation_complete,
            "destination_authority_rechecked_before_dispatch": True,
            "destination_authority_rechecked_after_reconciliation": True,
            "dns_pinning_required": True,
            "redirects_followed": False,
            "credential_material_persisted": False,
        }


__all__ = [
    "ADOBE_EXPERIENCE_PLATFORM",
    "MARKETO",
    "SALESFORCE",
    "SNOWFLAKE",
    "STOCK_DESTINATION_PROVIDERS",
    "STOCK_RECONCILIATION_PROVIDERS",
    "ConsentDestinationAdapterError",
    "ConsentDestinationConfigError",
    "ConsentDestinationConflict",
    "ConsentDestinationCredentialError",
    "ConsentDestinationHTTPTransport",
    "ConsentDestinationOperationStore",
    "ConsentDestinationProtocolError",
    "ConsentDestinationReconciliationAuthority",
    "ConsentDestinationReconciliationRequired",
    "ConsentDestinationRegistry",
    "ConsentDestinationRequestNotSent",
    "ConsentDestinationRouterTransport",
    "ConsentDestinationTransportAmbiguous",
    "ConsentDestinationBinding",
    "DeploymentConsentDestinationCredentialOwner",
    "DestinationCredentialLease",
    "DestinationHTTPRequest",
    "DestinationHTTPResponse",
    "DestinationReconciliationProbe",
    "DestinationReconciliationResult",
    "PinnedConsentDestinationHTTPTransport",
    "StockConsentDestinationReconciliationAuthority",
    "build_consent_destination_registry",
]
