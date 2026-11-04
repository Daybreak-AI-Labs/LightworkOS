"""Credential-gated live contract acceptance for four AI-governance providers.

The harness is deliberately narrower than the underlying connector catalog.  It
admits exactly one read-only inventory provider (Hugging Face), one read-only
identity provider (Microsoft Entra), one sandbox-only GRC mutation contract
(ServiceNow IRM), and the read-only OpenAI organization Costs endpoint.

No live request is made until the operator supplies an exact consenting-test-
estate acknowledgement.  The ServiceNow write additionally requires a second
exact acknowledgement, an explicit non-production environment classification,
and an exact match against a closed, operator-reviewed origin allowlist.  A
hostname marker or environment self-declaration cannot authorize mutation.

Reports contain counts, booleans, fixed reason codes, and SHA-256 bindings.  A
secret value, raw tenant identifier, raw provider identifier, provider response
body, or exception message is never copied into evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

CONSENT_ACKNOWLEDGEMENT = (
    "I authorize bounded live provider contract tests against this consenting "
    "test estate."
)
SERVICENOW_WRITE_ACKNOWLEDGEMENT = (
    "I authorize one idempotent Lightwork finding write and replay to this "
    "ServiceNow test estate."
)
ESTATE_CLASSIFICATION = "consenting_test_estate"
CONFIG_SCHEMA = "lightwork.ai-provider-contract-acceptance.config.v1"
REPORT_SCHEMA = "lightwork.ai-provider-contract-acceptance.report.v1"
CHECK_SCHEMA = "lightwork.ai-provider-contract-acceptance.check.v1"

_SECRET_REFERENCE = re.compile(r"[A-Z][A-Z0-9_]{1,127}\Z")
_CASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_HF_NAMESPACE = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,94}[A-Za-z0-9])?\Z"
)
_SANDBOX_ENVIRONMENTS = frozenset({"dev", "test", "sandbox", "uat", "nonprod"})
_MAX_CONFIG_BYTES = 64 * 1024
_MAX_REPORT_BYTES = 64 * 1024


class ProviderContractAcceptanceConfigError(ValueError):
    """The acceptance configuration is malformed or outside its closed scope."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
            default=str,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ProviderContractAcceptanceConfigError(
            "acceptance value is not canonical JSON"
        ) from exc


def _sha256(value: object) -> str:
    payload = value if isinstance(value, bytes) else _canonical(value)
    return hashlib.sha256(payload).hexdigest()


def _text(value: object, label: str, maximum: int, *, required: bool = True) -> str:
    if not isinstance(value, str):
        raise ProviderContractAcceptanceConfigError(f"{label} must be a string")
    text = value.strip()
    if (
        (required and not text)
        or len(text) > maximum
        or any(ord(character) < 32 for character in text)
    ):
        raise ProviderContractAcceptanceConfigError(f"{label} is invalid")
    return text


def _secret_reference(value: object, label: str) -> str:
    reference = _text(value, label, 128)
    if not _SECRET_REFERENCE.fullmatch(reference):
        raise ProviderContractAcceptanceConfigError(
            f"{label} must name an environment or mounted secret"
        )
    return reference


def _enabled(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ProviderContractAcceptanceConfigError(f"{label} must be boolean")
    return value


def _section(value: object, label: str) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ProviderContractAcceptanceConfigError(f"{label} must be an object")
    return value


def _closed(section: Mapping[str, Any], allowed: set[str], label: str) -> None:
    unknown = set(section) - allowed
    if unknown:
        raise ProviderContractAcceptanceConfigError(
            f"{label} contains unsupported fields"
        )


def _https_origin(value: object, label: str) -> str:
    raw = _text(value, label, 2_048).rstrip("/")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise ProviderContractAcceptanceConfigError(f"{label} is invalid") from exc
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or port not in {None, 443}
    ):
        raise ProviderContractAcceptanceConfigError(
            f"{label} must be a credential-free HTTPS origin"
        )
    host = parsed.hostname.rstrip(".").lower()
    return f"https://{host}" + (":443" if port == 443 else "")


def _servicenow_origin(value: object, label: str) -> str:
    origin = _https_origin(value, label)
    host = (urlsplit(origin).hostname or "").lower()
    if not host.endswith(".service-now.com"):
        raise ProviderContractAcceptanceConfigError(
            f"{label} must be a service-now.com instance"
        )
    return origin


def _servicenow_origin_allowlist(value: object) -> tuple[str, ...]:
    label = "servicenow.write_origin_allowlist"
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)) or len(value) > 16:
        raise ProviderContractAcceptanceConfigError(
            f"{label} must be a bounded array of exact HTTPS origins"
        )
    origins = tuple(
        _servicenow_origin(item, f"{label}[{index}]")
        for index, item in enumerate(value)
    )
    if len(set(origins)) != len(origins):
        raise ProviderContractAcceptanceConfigError(
            f"{label} must not contain duplicate origins"
        )
    return tuple(sorted(origins))


@dataclass(frozen=True, repr=False)
class HuggingFaceAcceptanceConfig:
    enable: bool = False
    namespace: str = ""
    endpoint: str = "https://huggingface.co"
    credential_secret_ref: str = "HF_TOKEN"

    def __post_init__(self) -> None:
        object.__setattr__(self, "enable", _enabled(self.enable, "hugging_face.enable"))
        endpoint = _https_origin(self.endpoint, "hugging_face.endpoint")
        if endpoint != "https://huggingface.co":
            raise ProviderContractAcceptanceConfigError(
                "hugging_face.endpoint must be https://huggingface.co"
            )
        object.__setattr__(self, "endpoint", endpoint)
        object.__setattr__(
            self,
            "credential_secret_ref",
            _secret_reference(
                self.credential_secret_ref,
                "hugging_face.credential_secret_ref",
            ),
        )
        namespace = _text(
            self.namespace,
            "hugging_face.namespace",
            96,
            required=self.enable,
        )
        if namespace and not _HF_NAMESPACE.fullmatch(namespace):
            raise ProviderContractAcceptanceConfigError(
                "hugging_face.namespace is invalid"
            )
        object.__setattr__(self, "namespace", namespace)


@dataclass(frozen=True, repr=False)
class EntraAcceptanceConfig:
    enable: bool = False
    tenant_id: str = ""
    base_url: str = "https://graph.microsoft.com"
    credential_secret_ref: str = "ENTRA_DISCOVERY_TOKEN"

    def __post_init__(self) -> None:
        object.__setattr__(self, "enable", _enabled(self.enable, "entra.enable"))
        base_url = _https_origin(self.base_url, "entra.base_url")
        if base_url != "https://graph.microsoft.com":
            raise ProviderContractAcceptanceConfigError(
                "entra.base_url must be https://graph.microsoft.com"
            )
        object.__setattr__(self, "base_url", base_url)
        object.__setattr__(
            self,
            "credential_secret_ref",
            _secret_reference(self.credential_secret_ref, "entra.credential_secret_ref"),
        )
        object.__setattr__(
            self,
            "tenant_id",
            _text(self.tenant_id, "entra.tenant_id", 256, required=self.enable),
        )


@dataclass(frozen=True, repr=False)
class ServiceNowAcceptanceConfig:
    enable: bool = False
    base_url: str = ""
    environment: str = ""
    write_origin_allowlist: tuple[str, ...] = ()
    credential_secret_ref: str = "SERVICENOW_TOKEN"
    write_acknowledgement: str = ""
    case_id: str = "lightwork-provider-contract-v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "enable", _enabled(self.enable, "servicenow.enable"))
        base_url = (
            _servicenow_origin(self.base_url, "servicenow.base_url")
            if self.base_url or self.enable
            else ""
        )
        object.__setattr__(self, "base_url", base_url)
        object.__setattr__(
            self,
            "environment",
            _text(
                self.environment,
                "servicenow.environment",
                32,
                required=self.enable,
            ).lower(),
        )
        object.__setattr__(
            self,
            "write_origin_allowlist",
            _servicenow_origin_allowlist(self.write_origin_allowlist),
        )
        object.__setattr__(
            self,
            "credential_secret_ref",
            _secret_reference(
                self.credential_secret_ref,
                "servicenow.credential_secret_ref",
            ),
        )
        object.__setattr__(
            self,
            "write_acknowledgement",
            _text(
                self.write_acknowledgement,
                "servicenow.write_acknowledgement",
                256,
                required=False,
            ),
        )
        case_id = _text(self.case_id, "servicenow.case_id", 64)
        if not _CASE_ID.fullmatch(case_id):
            raise ProviderContractAcceptanceConfigError(
                "servicenow.case_id is invalid"
            )
        object.__setattr__(self, "case_id", case_id)


@dataclass(frozen=True, repr=False)
class OpenAICostsAcceptanceConfig:
    enable: bool = False
    organization_ref: str = ""
    credential_secret_ref: str = "OPENAI_ADMIN_KEY"
    period_start: str = ""
    period_end: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "enable", _enabled(self.enable, "openai_costs.enable"))
        object.__setattr__(
            self,
            "credential_secret_ref",
            _secret_reference(
                self.credential_secret_ref,
                "openai_costs.credential_secret_ref",
            ),
        )
        object.__setattr__(
            self,
            "organization_ref",
            _text(
                self.organization_ref,
                "openai_costs.organization_ref",
                256,
                required=self.enable,
            ),
        )
        start = _text(
            self.period_start,
            "openai_costs.period_start",
            64,
            required=self.enable,
        )
        end = _text(
            self.period_end,
            "openai_costs.period_end",
            64,
            required=self.enable,
        )
        if self.enable:
            from maverick.ai_cost_roi import CollectionRequest

            try:
                request = CollectionRequest(period_start=start, period_end=end)
            except (TypeError, ValueError) as exc:
                raise ProviderContractAcceptanceConfigError(
                    "openai_costs period is invalid"
                ) from exc
            started = datetime.fromisoformat(
                request.period_start.removesuffix("Z") + "+00:00"
            )
            ended = datetime.fromisoformat(
                request.period_end.removesuffix("Z") + "+00:00"
            )
            if (ended - started).total_seconds() > 7 * 86_400:
                raise ProviderContractAcceptanceConfigError(
                    "openai_costs acceptance period exceeds seven days"
                )
            start, end = request.period_start, request.period_end
        object.__setattr__(self, "period_start", start)
        object.__setattr__(self, "period_end", end)


@dataclass(frozen=True, repr=False)
class ProviderContractAcceptanceConfig:
    schema: str
    estate_classification: str
    consent_acknowledgement: str
    hugging_face: HuggingFaceAcceptanceConfig
    entra: EntraAcceptanceConfig
    servicenow: ServiceNowAcceptanceConfig
    openai_costs: OpenAICostsAcceptanceConfig

    @classmethod
    def from_mapping(cls, value: object) -> ProviderContractAcceptanceConfig:
        if not isinstance(value, Mapping):
            raise ProviderContractAcceptanceConfigError(
                "acceptance config must be an object"
            )
        _closed(
            value,
            {
                "schema",
                "estate_classification",
                "consent_acknowledgement",
                "hugging_face",
                "entra",
                "servicenow",
                "openai_costs",
            },
            "acceptance config",
        )
        schema = _text(value.get("schema", ""), "schema", 128)
        if schema != CONFIG_SCHEMA:
            raise ProviderContractAcceptanceConfigError("config schema is unsupported")
        hf = _section(value.get("hugging_face"), "hugging_face")
        entra = _section(value.get("entra"), "entra")
        servicenow = _section(value.get("servicenow"), "servicenow")
        openai = _section(value.get("openai_costs"), "openai_costs")
        _closed(
            hf,
            {"enable", "namespace", "endpoint", "credential_secret_ref"},
            "hugging_face",
        )
        _closed(
            entra,
            {"enable", "tenant_id", "base_url", "credential_secret_ref"},
            "entra",
        )
        _closed(
            servicenow,
            {
                "enable",
                "base_url",
                "environment",
                "write_origin_allowlist",
                "credential_secret_ref",
                "write_acknowledgement",
                "case_id",
            },
            "servicenow",
        )
        _closed(
            openai,
            {
                "enable",
                "organization_ref",
                "credential_secret_ref",
                "period_start",
                "period_end",
            },
            "openai_costs",
        )
        return cls(
            schema=schema,
            estate_classification=_text(
                value.get("estate_classification", ""),
                "estate_classification",
                64,
                required=False,
            ),
            consent_acknowledgement=_text(
                value.get("consent_acknowledgement", ""),
                "consent_acknowledgement",
                256,
                required=False,
            ),
            hugging_face=HuggingFaceAcceptanceConfig(
                enable=hf.get("enable", False),
                namespace=hf.get("namespace", ""),
                endpoint=hf.get("endpoint", "https://huggingface.co"),
                credential_secret_ref=hf.get("credential_secret_ref", "HF_TOKEN"),
            ),
            entra=EntraAcceptanceConfig(
                enable=entra.get("enable", False),
                tenant_id=entra.get("tenant_id", ""),
                base_url=entra.get("base_url", "https://graph.microsoft.com"),
                credential_secret_ref=entra.get(
                    "credential_secret_ref", "ENTRA_DISCOVERY_TOKEN"
                ),
            ),
            servicenow=ServiceNowAcceptanceConfig(
                enable=servicenow.get("enable", False),
                base_url=servicenow.get("base_url", ""),
                environment=servicenow.get("environment", ""),
                write_origin_allowlist=servicenow.get(
                    "write_origin_allowlist", ()
                ),
                credential_secret_ref=servicenow.get(
                    "credential_secret_ref", "SERVICENOW_TOKEN"
                ),
                write_acknowledgement=servicenow.get("write_acknowledgement", ""),
                case_id=servicenow.get(
                    "case_id", "lightwork-provider-contract-v1"
                ),
            ),
            openai_costs=OpenAICostsAcceptanceConfig(
                enable=openai.get("enable", False),
                organization_ref=openai.get("organization_ref", ""),
                credential_secret_ref=openai.get(
                    "credential_secret_ref", "OPENAI_ADMIN_KEY"
                ),
                period_start=openai.get("period_start", ""),
                period_end=openai.get("period_end", ""),
            ),
        )


CredentialProbe = Callable[[str, str], bool]
AdapterFactory = Callable[[object], object]


@dataclass(frozen=True)
class ProviderAcceptanceDependencies:
    """Injectable construction seams; defaults build the production adapters."""

    credential_probe: CredentialProbe
    hugging_face_factory: AdapterFactory
    entra_factory: AdapterFactory
    servicenow_factory: AdapterFactory
    openai_costs_factory: AdapterFactory
    clock: Callable[[], float] = time.time


def _default_credential_probe(provider: str, reference: str) -> bool:
    try:
        if provider in {"hugging_face", "openai_costs"}:
            value = os.environ.get(reference)
        else:
            from maverick.secret_provider import get_secret

            value = get_secret(reference)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False
    return bool(
        isinstance(value, str)
        and value
        and len(value.encode("utf-8")) <= 8_192
        and not any(character in value for character in "\r\n\x00")
    )


def _hugging_face_factory(config: object) -> object:
    assert isinstance(config, HuggingFaceAcceptanceConfig)
    from maverick.ai_inventory import DiscoveryLimits
    from maverick.ai_inventory_connectors import HuggingFaceInventoryAdapter

    return HuggingFaceInventoryAdapter(
        namespace=config.namespace,
        endpoint=config.endpoint,
        token_env=config.credential_secret_ref,
        limits=DiscoveryLimits(
            page_cap=20,
            record_cap=2_000,
            retry_attempts=3,
            timeout_seconds=20.0,
        ),
    )


def _entra_factory(config: object) -> object:
    assert isinstance(config, EntraAcceptanceConfig)
    from maverick.ai_identity_governance_connectors import (
        ConnectorConfig,
        ConnectorLimits,
        EntraIdentityGovernanceAdapter,
    )
    from maverick.secret_provider import get_secret

    from .identity_governance_runtime import PinnedIdentityGovernanceHTTPTransport

    return EntraIdentityGovernanceAdapter(
        ConnectorConfig(
            provider="entra",
            enable=True,
            tenant_id=config.tenant_id,
            base_url=config.base_url,
            credential_secret_ref=config.credential_secret_ref,
            limits=ConnectorLimits(
                timeout_seconds=15.0,
                max_pages=20,
                max_records=2_000,
                max_response_bytes=256 * 1_024,
                page_size=100,
                retry_attempts=3,
            ),
        ),
        transport=PinnedIdentityGovernanceHTTPTransport(),
        secret_resolver=get_secret,
    )


def _servicenow_factory(config: object) -> object:
    assert isinstance(config, ServiceNowAcceptanceConfig)
    from maverick.grc_vendor_transports import (
        ServiceNowIRMTransport,
        VendorTransportLimits,
    )

    return ServiceNowIRMTransport(
        base_url=config.base_url,
        credential_secret_ref=config.credential_secret_ref,
        limits=VendorTransportLimits(
            timeout_seconds=15.0,
            max_response_bytes=256 * 1_024,
        ),
    )


def _openai_costs_factory(config: object) -> object:
    assert isinstance(config, OpenAICostsAcceptanceConfig)
    from maverick.ai_cost_collectors import CollectorLimits
    from maverick.ai_cost_openai import OpenAIOrganizationCostCollector

    return OpenAIOrganizationCostCollector(
        organization_ref=config.organization_ref,
        enabled=True,
        admin_key_env=config.credential_secret_ref,
        limits=CollectorLimits(
            timeout_seconds=20.0,
            page_cap=10,
            record_cap=1_000,
            max_period_days=7,
            page_size=100,
        ),
    )


def default_dependencies() -> ProviderAcceptanceDependencies:
    return ProviderAcceptanceDependencies(
        credential_probe=_default_credential_probe,
        hugging_face_factory=_hugging_face_factory,
        entra_factory=_entra_factory,
        servicenow_factory=_servicenow_factory,
        openai_costs_factory=_openai_costs_factory,
    )


def _config_projection(config: object) -> Mapping[str, object]:
    if isinstance(config, HuggingFaceAcceptanceConfig):
        return {
            "provider": "hugging_face",
            "enable": config.enable,
            "namespace": config.namespace,
            "endpoint": config.endpoint,
            "credential_secret_ref": config.credential_secret_ref,
        }
    if isinstance(config, EntraAcceptanceConfig):
        return {
            "provider": "entra",
            "enable": config.enable,
            "tenant_id": config.tenant_id,
            "base_url": config.base_url,
            "credential_secret_ref": config.credential_secret_ref,
        }
    if isinstance(config, ServiceNowAcceptanceConfig):
        return {
            "provider": "servicenow",
            "enable": config.enable,
            "base_url": config.base_url,
            "environment": config.environment,
            "write_origin_allowlist": list(config.write_origin_allowlist),
            "credential_secret_ref": config.credential_secret_ref,
            "case_id": config.case_id,
        }
    assert isinstance(config, OpenAICostsAcceptanceConfig)
    return {
        "provider": "openai_costs",
        "enable": config.enable,
        "organization_ref": config.organization_ref,
        "credential_secret_ref": config.credential_secret_ref,
        "period_start": config.period_start,
        "period_end": config.period_end,
    }


def _base_check(
    provider: str,
    capability: str,
    operation: str,
    config: object,
    *,
    mutation: bool,
) -> dict[str, object]:
    return {
        "schema": CHECK_SCHEMA,
        "provider": provider,
        "capability": capability,
        "operation": operation,
        "status": "blocked",
        "reason_code": "preflight_blocked",
        "blocking_reasons": [],
        "live_request_attempted": False,
        "mutation_attempted": False,
        "mutation_contract": mutation,
        "secret_values_included": False,
        "provider_response_body_included": False,
        "config_sha256": _sha256(_config_projection(config)),
        "evidence": {},
        "limitations": [],
    }


def _readiness_checks(
    config: ProviderContractAcceptanceConfig,
    dependencies: ProviderAcceptanceDependencies,
) -> list[dict[str, object]]:
    definitions = (
        (
            "hugging_face",
            "ai_inventory",
            "bounded_namespace_model_listing",
            config.hugging_face,
            False,
        ),
        (
            "entra",
            "identity_discovery",
            "bounded_service_principal_and_grant_snapshot",
            config.entra,
            False,
        ),
        (
            "servicenow",
            "grc_writeback",
            "sandbox_finding_write_and_idempotency_replay",
            config.servicenow,
            True,
        ),
        (
            "openai_costs",
            "organization_costs",
            "bounded_complete_daily_cost_window",
            config.openai_costs,
            False,
        ),
    )
    checks: list[dict[str, object]] = []
    for provider, capability, operation, section, mutation in definitions:
        check = _base_check(
            provider,
            capability,
            operation,
            section,
            mutation=mutation,
        )
        reasons: list[str] = []
        if not section.enable:
            reasons.append("provider_disabled")
        if config.estate_classification != ESTATE_CLASSIFICATION:
            reasons.append("consenting_test_estate_not_declared")
        if config.consent_acknowledgement != CONSENT_ACKNOWLEDGEMENT:
            reasons.append("live_test_consent_not_acknowledged")
        if section.enable:
            reference = section.credential_secret_ref
            try:
                available = dependencies.credential_probe(provider, reference)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                available = False
            if not available:
                reasons.append("credential_unavailable")
        if isinstance(section, ServiceNowAcceptanceConfig):
            if section.write_acknowledgement != SERVICENOW_WRITE_ACKNOWLEDGEMENT:
                reasons.append("sandbox_write_not_acknowledged")
            if section.environment not in _SANDBOX_ENVIRONMENTS:
                reasons.append("sandbox_environment_not_declared")
            if section.base_url not in section.write_origin_allowlist:
                reasons.append("servicenow_write_origin_not_allowlisted")
        if reasons:
            check["blocking_reasons"] = reasons
            check["reason_code"] = reasons[0]
        else:
            check["status"] = "ready"
            check["reason_code"] = "preflight_ready"
        checks.append(check)
    return checks


def _hex(value: object, label: str) -> str:
    if not isinstance(value, str) or not _HEX_DIGEST.fullmatch(value):
        raise ValueError(f"{label} is not a SHA-256 digest")
    return value


def _run_hugging_face(
    check: dict[str, object],
    config: HuggingFaceAcceptanceConfig,
    dependencies: ProviderAcceptanceDependencies,
) -> None:
    adapter = dependencies.hugging_face_factory(config)
    check["live_request_attempted"] = True
    result = adapter.discover()
    pages = getattr(result, "pages", None)
    assets = tuple(getattr(result, "assets", ()))
    if (
        isinstance(pages, bool)
        or not isinstance(pages, int)
        or not 1 <= pages <= 20
        or len(assets) > 2_000
    ):
        raise ValueError("Hugging Face acceptance result exceeds its bounds")
    bindings: list[dict[str, str]] = []
    for asset in assets:
        source_id = getattr(asset, "source_id", None)
        version_digest = _hex(
            getattr(asset, "version_digest", None),
            "Hugging Face asset version",
        )
        if not isinstance(source_id, str) or not source_id:
            raise ValueError("Hugging Face asset source id is invalid")
        bindings.append(
            {
                "source_id_sha256": _sha256(source_id.encode("utf-8")),
                "version_digest": version_digest,
            }
        )
    check.update(
        {
            "status": "passed",
            "reason_code": "live_contract_passed",
            "blocking_reasons": [],
            "live_request_attempted": True,
            "evidence": {
                "pages": pages,
                "asset_count": len(assets),
                "normalized_binding_sha256": _sha256(
                    sorted(bindings, key=lambda item: item["source_id_sha256"])
                ),
                "scope": "configured_namespace_only",
                "complete_inventory_claimed": False,
            },
            "limitations": [
                "A complete configured namespace listing is not a complete enterprise AI inventory."
            ],
        }
    )


def _run_entra(
    check: dict[str, object],
    config: EntraAcceptanceConfig,
    dependencies: ProviderAcceptanceDependencies,
) -> None:
    adapter = dependencies.entra_factory(config)
    check["live_request_attempted"] = True
    snapshot = adapter.collect()
    identities = tuple(getattr(snapshot, "identities", ()))
    grants = tuple(getattr(snapshot, "grants", ()))
    classifications = tuple(getattr(snapshot, "data_classifications", ()))
    if len(identities) + len(grants) + len(classifications) > 2_000:
        raise ValueError("Entra acceptance result exceeds its record bound")
    check.update(
        {
            "status": "passed",
            "reason_code": "live_contract_passed",
            "blocking_reasons": [],
            "live_request_attempted": True,
            "evidence": {
                "identity_count": len(identities),
                "grant_count": len(grants),
                "classification_count": len(classifications),
                "snapshot_sha256": _hex(
                    getattr(snapshot, "source_sha256", None),
                    "Entra snapshot",
                ),
                "scope": getattr(snapshot, "coverage", "bounded_read_only_snapshot"),
                "complete_inventory_claimed": False,
            },
            "limitations": [
                "The result is a bounded read-only service-principal and grant snapshot."
            ],
        }
    )


def _servicenow_request(config: ServiceNowAcceptanceConfig) -> object:
    from maverick.grc_outbound_sync import (
        FindingSource,
        GRCSystem,
        OutboundRequest,
        ServiceNowIRMAdapter,
    )

    tenant_sha256 = _sha256(
        b"lightwork-provider-contract-servicenow-tenant-v1\0"
        + config.base_url.encode("utf-8")
    )
    source_digest = _sha256(
        {
            "schema": "lightwork.provider-contract.servicenow-source.v1",
            "case_id": config.case_id,
            "instance_origin": config.base_url,
        }
    )
    marker = _sha256([config.base_url, config.case_id])[:24]
    source = FindingSource(
        finding_id=f"provider-contract-{marker}",
        asset_id=f"acceptance-asset-{marker}",
        finding_type="provider_contract_acceptance",
        severity="low",
        summary="Lightwork ServiceNow sandbox provider-contract acceptance marker",
        source_revision=1,
        source_digest=source_digest,
    )
    dialect = ServiceNowIRMAdapter()
    payload = dialect.payload(source, tenant_sha256=tenant_sha256)
    return OutboundRequest(
        target=GRCSystem.SERVICENOW_IRM,
        operation=dialect.operation(source),
        source_kind=source.kind,
        source_id=source.source_id,
        source_revision=source.source_revision,
        source_digest=source.source_digest,
        tenant_sha256=tenant_sha256,
        idempotency_key=f"GRC-servicenow-contract-{marker}",
        payload_sha256=_sha256(payload),
        payload=payload,
    )


def _run_servicenow(
    check: dict[str, object],
    config: ServiceNowAcceptanceConfig,
    dependencies: ProviderAcceptanceDependencies,
) -> None:
    transport = dependencies.servicenow_factory(config)
    request = _servicenow_request(config)
    check["live_request_attempted"] = True
    check["mutation_attempted"] = True
    first = transport.send(request)
    replay = transport.send(request)
    fields = (
        "idempotency_key",
        "source_revision",
        "source_digest",
        "external_id",
        "external_url",
        "external_revision",
    )
    first_projection = {field: getattr(first, field, None) for field in fields}
    replay_projection = {field: getattr(replay, field, None) for field in fields}
    if first_projection != replay_projection:
        raise ValueError("ServiceNow idempotency replay returned a different binding")
    external_id = first_projection["external_id"]
    external_url = first_projection["external_url"]
    if not isinstance(external_id, str) or not isinstance(external_url, str):
        raise ValueError("ServiceNow response binding is invalid")
    check.update(
        {
            "status": "passed",
            "reason_code": "live_write_and_replay_passed",
            "blocking_reasons": [],
            "evidence": {
                "write_count": 1,
                "replay_count": 1,
                "replay_binding_equal": True,
                "request_sha256": _sha256(request.safe_projection()),
                "external_id_sha256": _sha256(external_id.encode("utf-8")),
                "external_url_sha256": _sha256(external_url.encode("utf-8")),
                "response_binding_sha256": _sha256(first_projection),
                "production_target_accepted": False,
            },
            "limitations": [
                "The acceptance record remains in the test instance for operator retention or cleanup."
            ],
        }
    )


def _run_openai_costs(
    check: dict[str, object],
    config: OpenAICostsAcceptanceConfig,
    dependencies: ProviderAcceptanceDependencies,
) -> None:
    from maverick.ai_cost_roi import CollectionRequest

    request = CollectionRequest(
        period_start=config.period_start,
        period_end=config.period_end,
        max_records=1_000,
    )
    collector = dependencies.openai_costs_factory(config)
    check["live_request_attempted"] = True
    collection = collector.collect(request)
    records = tuple(getattr(collection, "records", ()))
    if not 1 <= len(records) <= 1_000:
        raise ValueError("OpenAI Costs acceptance returned an invalid record count")
    manifest = getattr(collection, "manifest_citation", None)
    check.update(
        {
            "status": "passed",
            "reason_code": "live_contract_passed",
            "blocking_reasons": [],
            "live_request_attempted": True,
            "evidence": {
                "record_count": len(records),
                "period_start": request.period_start,
                "period_end": request.period_end,
                "batch_sha256": _sha256(
                    str(getattr(collection, "batch_id", "")).encode("utf-8")
                ),
                "manifest_sha256": _hex(
                    getattr(manifest, "sha256", None),
                    "OpenAI Costs manifest",
                ),
                "model_level_attribution_claimed": False,
            },
            "limitations": [
                "OpenAI organization Costs does not establish model-level cost attribution."
            ],
        }
    )


def _failure_code(exc: BaseException) -> tuple[str, str]:
    from maverick.ai_cost_collectors import (
        AICostCollectorConfigError,
        AICostCollectorLimitError,
        AICostCollectorNoData,
        AICostCollectorProtocolError,
        AICostCollectorTransportError,
    )
    from maverick.ai_identity_governance_connectors import (
        IdentityGovernanceConfigError,
        IdentityGovernanceLimitError,
        IdentityGovernanceProtocolError,
        IdentityGovernanceTransportError,
    )
    from maverick.ai_inventory import (
        AIInventoryConfigError,
        DiscoveryLimitError,
        DiscoveryProtocolError,
        DiscoveryTransportError,
    )
    from maverick.grc_outbound_sync import GRCTransportFailure

    if isinstance(exc, AICostCollectorNoData):
        return "blocked", "openai_costs_no_billable_rows"
    if isinstance(exc, GRCTransportFailure):
        category = getattr(exc, "category", "grc_transport_failure")
        if isinstance(category, str) and re.fullmatch(r"[a-z0-9_:-]{1,128}", category):
            return "failed", category
        return "failed", "grc_transport_failure"
    classifications = (
        (AIInventoryConfigError, "inventory_config_error"),
        (DiscoveryLimitError, "inventory_limit_error"),
        (DiscoveryProtocolError, "inventory_protocol_error"),
        (DiscoveryTransportError, "inventory_transport_error"),
        (IdentityGovernanceConfigError, "identity_config_error"),
        (IdentityGovernanceLimitError, "identity_limit_error"),
        (IdentityGovernanceProtocolError, "identity_protocol_error"),
        (IdentityGovernanceTransportError, "identity_transport_error"),
        (AICostCollectorConfigError, "openai_costs_config_error"),
        (AICostCollectorLimitError, "openai_costs_limit_error"),
        (AICostCollectorProtocolError, "openai_costs_protocol_error"),
        (AICostCollectorTransportError, "openai_costs_transport_error"),
    )
    for exception_type, code in classifications:
        if isinstance(exc, exception_type):
            return "failed", code
    return "failed", "unexpected_runtime_error"


def _overall(checks: list[dict[str, object]], *, readiness_only: bool) -> str:
    statuses = {str(check["status"]) for check in checks}
    if "failed" in statuses:
        return "failed"
    if "blocked" in statuses:
        return "blocked"
    if readiness_only and statuses == {"ready"}:
        return "ready"
    if not readiness_only and statuses == {"passed"}:
        return "passed"
    return "failed"


def run_acceptance(
    config: ProviderContractAcceptanceConfig,
    *,
    readiness_only: bool = False,
    dependencies: ProviderAcceptanceDependencies | None = None,
) -> dict[str, object]:
    """Run preflight or live contracts and return bounded, secret-free evidence."""

    if not isinstance(config, ProviderContractAcceptanceConfig):
        raise TypeError("config must be ProviderContractAcceptanceConfig")
    if not isinstance(readiness_only, bool):
        raise TypeError("readiness_only must be boolean")
    selected = dependencies or default_dependencies()
    try:
        now = float(selected.clock())
    except (TypeError, ValueError, OverflowError) as exc:
        raise ProviderContractAcceptanceConfigError("acceptance clock is invalid") from exc
    if not math.isfinite(now) or now < 0:
        raise ProviderContractAcceptanceConfigError("acceptance clock is invalid")
    checks = _readiness_checks(config, selected)
    if not readiness_only:
        runners = {
            "hugging_face": lambda check: _run_hugging_face(
                check, config.hugging_face, selected
            ),
            "entra": lambda check: _run_entra(check, config.entra, selected),
            "servicenow": lambda check: _run_servicenow(
                check, config.servicenow, selected
            ),
            "openai_costs": lambda check: _run_openai_costs(
                check, config.openai_costs, selected
            ),
        }
        for check in checks:
            if check["status"] != "ready":
                continue
            provider = str(check["provider"])
            try:
                runners[provider](check)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                status, reason = _failure_code(exc)
                check.update(
                    {
                        "status": status,
                        "reason_code": reason,
                        "blocking_reasons": ([reason] if status == "blocked" else []),
                        "evidence": {},
                        "exception_message_included": False,
                    }
                )
    mode = "readiness_only" if readiness_only else "live_contract_acceptance"
    generated = datetime.fromtimestamp(now, tz=timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    status = _overall(checks, readiness_only=readiness_only)
    report: dict[str, object] = {
        "schema": REPORT_SCHEMA,
        "mode": mode,
        "status": status,
        "generated_at": generated,
        "run_id": "PAC-" + _sha256([generated, mode, [c["config_sha256"] for c in checks]])[:32],
        "checks": checks,
        "summary": {
            label: sum(check["status"] == label for check in checks)
            for label in ("ready", "passed", "blocked", "failed")
        },
        "admission": {
            "consenting_test_estate_declared": (
                config.estate_classification == ESTATE_CLASSIFICATION
            ),
            "live_test_consent_acknowledged": (
                config.consent_acknowledgement == CONSENT_ACKNOWLEDGEMENT
            ),
            "servicenow_sandbox_write_acknowledged": (
                config.servicenow.write_acknowledgement
                == SERVICENOW_WRITE_ACKNOWLEDGEMENT
            ),
            "servicenow_write_origin_allowlisted": (
                config.servicenow.base_url
                in config.servicenow.write_origin_allowlist
            ),
        },
        "configured_contracts_live_accepted": status == "passed",
        "complete_enterprise_inventory_claimed": False,
        "production_acceptance_claimed": False,
        "secret_values_included": False,
        "raw_provider_response_bodies_included": False,
    }
    report["report_sha256"] = _sha256(report)
    if len(_canonical(report)) > _MAX_REPORT_BYTES:
        raise RuntimeError("acceptance report exceeded its byte bound")
    return report


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProviderContractAcceptanceConfigError(
                "acceptance config contains duplicate fields"
            )
        result[key] = value
    return result


def load_config_file(path: Path) -> ProviderContractAcceptanceConfig:
    if path.is_symlink():
        raise ProviderContractAcceptanceConfigError(
            "acceptance config must be a regular non-symlink file"
        )
    resolved = path.resolve(strict=True)
    if not resolved.is_file() or resolved.is_symlink():
        raise ProviderContractAcceptanceConfigError(
            "acceptance config must be a regular non-symlink file"
        )
    payload = resolved.read_bytes()
    if not 1 <= len(payload) <= _MAX_CONFIG_BYTES:
        raise ProviderContractAcceptanceConfigError(
            "acceptance config exceeds its byte bound"
        )
    try:
        decoded = payload.decode("utf-8")
        value = json.loads(decoded, object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ProviderContractAcceptanceConfigError(
            "acceptance config is not valid JSON"
        ) from exc
    return ProviderContractAcceptanceConfig.from_mapping(value)


def example_config() -> dict[str, object]:
    """Return an executable-shape template; placeholder secrets are references."""

    return {
        "schema": CONFIG_SCHEMA,
        "estate_classification": ESTATE_CLASSIFICATION,
        "consent_acknowledgement": CONSENT_ACKNOWLEDGEMENT,
        "hugging_face": {
            "enable": True,
            "namespace": "consenting-test-namespace",
            "endpoint": "https://huggingface.co",
            "credential_secret_ref": "HF_TOKEN",
        },
        "entra": {
            "enable": True,
            "tenant_id": "00000000-0000-4000-8000-000000000000",
            "base_url": "https://graph.microsoft.com",
            "credential_secret_ref": "ENTRA_DISCOVERY_TOKEN",
        },
        "servicenow": {
            "enable": True,
            "base_url": "https://dev00000.service-now.com",
            "environment": "dev",
            "write_origin_allowlist": ["https://dev00000.service-now.com"],
            "credential_secret_ref": "SERVICENOW_TOKEN",
            "write_acknowledgement": SERVICENOW_WRITE_ACKNOWLEDGEMENT,
            "case_id": "lightwork-provider-contract-v1",
        },
        "openai_costs": {
            "enable": True,
            "organization_ref": "consenting-test-organization",
            "credential_secret_ref": "OPENAI_ADMIN_KEY",
            "period_start": "2026-08-01T00:00:00Z",
            "period_end": "2026-08-02T00:00:00Z",
        },
    }


def _render(value: object) -> str:
    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"


def _write_output(path: Path | None, text: str) -> None:
    if path is None:
        sys.stdout.write(text)
        return
    from maverick.file_lock import atomic_write_text

    atomic_write_text(path, text, mode=0o600, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run bounded live provider contract acceptance."
    )
    parser.add_argument("--config", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--readiness-only", action="store_true")
    parser.add_argument("--print-template", action="store_true")
    args = parser.parse_args(argv)
    if args.print_template:
        if args.config is not None:
            parser.error("--print-template cannot be combined with --config")
        _write_output(args.output, _render(example_config()))
        return 0
    if args.config is None:
        parser.error("--config is required unless --print-template is used")
    try:
        config = load_config_file(args.config)
        report = run_acceptance(config, readiness_only=args.readiness_only)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        report = {
            "schema": REPORT_SCHEMA,
            "mode": "readiness_only" if args.readiness_only else "live_contract_acceptance",
            "status": "failed",
            "reason_code": "config_or_harness_error",
            "exception_message_included": False,
            "secret_values_included": False,
        }
        report["report_sha256"] = _sha256(report)
    _write_output(args.output, _render(report))
    return {"passed": 0, "ready": 0, "blocked": 2}.get(str(report["status"]), 1)


__all__ = [
    "CONFIG_SCHEMA",
    "CONSENT_ACKNOWLEDGEMENT",
    "ESTATE_CLASSIFICATION",
    "ProviderAcceptanceDependencies",
    "ProviderContractAcceptanceConfig",
    "ProviderContractAcceptanceConfigError",
    "REPORT_SCHEMA",
    "SERVICENOW_WRITE_ACKNOWLEDGEMENT",
    "default_dependencies",
    "example_config",
    "load_config_file",
    "main",
    "run_acceptance",
]


if __name__ == "__main__":
    raise SystemExit(main())
