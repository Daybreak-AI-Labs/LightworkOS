"""Stock production composition for consent application-manifest analysis."""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from fastapi import Request
from maverick import consent_application_scanner as application_scanner
from maverick.paths import canonical_tenant_id, current_tenant_id_strict, tenant_scope

_CONFIG_KEYS = frozenset({"enable", "max_records", "retention_seconds"})
_DEFAULT_MAX_RECORDS = 25_000
_DEFAULT_RETENTION_SECONDS = 31_536_000
_MAX_CACHED_TENANTS = 4_096


class ConsentApplicationScannerCompositionError(application_scanner.ConsentApplicationScanError):
    """Deployment configuration or request authority is unavailable."""


@dataclass(frozen=True, slots=True)
class ConsentApplicationScannerSettings:
    max_records: int
    retention_seconds: int


def _integer(value: object, label: str, lower: int, upper: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        raise ConsentApplicationScannerCompositionError(f"{label} is outside its bound")
    return value


def consent_application_scanner_settings(
    config: Mapping[str, Any],
) -> ConsentApplicationScannerSettings | None:
    """Validate the closed nested configuration; return ``None`` only when off."""

    if not isinstance(config, Mapping):
        raise ConsentApplicationScannerCompositionError(
            "consent application-scanner configuration is unavailable"
        )
    consent = config.get("consent_preferences")
    if not isinstance(consent, Mapping):
        return None
    section = consent.get("application_scanner")
    if section is None:
        return None
    if not isinstance(section, Mapping):
        raise ConsentApplicationScannerCompositionError(
            "consent_preferences.application_scanner must be a table"
        )
    unknown = sorted(str(key) for key in section if key not in _CONFIG_KEYS)
    if unknown:
        raise ConsentApplicationScannerCompositionError(
            "consent application-scanner configuration contains an unknown key"
        )
    enabled = section.get("enable", False)
    if type(enabled) is not bool:
        raise ConsentApplicationScannerCompositionError(
            "consent application-scanner enable gate must be true or false"
        )
    if enabled is not True:
        return None
    if consent.get("enable") is not True:
        raise ConsentApplicationScannerCompositionError(
            "consent application scanning requires consent_preferences.enable"
        )
    return ConsentApplicationScannerSettings(
        max_records=_integer(
            section.get("max_records", _DEFAULT_MAX_RECORDS),
            "consent application-scanner max_records",
            1,
            1_000_000,
        ),
        retention_seconds=_integer(
            section.get("retention_seconds", _DEFAULT_RETENTION_SECONDS),
            "consent application-scanner retention_seconds",
            86_400,
            315_360_000,
        ),
    )


def _load_tenant_config(tenant_id: str) -> Mapping[str, Any]:
    tenant = canonical_tenant_id(tenant_id)
    try:
        from maverick import config as config_module

        with tenant_scope(tenant=tenant):
            loaded = config_module.load_config()
            errors = config_module.config_source_errors(include_tenant=True)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise ConsentApplicationScannerCompositionError(
            "consent application-scanner configuration is unavailable"
        ) from exc
    if errors or not isinstance(loaded, Mapping):
        raise ConsentApplicationScannerCompositionError(
            "consent application-scanner configuration is unavailable"
        )
    return loaded


def settings_for_tenant(tenant_id: str) -> ConsentApplicationScannerSettings:
    settings = consent_application_scanner_settings(_load_tenant_config(tenant_id))
    if settings is None:
        raise ConsentApplicationScannerCompositionError("consent application scanning is disabled")
    return settings


def consent_application_scanner_enabled(tenant_id: str) -> bool:
    try:
        return consent_application_scanner_settings(_load_tenant_config(tenant_id)) is not None
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def _request_for(app: Any, request: object, tenant_id: str) -> Request:
    if not isinstance(request, Request):
        raise ConsentApplicationScannerCompositionError(
            "consent application-scanner request authority is unavailable"
        )
    try:
        owner = request.app
    except Exception as exc:
        raise ConsentApplicationScannerCompositionError(
            "consent application-scanner request authority is unavailable"
        ) from exc
    if owner is not app:
        raise ConsentApplicationScannerCompositionError(
            "consent application-scanner request authority is unavailable"
        )
    tenant = canonical_tenant_id(tenant_id)
    if current_tenant_id_strict() != tenant:
        raise ConsentApplicationScannerCompositionError(
            "consent application-scanner tenant authority is unavailable"
        )
    return request


def attach_consent_application_scanner_composition(app: Any) -> None:
    """Install exact request/tenant-bound service and readiness seams."""

    services: OrderedDict[
        str,
        tuple[
            ConsentApplicationScannerSettings,
            application_scanner.ConsentApplicationScanService,
        ],
    ] = OrderedDict()
    services_lock = threading.Lock()

    def service_factory(request: object, tenant_id: str):
        _request_for(app, request, tenant_id)
        tenant = canonical_tenant_id(tenant_id)
        settings = settings_for_tenant(tenant)
        with services_lock:
            cached = services.pop(tenant, None)
            if cached is not None and cached[0] == settings:
                services[tenant] = cached
                return cached[1]
            service = application_scanner.ConsentApplicationScanService(
                max_records=settings.max_records,
                retention_seconds=settings.retention_seconds,
            )
            services[tenant] = (settings, service)
            while len(services) > _MAX_CACHED_TENANTS:
                services.popitem(last=False)
            return service

    def readiness_probe(request: object, tenant_id: str) -> bool:
        try:
            # Readiness performs an explicitly bounded rotating sample. The
            # auditor endpoint reports whether its requested integrity window
            # was complete and never presents a truncated pass as full proof.
            return (
                service_factory(request, tenant_id).verify_integrity(limit=1).get("sample_ok")
                is True
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            return False

    def maintenance(
        request: object,
        tenant_id: str,
        *,
        actor: str,
        limit: int,
    ) -> dict[str, int]:
        # Production retention always uses the service's server-owned clock.
        # Only direct core tests may inject ``now`` into purge_expired().
        return service_factory(request, tenant_id).purge_expired(
            actor=actor,
            limit=limit,
        )

    app.state.consent_application_scanner_service_factory = service_factory
    app.state.consent_application_scanner_enabled_probe = consent_application_scanner_enabled
    app.state.consent_application_scanner_readiness_probe = readiness_probe
    app.state.consent_application_scanner_maintenance = maintenance
