"""Stock lazy composition for Contract and Engagement lifecycle management.

The default vendor authority is derived from the tenant's persisted
third-party-intelligence vendor profile.  Installation is store-free and does
not resolve a vendor, open SQLite, or perform provider I/O.  Deployments may
replace any explicitly named factory before installation.
"""

from __future__ import annotations

import hashlib
import math
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import Request
from maverick import third_party_contracts as contracts
from maverick import third_party_intelligence as intelligence
from maverick.paths import canonical_tenant_id, data_dir, tenant_scope

from .auth import has_global_permission

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_CONFIG_KEYS = frozenset(
    {"enable", "max_records", "retention_seconds", "authority_max_age_seconds"}
)
_DEFAULT_MAX_RECORDS = 100_000
_DEFAULT_RETENTION_SECONDS = 31_536_000
_DEFAULT_AUTHORITY_MAX_AGE_SECONDS = 604_800
_MAX_RECORDS = 1_000_000
_MIN_RETENTION_SECONDS = 86_400
_MAX_RETENTION_SECONDS = 315_360_000
_MIN_AUTHORITY_MAX_AGE_SECONDS = 60
_MAX_AUTHORITY_MAX_AGE_SECONDS = 31_536_000


class ThirdPartyContractsCompositionError(contracts.ThirdPartyContractConfigError):
    """The deployment-owned Contract lifecycle composition is unavailable."""


@dataclass(frozen=True)
class ThirdPartyContractsSettings:
    max_records: int
    retention_seconds: int
    authority_max_age_seconds: int


def _integer(value: object, label: str, lower: int, upper: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        raise ThirdPartyContractsCompositionError(f"{label} is outside its bound")
    return value


def third_party_contracts_settings(
    config: Mapping[str, Any],
) -> ThirdPartyContractsSettings | None:
    """Parse exact closed settings, returning ``None`` only when disabled."""

    if not isinstance(config, Mapping):
        raise ThirdPartyContractsCompositionError("Contract lifecycle configuration is unavailable")
    parent = config.get("third_party_management")
    if not isinstance(parent, Mapping):
        return None
    if parent.get("enable") is not True:
        return None
    section = parent.get("contracts")
    if section is None:
        return None
    if not isinstance(section, Mapping):
        raise ThirdPartyContractsCompositionError(
            "third_party_management.contracts must be a table"
        )
    if any(key not in _CONFIG_KEYS for key in section):
        raise ThirdPartyContractsCompositionError(
            "third_party_management.contracts contains an unknown key"
        )
    enabled = section.get("enable", False)
    if type(enabled) is not bool:
        raise ThirdPartyContractsCompositionError(
            "third_party_management.contracts.enable must be true or false"
        )
    if enabled is not True:
        return None
    intelligence_section = parent.get("intelligence")
    if not isinstance(intelligence_section, Mapping) or intelligence_section.get("enable") is not True:
        raise ThirdPartyContractsCompositionError(
            "stock Contract lifecycle requires third_party_management.intelligence.enable = true"
        )
    return ThirdPartyContractsSettings(
        max_records=_integer(
            section.get("max_records", _DEFAULT_MAX_RECORDS),
            "third_party_management.contracts.max_records",
            1,
            _MAX_RECORDS,
        ),
        retention_seconds=_integer(
            section.get("retention_seconds", _DEFAULT_RETENTION_SECONDS),
            "third_party_management.contracts.retention_seconds",
            _MIN_RETENTION_SECONDS,
            _MAX_RETENTION_SECONDS,
        ),
        authority_max_age_seconds=_integer(
            section.get(
                "authority_max_age_seconds",
                _DEFAULT_AUTHORITY_MAX_AGE_SECONDS,
            ),
            "third_party_management.contracts.authority_max_age_seconds",
            _MIN_AUTHORITY_MAX_AGE_SECONDS,
            _MAX_AUTHORITY_MAX_AGE_SECONDS,
        ),
    )


def _load_tenant_config(tenant_id: str) -> Mapping[str, Any]:
    tenant = canonical_tenant_id(tenant_id)
    try:
        from maverick import config as config_module

        with tenant_scope(tenant=tenant):
            config = config_module.load_config()
            errors = config_module.config_source_errors(include_tenant=True)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise ThirdPartyContractsCompositionError(
            "Contract lifecycle configuration is unavailable"
        ) from exc
    if errors or not isinstance(config, Mapping):
        raise ThirdPartyContractsCompositionError(
            "Contract lifecycle configuration is unavailable"
        )
    return config


def settings_for_tenant(tenant_id: str) -> ThirdPartyContractsSettings:
    settings = third_party_contracts_settings(_load_tenant_config(tenant_id))
    if settings is None:
        raise ThirdPartyContractsCompositionError("Contract lifecycle is disabled")
    return settings


def third_party_contracts_enabled(tenant_id: str) -> bool:
    try:
        return third_party_contracts_settings(_load_tenant_config(tenant_id)) is not None
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def _clock_for(app: Any) -> Callable[[], float]:
    configured = getattr(app.state, "third_party_contracts_clock", None) or time.time
    if not callable(configured):
        raise ThirdPartyContractsCompositionError("Contract lifecycle clock is unavailable")

    def read() -> float:
        try:
            value = configured()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise ThirdPartyContractsCompositionError(
                "Contract lifecycle clock is unavailable"
            ) from exc
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or float(value) <= 0
        ):
            raise ThirdPartyContractsCompositionError(
                "Contract lifecycle clock is unavailable"
            )
        return float(value)

    return read


def _request_for(app: Any, request: object) -> Request:
    if not isinstance(request, Request) or request.app is not app:
        raise ThirdPartyContractsCompositionError(
            "Contract lifecycle request authority is unavailable"
        )
    return request


def _subject(request: Request) -> str:
    verified = getattr(request.state, "principal", None)
    subject = getattr(verified, "principal", None) or getattr(verified, "sub", None)
    if isinstance(subject, str) and subject.strip() and len(subject) <= 512:
        return subject.strip()
    try:
        from .auth import anonymous_local_access_allowed

        if anonymous_local_access_allowed():
            return "local-operator"
    except Exception as exc:
        raise ThirdPartyContractsCompositionError(
            "Contract lifecycle principal authority is unavailable"
        ) from exc
    raise ThirdPartyContractsCompositionError(
        "Contract lifecycle principal authority is unavailable"
    )


def _expected_principal(request: Request, tenant_id: str) -> str:
    digest = hashlib.sha256(
        f"lightwork.third-party-contract.identity.v1:{tenant_id}:{_subject(request)}".encode()
    ).hexdigest()
    return f"contract-principal-{digest[:32]}"


def _default_principal_resolver_factory(
    app: Any,
    *,
    tenant_id: str,
    principal_ref: str,
    request: object,
) -> Callable[[], str]:
    tenant = canonical_tenant_id(tenant_id)
    selected = _request_for(app, request)
    expected = _expected_principal(selected, tenant)
    if principal_ref != expected or not _ID_RE.fullmatch(principal_ref):
        raise ThirdPartyContractsCompositionError(
            "Contract lifecycle principal authority is unavailable"
        )

    def resolve() -> str:
        if _expected_principal(selected, tenant) != expected:
            raise contracts.ThirdPartyContractPermissionDenied(
                "authenticated principal changed"
            )
        return expected

    return resolve


def _default_maintenance_authorizer_factory(
    app: Any,
    *,
    tenant_id: str,
    request: object,
) -> Callable[[], bool]:
    canonical_tenant_id(tenant_id)
    selected = _request_for(app, request)

    def authorize() -> bool:
        return has_global_permission(selected, "admin") is True

    return authorize


def _default_vendor_store_for(app: Any, tenant_id: str, request: Request):
    factory = getattr(app.state, "third_party_intelligence_store_factory", None)
    if callable(factory):
        return factory(tenant_id=tenant_id, request=request)
    with tenant_scope(tenant=tenant_id):
        return intelligence.ThirdPartyIntelligenceStore(
            data_dir(
                "third_party_management",
                "third-party-intelligence.sqlite3",
                tenant=tenant_id,
            )
        )


class VendorProfileAuthorityResolver:
    """Resolve an exact authority from a persisted vendor profile revision."""

    def __init__(
        self,
        app: Any,
        *,
        tenant_id: str,
        settings: ThirdPartyContractsSettings,
        request: object,
        clock: Callable[[], float],
    ) -> None:
        self._app = app
        self._tenant = canonical_tenant_id(tenant_id)
        self._settings = settings
        self._request = _request_for(app, request)
        self._clock = clock

    def __call__(
        self,
        tenant_id: str,
        vendor_id: str,
        vendor_revision: int,
    ) -> contracts.VendorAuthority:
        tenant = canonical_tenant_id(tenant_id)
        if tenant != self._tenant or not _ID_RE.fullmatch(vendor_id):
            raise contracts.ThirdPartyContractConflict("vendor authority is unavailable")
        try:
            store = _default_vendor_store_for(self._app, tenant, self._request)
            with tenant_scope(tenant=tenant):
                profile = store.get_vendor(tenant, vendor_id)
        except contracts.ThirdPartyContractError:
            raise
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise contracts.ThirdPartyContractConflict(
                "vendor authority is unavailable"
            ) from exc
        if profile.vendor_id != vendor_id or profile.revision != vendor_revision:
            raise contracts.ThirdPartyContractConflict("vendor revision changed")
        criticality = {
            1: "low",
            2: "low",
            3: "medium",
            4: "high",
            5: "critical",
        }.get(profile.criticality)
        if criticality is None:
            raise contracts.ThirdPartyContractConflict("vendor metadata is unavailable")
        issued_at = float(profile.updated_at)
        valid_until = issued_at + self._settings.authority_max_age_seconds
        now = self._clock()
        if issued_at > now or now >= valid_until:
            raise contracts.ThirdPartyContractConflict("vendor profile authority is stale")
        issuer_digest = hashlib.sha256(
            (
                f"lightwork.third-party-contract.vendor-issuer.v1:{tenant}:"
                f"{profile.vendor_id}:{profile.revision}:{profile.entity_identity_sha256}:"
                f"{profile.integrity_sha256}"
            ).encode()
        ).hexdigest()
        return contracts.issue_vendor_authority(
            tenant_id=tenant,
            vendor_id=profile.vendor_id,
            vendor_revision=profile.revision,
            vendor_type="service_provider",
            criticality=criticality,
            jurisdiction_codes=tuple(profile.territories),
            classification_refs=tuple(profile.service_categories),
            issuer_ref=f"third-party-intelligence:{issuer_digest}",
            issued_at=issued_at,
            valid_until=valid_until,
            revoked=profile.state != "active",
        )


def _default_vendor_authority_resolver_factory(
    app: Any,
    *,
    tenant_id: str,
    settings: ThirdPartyContractsSettings,
    request: object,
) -> VendorProfileAuthorityResolver:
    return VendorProfileAuthorityResolver(
        app,
        tenant_id=tenant_id,
        settings=settings,
        request=request,
        clock=_clock_for(app),
    )


def _default_store_path_factory(*, tenant_id: str, request: object) -> Path:
    del request
    tenant = canonical_tenant_id(tenant_id)
    return data_dir(
        "third_party_management",
        "contracts",
        "contract-engagement.sqlite3",
        tenant=tenant,
    )


def _factory_result(
    app: Any,
    *,
    state_name: str,
    unavailable: str,
    kwargs: Mapping[str, Any],
) -> object:
    factory = getattr(app.state, state_name, None)
    if not callable(factory):
        raise ThirdPartyContractsCompositionError(unavailable)
    try:
        return factory(**dict(kwargs))
    except contracts.ThirdPartyContractError:
        raise
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise ThirdPartyContractsCompositionError(unavailable) from exc


def _build_store(
    app: Any,
    *,
    tenant_id: str,
    principal_ref: str,
    request: object,
) -> contracts.ThirdPartyContractStore:
    tenant = canonical_tenant_id(tenant_id)
    selected = _request_for(app, request)
    settings = settings_for_tenant(tenant)
    common = {"tenant_id": tenant, "request": selected}
    principal_resolver = _factory_result(
        app,
        state_name="third_party_contracts_principal_resolver_factory",
        unavailable="Contract lifecycle principal authority is unavailable",
        kwargs={**common, "principal_ref": principal_ref},
    )
    maintenance_authorizer = _factory_result(
        app,
        state_name="third_party_contracts_maintenance_authorizer_factory",
        unavailable="Contract lifecycle maintenance authority is unavailable",
        kwargs=common,
    )
    authority_resolver = _factory_result(
        app,
        state_name="third_party_contracts_vendor_authority_resolver_factory",
        unavailable="Contract lifecycle vendor authority is unavailable",
        kwargs={**common, "settings": settings},
    )
    path = _factory_result(
        app,
        state_name="third_party_contracts_store_path_factory",
        unavailable="Contract lifecycle storage path is unavailable",
        kwargs=common,
    )
    if not all(
        callable(item)
        for item in (principal_resolver, maintenance_authorizer, authority_resolver)
    ) or not isinstance(path, (str, Path)):
        raise ThirdPartyContractsCompositionError(
            "Contract lifecycle runtime authorities are unavailable"
        )

    def config_gate() -> None:
        if settings_for_tenant(tenant) != settings:
            raise ThirdPartyContractsCompositionError(
                "Contract lifecycle configuration changed during admission"
            )

    return contracts.ThirdPartyContractStore(
        Path(path),
        tenant_id=tenant,
        vendor_authority_resolver=authority_resolver,  # type: ignore[arg-type]
        principal_resolver=principal_resolver,  # type: ignore[arg-type]
        maintenance_authorizer=maintenance_authorizer,  # type: ignore[arg-type]
        config_gate=config_gate,
        retention_seconds=settings.retention_seconds,
        max_records=settings.max_records,
        clock=_clock_for(app),
    )


def install_third_party_contracts_composition(app: Any) -> None:
    """Install all strict API seams without opening tenant state."""

    state = getattr(app, "state", None)
    if state is None:
        raise TypeError("app must expose state")
    marker = "third_party_contracts_composition_installed"
    if getattr(state, marker, False):
        return
    deployment_enabled = getattr(state, "third_party_contracts_enabled_probe", None)
    deployment_ready = getattr(state, "third_party_contracts_readiness_probe", None)
    if deployment_enabled is not None and not callable(deployment_enabled):
        raise TypeError("Contract lifecycle enabled probe must be callable")
    if deployment_ready is not None and not callable(deployment_ready):
        raise TypeError("Contract lifecycle readiness probe must be callable")
    defaults = {
        "third_party_contracts_principal_resolver_factory": (
            lambda **kwargs: _default_principal_resolver_factory(app, **kwargs)
        ),
        "third_party_contracts_maintenance_authorizer_factory": (
            lambda **kwargs: _default_maintenance_authorizer_factory(app, **kwargs)
        ),
        "third_party_contracts_vendor_authority_resolver_factory": (
            lambda **kwargs: _default_vendor_authority_resolver_factory(app, **kwargs)
        ),
        "third_party_contracts_store_path_factory": _default_store_path_factory,
    }
    for name, value in defaults.items():
        existing = getattr(state, name, None)
        if existing is not None and not callable(existing):
            raise TypeError(f"{name} must be callable")
        if existing is None:
            setattr(state, name, value)
    if getattr(state, "third_party_contracts_store_factory", None) is None:

        def store_factory(
            *,
            tenant_id: str,
            principal_ref: str,
            request: object,
        ) -> contracts.ThirdPartyContractStore:
            return _build_store(
                app,
                tenant_id=tenant_id,
                principal_ref=principal_ref,
                request=request,
            )

        state.third_party_contracts_store_factory = store_factory
    elif not callable(state.third_party_contracts_store_factory):
        raise TypeError("Contract lifecycle store factory must be callable")

    def enabled_probe(tenant_id: str) -> bool:
        try:
            base = third_party_contracts_enabled(tenant_id)
            if base is not True:
                return False
            return deployment_enabled(tenant_id) is True if callable(deployment_enabled) else True
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            return False

    def readiness_probe(tenant_id: str) -> bool:
        try:
            tenant = canonical_tenant_id(tenant_id)
            if enabled_probe(tenant) is not True:
                return False
            settings_for_tenant(tenant)
            with tenant_scope(tenant=tenant):
                inventory_ready = intelligence.enabled()
            required = (
                "third_party_contracts_store_factory",
                "third_party_contracts_principal_resolver_factory",
                "third_party_contracts_maintenance_authorizer_factory",
                "third_party_contracts_vendor_authority_resolver_factory",
                "third_party_contracts_store_path_factory",
            )
            if inventory_ready is not True or not all(
                callable(getattr(state, name, None)) for name in required
            ):
                return False
            _clock_for(app)()
            return deployment_ready(tenant) is True if callable(deployment_ready) else True
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            return False

    state.third_party_contracts_enabled_probe = enabled_probe
    state.third_party_contracts_readiness_probe = readiness_probe
    setattr(state, marker, True)


__all__ = [
    "ThirdPartyContractsCompositionError",
    "ThirdPartyContractsSettings",
    "VendorProfileAuthorityResolver",
    "install_third_party_contracts_composition",
    "settings_for_tenant",
    "third_party_contracts_enabled",
    "third_party_contracts_settings",
]
