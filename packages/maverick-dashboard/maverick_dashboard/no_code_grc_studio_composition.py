"""Stock tenant-private composition for the no-code GRC studio.

Installation is lazy and store-free.  The local SQLite authority and HMAC key
are created only for an authorized operation.  Runtime target resolvers and
appliers are deliberately deployment-owned because they confer write authority
over questionnaires, continuous-evidence definitions and report catalogs.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import Request
from maverick import no_code_grc_studio as studio
from maverick.file_lock import atomic_create_bytes, ensure_private_directory, ensure_private_file
from maverick.paths import canonical_tenant_id, data_dir, tenant_scope

from .auth import caller_principal, has_global_permission

_CONFIG_KEYS = frozenset({"enable", "max_studios", "retention_seconds", "max_import_bytes"})
_DEFAULT_MAX_STUDIOS = 10_000
_DEFAULT_RETENTION_SECONDS = 31_536_000
_DEFAULT_MAX_IMPORT_BYTES = 2 * 1024 * 1024


class GRCStudioCompositionError(studio.GRCStudioConfigError):
    """The stock GRC studio composition is unavailable or malformed."""


@dataclass(frozen=True, slots=True)
class GRCStudioSettings:
    max_studios: int
    retention_seconds: int
    max_import_bytes: int


def _integer(value: object, label: str, lower: int, upper: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        raise GRCStudioCompositionError(f"{label} is outside its bound")
    return value


def grc_studio_settings(config: Mapping[str, Any]) -> GRCStudioSettings | None:
    """Parse an exact closed config section; ``None`` means disabled."""

    if not isinstance(config, Mapping):
        raise GRCStudioCompositionError("GRC studio configuration is unavailable")
    parent = config.get("tech_risk_compliance")
    if not isinstance(parent, Mapping) or parent.get("enable") is not True:
        return None
    section = parent.get("grc_studio")
    if section is None:
        return None
    if not isinstance(section, Mapping):
        raise GRCStudioCompositionError("tech_risk_compliance.grc_studio must be a table")
    if any(key not in _CONFIG_KEYS for key in section):
        raise GRCStudioCompositionError("tech_risk_compliance.grc_studio contains an unknown key")
    feature_enabled = section.get("enable", False)
    if type(feature_enabled) is not bool:
        raise GRCStudioCompositionError("tech_risk_compliance.grc_studio.enable must be boolean")
    if feature_enabled is not True:
        return None
    return GRCStudioSettings(
        max_studios=_integer(
            section.get("max_studios", _DEFAULT_MAX_STUDIOS),
            "tech_risk_compliance.grc_studio.max_studios",
            1,
            10_000,
        ),
        retention_seconds=_integer(
            section.get("retention_seconds", _DEFAULT_RETENTION_SECONDS),
            "tech_risk_compliance.grc_studio.retention_seconds",
            86_400,
            315_360_000,
        ),
        max_import_bytes=_integer(
            section.get("max_import_bytes", _DEFAULT_MAX_IMPORT_BYTES),
            "tech_risk_compliance.grc_studio.max_import_bytes",
            1_024,
            2 * 1024 * 1024,
        ),
    )


def _tenant_config(tenant_id: str) -> Mapping[str, Any]:
    tenant = canonical_tenant_id(tenant_id)
    try:
        from maverick import config as config_module

        with tenant_scope(tenant=tenant):
            config = config_module.load_config()
            errors = config_module.config_source_errors(include_tenant=True)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise GRCStudioCompositionError("GRC studio configuration is unavailable") from exc
    if errors or not isinstance(config, Mapping):
        raise GRCStudioCompositionError("GRC studio configuration is unavailable")
    return config


def settings_for_tenant(tenant_id: str) -> GRCStudioSettings:
    settings = grc_studio_settings(_tenant_config(tenant_id))
    if settings is None:
        raise GRCStudioCompositionError("GRC studio is disabled")
    return settings


def grc_studio_enabled(tenant_id: str) -> bool:
    try:
        return grc_studio_settings(_tenant_config(tenant_id)) is not None
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def _custody_path(tenant_id: str) -> Path:
    return data_dir("tech_risk_compliance", "grc-studio", "integrity.key", tenant=tenant_id)


def _integrity_key(tenant_id: str) -> bytes:
    path = _custody_path(tenant_id)
    ensure_private_directory(path.parent)
    try:
        atomic_create_bytes(path, secrets.token_bytes(32), mode=0o600)
    except FileExistsError:
        pass
    ensure_private_file(path)
    key = path.read_bytes()
    if len(key) != 32:
        raise GRCStudioCompositionError("GRC studio integrity custody is invalid")
    return key


def grc_studio_readiness(tenant_id: str) -> bool:
    """Check config and existing custody without opening SQLite or external systems."""

    try:
        tenant = canonical_tenant_id(tenant_id)
        settings_for_tenant(tenant)
        key_path = _custody_path(tenant)
        if key_path.exists():
            ensure_private_file(key_path)
            return len(key_path.read_bytes()) == 32
        # Missing first-use custody is provisionable by an authorized operation;
        # the status probe itself remains read-only.
        return not key_path.parent.exists() or key_path.parent.is_dir()
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def _request_for(app: Any, request: object) -> Request:
    if not isinstance(request, Request) or request.app is not app:
        raise studio.GRCStudioPermissionDenied("GRC studio request authority is unavailable")
    return request


def principal_ref(request: Request, tenant_id: str) -> str:
    tenant = canonical_tenant_id(tenant_id)
    subject = caller_principal(request) or "authorized-local-operator"
    if not isinstance(subject, str) or not subject.strip() or len(subject) > 512:
        raise studio.GRCStudioPermissionDenied("GRC studio principal is invalid")
    digest = hashlib.sha256(
        f"lightwork.no-code-grc-studio.identity.v1:{tenant}:{subject.strip()}".encode()
    ).hexdigest()
    return f"grc-studio-principal-{digest[:40]}"


def _clock_for(app: Any) -> Callable[[], float]:
    clock = getattr(app.state, "grc_studio_clock", time.time)
    if not callable(clock):
        raise GRCStudioCompositionError("GRC studio clock is unavailable")
    return clock


def store_factory(
    app: Any,
    *,
    tenant_id: str,
    principal_ref_value: str,
    request: object,
) -> studio.GRCStudioStore:
    selected_request = _request_for(app, request)
    tenant = canonical_tenant_id(tenant_id)
    expected = principal_ref(selected_request, tenant)
    if principal_ref_value != expected or not has_global_permission(selected_request, "view"):
        raise studio.GRCStudioPermissionDenied("GRC studio principal is not admitted")
    settings = settings_for_tenant(tenant)
    return studio.GRCStudioStore(
        data_dir("tech_risk_compliance", "grc-studio", "studio.sqlite3", tenant=tenant),
        tenant_id=tenant,
        integrity_key=_integrity_key(tenant),
        principal_resolver=lambda: principal_ref(selected_request, tenant),
        maintenance_authorizer=lambda: has_global_permission(selected_request, "admin"),
        config_gate=lambda: settings_for_tenant(tenant),
        clock=_clock_for(app),
        max_studios=settings.max_studios,
        retention_seconds=settings.retention_seconds,
        max_import_bytes=settings.max_import_bytes,
        recovery_directory=data_dir(
            "tech_risk_compliance", "grc-studio", "recovery", tenant=tenant
        ),
    )


def _install_default(state: Any, name: str, value: object) -> None:
    current = getattr(state, name, None)
    if current is not None and not callable(current):
        raise TypeError(f"{name} must be callable")
    if current is None:
        setattr(state, name, value)


def install_no_code_grc_studio_composition(app: Any) -> None:
    """Install lazy store/readiness seams without claiming a target write adapter."""

    state = getattr(app, "state", None)
    if state is None:
        raise TypeError("app must expose state")
    marker = "no_code_grc_studio_composition_installed"
    if getattr(state, marker, False):
        return
    _install_default(state, "grc_studio_enabled_probe", grc_studio_enabled)
    _install_default(state, "grc_studio_readiness_probe", grc_studio_readiness)
    _install_default(
        state,
        "grc_studio_store_factory",
        lambda *, tenant_id, principal_ref, request: store_factory(
            app,
            tenant_id=tenant_id,
            principal_ref_value=principal_ref,
            request=request,
        ),
    )
    setattr(state, marker, True)


__all__ = [
    "GRCStudioCompositionError",
    "GRCStudioSettings",
    "grc_studio_enabled",
    "grc_studio_readiness",
    "grc_studio_settings",
    "install_no_code_grc_studio_composition",
    "principal_ref",
    "settings_for_tenant",
    "store_factory",
]
