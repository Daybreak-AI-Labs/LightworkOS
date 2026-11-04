"""Stock production composition for the shared governance inventory."""

from __future__ import annotations

import hashlib
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import Request
from maverick import entity_graph
from maverick import shared_governance_inventory as inventory
from maverick.file_lock import (
    atomic_create_bytes,
    ensure_private_directory,
    ensure_private_file,
)
from maverick.paths import canonical_tenant_id, data_dir, tenant_scope
from maverick.stock_suite_audit_capture import StockSuiteAuditCaptureProvider

from .auth import caller_principal, has_global_permission

_CONFIG_KEYS = frozenset(
    {
        "enable",
        "retention_seconds",
        "max_source_records",
        "max_entities",
        "max_relationships",
        "max_export_bytes",
        "max_snapshots",
    }
)


class SharedGovernanceInventoryCompositionError(
    inventory.SharedGovernanceInventoryConfigError
):
    """The stock shared-inventory authority cannot be composed."""


@dataclass(frozen=True, slots=True)
class SharedGovernanceInventorySettings:
    retention_seconds: int = 31_536_000
    max_source_records: int = 10_000
    max_entities: int = 20_000
    max_relationships: int = 40_000
    max_export_bytes: int = 10 * 1024 * 1024
    max_snapshots: int = 10_000


def _integer(value: object, label: str, lower: int, upper: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        raise SharedGovernanceInventoryCompositionError(
            f"{label} is outside its bound"
        )
    return value


def inventory_settings(
    config: Mapping[str, Any],
) -> SharedGovernanceInventorySettings | None:
    if not isinstance(config, Mapping):
        raise SharedGovernanceInventoryCompositionError(
            "shared governance inventory configuration is unavailable"
        )
    section = config.get("governance_inventory")
    if section is None:
        return None
    if not isinstance(section, Mapping):
        raise SharedGovernanceInventoryCompositionError(
            "governance_inventory must be a table"
        )
    unknown = sorted(str(key) for key in section if key not in _CONFIG_KEYS)
    if unknown:
        raise SharedGovernanceInventoryCompositionError(
            "governance_inventory contains unknown keys: " + ", ".join(unknown)
        )
    enabled = section.get("enable", False)
    if type(enabled) is not bool:
        raise SharedGovernanceInventoryCompositionError(
            "governance_inventory.enable must be boolean"
        )
    if enabled is not True:
        return None
    graph = config.get("entity_graph") or {}
    if not isinstance(graph, Mapping) or graph.get("enable", True) is not True:
        raise SharedGovernanceInventoryCompositionError(
            "shared governance inventory requires entity_graph.enable = true"
        )
    return SharedGovernanceInventorySettings(
        retention_seconds=_integer(
            section.get("retention_seconds", 31_536_000),
            "governance_inventory.retention_seconds",
            86_400,
            315_360_000,
        ),
        max_source_records=_integer(
            section.get("max_source_records", 10_000),
            "governance_inventory.max_source_records",
            1,
            100_000,
        ),
        max_entities=_integer(
            section.get("max_entities", 20_000),
            "governance_inventory.max_entities",
            1,
            100_000,
        ),
        max_relationships=_integer(
            section.get("max_relationships", 40_000),
            "governance_inventory.max_relationships",
            1,
            200_000,
        ),
        max_export_bytes=_integer(
            section.get("max_export_bytes", 10 * 1024 * 1024),
            "governance_inventory.max_export_bytes",
            1_024,
            100 * 1024 * 1024,
        ),
        max_snapshots=_integer(
            section.get("max_snapshots", 10_000),
            "governance_inventory.max_snapshots",
            2,
            10_000,
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
        raise SharedGovernanceInventoryCompositionError(
            "shared governance inventory configuration is unavailable"
        ) from exc
    if errors or not isinstance(config, Mapping):
        raise SharedGovernanceInventoryCompositionError(
            "shared governance inventory configuration is unavailable"
        )
    return config


def settings_for_tenant(tenant_id: str) -> SharedGovernanceInventorySettings:
    settings = inventory_settings(_tenant_config(tenant_id))
    if settings is None:
        raise SharedGovernanceInventoryCompositionError(
            "shared governance inventory is disabled"
        )
    return settings


def inventory_enabled(tenant_id: str) -> bool:
    try:
        return inventory_settings(_tenant_config(tenant_id)) is not None
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def _custody_path(tenant_id: str) -> Path:
    return data_dir(
        "governance_inventory",
        "integrity.key",
        tenant=canonical_tenant_id(tenant_id),
    )


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
        raise SharedGovernanceInventoryCompositionError(
            "shared governance inventory custody is invalid"
        )
    return key


def inventory_readiness(tenant_id: str) -> bool:
    """Side-effect-free config/custody readiness; sources may remain partial."""

    try:
        tenant = canonical_tenant_id(tenant_id)
        settings_for_tenant(tenant)
        path = _custody_path(tenant)
        if path.exists():
            ensure_private_file(path)
            return len(path.read_bytes()) == 32
        return not path.parent.exists() or path.parent.is_dir()
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def _request_for(app: Any, request: object) -> Request:
    if not isinstance(request, Request) or request.app is not app:
        raise inventory.SharedGovernanceInventoryPermissionDenied(
            "inventory request authority is unavailable"
        )
    return request


def principal_ref(request: Request, tenant_id: str) -> str:
    tenant = canonical_tenant_id(tenant_id)
    subject = caller_principal(request) or "authorized-local-operator"
    if not isinstance(subject, str) or not subject.strip() or len(subject) > 512:
        raise inventory.SharedGovernanceInventoryPermissionDenied(
            "inventory principal is invalid"
        )
    digest = hashlib.sha256(
        f"lightwork.shared-governance-inventory.identity.v1:{tenant}:{subject.strip()}".encode()
    ).hexdigest()
    return f"governance-inventory-principal-{digest[:40]}"


class SharedGovernanceInventoryRuntime:
    """Closed runtime: callers cannot replace source or provenance authorities."""

    def __init__(
        self,
        *,
        store: inventory.SharedGovernanceInventoryStore,
    ) -> None:
        self.store = store
        self._provider = StockSuiteAuditCaptureProvider()

    def reconcile(self, **kwargs):
        return self.store.reconcile(
            provider=self._provider,
            provenance_reader=entity_graph.inventory_provenance_manifest,
            **kwargs,
        )

    def __getattr__(self, name: str):
        # Only explicit store methods are reachable; Python internals and key
        # custody remain outside the HTTP dependency protocol.
        allowed = {
            "active_authority",
            "current_snapshot",
            "export_snapshot",
            "get_snapshot",
            "list_snapshots",
            "purge_expired",
            "query_entities",
            "query_relationships",
            "recover_latest",
            "status",
            "verify_integrity",
            "write_recovery_checkpoint",
        }
        if name not in allowed:
            raise AttributeError(name)
        return getattr(self.store, name)


def runtime_factory(
    app: Any,
    *,
    tenant_id: str,
    principal_ref_value: str,
    request: object,
) -> SharedGovernanceInventoryRuntime:
    selected_request = _request_for(app, request)
    tenant = canonical_tenant_id(tenant_id)
    expected = principal_ref(selected_request, tenant)
    if principal_ref_value != expected or not has_global_permission(selected_request, "view"):
        raise inventory.SharedGovernanceInventoryPermissionDenied(
            "inventory principal is not admitted"
        )
    settings = settings_for_tenant(tenant)
    clock = getattr(app.state, "shared_governance_inventory_clock", time.time)
    if not callable(clock):
        raise SharedGovernanceInventoryCompositionError(
            "shared governance inventory clock is unavailable"
        )
    store = inventory.SharedGovernanceInventoryStore(
        data_dir(
            "governance_inventory",
            "inventory.sqlite3",
            tenant=tenant,
        ),
        tenant_id=tenant,
        integrity_key=_integrity_key(tenant),
        principal_resolver=lambda: principal_ref(selected_request, tenant),
        maintenance_authorizer=lambda: has_global_permission(selected_request, "admin"),
        config_gate=lambda: settings_for_tenant(tenant),
        clock=clock,
        retention_seconds=settings.retention_seconds,
        max_source_records=settings.max_source_records,
        max_entities=settings.max_entities,
        max_relationships=settings.max_relationships,
        max_export_bytes=settings.max_export_bytes,
        max_snapshots=settings.max_snapshots,
        recovery_directory=data_dir(
            "governance_inventory",
            "recovery",
            tenant=tenant,
        ),
    )
    return SharedGovernanceInventoryRuntime(store=store)


def _install_default(state: Any, name: str, value: object) -> None:
    current = getattr(state, name, None)
    if current is not None and not callable(current):
        raise TypeError(f"{name} must be callable")
    if current is None:
        setattr(state, name, value)


def install_shared_governance_inventory_composition(app: Any) -> None:
    """Install lazy stock authority seams without opening custody or SQLite."""

    state = getattr(app, "state", None)
    if state is None:
        raise TypeError("app must expose state")
    marker = "shared_governance_inventory_composition_installed"
    if getattr(state, marker, False):
        return
    _install_default(state, "shared_governance_inventory_enabled_probe", inventory_enabled)
    _install_default(
        state,
        "shared_governance_inventory_readiness_probe",
        inventory_readiness,
    )
    _install_default(
        state,
        "shared_governance_inventory_runtime_factory",
        lambda *, tenant_id, principal_ref, request: runtime_factory(
            app,
            tenant_id=tenant_id,
            principal_ref_value=principal_ref,
            request=request,
        ),
    )
    setattr(state, marker, True)


__all__ = [
    "SharedGovernanceInventoryCompositionError",
    "SharedGovernanceInventoryRuntime",
    "SharedGovernanceInventorySettings",
    "install_shared_governance_inventory_composition",
    "inventory_enabled",
    "inventory_readiness",
    "inventory_settings",
    "principal_ref",
    "runtime_factory",
    "settings_for_tenant",
]
