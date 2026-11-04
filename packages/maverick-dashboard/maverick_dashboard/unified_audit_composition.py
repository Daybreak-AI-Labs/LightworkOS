"""Server-owned composition for the tenant-bound unified-audit projection.

Mounting this module only installs lazy factories.  It does not open the
projection database, create an audit log, inspect suite-private stores, or
perform network I/O. At first enabled use, stock source-owned readers and a
separately instantiated local verifier cover one canonical history in each of
the fixed six suites. A deployment may replace them through the two explicit
app-state factories; omitted or unpaired authorities remain incomplete.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from typing import Any

from maverick import unified_audit as audit
from maverick import unified_audit_custody as custody
from maverick.audit.writer import AuditLog
from maverick.paths import canonical_tenant_id, data_dir, tenant_scope

from .stock_unified_audit_sources import build_stock_unified_audit_authorities
from .unified_audit_sources import (
    SOURCE_IDS,
    AuthoritativeAuditHistoryReader,
    UnifiedAuditSourceComposition,
    build_unified_audit_source_composition,
)


def _load_tenant_config(tenant_id: str) -> Mapping[str, Any]:
    """Read one admitted tenant snapshot without constructing runtime state."""

    tenant = canonical_tenant_id(tenant_id)
    try:
        from maverick import config as config_module

        with tenant_scope(tenant=tenant):
            config = config_module.load_config()
            source_errors = config_module.config_source_errors(include_tenant=True)
    except audit.UnifiedAuditError:
        raise
    except Exception as exc:
        raise audit.UnifiedAuditConfigError("unified-audit configuration is unavailable") from exc
    if source_errors:
        raise audit.UnifiedAuditConfigError("unified-audit configuration source is invalid")
    if not isinstance(config, Mapping):
        raise audit.UnifiedAuditConfigError("unified-audit configuration is unavailable")
    return config


def unified_audit_capability_enabled(tenant_id: str) -> bool:
    """Side-effect-free tenant feature probe used by the disabled status path."""

    try:
        return audit.enabled(_load_tenant_config(tenant_id))
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def _injected_mapping(
    state: Any,
    *,
    attribute: str,
    tenant_id: str,
    request: Any,
    unavailable_message: str,
) -> Mapping[str, Any]:
    factory = getattr(state, attribute, None)
    if factory is None:
        return {}
    if not callable(factory):
        raise audit.UnifiedAuditConfigError(unavailable_message)
    try:
        result = factory(tenant_id, request)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise audit.UnifiedAuditConfigError(unavailable_message) from exc
    if not isinstance(result, Mapping):
        raise audit.UnifiedAuditConfigError(unavailable_message)
    return dict(result)


class DashboardUnifiedAuditProjector:
    """Core projector plus candid source-adapter coverage metadata."""

    def __init__(
        self,
        *,
        projector: audit.UnifiedAuditProjector,
        source_composition: UnifiedAuditSourceComposition,
        source_authority_mode: str = "injected",
        custody_runtime: custody.UnifiedAuditCustodyRuntime | None = None,
    ) -> None:
        if not isinstance(projector, audit.UnifiedAuditProjector):
            raise audit.UnifiedAuditConfigError("unified-audit projector is unavailable")
        if not isinstance(source_composition, UnifiedAuditSourceComposition):
            raise audit.UnifiedAuditConfigError("unified-audit source composition is unavailable")
        if source_authority_mode not in {"injected", "stock"}:
            raise audit.UnifiedAuditConfigError("unified-audit source authority mode is invalid")
        self._projector = projector
        self._source_composition = source_composition
        self._source_authority_mode = source_authority_mode
        self._custody_runtime = custody_runtime

    @property
    def store(self) -> audit.UnifiedAuditStore:
        return self._projector.store

    def run_all(self, *, worker_id: str):
        results = self._projector.run_all(worker_id=worker_id)
        if self._custody_runtime is not None:
            self._custody_runtime.run_once()
        return results

    def run_source(self, source_id: str, *, worker_id: str):
        return self._projector.run_source(source_id, worker_id=worker_id)

    def status(self) -> dict[str, Any]:
        core_status = dict(self._projector.status())
        adapter_status = dict(self._source_composition.status())
        core_status.update(
            # The core store is the only completeness authority: it requires a
            # current independent verification plus a strict signed receipt,
            # and rechecks all six runtime pairs plus sink readiness. Adapter
            # status is diagnostic and intentionally never promotes itself.
            complete=core_status.get("complete") is True,
            source_adapter_coverage=adapter_status,
            source_authority_mode=self._source_authority_mode,
            stock_source_authorities_installed=(
                self._source_authority_mode == "stock"
            ),
            stock_source_scope="canonical_partial",
            live_source_interoperability_verified=False,
            live_customer_acceptance_verified=False,
            custody=(
                self._custody_runtime.readiness()
                if self._custody_runtime is not None
                else {
                    "schema": "lightwork.unified-audit-custody-status.v1",
                    "enabled": False,
                    "ready": False,
                    "automatic_sealing_performed": False,
                    "independent_operation_verified": False,
                    "off_host_key_custody_verified": False,
                    "s3_object_lock_acceptance_verified": False,
                    "siem_acceptance_verified": False,
                    "live_customer_acceptance_verified": False,
                }
            ),
        )
        limits = dict(core_status.get("limits", {}))
        limits.update(
            raw_source_payloads_persisted=False,
            private_suite_tables_read_by_composition=False,
            network_io_performed_by_composition=False,
            live_completeness_inferred=False,
        )
        core_status["limits"] = limits
        return core_status


def build_unified_audit_projector(
    *,
    tenant_id: str,
    readers: Mapping[str, AuthoritativeAuditHistoryReader],
    verifiers: Mapping[str, audit.SourceVerifier],
    config: Mapping[str, Any],
    clock: Callable[[], float] = time.time,
    source_authority_mode: str = "injected",
) -> DashboardUnifiedAuditProjector:
    """Build one tenant runtime from validated source-owned authorities."""

    tenant = canonical_tenant_id(tenant_id)
    settings = audit.require_enabled(config)
    source_composition = build_unified_audit_source_composition(
        tenant_id=tenant,
        readers=readers,
        verifiers=verifiers,
        max_page_records=settings.page_size,
    )
    registry = audit.UnifiedAuditRegistry(tenant)
    for source_id in SOURCE_IDS:
        source = source_composition.sources.get(source_id)
        if source is None:
            continue
        try:
            registry.register(
                source,
                verifier=source_composition.verifiers[source_id],
            )
        except audit.UnifiedAuditConfigError:
            # The adapter records a closed limitation when its authority cannot
            # be resolved. One failed source must remain visible as incomplete
            # rather than hiding the other five source slots.
            continue

    store_path = data_dir("unified-audit", "projection.sqlite3", tenant=tenant)
    selected_audit_dir = data_dir("audit", tenant=tenant)
    store = audit.UnifiedAuditStore(store_path, tenant_id=tenant, clock=clock)
    audit_log = AuditLog(selected_audit_dir, sign=True)
    sink = audit.StrictAuditProjectionSink(
        tenant_id=tenant,
        audit_log=audit_log,
        clock=clock,
    )
    projector = audit.UnifiedAuditProjector(
        registry=registry,
        store=store,
        sink=sink,
        config=settings,
    )
    custody_runtime = None
    try:
        custody_settings = custody.settings_from(config, tenant_id=tenant)
    except custody.UnifiedAuditCustodyError as exc:
        raise audit.UnifiedAuditConfigError(
            "unified-audit custody configuration is unavailable"
        ) from exc
    if custody_settings.enable:
        custody_runtime = custody.UnifiedAuditCustodyRuntime(
            tenant_id=tenant,
            config_loader=lambda: _load_tenant_config(tenant),
            clock=clock,
        )
    return DashboardUnifiedAuditProjector(
        projector=projector,
        source_composition=source_composition,
        source_authority_mode=source_authority_mode,
        custody_runtime=custody_runtime,
    )


def attach_unified_audit_composition(app: Any) -> None:
    """Install lazy tenant factories without opening any persistent store."""

    state = getattr(app, "state", None)
    if state is None:
        raise TypeError("app must expose state")

    existing_probe = getattr(state, "unified_audit_enabled_probe", None)
    if existing_probe is not None and not callable(existing_probe):
        raise TypeError("unified-audit enabled probe must be callable")
    if existing_probe is None:
        state.unified_audit_enabled_probe = unified_audit_capability_enabled

    existing_factory = getattr(state, "unified_audit_projector_factory", None)
    if existing_factory is not None and not callable(existing_factory):
        raise TypeError("unified-audit projector factory must be callable")
    if existing_factory is not None:
        return

    def projector_factory(
        tenant_id: str,
        principal_ref: str,
        request: Any,
    ) -> DashboardUnifiedAuditProjector:
        if not isinstance(principal_ref, str) or not principal_ref or len(principal_ref) > 512:
            raise audit.UnifiedAuditConfigError("unified-audit principal authority is unavailable")
        tenant = canonical_tenant_id(tenant_id)
        config = _load_tenant_config(tenant)
        # Admission happens before any call to data_dir or a SQLite constructor.
        audit.require_enabled(config)
        injected = any(
            getattr(state, attribute, None) is not None
            for attribute in (
                "unified_audit_source_readers_factory",
                "unified_audit_source_verifiers_factory",
            )
        )
        if injected:
            readers = _injected_mapping(
                state,
                attribute="unified_audit_source_readers_factory",
                tenant_id=tenant,
                request=request,
                unavailable_message="unified-audit source readers are unavailable",
            )
            verifiers = _injected_mapping(
                state,
                attribute="unified_audit_source_verifiers_factory",
                tenant_id=tenant,
                request=request,
                unavailable_message="unified-audit source verifiers are unavailable",
            )
            source_authority_mode = "injected"
        else:
            readers, verifiers = build_stock_unified_audit_authorities(
                tenant_id=tenant,
            )
            source_authority_mode = "stock"
        return build_unified_audit_projector(
            tenant_id=tenant,
            readers=readers,
            verifiers=verifiers,
            config=config,
            source_authority_mode=source_authority_mode,
        )

    state.unified_audit_projector_factory = projector_factory


__all__ = [
    "DashboardUnifiedAuditProjector",
    "attach_unified_audit_composition",
    "build_unified_audit_projector",
    "unified_audit_capability_enabled",
]
