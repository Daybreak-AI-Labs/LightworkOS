"""Durable composition for native provider writes and audit reconciliation.

The native provider adapter owns the external mutation.  The authority outbox
is staged before that mutation and finalized only from the adapter's durable,
credential-free operation evidence.  Registration in the provider-audit store
is idempotent and recoverable, so a dashboard crash after a successful provider
write cannot silently discard the audit obligation.

This module provides dependency wiring only.  Construction initializes local
private SQLite stores, but does not resolve credentials, perform provider or
network I/O, implement a provider audit transport, or claim provider-log
completeness.
"""

from __future__ import annotations

import hashlib
import json
import math
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from maverick.data_use_provider_adapters import ProviderBindingStore
from maverick.data_use_provider_audit import (
    DataUseProviderAuditConfigError,
    DataUseProviderAuditError,
    DataUseProviderAuditIntegrityError,
    DataUseProviderAuditNotFound,
    DataUseProviderAuditStore,
    ProviderAuditExpectation,
    ProviderAuditWorkerResult,
)
from maverick.data_use_provider_audit_authority import (
    DataUseProviderAuditAuthorityError,
    DataUseProviderAuditAuthorityIntegrityError,
    DataUseProviderAuditAuthorityNotFound,
    DataUseProviderAuditAuthorityStore,
    ProviderAuditAuthorityRecord,
    ProviderAuditReadGrant,
)
from maverick.paths import canonical_tenant_id, data_dir

from .data_use_provider_audit_runtime import (
    DataUseProviderAuditRuntime,
    build_provider_audit_runtime,
    require_provider_audit_config,
)
from .data_use_provider_audit_transport import WatermarkAuthorityResolver

COMPOSITION_STATUS_SCHEMA = "lightwork.dashboard.data-use-provider-audit-composition-status.v1"
RECOVERY_RESULT_SCHEMA = "lightwork.data-use.provider-audit-recovery-result.v1"

_DEFAULT_AUDIT_WINDOW_SECONDS = 3_600
_DEFAULT_RETENTION_SECONDS = 31_536_000
_DEFAULT_MAX_ATTEMPTS = 5
_AUTHORITY_GRACE_SECONDS = 3_600
_MAX_RECOVERY_LIMIT = 500


def _canonical_sha256(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise DataUseProviderAuditConfigError(
            "provider-audit composition material is not canonical"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise DataUseProviderAuditConfigError(f"{label} is outside its bound")
    return value


def _now(clock: Callable[[], float]) -> float:
    try:
        value = float(clock())
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise DataUseProviderAuditConfigError(
            "provider-audit composition clock is unavailable"
        ) from exc
    if not math.isfinite(value) or value <= 0:
        raise DataUseProviderAuditConfigError("provider-audit composition clock is invalid")
    return value


@dataclass(frozen=True, slots=True)
class ProviderAuditOperationSettings:
    audit_window_seconds: int
    retention_seconds: int
    max_attempts: int
    authority_grace_seconds: int = _AUTHORITY_GRACE_SECONDS


def operation_settings(config: Mapping[str, Any]) -> ProviderAuditOperationSettings:
    """Parse the exact enabled operation settings with bounded defaults."""

    require_provider_audit_config(config)
    root = config.get("data_use_governance")
    audit = root.get("provider_audit") if isinstance(root, Mapping) else None
    if not isinstance(audit, Mapping):
        raise DataUseProviderAuditConfigError("provider-audit configuration is unavailable")
    window = _integer(
        audit.get("audit_window_seconds", _DEFAULT_AUDIT_WINDOW_SECONDS),
        "provider-audit audit_window_seconds",
        60,
        604_800,
    )
    retention = _integer(
        audit.get("retention_seconds", _DEFAULT_RETENTION_SECONDS),
        "provider-audit retention_seconds",
        60,
        316_224_000,
    )
    attempts = _integer(
        audit.get("max_attempts", _DEFAULT_MAX_ATTEMPTS),
        "provider-audit max_attempts",
        1,
        20,
    )
    if retention < window:
        raise DataUseProviderAuditConfigError(
            "provider-audit retention must cover the complete audit window"
        )
    return ProviderAuditOperationSettings(
        audit_window_seconds=window,
        retention_seconds=retention,
        max_attempts=attempts,
    )


@dataclass(frozen=True, slots=True)
class ProviderAuditRecoveryResult:
    schema: str
    considered: int
    finalized: int
    registered: int
    already_registered: int
    pending_or_failed: int
    limit_reached: bool
    recovery_sha256: str


@dataclass(frozen=True, slots=True)
class ProviderAuditCompletion:
    authority: ProviderAuditAuthorityRecord
    expectation: ProviderAuditExpectation


class _CombinedRetentionStore:
    """Purge audit evidence before the authority records that validate it."""

    __slots__ = ("_audit_store", "_authority_store")

    def __init__(
        self,
        audit_store: DataUseProviderAuditStore,
        authority_store: DataUseProviderAuditAuthorityStore,
    ) -> None:
        self._audit_store = audit_store
        self._authority_store = authority_store

    def purge_expired(self, *, cutoff: float, limit: int) -> int:
        audit_count = self._audit_store.purge_expired(cutoff=cutoff, limit=limit)
        authority = self._authority_store.purge_expired(cutoff=cutoff, limit=limit)
        return audit_count + authority.control_authorities + authority.read_grants


class ProviderAuditRecoveryWorker:
    """Scheduler/administrator worker that recovers the outbox before reads."""

    __slots__ = ("_composition", "_runtime", "store")

    def __init__(
        self,
        composition: DataUseProviderAuditComposition,
        runtime: DataUseProviderAuditRuntime,
    ) -> None:
        self._composition = composition
        self._runtime = runtime
        self.store = _CombinedRetentionStore(composition.store, composition.authority)

    def run_once(
        self,
        *,
        worker_id: str,
        limit: int = 10,
        lease_seconds: int = 60,
        event_limit: int = 100,
        backoff_seconds: int = 30,
    ) -> ProviderAuditWorkerResult:
        self._composition.recover_pending(limit=min(limit, _MAX_RECOVERY_LIMIT))
        return self._runtime.run_once(
            worker_id=worker_id,
            limit=limit,
            lease_seconds=lease_seconds,
            event_limit=event_limit,
            backoff_seconds=backoff_seconds,
        )


class DataUseProviderAuditComposition:
    """Tenant-bound outbox, audit store, optional worker, and grant authority."""

    __slots__ = (
        "authority",
        "runtime",
        "settings",
        "store",
        "worker",
        "_clock",
        "_tenant_sha256",
    )

    def __init__(
        self,
        *,
        authority: DataUseProviderAuditAuthorityStore,
        store: DataUseProviderAuditStore,
        settings: ProviderAuditOperationSettings,
        tenant_id: str,
        clock: Callable[[], float],
        runtime: DataUseProviderAuditRuntime | None = None,
    ) -> None:
        if not isinstance(authority, DataUseProviderAuditAuthorityStore):
            raise DataUseProviderAuditConfigError("provider-audit authority store is unavailable")
        if not isinstance(store, DataUseProviderAuditStore):
            raise DataUseProviderAuditConfigError("provider-audit expectation store is unavailable")
        self.authority = authority
        self.store = store
        self.settings = settings
        self.runtime = runtime
        self._clock = clock
        canonical = canonical_tenant_id(tenant_id)
        self._tenant_sha256 = hashlib.sha256(canonical.encode()).hexdigest()
        self.worker = None if runtime is None else ProviderAuditRecoveryWorker(self, runtime)

    @staticmethod
    def _stage_key(operation_idempotency_sha256: str) -> str:
        return f"stage:{operation_idempotency_sha256}"

    @staticmethod
    def _finalize_key(authority_id: str) -> str:
        return f"finalize:{authority_id}"

    @staticmethod
    def _register_key(authority_id: str) -> str:
        return f"register:{authority_id}"

    @staticmethod
    def _mark_key(authority_id: str) -> str:
        return f"mark:{authority_id}"

    def stage_operation(
        self,
        *,
        provider_id: str,
        binding_id: str,
        operation_idempotency_sha256: str,
        control_ir: Mapping[str, Any],
        operation: str,
    ) -> ProviderAuditAuthorityRecord:
        """Stage before provider I/O, or replay the exact original projection."""

        try:
            existing = self.authority.get_control_authority_for_operation(
                provider_id,
                binding_id,
                operation_idempotency_sha256,
            )
        except DataUseProviderAuditAuthorityNotFound:
            existing = None
        if existing is None:
            now = _now(self._clock)
            valid_until = (
                now + self.settings.audit_window_seconds + self.settings.authority_grace_seconds
            )
            retained_until = now + max(
                self.settings.retention_seconds,
                self.settings.audit_window_seconds + self.settings.authority_grace_seconds,
            )
            read = self.authority.resolve_read_authority(provider_id, binding_id)
            if read.valid_until < valid_until:
                raise DataUseProviderAuditConfigError(
                    "provider-audit read authority expires before the audit window closes"
                )
            authority_revision = 1
        else:
            if existing.state == "revoked":
                raise DataUseProviderAuditConfigError(
                    "provider-audit control authority for this operation is revoked"
                )
            valid_until = existing.valid_until
            retained_until = existing.retained_until
            authority_revision = existing.authority_revision
        # Calling stage on replay is intentional: the authority reprojects the
        # supplied IR and rejects any idempotency, binding, IR, or operation drift.
        return self.authority.stage_operation(
            provider_id=provider_id,
            binding_id=binding_id,
            operation_idempotency_sha256=operation_idempotency_sha256,
            control_ir=control_ir,
            operation=operation,
            authority_revision=authority_revision,
            valid_until=valid_until,
            retained_until=retained_until,
            idempotency_key=self._stage_key(operation_idempotency_sha256),
        )

    def _expectation_for(
        self, record: ProviderAuditAuthorityRecord
    ) -> ProviderAuditExpectation | None:
        getter = getattr(self.store, "get_expectation_for_registration", None)
        if not callable(getter):
            raise DataUseProviderAuditConfigError("provider-audit operation lookup is unavailable")
        try:
            value = getter(
                self._register_key(record.authority_id),
            )
        except DataUseProviderAuditNotFound:
            return None
        if (
            value.provider_id != record.provider_id
            or value.binding_id != record.binding_id
            or value.operation_idempotency_sha256 != record.operation_idempotency_sha256
        ):
            raise DataUseProviderAuditIntegrityError(
                "provider-audit registration does not match its authority"
            )
        return value

    def _register_finalized(self, record: ProviderAuditAuthorityRecord) -> ProviderAuditCompletion:
        existing = self._expectation_for(record)
        if existing is None:
            deadline = record.valid_until - self.settings.authority_grace_seconds
            expectation = self.store.register_operation(
                provider_id=record.provider_id,
                binding_id=record.binding_id,
                operation_idempotency_sha256=record.operation_idempotency_sha256,
                audit_deadline=deadline,
                retained_until=record.retained_until,
                idempotency_key=self._register_key(record.authority_id),
                max_attempts=self.settings.max_attempts,
            )
        else:
            expectation = existing
        current = self.authority.get_control_authority_record(record.authority_id)
        if current.state == "finalized":
            current = self.authority.mark_registered(
                current.authority_id,
                expected_revision=current.revision,
                idempotency_key=self._mark_key(current.authority_id),
            )
        if current.state != "registered":
            raise DataUseProviderAuditConfigError(
                "provider-audit control authority did not reach registered state"
            )
        return ProviderAuditCompletion(authority=current, expectation=expectation)

    def complete_operation(
        self,
        authority_id: str,
    ) -> ProviderAuditCompletion:
        """Finalize a completed provider operation and register its expectation."""

        current = self.authority.get_control_authority_record(authority_id)
        if current.state == "staged":
            current = self.authority.finalize_operation(
                current.authority_id,
                expected_revision=current.revision,
                idempotency_key=self._finalize_key(current.authority_id),
            )
        if current.state not in {"finalized", "registered"}:
            raise DataUseProviderAuditConfigError(
                "provider-audit control authority is not finalizable"
            )
        return self._register_finalized(current)

    def recover_pending(self, *, limit: int = 100) -> ProviderAuditRecoveryResult:
        """Recover bounded staged/finalized records with per-record isolation."""

        bounded = _integer(limit, "provider-audit recovery limit", 1, _MAX_RECOVERY_LIMIT)
        staged = self.authority.next_control_authorities(state="staged", limit=bounded)
        finalized_count = 0
        registered_count = 0
        already_registered = 0
        failed = 0
        for record in staged:
            try:
                self.authority.finalize_operation(
                    record.authority_id,
                    expected_revision=record.revision,
                    idempotency_key=self._finalize_key(record.authority_id),
                )
                finalized_count += 1
            except (
                DataUseProviderAuditIntegrityError,
                DataUseProviderAuditAuthorityIntegrityError,
            ):
                raise
            except (DataUseProviderAuditError, DataUseProviderAuditAuthorityError):
                failed += 1
        finalized = self.authority.next_control_authorities(state="finalized", limit=bounded)
        for record in finalized:
            try:
                had_expectation = self._expectation_for(record) is not None
                self._register_finalized(record)
                if had_expectation:
                    already_registered += 1
                else:
                    registered_count += 1
            except (
                DataUseProviderAuditIntegrityError,
                DataUseProviderAuditAuthorityIntegrityError,
            ):
                raise
            except (DataUseProviderAuditError, DataUseProviderAuditAuthorityError):
                failed += 1
        considered = len(staged) + len(finalized)
        limit_reached = len(staged) == bounded or len(finalized) == bounded
        payload = {
            "schema": RECOVERY_RESULT_SCHEMA,
            "considered": considered,
            "finalized": finalized_count,
            "registered": registered_count,
            "already_registered": already_registered,
            "pending_or_failed": failed,
            "limit_reached": limit_reached,
        }
        return ProviderAuditRecoveryResult(
            **payload,
            recovery_sha256=_canonical_sha256(payload),
        )

    # Operator read-grant manager contract.  Binding and credential authority
    # remain server-derived inside the authority store.
    def get_current_read_grant(self, provider_id: str, binding_id: str) -> ProviderAuditReadGrant:
        return self.authority.get_current_read_grant(provider_id, binding_id)

    def issue_read_grant(self, **kwargs: Any) -> ProviderAuditReadGrant:
        return self.authority.issue_read_grant(**kwargs)

    def revoke_read_grant(self, grant_id: str, **kwargs: Any) -> ProviderAuditReadGrant:
        return self.authority.revoke_read_grant(grant_id, **kwargs)

    def status(self) -> Mapping[str, object]:
        authority_counts = self.authority.verify_integrity()
        payload: dict[str, object] = {
            "schema": COMPOSITION_STATUS_SCHEMA,
            "tenant_sha256": self._tenant_sha256,
            "worker_ready": self.worker is not None,
            "control_authorities": authority_counts.control_authorities,
            "read_grants": authority_counts.read_grants,
            "expectation_counts": dict(self.store.state_counts()),
            "outbox_recovery_enabled": True,
            "digest_only_authority": True,
            "raw_provider_events_persisted": False,
            "credential_material_persisted": False,
            "provider_writes_performed_by_composition": False,
            "built_in_network_transport_available": True,
            "built_in_network_transport": bool(
                self.runtime is not None
                and getattr(self.runtime, "bundled_native_transport", False)
            ),
            "audit_log_completeness_verified": False,
            "live_provider_acceptance_verified": False,
        }
        payload["status_sha256"] = _canonical_sha256(payload)
        return payload


def build_provider_audit_composition(
    *,
    tenant_id: str,
    binding_store: ProviderBindingStore,
    config: Mapping[str, Any],
    authority_store_path: str | Path | None = None,
    audit_store_path: str | Path | None = None,
    credential_owner: object | None = None,
    transport: object | None = None,
    watermark_authority_resolver: WatermarkAuthorityResolver | None = None,
    require_worker: bool = False,
    clock: Callable[[], float] = time.time,
) -> DataUseProviderAuditComposition:
    """Build a tenant composition; require transport only for worker use."""

    settings = operation_settings(config)
    tenant = canonical_tenant_id(tenant_id)
    if not isinstance(binding_store, ProviderBindingStore):
        raise DataUseProviderAuditConfigError("provider binding store is unavailable")
    if not callable(clock):
        raise DataUseProviderAuditConfigError("provider-audit composition clock is unavailable")
    authority_path = (
        Path(authority_store_path)
        if authority_store_path is not None
        else data_dir(
            "data_use_governance",
            "provider-audit-authority.sqlite3",
            tenant=tenant,
        )
    )
    audit_path = (
        Path(audit_store_path)
        if audit_store_path is not None
        else data_dir(
            "data_use_governance",
            "provider-audit.sqlite3",
            tenant=tenant,
        )
    )

    def gate() -> None:
        require_provider_audit_config(config)

    authority = DataUseProviderAuditAuthorityStore(
        authority_path,
        tenant_id=tenant,
        binding_store=binding_store,
        config_gate=gate,
        clock=clock,
    )
    runtime: DataUseProviderAuditRuntime | None = None
    if require_worker:
        runtime = build_provider_audit_runtime(
            tenant_id=tenant,
            binding_store=binding_store,
            config=config,
            store_path=audit_path,
            authority=authority,
            credential_owner=credential_owner,
            transport=transport,
            watermark_authority_resolver=watermark_authority_resolver,
            clock=clock,
        )
        store = runtime.store
    else:
        store = DataUseProviderAuditStore(
            audit_path,
            tenant_id=tenant,
            binding_store=binding_store,
            control_authority_resolver=authority.resolve_control_authority,
            read_authority_resolver=authority.resolve_read_authority,
            config_gate=gate,
            clock=clock,
        )
    return DataUseProviderAuditComposition(
        authority=authority,
        store=store,
        settings=settings,
        tenant_id=tenant,
        clock=clock,
        runtime=runtime,
    )


def attach_data_use_provider_audit_composition(app: Any) -> None:
    """Install default app factories and the explicitly gated scheduler."""

    state = getattr(app, "state", None)
    if state is None:
        raise TypeError("app must expose state")

    def composition_factory(
        *,
        tenant_id: str,
        principal_ref: str,
        request: Any | None = None,
        require_worker: bool = False,
        **_unused: Any,
    ) -> DataUseProviderAuditComposition:
        # principal_ref is deliberately consumed but never persisted.  The
        # stores are tenant authorities; endpoint RBAC is enforced upstream.
        if not isinstance(principal_ref, str) or not principal_ref:
            raise DataUseProviderAuditConfigError(
                "provider-audit principal authority is unavailable"
            )
        from maverick import config as config_module

        if config_module.config_source_errors():
            raise DataUseProviderAuditConfigError("provider-audit configuration source is invalid")
        config = config_module.load_config()
        if not isinstance(config, Mapping):
            raise DataUseProviderAuditConfigError("provider-audit configuration is unavailable")
        tenant = canonical_tenant_id(tenant_id)
        bindings = ProviderBindingStore(
            data_dir(
                "data_use_governance",
                "data-use-providers.sqlite3",
                tenant=tenant,
            )
        )
        return build_provider_audit_composition(
            tenant_id=tenant,
            binding_store=bindings,
            config=config,
            credential_owner=getattr(state, "data_use_provider_credential_owner", None),
            transport=getattr(state, "data_use_provider_audit_transport", None),
            watermark_authority_resolver=getattr(
                state,
                "data_use_provider_audit_watermark_authority_resolver",
                None,
            ),
            require_worker=require_worker,
        )

    existing = getattr(state, "data_use_provider_audit_composition_factory", None)
    existing_worker_factory = getattr(state, "data_use_provider_audit_worker_factory", None)
    selected_factory = existing if callable(existing) else composition_factory
    if existing is None:
        state.data_use_provider_audit_composition_factory = selected_factory

    if getattr(state, "data_use_provider_audit_store_factory", None) is None:
        state.data_use_provider_audit_store_factory = lambda **kwargs: (
            selected_factory(**kwargs, require_worker=False).store
        )
    if getattr(state, "data_use_provider_audit_read_grant_factory", None) is None:
        state.data_use_provider_audit_read_grant_factory = lambda **kwargs: selected_factory(
            **kwargs, require_worker=False
        )
    if getattr(state, "data_use_provider_audit_worker_factory", None) is None:
        state.data_use_provider_audit_worker_factory = lambda **kwargs: (
            selected_factory(**kwargs, require_worker=True).worker
        )

    from .data_use_provider_audit_scheduler import (
        attach_data_use_provider_audit_scheduler,
    )

    def scheduler_worker_factory(tenant_id: str, principal_ref: str) -> Any:
        if callable(existing_worker_factory):
            return existing_worker_factory(
                tenant_id=tenant_id,
                principal_ref=principal_ref,
            )
        composition = selected_factory(
            tenant_id=tenant_id,
            principal_ref=principal_ref,
            require_worker=True,
        )
        if composition.worker is None:
            raise DataUseProviderAuditConfigError("provider-audit worker is unavailable")
        return composition.worker

    if getattr(state, "data_use_provider_audit_scheduler", None) is None:
        attach_data_use_provider_audit_scheduler(
            app,
            worker_factory=scheduler_worker_factory,
        )


__all__ = [
    "COMPOSITION_STATUS_SCHEMA",
    "DataUseProviderAuditComposition",
    "ProviderAuditCompletion",
    "ProviderAuditOperationSettings",
    "ProviderAuditRecoveryResult",
    "ProviderAuditRecoveryWorker",
    "attach_data_use_provider_audit_composition",
    "build_provider_audit_composition",
    "operation_settings",
]
