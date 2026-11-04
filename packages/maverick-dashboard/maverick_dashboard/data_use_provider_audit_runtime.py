"""Composable dashboard runtime for digest-only provider audit reconciliation.

The core audit store owns validation and persistence.  This module only binds
it to tenant storage, an injected authority, an ephemeral adapter credential
owner, and an injected read transport.  Construction performs no provider I/O
and resolves no credential material.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from maverick.data_use_provider_adapters import CredentialLease, ProviderBindingStore
from maverick.data_use_provider_audit import (
    DataUseProviderAuditConfigError,
    DataUseProviderAuditStore,
    DataUseProviderAuditWorker,
    ProviderAuditControlAuthority,
    ProviderAuditCredentialLease,
    ProviderAuditExpectation,
    ProviderAuditReadAuthority,
    ProviderAuditTransport,
    ProviderAuditWorkerResult,
)
from maverick.paths import canonical_tenant_id, data_dir

from .data_use_provider_audit_transport import (
    NativeProviderAuditTransport,
    WatermarkAuthorityResolver,
    build_native_provider_audit_transport,
    build_operator_watermark_authority,
)
from .data_use_provider_runtime import SecretProviderCredentialOwner

RUNTIME_STATUS_SCHEMA = "lightwork.dashboard.data-use-provider-audit-runtime-status.v2"

ControlAuthorityResolver = Callable[
    [str, str, str, Mapping[str, Any]], ProviderAuditControlAuthority
]
ReadAuthorityResolver = Callable[[str, str], ProviderAuditReadAuthority]


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
            "provider audit runtime status is not canonical"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def provider_audit_config_enabled(config: Mapping[str, Any]) -> bool:
    """Return true only for the core provider-audit default-off gates."""

    if not isinstance(config, Mapping):
        return False
    root = config.get("data_use_governance")
    audit = root.get("provider_audit") if isinstance(root, Mapping) else None
    return bool(
        isinstance(root, Mapping)
        and root.get("enable") is True
        and isinstance(audit, Mapping)
        and audit.get("enable") is True
    )


def require_provider_audit_config(config: Mapping[str, Any]) -> None:
    """Fail closed unless the captured runtime configuration remains enabled."""

    if not provider_audit_config_enabled(config):
        raise DataUseProviderAuditConfigError(
            "provider audit is disabled; enable data_use_governance.provider_audit explicitly"
        )


class ProviderAuditCredentialOwnerBridge:
    """Adapt an existing provider credential owner without retaining its lease."""

    __slots__ = ("_owner",)

    def __init__(self, owner: object) -> None:
        if not callable(getattr(owner, "lease", None)):
            raise DataUseProviderAuditConfigError("provider audit credential owner is unavailable")
        self._owner = owner

    def __repr__(self) -> str:
        return f"{type(self).__name__}(ready=True)"

    def lease(
        self, *, provider_id: str, tenant_id: str, binding_id: str
    ) -> ProviderAuditCredentialLease:
        lease = self._owner.lease(
            provider_id=provider_id,
            tenant_id=tenant_id,
            binding_id=binding_id,
        )
        if type(lease) is not CredentialLease:
            raise DataUseProviderAuditConfigError(
                "provider credential owner returned an invalid lease"
            )
        return ProviderAuditCredentialLease(
            authorization=lease.authorization,
            credential_key_id_sha256=hashlib.sha256(lease.key_id.encode("ascii")).hexdigest(),
            credential_revision=lease.key_revision,
            credential_authority_sha256=lease.authority_sha256,
            expires_at=lease.expires_at,
            revoked=lease.revoked,
        )


def _authority_resolvers(
    *,
    authority: object | None,
    control_authority_resolver: ControlAuthorityResolver | None,
    read_authority_resolver: ReadAuthorityResolver | None,
) -> tuple[ControlAuthorityResolver, ReadAuthorityResolver]:
    if authority is not None and (
        control_authority_resolver is not None or read_authority_resolver is not None
    ):
        raise DataUseProviderAuditConfigError("provider audit authority injection is ambiguous")
    if authority is None:
        if not callable(control_authority_resolver) or not callable(read_authority_resolver):
            raise DataUseProviderAuditConfigError(
                "provider audit control and read authorities are unavailable"
            )
        return control_authority_resolver, read_authority_resolver

    resolver_pairs = (
        ("resolve_control_authority", "resolve_read_authority"),
        ("control_authority_resolver", "read_authority_resolver"),
        ("control", "read"),
    )
    for control_name, read_name in resolver_pairs:
        control = getattr(authority, control_name, None)
        read = getattr(authority, read_name, None)
        if callable(control) and callable(read):
            return control, read
    raise DataUseProviderAuditConfigError(
        "provider audit authority does not expose a complete resolver pair"
    )


@dataclass(frozen=True, slots=True, repr=False)
class DataUseProviderAuditRuntime:
    """Tenant-bound store/worker bundle for API and scheduler composition."""

    store: DataUseProviderAuditStore
    worker: DataUseProviderAuditWorker
    control_authority_resolver: ControlAuthorityResolver
    read_authority_resolver: ReadAuthorityResolver
    credential_owner: ProviderAuditCredentialOwnerBridge
    transport: ProviderAuditTransport
    tenant_sha256: str
    store_path_sha256: str
    bundled_native_transport: bool

    def __repr__(self) -> str:
        return f"{type(self).__name__}(tenant_sha256={self.tenant_sha256!r}, ready=True)"

    def register_operation(
        self,
        *,
        provider_id: str,
        binding_id: str,
        operation_idempotency_sha256: str,
        audit_deadline: float,
        retained_until: float,
        idempotency_key: str,
        max_attempts: int = 5,
    ) -> ProviderAuditExpectation:
        return self.store.register_operation(
            provider_id=provider_id,
            binding_id=binding_id,
            operation_idempotency_sha256=operation_idempotency_sha256,
            audit_deadline=audit_deadline,
            retained_until=retained_until,
            idempotency_key=idempotency_key,
            max_attempts=max_attempts,
        )

    def run_once(
        self,
        *,
        worker_id: str,
        limit: int = 10,
        lease_seconds: int = 60,
        event_limit: int = 100,
        backoff_seconds: int = 30,
    ) -> ProviderAuditWorkerResult:
        return self.worker.run_once(
            worker_id=worker_id,
            limit=limit,
            lease_seconds=lease_seconds,
            event_limit=event_limit,
            backoff_seconds=backoff_seconds,
        )

    def state_counts(self) -> Mapping[str, int]:
        return self.store.state_counts()

    def status(self) -> Mapping[str, object]:
        """Return counts, digests, and explicit non-claims without provider I/O."""

        boundaries = self.store.product_boundaries()
        payload: dict[str, object] = {
            "schema": RUNTIME_STATUS_SCHEMA,
            "tenant_sha256": self.tenant_sha256,
            "store_path_sha256": self.store_path_sha256,
            "runtime_constructed": True,
            "tenant_bound": True,
            "control_authority_resolver_injected": True,
            "read_authority_resolver_injected": True,
            "credential_owner_bridge_ready": True,
            "worker_ready": True,
            "typed_read_transport_injected": True,
            "digest_only_status": True,
            "raw_provider_events_persisted": bool(boundaries["raw_provider_events_persisted"]),
            "credential_material_persisted": bool(boundaries["credential_material_persisted"]),
            "provider_writes": bool(boundaries["provider_writes"]),
            "built_in_network_transport_available": True,
            "built_in_network_transport": self.bundled_native_transport,
            "core_store_performs_network_io": bool(boundaries["built_in_network_transport"]),
            "audit_log_completeness_claim": bool(boundaries["audit_log_completeness_claim"]),
            "live_provider_acceptance": bool(boundaries["live_provider_acceptance"]),
            "state_counts": dict(self.state_counts()),
        }
        payload["status_sha256"] = _canonical_sha256(payload)
        return payload


def build_provider_audit_runtime(
    *,
    tenant_id: str,
    binding_store: ProviderBindingStore,
    config: Mapping[str, Any],
    store_path: str | Path | None = None,
    control_authority_resolver: ControlAuthorityResolver | None = None,
    read_authority_resolver: ReadAuthorityResolver | None = None,
    authority: object | None = None,
    credential_owner: object | None = None,
    transport: ProviderAuditTransport | None = None,
    watermark_authority_resolver: WatermarkAuthorityResolver | None = None,
    clock: Callable[[], float] = time.time,
) -> DataUseProviderAuditRuntime:
    """Build one closed runtime after validating every injected capability."""

    require_provider_audit_config(config)
    canonical_tenant = canonical_tenant_id(tenant_id)
    if not callable(getattr(binding_store, "get_binding", None)) or not callable(
        getattr(binding_store, "get_operation", None)
    ):
        raise DataUseProviderAuditConfigError("provider binding/operation authority is unavailable")
    control_resolver, read_resolver = _authority_resolvers(
        authority=authority,
        control_authority_resolver=control_authority_resolver,
        read_authority_resolver=read_authority_resolver,
    )
    if not callable(clock):
        raise DataUseProviderAuditConfigError("provider audit clock is unavailable")

    operator_watermark = build_operator_watermark_authority(
        tenant_id=canonical_tenant,
        binding_store=binding_store,
        config=config,
        databricks_resolver=watermark_authority_resolver,
        clock=clock,
    )
    owner = (
        credential_owner
        if credential_owner is not None
        else SecretProviderCredentialOwner(config, clock=clock)
    )
    bridge = ProviderAuditCredentialOwnerBridge(owner)
    selected_transport = transport
    if selected_transport is None:
        selected_transport = build_native_provider_audit_transport(
            tenant_id=canonical_tenant,
            binding_store=binding_store,
            config=config,
            watermark_authority_resolver=operator_watermark.resolve,
            credential_lease_resolver=bridge.lease,
            clock=clock,
        )
    if not callable(getattr(selected_transport, "read", None)):
        raise DataUseProviderAuditConfigError("provider audit typed read transport is unavailable")

    selected_path = (
        Path(store_path)
        if store_path is not None
        else data_dir(
            "data_use_governance",
            "provider-audit.sqlite3",
            tenant=canonical_tenant,
        )
    )

    def config_gate() -> None:
        require_provider_audit_config(config)

    store = DataUseProviderAuditStore(
        selected_path,
        tenant_id=canonical_tenant,
        binding_store=binding_store,
        control_authority_resolver=control_resolver,
        read_authority_resolver=read_resolver,
        watermark_authority_resolver=operator_watermark.resolve,
        config_gate=config_gate,
        clock=clock,
    )
    worker = DataUseProviderAuditWorker(
        store,
        credential_owner=bridge,
        transport=selected_transport,
    )
    return DataUseProviderAuditRuntime(
        store=store,
        worker=worker,
        control_authority_resolver=control_resolver,
        read_authority_resolver=read_resolver,
        credential_owner=bridge,
        transport=selected_transport,
        tenant_sha256=_text_sha256(canonical_tenant),
        store_path_sha256=_text_sha256(str(selected_path.resolve())),
        bundled_native_transport=isinstance(selected_transport, NativeProviderAuditTransport),
    )


__all__ = [
    "ControlAuthorityResolver",
    "DataUseProviderAuditRuntime",
    "ProviderAuditCredentialOwnerBridge",
    "RUNTIME_STATUS_SCHEMA",
    "ReadAuthorityResolver",
    "build_provider_audit_runtime",
    "provider_audit_config_enabled",
    "require_provider_audit_config",
]
