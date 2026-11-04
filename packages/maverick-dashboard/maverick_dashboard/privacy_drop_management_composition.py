"""Stock, default-off composition for California DROP management.

This module installs lazy app-state factories for the existing strict DROP API.
It composes a tenant-local authority registry, the durable DROP lifecycle store,
and the existing privacy-rights orchestration intake boundary.  No network
transport, California credential, broker registration or legal conclusion is
bundled or inferred.

The stock bridge opens an unverified privacy-rights case using only the imported
subject-binding digest.  A deployment may install a stricter
``privacy_drop_rights_intake_submitter`` (for example, an independently assured
identity workflow).  The stock bridge never marks subject identity verified and
never plans or executes provider work on its own.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from maverick.file_lock import cross_process_lock
from maverick.paths import canonical_tenant_id, data_dir, tenant_scope
from maverick.privacy_drop_management import (
    DROPDSARReceipt,
    DROPManagementConfigError,
    DROPManagementStore,
    DROPRecordAuthority,
)
from maverick.privacy_drop_management import (
    enabled as drop_enabled,
)

from .privacy_drop_authority_proposals import DROPAuthorityProposalStore
from .privacy_drop_authority_registry import DROPAuthorityRegistry
from .privacy_drop_principal_authority import DROPPrincipalKeyAuthority

_DEFAULT_RETENTION_SECONDS = 365 * 24 * 3_600
_MAX_RETENTION_SECONDS = 10 * 365 * 24 * 3_600
_BINDING_KEY_ENV = "MAVERICK_PRIVACY_RIGHTS_DIGEST_KEY"
_QUEUE_NAMESPACE = uuid.UUID("e1f05e39-74cc-48f9-bdd4-a8604e83e217")


@dataclass(frozen=True, slots=True)
class DROPManagementCompositionSettings:
    retention_seconds: int
    principal_binding_key_ref: str
    scheduler_interval_seconds: int
    scheduler_jitter_seconds: int
    scheduler_retry_max_seconds: int
    scheduler_enable: bool


def _bounded_integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise DROPManagementConfigError(f"{label} is outside its bound")
    return value


def _key_reference(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(
        r"(?:env:[A-Z][A-Z0-9_]{0,127}|"
        r"(?:kms|secret|vault|aws-kms|azure-keyvault|gcp-kms)://"
        r"[A-Za-z0-9][A-Za-z0-9_./:@+-]{0,239})",
        value,
    ) is None:
        raise DROPManagementConfigError("principal_binding_key_ref is invalid")
    return value


def privacy_drop_management_composition_enabled(
    config: Mapping[str, Any] | None = None,
) -> bool:
    """Return code-plane availability or exact supplied-tenant enablement."""

    if config is None:
        return True
    try:
        return drop_enabled(config) is True
    except Exception:
        return False


def _load_tenant_config(tenant_id: str) -> Mapping[str, Any]:
    tenant = canonical_tenant_id(tenant_id)
    try:
        from maverick import config as config_module

        with tenant_scope(tenant=tenant):
            config = config_module.load_config()
            source_errors = config_module.config_source_errors(include_tenant=True)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise DROPManagementConfigError("DROP tenant configuration is unavailable") from exc
    if source_errors or not isinstance(config, Mapping):
        raise DROPManagementConfigError("DROP tenant configuration source is invalid")
    if not privacy_drop_management_composition_enabled(config):
        raise DROPManagementConfigError("DROP management is disabled for this tenant")
    return config


def _default_tenant_supplier() -> Sequence[str]:
    floor = os.environ.get("MAVERICK_TENANT", "").strip()
    try:
        from maverick.tenant.registry import list_tenants

        records = tuple(list_tenants())
    except Exception as exc:
        raise DROPManagementConfigError("DROP tenant registry is unavailable") from exc
    tenants: list[str] = [floor] if floor else []
    for record in records:
        tenant = str(getattr(record, "id", "") or "").strip()
        if tenant and getattr(record, "active", False) and tenant not in tenants:
            tenants.append(tenant)
    return tuple(tenants)


def _settings(config: Mapping[str, Any]) -> DROPManagementCompositionSettings:
    privacy = config.get("privacy_automation") if isinstance(config, Mapping) else None
    table = privacy.get("drop_management") if isinstance(privacy, Mapping) else None
    if not isinstance(table, Mapping) or table.get("enable") is not True:
        raise DROPManagementConfigError("DROP management is disabled")
    scheduler_enable = table.get("scheduler_enable", False)
    if not isinstance(scheduler_enable, bool):
        raise DROPManagementConfigError("scheduler_enable must be boolean")
    interval = _bounded_integer(
        table.get("scheduler_interval_seconds", 3_600),
        "scheduler_interval_seconds",
        30,
        86_400,
    )
    jitter = _bounded_integer(
        table.get("scheduler_jitter_seconds", 60),
        "scheduler_jitter_seconds",
        0,
        3_600,
    )
    if jitter >= interval:
        raise DROPManagementConfigError("scheduler_jitter_seconds must be below interval")
    return DROPManagementCompositionSettings(
        retention_seconds=_bounded_integer(
            table.get("retention_seconds", _DEFAULT_RETENTION_SECONDS),
            "retention_seconds",
            3_600,
            _MAX_RETENTION_SECONDS,
        ),
        principal_binding_key_ref=_key_reference(
            table.get("principal_binding_key_ref", f"env:{_BINDING_KEY_ENV}")
        ),
        scheduler_interval_seconds=interval,
        scheduler_jitter_seconds=jitter,
        scheduler_retry_max_seconds=_bounded_integer(
            table.get("scheduler_retry_max_seconds", 900),
            "scheduler_retry_max_seconds",
            30,
            86_400,
        ),
        scheduler_enable=scheduler_enable,
    )


def _request_for(app: FastAPI, request: Request | None) -> Request | None:
    if request is not None and (not isinstance(request, Request) or request.app is not app):
        raise DROPManagementConfigError("DROP request authority is unavailable")
    return request


def _clock(app: FastAPI) -> Callable[[], float]:
    value = getattr(app.state, "privacy_drop_management_clock", None)
    return value if callable(value) else time.time


def _path(
    app: FastAPI,
    *,
    tenant_id: str,
    request: Request | None,
    state_name: str,
    filename: str,
) -> Path:
    factory = getattr(app.state, state_name, None)
    value = (
        factory(tenant_id=tenant_id, request=request)
        if callable(factory)
        else data_dir("privacy_automation", filename, tenant=tenant_id)
    )
    if not isinstance(value, (str, Path)):
        raise DROPManagementConfigError("DROP storage path is unavailable")
    return Path(value)


def _binding_key(
    app: FastAPI,
    tenant_id: str,
    key_ref: str,
    request: Request | None,
) -> bytes:
    resolver = getattr(app.state, "privacy_drop_secret_resolver", None)
    legacy = getattr(app.state, "privacy_drop_principal_binding_key_resolver", None)
    try:
        if callable(resolver):
            value = resolver(tenant_id=tenant_id, key_ref=key_ref, request=request)
        elif callable(legacy) and key_ref == f"env:{_BINDING_KEY_ENV}":
            value = legacy(tenant_id=tenant_id, request=request)
        elif key_ref == f"env:{_BINDING_KEY_ENV}":
            value = os.environ.get(_BINDING_KEY_ENV, "").encode("utf-8")
        else:
            raise DROPManagementConfigError("DROP secret provider is unavailable")
    except Exception as exc:
        raise DROPManagementConfigError("DROP principal binding key is unavailable") from exc
    if not isinstance(value, bytes) or len(value) < 32:
        raise DROPManagementConfigError("DROP principal binding key is unavailable")
    return value


def _maintenance_authorizer(
    app: FastAPI,
    *,
    tenant_id: str,
    request: Request | None,
    maintenance: bool,
) -> Callable[[], bool]:
    if not maintenance:
        return lambda: False
    factory = getattr(
        app.state,
        "privacy_drop_management_maintenance_authorizer_factory",
        None,
    )
    if not callable(factory):
        # Only the closure-private maintenance runner can request this branch;
        # the public API and exported registry factory always pass False.  The
        # underlying stores still require expiry, integrity, bounds and locks.
        return lambda: True
    try:
        value = factory(tenant_id=tenant_id, request=request)
    except Exception as exc:
        raise DROPManagementConfigError("DROP maintenance authority is unavailable") from exc
    if not callable(value):
        raise DROPManagementConfigError("DROP maintenance authority is unavailable")
    return value


def _config_gate(tenant_id: str) -> Callable[[], None]:
    tenant = canonical_tenant_id(tenant_id)

    def require() -> None:
        _load_tenant_config(tenant)

    return require


def _key_authority_for(
    app: FastAPI,
    *,
    tenant_id: str,
    request: Request | None,
) -> DROPPrincipalKeyAuthority:
    tenant = canonical_tenant_id(tenant_id)
    settings = _settings(_load_tenant_config(tenant))
    holder: dict[str, DROPPrincipalKeyAuthority] = {}

    def resolve_secret(resolved_tenant: str, key_ref: str) -> bytes:
        if canonical_tenant_id(resolved_tenant) != tenant:
            raise DROPManagementConfigError("DROP principal tenant changed")
        return _binding_key(app, tenant, key_ref, request)

    def dependency_count(revision: int) -> int:
        authority = holder.get("authority")
        if authority is None:
            raise DROPManagementConfigError("DROP key authority is unavailable")
        registry = _registry_for(
            app,
            tenant_id=tenant,
            request=request,
            key_authority=authority,
        )
        counts = dict(registry.retained_key_revision_counts())
        management_path = _path(
            app,
            tenant_id=tenant,
            request=request,
            state_name="privacy_drop_management_path_factory",
            filename="privacy-drop-management.sqlite3",
        )
        if management_path.exists():
            store = _store_for(
                app,
                tenant_id=tenant,
                actor_ref="drop-key-dependency-audit",
                request=request,
                key_authority=authority,
                registry=registry,
            )
            for key_revision, count in store.retained_key_revision_counts().items():
                counts[key_revision] = counts.get(key_revision, 0) + count
        proposal_path = _path(
            app,
            tenant_id=tenant,
            request=request,
            state_name="privacy_drop_authority_proposal_path_factory",
            filename="privacy-drop-authority-proposals.sqlite3",
        )
        if proposal_path.exists():
            proposals = DROPAuthorityProposalStore(
                proposal_path,
                tenant_id=tenant,
                principal_binding_resolver=authority.bind,
                principal_binding_verifier=authority.verify,
                retention_seconds=settings.retention_seconds,
                config_gate=_config_gate(tenant),
                clock=_clock(app),
            )
            for key_revision, count in proposals.retained_key_revision_counts().items():
                counts[key_revision] = counts.get(key_revision, 0) + count
        return int(counts.get(revision, 0))

    authority = DROPPrincipalKeyAuthority(
        _path(
            app,
            tenant_id=tenant,
            request=request,
            state_name="privacy_drop_principal_key_authority_path_factory",
            filename="privacy-drop-principal-key-authority.sqlite3",
        ),
        tenant_id=tenant,
        initial_key_ref=settings.principal_binding_key_ref,
        secret_resolver=resolve_secret,
        dependency_counter=dependency_count,
        config_gate=_config_gate(tenant),
        clock=_clock(app),
    )
    holder["authority"] = authority
    return authority


def _proposal_store_for(
    app: FastAPI,
    *,
    tenant_id: str,
    request: Request | None,
    maintenance: bool = False,
) -> DROPAuthorityProposalStore:
    tenant = canonical_tenant_id(tenant_id)
    settings = _settings(_load_tenant_config(tenant))
    keys = _key_authority_for(app, tenant_id=tenant, request=request)
    return DROPAuthorityProposalStore(
        _path(
            app,
            tenant_id=tenant,
            request=request,
            state_name="privacy_drop_authority_proposal_path_factory",
            filename="privacy-drop-authority-proposals.sqlite3",
        ),
        tenant_id=tenant,
        principal_binding_resolver=keys.bind,
        principal_binding_verifier=keys.verify,
        retention_seconds=settings.retention_seconds,
        maintenance_authorizer=_maintenance_authorizer(
            app,
            tenant_id=tenant,
            request=request,
            maintenance=maintenance,
        ),
        config_gate=_config_gate(tenant),
        clock=_clock(app),
    )


def _registry_for(
    app: FastAPI,
    *,
    tenant_id: str,
    request: Request | None,
    maintenance: bool = False,
    key_authority: DROPPrincipalKeyAuthority | None = None,
) -> DROPAuthorityRegistry:
    tenant = canonical_tenant_id(tenant_id)
    config = _load_tenant_config(tenant)
    settings = _settings(config)
    keys = key_authority or _key_authority_for(
        app,
        tenant_id=tenant,
        request=request,
    )
    return DROPAuthorityRegistry(
        _path(
            app,
            tenant_id=tenant,
            request=request,
            state_name="privacy_drop_authority_registry_path_factory",
            filename="privacy-drop-authority-registry.sqlite3",
        ),
        tenant_id=tenant,
        principal_binding_resolver=keys.bind,
        principal_binding_verifier=keys.verify,
        retention_seconds=settings.retention_seconds,
        maintenance_authorizer=_maintenance_authorizer(
            app,
            tenant_id=tenant,
            request=request,
            maintenance=maintenance,
        ),
        config_gate=_config_gate(tenant),
        clock=_clock(app),
    )


def _service_principal(authority: DROPRecordAuthority) -> str:
    digest = hashlib.sha256(
        (
            "lightwork.privacy-drop.rights-intake.v1:"
            f"{authority.tenant_id}:{authority.drop_id}:{authority.authority_sha256}"
        ).encode("ascii")
    ).hexdigest()
    return f"drop-rights-intake-{digest[:32]}"


def _default_rights_store(
    app: FastAPI,
    *,
    authority: DROPRecordAuthority,
    request: Request | None,
) -> object:
    from .privacy_rights_orchestration_api import _default_store_for

    principal_ref = _service_principal(authority)
    factory = getattr(app.state, "privacy_rights_orchestration_store_factory", None)

    def principal_resolver() -> str:
        return principal_ref

    value = (
        factory(
            tenant_id=authority.tenant_id,
            principal_ref=principal_ref,
            principal_resolver=principal_resolver,
            request=request,
        )
        if callable(factory)
        else _default_store_for(authority.tenant_id, principal_ref)
    )
    if not callable(getattr(value, "open_case", None)):
        raise DROPManagementConfigError("privacy-rights intake authority is unavailable")
    return value


def _stock_rights_submitter(
    app: FastAPI,
    *,
    authority: DROPRecordAuthority,
    idempotency_key: str,
    request: Request | None,
    retention_seconds: int,
) -> DROPDSARReceipt:
    """Open an unverified, provider-neutral rights-orchestration intake case."""

    store = _default_rights_store(app, authority=authority, request=request)
    case_id = f"DROP-{authority.drop_id}-{authority.authority_sha256[:24]}"
    right = "erasure" if authority.request_type == "DataDeletion" else "opt_out"
    now = float(_clock(app)())
    try:
        case = store.open_case(
            authority.tenant_id,
            case_id,
            request_version=authority.record_revision,
            external_request_ref=(
                f"drop:{authority.drop_id}:{authority.authority_sha256}"
            ),
            subject_reference=authority.subject_binding_sha256,
            rights=(right,),
            retained_until=now + retention_seconds,
            idempotency_key=f"drop-rights-{idempotency_key}",
        )
    except Exception as exc:
        raise DROPManagementConfigError("privacy-rights intake submission failed") from exc
    if (
        getattr(case, "tenant_id", None) != authority.tenant_id
        or getattr(case, "case_id", None) != case_id
        or tuple(getattr(case, "rights", ())) != (right,)
        or getattr(case, "identity_status", None) != "unverified"
        or not isinstance(getattr(case, "created_at", None), (int, float))
    ):
        raise DROPManagementConfigError("privacy-rights intake receipt changed")
    queue_id = str(
        uuid.uuid5(
            _QUEUE_NAMESPACE,
            f"{authority.tenant_id}:{authority.authority_sha256}:{case_id}",
        )
    )
    return DROPDSARReceipt(
        tenant_id=authority.tenant_id,
        drop_id=authority.drop_id,
        authority_sha256=authority.authority_sha256,
        subject_binding_sha256=authority.subject_binding_sha256,
        request_type=authority.request_type,
        request_queue_id=queue_id,
        request_queue_ref_id="privacy-rights-orchestration",
        internal_case_id=case_id,
        created_at=float(case.created_at),
    ).normalized()


def _rights_submitter(
    app: FastAPI,
    *,
    request: Request | None,
    retention_seconds: int,
) -> Callable[[DROPRecordAuthority, str], DROPDSARReceipt]:
    explicit = getattr(app.state, "privacy_drop_rights_intake_submitter", None)

    def submit(authority: DROPRecordAuthority, idempotency_key: str) -> DROPDSARReceipt:
        if callable(explicit):
            try:
                value = explicit(
                    authority=authority,
                    idempotency_key=idempotency_key,
                    request=request,
                )
            except Exception as exc:
                raise DROPManagementConfigError(
                    "privacy-rights intake submission failed"
                ) from exc
            if type(value) is not DROPDSARReceipt:
                raise DROPManagementConfigError("privacy-rights intake receipt changed")
            return value.normalized()
        return _stock_rights_submitter(
            app,
            authority=authority,
            idempotency_key=idempotency_key,
            request=request,
            retention_seconds=retention_seconds,
        )

    return submit


def _store_for(
    app: FastAPI,
    *,
    tenant_id: str,
    actor_ref: str,
    request: Request | None,
    maintenance: bool = False,
    key_authority: DROPPrincipalKeyAuthority | None = None,
    registry: DROPAuthorityRegistry | None = None,
) -> DROPManagementStore:
    del actor_ref  # The strict API passes it separately to terminal status updates.
    tenant = canonical_tenant_id(tenant_id)
    config = _load_tenant_config(tenant)
    settings = _settings(config)
    keys = key_authority or _key_authority_for(
        app,
        tenant_id=tenant,
        request=request,
    )
    resolved_registry = registry or _registry_for(
        app,
        tenant_id=tenant,
        request=request,
        maintenance=maintenance,
        key_authority=keys,
    )

    def resolve(expected: DROPRecordAuthority) -> DROPRecordAuthority:
        current = resolved_registry.resolve_record(drop_id=expected.drop_id)
        if current.authority_sha256 != expected.authority_sha256:
            raise DROPManagementConfigError("DROP record authority changed")
        return current

    return DROPManagementStore(
        _path(
            app,
            tenant_id=tenant,
            request=request,
            state_name="privacy_drop_management_path_factory",
            filename="privacy-drop-management.sqlite3",
        ),
        tenant_id=tenant,
        authority_resolver=resolve,
        dsar_submitter=_rights_submitter(
            app,
            request=request,
            retention_seconds=settings.retention_seconds,
        ),
        status_evidence_resolver=resolved_registry.resolve_outcome,
        principal_binding_resolver=keys.bind,
        principal_binding_verifier=keys.verify,
        principal_key_revision_checker=lambda revision: (
            keys.require_active_revision(revision) is None
        ),
        retention_seconds=settings.retention_seconds,
        maintenance_authorizer=_maintenance_authorizer(
            app,
            tenant_id=tenant,
            request=request,
            maintenance=maintenance,
        ),
        config_gate=_config_gate(tenant),
        clock=_clock(app),
    )


def attach_privacy_drop_management_composition(  # noqa: C901 - explicit app-state seams
    app: FastAPI,
) -> None:
    """Install lazy stock seams; no tenant store is opened during attachment."""

    if not isinstance(app, FastAPI):
        raise TypeError("DROP composition requires a FastAPI application")
    state = app.state
    deployment_enabled_probe = getattr(state, "privacy_drop_management_enabled_probe", None)
    deployment_readiness_probe = getattr(state, "privacy_drop_management_readiness_probe", None)

    def enabled_probe(tenant_id: str) -> bool:
        try:
            enabled = privacy_drop_management_composition_enabled(
                _load_tenant_config(canonical_tenant_id(tenant_id))
            )
            if callable(deployment_enabled_probe):
                return enabled and deployment_enabled_probe(tenant_id) is True
            return enabled
        except DROPManagementConfigError:
            return False

    def readiness_report(tenant_id: str) -> Mapping[str, object]:
        report: dict[str, object] = {
            "schema": "lightwork.privacy-drop-operational-readiness.v2",
            "configured_for_attempt": False,
            "locally_operational": False,
            "request_executable": False,
            "key_authority_integrity_valid": False,
            "registry_integrity_valid": False,
            "management_integrity_valid": False,
            "storage_lock_ready": False,
            "rights_intake_ready": False,
            "active_brokers": 0,
            "active_records": 0,
            "approved_outcomes": 0,
            "request_execution_blocker": "drop_not_configured",
            "scheduler": {"installed": False, "running": False, "healthy": False},
            "live_interoperability_verified": False,
            "legal_acceptance_verified": False,
        }
        try:
            tenant = canonical_tenant_id(tenant_id)
            if enabled_probe(tenant) is not True:
                return report
            required = (
                "privacy_drop_management_store_factory",
                "privacy_drop_record_authority_resolver",
                "privacy_drop_authority_registry_factory",
                "privacy_drop_principal_key_authority_factory",
                "privacy_drop_authority_proposal_store_factory",
                "privacy_drop_management_reconciliation_runner",
                "privacy_drop_management_maintenance_runner",
                "privacy_drop_management_maintenance_cycle_runner",
            )
            if not all(callable(getattr(state, name, None)) for name in required):
                return report
            report["configured_for_attempt"] = True
            keys = state.privacy_drop_principal_key_authority_factory(
                tenant_id=tenant,
                request=None,
            )
            registry = state.privacy_drop_authority_registry_factory(
                tenant_id=tenant,
                request=None,
            )
            store = _store_for(
                app,
                tenant_id=tenant,
                actor_ref="drop-readiness-probe",
                request=None,
                key_authority=keys,
                registry=registry,
            )
            proposals = state.privacy_drop_authority_proposal_store_factory(
                tenant_id=tenant,
                request=None,
            )
            key_valid = keys.verify_integrity() is True
            registry_valid = registry.verify_integrity() is True
            management_valid = (
                store.verify_integrity() is True and proposals.verify_integrity() is True
            )
            lock_ready = True
            for storage in (keys, registry, store, proposals):
                storage_path = getattr(storage, "path", None)
                if not isinstance(storage_path, Path):
                    lock_ready = False
                    break
                with cross_process_lock(storage_path, strict=True):
                    pass
            reconciliation = registry.reconcile()
            explicit_submitter = getattr(state, "privacy_drop_rights_intake_submitter", None)
            explicit_probe = getattr(
                state,
                "privacy_drop_rights_intake_readiness_probe",
                None,
            )
            rights_factory = getattr(state, "privacy_rights_orchestration_store_factory", None)
            if callable(explicit_submitter):
                rights_ready = bool(
                    callable(explicit_probe) and explicit_probe(tenant) is True
                )
            elif callable(rights_factory):
                rights_store = rights_factory(
                    tenant_id=tenant,
                    principal_ref="drop-readiness-probe",
                    principal_resolver=lambda: "drop-readiness-probe",
                    request=None,
                )
                rights_ready = callable(getattr(rights_store, "open_case", None))
            else:
                from .privacy_rights_orchestration_api import _default_store_for

                rights_store = _default_store_for(tenant, "drop-readiness-probe")
                rights_ready = callable(getattr(rights_store, "open_case", None))
            scheduler = getattr(state, "privacy_drop_management_scheduler", None)
            scheduler_health = (
                scheduler.health() if callable(getattr(scheduler, "health", None)) else {}
            )
            report.update(
                {
                    "key_authority_integrity_valid": key_valid,
                    "registry_integrity_valid": registry_valid,
                    "management_integrity_valid": management_valid,
                    "storage_lock_ready": lock_ready,
                    "rights_intake_ready": rights_ready,
                    "active_brokers": reconciliation.active_brokers,
                    "active_records": reconciliation.active_records,
                    "approved_outcomes": reconciliation.approved_outcomes,
                    "request_executable": bool(
                        reconciliation.active_brokers > 0
                        and reconciliation.active_records > 0
                        and rights_ready
                    ),
                    "request_execution_blocker": (
                        "rights_intake_unavailable"
                        if not rights_ready
                        else "no_active_drop_record_authority"
                        if reconciliation.active_records == 0
                        else "no_active_broker_authority"
                        if reconciliation.active_brokers == 0
                        else ""
                    ),
                    "scheduler": scheduler_health
                    or {"installed": False, "running": False, "healthy": False},
                }
            )
            report["locally_operational"] = bool(
                key_valid
                and registry_valid
                and management_valid
                and lock_ready
                and rights_ready
            )
            if callable(deployment_readiness_probe):
                report["deployment_readiness_verified"] = (
                    deployment_readiness_probe(tenant) is True
                )
                report["locally_operational"] = bool(
                    report["locally_operational"]
                    and report["deployment_readiness_verified"]
                )
            return report
        except Exception:
            return report

    def readiness_probe(tenant_id: str) -> bool:
        return readiness_report(tenant_id).get("locally_operational") is True

    state.privacy_drop_management_enabled_probe = enabled_probe

    if not callable(getattr(state, "privacy_drop_principal_key_authority_factory", None)):

        def key_authority_factory(
            *,
            tenant_id: str,
            request: Request | None = None,
        ) -> DROPPrincipalKeyAuthority:
            return _key_authority_for(
                app,
                tenant_id=tenant_id,
                request=_request_for(app, request),
            )

        state.privacy_drop_principal_key_authority_factory = key_authority_factory

    if not callable(getattr(state, "privacy_drop_authority_proposal_store_factory", None)):

        def proposal_store_factory(
            *,
            tenant_id: str,
            request: Request | None = None,
        ) -> DROPAuthorityProposalStore:
            return _proposal_store_for(
                app,
                tenant_id=tenant_id,
                request=_request_for(app, request),
            )

        state.privacy_drop_authority_proposal_store_factory = proposal_store_factory

    if not callable(getattr(state, "privacy_drop_authority_registry_factory", None)):

        def registry_factory(
            *,
            tenant_id: str,
            request: Request | None = None,
        ) -> DROPAuthorityRegistry:
            return _registry_for(
                app,
                tenant_id=tenant_id,
                request=_request_for(app, request),
                maintenance=False,
            )

        state.privacy_drop_authority_registry_factory = registry_factory

    if not callable(getattr(state, "privacy_drop_record_authority_resolver", None)):

        def authority_resolver(
            *,
            tenant_id: str,
            drop_id: int,
            request_type: str | None,
            template_id: str | None,
            language: str | None,
            request: Request,
        ) -> DROPRecordAuthority:
            registry = state.privacy_drop_authority_registry_factory(
                tenant_id=tenant_id,
                request=_request_for(app, request),
            )
            return registry.resolve_record(
                drop_id=drop_id,
                request_type=request_type,
                template_id=template_id,
                language=language,
            )

        state.privacy_drop_record_authority_resolver = authority_resolver

    if not callable(getattr(state, "privacy_drop_management_store_factory", None)):

        def store_factory(
            *,
            tenant_id: str,
            actor_ref: str,
            request: Request,
        ) -> DROPManagementStore:
            return _store_for(
                app,
                tenant_id=tenant_id,
                actor_ref=actor_ref,
                request=_request_for(app, request),
            )

        state.privacy_drop_management_store_factory = store_factory

    if not callable(getattr(state, "privacy_drop_management_reconciliation_runner", None)):

        def reconciliation_runner(tenant_id: str) -> Mapping[str, object]:
            tenant = canonical_tenant_id(tenant_id)
            registry = state.privacy_drop_authority_registry_factory(
                tenant_id=tenant,
                request=None,
            )
            report = registry.reconcile()
            return {
                "schema": "lightwork.privacy-drop-reconciliation.v1",
                "tenant_id": report.tenant_id,
                "registry_integrity_valid": report.integrity_valid,
                "active_brokers": report.active_brokers,
                "active_records": report.active_records,
                "approved_outcomes": report.approved_outcomes,
                "expired_active_brokers": report.expired_active_brokers,
                "expired_active_records": report.expired_active_records,
                "checked_at": report.checked_at,
                "management_store_opened": False,
                "external_completeness_claimed": False,
                "live_interoperability_verified": False,
                "legal_acceptance_verified": False,
            }

        state.privacy_drop_management_reconciliation_runner = reconciliation_runner

    if not callable(getattr(state, "privacy_drop_management_maintenance_runner", None)):

        def maintenance_runner(
            tenant_id: str,
            *,
            before: float | None = None,
            limit: int = 100,
        ) -> Mapping[str, object]:
            tenant = canonical_tenant_id(tenant_id)
            registry = _registry_for(
                app,
                tenant_id=tenant,
                request=None,
                maintenance=True,
            )
            store = _store_for(
                app,
                tenant_id=tenant,
                actor_ref="drop-maintenance-runtime",
                request=None,
                maintenance=True,
            )
            proposals = _proposal_store_for(
                app,
                tenant_id=tenant,
                request=None,
                maintenance=True,
            )
            requests_purged = store.purge_expired(before=before, limit=limit)
            registry_purged = registry.purge_expired(before=before, limit=limit)
            proposals_purged = proposals.purge_expired(before=before, limit=limit)
            return {
                "schema": "lightwork.privacy-drop-maintenance.v1",
                "tenant_id": tenant,
                "requests_purged": requests_purged,
                "registry_objects_purged": registry_purged,
                "authority_proposals_purged": proposals_purged,
                "external_side_effects": False,
            }

        state.privacy_drop_management_maintenance_runner = maintenance_runner

    if not callable(
        getattr(state, "privacy_drop_management_maintenance_cycle_runner", None)
    ):

        def maintenance_cycle_runner(
            *,
            tenant_supplier: Callable[[], Sequence[str]],
            tenant_limit: int = 1_000,
            purge_limit: int = 100,
            before: float | None = None,
        ) -> object:
            from .privacy_drop_management_scheduler import run_drop_maintenance_cycle

            return run_drop_maintenance_cycle(
                tenant_supplier=tenant_supplier,
                readiness_probe=readiness_probe,
                reconciliation_runner=state.privacy_drop_management_reconciliation_runner,
                maintenance_runner=state.privacy_drop_management_maintenance_runner,
                tenant_limit=tenant_limit,
                purge_limit=purge_limit,
                before=before,
                clock=_clock(app),
            )

        state.privacy_drop_management_maintenance_cycle_runner = maintenance_cycle_runner

    if getattr(state, "privacy_drop_management_scheduler", None) is None:
        configured_scheduler = getattr(
            state,
            "privacy_drop_management_scheduler_settings",
            None,
        )
        scheduler_settings: DROPManagementCompositionSettings | None = None
        try:
            if isinstance(configured_scheduler, Mapping):
                scheduler_settings = _settings(configured_scheduler)
            else:
                from maverick.config import config_source_errors, load_global_config

                if not config_source_errors(include_tenant=False):
                    loaded = load_global_config() or {}
                    if isinstance(loaded, Mapping) and drop_enabled(loaded):
                        scheduler_settings = _settings(loaded)
        except Exception:
            scheduler_settings = None
        if scheduler_settings is not None and scheduler_settings.scheduler_enable:
            from .privacy_drop_management_scheduler import (
                DROPManagedMaintenanceScheduler,
                attach_drop_managed_scheduler,
            )

            tenant_supplier = getattr(
                state,
                "privacy_drop_management_tenant_supplier",
                _default_tenant_supplier,
            )
            if not callable(tenant_supplier):
                raise DROPManagementConfigError("DROP tenant supplier is unavailable")
            scheduler_path_factory = getattr(
                state,
                "privacy_drop_management_scheduler_path_factory",
                None,
            )
            scheduler_path = (
                scheduler_path_factory()
                if callable(scheduler_path_factory)
                else data_dir(
                    "privacy_automation",
                    "privacy-drop-maintenance-scheduler.sqlite3",
                )
            )

            def managed_cycle() -> object:
                return state.privacy_drop_management_maintenance_cycle_runner(
                    tenant_supplier=tenant_supplier,
                )

            runtime = DROPManagedMaintenanceScheduler(
                scheduler_path,
                cycle_runner=managed_cycle,
                enabled=True,
                interval_seconds=scheduler_settings.scheduler_interval_seconds,
                jitter_seconds=scheduler_settings.scheduler_jitter_seconds,
                retry_max_seconds=scheduler_settings.scheduler_retry_max_seconds,
                clock=_clock(app),
            )
            attach_drop_managed_scheduler(app, runtime)

    state.privacy_drop_management_readiness_probe = readiness_probe
    state.privacy_drop_management_readiness_report = readiness_report


__all__ = [
    "DROPManagementCompositionSettings",
    "attach_privacy_drop_management_composition",
    "privacy_drop_management_composition_enabled",
]
