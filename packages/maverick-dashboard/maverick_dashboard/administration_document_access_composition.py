"""Lazy server composition for governed administration document access.

Attaching this module installs factories only.  Disabled status checks do not
open SQLite or invoke document/object-store dependencies.  A deployment must
inject both a tenant-scoped authoritative document resolver factory and an
opaque delivery-grant issuer factory; this package intentionally ships neither
external object-store custody nor a live relying workflow.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from maverick import administration_document_access as access
from maverick.paths import canonical_tenant_id, data_dir, tenant_scope


def _load_tenant_config(tenant_id: str) -> Mapping[str, Any]:
    tenant = canonical_tenant_id(tenant_id)
    try:
        from maverick import config as config_module

        with tenant_scope(tenant=tenant):
            config = config_module.load_config()
            source_errors = config_module.config_source_errors(include_tenant=True)
    except (KeyboardInterrupt, SystemExit):
        raise
    except access.DocumentAccessError:
        raise
    except Exception as exc:
        raise access.DocumentAccessConfigError("document_access_configuration_unavailable") from exc
    if source_errors:
        raise access.DocumentAccessConfigError("document_access_configuration_source_invalid")
    if not isinstance(config, Mapping):
        raise access.DocumentAccessConfigError("document_access_configuration_unavailable")
    return config


def administration_document_access_enabled(tenant_id: str) -> bool:
    """Side-effect-free tenant feature probe used by disabled status."""

    try:
        return access.enabled(_load_tenant_config(tenant_id))
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def _injected_callable(
    state: Any,
    *,
    attribute: str,
    tenant_id: str,
    request: Any,
    unavailable_code: str,
) -> Callable[..., Any]:
    factory = getattr(state, attribute, None)
    if not callable(factory):
        raise access.DocumentAccessConfigError(unavailable_code)
    try:
        dependency = factory(tenant_id, request)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise access.DocumentAccessConfigError(unavailable_code) from exc
    if not callable(dependency):
        raise access.DocumentAccessConfigError(unavailable_code)
    return dependency


def build_administration_document_access_service(
    *,
    tenant_id: str,
    principal_ref: str,
    document_resolver: access.DocumentAuthorityResolver,
    delivery_grant_issuer: access.DeliveryGrantIssuer,
    config: Mapping[str, Any],
    store_path: str | Path | None = None,
    clock: Callable[[], float] = time.time,
) -> access.DocumentAccessService:
    """Build one admitted tenant/principal runtime from injected authorities."""

    tenant = canonical_tenant_id(tenant_id)
    settings = access.require_enabled(config)
    if not isinstance(principal_ref, str) or not principal_ref or len(principal_ref) > 512:
        raise access.DocumentAccessConfigError("document_access_principal_unavailable")
    selected_path = (
        Path(store_path)
        if store_path is not None
        else data_dir(
            "administration-document-access",
            "control-plane.sqlite3",
            tenant=tenant,
        )
    )

    def principal_resolver() -> str:
        return principal_ref

    store = access.DocumentAccessStore(selected_path, tenant_id=tenant, clock=clock)
    return access.DocumentAccessService(
        store=store,
        config=settings,
        principal_resolver=principal_resolver,
        document_resolver=document_resolver,
        delivery_grant_issuer=delivery_grant_issuer,
        clock=clock,
    )


def attach_administration_document_access_composition(app: Any) -> None:
    """Install lazy probes/factories without opening a store or resolving a doc."""

    state = getattr(app, "state", None)
    if state is None:
        raise TypeError("app must expose state")

    existing_probe = getattr(
        state,
        "administration_document_access_enabled_probe",
        None,
    )
    if existing_probe is not None and not callable(existing_probe):
        raise TypeError("document-access enabled probe must be callable")
    if existing_probe is None:
        state.administration_document_access_enabled_probe = administration_document_access_enabled

    existing_readiness = getattr(
        state,
        "administration_document_access_readiness_probe",
        None,
    )
    if existing_readiness is not None and not callable(existing_readiness):
        raise TypeError("document-access readiness probe must be callable")
    if existing_readiness is None:

        def readiness_probe(tenant_id: str, request: Any) -> Mapping[str, Any]:
            tenant = canonical_tenant_id(tenant_id)
            config = _load_tenant_config(tenant)
            feature_enabled = access.enabled(config)
            resolver_factory = getattr(
                state,
                "administration_document_access_document_resolver_factory",
                None,
            )
            issuer_factory = getattr(
                state,
                "administration_document_access_delivery_grant_issuer_factory",
                None,
            )
            dependencies = {
                "document_resolver_factory_installed": callable(resolver_factory),
                "delivery_grant_issuer_factory_installed": callable(issuer_factory),
            }
            return {
                "enabled": feature_enabled,
                "configured": feature_enabled and all(dependencies.values()),
                "ready": False,
                "dependencies": dependencies,
                "status_probe_opened_store": False,
                "status_probe_invoked_external_dependency": False,
                "live_relying_workflow_verified": False,
                "external_object_store_custody_verified": False,
            }

        state.administration_document_access_readiness_probe = readiness_probe

    existing_factory = getattr(
        state,
        "administration_document_access_service_factory",
        None,
    )
    if existing_factory is not None and not callable(existing_factory):
        raise TypeError("document-access service factory must be callable")
    if existing_factory is not None:
        return

    def service_factory(
        tenant_id: str,
        principal_ref: str,
        request: Any,
    ) -> access.DocumentAccessService:
        tenant = canonical_tenant_id(tenant_id)
        config = _load_tenant_config(tenant)
        # Admission is checked before data_dir, SQLite, or injected dependency
        # factories are touched.
        access.require_enabled(config)
        resolver = _injected_callable(
            state,
            attribute="administration_document_access_document_resolver_factory",
            tenant_id=tenant,
            request=request,
            unavailable_code="document_access_document_resolver_unavailable",
        )
        issuer = _injected_callable(
            state,
            attribute="administration_document_access_delivery_grant_issuer_factory",
            tenant_id=tenant,
            request=request,
            unavailable_code="document_access_delivery_issuer_unavailable",
        )
        return build_administration_document_access_service(
            tenant_id=tenant,
            principal_ref=principal_ref,
            document_resolver=resolver,
            delivery_grant_issuer=issuer,
            config=config,
        )

    state.administration_document_access_service_factory = service_factory


__all__ = [
    "administration_document_access_enabled",
    "attach_administration_document_access_composition",
    "build_administration_document_access_service",
]
