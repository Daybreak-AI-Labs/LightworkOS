"""Stock production composition for the governed local document vault.

The composition binds the encrypted tenant vault to both existing consumers:
administration document access and incident attachment metadata.  Every
factory is request-bound, tenant-bound, permission checked, and lazy.  No
external object-store, locator, or relying-workflow claim is made.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from fastapi import Request
from maverick import governed_document_vault as vault
from maverick.paths import canonical_tenant_id, data_dir, tenant_scope

from .auth import caller_principal, has_global_permission


class GovernedDocumentVaultCompositionError(vault.VaultConfigError):
    pass


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
        raise GovernedDocumentVaultCompositionError(
            "document_vault_configuration_unavailable"
        ) from exc
    if errors or not isinstance(config, Mapping):
        raise GovernedDocumentVaultCompositionError(
            "document_vault_configuration_unavailable"
        )
    return config


def settings_for_tenant(tenant_id: str) -> vault.GovernedDocumentVaultConfig:
    settings = vault.GovernedDocumentVaultConfig.from_mapping(
        _load_tenant_config(tenant_id)
    )
    if not settings.enable:
        raise GovernedDocumentVaultCompositionError(
            "governed_document_vault_disabled"
        )
    return settings


def governed_document_vault_enabled(tenant_id: str) -> bool:
    try:
        settings = vault.GovernedDocumentVaultConfig.from_mapping(
            _load_tenant_config(tenant_id)
        )
        return settings.enable is True
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def governed_document_vault_custody_ready(tenant_id: str) -> bool:
    """Verify the exact existing stock vault through non-committing I/O."""

    try:
        tenant = canonical_tenant_id(tenant_id)
        settings = settings_for_tenant(tenant)
        path = data_dir(
            "governed-document-vault",
            "vault.sqlite3",
            tenant=tenant,
        )
        result = vault.GovernedDocumentVault.operational_probe(
            path,
            tenant_id=tenant,
            config=settings,
        )
        return result.get("ok") is True
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def _request_for(app: Any, request: object) -> Request:
    if not isinstance(request, Request):
        raise GovernedDocumentVaultCompositionError(
            "document_vault_request_authority_unavailable"
        )
    try:
        owner = request.app
    except Exception as exc:
        raise GovernedDocumentVaultCompositionError(
            "document_vault_request_authority_unavailable"
        ) from exc
    if owner is not app:
        raise GovernedDocumentVaultCompositionError(
            "document_vault_request_authority_unavailable"
        )
    return request


def _subject(request: Request) -> str:
    subject = caller_principal(request) or "authorized-local-operator"
    if (
        not isinstance(subject, str)
        or not subject.strip()
        or len(subject) > 512
    ):
        raise vault.VaultPermissionDenied("document_vault_principal_invalid")
    return subject.strip()


def document_access_principal_ref(request: Request, tenant_id: str) -> str:
    tenant = canonical_tenant_id(tenant_id)
    digest = hashlib.sha256(
        f"lightwork.document-access.api-principal.v1:{tenant}:{_subject(request)}".encode()
    ).hexdigest()
    return f"document-access-api.{digest[:40]}"


def incident_attachment_principal_ref(request: Request, tenant_id: str) -> str:
    tenant = canonical_tenant_id(tenant_id)
    digest = hashlib.sha256(
        f"lightwork.incident-attachment.identity.v1:{tenant}:{_subject(request)}".encode()
    ).hexdigest()
    return f"incident-principal-{digest[:32]}"


def vault_actor_ref(request: Request, tenant_id: str) -> str:
    tenant = canonical_tenant_id(tenant_id)
    digest = hashlib.sha256(
        f"lightwork.governed-document-vault.actor.v1:{tenant}:{_subject(request)}".encode()
    ).hexdigest()
    return f"document-vault-actor.{digest[:40]}"


def _admitted_principal(request: Request, tenant_id: str, principal_ref: object) -> str:
    if not isinstance(principal_ref, str):
        raise vault.VaultPermissionDenied("document_vault_principal_invalid")
    admitted = (
        document_access_principal_ref(request, tenant_id),
        incident_attachment_principal_ref(request, tenant_id),
    )
    if not any(hmac.compare_digest(principal_ref, expected) for expected in admitted):
        raise vault.VaultPermissionDenied("document_vault_principal_invalid")
    return principal_ref


def governed_document_vault_store(
    tenant_id: str,
    *,
    store_path: str | Path | None = None,
    clock: Callable[[], float] = time.time,
) -> vault.GovernedDocumentVault:
    tenant = canonical_tenant_id(tenant_id)
    settings = settings_for_tenant(tenant)
    selected_path = (
        Path(store_path)
        if store_path is not None
        else data_dir("governed-document-vault", "vault.sqlite3", tenant=tenant)
    )
    return vault.GovernedDocumentVault(
        selected_path,
        tenant_id=tenant,
        config=settings,
        clock=clock,
    )


def _clock_for(app: Any) -> Callable[[], float]:
    clock = getattr(app.state, "governed_document_vault_clock", time.time)
    if not callable(clock):
        raise GovernedDocumentVaultCompositionError(
            "document_vault_clock_unavailable"
        )
    return clock


def store_factory(
    app: Any,
    *,
    tenant_id: str,
    request: object,
) -> vault.GovernedDocumentVault:
    selected_request = _request_for(app, request)
    tenant = canonical_tenant_id(tenant_id)
    if not has_global_permission(selected_request, "view"):
        raise vault.VaultPermissionDenied("document_vault_permission_denied")
    return governed_document_vault_store(tenant, clock=_clock_for(app))


def document_resolver_factory(
    app: Any,
    tenant_id: str,
    request: object,
) -> Callable[[str, str, str], object]:
    selected_request = _request_for(app, request)
    tenant = canonical_tenant_id(tenant_id)
    if not has_global_permission(selected_request, "view"):
        raise vault.VaultPermissionDenied("document_vault_permission_denied")
    store = governed_document_vault_store(tenant, clock=_clock_for(app))

    def resolve(
        requested_tenant: str,
        principal_ref: str,
        document_ref: str,
    ) -> object:
        current = _request_for(app, selected_request)
        if not has_global_permission(current, "view"):
            raise vault.VaultPermissionDenied("document_vault_permission_denied")
        if canonical_tenant_id(requested_tenant) != tenant:
            raise vault.VaultNotFound("document_vault_document_not_found")
        admitted = _admitted_principal(current, tenant, principal_ref)
        return store.resolve_authority(tenant, admitted, document_ref)

    return resolve


def delivery_grant_issuer_factory(
    app: Any,
    tenant_id: str,
    request: object,
) -> Callable[[object], object]:
    selected_request = _request_for(app, request)
    tenant = canonical_tenant_id(tenant_id)
    if not has_global_permission(selected_request, "operate"):
        raise vault.VaultPermissionDenied("document_vault_permission_denied")
    store = governed_document_vault_store(tenant, clock=_clock_for(app))

    def issue(claim: object) -> object:
        from maverick import administration_document_access as access

        current = _request_for(app, selected_request)
        if not has_global_permission(current, "operate"):
            raise vault.VaultPermissionDenied("document_vault_permission_denied")
        if type(claim) is not access.DeliveryClaim:
            raise vault.VaultValidationError("document_vault_delivery_claim_invalid")
        _admitted_principal(current, tenant, claim.principal_ref)
        return store.issue_delivery_grant(claim)

    return issue


def administration_document_access_readiness(
    app: Any,
    tenant_id: str,
    request: object,
) -> Mapping[str, Any]:
    tenant = canonical_tenant_id(tenant_id)
    selected_request = _request_for(app, request)
    feature_enabled = governed_document_vault_enabled(tenant)
    try:
        from maverick import administration_document_access as access

        access_enabled = access.enabled(_load_tenant_config(tenant))
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        access_enabled = False
    dependencies = {
        "governed_document_vault_enabled": feature_enabled,
        "document_resolver_factory_installed": callable(
            getattr(
                app.state,
                "administration_document_access_document_resolver_factory",
                None,
            )
        ),
        "delivery_grant_issuer_factory_installed": callable(
            getattr(
                app.state,
                "administration_document_access_delivery_grant_issuer_factory",
                None,
            )
        ),
        "authenticated_request_authority": isinstance(selected_request, Request),
    }
    configured = access_enabled and all(dependencies.values())
    return {
        "enabled": access_enabled,
        "configured": configured,
        "ready": configured,
        "dependencies": dependencies,
        "status_probe_opened_store": False,
        "status_probe_invoked_external_dependency": False,
        "stock_local_encrypted_custody": feature_enabled,
        "live_relying_workflow_verified": False,
        "external_object_store_custody_verified": False,
    }


def _install_default(state: Any, name: str, value: object) -> None:
    current = getattr(state, name, None)
    if current is not None and not callable(current):
        raise TypeError(f"{name} must be callable")
    if current is None:
        setattr(state, name, value)


def attach_governed_document_vault_composition(app: Any) -> None:
    """Install the stock local resolver, issuer, delivery and readiness seams."""

    state = getattr(app, "state", None)
    if state is None:
        raise TypeError("app must expose state")
    from .administration_document_access_composition import (
        attach_administration_document_access_composition,
    )

    attach_administration_document_access_composition(app)
    _install_default(
        state,
        "governed_document_vault_enabled_probe",
        governed_document_vault_enabled,
    )
    _install_default(
        state,
        "governed_document_vault_custody_probe",
        governed_document_vault_custody_ready,
    )
    _install_default(
        state,
        "governed_document_vault_store_factory",
        lambda tenant_id, request: store_factory(
            app, tenant_id=tenant_id, request=request
        ),
    )
    def stock_document_resolver_factory(
        tenant_id: str,
        request: object,
    ) -> Callable[[str, str, str], object]:
        return document_resolver_factory(app, tenant_id, request)

    _install_default(
        state,
        "administration_document_access_document_resolver_factory",
        stock_document_resolver_factory,
    )
    if (
        getattr(
            state,
            "administration_document_access_document_resolver_factory",
            None,
        )
        is stock_document_resolver_factory
    ):
        # Incident readiness must distinguish this default-off stock resolver
        # from a deployment-provided external resolver with its own authority.
        state.governed_document_vault_stock_document_resolver_factory = (
            stock_document_resolver_factory
        )
        _install_default(
            state,
            "administration_document_access_document_custody_probe",
            governed_document_vault_custody_ready,
        )
    _install_default(
        state,
        "administration_document_access_delivery_grant_issuer_factory",
        lambda tenant_id, request: delivery_grant_issuer_factory(
            app, tenant_id, request
        ),
    )
    existing = getattr(
        state, "administration_document_access_readiness_probe", None
    )
    # Replace only the stock composition's intentionally-false placeholder;
    # preserve a deployment-injected readiness authority.
    if existing is None or getattr(existing, "__module__", "") == (
        "maverick_dashboard.administration_document_access_composition"
    ):
        state.administration_document_access_readiness_probe = (
            lambda tenant_id, request: administration_document_access_readiness(
                app, tenant_id, request
            )
        )


__all__ = [
    "GovernedDocumentVaultCompositionError",
    "administration_document_access_readiness",
    "attach_governed_document_vault_composition",
    "delivery_grant_issuer_factory",
    "document_access_principal_ref",
    "document_resolver_factory",
    "governed_document_vault_enabled",
    "governed_document_vault_custody_ready",
    "governed_document_vault_store",
    "incident_attachment_principal_ref",
    "settings_for_tenant",
    "store_factory",
    "vault_actor_ref",
]
