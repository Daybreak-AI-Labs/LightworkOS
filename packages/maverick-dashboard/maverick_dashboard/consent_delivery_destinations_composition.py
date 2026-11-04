"""Tenant-lazy production composition for named consent destinations.

Importing or attaching this composition resolves no tenant, secret, provider,
or store.  A dispatch request supplies the exact active tenant and delivery
authority.  The resulting router is pinned to a digest of that tenant's closed
configuration and revalidates the digest before every provider request.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from maverick import consent_delivery
from maverick.consent_delivery_destinations import (
    STOCK_RECONCILIATION_PROVIDERS,
    ConsentDestinationConfigError,
    ConsentDestinationOperationStore,
    ConsentDestinationReconciliationAuthority,
    ConsentDestinationRegistry,
    ConsentDestinationRouterTransport,
    DeploymentConsentDestinationCredentialOwner,
    PinnedConsentDestinationHTTPTransport,
    StockConsentDestinationReconciliationAuthority,
    build_consent_destination_registry,
)
from maverick.paths import canonical_tenant_id, data_dir, tenant_scope


class ConsentDestinationCompositionError(RuntimeError):
    """The deployment composition is absent or changed."""


def _canonical_digest(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ConsentDestinationCompositionError(
            "consent destination configuration is not finite JSON"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _tenant_config(tenant_id: str) -> Mapping[str, Any]:
    tenant = canonical_tenant_id(tenant_id)
    from maverick import config

    try:
        with tenant_scope(tenant=tenant):
            if config.config_source_errors():
                raise ConsentDestinationCompositionError(
                    "consent destination configuration is invalid"
                )
            loaded = config.load_config()
    except ConsentDestinationCompositionError:
        raise
    except Exception as exc:
        raise ConsentDestinationCompositionError(
            "consent destination configuration is unavailable"
        ) from exc
    if not isinstance(loaded, Mapping):
        raise ConsentDestinationCompositionError(
            "consent destination configuration is invalid"
        )
    return loaded


def _snapshot_material(config: Mapping[str, Any]) -> Mapping[str, object]:
    consent = config.get("consent_preferences")
    delivery = consent.get("delivery") if isinstance(consent, Mapping) else None
    destinations = (
        delivery.get("destinations") if isinstance(delivery, Mapping) else None
    )
    return {
        "schema": "lightwork.consent-destination-composition-config.v1",
        "consent_enable": (
            consent.get("enable") if isinstance(consent, Mapping) else None
        ),
        "delivery_enable": (
            delivery.get("enable") if isinstance(delivery, Mapping) else None
        ),
        "destinations": (
            dict(destinations) if isinstance(destinations, Mapping) else None
        ),
    }


def _config_snapshot(tenant_id: str) -> tuple[Mapping[str, Any], str]:
    config = _tenant_config(tenant_id)
    return config, _canonical_digest(_snapshot_material(config))


def _reference_present(name: str) -> bool:
    """Check deployment placement without opening or returning a secret value."""

    if name in os.environ:
        return True
    raw_dir = os.environ.get("MAVERICK_SECRETS_DIR")
    if not raw_dir:
        return False
    if not name or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for character in name):
        return False
    base = Path(raw_dir).expanduser()
    return (base / name).is_file() or (base / name.lower()).is_file()


def _credential_owner() -> DeploymentConsentDestinationCredentialOwner:
    from maverick.secret_provider import get_secret

    return DeploymentConsentDestinationCredentialOwner(
        resolver=get_secret,
        reference_present=_reference_present,
    )


def _optional_component(app: Any, name: str, tenant_id: str, protocol: str) -> Any:
    factory = getattr(app.state, name, None)
    if factory is None:
        return None
    if not callable(factory):
        raise ConsentDestinationCompositionError(f"{protocol} factory is invalid")
    try:
        component = factory(tenant_id=tenant_id)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise ConsentDestinationCompositionError(
            f"{protocol} factory failed"
        ) from exc
    return component


class _TenantPinnedDestinationTransport(ConsentDestinationRouterTransport):
    def __init__(
        self,
        app: Any,
        tenant_id: str,
        config_sha256: str,
        registry: ConsentDestinationRegistry,
        operation_store: ConsentDestinationOperationStore,
        *,
        destination_authority: Callable[[str, str], Mapping[str, Any]],
        credential_owner: DeploymentConsentDestinationCredentialOwner,
        http_transport: object | None,
        reconciliation_authority: ConsentDestinationReconciliationAuthority | None,
    ) -> None:
        self._app = app
        self._tenant_id = tenant_id
        self._config_sha256 = config_sha256
        super().__init__(
            registry,
            operation_store,
            destination_authority=destination_authority,
            credential_owner=credential_owner,
            http_transport=http_transport,
            reconciliation_authority=reconciliation_authority,
        )

    def _same_config(self) -> None:
        _, current = _config_snapshot(self._tenant_id)
        if current != self._config_sha256:
            raise ConsentDestinationCompositionError(
                "consent destination tenant configuration changed"
            )

    def post(self, request, *, timeout_seconds, max_response_bytes):
        self._same_config()
        return super().post(
            request,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )

    def reconcile(self, *, destination_id, message_sha256, request_sha256):
        self._same_config()
        return super().reconcile(
            destination_id=destination_id,
            message_sha256=message_sha256,
            request_sha256=request_sha256,
        )


@dataclass(frozen=True)
class TenantConsentDestinationRuntime:
    tenant_id: str
    config_sha256: str
    registry: ConsentDestinationRegistry
    operation_store: ConsentDestinationOperationStore
    transport: ConsentDestinationRouterTransport


def build_tenant_consent_destination_runtime(
    app: Any,
    *,
    tenant_id: str,
    delivery_store: consent_delivery.ConsentDeliveryStore,
    operation_path: str | Path | None = None,
) -> TenantConsentDestinationRuntime:
    """Build one tenant-exact runtime without opening a provider session."""

    tenant = canonical_tenant_id(tenant_id)
    if not isinstance(delivery_store, consent_delivery.ConsentDeliveryStore):
        raise ConsentDestinationCompositionError(
            "consent delivery authority is invalid"
        )
    config, config_sha256 = _config_snapshot(tenant)
    consent = config.get("consent_preferences")
    delivery = consent.get("delivery") if isinstance(consent, Mapping) else None
    if not (
        isinstance(consent, Mapping)
        and consent.get("enable") is True
        and isinstance(delivery, Mapping)
        and delivery.get("enable") is True
    ):
        raise ConsentDestinationCompositionError("consent delivery is disabled")
    try:
        registry = build_consent_destination_registry(config, tenant)
    except ConsentDestinationConfigError as exc:
        raise ConsentDestinationCompositionError(
            "named consent destination configuration is invalid"
        ) from exc
    if not registry.enabled or not registry.status()["configured"]:
        raise ConsentDestinationCompositionError(
            "named consent destinations are disabled or empty"
        )
    selected_path = (
        Path(operation_path)
        if operation_path is not None
        else data_dir(
            "consent_preferences",
            "consent-destination-operations.sqlite3",
            tenant=tenant,
        )
    )
    with tenant_scope(tenant=tenant):
        operations = ConsentDestinationOperationStore(selected_path)
    http_transport = _optional_component(
        app,
        "consent_destination_http_transport_factory",
        tenant,
        "consent destination HTTP transport",
    )
    if http_transport is not None and not callable(
        getattr(http_transport, "request", None)
    ):
        raise ConsentDestinationCompositionError(
            "consent destination HTTP transport is invalid"
        )
    provider_http = http_transport or PinnedConsentDestinationHTTPTransport()
    credential_owner = _credential_owner()
    reconciler = _optional_component(
        app,
        "consent_destination_reconciliation_authority_factory",
        tenant,
        "consent destination reconciliation authority",
    )
    if reconciler is not None and not callable(getattr(reconciler, "inspect", None)):
        raise ConsentDestinationCompositionError(
            "consent destination reconciliation authority is invalid"
        )
    if reconciler is None:
        reconciler = StockConsentDestinationReconciliationAuthority(
            registry,
            credential_owner=credential_owner,
            http_transport=provider_http,
        )
    transport = _TenantPinnedDestinationTransport(
        app,
        tenant,
        config_sha256,
        registry,
        operations,
        destination_authority=delivery_store.destination,
        credential_owner=credential_owner,
        http_transport=provider_http,
        reconciliation_authority=reconciler,
    )
    return TenantConsentDestinationRuntime(
        tenant_id=tenant,
        config_sha256=config_sha256,
        registry=registry,
        operation_store=operations,
        transport=transport,
    )


def consent_destination_readiness(app: Any, tenant_id: str) -> Mapping[str, object]:
    """Side-effect-light readiness: no DB creation, secret read, or provider call."""

    tenant = canonical_tenant_id(tenant_id)
    try:
        config, config_sha256 = _config_snapshot(tenant)
        registry = build_consent_destination_registry(config, tenant)
        status = registry.status(credential_reference_present=_reference_present)
    except Exception:
        return {
            "schema": "lightwork.consent-destination-composition-readiness.v1",
            "tenant_id": tenant,
            "enabled": False,
            "configured": False,
            "ready": False,
            "credential_values_resolved": False,
            "provider_session_opened": False,
            "live_provider_acceptance_verified": False,
        }
    runtime_factory_installed = callable(
        getattr(app.state, "consent_destination_runtime_factory", None)
    )
    reconciliation_factory_installed = callable(
        getattr(
            app.state,
            "consent_destination_reconciliation_authority_factory",
            None,
        )
    )
    providers = tuple(str(provider) for provider in status["providers"])
    reconciliation_supported = {
        provider: (
            True
            if reconciliation_factory_installed
            else provider in STOCK_RECONCILIATION_PROVIDERS
        )
        for provider in providers
    }
    reconciliation_complete = bool(providers) and all(
        reconciliation_supported.values()
    )
    return {
        **dict(status),
        "schema": "lightwork.consent-destination-composition-readiness.v1",
        "ready": (
            bool(status["ready"])
            and runtime_factory_installed
            and reconciliation_complete
        ),
        "config_sha256": config_sha256,
        "transport_factory_installed": runtime_factory_installed,
        "reconciliation_authority_factory_installed": (
            reconciliation_factory_installed
        ),
        "stock_reconciliation_authority_installed": True,
        "reconciliation_supported": reconciliation_supported,
        "reconciliation_complete": reconciliation_complete,
        "operation_store_opened": False,
        "credential_values_resolved": False,
        "provider_session_opened": False,
        "live_provider_acceptance_verified": False,
    }


def _install_callable(state: Any, name: str, value: Callable[..., object]) -> None:
    existing = getattr(state, name, None)
    if existing is None:
        setattr(state, name, value)
    elif not callable(existing):
        raise TypeError(f"{name} must be callable")


def attach_consent_delivery_destinations(app: Any) -> None:
    """Attach tenant-lazy factories without loading config or credentials."""

    state = getattr(app, "state", None)
    if state is None:
        raise TypeError("app must expose state")

    def runtime_factory(
        *,
        tenant_id: str,
        delivery_store: consent_delivery.ConsentDeliveryStore,
    ) -> TenantConsentDestinationRuntime:
        return build_tenant_consent_destination_runtime(
            app,
            tenant_id=tenant_id,
            delivery_store=delivery_store,
        )

    _install_callable(state, "consent_destination_runtime_factory", runtime_factory)
    _install_callable(
        state,
        "consent_destination_readiness_probe",
        lambda tenant_id: consent_destination_readiness(app, tenant_id),
    )


__all__ = [
    "ConsentDestinationCompositionError",
    "TenantConsentDestinationRuntime",
    "attach_consent_delivery_destinations",
    "build_tenant_consent_destination_runtime",
    "consent_destination_readiness",
]
