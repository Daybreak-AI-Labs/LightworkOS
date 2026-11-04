"""Production composition for governed Trust Center branding.

Tenant and public-client authority are resolved from server context.  The
deployment may inject ``app.state.trust_center_domain_deployment_authority``;
without that exact DNS/TLS/CDN authority, asset custody remains usable while
custom-domain verification fails closed and readiness reports it unavailable.
"""

from __future__ import annotations

import base64
import binascii
import os
from collections.abc import Mapping
from typing import Any

from fastapi import FastAPI, Request


def _config():
    from maverick.config import config_source_errors, load_config
    from maverick.trust_center_branding import BrandingConfigError, TrustCenterBrandingConfig

    if config_source_errors():
        raise BrandingConfigError("branding_configuration_unavailable")
    value = load_config()
    if not isinstance(value, Mapping):
        raise BrandingConfigError("branding_configuration_unavailable")
    return TrustCenterBrandingConfig.from_mapping(value)


def trust_center_branding_enabled() -> bool:
    try:
        config = _config()
        from maverick.config import load_config

        root = load_config() or {}
        consent = root.get("consent_preferences") or {}
        trust_center = consent.get("trust_center") or {}
        # config.enable is the validated [consent_preferences.trust_center.
        # branding] enable (Settings > All settings); read from the same load.
        branding = trust_center.get("branding") or {}
        return (
            config.enable
            and branding.get("enable") is True
            and consent.get("enable") is True
            and trust_center.get("enable") is True
        )
    except Exception:
        return False


def _key_resolver(tenant_id: str, key_ref: str, key_revision: int) -> bytes:
    from maverick.trust_center_branding import BrandingConfigError

    if (
        not tenant_id
        or key_ref != "env:MAVERICK_TRUST_CENTER_BRAND_ASSET_KEY"
        or isinstance(key_revision, bool)
        or not isinstance(key_revision, int)
        or key_revision < 1
    ):
        raise BrandingConfigError("branding_asset_key_unavailable")
    raw = os.environ.get("MAVERICK_TRUST_CENTER_BRAND_ASSET_KEY", "").strip()
    if not raw:
        raise BrandingConfigError("branding_asset_key_unavailable")
    try:
        if len(raw) == 64:
            value = bytes.fromhex(raw)
        else:
            value = base64.b64decode(raw, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise BrandingConfigError("branding_asset_key_unavailable") from exc
    if len(value) != 32:
        raise BrandingConfigError("branding_asset_key_unavailable")
    return value


def _public_dependencies(request: Request):
    factory = getattr(
        request.app.state,
        "privacy_rights_intake_public_dependencies_factory",
        None,
    )
    if not callable(factory):
        raise RuntimeError("public consent authority unavailable")
    value = factory(request=request)
    if value is None:
        raise RuntimeError("public consent authority unavailable")
    return value


def _publication_resolver(request: Request, tenant_id: str):
    from maverick.trust_center_branding import (
        BrandingConflict,
        BrandingExternalAuthorityError,
        BrandPublicationAuthority,
    )

    dependencies = _public_dependencies(request)

    def resolve(property_id: str, client_credential_id: str) -> BrandPublicationAuthority:
        listed = dependencies.credential_store.list_clients(tenant_id, limit=500)
        if listed.get("truncated") is not False or not isinstance(listed.get("items"), list):
            raise BrandingExternalAuthorityError("branding_public_client_authority_unavailable")
        matches = [
            item
            for item in listed["items"]
            if isinstance(item, Mapping)
            and item.get("credential_id") == client_credential_id
            and item.get("property_id") == property_id
            and item.get("status") == "active"
        ]
        if len(matches) != 1:
            raise BrandingConflict("branding_public_client_not_active")
        client = matches[0]
        if client.get("client_kind") != "browser" or not client.get("target_origin"):
            raise BrandingConflict("branding_browser_client_required")
        publishing = dependencies.publishing_store_for(tenant_id)
        history = publishing.publication_history(tenant_id, property_id, limit=1)
        items = history.get("items")
        if not isinstance(items, list) or len(items) != 1:
            raise BrandingConflict("branding_active_publication_required")
        publication = items[0]
        if (
            publication.get("action") != "publish"
            or publication.get("property_revision") != client.get("property_revision")
            or publication.get("publication_sha256") != client.get("publication_sha256")
            or publication.get("bundle_sha256") != client.get("bundle_sha256")
        ):
            raise BrandingConflict("branding_publication_client_binding_changed")
        return BrandPublicationAuthority(
            tenant_id=tenant_id,
            property_id=property_id,
            property_revision=int(publication["property_revision"]),
            publication_id=str(publication["publication_id"]),
            publication_revision=int(publication["publication_revision"]),
            publication_sha256=str(publication["publication_sha256"]),
            bundle_sha256=str(publication["bundle_sha256"]),
            client_credential_id=str(client["credential_id"]),
            client_revision=int(client["revision"]),
            client_record_sha256=str(client["record_sha256"]),
            public_origin=str(client["target_origin"]),
        ).normalized()

    return resolve


def _valid_domain_authority(value: object) -> object | None:
    required = ("verify", "activate", "reverify", "revoke")
    return value if value is not None and all(callable(getattr(value, name, None)) for name in required) else None


def _store_for(app: FastAPI, **kwargs: Any):
    from maverick.paths import data_dir
    from maverick.trust_center_branding import (
        BrandingConfigError,
        TrustCenterBrandingStore,
    )

    tenant_id = kwargs.get("tenant_id")
    request = kwargs.get("request")
    if not isinstance(tenant_id, str) or not isinstance(request, Request):
        raise BrandingConfigError("branding_runtime_authority_unavailable")
    config = _config()
    return TrustCenterBrandingStore(
        data_dir(
            "consent_preferences",
            "trust-center-branding.sqlite3",
            tenant=tenant_id,
        ),
        tenant_id=tenant_id,
        config=config,
        key_resolver=getattr(app.state, "trust_center_branding_key_resolver", _key_resolver),
        publication_resolver=_publication_resolver(request, tenant_id),
        domain_authority=_valid_domain_authority(
            getattr(app.state, "trust_center_domain_deployment_authority", None)
        ),
    )


def attach_trust_center_branding_composition(app: FastAPI) -> None:
    state = app.state
    if getattr(state, "trust_center_branding_gate", None) is None:
        state.trust_center_branding_gate = trust_center_branding_enabled
    if getattr(state, "trust_center_branding_key_resolver", None) is None:
        state.trust_center_branding_key_resolver = _key_resolver
    if getattr(state, "trust_center_branding_store_factory", None) is None:
        state.trust_center_branding_store_factory = lambda **kwargs: _store_for(app, **kwargs)


__all__ = ["attach_trust_center_branding_composition", "trust_center_branding_enabled"]
