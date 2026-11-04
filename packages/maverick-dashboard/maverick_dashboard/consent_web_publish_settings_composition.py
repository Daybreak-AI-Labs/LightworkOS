"""Production composition for governed website publish settings.

The stock publishing-authority adapter takes a consistent snapshot of the
existing consent-publishing database and validates the current property and
publication through that module's canonical digest verifiers.  The browser
never supplies those pins.  All app-state seams are installed lazily: mounting
this composition does not open tenant configuration or storage.
"""

from __future__ import annotations

import hashlib
import hmac
import sqlite3
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from fastapi import Request
from maverick import consent_web_publish_settings as web
from maverick.paths import canonical_tenant_id, data_dir, tenant_scope


class ConsentWebPublishSettingsCompositionError(web.WebPublishSettingsConfigError):
    """A deployment-owned web publish-settings dependency is unavailable."""


def consent_web_publish_settings_config(
    config: Mapping[str, Any],
) -> web.WebPublishSettingsConfig | None:
    selected = web.WebPublishSettingsConfig.from_mapping(config)
    return selected if selected.enable else None


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
        raise ConsentWebPublishSettingsCompositionError(
            "web_publish_settings_configuration_unavailable"
        ) from exc
    if errors or not isinstance(config, Mapping):
        raise ConsentWebPublishSettingsCompositionError(
            "web_publish_settings_configuration_unavailable"
        )
    return config


def settings_for_tenant(tenant_id: str) -> web.WebPublishSettingsConfig:
    selected = consent_web_publish_settings_config(_load_tenant_config(tenant_id))
    if selected is None:
        raise ConsentWebPublishSettingsCompositionError(
            "web_publish_settings_disabled"
        )
    return selected


def consent_web_publish_settings_enabled(tenant_id: str) -> bool:
    try:
        return (
            consent_web_publish_settings_config(_load_tenant_config(tenant_id))
            is not None
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def _request_for(app: Any, request: object) -> Request:
    if not isinstance(request, Request):
        raise ConsentWebPublishSettingsCompositionError(
            "web_publish_settings_request_authority_unavailable"
        )
    try:
        owner = request.app
    except Exception as exc:
        raise ConsentWebPublishSettingsCompositionError(
            "web_publish_settings_request_authority_unavailable"
        ) from exc
    if owner is not app:
        raise ConsentWebPublishSettingsCompositionError(
            "web_publish_settings_request_authority_unavailable"
        )
    return request


def _principal_ref_from_request(request: Request, tenant_id: str) -> str:
    verified = getattr(request.state, "principal", None)
    subject = getattr(verified, "principal", None) or getattr(verified, "sub", None)
    if not isinstance(subject, str) or not subject.strip() or len(subject) > 512:
        raise web.WebPublishSettingsPermissionDenied(
            "web_publish_settings_principal_unavailable"
        )
    digest = hashlib.sha256(
        f"lightwork.web-publish-settings.identity.v1:{tenant_id}:{subject.strip()}".encode()
    ).hexdigest()
    return f"web-settings-admin-{digest[:40]}"


def _principal_resolver(
    app: Any,
    *,
    tenant_id: str,
    principal_ref: str,
    request: object,
) -> Callable[[], str]:
    selected_request = _request_for(app, request)
    expected = _principal_ref_from_request(selected_request, tenant_id)
    if not isinstance(principal_ref, str) or not hmac.compare_digest(
        principal_ref, expected
    ):
        raise web.WebPublishSettingsPermissionDenied(
            "web_publish_settings_principal_unavailable"
        )

    def resolve() -> str:
        current = _principal_ref_from_request(selected_request, tenant_id)
        if not hmac.compare_digest(current, expected):
            raise web.WebPublishSettingsPermissionDenied(
                "web_publish_settings_principal_changed"
            )
        return expected

    return resolve


def _default_settings_store_path_factory(
    *, tenant_id: str, request: object | None
) -> Path:
    del request
    return data_dir(
        "consent_preferences",
        "consent-web-publish-settings.sqlite3",
        tenant=canonical_tenant_id(tenant_id),
    )


def _default_publishing_store_path_factory(
    *, tenant_id: str, request: object | None
) -> Path:
    del request
    return data_dir(
        "consent_preferences",
        "consent-publishing.sqlite3",
        tenant=canonical_tenant_id(tenant_id),
    )


class ConsentPublishingWebsiteAuthorityResolver:
    """Read-only adapter over the existing consent-publishing authority."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser().resolve()

    def __call__(
        self, tenant_id: str, property_id: str
    ) -> web.WebsitePublishingAuthority:
        tenant = canonical_tenant_id(tenant_id)
        try:
            from maverick import consent_publishing, consent_storage

            if not consent_storage.store_exists(self.path):
                raise ConsentWebPublishSettingsCompositionError(
                    "web_publish_settings_publishing_authority_unavailable"
                )
            store = consent_publishing.ConsentPublishingStore(self.path)
            with store._snapshot() as connection:  # noqa: SLF001 - authority adapter
                property_row = store._property_row(  # noqa: SLF001
                    connection, tenant, property_id
                )
                property_result = store._property_result(  # noqa: SLF001
                    property_row, tenant
                )
                head = connection.execute(
                    "SELECT current_publication_id,current_revision "
                    "FROM consent_publication_heads "
                    "WHERE tenant=? AND property_id=?",
                    (tenant, property_id),
                ).fetchone()
                if head is None:
                    raise ConsentWebPublishSettingsCompositionError(
                        "web_publish_settings_publication_missing"
                    )
                publication_row = connection.execute(
                    "SELECT * FROM consent_publications "
                    "WHERE tenant=? AND property_id=? AND publication_id=?",
                    (tenant, property_id, str(head["current_publication_id"])),
                ).fetchone()
                if publication_row is None:
                    raise ConsentWebPublishSettingsCompositionError(
                        "web_publish_settings_publication_missing"
                    )
                publication_result = store._publication_result(  # noqa: SLF001
                    publication_row, tenant
                )
                if int(head["current_revision"]) != int(
                    publication_result["publication_revision"]
                ):
                    raise ConsentWebPublishSettingsCompositionError(
                        "web_publish_settings_publication_head_invalid"
                    )
        except (KeyboardInterrupt, SystemExit):
            raise
        except web.WebPublishSettingsError:
            raise
        except Exception as exc:
            raise ConsentWebPublishSettingsCompositionError(
                "web_publish_settings_publishing_authority_unavailable"
            ) from exc
        return web.WebsitePublishingAuthority(
            tenant_id=tenant,
            property_id=str(property_result["property_id"]),
            property_kind=str(property_result["kind"]),
            property_revision=int(property_result["revision"]),
            property_sha256=str(property_result["record_sha256"]),
            publication_id=str(publication_result["publication_id"]),
            publication_revision=int(publication_result["publication_revision"]),
            publication_sha256=str(publication_result["publication_sha256"]),
            publication_bundle_sha256=str(publication_result["bundle_sha256"]),
            publication_action=str(publication_result["action"]),
            publication_property_revision=int(publication_result["property_revision"]),
        )


def _path_from_factory(
    app: Any,
    state_name: str,
    *,
    tenant_id: str,
    request: object | None,
) -> Path:
    factory = getattr(app.state, state_name, None)
    if not callable(factory):
        raise ConsentWebPublishSettingsCompositionError(
            "web_publish_settings_store_path_unavailable"
        )
    try:
        selected = Path(
            factory(tenant_id=tenant_id, request=request)
        ).expanduser().resolve()
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise ConsentWebPublishSettingsCompositionError(
            "web_publish_settings_store_path_unavailable"
        ) from exc
    return selected


def _publishing_resolver(
    app: Any, *, tenant_id: str, request: object | None
) -> web.PublishingAuthorityResolver:
    factory = getattr(
        app.state,
        "consent_web_publish_settings_publishing_authority_resolver_factory",
        None,
    )
    if not callable(factory):
        raise ConsentWebPublishSettingsCompositionError(
            "web_publish_settings_publishing_authority_unavailable"
        )
    try:
        resolver = factory(tenant_id=tenant_id, request=request)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise ConsentWebPublishSettingsCompositionError(
            "web_publish_settings_publishing_authority_unavailable"
        ) from exc
    if not callable(resolver):
        raise ConsentWebPublishSettingsCompositionError(
            "web_publish_settings_publishing_authority_unavailable"
        )
    return resolver


def _build_store(
    app: Any,
    *,
    tenant_id: str,
    principal_ref: str,
    request: object,
) -> web.WebPublishSettingsStore:
    tenant = canonical_tenant_id(tenant_id)
    selected_request = _request_for(app, request)
    settings = settings_for_tenant(tenant)
    principal = _principal_resolver(
        app,
        tenant_id=tenant,
        principal_ref=principal_ref,
        request=selected_request,
    )
    path = _path_from_factory(
        app,
        "consent_web_publish_settings_store_path_factory",
        tenant_id=tenant,
        request=selected_request,
    )
    resolver = _publishing_resolver(
        app, tenant_id=tenant, request=selected_request
    )

    def guarded_authority(
        resolved_tenant: str, property_id: str
    ) -> web.WebsitePublishingAuthority:
        current = settings_for_tenant(tenant)
        if current != settings:
            raise ConsentWebPublishSettingsCompositionError(
                "web_publish_settings_configuration_changed"
            )
        if canonical_tenant_id(resolved_tenant) != tenant:
            raise ConsentWebPublishSettingsCompositionError(
                "web_publish_settings_publishing_authority_mismatch"
            )
        return resolver(tenant, property_id)

    return web.WebPublishSettingsStore(
        path,
        tenant_id=tenant,
        publishing_authority_resolver=guarded_authority,
        principal_resolver=principal,
        retention_seconds=settings.retention_seconds,
    )


def _publishing_database_ready(path: Path) -> bool:
    from maverick import consent_storage

    try:
        connection = consent_storage.read_only_connection(path)
    except (OSError, sqlite3.DatabaseError, consent_storage.ConsentStorageError):
        return False
    if connection is None:
        return False
    try:
        with connection:
            rows = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN "
                "('publishing_meta','publishing_properties','consent_publications',"
                "'consent_publication_heads')"
            ).fetchall()
            if {str(row[0]) for row in rows} != {
                "publishing_meta",
                "publishing_properties",
                "consent_publications",
                "consent_publication_heads",
            }:
                return False
            version = connection.execute(
                "SELECT value FROM publishing_meta WHERE key='schema_version'"
            ).fetchone()
            quick = connection.execute("PRAGMA quick_check").fetchone()
    except (OSError, sqlite3.DatabaseError):
        return False
    finally:
        connection.close()
    return (
        version is not None
        and str(version[0]) == "2"
        and quick is not None
        and str(quick[0]).lower() == "ok"
    )


def attach_consent_web_publish_settings_composition(  # noqa: C901 - closed seam install
    app: Any,
) -> None:
    """Install lazy production seams; shared app wiring calls this explicitly."""

    state = getattr(app, "state", None)
    if state is None:
        raise TypeError("app must expose state")
    marker = "consent_web_publish_settings_composition_installed"
    if getattr(state, marker, False):
        return

    deployment_enabled = getattr(
        state, "consent_web_publish_settings_enabled_probe", None
    )
    deployment_readiness = getattr(
        state, "consent_web_publish_settings_readiness_probe", None
    )
    for selected, label in (
        (deployment_enabled, "enabled probe"),
        (deployment_readiness, "readiness probe"),
    ):
        if selected is not None and not callable(selected):
            raise TypeError(f"web publish-settings {label} must be callable")

    if getattr(state, "consent_web_publish_settings_store_path_factory", None) is None:
        state.consent_web_publish_settings_store_path_factory = (
            _default_settings_store_path_factory
        )
    elif not callable(state.consent_web_publish_settings_store_path_factory):
        raise TypeError("web publish-settings store path factory must be callable")

    if getattr(state, "consent_web_publish_settings_publishing_store_path_factory", None) is None:
        state.consent_web_publish_settings_publishing_store_path_factory = (
            _default_publishing_store_path_factory
        )
    elif not callable(
        state.consent_web_publish_settings_publishing_store_path_factory
    ):
        raise TypeError("consent-publishing store path factory must be callable")

    if getattr(
        state,
        "consent_web_publish_settings_publishing_authority_resolver_factory",
        None,
    ) is None:

        def resolver_factory(
            *, tenant_id: str, request: object | None
        ) -> ConsentPublishingWebsiteAuthorityResolver:
            path = _path_from_factory(
                app,
                "consent_web_publish_settings_publishing_store_path_factory",
                tenant_id=canonical_tenant_id(tenant_id),
                request=request,
            )
            return ConsentPublishingWebsiteAuthorityResolver(path)

        state.consent_web_publish_settings_publishing_authority_resolver_factory = (
            resolver_factory
        )
    elif not callable(
        state.consent_web_publish_settings_publishing_authority_resolver_factory
    ):
        raise TypeError("publishing-authority resolver factory must be callable")

    if getattr(state, "consent_web_publish_settings_service_factory", None) is None:

        def service_factory(
            *, tenant_id: str, principal_ref: str, request: object
        ) -> web.WebPublishSettingsStore:
            return _build_store(
                app,
                tenant_id=tenant_id,
                principal_ref=principal_ref,
                request=request,
            )

        state.consent_web_publish_settings_service_factory = service_factory
    elif not callable(state.consent_web_publish_settings_service_factory):
        raise TypeError("web publish-settings service factory must be callable")

    def enabled_probe(tenant_id: str) -> bool:
        try:
            if consent_web_publish_settings_enabled(tenant_id) is not True:
                return False
            if callable(deployment_enabled):
                return deployment_enabled(tenant_id) is True
            return True
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            return False

    def readiness_probe(tenant_id: str) -> bool:
        try:
            tenant = canonical_tenant_id(tenant_id)
            if enabled_probe(tenant) is not True:
                return False
            settings_for_tenant(tenant)
            publishing_path = _path_from_factory(
                app,
                "consent_web_publish_settings_publishing_store_path_factory",
                tenant_id=tenant,
                request=None,
            )
            if _publishing_database_ready(publishing_path) is not True:
                return False
            if callable(deployment_readiness):
                return deployment_readiness(tenant) is True
            return True
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            return False

    def public_projection(
        tenant_id: str,
        property_id: str,
        request: object | None = None,
    ) -> dict[str, object]:
        tenant = canonical_tenant_id(tenant_id)
        if enabled_probe(tenant) is not True:
            return {
                "schema": web.PUBLIC_PROJECTION_SCHEMA,
                "enabled": False,
                "ready": False,
                "reason": "feature_disabled",
                "property_id": property_id,
                "browser_property_acceptance_verified": False,
            }
        try:
            settings = settings_for_tenant(tenant)
            path = _path_from_factory(
                app,
                "consent_web_publish_settings_store_path_factory",
                tenant_id=tenant,
                request=request,
            )
            resolver = _publishing_resolver(
                app, tenant_id=tenant, request=request
            )
            store = web.WebPublishSettingsStore(
                path,
                tenant_id=tenant,
                publishing_authority_resolver=resolver,
                principal_resolver=lambda: "public-projection-runtime",
                retention_seconds=settings.retention_seconds,
            )
            return store.public_projection(property_id=property_id)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            return {
                "schema": web.PUBLIC_PROJECTION_SCHEMA,
                "enabled": True,
                "ready": False,
                "reason": "runtime_not_ready",
                "property_id": property_id,
                "browser_property_acceptance_verified": False,
            }

    state.consent_web_publish_settings_enabled_probe = enabled_probe
    state.consent_web_publish_settings_readiness_probe = readiness_probe
    state.consent_web_publish_settings_public_projection = public_projection
    setattr(state, marker, True)


install_consent_web_publish_settings_composition = (
    attach_consent_web_publish_settings_composition
)


__all__ = [
    "ConsentPublishingWebsiteAuthorityResolver",
    "ConsentWebPublishSettingsCompositionError",
    "attach_consent_web_publish_settings_composition",
    "consent_web_publish_settings_config",
    "consent_web_publish_settings_enabled",
    "install_consent_web_publish_settings_composition",
    "settings_for_tenant",
]
