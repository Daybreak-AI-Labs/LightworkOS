"""Stock production composition for consent custom data-element indexes.

The composition opens the tenant's existing consent profile-data SQLite file
only when an authorized API operation begins.  Index HMAC material is supplied
by deployment custody, never configuration or the browser.  The built-in
custody adapter reads one named environment secret and derives tenant/version
keys with a domain-separated HMAC.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import HTTPException, Request
from maverick import consent_custom_index as indexes
from maverick.file_lock import cross_process_lock
from maverick.paths import canonical_tenant_id, data_dir, tenant_scope

from ._shared import authenticated_subject

_SECRET_REF_RE = re.compile(r"[A-Z][A-Z0-9_]{2,127}\Z")
_CONFIG_KEYS = frozenset(
    {
        "enable",
        "key_secret_ref",
        "key_version",
        "max_indexes",
        "max_page_size",
        "retention_seconds",
    }
)
_DEFAULT_KEY_SECRET_REF = "MAVERICK_CONSENT_CUSTOM_INDEX_KEY"
_DEFAULT_KEY_VERSION = 1
_DEFAULT_MAX_INDEXES = 256
_DEFAULT_MAX_PAGE_SIZE = 100
_DEFAULT_RETENTION_SECONDS = 31_536_000


class ConsentCustomIndexCompositionError(indexes.ConsentCustomIndexConfigError):
    """A deployment-owned custom-index dependency is unavailable."""


@dataclass(frozen=True, slots=True)
class ConsentCustomIndexSettings:
    key_secret_ref: str
    key_version: int
    max_indexes: int
    max_page_size: int
    retention_seconds: int


def _integer(value: object, label: str, lower: int, upper: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        raise ConsentCustomIndexCompositionError(f"{label} is outside its bound")
    return value


def consent_custom_index_settings(
    config: Mapping[str, Any],
) -> ConsentCustomIndexSettings | None:
    """Validate the closed nested contract; return ``None`` only when off."""

    if not isinstance(config, Mapping):
        raise ConsentCustomIndexCompositionError(
            "consent custom-index configuration is unavailable"
        )
    consent = config.get("consent_preferences")
    if not isinstance(consent, Mapping):
        return None
    profile = consent.get("profile_data")
    if not isinstance(profile, Mapping):
        return None
    section = profile.get("custom_index")
    if section is None:
        return None
    if not isinstance(section, Mapping):
        raise ConsentCustomIndexCompositionError(
            "consent_preferences.profile_data.custom_index must be a table"
        )
    unknown = sorted(str(key) for key in section if key not in _CONFIG_KEYS)
    if unknown:
        raise ConsentCustomIndexCompositionError(
            "consent custom-index configuration contains an unknown key"
        )
    enabled = section.get("enable", False)
    if type(enabled) is not bool:
        raise ConsentCustomIndexCompositionError(
            "consent custom-index enable gate must be true or false"
        )
    if enabled is not True:
        return None
    if consent.get("enable") is not True or profile.get("enable") is not True:
        raise ConsentCustomIndexCompositionError(
            "consent custom indexes require consent and profile-data gates"
        )
    key_secret_ref = section.get("key_secret_ref", _DEFAULT_KEY_SECRET_REF)
    if (
        not isinstance(key_secret_ref, str)
        or _SECRET_REF_RE.fullmatch(key_secret_ref) is None
    ):
        raise ConsentCustomIndexCompositionError(
            "consent custom-index key_secret_ref is invalid"
        )
    return ConsentCustomIndexSettings(
        key_secret_ref=key_secret_ref,
        key_version=_integer(
            section.get("key_version", _DEFAULT_KEY_VERSION),
            "consent custom-index key_version",
            1,
            1_000_000,
        ),
        max_indexes=_integer(
            section.get("max_indexes", _DEFAULT_MAX_INDEXES),
            "consent custom-index max_indexes",
            1,
            10_000,
        ),
        max_page_size=_integer(
            section.get("max_page_size", _DEFAULT_MAX_PAGE_SIZE),
            "consent custom-index max_page_size",
            1,
            500,
        ),
        retention_seconds=_integer(
            section.get("retention_seconds", _DEFAULT_RETENTION_SECONDS),
            "consent custom-index retention_seconds",
            86_400,
            157_680_000,
        ),
    )


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
        raise ConsentCustomIndexCompositionError(
            "consent custom-index configuration is unavailable"
        ) from exc
    if errors or not isinstance(config, Mapping):
        raise ConsentCustomIndexCompositionError(
            "consent custom-index configuration is unavailable"
        )
    return config


def settings_for_tenant(tenant_id: str) -> ConsentCustomIndexSettings:
    settings = consent_custom_index_settings(_load_tenant_config(tenant_id))
    if settings is None:
        raise ConsentCustomIndexCompositionError(
            "consent custom indexes are disabled"
        )
    return settings


def consent_custom_index_enabled(tenant_id: str) -> bool:
    try:
        return consent_custom_index_settings(_load_tenant_config(tenant_id)) is not None
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def _secret_material(value: object) -> bytes:
    if isinstance(value, bytes):
        material = value
    elif isinstance(value, str):
        if value.startswith("base64:"):
            try:
                material = base64.b64decode(value[7:].encode("ascii"), validate=True)
            except (UnicodeError, binascii.Error) as exc:
                raise ConsentCustomIndexCompositionError(
                    "consent custom-index key custody is unavailable"
                ) from exc
        elif value.startswith("hex:"):
            try:
                material = bytes.fromhex(value[4:])
            except ValueError as exc:
                raise ConsentCustomIndexCompositionError(
                    "consent custom-index key custody is unavailable"
                ) from exc
        else:
            material = value.encode("utf-8")
    else:
        raise ConsentCustomIndexCompositionError(
            "consent custom-index key custody is unavailable"
        )
    if not 32 <= len(material) <= 4_096:
        raise ConsentCustomIndexCompositionError(
            "consent custom-index key custody is unavailable"
        )
    return material


def _environment_key_resolver(
    *, tenant_id: str, key_version: int, key_secret_ref: str
) -> bytes:
    """Resolve an environment-held root and derive a tenant/version HMAC key."""

    tenant = canonical_tenant_id(tenant_id)
    version = _integer(key_version, "consent custom-index key_version", 1, 1_000_000)
    if _SECRET_REF_RE.fullmatch(key_secret_ref) is None:
        raise ConsentCustomIndexCompositionError(
            "consent custom-index key custody is unavailable"
        )
    raw = os.environ.get(key_secret_ref)
    if raw is None:
        raise ConsentCustomIndexCompositionError(
            "consent custom-index key custody is unavailable"
        )
    root = _secret_material(raw)
    context = (
        "lightwork.consent-custom-index.hmac.v1\0"
        f"{tenant}\0{version}"
    ).encode()
    return hmac.new(root, context, hashlib.sha256).digest()


def _request_for(app: Any, request: object) -> Request:
    if not isinstance(request, Request):
        raise ConsentCustomIndexCompositionError(
            "consent custom-index request authority is unavailable"
        )
    try:
        owner = request.app
    except Exception as exc:
        raise ConsentCustomIndexCompositionError(
            "consent custom-index request authority is unavailable"
        ) from exc
    if owner is not app:
        raise ConsentCustomIndexCompositionError(
            "consent custom-index request authority is unavailable"
        )
    return request


def _principal_ref_from_request(request: Request, tenant_id: str) -> str:
    # The API's own subject resolution, so the local single-user operator and
    # a static dashboard token resolve to the same reference on both sides.
    try:
        subject = authenticated_subject(
            request, error_detail="authenticated principal authority is unavailable",
        )
    except HTTPException as exc:
        raise indexes.ConsentCustomIndexPermissionDenied(
            "authenticated principal authority is unavailable"
        ) from exc
    tenant = canonical_tenant_id(tenant_id)
    digest = hashlib.sha256(
        f"lightwork.consent-custom-index.identity.v1:{tenant}:{subject}".encode()
    ).hexdigest()
    return f"consent-index-admin-{digest[:40]}"


def _principal_resolver(
    app: Any,
    *,
    tenant_id: str,
    principal_ref: str,
    request: object,
) -> Callable[[], str]:
    tenant = canonical_tenant_id(tenant_id)
    selected_request = _request_for(app, request)
    expected = _principal_ref_from_request(selected_request, tenant)
    if not isinstance(principal_ref, str) or not hmac.compare_digest(
        principal_ref, expected
    ):
        raise indexes.ConsentCustomIndexPermissionDenied(
            "authenticated principal authority is unavailable"
        )

    def resolve() -> str:
        current = _principal_ref_from_request(selected_request, tenant)
        if not hmac.compare_digest(current, expected):
            raise indexes.ConsentCustomIndexPermissionDenied(
                "authenticated principal authority changed"
            )
        return expected

    return resolve


def _default_store_path_factory(*, tenant_id: str, request: object) -> Path:
    del request
    tenant = canonical_tenant_id(tenant_id)
    return data_dir(
        "consent_preferences",
        "consent-profile-data.sqlite3",
        tenant=tenant,
    )


def _selected_key_resolver(app: Any) -> Callable[..., bytes]:
    resolver = getattr(app.state, "consent_custom_index_key_resolver", None)
    if not callable(resolver):
        raise ConsentCustomIndexCompositionError(
            "consent custom-index key custody is unavailable"
        )
    return resolver


def _key_for(
    app: Any,
    *,
    tenant_id: str,
    key_version: int,
    settings: ConsentCustomIndexSettings,
) -> bytes:
    tenant = canonical_tenant_id(tenant_id)
    if (
        isinstance(key_version, bool)
        or not isinstance(key_version, int)
        or not 1 <= key_version <= settings.key_version
    ):
        raise ConsentCustomIndexCompositionError(
            "consent custom-index key version is unavailable"
        )
    try:
        selected = _selected_key_resolver(app)(
            tenant_id=tenant,
            key_version=key_version,
            key_secret_ref=settings.key_secret_ref,
        )
    except indexes.ConsentCustomIndexError:
        raise
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise ConsentCustomIndexCompositionError(
            "consent custom-index key custody is unavailable"
        ) from exc
    if not isinstance(selected, bytes) or len(selected) < 32:
        raise ConsentCustomIndexCompositionError(
            "consent custom-index key custody is unavailable"
        )
    return selected


def _store_path(app: Any, *, tenant_id: str, request: object) -> Path:
    factory = getattr(app.state, "consent_custom_index_store_path_factory", None)
    if not callable(factory):
        raise ConsentCustomIndexCompositionError(
            "consent profile-data storage path is unavailable"
        )
    try:
        selected = factory(tenant_id=tenant_id, request=request)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise ConsentCustomIndexCompositionError(
            "consent profile-data storage path is unavailable"
        ) from exc
    if not isinstance(selected, (str, Path)):
        raise ConsentCustomIndexCompositionError(
            "consent profile-data storage path is unavailable"
        )
    return Path(selected)


def _source_database_ready(path: Path) -> bool:
    from maverick import consent_storage

    try:
        connection = consent_storage.read_only_connection(path)
        if connection is None:
            return False
        try:
            names = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name IN ('catalogs','profile_values')"
                ).fetchall()
            }
        finally:
            connection.close()
    except (OSError, sqlite3.Error, ValueError, consent_storage.ConsentStorageError):
        return False
    return names == {"catalogs", "profile_values"}


class GovernedConsentCustomIndexRuntime:
    """Server-owned limits and key/retention selection around the core store."""

    def __init__(
        self,
        store: indexes.ConsentCustomIndexStore,
        *,
        tenant_id: str,
        settings: ConsentCustomIndexSettings,
        settings_resolver: Callable[[], ConsentCustomIndexSettings],
    ) -> None:
        self._store = store
        self.tenant_id = canonical_tenant_id(tenant_id)
        self._settings = settings
        self._settings_resolver = settings_resolver
        self.path = store.path
        self.current_key_version = settings.key_version
        self.max_indexes = settings.max_indexes
        self.max_page_size = settings.max_page_size

    def _admit(self, tenant_id: str) -> str:
        tenant = canonical_tenant_id(tenant_id)
        if tenant != self.tenant_id or self._settings_resolver() != self._settings:
            raise ConsentCustomIndexCompositionError(
                "consent custom-index runtime authority changed"
            )
        return tenant

    def create_index(
        self,
        tenant_id: str,
        *,
        index_id: str,
        element_name: str,
        idempotency_key: str,
    ) -> object:
        tenant = self._admit(tenant_id)
        with cross_process_lock(self.path, strict=True):
            existing = self._store.list_indexes(tenant)
            existing_ids = {item.index_id for item in existing}
            if len(existing) >= self.max_indexes and index_id not in existing_ids:
                raise indexes.ConsentCustomIndexConflict(
                    "tenant custom-index quota is exhausted"
                )
            return self._store.create_index(
                tenant,
                index_id=index_id,
                element_name=element_name,
                key_version=self.current_key_version,
                retention_seconds=self._settings.retention_seconds,
                idempotency_key=idempotency_key,
            )

    def get_index(self, tenant_id: str, index_id: str) -> object:
        return self._store.get_index(self._admit(tenant_id), index_id)

    def list_indexes_page(
        self,
        tenant_id: str,
        *,
        limit: int,
        cursor: str | None = None,
    ) -> tuple[tuple[object, ...], str | None]:
        tenant = self._admit(tenant_id)
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise indexes.ConsentCustomIndexValidationError("list limit is invalid")
        applied = min(limit, self.max_page_size)
        records = self._store.list_indexes(tenant)
        selected = [item for item in records if cursor is None or item.index_id > cursor]
        visible = tuple(selected[:applied])
        next_cursor = (
            visible[-1].index_id if len(selected) > applied and visible else None
        )
        return visible, next_cursor

    def build_index(self, tenant_id: str, index_id: str, **kwargs: object) -> object:
        return self._store.build_index(
            self._admit(tenant_id), index_id, **kwargs  # type: ignore[arg-type]
        )

    def search(
        self,
        tenant_id: str,
        index_id: str,
        *,
        value: object,
        limit: int = 100,
        cursor: str | None = None,
    ) -> object:
        tenant = self._admit(tenant_id)
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise indexes.ConsentCustomIndexValidationError("search limit is invalid")
        return self._store.search(
            tenant,
            index_id,
            value=value,
            limit=min(limit, self.max_page_size),
            cursor=cursor,
        )

    def revoke_index(self, tenant_id: str, index_id: str, **kwargs: object) -> object:
        return self._store.revoke_index(
            self._admit(tenant_id), index_id, **kwargs  # type: ignore[arg-type]
        )

    def audit_history(self, tenant_id: str, *, limit: int = 100) -> object:
        tenant = self._admit(tenant_id)
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise indexes.ConsentCustomIndexValidationError("history limit is invalid")
        return self._store.audit_history(
            tenant,
            limit=min(limit, self.max_page_size),
        )

    def verify_integrity(self, tenant_id: str) -> object:
        return self._store.verify_integrity(self._admit(tenant_id))


def _build_runtime(
    app: Any,
    *,
    tenant_id: str,
    principal_ref: str,
    request: object,
) -> GovernedConsentCustomIndexRuntime:
    tenant = canonical_tenant_id(tenant_id)
    selected_request = _request_for(app, request)
    settings = settings_for_tenant(tenant)
    principal = _principal_resolver(
        app,
        tenant_id=tenant,
        principal_ref=principal_ref,
        request=selected_request,
    )
    path = _store_path(
        app,
        tenant_id=tenant,
        request=selected_request,
    )

    def current_settings() -> ConsentCustomIndexSettings:
        return settings_for_tenant(tenant)

    def config_gate() -> None:
        if current_settings() != settings:
            raise ConsentCustomIndexCompositionError(
                "consent custom-index configuration changed during admission"
            )

    def key_resolver(resolved_tenant: str, version: int) -> bytes:
        if canonical_tenant_id(resolved_tenant) != tenant:
            raise ConsentCustomIndexCompositionError(
                "consent custom-index key custody is unavailable"
            )
        return _key_for(
            app,
            tenant_id=tenant,
            key_version=version,
            settings=settings,
        )

    store = indexes.ConsentCustomIndexStore(
        path,
        key_resolver=key_resolver,
        config_gate=config_gate,
        principal_resolver=principal,
    )
    return GovernedConsentCustomIndexRuntime(
        store,
        tenant_id=tenant,
        settings=settings,
        settings_resolver=current_settings,
    )


def install_consent_custom_index_composition(  # noqa: C901 - closed seam install
    app: Any,
) -> None:
    """Install lazy production seams without opening configuration or storage."""

    state = getattr(app, "state", None)
    if state is None:
        raise TypeError("app must expose state")
    marker = "consent_custom_index_composition_installed"
    if getattr(state, marker, False):
        return

    deployment_enabled_probe = getattr(
        state, "consent_custom_index_enabled_probe", None
    )
    deployment_readiness_probe = getattr(
        state, "consent_custom_index_readiness_probe", None
    )
    for value, label in (
        (deployment_enabled_probe, "enabled probe"),
        (deployment_readiness_probe, "readiness probe"),
    ):
        if value is not None and not callable(value):
            raise TypeError(f"consent custom-index {label} must be callable")

    if getattr(state, "consent_custom_index_key_resolver", None) is None:
        state.consent_custom_index_key_resolver = _environment_key_resolver
    elif not callable(state.consent_custom_index_key_resolver):
        raise TypeError("consent custom-index key resolver must be callable")

    if getattr(state, "consent_custom_index_store_path_factory", None) is None:
        state.consent_custom_index_store_path_factory = _default_store_path_factory
    elif not callable(state.consent_custom_index_store_path_factory):
        raise TypeError("consent custom-index store path factory must be callable")

    if getattr(state, "consent_custom_index_store_factory", None) is None:

        def store_factory(
            *, tenant_id: str, principal_ref: str, request: object
        ) -> GovernedConsentCustomIndexRuntime:
            return _build_runtime(
                app,
                tenant_id=tenant_id,
                principal_ref=principal_ref,
                request=request,
            )

        state.consent_custom_index_store_factory = store_factory
    elif not callable(state.consent_custom_index_store_factory):
        raise TypeError("consent custom-index store factory must be callable")

    def enabled_probe(tenant_id: str) -> bool:
        try:
            if consent_custom_index_enabled(tenant_id) is not True:
                return False
            if callable(deployment_enabled_probe):
                return deployment_enabled_probe(tenant_id) is True
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
            settings = settings_for_tenant(tenant)
            _key_for(
                app,
                tenant_id=tenant,
                key_version=settings.key_version,
                settings=settings,
            )
            path = _store_path(app, tenant_id=tenant, request=None)
            if _source_database_ready(path) is not True:
                return False
            if callable(deployment_readiness_probe):
                return deployment_readiness_probe(tenant) is True
            return True
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            return False

    state.consent_custom_index_enabled_probe = enabled_probe
    state.consent_custom_index_readiness_probe = readiness_probe
    setattr(state, marker, True)


__all__ = [
    "ConsentCustomIndexCompositionError",
    "ConsentCustomIndexSettings",
    "GovernedConsentCustomIndexRuntime",
    "consent_custom_index_enabled",
    "consent_custom_index_settings",
    "install_consent_custom_index_composition",
    "settings_for_tenant",
]
