"""Stock composition for governed privacy/security incident attachments.

The composition is lazy and default-off.  It resolves incidents directly from
their existing tenant-scoped privacy/security stores, obtains document facts
from the administration document-access authority, and builds a metadata-only
store for the authenticated principal.  It performs no object-store I/O and
does not issue document delivery grants.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from fastapi import HTTPException, Request
from maverick import incident_attachment_metadata as attachments
from maverick.paths import canonical_tenant_id, tenant_scope

from ._shared import authenticated_subject
from .auth import has_global_permission

_CONFIG_KEYS = frozenset(
    {
        "enable",
        "retention_seconds",
        "attachment_ttl_seconds",
        "max_attachments",
        "allowed_media_types",
    }
)
_MIN_RETENTION_SECONDS = 3_600
_MAX_RETENTION_SECONDS = 10 * 365 * 24 * 3_600
_MIN_TTL_SECONDS = 60
_MAX_TTL_SECONDS = 365 * 24 * 3_600
_MAX_ATTACHMENTS = 1_000_000
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")


class IncidentAttachmentCompositionError(attachments.IncidentAttachmentConfigError):
    """A deployment-owned attachment dependency is unavailable."""


class IncidentAttachmentSettings:
    """Validated immutable settings for one tenant."""

    __slots__ = (
        "allowed_media_types",
        "attachment_ttl_seconds",
        "max_attachments",
        "retention_seconds",
    )

    def __init__(
        self,
        *,
        retention_seconds: int,
        attachment_ttl_seconds: int,
        max_attachments: int,
        allowed_media_types: Sequence[str],
    ) -> None:
        self.retention_seconds = retention_seconds
        self.attachment_ttl_seconds = attachment_ttl_seconds
        self.max_attachments = max_attachments
        self.allowed_media_types = tuple(allowed_media_types)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, IncidentAttachmentSettings) and all(
            getattr(self, field) == getattr(other, field)
            for field in self.__slots__
        )


def _integer(value: object, label: str, lower: int, upper: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        raise IncidentAttachmentCompositionError(f"{label} is outside its bound")
    return value


def incident_attachment_settings(
    config: Mapping[str, Any],
) -> IncidentAttachmentSettings | None:
    """Return settings, with ``None`` reserved for a literal disabled gate."""

    if not isinstance(config, Mapping):
        raise IncidentAttachmentCompositionError(
            "incident attachment configuration is unavailable"
        )
    section = config.get("incident_attachment_metadata")
    if section is None:
        return None
    if not isinstance(section, Mapping):
        raise IncidentAttachmentCompositionError(
            "incident_attachment_metadata must be a table"
        )
    unknown = sorted(str(key) for key in section if key not in _CONFIG_KEYS)
    if unknown:
        raise IncidentAttachmentCompositionError(
            "incident_attachment_metadata contains an unknown key"
        )
    gate = section.get("enable", False)
    if type(gate) is not bool:
        raise IncidentAttachmentCompositionError(
            "incident_attachment_metadata.enable must be true or false"
        )
    if gate is not True:
        return None
    raw_media = section.get(
        "allowed_media_types", list(sorted(attachments.DEFAULT_MEDIA_TYPES))
    )
    if not isinstance(raw_media, list) or not raw_media or len(raw_media) > 128:
        raise IncidentAttachmentCompositionError(
            "incident_attachment_metadata.allowed_media_types must be a non-empty array"
        )
    normalized_media: list[str] = []
    for value in raw_media:
        if not isinstance(value, str):
            raise IncidentAttachmentCompositionError(
                "incident attachment media type allowlist is invalid"
            )
        media_type = value.strip().lower()
        if media_type not in attachments.DEFAULT_MEDIA_TYPES:
            raise IncidentAttachmentCompositionError(
                "incident attachment media type is outside the product allowlist"
            )
        normalized_media.append(media_type)
    if len(set(normalized_media)) != len(normalized_media):
        raise IncidentAttachmentCompositionError(
            "incident attachment media type allowlist contains duplicates"
        )
    return IncidentAttachmentSettings(
        retention_seconds=_integer(
            section.get("retention_seconds", 365 * 24 * 3_600),
            "incident_attachment_metadata.retention_seconds",
            _MIN_RETENTION_SECONDS,
            _MAX_RETENTION_SECONDS,
        ),
        attachment_ttl_seconds=_integer(
            section.get("attachment_ttl_seconds", 7 * 24 * 3_600),
            "incident_attachment_metadata.attachment_ttl_seconds",
            _MIN_TTL_SECONDS,
            _MAX_TTL_SECONDS,
        ),
        max_attachments=_integer(
            section.get("max_attachments", 100_000),
            "incident_attachment_metadata.max_attachments",
            1,
            _MAX_ATTACHMENTS,
        ),
        allowed_media_types=tuple(sorted(normalized_media)),
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
        raise IncidentAttachmentCompositionError(
            "incident attachment configuration is unavailable"
        ) from exc
    if errors or not isinstance(config, Mapping):
        raise IncidentAttachmentCompositionError(
            "incident attachment configuration is unavailable"
        )
    return config


def settings_for_tenant(tenant_id: str) -> IncidentAttachmentSettings:
    settings = incident_attachment_settings(_load_tenant_config(tenant_id))
    if settings is None:
        raise IncidentAttachmentCompositionError("incident attachment metadata is disabled")
    return settings


def incident_attachment_metadata_enabled(tenant_id: str) -> bool:
    try:
        return incident_attachment_settings(_load_tenant_config(tenant_id)) is not None
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def principal_ref_from_request(request: Request, tenant_id: str) -> str:
    # The API's own subject resolution, so the local single-user operator and
    # a static dashboard token resolve to the same reference on both sides.
    try:
        subject = authenticated_subject(
            request, error_detail="authenticated principal authority is unavailable",
        )
    except HTTPException as exc:
        raise attachments.IncidentAttachmentPermissionDenied(
            "authenticated principal authority is unavailable"
        ) from exc
    return attachments.principal_ref_for_subject(tenant_id, subject)


def _canonical_sha256(value: object) -> str:
    try:
        payload = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise attachments.IncidentAttachmentConflict(
            "incident authority is unavailable"
        ) from exc
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def incident_record_sha256(record: Mapping[str, Any]) -> str:
    """Digest the exact persisted incident document, excluding audit delivery state."""

    if not isinstance(record, Mapping):
        raise attachments.IncidentAttachmentConflict("incident authority is unavailable")
    logical = {key: value for key, value in record.items() if key != "_audit_pending"}
    return _canonical_sha256(logical)


def _load_incident_record(
    tenant_id: str, incident_kind: str, incident_id: str
) -> Mapping[str, Any] | None:
    tenant = canonical_tenant_id(tenant_id)
    with tenant_scope(tenant=tenant):
        if incident_kind == "privacy":
            from maverick import privacy_ops

            value = privacy_ops._INCIDENT.load(incident_id)  # noqa: SLF001
        elif incident_kind == "security":
            from maverick import security_ops

            value = security_ops._INCIDENTS.load(incident_id)  # noqa: SLF001
        else:
            raise attachments.IncidentAttachmentValidationError(
                "incident_kind is invalid"
            )
    return value if isinstance(value, Mapping) else None


def _request_for(app: Any, request: object) -> Request:
    if not isinstance(request, Request):
        raise IncidentAttachmentCompositionError(
            "incident attachment request authority is unavailable"
        )
    try:
        owner = request.app
    except Exception as exc:
        raise IncidentAttachmentCompositionError(
            "incident attachment request authority is unavailable"
        ) from exc
    if owner is not app:
        raise IncidentAttachmentCompositionError(
            "incident attachment request authority is unavailable"
        )
    return request


def _incident_resolver_factory(
    app: Any,
    *,
    tenant_id: str,
    principal_ref: str,
    request: object,
) -> Callable[[str, str, str, str], attachments.IncidentAuthority]:
    tenant = canonical_tenant_id(tenant_id)
    selected_request = _request_for(app, request)
    expected_principal = principal_ref_from_request(selected_request, tenant)
    if not isinstance(principal_ref, str) or not hmac_compare(
        principal_ref, expected_principal
    ):
        raise attachments.IncidentAttachmentPermissionDenied(
            "authenticated principal authority is unavailable"
        )

    def resolve(
        requested_tenant: str,
        requested_principal: str,
        incident_kind: str,
        incident_id: str,
    ) -> attachments.IncidentAuthority:
        current_principal = principal_ref_from_request(selected_request, tenant)
        if (
            canonical_tenant_id(requested_tenant) != tenant
            or not hmac_compare(requested_principal, expected_principal)
            or not hmac_compare(current_principal, expected_principal)
        ):
            raise attachments.IncidentAttachmentNotFound(
                "incident authority was not found"
            )
        first = _load_incident_record(tenant, incident_kind, incident_id)
        second = _load_incident_record(tenant, incident_kind, incident_id)
        if first is None or second is None:
            raise attachments.IncidentAttachmentNotFound(
                "incident authority was not found"
            )
        left_sha = incident_record_sha256(first)
        right_sha = incident_record_sha256(second)
        left_revision = first.get("revision")
        right_revision = second.get("revision")
        if (
            isinstance(left_revision, bool)
            or not isinstance(left_revision, int)
            or left_revision < 1
            or left_revision != right_revision
            or not hmac_compare(left_sha, right_sha)
            or first.get("id") != incident_id
            or second.get("id") != incident_id
        ):
            raise attachments.IncidentAttachmentConflict(
                "incident authority changed during resolution"
            )
        return attachments.issue_incident_authority(
            tenant_id=tenant,
            principal_ref=expected_principal,
            incident_kind=incident_kind,
            incident_id=incident_id,
            incident_revision=left_revision,
            incident_sha256=left_sha,
        )

    return resolve


def hmac_compare(left: object, right: object) -> bool:
    """Bounded comparison without retaining caller identity in diagnostics."""

    import hmac

    return isinstance(left, str) and isinstance(right, str) and hmac.compare_digest(left, right)


def _document_resolver_factory(
    app: Any,
    *,
    tenant_id: str,
    request: object,
) -> Callable[[str, str, str], object]:
    tenant = canonical_tenant_id(tenant_id)
    selected_request = _request_for(app, request)
    factory = getattr(
        app.state,
        "administration_document_access_document_resolver_factory",
        None,
    )
    if not callable(factory):
        raise IncidentAttachmentCompositionError(
            "governed document authority is unavailable"
        )
    try:
        resolver = factory(tenant, selected_request)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise IncidentAttachmentCompositionError(
            "governed document authority is unavailable"
        ) from exc
    if not callable(resolver):
        raise IncidentAttachmentCompositionError(
            "governed document authority is unavailable"
        )
    return resolver


def _clock_for(app: Any) -> Callable[[], float]:
    clock = getattr(app.state, "incident_attachment_metadata_clock", time.time)
    if not callable(clock):
        raise IncidentAttachmentCompositionError(
            "incident attachment clock is unavailable"
        )
    return clock


def incident_attachment_metadata_store_factory(
    app: Any,
    *,
    tenant_id: str,
    principal_ref: str,
    request: object,
) -> attachments.IncidentAttachmentStore:
    tenant = canonical_tenant_id(tenant_id)
    selected_request = _request_for(app, request)
    settings = settings_for_tenant(tenant)
    expected_principal = principal_ref_from_request(selected_request, tenant)
    if not hmac_compare(principal_ref, expected_principal):
        raise attachments.IncidentAttachmentPermissionDenied(
            "authenticated principal authority is unavailable"
        )

    def principal_resolver() -> str:
        current = principal_ref_from_request(selected_request, tenant)
        if not hmac_compare(current, expected_principal):
            raise attachments.IncidentAttachmentPermissionDenied(
                "authenticated principal authority changed"
            )
        return expected_principal

    def maintenance_authorizer() -> bool:
        _request_for(app, selected_request)
        return has_global_permission(selected_request, "admin") is True

    return attachments.IncidentAttachmentStore(
        tenant_id=tenant,
        principal_ref=expected_principal,
        incident_authority_resolver=_incident_resolver_factory(
            app,
            tenant_id=tenant,
            principal_ref=expected_principal,
            request=selected_request,
        ),
        document_authority_resolver=_document_resolver_factory(
            app,
            tenant_id=tenant,
            request=selected_request,
        ),
        principal_resolver=principal_resolver,
        maintenance_authorizer=maintenance_authorizer,
        config_gate=lambda: settings_for_tenant(tenant),
        retention_seconds=settings.retention_seconds,
        attachment_ttl_seconds=settings.attachment_ttl_seconds,
        allowed_media_types=settings.allowed_media_types,
        max_attachments=settings.max_attachments,
        clock=_clock_for(app),
    )


def _stock_metadata_custody_ready(tenant_id: str) -> bool:
    """Exercise the exact governed-record backend without domain mutations."""

    from maverick.file_lock import (
        atomic_create_bytes,
        prepare_private_directory,
        private_path_is_restricted,
    )
    from maverick.governed_records import GovernedRecordStore

    tenant = canonical_tenant_id(tenant_id)
    with tenant_scope(tenant=tenant):
        records = GovernedRecordStore(
            "incident_attachment_metadata",
            "IAT",
            "incident_attachment_metadata",
            event_kind="incident_attachment_metadata_changed",
        )
        backend = records._backend()  # noqa: SLF001 - exact custody seam
        # Validate every record below the operational ceiling.  Reaching the
        # sentinel bound is itself not a trustworthy readiness result.
        stored = records.list(limit=10_001)
        if len(stored) >= 10_001:
            return False
        for raw in stored:
            attachments._normalize_record(raw)  # noqa: SLF001 - exact contract
        if backend.kind == "local":
            directory = prepare_private_directory(
                backend._store._dir()  # noqa: SLF001 - backend-owned path
            )
            probe = directory / f".readiness-{secrets.token_hex(16)}.tmp"
            try:
                atomic_create_bytes(probe, b"lightwork-readiness-v1")
                if not private_path_is_restricted(probe):
                    return False
            finally:
                try:
                    probe.unlink(missing_ok=True)
                except OSError:
                    return False
            return not probe.exists()
        if backend.kind == "postgres":
            tenant_key = backend._tenant_key()  # noqa: SLF001 - exact authority
            with backend._operation("readiness probe"):  # noqa: SLF001
                with backend._transaction(tenant_key) as cursor:  # noqa: SLF001
                    # Zero rows are changed, but Postgres still checks UPDATE
                    # privilege, schema, tenant RLS, and transaction writability.
                    cursor.execute(
                        "UPDATE governed_records SET updated_at=updated_at "
                        "WHERE tenant_id=%s AND namespace=%s AND FALSE",
                        (tenant_key, records.namespace),
                    )
            return True
    return False


def incident_attachment_metadata_readiness(app: Any, tenant_id: str) -> bool:
    """Operational readiness across the exact read/write custody seams."""

    try:
        tenant = canonical_tenant_id(tenant_id)
        settings_for_tenant(tenant)
        document_factory = getattr(
            app.state,
            "administration_document_access_document_resolver_factory",
            None,
        )
        document_enabled = getattr(
            app.state, "administration_document_access_enabled_probe", None
        )
        if not callable(document_factory) or not callable(document_enabled):
            return False
        document_custody = getattr(
            app.state,
            "administration_document_access_document_custody_probe",
            None,
        )
        metadata_custody = getattr(
            app.state,
            "incident_attachment_metadata_custody_probe",
            None,
        )
        if not callable(document_custody) or not callable(metadata_custody):
            return False
        stock_document_factory = getattr(
            app.state,
            "governed_document_vault_stock_document_resolver_factory",
            None,
        )
        if document_factory is stock_document_factory:
            vault_enabled = getattr(
                app.state,
                "governed_document_vault_enabled_probe",
                None,
            )
            if not callable(vault_enabled) or vault_enabled(tenant) is not True:
                return False
        # Incident attachments consume only the ephemeral document authority.  Delivery
        # grant issuance and live object-store custody remain explicitly
        # external, so their intentionally-false readiness does not prevent the
        # metadata-only authority from becoming locally ready.
        if document_enabled(tenant) is not True:
            return False
        if document_custody(tenant) is not True or metadata_custody(tenant) is not True:
            return False
        # Exercise both exact incident read authorities. Bounded scans validate
        # all accepted stores; the sentinel ceiling fails closed.
        from maverick import privacy_ops, security_ops

        with tenant_scope(tenant=tenant):
            for store in (privacy_ops._INCIDENT, security_ops._INCIDENTS):  # noqa: SLF001
                if len(store.list_bounded(limit=10_001)) >= 10_001:
                    return False
        return True
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def incident_attachment_projection_factory(
    app: Any,
    *,
    tenant_id: str,
    principal_ref: str,
    request: object,
) -> Callable[[Mapping[str, Any], str], dict[str, Any]]:
    """Build the response hook used by privacy/security incident endpoints."""

    store = incident_attachment_metadata_store_factory(
        app,
        tenant_id=tenant_id,
        principal_ref=principal_ref,
        request=request,
    )

    def project(incident: Mapping[str, Any], incident_kind: str) -> dict[str, Any]:
        return attachments.with_incident_attachment_metadata(
            incident,
            store=store,
            tenant_id=tenant_id,
            incident_kind=incident_kind,
        )

    return project


def _install_default(state: Any, name: str, value: object) -> None:
    if not hasattr(state, name):
        setattr(state, name, value)


def attach_incident_attachment_metadata_composition(app: Any) -> None:
    """Attach lazy factories without enabling the feature or opening storage."""

    # Incident attachments depend on the governed document authority.  Attaching that
    # composition is configuration-neutral and performs no provider or storage
    # I/O; its own gate remains default-off.
    try:
        from .administration_document_access_composition import (
            attach_administration_document_access_composition,
        )
    except ImportError:
        attach_administration_document_access_composition = None
    if callable(attach_administration_document_access_composition):
        attach_administration_document_access_composition(app)
    _install_default(
        app.state,
        "incident_attachment_metadata_enabled_probe",
        incident_attachment_metadata_enabled,
    )
    _install_default(
        app.state,
        "incident_attachment_metadata_readiness_probe",
        lambda tenant_id: incident_attachment_metadata_readiness(app, tenant_id),
    )
    _install_default(
        app.state,
        "incident_attachment_metadata_custody_probe",
        _stock_metadata_custody_ready,
    )
    _install_default(
        app.state,
        "incident_attachment_metadata_store_factory",
        lambda **kwargs: incident_attachment_metadata_store_factory(app, **kwargs),
    )
    _install_default(
        app.state,
        "incident_attachment_metadata_projection_factory",
        lambda **kwargs: incident_attachment_projection_factory(app, **kwargs),
    )


__all__ = [
    "IncidentAttachmentCompositionError",
    "IncidentAttachmentSettings",
    "attach_incident_attachment_metadata_composition",
    "incident_attachment_metadata_enabled",
    "incident_attachment_metadata_readiness",
    "incident_attachment_metadata_store_factory",
    "incident_attachment_projection_factory",
    "incident_attachment_settings",
    "incident_record_sha256",
    "principal_ref_from_request",
    "settings_for_tenant",
]
