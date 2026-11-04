"""Governed metadata for privacy and security incident attachments.

This authority stores metadata only.  It never accepts or persists document
bytes, filesystem paths, object-store locations, download grants, credentials,
or caller-supplied filenames.  Every create/update resolves both the incident
record and the governed document again through server-owned callbacks and pins
the exact revisions and digests returned by those authorities.

The product core is default-off.  Durability, tenant isolation, compare-and-
swap mutation and signed audit delivery are delegated to
``GovernedRecordStore``; this module adds principal binding, idempotency,
closed schemas, lifecycle rules, digest-linked history and retention-safe
tombstones.  Live object storage and relying workflow acceptance are outside
this metadata authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import time
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .constant_time import text_equals
from .governed_document_vault import (
    DEFAULT_MEDIA_TYPES as STOCK_VAULT_MEDIA_TYPES,
)
from .governed_records import GovernedRecordBackendError, GovernedRecordStore
from .paths import canonical_tenant_id
from .privacy_ops import RecordConflict

SCHEMA_VERSION = 1
INCIDENT_AUTHORITY_SCHEMA = "lightwork.incident-attachment.incident-authority.v1"
ATTACHMENT_SCHEMA = "lightwork.incident-attachment-metadata.v1"
HISTORY_SCHEMA = "lightwork.incident-attachment-history.v1"
PROJECTION_SCHEMA = "lightwork.incident-attachment-projection.v1"
INTEGRITY_SCHEMA = "lightwork.incident-attachment-integrity.v1"

INCIDENT_KINDS = frozenset({"privacy", "security"})
ATTACHMENT_STATUSES = frozenset({"active", "tombstoned", "purged"})
REDACTION_STATES = frozenset(
    {"unreviewed", "pending", "redacted", "approved", "not_required"}
)
AUTHORITY_STATES = frozenset(
    {"active", "expired", "revoked", "stale", "unavailable", "tombstoned", "purged"}
)
DEFAULT_MEDIA_TYPES = STOCK_VAULT_MEDIA_TYPES

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_ATTACHMENT_ID_RE = re.compile(r"IAT-[0-9a-f]{32}\Z")
_OPERATION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_MEDIA_RE = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}\Z")
_MAX_BYTES = 5 * 1024 * 1024 * 1024
_MAX_ATTACHMENTS = 1_000_000
_MAX_OPERATIONS = 128
_MIN_RETENTION_SECONDS = 3_600
_MAX_RETENTION_SECONDS = 10 * 365 * 24 * 3_600
_MIN_TTL_SECONDS = 60
_MAX_TTL_SECONDS = 365 * 24 * 3_600

_REDACTION_TRANSITIONS: Mapping[str, frozenset[str]] = {
    "unreviewed": frozenset({"pending", "redacted", "not_required"}),
    "pending": frozenset({"redacted", "not_required"}),
    "redacted": frozenset({"approved", "pending"}),
    "approved": frozenset({"pending"}),
    "not_required": frozenset({"pending"}),
}


class IncidentAttachmentError(RuntimeError):
    """Base error for the incident-attachment metadata authority."""


class IncidentAttachmentConfigError(IncidentAttachmentError):
    """The feature or one of its server-owned dependencies is unavailable."""


class IncidentAttachmentValidationError(IncidentAttachmentError, ValueError):
    """A value falls outside the closed attachment contract."""


class IncidentAttachmentConflict(IncidentAttachmentError):
    """A CAS, idempotency, lifecycle or authority binding changed."""


class IncidentAttachmentNotFound(IncidentAttachmentError):
    """An attachment is absent or deliberately hidden by scope binding."""


class IncidentAttachmentPermissionDenied(IncidentAttachmentError):
    """The current principal or maintenance authority is insufficient."""


class IncidentAttachmentIntegrityError(IncidentAttachmentError):
    """Persisted attachment metadata failed closed-schema or digest checks."""


def enabled() -> bool:
    """Return true only for an explicit tenant configuration gate."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    section = config.get("incident_attachment_metadata") if isinstance(config, Mapping) else None
    return isinstance(section, Mapping) and section.get("enable") is True


def require_enabled() -> None:
    if not enabled():
        raise IncidentAttachmentConfigError(
            "incident attachment metadata is disabled; explicitly enable "
            "incident_attachment_metadata"
        )


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise IncidentAttachmentValidationError("value must be finite JSON") from exc


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("ascii")).hexdigest()


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise IncidentAttachmentValidationError(f"{label} is not a SHA-256 digest")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise IncidentAttachmentValidationError(f"{label} is not a closed opaque identifier")
    return value


def _attachment_id(value: object) -> str:
    if not isinstance(value, str) or _ATTACHMENT_ID_RE.fullmatch(value) is None:
        raise IncidentAttachmentValidationError("attachment_id is invalid")
    return value


def _operation_key(value: object) -> str:
    if not isinstance(value, str) or _OPERATION_RE.fullmatch(value) is None:
        raise IncidentAttachmentValidationError("idempotency_key is invalid")
    return value


def _integer(value: object, label: str, lower: int, upper: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        raise IncidentAttachmentValidationError(f"{label} is outside its bound")
    return value


def _timestamp(value: object, label: str, *, optional: bool = False) -> float | None:
    if optional and value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise IncidentAttachmentValidationError(f"{label} is not a finite timestamp")
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise IncidentAttachmentValidationError(f"{label} is not a finite timestamp")
    return result


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value if isinstance(value, str) else "")
    except (TypeError, ValueError) as exc:
        raise IncidentAttachmentValidationError("tenant authority is invalid") from exc


def _kind(value: object) -> str:
    kind = _identifier(value, "incident_kind")
    if kind not in INCIDENT_KINDS:
        raise IncidentAttachmentValidationError("incident_kind is invalid")
    return kind


def _revision(value: object, label: str = "revision") -> int:
    return _integer(value, label, 1, 2_147_483_647)


def _safe_display_name(value: object, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str):
        raise IncidentAttachmentValidationError("safe display name must be text")
    name = value.strip()
    if not name or len(name) > 255 or name in {".", ".."}:
        raise IncidentAttachmentValidationError("safe display name is invalid")
    if any(ord(character) < 32 or ord(character) == 127 for character in name):
        raise IncidentAttachmentValidationError("safe display name contains a control character")
    if "/" in name or "\\" in name or ":" in name:
        raise IncidentAttachmentValidationError("safe display name must not contain a path")
    return name


def _media_type(value: object) -> str:
    if not isinstance(value, str):
        raise IncidentAttachmentValidationError("media type must be text")
    normalized = value.strip().lower()
    if ";" in normalized or _MEDIA_RE.fullmatch(normalized) is None:
        raise IncidentAttachmentValidationError("media type is invalid")
    return normalized


def _byte_size(value: object) -> int:
    return _integer(value, "byte_size", 0, _MAX_BYTES)


def _mapping_value(value: object, key: str) -> object:
    if isinstance(value, Mapping):
        return value.get(key)
    return getattr(value, key, None)


@dataclass(frozen=True)
class IncidentAuthority:
    """Stable server-issued binding for one exact incident revision."""

    schema: str
    tenant_id: str
    principal_ref: str
    incident_kind: str
    incident_id: str
    incident_revision: int
    incident_sha256: str
    revoked: bool
    authority_sha256: str

    def normalized(self) -> IncidentAuthority:
        if self.schema != INCIDENT_AUTHORITY_SCHEMA or type(self.revoked) is not bool:
            raise IncidentAttachmentValidationError("incident authority schema is invalid")
        body = {
            "schema": INCIDENT_AUTHORITY_SCHEMA,
            "tenant_id": _tenant(self.tenant_id),
            "principal_ref": _identifier(self.principal_ref, "principal_ref"),
            "incident_kind": _kind(self.incident_kind),
            "incident_id": _identifier(self.incident_id, "incident_id"),
            "incident_revision": _revision(self.incident_revision, "incident_revision"),
            "incident_sha256": _digest(self.incident_sha256, "incident_sha256"),
            "revoked": self.revoked,
        }
        expected = _sha256(body)
        if not hmac.compare_digest(
            _digest(self.authority_sha256, "incident authority digest"), expected
        ):
            raise IncidentAttachmentValidationError("incident authority digest changed")
        return IncidentAuthority(**body, authority_sha256=expected)


def issue_incident_authority(
    *,
    tenant_id: str,
    principal_ref: str,
    incident_kind: str,
    incident_id: str,
    incident_revision: int,
    incident_sha256: str,
    revoked: bool = False,
) -> IncidentAuthority:
    body = {
        "schema": INCIDENT_AUTHORITY_SCHEMA,
        "tenant_id": _tenant(tenant_id),
        "principal_ref": _identifier(principal_ref, "principal_ref"),
        "incident_kind": _kind(incident_kind),
        "incident_id": _identifier(incident_id, "incident_id"),
        "incident_revision": _revision(incident_revision, "incident_revision"),
        "incident_sha256": _digest(incident_sha256, "incident_sha256"),
        "revoked": revoked,
    }
    if type(revoked) is not bool:
        raise IncidentAttachmentValidationError("incident authority revocation is invalid")
    return IncidentAuthority(**body, authority_sha256=_sha256(body)).normalized()


@dataclass(frozen=True)
class _DocumentAuthority:
    tenant_id: str
    principal_ref: str
    document_id: str
    document_revision: int
    document_authority_sha256: str
    safe_display_name: str
    media_type: str
    byte_size: int
    content_sha256: str
    download_allowed: bool


def _normalize_document_authority(value: object) -> _DocumentAuthority:
    allowed = _mapping_value(value, "download_allowed")
    if type(allowed) is not bool:
        raise IncidentAttachmentValidationError("document authority state is invalid")
    return _DocumentAuthority(
        tenant_id=_tenant(_mapping_value(value, "tenant_id")),
        principal_ref=_identifier(_mapping_value(value, "principal_ref"), "principal_ref"),
        document_id=_identifier(
            _mapping_value(value, "document_ref")
            if _mapping_value(value, "document_ref") is not None
            else _mapping_value(value, "document_id"),
            "document_id",
        ),
        document_revision=_revision(
            _mapping_value(value, "authority_revision")
            if _mapping_value(value, "authority_revision") is not None
            else _mapping_value(value, "document_revision"),
            "document_revision",
        ),
        document_authority_sha256=_digest(
            _mapping_value(value, "authority_sha256"), "document authority digest"
        ),
        safe_display_name=str(_safe_display_name(_mapping_value(value, "safe_display_name"))),
        media_type=_media_type(_mapping_value(value, "media_type")),
        byte_size=_byte_size(_mapping_value(value, "byte_size")),
        content_sha256=_digest(_mapping_value(value, "content_sha256"), "content_sha256"),
        download_allowed=allowed,
    )


@dataclass(frozen=True)
class IncidentAttachmentMetadata:
    schema: str
    tenant_id: str
    principal_ref: str
    attachment_id: str
    incident_kind: str
    incident_id: str
    incident_revision: int
    incident_sha256: str
    incident_authority_sha256: str
    document_id: str
    document_revision: int
    document_authority_sha256: str
    safe_display_name: str | None
    media_type: str
    byte_size: int
    sha256: str
    redaction_state: str
    status: str
    created_at: float
    updated_at: float
    expires_at: float
    retained_until: float
    tombstoned_at: float | None
    purged_at: float | None
    revision: int
    previous_integrity_sha256: str | None
    history_sha256: str
    integrity_sha256: str


def _history_event(
    *,
    event_type: str,
    revision: int,
    actor_ref: str,
    created_at: float,
    changes: object,
    previous_event_sha256: str | None,
) -> dict[str, object]:
    body = {
        "schema": HISTORY_SCHEMA,
        "event_type": _identifier(event_type, "history event type"),
        "revision": _revision(revision, "history revision"),
        "actor_ref": _identifier(actor_ref, "history actor"),
        "created_at": _timestamp(created_at, "history timestamp"),
        "changes_sha256": _sha256(changes),
        "previous_event_sha256": (
            _digest(previous_event_sha256, "previous history digest")
            if previous_event_sha256 is not None
            else None
        ),
    }
    return {**body, "event_sha256": _sha256(body)}


def _validate_history(value: object, record_revision: int) -> tuple[dict[str, object], ...]:
    if not isinstance(value, list) or not value or len(value) > record_revision:
        raise IncidentAttachmentIntegrityError("attachment history is invalid")
    previous: str | None = None
    events: list[dict[str, object]] = []
    for index, raw in enumerate(value, 1):
        if not isinstance(raw, Mapping) or set(raw) != {
            "schema",
            "event_type",
            "revision",
            "actor_ref",
            "created_at",
            "changes_sha256",
            "previous_event_sha256",
            "event_sha256",
        }:
            raise IncidentAttachmentIntegrityError("attachment history shape is invalid")
        try:
            body = {
                "schema": raw["schema"],
                "event_type": _identifier(raw["event_type"], "history event type"),
                "revision": _revision(raw["revision"], "history revision"),
                "actor_ref": _identifier(raw["actor_ref"], "history actor"),
                "created_at": _timestamp(raw["created_at"], "history timestamp"),
                "changes_sha256": _digest(raw["changes_sha256"], "history changes digest"),
                "previous_event_sha256": (
                    _digest(raw["previous_event_sha256"], "previous history digest")
                    if raw["previous_event_sha256"] is not None
                    else None
                ),
            }
            event_digest = _digest(raw["event_sha256"], "history digest")
        except IncidentAttachmentValidationError as exc:
            raise IncidentAttachmentIntegrityError("attachment history is invalid") from exc
        if (
            body["schema"] != HISTORY_SCHEMA
            or body["revision"] != index
            or body["previous_event_sha256"] != previous
            or not hmac.compare_digest(event_digest, _sha256(body))
        ):
            raise IncidentAttachmentIntegrityError("attachment history chain changed")
        event = {**body, "event_sha256": event_digest}
        events.append(event)
        previous = event_digest
    if events[-1]["revision"] != record_revision:
        raise IncidentAttachmentIntegrityError("attachment history is incomplete")
    return tuple(events)


def _validate_operations(value: object, record_revision: int) -> tuple[dict[str, object], ...]:
    if not isinstance(value, list) or not value or len(value) > _MAX_OPERATIONS:
        raise IncidentAttachmentIntegrityError("attachment idempotency receipts are invalid")
    receipts: list[dict[str, object]] = []
    keys: set[str] = set()
    for raw in value:
        if not isinstance(raw, Mapping) or set(raw) != {
            "key_sha256",
            "operation",
            "request_sha256",
            "result_revision",
        }:
            raise IncidentAttachmentIntegrityError("attachment idempotency receipt is invalid")
        try:
            receipt = {
                "key_sha256": _digest(raw["key_sha256"], "idempotency key digest"),
                "operation": _identifier(raw["operation"], "operation"),
                "request_sha256": _digest(raw["request_sha256"], "request digest"),
                "result_revision": _revision(raw["result_revision"], "result revision"),
            }
        except IncidentAttachmentValidationError as exc:
            raise IncidentAttachmentIntegrityError(
                "attachment idempotency receipt is invalid"
            ) from exc
        if receipt["result_revision"] > record_revision or receipt["key_sha256"] in keys:
            raise IncidentAttachmentIntegrityError("attachment idempotency receipt changed")
        keys.add(str(receipt["key_sha256"]))
        receipts.append(receipt)
    return tuple(receipts)


_RECORD_KEYS = frozenset(
    {
        "schema",
        "id",
        "tenant_id",
        "principal_ref",
        "incident_kind",
        "incident_id",
        "incident_revision",
        "incident_sha256",
        "incident_authority_sha256",
        "document_id",
        "document_revision",
        "document_authority_sha256",
        "safe_display_name",
        "media_type",
        "byte_size",
        "sha256",
        "redaction_state",
        "status",
        "expires_at",
        "retained_until",
        "tombstoned_at",
        "purged_at",
        "created_by_ref",
        "previous_integrity_sha256",
        "history",
        "operations",
        "created_at",
        "updated_at",
        "revision",
    }
)


def _record_digest(record: Mapping[str, Any]) -> str:
    logical = {key: value for key, value in record.items() if key != "_audit_pending"}
    return _sha256(logical)


def _normalize_record(record: Mapping[str, Any]) -> IncidentAttachmentMetadata:
    keys = set(record)
    allowed = set(_RECORD_KEYS) | {"_audit_pending"}
    if keys - allowed or not _RECORD_KEYS.issubset(keys):
        raise IncidentAttachmentIntegrityError("stored attachment schema is not closed")
    try:
        schema = record["schema"]
        tenant_id = _tenant(record["tenant_id"])
        principal_ref = _identifier(record["principal_ref"], "principal_ref")
        attachment_id = _attachment_id(record["id"])
        incident_kind = _kind(record["incident_kind"])
        incident_id = _identifier(record["incident_id"], "incident_id")
        incident_revision = _revision(record["incident_revision"], "incident_revision")
        incident_sha256 = _digest(record["incident_sha256"], "incident_sha256")
        incident_authority_sha256 = _digest(
            record["incident_authority_sha256"], "incident authority digest"
        )
        document_id = _identifier(record["document_id"], "document_id")
        document_revision = _revision(record["document_revision"], "document_revision")
        document_authority_sha256 = _digest(
            record["document_authority_sha256"], "document authority digest"
        )
        status = _identifier(record["status"], "status")
        safe_display_name = _safe_display_name(
            record["safe_display_name"], optional=status == "purged"
        )
        media_type = _media_type(record["media_type"])
        byte_size = _byte_size(record["byte_size"])
        content_sha256 = _digest(record["sha256"], "sha256")
        redaction_state = _identifier(record["redaction_state"], "redaction_state")
        created_at = float(_timestamp(record["created_at"], "created_at"))
        updated_at = float(_timestamp(record["updated_at"], "updated_at"))
        expires_at = float(_timestamp(record["expires_at"], "expires_at"))
        retained_until = float(_timestamp(record["retained_until"], "retained_until"))
        tombstoned_at = _timestamp(record["tombstoned_at"], "tombstoned_at", optional=True)
        purged_at = _timestamp(record["purged_at"], "purged_at", optional=True)
        revision = _revision(record["revision"])
        previous_integrity = (
            _digest(record["previous_integrity_sha256"], "previous integrity digest")
            if record["previous_integrity_sha256"] is not None
            else None
        )
        created_by = _identifier(record["created_by_ref"], "created_by_ref")
    except IncidentAttachmentValidationError as exc:
        raise IncidentAttachmentIntegrityError("stored attachment metadata is invalid") from exc
    if (
        schema != ATTACHMENT_SCHEMA
        or status not in ATTACHMENT_STATUSES
        or redaction_state not in REDACTION_STATES
        or created_by != principal_ref
        or updated_at < created_at
        or expires_at <= created_at
    ):
        raise IncidentAttachmentIntegrityError("stored attachment lifecycle is invalid")
    if revision == 1 and previous_integrity is not None:
        raise IncidentAttachmentIntegrityError("initial attachment has a previous digest")
    if revision > 1 and previous_integrity is None:
        raise IncidentAttachmentIntegrityError("revised attachment lacks a previous digest")
    if status == "active" and (tombstoned_at is not None or purged_at is not None):
        raise IncidentAttachmentIntegrityError("active attachment has deletion timestamps")
    if status == "tombstoned" and (tombstoned_at is None or purged_at is not None):
        raise IncidentAttachmentIntegrityError("attachment tombstone is invalid")
    if status == "purged" and (tombstoned_at is None or purged_at is None):
        raise IncidentAttachmentIntegrityError("purged attachment tombstone is invalid")
    if status != "purged" and safe_display_name is None:
        raise IncidentAttachmentIntegrityError("attachment display name is missing")
    history = _validate_history(record["history"], revision)
    _validate_operations(record["operations"], revision)
    return IncidentAttachmentMetadata(
        schema=ATTACHMENT_SCHEMA,
        tenant_id=tenant_id,
        principal_ref=principal_ref,
        attachment_id=attachment_id,
        incident_kind=incident_kind,
        incident_id=incident_id,
        incident_revision=incident_revision,
        incident_sha256=incident_sha256,
        incident_authority_sha256=incident_authority_sha256,
        document_id=document_id,
        document_revision=document_revision,
        document_authority_sha256=document_authority_sha256,
        safe_display_name=safe_display_name,
        media_type=media_type,
        byte_size=byte_size,
        sha256=content_sha256,
        redaction_state=redaction_state,
        status=status,
        created_at=created_at,
        updated_at=updated_at,
        expires_at=expires_at,
        retained_until=retained_until,
        tombstoned_at=float(tombstoned_at) if tombstoned_at is not None else None,
        purged_at=float(purged_at) if purged_at is not None else None,
        revision=revision,
        previous_integrity_sha256=previous_integrity,
        history_sha256=str(history[-1]["event_sha256"]),
        integrity_sha256=_record_digest(record),
    )


def _operation_digest(tenant_id: str, principal_ref: str, key: str) -> str:
    return hashlib.sha256(
        f"lightwork.incident-attachment.idempotency.v1:{tenant_id}:{principal_ref}:{key}".encode()
    ).hexdigest()


def _find_operation(
    raw: Mapping[str, Any],
    *,
    key_sha256: str,
    operation: str,
    request_sha256: str,
) -> bool:
    _normalize_record(raw)
    for receipt in raw["operations"]:
        if hmac.compare_digest(str(receipt["key_sha256"]), key_sha256):
            if (
                receipt["operation"] != operation
                or not hmac.compare_digest(str(receipt["request_sha256"]), request_sha256)
            ):
                raise IncidentAttachmentConflict("idempotency key was reused")
            return True
    return False


def _append_operation(
    raw: dict[str, Any],
    *,
    key_sha256: str,
    operation: str,
    request_sha256: str,
    result_revision: int,
) -> None:
    receipts = list(raw["operations"])
    if len(receipts) >= _MAX_OPERATIONS:
        raise IncidentAttachmentConflict("attachment idempotency history is full")
    receipts.append(
        {
            "key_sha256": key_sha256,
            "operation": operation,
            "request_sha256": request_sha256,
            "result_revision": result_revision,
        }
    )
    raw["operations"] = receipts


def _append_history(
    raw: dict[str, Any],
    *,
    event_type: str,
    actor_ref: str,
    created_at: float,
    changes: object,
    result_revision: int,
) -> None:
    history = list(raw["history"])
    previous = str(history[-1]["event_sha256"]) if history else None
    history.append(
        _history_event(
            event_type=event_type,
            revision=result_revision,
            actor_ref=actor_ref,
            created_at=created_at,
            changes=changes,
            previous_event_sha256=previous,
        )
    )
    raw["history"] = history


def principal_ref_for_subject(tenant_id: str, subject: str) -> str:
    """The uploader reference stored for one authenticated subject in one workspace.

    The reference is a one-way digest, so a stored record names its uploader only
    through it.  A legal matter names a person with the same derivation.
    """

    tenant = canonical_tenant_id(tenant_id)
    digest = hashlib.sha256(
        f"lightwork.incident-attachment.identity.v1:{tenant}:{subject}".encode()
    ).hexdigest()
    return f"incident-principal-{digest[:32]}"


def _default_record_store() -> GovernedRecordStore:
    return GovernedRecordStore(
        "incident_attachment_metadata",
        "IAT",
        "incident_attachment_metadata",
        event_kind="incident_attachment_metadata_changed",
    )


def records_for_principal_refs(
    tenant_id: str, principal_refs: Collection[str], *, limit: int = 10_000
) -> list[IncidentAttachmentMetadata]:
    """Validated attachment records of one workspace whose uploader is in ``principal_refs``.

    Read only, and the caller must already be in that workspace's scope.  More
    than ``limit`` stored records is refused, so a caller never works from a partial list.
    """

    tenant = _tenant(tenant_id)
    rows = _default_record_store().list(limit=limit + 1)
    if len(rows) > limit:
        raise IncidentAttachmentIntegrityError(
            "too many incident attachment records to list completely"
        )
    wanted = set(principal_refs)
    return [
        _normalize_record(raw)
        for raw in rows
        if raw.get("tenant_id") == tenant and raw.get("principal_ref") in wanted
    ]


def _matter_refusal(tenant_id: str, metadata: IncidentAttachmentMetadata, *, actor: str) -> str | None:
    """The plain refusal text when a legal matter holds this attachment (see ``ediscovery``)."""

    from .ediscovery import incident_attachment_refusal

    return incident_attachment_refusal(
        tenant_id,
        principal_ref=metadata.principal_ref,
        created_at=metadata.created_at,
        actor=actor,
    )


class IncidentAttachmentStore:
    """Tenant/principal-bound durable incident attachment metadata authority."""

    def __init__(
        self,
        *,
        tenant_id: str,
        principal_ref: str,
        incident_authority_resolver: Callable[[str, str, str, str], IncidentAuthority],
        document_authority_resolver: Callable[[str, str, str], object],
        principal_resolver: Callable[[], str | None],
        maintenance_authorizer: Callable[[], bool] = lambda: False,
        config_gate: Callable[[], None] = require_enabled,
        record_store: GovernedRecordStore | None = None,
        retention_seconds: int = 365 * 24 * 3_600,
        attachment_ttl_seconds: int = 7 * 24 * 3_600,
        allowed_media_types: Sequence[str] = tuple(sorted(DEFAULT_MEDIA_TYPES)),
        max_attachments: int = 100_000,
        clock: Callable[[], float] = time.time,
    ) -> None:
        dependencies = (
            incident_authority_resolver,
            document_authority_resolver,
            principal_resolver,
            maintenance_authorizer,
            config_gate,
            clock,
        )
        if not all(callable(value) for value in dependencies):
            raise IncidentAttachmentConfigError("incident attachment dependencies are incomplete")
        try:
            config_gate()
        except IncidentAttachmentError:
            raise
        except Exception as exc:
            raise IncidentAttachmentConfigError(
                "incident attachment configuration is unavailable"
            ) from exc
        self.tenant_id = _tenant(tenant_id)
        self.principal_ref = _identifier(principal_ref, "principal_ref")
        self._incident_resolver = incident_authority_resolver
        self._document_resolver = document_authority_resolver
        self._principal_resolver = principal_resolver
        self._maintenance_authorizer = maintenance_authorizer
        self._retention_seconds = _integer(
            retention_seconds,
            "retention_seconds",
            _MIN_RETENTION_SECONDS,
            _MAX_RETENTION_SECONDS,
        )
        self._ttl_seconds = _integer(
            attachment_ttl_seconds,
            "attachment_ttl_seconds",
            _MIN_TTL_SECONDS,
            _MAX_TTL_SECONDS,
        )
        if not isinstance(allowed_media_types, (list, tuple, set, frozenset)):
            raise IncidentAttachmentValidationError("allowed media types are invalid")
        normalized_media = frozenset(_media_type(value) for value in allowed_media_types)
        if not normalized_media or len(normalized_media) > 128:
            raise IncidentAttachmentValidationError("allowed media types are invalid")
        self.allowed_media_types = normalized_media
        self._max_attachments = _integer(
            max_attachments, "max_attachments", 1, _MAX_ATTACHMENTS
        )
        self._clock = clock
        self._records = record_store or _default_record_store()

    @property
    def backend_kind(self) -> str:
        try:
            return self._records.backend_kind
        except GovernedRecordBackendError as exc:
            raise IncidentAttachmentConfigError(
                "incident attachment durable authority is unavailable"
            ) from exc

    def _now(self) -> float:
        try:
            return float(_timestamp(self._clock(), "clock"))
        except IncidentAttachmentValidationError as exc:
            raise IncidentAttachmentConfigError("incident attachment clock is unavailable") from exc

    def _actor(self) -> str:
        try:
            current = self._principal_resolver()
            actor = _identifier(current, "authenticated principal")
        except IncidentAttachmentError:
            raise
        except Exception as exc:
            raise IncidentAttachmentPermissionDenied(
                "authenticated principal is unavailable"
            ) from exc
        if not hmac.compare_digest(actor, self.principal_ref):
            raise IncidentAttachmentPermissionDenied("authenticated principal changed")
        return actor

    def _require_tenant(self, tenant_id: object) -> None:
        if not text_equals(_tenant(tenant_id), self.tenant_id):
            raise IncidentAttachmentNotFound("incident attachment was not found")

    def _resolve_incident(self, incident_kind: str, incident_id: str) -> IncidentAuthority:
        kind = _kind(incident_kind)
        identifier = _identifier(incident_id, "incident_id")
        try:
            first = self._incident_resolver(
                self.tenant_id, self.principal_ref, kind, identifier
            )
            second = self._incident_resolver(
                self.tenant_id, self.principal_ref, kind, identifier
            )
            if not isinstance(first, IncidentAuthority) or not isinstance(
                second, IncidentAuthority
            ):
                raise TypeError("incident authority type is invalid")
            left = first.normalized()
            right = second.normalized()
        except IncidentAttachmentError:
            raise
        except Exception as exc:
            raise IncidentAttachmentConflict("incident authority is unavailable") from exc
        if left != right:
            raise IncidentAttachmentConflict("incident authority changed during resolution")
        if (
            left.tenant_id != self.tenant_id
            or left.principal_ref != self.principal_ref
            or left.incident_kind != kind
            or left.incident_id != identifier
            or left.revoked
        ):
            raise IncidentAttachmentConflict("incident authority is not current")
        return left

    def _resolve_document(self, document_id: str) -> _DocumentAuthority:
        identifier = _identifier(document_id, "document_id")
        try:
            first = _normalize_document_authority(
                self._document_resolver(self.tenant_id, self.principal_ref, identifier)
            )
            second = _normalize_document_authority(
                self._document_resolver(self.tenant_id, self.principal_ref, identifier)
            )
        except IncidentAttachmentError:
            raise
        except Exception as exc:
            raise IncidentAttachmentConflict("document authority is unavailable") from exc
        if first != second:
            raise IncidentAttachmentConflict("document authority changed during resolution")
        if (
            first.tenant_id != self.tenant_id
            or first.principal_ref != self.principal_ref
            or first.document_id != identifier
            or first.download_allowed is not True
        ):
            raise IncidentAttachmentConflict("document authority is not current")
        if first.media_type not in self.allowed_media_types:
            raise IncidentAttachmentValidationError("document media type is not allowed")
        return first

    @staticmethod
    def _exact_incident(
        authority: IncidentAuthority,
        expected_revision: int,
        expected_sha256: str,
    ) -> None:
        revision = _revision(expected_revision, "incident_revision")
        digest = _digest(expected_sha256, "incident_sha256")
        if authority.incident_revision != revision or not hmac.compare_digest(
            authority.incident_sha256, digest
        ):
            raise IncidentAttachmentConflict("incident revision or digest changed")

    @staticmethod
    def _exact_document(
        authority: _DocumentAuthority,
        expected_revision: int,
        expected_authority_sha256: str,
        expected_content_sha256: str,
    ) -> None:
        revision = _revision(expected_revision, "document_revision")
        authority_digest = _digest(
            expected_authority_sha256, "document_authority_sha256"
        )
        content_digest = _digest(expected_content_sha256, "sha256")
        if (
            authority.document_revision != revision
            or not hmac.compare_digest(
                authority.document_authority_sha256, authority_digest
            )
            or not hmac.compare_digest(authority.content_sha256, content_digest)
        ):
            raise IncidentAttachmentConflict("document revision or digest changed")

    def _raw(self, attachment_id: str) -> dict[str, Any]:
        identifier = _attachment_id(attachment_id)
        try:
            raw = self._records.get(identifier)
        except GovernedRecordBackendError as exc:
            raise IncidentAttachmentConfigError(
                "incident attachment durable authority is unavailable"
            ) from exc
        if raw is None:
            raise IncidentAttachmentNotFound("incident attachment was not found")
        metadata = _normalize_record(raw)
        if (
            metadata.tenant_id != self.tenant_id
            or metadata.principal_ref != self.principal_ref
        ):
            raise IncidentAttachmentNotFound("incident attachment was not found")
        return raw

    def create_attachment(
        self,
        tenant_id: str,
        *,
        incident_kind: str,
        incident_id: str,
        incident_revision: int,
        incident_sha256: str,
        document_id: str,
        document_revision: int,
        document_authority_sha256: str,
        sha256: str,
        redaction_state: str = "unreviewed",
        idempotency_key: str,
    ) -> IncidentAttachmentMetadata:
        self._require_tenant(tenant_id)
        actor = self._actor()
        kind = _kind(incident_kind)
        incident = _identifier(incident_id, "incident_id")
        document = _identifier(document_id, "document_id")
        expected_incident_revision = _revision(incident_revision, "incident_revision")
        expected_incident_sha = _digest(incident_sha256, "incident_sha256")
        expected_document_revision = _revision(document_revision, "document_revision")
        expected_document_authority_sha = _digest(
            document_authority_sha256, "document_authority_sha256"
        )
        expected_content_sha = _digest(sha256, "sha256")
        state = _identifier(redaction_state, "redaction_state")
        if state not in REDACTION_STATES:
            raise IncidentAttachmentValidationError("redaction_state is invalid")
        operation_key = _operation_key(idempotency_key)
        key_sha = _operation_digest(self.tenant_id, actor, operation_key)
        attachment_id = f"IAT-{hashlib.sha256(key_sha.encode()).hexdigest()[:32]}"
        request = {
            "schema": "lightwork.incident-attachment-create.v1",
            "incident_kind": kind,
            "incident_id": incident,
            "incident_revision": expected_incident_revision,
            "incident_sha256": expected_incident_sha,
            "document_id": document,
            "document_revision": expected_document_revision,
            "document_authority_sha256": expected_document_authority_sha,
            "sha256": expected_content_sha,
            "redaction_state": state,
        }
        request_sha = _sha256(request)
        try:
            existing = self._records.get(attachment_id)
        except GovernedRecordBackendError as exc:
            raise IncidentAttachmentConfigError(
                "incident attachment durable authority is unavailable"
            ) from exc
        if existing is not None:
            metadata = _normalize_record(existing)
            if (
                metadata.tenant_id != self.tenant_id
                or metadata.principal_ref != self.principal_ref
                or not _find_operation(
                    existing,
                    key_sha256=key_sha,
                    operation="create",
                    request_sha256=request_sha,
                )
            ):
                raise IncidentAttachmentConflict("attachment identity is already used")
            return metadata
        incident_authority = self._resolve_incident(kind, incident)
        self._exact_incident(
            incident_authority, expected_incident_revision, expected_incident_sha
        )
        document_authority = self._resolve_document(document)
        self._exact_document(
            document_authority,
            expected_document_revision,
            expected_document_authority_sha,
            expected_content_sha,
        )
        now = self._now()
        raw: dict[str, Any] = {
            "schema": ATTACHMENT_SCHEMA,
            "id": attachment_id,
            "tenant_id": self.tenant_id,
            "principal_ref": actor,
            "incident_kind": kind,
            "incident_id": incident_authority.incident_id,
            "incident_revision": incident_authority.incident_revision,
            "incident_sha256": incident_authority.incident_sha256,
            "incident_authority_sha256": incident_authority.authority_sha256,
            "document_id": document_authority.document_id,
            "document_revision": document_authority.document_revision,
            "document_authority_sha256": document_authority.document_authority_sha256,
            "safe_display_name": document_authority.safe_display_name,
            "media_type": document_authority.media_type,
            "byte_size": document_authority.byte_size,
            "sha256": document_authority.content_sha256,
            "redaction_state": state,
            "status": "active",
            "expires_at": now + self._ttl_seconds,
            "retained_until": now + self._retention_seconds,
            "tombstoned_at": None,
            "purged_at": None,
            "created_by_ref": actor,
            "previous_integrity_sha256": None,
            "history": [
                _history_event(
                    event_type="created",
                    revision=1,
                    actor_ref=actor,
                    created_at=now,
                    changes=request,
                    previous_event_sha256=None,
                )
            ],
            "operations": [
                {
                    "key_sha256": key_sha,
                    "operation": "create",
                    "request_sha256": request_sha,
                    "result_revision": 1,
                }
            ],
        }
        try:
            saved = self._records.create(
                raw,
                action="create",
                actor=actor,
                max_records=self._max_attachments,
            )
        except RecordConflict:
            raced = self._records.get(attachment_id)
            if raced is None or not _find_operation(
                raced,
                key_sha256=key_sha,
                operation="create",
                request_sha256=request_sha,
            ):
                raise IncidentAttachmentConflict("attachment create changed concurrently") from None
            saved = raced
        except GovernedRecordBackendError as exc:
            raise IncidentAttachmentConfigError(
                "incident attachment durable authority is unavailable"
            ) from exc
        return _normalize_record(saved)

    def update_attachment(
        self,
        tenant_id: str,
        attachment_id: str,
        *,
        expected_revision: int,
        incident_revision: int,
        incident_sha256: str,
        document_revision: int,
        document_authority_sha256: str,
        sha256: str,
        redaction_state: str,
        idempotency_key: str,
    ) -> IncidentAttachmentMetadata:
        self._require_tenant(tenant_id)
        actor = self._actor()
        identifier = _attachment_id(attachment_id)
        revision = _revision(expected_revision, "expected_revision")
        state = _identifier(redaction_state, "redaction_state")
        if state not in REDACTION_STATES:
            raise IncidentAttachmentValidationError("redaction_state is invalid")
        expected_incident_revision = _revision(incident_revision, "incident_revision")
        expected_incident_sha = _digest(incident_sha256, "incident_sha256")
        expected_document_revision = _revision(document_revision, "document_revision")
        expected_document_authority_sha = _digest(
            document_authority_sha256, "document_authority_sha256"
        )
        expected_content_sha = _digest(sha256, "sha256")
        key_sha = _operation_digest(
            self.tenant_id, actor, _operation_key(idempotency_key)
        )
        request = {
            "schema": "lightwork.incident-attachment-update.v1",
            "attachment_id": identifier,
            "expected_revision": revision,
            "incident_revision": expected_incident_revision,
            "incident_sha256": expected_incident_sha,
            "document_revision": expected_document_revision,
            "document_authority_sha256": expected_document_authority_sha,
            "sha256": expected_content_sha,
            "redaction_state": state,
        }
        request_sha = _sha256(request)
        current_raw = self._raw(identifier)
        if _find_operation(
            current_raw,
            key_sha256=key_sha,
            operation="update",
            request_sha256=request_sha,
        ):
            return _normalize_record(current_raw)
        current = _normalize_record(current_raw)
        if current.status != "active":
            raise IncidentAttachmentConflict("deleted attachment metadata is immutable")
        # A rebind overwrites the binding in place and keeps no copy of the earlier one, so
        # a held record cannot be changed at all while its matter is active.
        refusal = _matter_refusal(self.tenant_id, current, actor=actor)
        if refusal is not None:
            raise IncidentAttachmentConflict(refusal)
        incident_authority = self._resolve_incident(
            current.incident_kind, current.incident_id
        )
        self._exact_incident(
            incident_authority, expected_incident_revision, expected_incident_sha
        )
        document_authority = self._resolve_document(current.document_id)
        self._exact_document(
            document_authority,
            expected_document_revision,
            expected_document_authority_sha,
            expected_content_sha,
        )
        binding_changed = (
            current.incident_revision != incident_authority.incident_revision
            or not hmac.compare_digest(
                current.incident_authority_sha256, incident_authority.authority_sha256
            )
            or current.document_revision != document_authority.document_revision
            or not hmac.compare_digest(
                current.document_authority_sha256,
                document_authority.document_authority_sha256,
            )
            or not hmac.compare_digest(current.sha256, document_authority.content_sha256)
            or current.safe_display_name != document_authority.safe_display_name
            or current.media_type != document_authority.media_type
            or current.byte_size != document_authority.byte_size
        )
        if state != current.redaction_state and state not in _REDACTION_TRANSITIONS[
            current.redaction_state
        ]:
            raise IncidentAttachmentConflict("redaction_state transition is invalid")
        if state == current.redaction_state and not binding_changed:
            raise IncidentAttachmentConflict("attachment update has no material change")
        now = self._now()

        def mutate(raw: dict[str, Any]) -> None:
            live = _normalize_record(raw)
            if live.tenant_id != self.tenant_id or live.principal_ref != actor:
                raise IncidentAttachmentNotFound("incident attachment was not found")
            if live.status != "active":
                raise IncidentAttachmentConflict("deleted attachment metadata is immutable")
            if _find_operation(
                raw,
                key_sha256=key_sha,
                operation="update",
                request_sha256=request_sha,
            ):
                return
            result_revision = live.revision + 1
            raw["previous_integrity_sha256"] = live.integrity_sha256
            raw.update(
                {
                    "incident_revision": incident_authority.incident_revision,
                    "incident_sha256": incident_authority.incident_sha256,
                    "incident_authority_sha256": incident_authority.authority_sha256,
                    "document_revision": document_authority.document_revision,
                    "document_authority_sha256": (
                        document_authority.document_authority_sha256
                    ),
                    "safe_display_name": document_authority.safe_display_name,
                    "media_type": document_authority.media_type,
                    "byte_size": document_authority.byte_size,
                    "sha256": document_authority.content_sha256,
                    "redaction_state": state,
                    "expires_at": now + self._ttl_seconds,
                    "retained_until": now + self._retention_seconds,
                }
            )
            _append_history(
                raw,
                event_type="updated",
                actor_ref=actor,
                created_at=now,
                changes=request,
                result_revision=result_revision,
            )
            _append_operation(
                raw,
                key_sha256=key_sha,
                operation="update",
                request_sha256=request_sha,
                result_revision=result_revision,
            )

        try:
            saved = self._records.update(
                identifier,
                mutate,
                expected_revision=revision,
                action="update",
                actor=actor,
            )
        except RecordConflict as exc:
            raise IncidentAttachmentConflict("attachment revision changed") from exc
        except GovernedRecordBackendError as exc:
            raise IncidentAttachmentConfigError(
                "incident attachment durable authority is unavailable"
            ) from exc
        if saved is None:
            raise IncidentAttachmentNotFound("incident attachment was not found")
        return _normalize_record(saved)

    def delete_attachment(
        self,
        tenant_id: str,
        attachment_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> IncidentAttachmentMetadata:
        self._require_tenant(tenant_id)
        actor = self._actor()
        identifier = _attachment_id(attachment_id)
        revision = _revision(expected_revision, "expected_revision")
        key_sha = _operation_digest(
            self.tenant_id, actor, _operation_key(idempotency_key)
        )
        request = {
            "schema": "lightwork.incident-attachment-delete.v1",
            "attachment_id": identifier,
            "expected_revision": revision,
        }
        request_sha = _sha256(request)
        current_raw = self._raw(identifier)
        if _find_operation(
            current_raw,
            key_sha256=key_sha,
            operation="delete",
            request_sha256=request_sha,
        ):
            return _normalize_record(current_raw)
        current = _normalize_record(current_raw)
        if current.status != "active":
            raise IncidentAttachmentConflict("attachment is already deleted")
        refusal = _matter_refusal(self.tenant_id, current, actor=actor)
        if refusal is not None:
            raise IncidentAttachmentConflict(refusal)
        now = self._now()

        def mutate(raw: dict[str, Any]) -> None:
            live = _normalize_record(raw)
            if live.principal_ref != actor:
                raise IncidentAttachmentNotFound("incident attachment was not found")
            if live.status != "active":
                raise IncidentAttachmentConflict("attachment is already deleted")
            result_revision = live.revision + 1
            raw["previous_integrity_sha256"] = live.integrity_sha256
            raw["status"] = "tombstoned"
            raw["tombstoned_at"] = now
            raw["retained_until"] = now + self._retention_seconds
            _append_history(
                raw,
                event_type="tombstoned",
                actor_ref=actor,
                created_at=now,
                changes=request,
                result_revision=result_revision,
            )
            _append_operation(
                raw,
                key_sha256=key_sha,
                operation="delete",
                request_sha256=request_sha,
                result_revision=result_revision,
            )

        try:
            saved = self._records.update(
                identifier,
                mutate,
                expected_revision=revision,
                action="tombstone",
                actor=actor,
            )
        except RecordConflict as exc:
            raise IncidentAttachmentConflict("attachment revision changed") from exc
        if saved is None:
            raise IncidentAttachmentNotFound("incident attachment was not found")
        return _normalize_record(saved)

    def get_attachment(
        self, tenant_id: str, attachment_id: str
    ) -> IncidentAttachmentMetadata:
        self._require_tenant(tenant_id)
        self._actor()
        return _normalize_record(self._raw(attachment_id))

    def list_for_incident(
        self,
        tenant_id: str,
        incident_kind: str,
        incident_id: str,
        *,
        include_tombstones: bool = False,
        limit: int = 500,
    ) -> tuple[IncidentAttachmentMetadata, ...]:
        self._require_tenant(tenant_id)
        self._actor()
        kind = _kind(incident_kind)
        incident = _identifier(incident_id, "incident_id")
        bounded = _integer(limit, "limit", 1, 1_000)
        try:
            rows = self._records.list(limit=min(10_001, max(bounded, self._max_attachments)))
        except GovernedRecordBackendError as exc:
            raise IncidentAttachmentConfigError(
                "incident attachment durable authority is unavailable"
            ) from exc
        selected: list[IncidentAttachmentMetadata] = []
        for raw in rows:
            metadata = _normalize_record(raw)
            if (
                metadata.tenant_id != self.tenant_id
                or metadata.principal_ref != self.principal_ref
                or metadata.incident_kind != kind
                or metadata.incident_id != incident
                or (not include_tombstones and metadata.status != "active")
            ):
                continue
            selected.append(metadata)
        selected.sort(key=lambda item: (item.created_at, item.attachment_id))
        return tuple(selected[:bounded])

    def history(
        self, tenant_id: str, attachment_id: str
    ) -> tuple[dict[str, object], ...]:
        self._require_tenant(tenant_id)
        self._actor()
        raw = self._raw(attachment_id)
        metadata = _normalize_record(raw)
        return _validate_history(raw["history"], metadata.revision)

    def authority_state(self, metadata: IncidentAttachmentMetadata) -> str:
        if metadata.tenant_id != self.tenant_id or metadata.principal_ref != self.principal_ref:
            raise IncidentAttachmentNotFound("incident attachment was not found")
        if metadata.status in {"tombstoned", "purged"}:
            return metadata.status
        if self._now() >= metadata.expires_at:
            return "expired"
        try:
            incident = self._resolve_incident(
                metadata.incident_kind, metadata.incident_id
            )
        except IncidentAttachmentConflict:
            return "unavailable"
        if (
            incident.incident_revision != metadata.incident_revision
            or not hmac.compare_digest(
                incident.authority_sha256, metadata.incident_authority_sha256
            )
        ):
            return "stale"
        try:
            document = self._resolve_document(metadata.document_id)
        except IncidentAttachmentConflict:
            return "revoked"
        if (
            document.document_revision != metadata.document_revision
            or not hmac.compare_digest(
                document.document_authority_sha256,
                metadata.document_authority_sha256,
            )
            or not hmac.compare_digest(document.content_sha256, metadata.sha256)
            or document.media_type != metadata.media_type
            or document.byte_size != metadata.byte_size
        ):
            return "revoked"
        return "active"

    def projection(self, metadata: IncidentAttachmentMetadata) -> dict[str, object]:
        state = self.authority_state(metadata)
        if state not in AUTHORITY_STATES:
            raise IncidentAttachmentIntegrityError("attachment authority state is invalid")
        return {
            "schema": PROJECTION_SCHEMA,
            "attachment_id": metadata.attachment_id,
            "document_id": metadata.document_id,
            "safe_display_name": metadata.safe_display_name,
            "media_type": metadata.media_type,
            "byte_size": metadata.byte_size,
            "sha256": metadata.sha256,
            "redaction_state": metadata.redaction_state,
            "status": metadata.status,
            "authority_state": state,
            "incident_revision": metadata.incident_revision,
            "incident_sha256": metadata.incident_sha256,
            "document_revision": metadata.document_revision,
            "document_authority_sha256": metadata.document_authority_sha256,
            "created_at": metadata.created_at,
            "updated_at": metadata.updated_at,
            "expires_at": metadata.expires_at,
            "retained_until": metadata.retained_until,
            "revision": metadata.revision,
            "integrity_sha256": metadata.integrity_sha256,
        }

    def verify_integrity(self, tenant_id: str) -> dict[str, object]:
        self._require_tenant(tenant_id)
        self._actor()
        rows = self._records.list(limit=10_001)
        metadata = [
            _normalize_record(raw)
            for raw in rows
            if raw.get("tenant_id") == self.tenant_id
            and raw.get("principal_ref") == self.principal_ref
        ]
        return {
            "schema": INTEGRITY_SCHEMA,
            "ok": True,
            "attachment_count": len(metadata),
            "active_count": sum(item.status == "active" for item in metadata),
            "tombstone_count": sum(item.status != "active" for item in metadata),
            "integrity_sha256": _sha256(
                {
                    "schema": INTEGRITY_SCHEMA,
                    "tenant_id": self.tenant_id,
                    "principal_ref": self.principal_ref,
                    "attachments": sorted(item.integrity_sha256 for item in metadata),
                }
            ),
        }

    def retention_due(
        self, tenant_id: str, *, limit: int = 100
    ) -> tuple[IncidentAttachmentMetadata, ...]:
        self._require_tenant(tenant_id)
        self._actor()
        bounded = _integer(limit, "limit", 1, 1_000)
        now = self._now()
        rows = self._records.list(limit=10_001)
        due = []
        for raw in rows:
            metadata = _normalize_record(raw)
            if (
                metadata.tenant_id == self.tenant_id
                and metadata.principal_ref == self.principal_ref
                and metadata.status in {"active", "tombstoned"}
                and metadata.retained_until <= now
            ):
                due.append(metadata)
        due.sort(key=lambda item: (item.retained_until, item.attachment_id))
        return tuple(due[:bounded])

    def purge_expired(self, tenant_id: str, *, limit: int = 100) -> int:
        self._require_tenant(tenant_id)
        actor = self._actor()
        try:
            authorized = self._maintenance_authorizer()
        except Exception as exc:
            raise IncidentAttachmentPermissionDenied(
                "maintenance authority is unavailable"
            ) from exc
        if authorized is not True:
            raise IncidentAttachmentPermissionDenied("maintenance authority is required")
        due = self.retention_due(tenant_id, limit=limit)
        if not due:
            return 0
        self.verify_integrity(tenant_id)
        now = self._now()
        removed = 0
        for item in due:
            if _matter_refusal(self.tenant_id, item, actor=actor) is not None:
                continue  # a legal matter holds this attachment until it is released
            def mutate(raw: dict[str, Any], expected: IncidentAttachmentMetadata = item) -> None:
                live = _normalize_record(raw)
                if (
                    live.status not in {"active", "tombstoned"}
                    or live.retained_until > now
                    or live.revision != expected.revision
                ):
                    raise IncidentAttachmentConflict("attachment retention state changed")
                result_revision = live.revision + 1
                raw["previous_integrity_sha256"] = live.integrity_sha256
                raw["status"] = "purged"
                raw["safe_display_name"] = None
                raw["tombstoned_at"] = live.tombstoned_at or now
                raw["purged_at"] = now
                _append_history(
                    raw,
                    event_type="purged",
                    actor_ref=actor,
                    created_at=now,
                    changes={"retained_until": live.retained_until},
                    result_revision=result_revision,
                )

            try:
                saved = self._records.update(
                    item.attachment_id,
                    mutate,
                    expected_revision=item.revision,
                    action="retention_purge",
                    actor=actor,
                )
            except RecordConflict:
                continue
            if saved is not None:
                _normalize_record(saved)
                removed += 1
        return removed

    def retry_pending_audits(self, *, limit: int = 100) -> int:
        try:
            return self._records.retry_pending(limit=limit)
        except GovernedRecordBackendError as exc:
            raise IncidentAttachmentConfigError(
                "incident attachment audit authority is unavailable"
            ) from exc


def with_incident_attachment_metadata(
    incident: Mapping[str, Any],
    *,
    store: IncidentAttachmentStore,
    tenant_id: str,
    incident_kind: str,
    include_tombstones: bool = False,
) -> dict[str, Any]:
    """Return one incident response with independently governed attachments.

    This is the integration seam for privacy/security retrieval and mutation
    responses.  The incident mapping is never trusted as authority: the store
    independently resolves the same id and requires the exact current revision
    before adding its bounded attachment projection.
    """

    if not isinstance(incident, Mapping):
        raise IncidentAttachmentValidationError("incident response must be an object")
    incident_id = _identifier(incident.get("id"), "incident_id")
    response_revision = _revision(incident.get("revision"), "incident_revision")
    authority = store._resolve_incident(incident_kind, incident_id)  # noqa: SLF001
    if authority.incident_revision != response_revision:
        raise IncidentAttachmentConflict("incident response revision changed")
    attachments = store.list_for_incident(
        tenant_id,
        incident_kind,
        incident_id,
        include_tombstones=include_tombstones,
    )
    projected = [store.projection(item) for item in attachments]
    response = dict(incident)
    response["attachments"] = projected
    response["attachment_metadata"] = {
        "schema": PROJECTION_SCHEMA,
        "incident_revision": authority.incident_revision,
        "incident_sha256": authority.incident_sha256,
        "incident_authority_sha256": authority.authority_sha256,
        "count": len(projected),
    }
    return response


# Verbose alias makes the response integration intent obvious at call sites.
project_incident_attachment_metadata = with_incident_attachment_metadata


__all__ = [
    "ATTACHMENT_SCHEMA",
    "ATTACHMENT_STATUSES",
    "AUTHORITY_STATES",
    "DEFAULT_MEDIA_TYPES",
    "HISTORY_SCHEMA",
    "INCIDENT_AUTHORITY_SCHEMA",
    "INCIDENT_KINDS",
    "INTEGRITY_SCHEMA",
    "PROJECTION_SCHEMA",
    "REDACTION_STATES",
    "SCHEMA_VERSION",
    "IncidentAttachmentConfigError",
    "IncidentAttachmentConflict",
    "IncidentAttachmentError",
    "IncidentAttachmentIntegrityError",
    "IncidentAttachmentMetadata",
    "IncidentAttachmentNotFound",
    "IncidentAttachmentPermissionDenied",
    "IncidentAttachmentStore",
    "IncidentAttachmentValidationError",
    "IncidentAuthority",
    "enabled",
    "issue_incident_authority",
    "project_incident_attachment_metadata",
    "require_enabled",
    "with_incident_attachment_metadata",
]
