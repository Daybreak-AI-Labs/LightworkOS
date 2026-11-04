"""Strict FastAPI surface for governed incident attachment metadata.

Callers provide only opaque incident/document identifiers, exact expected
revisions/digests and closed lifecycle choices.  Tenant, principal, incident
authority, document metadata, filenames and retention policy are server-owned.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi import Path as ApiPath
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from ._shared import authenticated_subject
from .auth import require_global_permission, require_permission

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_ATTACHMENT_PATTERN = r"^IAT-[0-9a-f]{32}$"
_OP_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"

OpaqueId = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=128, pattern=_ID_PATTERN),
]
OpaquePath = Annotated[
    str,
    ApiPath(min_length=1, max_length=128, pattern=_ID_PATTERN),
]
AttachmentPath = Annotated[
    str,
    ApiPath(min_length=36, max_length=36, pattern=_ATTACHMENT_PATTERN),
]
IdempotencyKey = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=192, pattern=_OP_PATTERN),
]
Digest = Annotated[
    str,
    StringConstraints(strict=True, min_length=64, max_length=64, pattern=_DIGEST_PATTERN),
]
IncidentKind = Literal["privacy", "security"]
RedactionState = Literal["unreviewed", "pending", "redacted", "approved", "not_required"]

_SECURE_HEADERS = {
    "Cache-Control": "no-store, private, max-age=0",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
}
_REQUIRED_METHODS = (
    "create_attachment",
    "update_attachment",
    "delete_attachment",
    "get_attachment",
    "list_for_incident",
    "history",
    "projection",
    "verify_integrity",
    "purge_expired",
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CreateIncidentAttachmentIn(_StrictModel):
    incident_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    incident_sha256: Digest
    document_id: OpaqueId
    document_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    document_authority_sha256: Digest
    sha256: Digest
    redaction_state: RedactionState = "unreviewed"
    idempotency_key: IdempotencyKey


class UpdateIncidentAttachmentIn(_StrictModel):
    expected_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    incident_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    incident_sha256: Digest
    document_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    document_authority_sha256: Digest
    sha256: Digest
    redaction_state: RedactionState
    idempotency_key: IdempotencyKey


class DeleteIncidentAttachmentIn(_StrictModel):
    expected_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    idempotency_key: IdempotencyKey


class PurgeIncidentAttachmentsIn(_StrictModel):
    limit: int = Field(default=100, strict=True, ge=1, le=1_000)


class IncidentAttachmentOut(_StrictModel):
    schema_: Literal["lightwork.incident-attachment-projection.v1"] = Field(alias="schema")
    attachment_id: str
    document_id: str
    safe_display_name: str | None
    media_type: str
    byte_size: int
    sha256: str
    redaction_state: RedactionState
    status: Literal["active", "tombstoned", "purged"]
    authority_state: Literal[
        "active",
        "expired",
        "revoked",
        "stale",
        "unavailable",
        "tombstoned",
        "purged",
    ]
    incident_revision: int
    incident_sha256: str
    document_revision: int
    document_authority_sha256: str
    created_at: float
    updated_at: float
    expires_at: float
    retained_until: float
    revision: int
    integrity_sha256: str


class IncidentAttachmentListOut(_StrictModel):
    schema_: Literal["lightwork.incident-attachment-list.v1"] = Field(alias="schema")
    incident_kind: IncidentKind
    incident_id: str
    count: int
    attachments: list[IncidentAttachmentOut]


class IncidentAttachmentHistoryOut(_StrictModel):
    schema_: Literal["lightwork.incident-attachment-history-list.v1"] = Field(alias="schema")
    attachment_id: str
    count: int
    events: list[dict[str, Any]]


class IncidentAttachmentStatusOut(_StrictModel):
    schema_: Literal["lightwork.incident-attachment-status.v1"] = Field(alias="schema")
    enabled: bool
    configured: bool
    ready: bool
    metadata_only: Literal[True]
    object_store_operational: Literal[False]
    relying_workflow_accepted: Literal[False]


class IncidentAttachmentDependencies:
    """Deployment-owned composition seams for the HTTP adapter."""

    def __init__(
        self,
        *,
        store_factory: Callable[..., Any] | None = None,
        enabled_probe: Callable[[str], bool] | None = None,
        readiness_probe: Callable[[str], bool] | None = None,
    ) -> None:
        for dependency in (store_factory, enabled_probe, readiness_probe):
            if dependency is not None and not callable(dependency):
                raise TypeError("incident attachment dependency must be callable")
        self.store_factory = store_factory
        self.enabled_probe = enabled_probe
        self.readiness_probe = readiness_probe


def _ops():
    from maverick import incident_attachment_metadata as attachments

    return attachments


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using incident attachment metadata",
        )
    return tenant


def _principal(request: Request, tenant_id: str) -> str:
    subject = authenticated_subject(
        request, error_detail="an authenticated principal is required for incident attachments",
    )
    # The store's own derivation, so the uploader reference matches what it records.
    try:
        return _ops().principal_ref_for_subject(tenant_id, subject)
    except ValueError as exc:  # a workspace id the store cannot name is unavailable, as in the store factory
        raise HTTPException(
            status_code=503,
            detail="incident attachment authority is unavailable",
        ) from exc


def _dependency(request: Request, name: str, fallback: object) -> object:
    try:
        return getattr(request.app.state, name)
    except AttributeError:
        return fallback


def _secure(response: Response) -> None:
    for name, value in _SECURE_HEADERS.items():
        response.headers[name] = value


def create_incident_attachment_metadata_router(  # noqa: C901 - route-local trust boundaries
    dependencies: IncidentAttachmentDependencies | None = None,
) -> APIRouter:
    deps = dependencies or IncidentAttachmentDependencies()
    router = APIRouter(
        prefix="/incident-attachments",
        tags=["incident-attachments"],
    )

    def probes(request: Request, tenant: str) -> tuple[bool, bool, bool]:
        ops = _ops()
        enabled_probe = _dependency(
            request,
            "incident_attachment_metadata_enabled_probe",
            deps.enabled_probe,
        )
        try:
            feature_enabled = (
                enabled_probe(tenant) if callable(enabled_probe) else ops.enabled()
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="incident attachment configuration is unavailable",
            ) from exc
        if type(feature_enabled) is not bool:
            raise HTTPException(
                status_code=503,
                detail="incident attachment configuration is unavailable",
            )
        factory = _dependency(
            request,
            "incident_attachment_metadata_store_factory",
            deps.store_factory,
        )
        readiness_probe = _dependency(
            request,
            "incident_attachment_metadata_readiness_probe",
            deps.readiness_probe,
        )
        configured = callable(factory) and callable(readiness_probe)
        ready = False
        if feature_enabled and configured:
            try:
                ready = readiness_probe(tenant)  # type: ignore[operator]
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                raise HTTPException(
                    status_code=503,
                    detail="incident attachment readiness is unavailable",
                ) from exc
            if type(ready) is not bool:
                raise HTTPException(
                    status_code=503,
                    detail="incident attachment readiness is unavailable",
                )
        return feature_enabled, configured, ready

    async def composition(request: Request):
        ops = _ops()
        tenant = _tenant_id()
        feature_enabled, configured, ready = await run_in_threadpool(
            probes, request, tenant
        )
        if not feature_enabled:
            raise HTTPException(
                status_code=403,
                detail="incident attachment metadata is disabled",
            )
        if not configured or ready is not True:
            raise HTTPException(
                status_code=503,
                detail="incident attachment operational readiness is not verified",
            )
        principal = _principal(request, tenant)
        factory = _dependency(
            request,
            "incident_attachment_metadata_store_factory",
            deps.store_factory,
        )
        try:
            store = await run_in_threadpool(
                factory,  # type: ignore[arg-type]
                tenant_id=tenant,
                principal_ref=principal,
                request=request,
            )
            valid = (
                store.tenant_id == tenant
                and store.principal_ref == principal
                and all(callable(getattr(store, method, None)) for method in _REQUIRED_METHODS)
                and isinstance(store.backend_kind, str)
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except ops.IncidentAttachmentPermissionDenied as exc:
            raise HTTPException(
                status_code=403,
                detail="incident attachment action is not authorized",
            ) from exc
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="incident attachment authority is unavailable",
            ) from exc
        if not valid:
            raise HTTPException(
                status_code=503,
                detail="incident attachment authority is unavailable",
            )
        return ops, tenant, store

    async def call(ops, function, *args, **kwargs):
        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except ops.IncidentAttachmentNotFound as exc:
            raise HTTPException(
                status_code=404,
                detail="incident attachment was not found",
            ) from exc
        except ops.IncidentAttachmentPermissionDenied as exc:
            raise HTTPException(
                status_code=403,
                detail="incident attachment action is not authorized",
            ) from exc
        except ops.IncidentAttachmentConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ops.IncidentAttachmentValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except (
            ops.IncidentAttachmentConfigError,
            ops.IncidentAttachmentIntegrityError,
        ) as exc:
            raise HTTPException(
                status_code=503,
                detail="incident attachment authority is unavailable",
            ) from exc

    @router.get("/status", response_model=IncidentAttachmentStatusOut)
    async def status(request: Request, response: Response) -> Mapping[str, object]:
        require_permission(request, "view")
        tenant = _tenant_id()
        feature_enabled, configured, ready = await run_in_threadpool(
            probes, request, tenant
        )
        _secure(response)
        return {
            "schema": "lightwork.incident-attachment-status.v1",
            "enabled": feature_enabled,
            "configured": configured,
            "ready": ready,
            "metadata_only": True,
            "object_store_operational": False,
            "relying_workflow_accepted": False,
        }

    @router.get("/integrity")
    async def integrity(request: Request, response: Response) -> Mapping[str, object]:
        require_permission(request, "operate")
        ops, tenant, store = await composition(request)
        value = await call(ops, store.verify_integrity, tenant)
        _secure(response)
        return value

    @router.post("/retention/purge")
    async def purge_retention(
        request: Request,
        body: PurgeIncidentAttachmentsIn,
        response: Response,
    ) -> Mapping[str, object]:
        require_global_permission(request, "admin")
        ops, tenant, store = await composition(request)
        count = await call(ops, store.purge_expired, tenant, limit=body.limit)
        _secure(response)
        return {
            "schema": "lightwork.incident-attachment-retention.v1",
            "purged": count,
        }

    @router.get(
        "/{incident_kind}/{incident_id}",
        response_model=IncidentAttachmentListOut,
    )
    async def list_attachments(
        request: Request,
        response: Response,
        incident_kind: IncidentKind,
        incident_id: OpaquePath,
        include_tombstones: bool = Query(default=False),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> Mapping[str, object]:
        require_permission(request, "view")
        ops, tenant, store = await composition(request)
        records = await call(
            ops,
            store.list_for_incident,
            tenant,
            incident_kind,
            incident_id,
            include_tombstones=include_tombstones,
            limit=limit,
        )
        projections = [await call(ops, store.projection, item) for item in records]
        _secure(response)
        return {
            "schema": "lightwork.incident-attachment-list.v1",
            "incident_kind": incident_kind,
            "incident_id": incident_id,
            "count": len(projections),
            "attachments": projections,
        }

    @router.post(
        "/{incident_kind}/{incident_id}",
        response_model=IncidentAttachmentOut,
        status_code=201,
    )
    async def create_attachment(
        request: Request,
        body: CreateIncidentAttachmentIn,
        response: Response,
        incident_kind: IncidentKind,
        incident_id: OpaquePath,
    ) -> Mapping[str, object]:
        require_permission(request, "operate")
        ops, tenant, store = await composition(request)
        record = await call(
            ops,
            store.create_attachment,
            tenant,
            incident_kind=incident_kind,
            incident_id=incident_id,
            incident_revision=body.incident_revision,
            incident_sha256=body.incident_sha256,
            document_id=body.document_id,
            document_revision=body.document_revision,
            document_authority_sha256=body.document_authority_sha256,
            sha256=body.sha256,
            redaction_state=body.redaction_state,
            idempotency_key=body.idempotency_key,
        )
        projection = await call(ops, store.projection, record)
        _secure(response)
        return projection

    @router.get(
        "/{incident_kind}/{incident_id}/{attachment_id}",
        response_model=IncidentAttachmentOut,
    )
    async def get_attachment(
        request: Request,
        response: Response,
        incident_kind: IncidentKind,
        incident_id: OpaquePath,
        attachment_id: AttachmentPath,
    ) -> Mapping[str, object]:
        require_permission(request, "view")
        ops, tenant, store = await composition(request)
        record = await call(ops, store.get_attachment, tenant, attachment_id)
        if record.incident_kind != incident_kind or record.incident_id != incident_id:
            raise HTTPException(status_code=404, detail="incident attachment was not found")
        projection = await call(ops, store.projection, record)
        _secure(response)
        return projection

    @router.patch(
        "/{incident_kind}/{incident_id}/{attachment_id}",
        response_model=IncidentAttachmentOut,
    )
    async def update_attachment(
        request: Request,
        body: UpdateIncidentAttachmentIn,
        response: Response,
        incident_kind: IncidentKind,
        incident_id: OpaquePath,
        attachment_id: AttachmentPath,
    ) -> Mapping[str, object]:
        require_permission(request, "operate")
        ops, tenant, store = await composition(request)
        current = await call(ops, store.get_attachment, tenant, attachment_id)
        if current.incident_kind != incident_kind or current.incident_id != incident_id:
            raise HTTPException(status_code=404, detail="incident attachment was not found")
        record = await call(
            ops,
            store.update_attachment,
            tenant,
            attachment_id,
            expected_revision=body.expected_revision,
            incident_revision=body.incident_revision,
            incident_sha256=body.incident_sha256,
            document_revision=body.document_revision,
            document_authority_sha256=body.document_authority_sha256,
            sha256=body.sha256,
            redaction_state=body.redaction_state,
            idempotency_key=body.idempotency_key,
        )
        projection = await call(ops, store.projection, record)
        _secure(response)
        return projection

    @router.delete(
        "/{incident_kind}/{incident_id}/{attachment_id}",
        response_model=IncidentAttachmentOut,
    )
    async def delete_attachment(
        request: Request,
        body: DeleteIncidentAttachmentIn,
        response: Response,
        incident_kind: IncidentKind,
        incident_id: OpaquePath,
        attachment_id: AttachmentPath,
    ) -> Mapping[str, object]:
        require_permission(request, "operate")
        ops, tenant, store = await composition(request)
        current = await call(ops, store.get_attachment, tenant, attachment_id)
        if current.incident_kind != incident_kind or current.incident_id != incident_id:
            raise HTTPException(status_code=404, detail="incident attachment was not found")
        record = await call(
            ops,
            store.delete_attachment,
            tenant,
            attachment_id,
            expected_revision=body.expected_revision,
            idempotency_key=body.idempotency_key,
        )
        projection = await call(ops, store.projection, record)
        _secure(response)
        return projection

    @router.get(
        "/{incident_kind}/{incident_id}/{attachment_id}/history",
        response_model=IncidentAttachmentHistoryOut,
    )
    async def attachment_history(
        request: Request,
        response: Response,
        incident_kind: IncidentKind,
        incident_id: OpaquePath,
        attachment_id: AttachmentPath,
    ) -> Mapping[str, object]:
        require_permission(request, "view")
        ops, tenant, store = await composition(request)
        current = await call(ops, store.get_attachment, tenant, attachment_id)
        if current.incident_kind != incident_kind or current.incident_id != incident_id:
            raise HTTPException(status_code=404, detail="incident attachment was not found")
        events = await call(ops, store.history, tenant, attachment_id)
        _secure(response)
        return {
            "schema": "lightwork.incident-attachment-history-list.v1",
            "attachment_id": attachment_id,
            "count": len(events),
            "events": list(events),
        }

    return router


router = create_incident_attachment_metadata_router()


__all__ = [
    "CreateIncidentAttachmentIn",
    "DeleteIncidentAttachmentIn",
    "IncidentAttachmentDependencies",
    "IncidentAttachmentHistoryOut",
    "IncidentAttachmentListOut",
    "IncidentAttachmentOut",
    "IncidentAttachmentStatusOut",
    "PurgeIncidentAttachmentsIn",
    "UpdateIncidentAttachmentIn",
    "create_incident_attachment_metadata_router",
    "router",
]
