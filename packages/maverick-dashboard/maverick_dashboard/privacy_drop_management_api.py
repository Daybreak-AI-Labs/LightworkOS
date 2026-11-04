"""Strict tenant-bound API for California DROP request management.

HTTP callers select only an externally assigned DROP id and a closed operation.
Tenant, actor, broker registration, subject binding, DSAR composition, outcome
evidence, principal equivalence and retention authority are server-owned.  Raw
identity fields, attachments, provider credentials and caller-supplied adapter
authority are not accepted or returned.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Callable, Mapping
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi import Path as ApiPath
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from ._shared import authenticated_subject
from .auth import require_global_permission, require_permission

IdempotencyKey = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$",
    ),
]
Language = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=2,
        max_length=12,
        pattern=r"^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})?$",
    ),
]
TemplateId = Annotated[
    str,
    StringConstraints(
        strict=True,
        pattern=(
            r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-5][0-9A-Fa-f]{3}-"
            r"[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$"
        ),
    ),
]
DropId = Annotated[int, ApiPath(ge=1, le=2_147_483_647)]

_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_REQUIRED_STORE_METHODS = (
    "create_request",
    "update_status",
    "get_request",
    "verify_integrity",
)
_MISSING = object()
_SECURE_HEADERS = {
    "Cache-Control": "no-store, private, max-age=0",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
}


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CreateDROPRequestIn(_StrictModel):
    request_type: Literal["DataDeletion", "OptOut"]
    template_id: TemplateId
    language: Language
    expected_revision: int = Field(default=0, strict=True, ge=0, le=0)
    idempotency_key: IdempotencyKey


class UpdateDROPStatusIn(_StrictModel):
    status: Literal["EXEMPTED", "DELETED", "OPTED_OUT", "NOT_FOUND"]
    expected_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    idempotency_key: IdempotencyKey


class DROPManagementDependencies:
    """Lazy server-owned composition seams for deployment and isolated tests."""

    def __init__(
        self,
        *,
        store_factory: Callable[..., Any] | None = None,
        authority_resolver: Callable[..., Any] | None = None,
        enabled_probe: Callable[[str], bool] | None = None,
        readiness_probe: Callable[[str], bool] | None = None,
    ) -> None:
        for dependency in (
            store_factory,
            authority_resolver,
            enabled_probe,
            readiness_probe,
        ):
            if dependency is not None and not callable(dependency):
                raise TypeError("DROP management dependency must be callable")
        self.store_factory = store_factory
        self.authority_resolver = authority_resolver
        self.enabled_probe = enabled_probe
        self.readiness_probe = readiness_probe


def _ops():
    from maverick import privacy_drop_management as ops

    return ops


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using DROP management",
        )
    return tenant


def _principal(request: Request, tenant_id: str) -> str:
    subject = authenticated_subject(
        request, error_detail="an authenticated principal is required for DROP management",
    )
    digest = hashlib.sha256(
        f"lightwork.privacy-drop.identity.v1:{tenant_id}:{subject}".encode()
    ).hexdigest()
    return f"drop-principal-{digest[:32]}"


def _secure(response: Response) -> None:
    for name, value in _SECURE_HEADERS.items():
        response.headers[name] = value


def _dependency(request: Request, state_name: str, fallback: object) -> object:
    try:
        return getattr(request.app.state, state_name)
    except AttributeError:
        return fallback


def _probe_status(
    request: Request,
    dependencies: DROPManagementDependencies,
    ops: Any,
    tenant_id: str,
) -> tuple[bool, bool]:
    probe = _dependency(
        request,
        "privacy_drop_management_enabled_probe",
        dependencies.enabled_probe,
    )
    custom_probe = probe is not None
    try:
        if custom_probe:
            if not callable(probe):
                raise TypeError("DROP enabled probe is not callable")
            result = probe(tenant_id)
        else:
            from maverick.paths import tenant_scope

            with tenant_scope(tenant=tenant_id):
                result = ops.enabled()
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="DROP management configuration is unavailable",
        ) from exc
    if type(result) is not bool:
        raise HTTPException(
            status_code=503,
            detail="DROP management configuration is unavailable",
        )
    return result, custom_probe


def _require_enabled(enabled: bool) -> None:
    if enabled is not True:
        raise HTTPException(status_code=403, detail="DROP management is disabled")


def _reject_query(request: Request) -> None:
    if request.query_params:
        raise HTTPException(status_code=422, detail="DROP request query is invalid")


def _record_out(
    ops: Any,
    value: object,
    *,
    tenant_id: str,
    authority: object,
) -> dict[str, object]:
    try:
        if type(value) is not ops.DROPRequestRecord:
            raise TypeError("unexpected DROP record type")
        if type(authority) is not ops.DROPRecordAuthority:
            raise TypeError("unexpected DROP authority type")
        if (
            value.tenant_id != tenant_id
            or authority.tenant_id != tenant_id
            or value.drop_id != authority.drop_id
            or value.request_type != authority.request_type
            or value.authority_sha256 != authority.authority_sha256
            or value.request_type not in ops.REQUEST_TYPES
            or value.status not in ops.DROP_STATUSES
            or isinstance(value.drop_id, bool)
            or not isinstance(value.drop_id, int)
            or not 1 <= value.drop_id <= 2_147_483_647
            or isinstance(value.revision, bool)
            or not isinstance(value.revision, int)
            or value.revision not in (1, 2)
            or not _REF_RE.fullmatch(value.request_queue_ref_id)
            or not _REF_RE.fullmatch(value.internal_case_id)
            or not _DIGEST_RE.fullmatch(value.authority_sha256)
            or not _DIGEST_RE.fullmatch(value.integrity_sha256)
        ):
            raise ValueError("DROP record binding changed")
        UUID(value.request_queue_id)
        times = (value.created_at, value.updated_at, value.retained_until)
        if (
            any(
                isinstance(item, bool)
                or not isinstance(item, (int, float))
                or not math.isfinite(float(item))
                for item in times
            )
            or not 0 < value.created_at <= value.updated_at < value.retained_until
        ):
            raise ValueError("DROP record time changed")
        if value.status == "PENDING":
            if value.revision != 1 or value.outcome_evidence_sha256 != "":
                raise ValueError("DROP pending state changed")
        elif value.revision != 2 or not _DIGEST_RE.fullmatch(value.outcome_evidence_sha256):
            raise ValueError("DROP terminal state changed")
    except (AttributeError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail="DROP management returned an invalid record",
        ) from exc
    return {
        "schema": "lightwork.privacy-drop-request-api.v1",
        "drop_id": value.drop_id,
        "request_type": value.request_type,
        "status": value.status,
        "revision": value.revision,
        "request_queue_id": value.request_queue_id,
        "request_queue_ref_id": value.request_queue_ref_id,
        "internal_case_id": value.internal_case_id,
        "authority_sha256": value.authority_sha256,
        "outcome_evidence_sha256": value.outcome_evidence_sha256,
        "principal_key_revision": value.principal_key_revision,
        "status_actor_key_revision": value.status_actor_key_revision,
        "status_reviewer_key_revision": value.status_reviewer_key_revision,
        "created_at": value.created_at,
        "updated_at": value.updated_at,
        "retained_until": value.retained_until,
        "integrity_sha256": value.integrity_sha256,
    }


def create_privacy_drop_management_router(  # noqa: C901 - explicit trust-boundary routing
    dependencies: DROPManagementDependencies | None = None,
) -> APIRouter:
    deps = dependencies or DROPManagementDependencies()
    router = APIRouter(prefix="/privacy/drop", tags=["privacy-drop-management"])

    def capability(request: Request, ops: Any, tenant: str) -> tuple[bool, bool]:
        return _probe_status(request, deps, ops, tenant)

    async def readiness(
        request: Request,
        tenant: str,
        *,
        enabled: bool,
        configured: bool,
    ) -> tuple[bool, bool]:
        """Evaluate the deployment-owned readiness authority without side effects."""

        readiness_probe = _dependency(
            request,
            "privacy_drop_management_readiness_probe",
            deps.readiness_probe,
        )
        if not enabled or not configured or not callable(readiness_probe):
            return False, False
        try:
            readiness_result = await run_in_threadpool(readiness_probe, tenant)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="DROP management readiness is unavailable",
            ) from exc
        if type(readiness_result) is not bool:
            raise HTTPException(
                status_code=503,
                detail="DROP management readiness is unavailable",
            )
        return True, readiness_result

    async def composition(request: Request, *, resolver_required: bool = True):
        ops = _ops()
        tenant = _tenant_id()
        enabled, _configured = capability(request, ops, tenant)
        _require_enabled(enabled)
        factory = _dependency(
            request,
            "privacy_drop_management_store_factory",
            deps.store_factory,
        )
        resolver = _dependency(
            request,
            "privacy_drop_record_authority_resolver",
            deps.authority_resolver,
        )
        if not callable(factory) or (resolver_required and not callable(resolver)):
            raise HTTPException(
                status_code=503,
                detail="DROP management composition is unavailable",
            )
        configured = bool(callable(factory) and callable(resolver))
        _checked, readiness_verified = await readiness(
            request,
            tenant,
            enabled=enabled,
            configured=configured,
        )
        if readiness_verified is not True:
            raise HTTPException(
                status_code=503,
                detail="DROP management operational readiness is not verified",
            )
        actor = _principal(request, tenant)
        try:
            store = await run_in_threadpool(
                factory,
                tenant_id=tenant,
                actor_ref=actor,
                request=request,
            )
            store_tenant = store.tenant_id
            methods_ready = all(
                callable(getattr(store, method, None)) for method in _REQUIRED_STORE_METHODS
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="DROP management store is unavailable",
            ) from exc
        if store_tenant != tenant or not methods_ready:
            raise HTTPException(
                status_code=503,
                detail="DROP management store is unavailable",
            )
        return ops, tenant, actor, store, resolver

    async def call(ops: Any, function: Callable[..., Any], *args: object, **kwargs: object):
        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except ops.DROPManagementNotFound as exc:
            raise HTTPException(status_code=404, detail="DROP request was not found") from exc
        except ops.DROPManagementConflict as exc:
            raise HTTPException(
                status_code=409,
                detail="DROP request conflicts with current authority or state",
            ) from exc
        except ops.DROPManagementValidationError as exc:
            raise HTTPException(status_code=422, detail="DROP request is invalid") from exc
        except ops.DROPManagementIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail="DROP management integrity verification failed",
            ) from exc
        except ops.DROPManagementConfigError as exc:
            raise HTTPException(
                status_code=503,
                detail="DROP management dependency is unavailable",
            ) from exc
        except ops.DROPManagementError as exc:
            raise HTTPException(status_code=503, detail="DROP management failed") from exc
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(status_code=503, detail="DROP management failed") from exc

    async def resolve_authority(
        ops: Any,
        resolver: Callable[..., Any],
        *,
        tenant: str,
        drop_id: int,
        request: Request,
        request_type: str | None = None,
        template_id: str | None = None,
        language: str | None = None,
    ):
        try:
            authority = await run_in_threadpool(
                resolver,
                tenant_id=tenant,
                drop_id=drop_id,
                request_type=request_type,
                template_id=template_id,
                language=language,
                request=request,
            )
            if type(authority) is not ops.DROPRecordAuthority:
                raise TypeError("unexpected DROP authority type")
            authority = authority.normalized()
        except ops.DROPManagementNotFound as exc:
            raise HTTPException(status_code=404, detail="DROP request was not found") from exc
        except (
            ops.DROPManagementConflict,
            ops.DROPManagementValidationError,
        ) as exc:
            raise HTTPException(status_code=409, detail="DROP record authority changed") from exc
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="DROP record authority is unavailable",
            ) from exc
        if (
            authority.tenant_id != tenant
            or authority.drop_id != drop_id
            or (request_type is not None and authority.request_type != request_type)
            or (template_id is not None and authority.template_id != template_id)
            or (language is not None and authority.language != language.lower())
        ):
            raise HTTPException(status_code=409, detail="DROP record authority changed")
        return authority

    @router.get("/status")
    async def status(request: Request, response: Response) -> dict[str, object]:
        require_permission(request, "view")
        _reject_query(request)
        ops = _ops()
        tenant = _tenant_id()
        is_enabled, custom_probe = capability(request, ops, tenant)
        factory = _dependency(
            request,
            "privacy_drop_management_store_factory",
            deps.store_factory,
        )
        resolver = _dependency(
            request,
            "privacy_drop_record_authority_resolver",
            deps.authority_resolver,
        )
        configured = bool(callable(factory) and callable(resolver))
        readiness_probe = _dependency(
            request,
            "privacy_drop_management_readiness_probe",
            deps.readiness_probe,
        )
        readiness_checked, readiness_verified = await readiness(
            request,
            tenant,
            enabled=is_enabled,
            configured=configured,
        )
        readiness_reporter = _dependency(
            request,
            "privacy_drop_management_readiness_report",
            None,
        )
        readiness_report: Mapping[str, object] = {}
        if is_enabled and configured and callable(readiness_reporter):
            try:
                value = await run_in_threadpool(readiness_reporter, tenant)
                if not isinstance(value, Mapping):
                    raise TypeError("DROP readiness report is invalid")
                readiness_report = dict(value)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                raise HTTPException(
                    status_code=503,
                    detail="DROP management readiness is unavailable",
                ) from exc
        configured_for_attempt = bool(
            readiness_report.get("configured_for_attempt", configured)
        )
        locally_operational = bool(
            readiness_report.get("locally_operational", readiness_verified)
        )
        _secure(response)
        return {
            "schema": "lightwork.privacy-drop-management-status.v1",
            "enabled": is_enabled,
            "configured": configured,
            "configured_for_attempt": configured_for_attempt,
            "locally_operational": locally_operational,
            "request_executable": bool(readiness_report.get("request_executable", False)),
            "request_execution_blocker": str(
                readiness_report.get("request_execution_blocker", "readiness_unverified")
            ),
            "ready": bool(is_enabled and configured_for_attempt and locally_operational),
            "configuration": {
                "custom_enabled_probe_configured": custom_probe,
                "store_factory_configured": callable(factory),
                "authority_resolver_configured": callable(resolver),
                "operational_readiness_probe_configured": callable(readiness_probe),
                "operational_readiness_checked": readiness_checked,
                "operational_readiness_verified": readiness_verified,
                "store_opened_for_status": bool(readiness_report),
                "record_authority_resolved_for_status": False,
            },
            "authority_counts": {
                "active_brokers": int(readiness_report.get("active_brokers", 0)),
                "active_records": int(readiness_report.get("active_records", 0)),
                "approved_outcomes": int(readiness_report.get("approved_outcomes", 0)),
            },
            "scheduler": readiness_report.get(
                "scheduler",
                {"installed": False, "running": False, "healthy": False},
            ),
            "request_types": ["DataDeletion", "OptOut"],
            "terminal_statuses": ["DELETED", "EXEMPTED", "NOT_FOUND", "OPTED_OUT"],
            "raw_identity_fields_accepted": False,
            "caller_selected_tenant": False,
            "caller_selected_actor": False,
            "caller_selected_subject_binding": False,
            "caller_selected_broker_registration": False,
            "independent_outcome_evidence_required": True,
            "network_io": ops.NETWORK_IO,
            "live_drop_interoperability_verified": ops.LIVE_DROP_INTEROPERABILITY_VERIFIED,
            "legal_acceptance_verified": ops.LEGAL_ACCEPTANCE_VERIFIED,
        }

    @router.get("/integrity")
    async def integrity(request: Request, response: Response) -> dict[str, object]:
        require_global_permission(request, "audit")
        _reject_query(request)
        ops, _tenant, _actor, store, _resolver = await composition(
            request,
            resolver_required=False,
        )
        valid = await call(ops, store.verify_integrity)
        if valid is not True:
            raise HTTPException(
                status_code=503,
                detail="DROP management integrity verification failed",
            )
        _secure(response)
        return {
            "schema": "lightwork.privacy-drop-management-integrity.v1",
            "valid": True,
        }

    @router.post("/{drop_id}/request", status_code=201)
    async def create_request(
        request: Request,
        response: Response,
        drop_id: DropId,
        body: CreateDROPRequestIn,
    ) -> dict[str, object]:
        require_permission(request, "operate")
        _reject_query(request)
        ops, tenant, _actor, store, resolver = await composition(request)
        authority = await resolve_authority(
            ops,
            resolver,
            tenant=tenant,
            drop_id=drop_id,
            request_type=body.request_type,
            template_id=str(body.template_id),
            language=body.language,
            request=request,
        )
        record = await call(
            ops,
            store.create_request,
            authority,
            expected_revision=body.expected_revision,
            idempotency_key=body.idempotency_key,
        )
        _secure(response)
        return _record_out(ops, record, tenant_id=tenant, authority=authority)

    @router.put("/{drop_id}")
    async def update_status(
        request: Request,
        response: Response,
        drop_id: DropId,
        body: UpdateDROPStatusIn,
    ) -> dict[str, object]:
        require_global_permission(request, "admin")
        _reject_query(request)
        ops, tenant, actor, store, resolver = await composition(request)
        authority = await resolve_authority(
            ops,
            resolver,
            tenant=tenant,
            drop_id=drop_id,
            request=request,
        )
        record = await call(
            ops,
            store.update_status,
            authority,
            status=body.status,
            expected_revision=body.expected_revision,
            idempotency_key=body.idempotency_key,
            actor_ref=actor,
        )
        _secure(response)
        return _record_out(ops, record, tenant_id=tenant, authority=authority)

    @router.get("/{drop_id}")
    async def get_request(
        request: Request,
        response: Response,
        drop_id: DropId,
    ) -> dict[str, object]:
        require_permission(request, "view")
        _reject_query(request)
        ops, tenant, _actor, store, resolver = await composition(request)
        authority = await resolve_authority(
            ops,
            resolver,
            tenant=tenant,
            drop_id=drop_id,
            request=request,
        )
        record = await call(ops, store.get_request, authority)
        _secure(response)
        return _record_out(ops, record, tenant_id=tenant, authority=authority)

    return router


router = create_privacy_drop_management_router()

__all__ = [
    "CreateDROPRequestIn",
    "DROPManagementDependencies",
    "UpdateDROPStatusIn",
    "create_privacy_drop_management_router",
    "router",
]
