"""Strict HTTP adapter for AI-entity review and remediation tasks.

Tenant, actor and AI-entity authority are always server-owned.  HTTP callers
may select only a task operation and closed task fields; they cannot inject an
entity authority, provider adapter, tenant or principal.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import asdict
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi import Path as ApiPath
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from ._shared import authenticated_subject
from .auth import require_global_permission, require_permission

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_OP_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$"
OpaqueId = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=128, pattern=_ID_PATTERN),
]
ObjectPath = Annotated[
    str,
    ApiPath(min_length=1, max_length=128, pattern=_ID_PATTERN),
]
IdempotencyKey = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=192, pattern=_OP_PATTERN),
]
TaskKind = Literal["review", "remediation"]
TaskStatus = Literal["open", "in_progress", "blocked", "resolved", "dismissed"]
TaskPriority = Literal["low", "medium", "high", "critical"]

_REQUIRED_STORE_METHODS = (
    "create_task",
    "update_task",
    "get_task",
    "list_tasks",
    "history",
    "verify_integrity",
    "retention_due",
    "purge_expired",
)
_SECURE_HEADERS = {
    "Cache-Control": "no-store, private, max-age=0",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
}


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CreateTaskIn(_StrictModel):
    entity_id: OpaqueId
    entity_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    kind: TaskKind
    title: str = Field(strict=True, min_length=1, max_length=500)
    description: str = Field(default="", strict=True, max_length=16_000)
    assignee_ref: OpaqueId | None = None
    collaborator_refs: list[OpaqueId] = Field(default_factory=list, max_length=64)
    priority: TaskPriority = "medium"
    due_at: float | None = Field(default=None, strict=True, gt=0)
    idempotency_key: IdempotencyKey


class UpdateTaskIn(_StrictModel):
    expected_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    status: TaskStatus | None = None
    assignee_ref: OpaqueId | None = None
    collaborator_refs: list[OpaqueId] | None = Field(default=None, max_length=64)
    priority: TaskPriority | None = None
    due_at: float | None = Field(default=None, strict=True, gt=0)
    idempotency_key: IdempotencyKey


class PurgeIn(_StrictModel):
    limit: int = Field(default=100, strict=True, ge=1, le=1_000)


class AIEntityTaskDependencies:
    """Deployment-owned task composition seams."""

    def __init__(
        self,
        *,
        store_factory: Callable[..., Any] | None = None,
        enabled_probe: Callable[[str], bool] | None = None,
        readiness_probe: Callable[[str], bool] | None = None,
    ) -> None:
        for dependency in (store_factory, enabled_probe, readiness_probe):
            if dependency is not None and not callable(dependency):
                raise TypeError("AI-entity task dependency must be callable")
        self.store_factory = store_factory
        self.enabled_probe = enabled_probe
        self.readiness_probe = readiness_probe


def _ops():
    from maverick import ai_entity_tasks as tasks

    return tasks


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using AI-entity tasks",
        )
    return tenant


def _principal(request: Request, tenant_id: str) -> str:
    subject = authenticated_subject(
        request, error_detail="an authenticated principal is required for AI-entity tasks",
    )
    digest = hashlib.sha256(
        f"lightwork.ai-entity-task.identity.v1:{tenant_id}:{subject}".encode()
    ).hexdigest()
    return f"ai-task-principal-{digest[:32]}"


def _dependency(request: Request, state_name: str, fallback: object) -> object:
    try:
        return getattr(request.app.state, state_name)
    except AttributeError:
        return fallback


def _secure(response: Response) -> None:
    for name, value in _SECURE_HEADERS.items():
        response.headers[name] = value


def _jsonable(value: object) -> object:
    if hasattr(value, "__dataclass_fields__"):
        return asdict(value)  # type: ignore[arg-type]
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def create_ai_entity_tasks_router(  # noqa: C901 - route-local trust boundaries
    dependencies: AIEntityTaskDependencies | None = None,
) -> APIRouter:
    deps = dependencies or AIEntityTaskDependencies()
    router = APIRouter(prefix="/ai-entity-tasks", tags=["ai-entity-tasks"])

    def probes(request: Request, tenant: str) -> tuple[bool, bool, bool]:
        ops = _ops()
        enabled_probe = _dependency(
            request, "ai_entity_tasks_enabled_probe", deps.enabled_probe
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
                detail="AI-entity task configuration is unavailable",
            ) from exc
        if type(feature_enabled) is not bool:
            raise HTTPException(
                status_code=503,
                detail="AI-entity task configuration is unavailable",
            )
        factory = _dependency(request, "ai_entity_tasks_store_factory", deps.store_factory)
        readiness_probe = _dependency(
            request, "ai_entity_tasks_readiness_probe", deps.readiness_probe
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
                    detail="AI-entity task readiness is unavailable",
                ) from exc
            if type(ready) is not bool:
                raise HTTPException(
                    status_code=503,
                    detail="AI-entity task readiness is unavailable",
                )
        return feature_enabled, configured, ready

    async def composition(request: Request):
        ops = _ops()
        tenant = _tenant_id()
        feature_enabled, configured, ready = await run_in_threadpool(
            probes, request, tenant
        )
        if not feature_enabled:
            raise HTTPException(status_code=403, detail="AI-entity tasks are disabled")
        if not configured or ready is not True:
            raise HTTPException(
                status_code=503,
                detail="AI-entity task operational readiness is not verified",
            )
        principal = _principal(request, tenant)
        factory = _dependency(request, "ai_entity_tasks_store_factory", deps.store_factory)
        try:
            store = await run_in_threadpool(
                factory,  # type: ignore[arg-type]
                tenant_id=tenant,
                principal_ref=principal,
                request=request,
            )
            bound_tenant = store.tenant_id
            contract_valid = all(
                callable(getattr(store, method, None)) for method in _REQUIRED_STORE_METHODS
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="AI-entity task store is unavailable",
            ) from exc
        if bound_tenant != tenant or not contract_valid:
            raise HTTPException(
                status_code=503,
                detail="AI-entity task store is unavailable",
            )
        return ops, tenant, store

    async def call(ops, function, *args, **kwargs):
        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except ops.AIEntityTaskNotFound as exc:
            raise HTTPException(status_code=404, detail="AI-entity task was not found") from exc
        except ops.AIEntityTaskPermissionDenied as exc:
            raise HTTPException(
                status_code=403,
                detail="AI-entity task action is not authorized",
            ) from exc
        except ops.AIEntityTaskConflict as exc:
            raise HTTPException(
                status_code=409,
                detail="AI-entity task conflicts with current authority or state",
            ) from exc
        except ops.AIEntityTaskValidationError as exc:
            raise HTTPException(status_code=422, detail="AI-entity task request is invalid") from exc
        except ops.AIEntityTaskIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail="AI-entity task integrity verification failed",
            ) from exc
        except ops.AIEntityTaskConfigError as exc:
            raise HTTPException(
                status_code=503,
                detail="AI-entity task dependency is unavailable",
            ) from exc
        except ops.AIEntityTaskError as exc:
            raise HTTPException(status_code=503, detail="AI-entity task operation failed") from exc

    @router.get("/status")
    async def status(request: Request, response: Response) -> dict[str, object]:
        require_permission(request, "view")
        tenant = _tenant_id()
        feature_enabled, configured, ready = await run_in_threadpool(
            probes, request, tenant
        )
        factory = _dependency(request, "ai_entity_tasks_store_factory", deps.store_factory)
        readiness_probe = _dependency(
            request, "ai_entity_tasks_readiness_probe", deps.readiness_probe
        )
        _secure(response)
        return {
            "schema": "lightwork.ai-entity-task-api-status.v1",
            "enabled": feature_enabled,
            "configured": configured,
            "ready": bool(feature_enabled and configured and ready),
            "configuration": {
                "store_factory_configured": callable(factory),
                "readiness_probe_configured": callable(readiness_probe),
                "store_opened_for_status": False,
                "entity_authority_resolved_for_status": False,
            },
            "task_kinds": ["remediation", "review"],
            "statuses": ["blocked", "dismissed", "in_progress", "open", "resolved"],
            "priorities": ["critical", "high", "low", "medium"],
            "tenant_or_actor_caller_fields_accepted": False,
            "entity_authority_caller_controlled": False,
            "live_provider_acceptance_verified": False,
        }

    @router.post("")
    async def create_task(
        request: Request, response: Response, body: CreateTaskIn
    ) -> dict[str, object]:
        require_permission(request, "operate")
        ops, tenant, store = await composition(request)
        record = await call(ops, store.create_task, tenant, **body.model_dump())
        _secure(response)
        return _jsonable(record)  # type: ignore[return-value]

    @router.get("")
    async def list_tasks(
        request: Request,
        response: Response,
        entity_id: OpaqueId | None = Query(default=None),
        status_filter: TaskStatus | None = Query(default=None, alias="status"),
        assignee_ref: OpaqueId | None = Query(default=None),
        priority: TaskPriority | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> dict[str, object]:
        require_permission(request, "view")
        ops, tenant, store = await composition(request)
        records = await call(
            ops,
            store.list_tasks,
            tenant,
            entity_id=entity_id,
            status=status_filter,
            assignee_ref=assignee_ref,
            priority=priority,
            limit=limit,
        )
        _secure(response)
        return {
            "schema": "lightwork.ai-entity-task-page.v1",
            "items": _jsonable(records),
            "count": len(records),
        }

    @router.get("/{task_id}")
    async def get_task(
        request: Request, response: Response, task_id: ObjectPath
    ) -> dict[str, object]:
        require_permission(request, "view")
        ops, tenant, store = await composition(request)
        record = await call(ops, store.get_task, tenant, task_id)
        _secure(response)
        return _jsonable(record)  # type: ignore[return-value]

    @router.patch("/{task_id}")
    async def update_task(
        request: Request,
        response: Response,
        task_id: ObjectPath,
        body: UpdateTaskIn,
    ) -> dict[str, object]:
        require_permission(request, "operate")
        selected = body.model_fields_set - {"expected_revision", "idempotency_key"}
        if not selected:
            raise HTTPException(status_code=422, detail="AI-entity task update is empty")
        changes = {name: getattr(body, name) for name in selected}
        ops, tenant, store = await composition(request)
        record = await call(
            ops,
            store.update_task,
            tenant,
            task_id,
            expected_revision=body.expected_revision,
            changes=changes,
            idempotency_key=body.idempotency_key,
        )
        _secure(response)
        return _jsonable(record)  # type: ignore[return-value]

    @router.get("/{task_id}/history")
    async def history(
        request: Request, response: Response, task_id: ObjectPath
    ) -> dict[str, object]:
        require_permission(request, "view")
        ops, tenant, store = await composition(request)
        records = await call(ops, store.history, tenant, task_id)
        _secure(response)
        return {
            "schema": "lightwork.ai-entity-task-history-page.v1",
            "items": _jsonable(records),
            "count": len(records),
        }

    @router.get("/operations/integrity")
    async def integrity(request: Request, response: Response) -> dict[str, object]:
        require_global_permission(request, "audit")
        ops, tenant, store = await composition(request)
        result = await call(ops, store.verify_integrity, tenant)
        _secure(response)
        return result

    @router.get("/operations/retention-due")
    async def retention_due(
        request: Request,
        response: Response,
        limit: int = Query(default=100, ge=1, le=1_000),
    ) -> dict[str, object]:
        require_global_permission(request, "audit")
        ops, tenant, store = await composition(request)
        records = await call(ops, store.retention_due, tenant, limit=limit)
        _secure(response)
        return {
            "schema": "lightwork.ai-entity-task-retention-page.v1",
            "items": _jsonable(records),
            "count": len(records),
        }

    @router.post("/operations/purge-expired")
    async def purge_expired(
        request: Request, response: Response, body: PurgeIn
    ) -> dict[str, object]:
        require_global_permission(request, "admin")
        ops, tenant, store = await composition(request)
        removed = await call(ops, store.purge_expired, tenant, limit=body.limit)
        _secure(response)
        return {
            "schema": "lightwork.ai-entity-task-purge-result.v1",
            "removed": removed,
        }

    return router


router = create_ai_entity_tasks_router()

__all__ = [
    "AIEntityTaskDependencies",
    "CreateTaskIn",
    "PurgeIn",
    "UpdateTaskIn",
    "create_ai_entity_tasks_router",
    "router",
]
