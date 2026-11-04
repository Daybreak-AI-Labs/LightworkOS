"""Strict tenant-bound adapter for deterministic compliance scope actions.

The request boundary accepts only opaque mapping references, closed control and
evidence-task contracts, CAS revisions, retention timestamps, and signing-key
references.  Tenant, authenticated actor, finalized-scope facts, apply callback,
signing-key values, and storage paths are supplied only by the trusted runtime.

The default factory joins the tenant-local compliance-scoping authority to a
separate tenant-local scope-action store.  It performs no network I/O and has no
built-in provider writer.  Apply, reconcile, and rollback remain unavailable
unless the host injects the closed local callback explicitly.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import asdict, is_dataclass
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi import Path as ApiPath
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from ._shared import authenticated_subject
from .auth import require_global_permission, require_permission

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_OP_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$"
_KEY_REF_PATTERN = r"^(?:env|vault|secret):[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}$"

OpaqueId = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=128, pattern=_ID_PATTERN),
]
ObjectPath = Annotated[
    str,
    ApiPath(min_length=1, max_length=128, pattern=_ID_PATTERN),
]
VersionPath = Annotated[int, ApiPath(ge=1, le=1_000_000)]
IdempotencyKey = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=192, pattern=_OP_PATTERN),
]
SigningKeyRef = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=5,
        max_length=128,
        pattern=_KEY_REF_PATTERN,
    ),
]

DesiredControlState = Literal["not_started", "not_implemented", "planned"]
ControlOwnerRole = Literal["second_line", "control_owner"]
EvidenceOwnerRole = Literal["second_line", "control_owner", "evidence_owner"]
EvidenceTaskKind = Literal["collect", "refresh", "review"]
EvidenceCadence = Literal["one_time", "monthly", "quarterly", "annual", "continuous"]


class _GenericValidationRoute(APIRoute):
    """Do not reflect rejected framework text, evidence, secrets, or selectors."""

    def get_route_handler(self):
        original = super().get_route_handler()

        async def handler(request: Request):
            try:
                return await original(request)
            except RequestValidationError as exc:
                raise HTTPException(
                    status_code=422,
                    detail="compliance scope-action request is invalid",
                ) from exc

        return handler


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class EvidenceTaskIn(_StrictModel):
    evidence_mapping_ref: OpaqueId
    task_kind: EvidenceTaskKind
    owner_role: EvidenceOwnerRole
    cadence: EvidenceCadence


class CatalogEntryIn(_StrictModel):
    entry_id: OpaqueId
    framework_ref: OpaqueId
    scope_control_ref: OpaqueId
    desired_control_ref: OpaqueId
    desired_control_state: DesiredControlState
    control_owner_role: ControlOwnerRole
    evidence_tasks: list[EvidenceTaskIn] = Field(max_length=64)


class CatalogVersionIn(_StrictModel):
    entries: list[CatalogEntryIn] = Field(min_length=1, max_length=2_000)
    expected_latest_version: int = Field(ge=0, le=1_000_000)
    idempotency_key: IdempotencyKey


class RevisionIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=1_000_000)
    idempotency_key: IdempotencyKey


class PlanCreateIn(_StrictModel):
    catalog_id: OpaqueId
    catalog_version: int = Field(ge=1, le=1_000_000)
    expected_scope_revision: int = Field(ge=1, le=1_000_000)
    retained_until: float | int = Field(gt=0, lt=100_000_000_000.0)
    idempotency_key: IdempotencyKey


class ExportPlanIn(_StrictModel):
    signing_key_ref: SigningKeyRef
    retained_until: float | int = Field(gt=0, lt=100_000_000_000.0)
    idempotency_key: IdempotencyKey


class ReportIn(_StrictModel):
    idempotency_key: IdempotencyKey


#: Signing key the page's "Create report" button uses; nobody types a key
#: reference. The key itself stays in the environment.
DEFAULT_REPORT_SIGNING_KEY_REF = "env:MAVERICK_COMPLIANCE_SCOPE_SIGNING_KEY"


def _enabled() -> bool:
    from maverick import compliance_scope_actions as actions

    return actions.enabled()


def compliance_scope_actions_enabled_for_page() -> bool:
    """Read only the exact two-level feature gate; do not open tenant storage."""

    return _enabled()


def _actions():
    from maverick import compliance_scope_actions as actions

    try:
        actions.require_enabled()
    except actions.ComplianceScopeActionConfigError as exc:
        raise HTTPException(
            status_code=403,
            detail="compliance scope actions are disabled",
        ) from exc
    return actions


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using compliance scope actions",
        )
    return tenant


def _principal(request: Request, tenant_id: str) -> str:
    subject = authenticated_subject(
        request,
        error_detail="an authenticated principal is required for compliance scope actions",
    )
    digest = hashlib.sha256(
        (f"lightwork.compliance-scope-actions.identity.v1:{tenant_id}:{subject}").encode()
    ).hexdigest()
    return f"csa-principal-{digest[:32]}"


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _default_store_for(
    tenant_id: str,
    principal_ref: str,
    *,
    apply_callback: Callable[[Mapping[str, object]], Mapping[str, object]] | None = None,
):
    from maverick.compliance_scope_actions import (
        ComplianceScopeActionStore,
        resolver_from_scoping_store,
    )
    from maverick.compliance_scoping import ComplianceScopingStore
    from maverick.paths import data_dir

    def principal_resolver() -> str:
        return principal_ref

    scoping_store = ComplianceScopingStore(
        data_dir(
            "tech_risk_compliance",
            "compliance-scoping.sqlite3",
            tenant=tenant_id,
        ),
        principal_resolver=principal_resolver,
    )
    return ComplianceScopeActionStore(
        data_dir(
            "tech_risk_compliance",
            "compliance-scope-actions.sqlite3",
            tenant=tenant_id,
        ),
        scope_resolver=resolver_from_scoping_store(scoping_store),
        principal_resolver=principal_resolver,
        apply_callback=apply_callback,
    )


class ComplianceScopeActionDependencies:
    """Explicit tenant/principal-bound store seam for runtimes and tests."""

    def __init__(
        self,
        *,
        store_for: Callable[..., Any] = _default_store_for,
    ) -> None:
        self.store_for = store_for


def authority(request: Request, dependencies: ComplianceScopeActionDependencies | None = None):
    """Shared native tenant/principal and injected-store boundary."""
    deps = dependencies or ComplianceScopeActionDependencies()
    actions = _actions()
    tenant = _tenant_id()
    principal = _principal(request, tenant)
    factory = getattr(
        request.app.state,
        "compliance_scope_actions_store_factory",
        None,
    )
    apply_callback = getattr(
        request.app.state,
        "compliance_scope_actions_apply_callback",
        None,
    )
    if apply_callback is not None and not callable(apply_callback):
        raise HTTPException(
            status_code=503,
            detail="compliance scope-action runtime is unavailable",
        )

    def resolver() -> str:
        return principal

    try:
        store = (
            factory(
                tenant_id=tenant,
                principal_ref=principal,
                principal_resolver=resolver,
                apply_callback=apply_callback,
                request=request,
            )
            if callable(factory)
            else deps.store_for(
                tenant,
                principal,
                apply_callback=apply_callback,
            )
        )
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="compliance scope-action store is unavailable",
        ) from exc
    if store is None:
        raise HTTPException(
            status_code=503,
            detail="compliance scope-action store is unavailable",
        )
    return actions, tenant, store


def create_compliance_scope_actions_router(  # noqa: C901, PLR0915
    dependencies: ComplianceScopeActionDependencies | None = None,
) -> APIRouter:
    deps = dependencies or ComplianceScopeActionDependencies()
    router = APIRouter(
        prefix="/compliance/scope-actions",
        tags=["compliance-scope-actions"],
        route_class=_GenericValidationRoute,
    )

    def bound_authority(request: Request):
        return authority(request, deps)

    async def call(actions, function, *args, **kwargs):
        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except actions.ComplianceScopeActionNotFound as exc:
            raise HTTPException(
                status_code=404,
                detail="compliance scope-action record was not found",
            ) from exc
        except actions.ComplianceScopeActionPermissionDenied as exc:
            raise HTTPException(
                status_code=403,
                detail="compliance scope-action operation is not permitted",
            ) from exc
        except actions.ComplianceScopeActionConflict as exc:
            raise HTTPException(
                status_code=409,
                detail="compliance scope-action state conflict",
            ) from exc
        except actions.ComplianceScopeActionValidationError as exc:
            raise HTTPException(
                status_code=422,
                detail="compliance scope-action request is invalid",
            ) from exc
        except actions.ComplianceScopeActionConfigError as exc:
            raise HTTPException(
                status_code=503,
                detail="compliance scope-action configuration is unavailable",
            ) from exc
        except actions.ComplianceScopeActionIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail="compliance scope-action integrity verification failed",
            ) from exc
        except actions.ComplianceScopeActionError as exc:
            raise HTTPException(
                status_code=503,
                detail="compliance scope-action operation failed",
            ) from exc
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="compliance scope-action operation failed",
            ) from exc

    @router.get("/status")
    async def status(request: Request) -> dict[str, Any]:
        require_permission(request, "view")
        tenant = _tenant_id()
        principal = _principal(request, tenant)
        from maverick.compliance_scope_actions import ComplianceScopeActionStore

        callback = getattr(
            request.app.state,
            "compliance_scope_actions_apply_callback",
            None,
        )
        return {
            "schema": "lightwork.compliance-scope-actions-status.v1",
            "enabled": _enabled(),
            "principal_ref": principal,
            **ComplianceScopeActionStore.product_boundaries(),
            "apply_callback_configured": callable(callback),
            "apply_callback_invoked_by_status": False,
            "network_io_performed_by_adapter": False,
            "external_provider_writes_performed_by_adapter": False,
            "live_acceptance_verified": False,
            "status_request_external_network_io": False,
        }

    @router.get("/records")
    async def records(request: Request) -> dict[str, Any]:
        """Catalogs, plans and reports in this workspace, newest first."""

        require_permission(request, "view")
        actions, tenant, store = bound_authority(request)
        listed = await call(actions, store.list_records, tenant)
        callback = getattr(request.app.state, "compliance_scope_actions_apply_callback", None)
        return {
            "can_create_tasks": callable(callback),
            "catalogs": [
                {
                    "catalog_id": c.catalog_id,
                    "version": c.version,
                    "status": c.status,
                    "entries": len(c.entries),
                    "revision": c.revision,
                    "created_at": c.created_at,
                }
                for c in listed["catalogs"]
            ],
            "plans": [
                {
                    "plan_id": p.plan_id,
                    "scope_id": p.scope_id,
                    "catalog_id": p.catalog_id,
                    "catalog_version": p.catalog_version,
                    "status": p.status,
                    "controls": len(p.control_intents),
                    "evidence_tasks": len(p.evidence_task_intents),
                    "approved": bool(p.approved_by),
                    "last_outcome": p.last_outcome,
                    "revision": p.revision,
                    "retained_until": p.retained_until,
                    "created_at": p.created_at,
                }
                for p in listed["plans"]
            ],
            "reports": [
                {"export_id": e.export_id, "plan_id": e.plan_id, "created_at": e.created_at}
                for e in listed["exports"]
            ],
        }

    @router.post("/plans/{plan_id}/report")
    async def create_report(request: Request, plan_id: ObjectPath, body: ReportIn):
        """Signed report for a plan with the deployment signing key."""

        require_permission(request, "operate")
        actions, tenant, store = bound_authority(request)
        plan = await call(actions, store.get_plan, tenant, plan_id)
        export_id = "report-" + hashlib.sha256(
            f"{plan_id}:{body.idempotency_key}".encode()
        ).hexdigest()[:24]
        return _jsonable(
            await call(
                actions,
                store.export_plan,
                tenant,
                plan_id,
                export_id,
                signing_key_ref=DEFAULT_REPORT_SIGNING_KEY_REF,
                retained_until=plan.retained_until,
                idempotency_key=body.idempotency_key,
            )
        )

    @router.put("/catalogs/{catalog_id}/versions")
    async def create_catalog_version(
        request: Request,
        catalog_id: ObjectPath,
        body: CatalogVersionIn,
    ):
        require_permission(request, "operate")
        actions, tenant, store = bound_authority(request)
        payload = body.model_dump()
        payload["entries"] = [entry.model_dump() for entry in body.entries]
        return _jsonable(
            await call(
                actions,
                store.create_catalog_version,
                tenant,
                catalog_id,
                **payload,
            )
        )

    @router.get("/catalogs/{catalog_id}/versions/{version}")
    async def get_catalog_version(
        request: Request,
        catalog_id: ObjectPath,
        version: VersionPath,
    ):
        require_permission(request, "view")
        actions, tenant, store = bound_authority(request)
        return _jsonable(
            await call(
                actions,
                store.get_catalog_version,
                tenant,
                catalog_id,
                version,
            )
        )

    @router.post("/catalogs/{catalog_id}/versions/{version}/approve")
    async def approve_catalog_version(
        request: Request,
        catalog_id: ObjectPath,
        version: VersionPath,
        body: RevisionIn,
    ):
        require_global_permission(request, "admin")
        actions, tenant, store = bound_authority(request)
        return _jsonable(
            await call(
                actions,
                store.approve_catalog_version,
                tenant,
                catalog_id,
                version,
                **body.model_dump(),
            )
        )

    @router.put("/scopes/{scope_id}/plans/{plan_id}")
    async def create_plan(
        request: Request,
        scope_id: ObjectPath,
        plan_id: ObjectPath,
        body: PlanCreateIn,
    ):
        require_permission(request, "operate")
        actions, tenant, store = bound_authority(request)
        return _jsonable(
            await call(
                actions,
                store.create_plan,
                tenant,
                scope_id,
                plan_id,
                **body.model_dump(),
            )
        )

    @router.get("/plans/{plan_id}")
    async def get_plan(request: Request, plan_id: ObjectPath):
        require_permission(request, "view")
        actions, tenant, store = bound_authority(request)
        return _jsonable(await call(actions, store.get_plan, tenant, plan_id))

    @router.get("/plans/{plan_id}/history")
    async def get_plan_history(request: Request, plan_id: ObjectPath):
        require_permission(request, "view")
        actions, tenant, store = bound_authority(request)
        items = await call(actions, store.get_plan_history, tenant, plan_id)
        return {"items": _jsonable(items), "count": len(items)}

    @router.post("/plans/{plan_id}/approve")
    async def approve_plan(request: Request, plan_id: ObjectPath, body: RevisionIn):
        require_global_permission(request, "admin")
        actions, tenant, store = bound_authority(request)
        return _jsonable(
            await call(
                actions,
                store.approve_plan,
                tenant,
                plan_id,
                **body.model_dump(),
            )
        )

    async def execute_plan(
        request: Request,
        plan_id: str,
        body: RevisionIn,
        method_name: str,
    ):
        require_global_permission(request, "admin")
        actions, tenant, store = bound_authority(request)
        try:
            method = getattr(store, method_name)
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="compliance scope-action operation failed",
            ) from exc
        if not callable(method):
            raise HTTPException(
                status_code=503,
                detail="compliance scope-action operation failed",
            )
        return _jsonable(
            await call(
                actions,
                method,
                tenant,
                plan_id,
                **body.model_dump(),
            )
        )

    @router.post("/plans/{plan_id}/apply")
    async def apply_plan(request: Request, plan_id: ObjectPath, body: RevisionIn):
        return await execute_plan(request, plan_id, body, "apply_plan")

    @router.post("/plans/{plan_id}/reconcile")
    async def reconcile_plan(request: Request, plan_id: ObjectPath, body: RevisionIn):
        return await execute_plan(request, plan_id, body, "reconcile_plan")

    @router.post("/plans/{plan_id}/rollback")
    async def rollback_plan(request: Request, plan_id: ObjectPath, body: RevisionIn):
        return await execute_plan(request, plan_id, body, "rollback_plan")

    @router.put("/plans/{plan_id}/exports/{export_id}")
    async def export_plan(
        request: Request,
        plan_id: ObjectPath,
        export_id: ObjectPath,
        body: ExportPlanIn,
    ):
        require_permission(request, "operate")
        actions, tenant, store = bound_authority(request)
        return _jsonable(
            await call(
                actions,
                store.export_plan,
                tenant,
                plan_id,
                export_id,
                **body.model_dump(),
            )
        )

    @router.get("/exports/{export_id}")
    async def get_export(request: Request, export_id: ObjectPath):
        require_permission(request, "view")
        actions, tenant, store = bound_authority(request)
        return _jsonable(await call(actions, store.get_export, tenant, export_id))

    @router.get("/integrity")
    async def integrity(request: Request):
        require_global_permission(request, "audit")
        actions, tenant, store = bound_authority(request)
        result = _jsonable(await call(actions, store.verify_integrity, tenant))
        result["valid"] = True
        return result

    return router


router = create_compliance_scope_actions_router()

__all__ = [
    "DEFAULT_REPORT_SIGNING_KEY_REF",
    "ComplianceScopeActionDependencies",
    "compliance_scope_actions_enabled_for_page",
    "create_compliance_scope_actions_router",
    "router",
]
