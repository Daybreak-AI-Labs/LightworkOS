"""Authenticated research submission and explicit operator queue dispatch.

This source API is disabled until a global reviewed execution profile exists.
It does not start Docker, pull images, or expose evaluator configuration writes.
"""

from __future__ import annotations

import hmac
from dataclasses import asdict
from typing import Annotated

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.routing import APIRoute
from maverick.governed_operations import digest
from maverick.paths import current_tenant_id_strict, tenant_scope
from maverick.privacy_ops import RecordConflict
from maverick.research_jobs import (
    ResearchAuthority,
    ResearchConflict,
    ResearchDispatchAuthority,
    ResearchJobs,
    ResearchNotFound,
    ResearchUnavailable,
    configured_profile,
)
from maverick.sandbox.research import ResearchContainerRunner
from pydantic import BaseModel, ConfigDict, Field, model_validator
from starlette.concurrency import run_in_threadpool

from . import (
    candidate_promotion_api,
    rbac,
    research_workspace_api,
    settings_store,
    workspace_tenants,
)
from .auth import (
    caller_principal,
    global_role_for_principal,
    has_global_permission,
    require_global_permission,
    require_permission,
)
from .draft_api import context_for
from .vendor_onboarding_composition import _budget_authority, _role_authority


class _PrivateResearchRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def private_validation(request):
            try:
                return await handler(request)
            except RequestValidationError:
                return JSONResponse(
                    status_code=422,
                    content={
                        "detail": "Research submission is malformed; check the source files and reviewed fields"
                    },
                    headers={"Cache-Control": "private, no-store"},
                )

        return private_validation


router = APIRouter(prefix="/api/v1/research", tags=["research"], route_class=_PrivateResearchRoute)
page_router = APIRouter(tags=["research"])
Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")]


class Reviewed(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    confirm: bool


class Submit(Reviewed):
    files: dict[Annotated[str, Field(max_length=200)], Annotated[str, Field(max_length=262144)]] = (
        Field(min_length=1, max_length=64)
    )
    evaluator_id: Identifier
    idempotency_key: Identifier
    entrypoint: str = Field(default="main.py", min_length=1, max_length=200)


class Revision(Reviewed):
    expected_revision: int = Field(ge=1, le=2**31 - 1)


class Dispatch(Revision):
    review_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class EvaluatorSetting(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: Identifier
    version: Identifier
    stdout_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class LimitSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)
    timeout_seconds: float = Field(default=10.0, ge=0.1, le=300)
    output_bytes: int = Field(default=65536, ge=1024, le=1048576)
    memory_bytes: int = Field(default=134217728, ge=33554432, le=1073741824)
    scratch_bytes: int = Field(default=16777216, ge=1048576, le=268435456)
    pids: int = Field(default=32, ge=8, le=256)
    cpus: float = Field(default=0.5, ge=0.1, le=2)


class ExecutionSettings(Reviewed):
    expected_settings_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    enable: bool
    image_id: str = Field(default="", max_length=256)
    evaluators: list[EvaluatorSetting] = Field(default_factory=list, max_length=32)
    queue_seconds: int = Field(default=3600, ge=30, le=86400)
    limits: LimitSettings = Field(default_factory=LimitSettings)

    @model_validator(mode="before")
    @classmethod
    def discard_disabled_profile_fields(cls, value):
        """Let an administrator disable a damaged profile from the app.

        Nested evaluator/limit validation must not trap the operator behind the
        very configuration they are trying to turn off. Unknown top-level keys
        remain subject to ``extra=forbid``.
        """
        _ = cls  # classmethod binding is part of Pydantic's validator contract
        if isinstance(value, dict) and value.get("enable") is False:
            value = dict(value)
            for field in ("image_id", "evaluators", "queue_seconds", "limits"):
                value.pop(field, None)
        return value


def resolve_authority(tenant: str, principal: str) -> ResearchAuthority:
    """Re-read actual membership, selection generation and budget in a worker."""
    from maverick.tenant.registry import assert_tenant_active, get_tenant

    from .scim_groups import active_for_principal
    from .session_revocation import revocation_epoch

    with tenant_scope(tenant=tenant):
        if active_for_principal(principal) is False:
            raise PermissionError("Research submitter is no longer active")
        if get_tenant(tenant) is None:
            raise PermissionError("Select an existing research workspace")
        assert_tenant_active(tenant)
        role = rbac.get_tenant_role(tenant, principal)
        if not role or not ({"operate", "admin"} & rbac.permissions_for(role)):
            raise PermissionError("Current workspace membership must permit research submission")
        selected, generation = workspace_tenants.get_selection_binding(principal)
        if selected != tenant:
            raise PermissionError("Research workspace selection changed")
        return ResearchAuthority(
            tenant,
            principal,
            digest(
                {
                    "schema": "lightwork.research-authority.v1",
                    "tenant": tenant,
                    "principal": principal,
                    "role": _role_authority(role),
                    "budget": _budget_authority(tenant),
                    "selection_generation": generation,
                    "credential_epoch": revocation_epoch(principal.removeprefix("user:")),
                }
            ),
        )


def resolve_dispatch_authority(tenant: str, principal: str) -> ResearchDispatchAuthority:
    """Re-read named global-admin authority inside the dispatch worker."""
    from maverick.tenant.registry import assert_tenant_active, get_tenant

    from .scim_groups import active_for_principal
    from .session_revocation import revocation_epoch

    with tenant_scope(tenant=tenant):
        if active_for_principal(principal) is False:
            raise PermissionError("Research dispatcher is no longer active")
        if get_tenant(tenant) is None:
            raise PermissionError("Select an existing research workspace")
        assert_tenant_active(tenant)
        global_role = global_role_for_principal(principal)
        if "admin" not in rbac.permissions_for(global_role):
            raise PermissionError("Current global administrator authority is required")
        selected, generation = workspace_tenants.get_selection_binding(principal)
        if selected != tenant:
            raise PermissionError("Research workspace selection changed")
        tenant_role = rbac.get_tenant_role(tenant, principal)
        if not tenant_role or not ({"operate", "admin"} & rbac.permissions_for(tenant_role)):
            raise PermissionError("Current workspace membership must permit research dispatch")
        return ResearchDispatchAuthority(
            tenant,
            principal,
            digest(
                {
                    "schema": "lightwork.research-dispatch-authority.v1",
                    "tenant": tenant,
                    "principal": principal,
                    "global_role": _role_authority(global_role),
                    "tenant_role": _role_authority(tenant_role) if tenant_role else "",
                    "budget": _budget_authority(tenant),
                    "selection_generation": generation,
                    "credential_epoch": revocation_epoch(principal.removeprefix("user:")),
                }
            ),
        )


def _service():
    return ResearchJobs(
        authority_resolver=resolve_authority,
        dispatch_authority_resolver=resolve_dispatch_authority,
        runner_factory=ResearchContainerRunner,
    )


def _settings_projection(state, profile):
    configuration = state.get("configuration")
    enabled = isinstance(configuration, dict) and configuration.get("enable") is True
    result = {
        "settings_sha256": state["settings_sha256"],
        "enabled": enabled,
        "valid": profile is not None,
        "writable": state.get("writable") is True,
        "source": state.get("source", "unavailable"),
    }
    if profile is not None:
        result.update(
            image_id=profile.image_id,
            queue_seconds=profile.queue_seconds,
            evaluators=[
                {"id": item.id, "version": item.version, "stdout_sha256": item.stdout_sha256}
                for item in profile.evaluators
            ],
            limits=asdict(profile.limits),
        )
    return result


def _binding(request, response, payload=None, *, operator=False):
    require_permission(request, "operate")
    if operator:
        require_global_permission(request, "admin")
    actor, tenant = caller_principal(request), current_tenant_id_strict()
    if not actor or not actor.startswith("user:") or not tenant:
        raise HTTPException(403, "Sign in with a named account and select a research workspace")
    response.headers["Cache-Control"] = "private, no-store"
    context = context_for(request)
    if payload is not None:
        from .app import _require_same_origin

        _require_same_origin(request)
        if not hmac.compare_digest(payload.context, context):
            raise HTTPException(409, "Your account or workspace changed. Reload the page to see current research runs.")
        if payload.confirm is not True:
            raise HTTPException(422, "Review and confirm this research action")
    return tenant, actor, context


async def _call(function, *args, **kwargs):
    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except ResearchNotFound as exc:
        raise HTTPException(404, str(exc)) from exc
    except (ResearchConflict, RecordConflict) as exc:
        raise HTTPException(409, "This research run changed. Reload the page to see its current state.") from exc
    except PermissionError as exc:
        raise HTTPException(403, "Current research workspace authority is required") from exc
    except ResearchUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            422, "Research input or operator execution configuration is invalid"
        ) from exc
    except Exception as exc:  # noqa: BLE001 - storage failures must not expose source/configuration
        raise HTTPException(
            503, "Research state is unavailable; inspect the existing job before retrying"
        ) from exc


@router.get("")
async def overview(request: Request, response: Response):
    tenant, actor, context = _binding(request, response)
    rows = await _call(_service().list, tenant, actor)
    workspace = await research_workspace_api.workspace_overview(request, tenant, actor)
    administrator = has_global_permission(request, "admin")
    review_queue = await _call(_service().review_list, tenant, actor) if administrator else []
    try:
        profile = await run_in_threadpool(configured_profile)
    except Exception:  # noqa: BLE001 - the overview remains available for recovery
        profile = None
    settings = None
    if administrator:
        try:
            settings = _settings_projection(
                await run_in_threadpool(settings_store.research_execution_state), profile
            )
        except Exception:  # noqa: BLE001 - job recovery must survive settings-store damage
            settings = {
                "settings_sha256": "",
                "enabled": False,
                "valid": False,
                "writable": False,
                "source": "unavailable",
            }
    return {
        "context": context,
        "jobs": rows,
        "review_queue": review_queue,
        "can_dispatch": administrator and profile is not None,
        "execution_available": profile is not None,
        "evaluators": []
        if profile is None
        else [{"id": item.id, "version": item.version} for item in profile.evaluators],
        "limits": None if profile is None else asdict(profile.limits),
        "settings": settings,
        **workspace,
        "qualification": "local-source-integration; runtime containment not qualified",
    }


@page_router.get("/research")
async def research_page(request: Request, response: Response):
    from .app import templates

    _, _, context = _binding(request, response)
    from .model_pickers import config_catalog
    from .plain_labels import model_label

    try:
        models = [{"value": spec, "label": model_label(spec)} for spec in config_catalog()]
    except Exception:  # noqa: BLE001 -- the picker still offers "Another model"
        models = []
    return templates.TemplateResponse(
        request,
        "research.html",
        {"research_context": context, "model_choices": models},
        headers={"Cache-Control": "private, no-store"},
    )


@page_router.get("/static/lightwork-research.js")
async def research_ui_asset():
    from .app import _STATIC_DIR

    return FileResponse(
        _STATIC_DIR / "lightwork-research.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@page_router.get("/static/lightwork-research-workspace.js")
async def research_workspace_ui_asset():
    from .app import _STATIC_DIR

    return FileResponse(
        _STATIC_DIR / "lightwork-research-workspace.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@router.put("/settings")
async def update_settings(payload: ExecutionSettings, request: Request, response: Response):
    _, _, _ = _binding(request, response, payload, operator=True)
    value = {"enable": False}
    if payload.enable:
        value = {
            "enable": True,
            "image_id": payload.image_id,
            "queue_seconds": payload.queue_seconds,
            "evaluators": {
                item.id: {"version": item.version, "stdout_sha256": item.stdout_sha256}
                for item in payload.evaluators
            },
            "limits": payload.limits.model_dump(),
        }
    try:
        state = await run_in_threadpool(
            settings_store.set_research_execution,
            value,
            expected_settings_sha256=payload.expected_settings_sha256,
        )
        profile = await run_in_threadpool(configured_profile) if payload.enable else None
    except settings_store.ResearchSettingsConflict as exc:
        raise HTTPException(409, "Research settings changed; reload before saving") from exc
    except settings_store.ResearchSettingsUnavailable as exc:
        raise HTTPException(
            409, "Research settings are managed by the operator config overlay"
        ) from exc
    except (ResearchUnavailable, ValueError) as exc:
        raise HTTPException(422, "Research settings are incomplete or invalid") from exc
    except Exception as exc:  # noqa: BLE001 - do not disclose local config paths or contents
        raise HTTPException(503, "Research settings could not be saved") from exc
    response.headers["Cache-Control"] = "private, no-store"
    return {"context": context_for(request), "settings": _settings_projection(state, profile)}


@router.post("/jobs", status_code=201)
async def submit(payload: Submit, request: Request, response: Response):
    tenant, actor, _ = _binding(request, response, payload)
    return await _call(
        _service().submit,
        tenant,
        actor,
        files=payload.files,
        evaluator_id=payload.evaluator_id,
        idempotency_key=payload.idempotency_key,
        entrypoint=payload.entrypoint,
    )


@router.get("/jobs/{job_id}")
async def get(job_id: str, request: Request, response: Response):
    tenant, actor, _ = _binding(request, response)
    return await _call(_service().get, tenant, actor, job_id)


@router.get("/review/{job_id}")
async def review(job_id: str, request: Request, response: Response):
    tenant, actor, _ = _binding(request, response, operator=True)
    return await _call(_service().review, tenant, actor, job_id)


@router.post("/jobs/{job_id}/cancel")
async def cancel(job_id: str, payload: Revision, request: Request, response: Response):
    tenant, actor, _ = _binding(request, response, payload)
    if has_global_permission(request, "admin"):
        return await _call(
            _service().cancel_for_review,
            tenant,
            actor,
            job_id,
            expected_revision=payload.expected_revision,
        )
    return await _call(
        _service().cancel, tenant, actor, job_id, expected_revision=payload.expected_revision
    )


@router.post("/jobs/{job_id}/run")
async def run(job_id: str, payload: Dispatch, request: Request, response: Response):
    tenant, actor, _ = _binding(request, response, payload, operator=True)
    return await _call(
        _service().run,
        tenant,
        job_id,
        expected_revision=payload.expected_revision,
        dispatcher=actor,
        review_sha256=payload.review_sha256,
    )


router.include_router(research_workspace_api.router)
router.include_router(candidate_promotion_api.router)
page_router.include_router(candidate_promotion_api.page_router)
