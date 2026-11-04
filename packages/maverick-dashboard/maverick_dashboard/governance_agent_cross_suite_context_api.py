"""Authenticated metadata API for governance-agent cross-suite context."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict
from starlette.concurrency import run_in_threadpool

from .auth import require_global_permission, require_permission

AgentKind = Literal[
    "breach_response",
    "knowledgebase_governance",
    "privacy_risk_assessment",
    "program_copilot",
    "third_party_risk",
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class RecoveryIn(_StrictModel):
    confirm_stateless_recapture: Literal[True]


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before projecting governance context",
        )
    return tenant


def _seam(request: Request, name: str):
    value = getattr(request.app.state, name, None)
    if not callable(value):
        raise HTTPException(
            status_code=503,
            detail="governance-agent cross-suite context composition is unavailable",
        )
    return value


async def _call(function, *args) -> Any:
    from maverick import governance_agent_context as context

    try:
        return await run_in_threadpool(function, *args)
    except context.GovernanceContextProjectionConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except context.GovernanceContextProjectionValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except context.GovernanceContextProjectionConfigError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except context.GovernanceContextProjectionError as exc:
        raise HTTPException(
            status_code=503,
            detail="governance-agent cross-suite context operation failed",
        ) from exc
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="governance-agent cross-suite context operation failed",
        ) from exc


def create_governance_agent_cross_suite_context_router() -> APIRouter:
    router = APIRouter(
        prefix="/governance-agents/context",
        tags=["governance-agent-context"],
    )

    @router.get("/status")
    async def status(request: Request) -> dict[str, object]:
        require_permission(request, "view")
        tenant = _tenant_id()
        readiness = _seam(
            request,
            "governance_agent_cross_suite_readiness",
        )
        return await _call(readiness, tenant)

    @router.get("/preview/{agent_kind}")
    async def preview(
        request: Request,
        agent_kind: AgentKind,
    ) -> dict[str, object]:
        require_permission(request, "view")
        tenant = _tenant_id()
        resolver = _seam(
            request,
            "governance_agent_cross_suite_preview_resolver",
        )
        projection = await _call(resolver, tenant, agent_kind)
        public_manifest = getattr(projection, "public_manifest", None)
        if not callable(public_manifest):
            raise HTTPException(
                status_code=503,
                detail="governance-agent cross-suite context operation failed",
            )
        result = public_manifest()
        if not isinstance(result, dict):
            raise HTTPException(
                status_code=503,
                detail="governance-agent cross-suite context operation failed",
            )
        return result

    @router.get("/integrity")
    async def integrity(request: Request) -> dict[str, object]:
        require_global_permission(request, "audit")
        tenant = _tenant_id()
        verifier = _seam(
            request,
            "governance_agent_cross_suite_maintenance",
        )
        return await _call(verifier, tenant)

    @router.post("/recovery")
    async def recovery(
        request: Request,
        _body: RecoveryIn,
    ) -> dict[str, object]:
        require_global_permission(request, "admin")
        tenant = _tenant_id()
        recover = _seam(
            request,
            "governance_agent_cross_suite_recovery",
        )
        return await _call(recover, tenant)

    return router


router = create_governance_agent_cross_suite_context_router()

__all__ = [
    "RecoveryIn",
    "create_governance_agent_cross_suite_context_router",
    "router",
]
