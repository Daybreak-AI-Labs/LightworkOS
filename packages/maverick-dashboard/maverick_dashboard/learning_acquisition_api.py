"""Current automatic skill prerequisites, without catalog or provider requests."""
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick.authority_effects import authority_effect_fence
from maverick.self_learning import skill_acquisition_readiness
from starlette.concurrency import run_in_threadpool

from . import auth, settings_store
from .draft_api import context_for

router = APIRouter(prefix="/learning-ops/skill-acquisition", tags=["learning-ops"])


def current(request):
    with authority_effect_fence(), settings_store._locked(strict=True), auth.fresh_configuration():
        auth.require_global_permission(request, "admin")
        context = context_for(request)
        value = skill_acquisition_readiness()
        auth.require_global_permission(request, "admin")
        if context != context_for(request):
            raise HTTPException(409, "Your account or workspace changed. Refresh the current skill preparation status.")
        return {**value, "context": context}


@router.get("/readiness")
async def readiness(request: Request):
    return JSONResponse(await run_in_threadpool(current, request), headers={"Cache-Control": "private, no-store"})
