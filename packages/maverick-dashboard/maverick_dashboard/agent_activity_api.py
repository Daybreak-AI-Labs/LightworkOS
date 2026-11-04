"""Pure authorized specialist activity reader."""
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from . import agent_activity as native

router = APIRouter(prefix="/api/v1/agents", tags=["agent-activity"])


@router.get("/{name}/recent-work")
async def recent_work(request: Request, name: str, days: int = 30):
    value = await run_in_threadpool(native.read, request, name, days,
                                    context=request.headers.get(native.HEADER))
    native.authority(request, value["context"])
    return JSONResponse(value, headers={native.HEADER: value["context"], "Cache-Control": "private, no-store"})
