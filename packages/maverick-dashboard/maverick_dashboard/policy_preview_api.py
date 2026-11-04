"""Previews of a tool policy change before it is saved.

``GET /api/v1/policy-preview/tools`` says what blocking tools (for everyone,
or for one agent or specialist) would have stopped in the last 30 days, from
the activity record. Report only: nothing is saved or enforced here.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException, Query, Request
from starlette.concurrency import run_in_threadpool

from .auth import require_permission

router = APIRouter()
_NAME = re.compile(r"[A-Za-z0-9_.:-]{1,128}")


@router.get("/api/v1/policy-preview/tools")
async def tools(request: Request, tools: str = Query(..., max_length=4000),
                agent: str = Query("", max_length=128)) -> dict:
    require_permission(request, "operate")
    from maverick import policy_preview

    names = [name.strip() for name in tools.split(",") if name.strip()]
    if not names or len(names) > 100 or any(not _NAME.fullmatch(n) for n in names):
        raise HTTPException(422, "Choose up to 100 tools from the list.")
    if agent and not _NAME.fullmatch(agent):
        raise HTTPException(422, "Choose an agent or specialist from the list.")
    return await run_in_threadpool(policy_preview.tool_block, names, agent=agent)
