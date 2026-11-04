"""Pages for the immune layer (/immune) and the code vault (/code).

Both render a server template whose same-origin script reads one JSON summary.
Summaries carry counts, scores, labels, statuses and names only -- never canary
flaws, tool arguments, recorded outputs, diffs or code. The summaries never
mutate; the pages' buttons call the administrator-only action routes in
:mod:`.code_actions_api` and :mod:`.immune_actions_api`. Approvals are still
decided in the approvals queue.
"""
from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from .auth import (
    caller_principal,
    can_access_goal_principal,
    has_global_permission,
    has_permission,
    require_permission,
)
from .evolution_ledger_page import _HEADERS

IMMUNE_PATH = "/immune"
CODE_PATH = "/code"
ASSET_PATH = "/static/lightwork-immune-console.js"
_PERMISSION = {IMMUNE_PATH: "audit", CODE_PATH: "operate"}


def _world_or_none() -> Any:
    from ._shared import _world
    try:
        return _world()
    except Exception:  # noqa: BLE001 -- the summary reports the section unavailable
        return None


def _immune_summary(principal=None) -> dict:
    from maverick.immune import report

    from .identity_format import humanize_principal
    world = _world_or_none()
    data = report.summary(world)
    # Readable names for the page: task titles and people, never raw ids.
    ids: set[int] = set()
    for row in (data.get("ifc") or {}).get("recent") or []:
        if isinstance(row.get("goal_id"), int):
            ids.add(row["goal_id"])
    for row in (data.get("twin") or {}).get("replays") or []:
        for key in ("production_goal", "twin_goal"):
            if isinstance(row.get(key), int):
                ids.add(row[key])
    titles: dict[str, str] = {}
    if world is not None:
        for gid in sorted(ids)[:500]:
            try:
                goal = world.get_goal(gid)
            except Exception:  # noqa: BLE001 -- a missing title falls back to a number
                goal = None
            if goal is not None and goal.title and can_access_goal_principal(principal, goal):
                titles[str(gid)] = goal.title[:200]
    data["goal_titles"] = titles
    for kind in ("canary", "drill"):
        for row in (data.get("oversight") or {}).get(kind) or []:
            row["person_label"] = humanize_principal(row.get("person")).name
    return data


def _code_summary() -> dict:
    from maverick.codebase import features, vault
    if not vault.enabled():
        return {"schema": "lightwork.codebase-summary.v1", "enabled": False,
                "repos": [], "proposals": []}
    world = _world_or_none()
    if world is None:
        raise HTTPException(status_code=503, detail="world model unavailable")
    try:
        return features.summary(world)
    except Exception as exc:  # noqa: BLE001 -- vault, decryption or corrupt records
        raise HTTPException(status_code=503, detail="code vault unavailable") from exc


def _module_on(path: str) -> bool:
    if path != CODE_PATH:
        return True
    try:
        from maverick.codebase import vault
        return bool(vault.enabled())
    except Exception:  # noqa: BLE001 -- an unreadable switch shows as off
        return False


def create_immune_console_router() -> APIRouter:
    router = APIRouter(tags=["immune-console"])

    @router.get("/immune/summary")
    async def immune_summary(request: Request) -> dict:
        require_permission(request, "audit")
        if request.query_params:
            raise HTTPException(status_code=404, detail="immune summary unavailable")
        return await run_in_threadpool(_immune_summary, caller_principal(request))

    @router.get("/code/summary")
    async def code_summary(request: Request) -> dict:
        require_permission(request, "operate")
        if request.query_params:
            raise HTTPException(status_code=404, detail="code summary unavailable")
        return await run_in_threadpool(_code_summary)

    return router


def create_immune_console_page_router(templates: Jinja2Templates) -> APIRouter:
    if not isinstance(templates, Jinja2Templates):
        raise TypeError("immune consoles require a Jinja template authority")
    router = APIRouter(tags=["immune-console-pages"])

    def _render(request: Request, path: str, template: str) -> HTMLResponse:
        require_permission(request, _PERMISSION[path])
        if any(key not in {"theme", "density", "font", "lang"} for key in request.query_params):
            raise HTTPException(status_code=404, detail="page unavailable")
        nonce = secrets.token_urlsafe(18)
        response = templates.TemplateResponse(request, template, {
            "api_url": f"/api/v1{path}/summary", "page_path": path,
            "csp_style_nonce": nonce, "can_admin": has_permission(request, "admin"),
            "can_global_admin": has_global_permission(request, "admin"),
            "module_on": _module_on(path)})
        for name, value in _HEADERS.items():
            if name == "Content-Security-Policy":
                value = value.replace("style-src 'self'", f"style-src 'self' 'nonce-{nonce}'")
            response.headers[name] = value
        return response

    @router.get(IMMUNE_PATH, response_class=HTMLResponse, include_in_schema=False)
    async def immune_page(request: Request) -> HTMLResponse:
        return _render(request, IMMUNE_PATH, "immune.html")

    @router.get(CODE_PATH, response_class=HTMLResponse, include_in_schema=False)
    async def code_page(request: Request) -> HTMLResponse:
        return _render(request, CODE_PATH, "code.html")

    return router


router = create_immune_console_router()

__all__ = ["ASSET_PATH", "CODE_PATH", "IMMUNE_PATH", "create_immune_console_page_router",
           "create_immune_console_router", "router"]
