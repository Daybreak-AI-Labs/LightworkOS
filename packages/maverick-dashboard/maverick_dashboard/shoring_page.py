"""Authenticated operator page for Autonomous Shoring (Observe -> Autonomous
Shoring).

Ties the engagement together on one surface: the Shoring P&L (money saved vs
the human baseline, from :mod:`maverick.savings`), the Book of Work with each
function's lifecycle status and per-SLA met/at-risk/breached indicators
(:mod:`maverick.shoring`), an operator form to add or update a function, and
the exception desk -- the pending human sign-offs for each shored function's
department, drawn from the same approvals queue behind ``/approvals``.

Read-only ``view`` floor; the add/update form posts to the operate-gated
shoring API.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from ._shared import _world
from .auth import goal_owner_filter, has_global_permission, require_permission

PAGE_PATH = "/shoring"
API_BASE = "/api/v1/shoring"

LIFECYCLE_LABELS = {
    "scoping": ("Planning", "Deciding what work moves and what good looks like."),
    "demonstrating": ("Trying it out", "Lightwork does the work alongside your team."),
    "running": ("Running", "Lightwork does the work; people handle exceptions."),
    "proving": ("Proving results", "Measuring savings and service levels over time."),
}
METRIC_LABELS = {
    "throughput_per_day": ("Items completed per day", "at least", "per day"),
    "max_exception_rate_pct": ("Items needing a person (%)", "at most", "%"),
    "max_turnaround_hours": ("Longest time to finish (hours)", "at most", "hours"),
}


def _people() -> list[dict]:
    from .ui_choices_api import people_choices

    try:
        return people_choices()
    except Exception:  # the picker degrades to "No owner"; saving still works
        return []


def _department_choices(world, functions) -> dict:
    from .ui_choices_api import work_area_choices

    return work_area_choices(world, [f.get("department") for f in functions or []])


def create_shoring_page_router(templates: Jinja2Templates) -> APIRouter:
    if not isinstance(templates, Jinja2Templates):
        raise TypeError("shoring page requires a Jinja template authority")
    router = APIRouter(tags=["shoring-console"])

    @router.get(PAGE_PATH, response_class=HTMLResponse, include_in_schema=False)
    async def shoring_console(request: Request) -> HTMLResponse:
        require_permission(request, "view")
        from maverick import savings as savings_mod
        from maverick import shoring

        if not shoring.enabled():
            # Friendly turned-off page (still 404 for clients probing it).
            return templates.TemplateResponse(
                request, "shoring.html",
                {"disabled": True, "api_base": API_BASE,
                 "can_turn_on": has_global_permission(request, "admin")},
                status_code=404)

        world = _world()
        try:
            report = await run_in_threadpool(savings_mod.compute, world, owner=goal_owner_filter(request))
            functions = await run_in_threadpool(shoring.book_status, world, owner=goal_owner_filter(request))
        except (OSError, RuntimeError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="Shoring data is unavailable. Restore access to the work store and reload.",
            ) from exc
        can_manage = has_global_permission(request, "operate")
        return templates.TemplateResponse(
            request,
            "shoring.html",
            {
                "api_base": API_BASE,
                "report": savings_mod.to_dict(report),
                "functions": functions,
                "lifecycle": shoring.LIFECYCLE,
                "metrics": [
                    {"key": key, "unit": spec["unit"], "direction": spec["direction"]}
                    for key, spec in shoring.METRICS.items()
                ],
                "metric_labels": METRIC_LABELS,
                "lifecycle_labels": LIFECYCLE_LABELS,
                "can_manage": can_manage,
                "people": _people() if can_manage else [],
                "departments": (
                    await run_in_threadpool(_department_choices, world, functions)
                    if can_manage else {"recent": [], "groups": []}
                ),
                "approvals_path": "/approvals",
            },
        )

    return router


__all__ = ["API_BASE", "PAGE_PATH", "create_shoring_page_router"]
