"""Finance operations that were terminal-only, as buttons on the finance pages.

``GET /api/v1/finance/sod-check`` is ``maverick finance lint-sod``: the same
kernel check (:func:`maverick.finance.sod_linter.lint_finance_roster`) over
every installed finance team, answered in plain sentences. The command's own
lines stay in ``technical`` for the page's collapsed "Technical details". It
only reads, so it records nothing, and it needs the same ``operate``
permission as the finance command center that shows it.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, JSONResponse
from starlette.concurrency import run_in_threadpool

from .auth import require_permission

router = APIRouter()

_STATIC = Path(__file__).parent / "static"

# The four duties the check keeps apart, as a person would say them.
_DUTIES = {
    "record": "record entries",
    "authorize": "approve or post",
    "custody": "move money",
    "reconcile": "reconcile accounts",
}


def _plain(value: str) -> str:
    return str(value).replace("_", " ").strip()


def _team(compartment: str) -> str:
    return _plain(compartment).capitalize() or "A finance team"


def _finding(conflict) -> dict[str, str]:
    duty_a = _DUTIES.get(conflict.duty_a, _plain(conflict.duty_a))
    duty_b = _DUTIES.get(conflict.duty_b, _plain(conflict.duty_b))
    tools_a = ", ".join(_plain(t) for t in conflict.tools_a)
    tools_b = ", ".join(_plain(t) for t in conflict.tools_b)
    return {
        "team": _team(conflict.compartment),
        "sentence": (f"This team can both {duty_a} ({tools_a}) and {duty_b} ({tools_b}). "
                     "These duties must sit with different teams."),
    }


def sod_check() -> dict[str, Any]:
    from maverick.finance.sod_linter import lint_finance_roster

    packs, conflicts = lint_finance_roster()
    teams = len(packs)
    if conflicts:
        count = len(conflicts)
        summary = (f"{count} problem{'s' if count != 1 else ''} found across {teams} finance AI teams. "
                   "Each one lets a single team hold two duties that should be kept apart.")
    else:
        summary = (f"No problems found. All {teams} finance AI teams keep recording, approving, "
                   "moving money and reconciling apart.")
    return {
        "ok": not conflicts,
        "teams": teams,
        "summary": summary,
        "findings": [_finding(c) for c in conflicts],
        # The command's own wording, for the collapsed technical view only.
        "technical": ([f"SoD CONFLICT: {c}" for c in conflicts]
                      or [f"OK: {teams} finance packs are segregation-of-duties clean."]),
    }


@router.get("/api/v1/finance/sod-check")
async def finance_sod_check(request: Request) -> JSONResponse:
    require_permission(request, "operate")
    return JSONResponse(await run_in_threadpool(sod_check), headers={"Cache-Control": "no-store"})


@router.get("/static/lightwork-finance-sod-check.js", include_in_schema=False)
async def finance_sod_check_script() -> FileResponse:
    return FileResponse(_STATIC / "lightwork-finance-sod-check.js",
                        media_type="application/javascript; charset=utf-8",
                        headers={"Cache-Control": "public, max-age=300"})


__all__ = ["router", "sod_check"]
