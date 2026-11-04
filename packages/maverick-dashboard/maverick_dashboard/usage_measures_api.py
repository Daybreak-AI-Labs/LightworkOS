"""The optional, name-free usage measures ([analytics] usage_measures) in the dashboard.

Pages report AI suggestions shown, used or dismissed through
``/api/v1/usage-measures/suggestion``; the shell notes when a signed-in person
is first seen, and the task page notes when they first see a finished result
of their own task. Results are on People > Ease-of-use results.
"""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import auth

router = APIRouter()
_SEEN: set[str] = set()  # people already noted by this process
_RESULTS: set[str] = set()  # people whose first result this process already noted


class SuggestionEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str = Field(min_length=1, max_length=40, pattern=r"^[a-z0-9_-]+$")
    item: str = Field(default="", max_length=500)
    event: Literal["shown", "accepted", "dismissed"]
    typing: bool = False


@router.post("/api/v1/usage-measures/suggestion")
async def suggestion_event(body: SuggestionEvent, request: Request) -> dict[str, Any]:
    from maverick import usage_measures

    from .app import _require_same_origin

    _require_same_origin(request)
    auth.require_permission(request, "view")
    principal = auth.caller_principal(request) or ""
    await run_in_threadpool(usage_measures.record_suggestion, principal, body.kind, body.item, body.event,
                            typing=body.typing)
    return {"recorded": usage_measures.enabled()}


def note_first_result(request: Request, goal) -> None:
    """A person sees a finished result of their own task."""
    try:
        from maverick import usage_measures

        principal = auth.caller_principal(request) or ""
        if goal is not None and goal.status == "done" and principal and goal.owner == principal \
                and principal not in _RESULTS and usage_measures.enabled():
            if usage_measures.note_first_result(principal):
                _RESULTS.add(principal)
    except Exception:  # noqa: BLE001 -- measuring never breaks the page
        return


def context(request: Request) -> dict[str, Any]:
    """Note a signed-in person the first time they are seen, and load the script."""
    try:
        from maverick import usage_measures

        on = usage_measures.enabled()
        principal = auth.caller_principal(request) or ""
        if on and principal and principal not in _SEEN:
            usage_measures.note_seen(principal, auth.caller_role(request) or "unknown")
            _SEEN.add(principal)
    except Exception:  # noqa: BLE001 -- the shell never fails over an optional measure
        on = False
    return {"usage_measures_on": on}


__all__ = ["context", "note_first_result", "router"]
