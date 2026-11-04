"""Get started: run a department's first outcome on bundled sample data.

The page offers the eight departments from :mod:`maverick.sample_outcomes`.
On click this creates the sample workspace under the configured sandbox
workdir, records a goal that runs the department's specialist pack, marks the
goal as sample data, and starts it in the background exactly like a REST goal
start. When no AI service is ready it says so plainly and points at Settings
instead of failing quietly.
"""
from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from maverick.runner import (
    DEFAULT_MAX_DEPTH,
    clamp_task_limit,
    configured_max_dollars,
    configured_max_wall_seconds,
    run_goal_in_background_async,
)
from pydantic import BaseModel, ConfigDict, Field

from ._shared import _world
from .auth import (
    caller_principal,
    caller_suites,
    execution_user_id_from_request,
    require_permission,
    require_suite,
)

router = APIRouter(prefix="/api/v1", tags=["v1"])

CONNECT_HREF = "/settings#settings-integrations"
NOT_READY_DETAIL = ("No AI service is ready yet, so the sample task cannot run. "
                    "Connect an AI service in Settings, then try again.")


class FirstOutcomeRunIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    department: str = Field(..., min_length=1, max_length=40)


def provider_ready() -> bool:
    """Offline readiness of the selected model routes (never a live check)."""
    from . import onboarding_state

    try:
        return onboarding_state.selected_model_route_state()["configured"] is True
    except Exception:
        return False


@router.get("/first-outcome")
def list_first_outcomes(request: Request) -> dict:
    require_permission(request, "view")
    from .guided_outcome import first_outcomes_for

    return first_outcomes_for(request)


@router.post("/first-outcome/run", status_code=201)
def run_first_outcome(request: Request, payload: FirstOutcomeRunIn, bg: BackgroundTasks) -> dict:
    require_permission(request, "operate")
    from maverick import sample_outcomes
    from maverick.domain import enabled_domains, suites_for_domain

    from maverick_dashboard.app import check_goal_rate_limit

    department = sample_outcomes.resolve_department(payload.department, default=None)
    if department is None:
        raise HTTPException(404, "Choose one of the listed departments.")
    outcome = sample_outcomes.get(department)
    profile = enabled_domains().get(outcome.pack)
    if profile is None:
        raise HTTPException(409, f"The {outcome.label} specialist is turned off in this workspace.")
    for suite in suites_for_domain(outcome.pack, profile):
        require_suite(request, suite)
    if not provider_ready():
        raise HTTPException(409, {"ready": False, "detail": NOT_READY_DETAIL, "href": CONNECT_HREF})
    check_goal_rate_limit(request)
    try:
        workspace = sample_outcomes.create_sample_workspace(department)
    except OSError as exc:
        raise HTTPException(503, "The sample workspace could not be created in the work folder. "
                                 "Check the folder in Settings and try again.") from exc
    world = _world()
    owner = caller_principal(request) or ""
    goal_id = world.create_goal(outcome.title[:200], sample_outcomes.goal_description(department), owner=owner)
    world.set_goal_domain(goal_id, outcome.pack)
    sample_outcomes.mark_goal_as_sample(world, goal_id, department)
    max_dollars = clamp_task_limit(None, configured_max_dollars())
    max_wall_seconds = clamp_task_limit(None, configured_max_wall_seconds())
    allowed_suites = caller_suites(request)
    user_id = execution_user_id_from_request(request)
    kwargs = {"allowed_suites": allowed_suites}
    if user_id:
        kwargs.update(channel="api", user_id=user_id)
    bg.add_task(run_goal_in_background_async, goal_id, max_dollars, max_wall_seconds, DEFAULT_MAX_DEPTH, **kwargs)
    return {
        "goal_id": goal_id, "href": f"/chat/goal/{goal_id}", "department": department,
        "pack": outcome.pack, "lands_in": outcome.lands_in, "sample": True,
        "workspace": str(workspace), "detail": sample_outcomes.SAMPLE_RULE,
    }
