"""Native handoff review and acceptance: no implicit chat access or execution."""
from fastapi import APIRouter, Request
from maverick import config
from maverick.authority_effects import authority_effect_fence
from maverick.goal_mutations import GoalMutationConflict
from maverick.task_execution_guard import TaskBusy
from maverick.task_handoffs import TaskHandoffs
from pydantic import BaseModel, ConfigDict, Field

from .deliverable_bundles_api import call as bundle_call
from .deliverable_bundles_api import response
from .deliverable_bundles_api import service as bundle_service
from .draft_api import context_for
from .product_errors import product_error

router = APIRouter()
BASE = "/api/v1/task-handoffs"


class Choices(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    title: str = Field(min_length=1, max_length=160)
    instruction: str = Field(min_length=1, max_length=12000)
    commitments: str = Field(min_length=1, max_length=4000)
    max_dollars: float = Field(gt=0, le=1000000, allow_inf_nan=False)


class Offer(Choices):
    expected_review: str = Field(pattern=r"^[a-f0-9]{64}$")
    operation_id: str = Field(pattern=r"^[A-Za-z0-9_-]{12,100}$")


class ResponseInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    action: str = Field(pattern=r"^(accept|decline|withdraw)$")
    expected_revision: int = Field(ge=1)
    operation_id: str = Field(pattern=r"^[A-Za-z0-9_-]{12,100}$")


def service(request, *, write=False):
    if config.config_source_errors(include_tenant=True) or config.get_features().get("task_handoffs") is not True:
        raise product_error(403, "handoffs_disabled", "Task handoffs are disabled or their policy is unavailable.")
    return TaskHandoffs(bundle_service(request, write=write))


def call(operation):
    try:
        return bundle_call(operation)
    except (TaskBusy, GoalMutationConflict) as exc:
        raise product_error(409, "handoff_boundary_changed", str(exc)) from exc


@router.get("/task-handoffs")
def page(request: Request, bundle: str = ""):
    from .app import templates
    service(request)
    return templates.TemplateResponse(request, "task_handoffs.html", {"handoff_context": context_for(request), "handoff_bundle": bundle},
                                      headers={"Cache-Control": "private, no-store"})


@router.get(BASE)
def inbox(request: Request):
    source = service(request)
    return response(request, {"items": call(source.inbox)})


@router.get(BASE + "/{handoff_id}")
def get(request: Request, handoff_id: str):
    source = service(request)
    return response(request, {"handoff": call(lambda: source.get(handoff_id))})


@router.post(BASE + "/bundle/{bundle_id}/preview")
def preview(request: Request, bundle_id: str, body: Choices):
    source = service(request, write=True)
    return response(request, {"preview": call(lambda: source.prepare(bundle_id, **body.model_dump()))})


@router.post(BASE + "/bundle/{bundle_id}/offer")
def offer(request: Request, bundle_id: str, body: Offer):
    source = service(request, write=True)
    with authority_effect_fence():
        return response(request, {"handoff": call(lambda: source.create(bundle_id, **body.model_dump()))})


@router.post(BASE + "/{handoff_id}/respond")
def respond(request: Request, handoff_id: str, body: ResponseInput):
    source = service(request, write=True)
    with authority_effect_fence():
        return response(request, {"handoff": call(lambda: source.respond(handoff_id, **body.model_dump()))})
