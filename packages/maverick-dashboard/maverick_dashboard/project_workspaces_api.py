"""Native project planning, reviewed writes and current-source reads."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Request, Response
from maverick import config
from maverick.authority_effects import authority_effect_fence
from maverick.paths import current_tenant_id_strict
from maverick.privacy_ops import RecordConflict
from maverick.project_reviews import ProjectReviewDenied, ProjectReviews
from maverick.project_workspaces import ProjectWorkspaces
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import rbac
from .auth import caller_principal, constant_time_equals, require_permission
from .draft_api import context_for
from .project_reviews_api import _eligible

router = APIRouter(tags=["project-workspaces"])
BASE = "/api/v1/project-workspaces"
Action = Literal["details", "member", "milestone", "remove_milestone", "reorder", "dependency",
                 "context", "remove_context", "save_defaults", "apply_defaults"]


class PlanIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    action: Action
    payload: dict


class ChangeIn(PlanIn):
    expected_revision: int = Field(ge=0)
    operation_id: str = Field(min_length=8, max_length=192, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]+$")
    confirmed: Literal[True]


def require_enabled(request):
    require_permission(request, "view")
    global_features = config.load_global_config().get("features", {})
    if (config.config_source_errors(include_tenant=True) or
            not isinstance(global_features, dict) or global_features.get("project_workspaces") is not True or
            config.get_features().get("project_workspaces") is not True):
        raise HTTPException(403, "Project workspaces are disabled. Ask an administrator to enable Project workspaces in Settings.")
    principal, tenant = caller_principal(request), current_tenant_id_strict()
    if not principal or not principal.startswith("user:") or not tenant:
        raise HTTPException(403, "Sign in with a named account and select a workspace to use project planning.")
    return principal, tenant


def service(request):
    from .app import _world
    principal, tenant = require_enabled(request)
    world = _world()
    def eligible(actor, suite, permission, member):
        return _eligible(tenant, actor, suite, permission, member)
    reviews = ProjectReviews(world, principal=principal, eligible=eligible) if config.get_features().get("project_reviews") is True else None
    return ProjectWorkspaces(world, principal=principal, eligible=eligible, reviews=reviews)


def state(request, project_id):
    native = service(request)
    workspace = native.get(project_id)
    choices = native.choices(project_id) if workspace["can_edit"] else {"goals": [], "reviews": []}
    if workspace["can_edit"]:
        choices["members"] = [actor for actor in rbac.list_tenant_roles(native.tenant)
                              if actor != native.principal and _eligible(native.tenant, actor, choices["suite"], "view", True)]
        choices["members"] = sorted(set(choices["members"]) | set(workspace["members"]))
    return {"context": context_for(request), "workspace": workspace, "choices": choices,
            "defaults": native.personal_defaults() if workspace["can_edit"] else None}


def prepare(request, project_id, action, payload):
    native = service(request)
    planned = native.plan(project_id, action, payload)
    def present(field, value):
        if field == "members":
            return [actor.removeprefix("user:") for actor in value]
        if field == "milestones":
            titles = {row["id"]: row["title"] for row in value}
            def goal_title(goal_id):
                try:
                    return native._task(project_id, goal_id).title
                except ProjectReviewDenied:
                    return "Restricted linked task"
            def review_title(packet_id):
                try:
                    return native._packet(project_id, packet_id)["snapshot"]["title"]
                except ProjectReviewDenied:
                    return "Restricted fixed review"
            return [{"milestone": row["title"], "date": row["due"] or "No target date",
                     "linked_tasks": [goal_title(goal_id) for goal_id in row["goals"]],
                     "linked_reviews": [review_title(packet_id) for packet_id in row["reviews"]],
                     "planning_prerequisites": [titles.get(key, "Removed milestone") for key in row["depends_on"]]} for row in value]
        if field == "context":
            result = []
            for ref in value:
                try:
                    current = native.preview_source(project_id, ref["kind"], ref["source_id"])
                    result.append({"source": current["title"], "current": current["version"] == ref["version"]})
                except (ValueError, ProjectReviewDenied):
                    result.append({"source": "Restricted or unavailable source", "current": False})
            return result
        return value
    changes = [{"label": row["field"].capitalize(), "before": present(row["field"], row["before"]),
                "after": present(row["field"], row["after"])} for row in planned["changes"]]
    if action == "save_defaults":
        structure = {key: planned["after"][key] for key in ("outcome", "criteria", "labels", "default_view")}
        structure["milestones"] = [row["title"] for row in planned["after"]["milestones"]]
        changes = [{"label": "My reusable project structure", "before": native.personal_defaults()["structure"], "after": structure}]
    return {"revision": planned["revision"], "changes": changes,
            "summary": "Review this project planning change. Shared metadata does not grant access to private tasks or reviews. Planning order and prerequisites do not change execution dependencies."}


def execute(request, project_id, body):
    require_permission(request, "operate")
    with authority_effect_fence():
        result = service(request).change(project_id, body.action, body.payload,
                                        expected_revision=body.expected_revision, operation_id=body.operation_id)
        require_enabled(request)
        return {**result, "context": context_for(request)}


async def _call(request, response, operation, *, write=False):
    require_enabled(request)
    response.headers["Cache-Control"] = "private, no-store"
    supplied = request.headers.get("X-Lightwork-Project-Context")
    if (write and supplied is None) or (supplied is not None and not constant_time_equals(supplied, context_for(request))):
        raise HTTPException(409, "Your account or workspace changed. Reload this project before continuing.")
    try:
        return await run_in_threadpool(operation)
    except ProjectReviewDenied as exc:
        raise HTTPException(404, str(exc)) from exc
    except RecordConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, "Project storage is unavailable. A save may be unconfirmed; check its status before another change. Your draft is kept.") from exc


@router.get("/project-workspaces")
@router.get("/project-workspaces/{project_id}")
async def page(request: Request, project_id: int | None = None):
    from .app import templates
    from .navigation_api import areas_redirect

    moved = areas_redirect(request)  # areas mode: Projects, and a project's Plan tab
    if moved is not None:
        return moved
    require_permission(request, "view")
    return templates.TemplateResponse(request, "project_workspaces.html",
                                      {"project_id": project_id, "project_context": context_for(request)},
                                      headers={"Cache-Control": "private, no-store"})


@router.get(BASE)
async def listing(request: Request, response: Response):
    return await _call(request, response, lambda: {"context": context_for(request), "projects": service(request).list()})


@router.get(BASE + "/{project_id}")
async def read(request: Request, response: Response, project_id: int):
    return await _call(request, response, lambda: state(request, project_id))


@router.post(BASE + "/{project_id}/prepare")
async def plan(request: Request, response: Response, project_id: int, body: PlanIn):
    return await _call(request, response, lambda: prepare(request, project_id, body.action, body.payload))


@router.post(BASE + "/{project_id}/change")
async def change(request: Request, response: Response, project_id: int, body: ChangeIn):
    return await _call(request, response, lambda: execute(request, project_id, body), write=True)


@router.post(BASE + "/{project_id}/receipt")
async def receipt(request: Request, response: Response, project_id: int, body: ChangeIn):
    return await _call(request, response, lambda: {"confirmed": service(request).receipt(
        project_id, body.operation_id, body.action, body.payload, body.expected_revision)})


@router.get(BASE + "/{project_id}/sources/{kind}/{source_id}")
async def source(request: Request, response: Response, project_id: int, kind: str, source_id: str):
    return await _call(request, response, lambda: service(request).preview_source(project_id, kind, source_id))


@router.get(BASE + "/{project_id}/context/{reference}")
async def context(request: Request, response: Response, project_id: int, reference: str):
    return await _call(request, response, lambda: service(request).open_source(project_id, reference))
