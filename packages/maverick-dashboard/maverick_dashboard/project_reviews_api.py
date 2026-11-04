"""Authenticated, workspace-scoped project-result review packets."""

from __future__ import annotations

import hmac
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request, Response
from maverick import config
from maverick.paths import current_tenant_id_strict
from maverick.privacy_ops import RecordConflict
from maverick.project_reviews import ProjectReviewDenied, ProjectReviews
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import rbac, scim_groups, suite_grants
from .auth import caller_principal, constant_time_equals, require_permission, role_for_principal
from .draft_api import context_for

router = APIRouter(tags=["project-reviews"])
BASE = "/api/v1/project-reviews"


class MutationIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    request_id: str = Field(
        ..., min_length=8, max_length=192, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]+$"
    )


class MembershipIn(MutationIn):
    member: str = Field(..., min_length=6, max_length=256)
    allowed: bool
    expected_revision: int = Field(..., ge=0)


class SendIn(MutationIn):
    previous_packet_id: str | None = Field(None, pattern=r"^PRP-[0-9a-f]{32}$")
    change_summary: str = Field("", max_length=4000)
    goal_id: int = Field(..., ge=1)
    reviewer: str = Field(..., min_length=6, max_length=256)
    note: str = Field(..., min_length=1, max_length=4000)
    due_at: float = Field(..., gt=0)
    source_version: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    expected_team_revision: int = Field(..., ge=1)


class RevisionIn(MutationIn):
    expected_revision: int = Field(..., ge=1)
    source_version: str = Field(..., pattern=r"^[0-9a-f]{64}$")


class ResponseIn(MutationIn):
    action: Literal["comment", "approve", "request_changes", "cancel"]
    note: str = Field(..., min_length=1, max_length=4000)
    expected_revision: int = Field(..., ge=1)
    source_version: str = Field(..., pattern=r"^[0-9a-f]{64}$")


def require_enabled(request):
    require_permission(request, "view")
    if (
        config.config_source_errors(include_tenant=True)
        or config.get_features().get("project_reviews") is not True
    ):
        raise HTTPException(
            403, "Project team reviews are disabled in Settings or configuration is unavailable."
        )
    principal, tenant = caller_principal(request), current_tenant_id_strict()
    if not principal or not principal.startswith("user:") or not tenant:
        raise HTTPException(
            403, "Sign in with a named account and select a workspace to use team reviews."
        )
    return principal, tenant


def _eligible(tenant, principal, suite, permission, member):
    if current_tenant_id_strict() != tenant or not principal.startswith("user:"):
        return False
    if member and principal not in rbac.list_tenant_roles(tenant):
        return False
    if scim_groups.active_for_principal(principal) is False:
        return False
    if permission not in rbac.permissions_for(role_for_principal(principal)):
        return False
    suites = suite_grants.granted_suites(principal)
    return suite is None or suites is None or suite in suites


def _service(request):
    from .app import _world

    principal, tenant = require_enabled(request)
    return ProjectReviews(
        _world(),
        principal=principal,
        eligible=lambda actor, suite, permission, member: _eligible(
            tenant, actor, suite, permission, member
        ),
    )


async def _call(request, response, operation, *, write=False):
    require_enabled(request)
    response.headers["Cache-Control"] = "private, no-store"
    supplied_context = request.headers.get("X-Lightwork-Review-Context")
    if supplied_context is not None and not constant_time_equals(supplied_context, context_for(request)):
        raise HTTPException(409, "Your account or workspace changed. Reload project reviews before reading or saving.")
    if write:
        require_permission(request, "operate")
        if not hmac.compare_digest(
            request.headers.get("X-Lightwork-Review-Context", ""), context_for(request)
        ):
            raise HTTPException(
                409, "Your account or workspace changed. Reload project reviews before saving."
            )
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
        raise HTTPException(
            503,
            "Project review authority is unavailable. The operation could not be confirmed; reload and retry the same request before creating another.",
        ) from exc


def _overview(request):
    service = _service(request)
    projects = []
    for project in service.world.list_projects(owner=service.principal):
        if project.get("status") == "active" and service._can_domain(
            service.principal, project.get("domain", ""), "operate"
        ):
            projects.append({key: project[key] for key in ("id", "name", "description")})
    items = service.inbox()
    return {
        "context": context_for(request),
        "principal": service.principal,
        "projects": projects,
        "items": items,
        "counts": {
            "total": len(items),
            "pending": sum(row["status"] == "pending" for row in items),
            "overdue": sum(row["overdue"] for row in items),
        },
        "live_task_authority_granted": False,
    }


@router.get("/project-reviews")
async def reviews_page(request: Request):
    from .app import templates

    require_enabled(request)
    return templates.TemplateResponse(
        request,
        "project_reviews.html",
        {"review_context": context_for(request)},
        headers={"Cache-Control": "private, no-store"},
    )


@router.get(BASE)
async def inbox(
    request: Request,
    response: Response,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    q: str = Query("", max_length=200),
):
    def read():
        model = _overview(request)
        rows = [
            row
            for row in model["items"]
            if not q or q.casefold() in (row["title"] + " " + row["project_name"]).casefold()
        ]
        return {
            **model,
            "items": rows[offset : offset + limit],
            "offset": offset,
            "limit": limit,
            "total": len(rows),
            "has_more": offset + limit < len(rows),
        }

    return await _call(request, response, read)


@router.get(BASE + "/projects/{project_id}")
async def project_setup(request: Request, response: Response, project_id: int):
    def read():
        service = _service(request)
        team = service.team(project_id)
        project = service.world.get_project(project_id)
        domain = project.get("domain", "")
        eligible = [
            actor
            for actor in rbac.list_tenant_roles(service.tenant)
            if actor != service.principal and service._can_domain(actor, domain, "operate", member=True)
        ]
        goals = []
        for goal in service.world.list_goals(
            project_id=project_id, owner=service.principal, limit=500, order="desc"
        ):
            if (
                goal.result
                and goal.status not in {"active", "pending"}
                and service._can_domain(service.principal, goal.domain, "operate")
            ):
                goals.append({"id": goal.id, "title": goal.title, "status": goal.status})
        return {"team": team, "eligible_members": sorted(eligible), "goals": goals}

    return await _call(request, response, read)


@router.put(BASE + "/projects/{project_id}/members")
async def membership(request: Request, response: Response, project_id: int, body: MembershipIn):
    return await _call(
        request,
        response,
        lambda: _service(request).set_member(project_id, **body.model_dump()),
        write=True,
    )


@router.get(BASE + "/projects/{project_id}/goals/{goal_id}/preview")
async def preview(request: Request, response: Response, project_id: int, goal_id: int):
    return await _call(request, response, lambda: _service(request).prepare(project_id, goal_id))


@router.post(BASE + "/projects/{project_id}/packets")
async def send(request: Request, response: Response, project_id: int, body: SendIn):
    return await _call(
        request,
        response,
        lambda: _service(request).send(project_id, **body.model_dump()),
        write=True,
    )


@router.get(BASE + "/packets/{packet_id}")
async def packet(request: Request, response: Response, packet_id: str):
    return await _call(request, response, lambda: _service(request).get(packet_id))


@router.post(BASE + "/packets/{packet_id}/responses")
async def respond(request: Request, response: Response, packet_id: str, body: ResponseIn):
    return await _call(
        request,
        response,
        lambda: _service(request).respond(packet_id, **body.model_dump()),
        write=True,
    )


@router.post(BASE + "/packets/{packet_id}/revision-draft")
async def revision_draft(request: Request, response: Response, packet_id: str, body: RevisionIn):
    return await _call(request, response,
                       lambda: _service(request).revision_draft(packet_id, **body.model_dump()), write=True)
