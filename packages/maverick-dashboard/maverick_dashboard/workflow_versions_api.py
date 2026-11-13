"""Review workflow snapshots and rendering-only samples without starting work."""
from __future__ import annotations

import difflib
import hashlib
import hmac
import json

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from .auth import caller_principal, goal_owner_filter, has_permission, require_permission
from .draft_api import context_for

router = APIRouter(tags=["workflow-versions"])


class Mutation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context: str = Field(pattern=r"^[a-f0-9]{64}$")


class FixtureIn(Mutation):
    expected_version: str = Field(pattern=r"^[a-f0-9]{64}$")
    inputs: dict[str, str] = Field(default_factory=dict)
    label: str = Field(default="Sample", min_length=1, max_length=100)
    expected_contains: str = Field(default="", max_length=4000)


class PublishIn(Mutation):
    expected_version: str = Field(pattern=r"^[a-f0-9]{64}$")
    impact_version: str = Field(pattern=r"^[a-f0-9]{64}$")
    label: str = Field(min_length=1, max_length=100)
    confirm: bool = False


class RestoreIn(Mutation):
    version: str = Field(pattern=r"^[a-f0-9]{64}$")
    expected_generation: int = Field(ge=0, strict=True)
    new_name: str | None = Field(default=None, min_length=1, max_length=120, pattern=r"^[A-Za-z0-9_-]+$")


def _authority(request, name, *, mutation=None):
    from maverick.templates import _validate_template_name
    from maverick.workflow_versions import enabled

    # Publishing pins a reviewed revision of one's own workflow. It neither
    # shares private content nor arms a schedule, and needs the same operate
    # ceiling as authoring and running that workflow.
    require_permission(request, "operate")
    try:
        _validate_template_name(name)
    except ValueError as exc:
        raise HTTPException(400, "Choose a saved workflow.") from exc
    if not enabled():
        raise HTTPException(403, "Workflow version management is disabled in Settings.")
    if mutation is not None:
        from .app import _require_same_origin

        _require_same_origin(request)
        if not hmac.compare_digest(mutation.context, context_for(request)):
            raise HTTPException(409, "Account or workspace changed. Review the workflow again.")
    return caller_principal(request) or "local", has_permission(request, "admin")


def _call(callable, *args, **kwargs):
    try:
        return callable(*args, **kwargs)
    except FileExistsError as exc:
        raise HTTPException(409, str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(404, "Workflow is unavailable.") from exc
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


def _impact(request, name):
    from maverick.job_queue import JobQueue
    from maverick.schedule_definitions import list_definitions

    schedules = [{k: row[k] for k in ("definition_id", "title", "revision", "state", "template_version", "template_generation")}
                 for row in list_definitions(JobQueue(), owner=goal_owner_filter(request)) if row["template_name"] == name]
    version = hashlib.sha256(json.dumps(schedules, sort_keys=True).encode()).hexdigest()
    return {"schedules": schedules, "impact_version": version,
            "effect": "Existing schedules keep their reviewed content and version. Publishing affects only new schedules; migration is never automatic."}


@router.get("/api/v1/workflows/{name}/versions")
def versions(request: Request, name: str):
    from maverick.workflow_versions import history

    actor, admin = _authority(request, name)
    value = _call(history, name, actor, admin=admin)
    current = next(item for item in value["versions"] if item["current"])
    for item in value["versions"]:
        item["diff"] = list(difflib.unified_diff(item["content"].splitlines(), current["content"].splitlines(),
                                                fromfile=item["label"], tofile="Current draft", lineterm=""))
        del item["content"]
    return {**value, **_impact(request, name), "context": context_for(request), "can_publish": has_permission(request, "operate")}


@router.post("/api/v1/workflows/{name}/fixtures")
def fixture(request: Request, name: str, body: FixtureIn):
    from maverick.workflow_versions import record_fixture

    actor, admin = _authority(request, name, mutation=body)
    return _call(record_fixture, name, actor, admin=admin, expected_version=body.expected_version,
                 inputs=body.inputs, expected_contains=body.expected_contains, label=body.label)


@router.post("/api/v1/workflows/{name}/publish")
def publish(request: Request, name: str, body: PublishIn):
    from maverick.workflow_versions import publish as publish_version

    actor, admin = _authority(request, name, mutation=body)
    if not body.confirm:
        raise HTTPException(422, "Review the schedule impact before publishing.")
    if not hmac.compare_digest(body.impact_version, _impact(request, name)["impact_version"]):
        raise HTTPException(409, "Schedule impact changed. Refresh the publication review.")
    return _call(publish_version, name, actor, expected_version=body.expected_version, label=body.label, admin=admin)


@router.post("/api/v1/workflows/{name}/restore")
def restore(request: Request, name: str, body: RestoreIn):
    from maverick.workflow_versions import restore as restore_version

    actor, admin = _authority(request, name, mutation=body)
    template = _call(restore_version, name, body.version, actor, expected_generation=body.expected_generation,
                     new_name=body.new_name, admin=admin)
    return {"name": template.name, "generation": template.generation, "state": "draft", "published_changed": False}
