"""Named task-owner review and explicit restoration of captured local files."""
from __future__ import annotations

import hmac
import os

from fastapi import APIRouter, HTTPException, Request, Response
from maverick import config, task_file_recovery, workspace_journal
from maverick.domain import suites_for_domain
from maverick.paths import current_tenant_id_strict
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import settings_store
from .auth import (
    caller_principal,
    constant_time_equals,
    require_global_permission,
    require_permission,
    require_suite,
)
from .draft_api import context_for

router = APIRouter(tags=["task-file-recovery"])
BASE = "/api/v1/task-files"


class Reviewed(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    confirm: bool


class Restore(Reviewed):
    version: str = Field(pattern=r"^[a-f0-9]{64}$")
    request_id: str = Field(pattern=r"^[A-Za-z0-9_-]{8,100}$")


def _authority(request, goal_id=None, payload=None):
    from .app import _require_same_origin, _world
    require_permission(request, "operate")
    actor = caller_principal(request)
    if not actor or not actor.startswith("user:") or not current_tenant_id_strict():
        raise HTTPException(403, "Sign in with a named account and select a workspace to recover task files.")
    context = context_for(request)
    supplied = request.headers.get("X-Lightwork-File-Context")
    if supplied is not None and not constant_time_equals(supplied, context):
        raise HTTPException(409, "Your account or workspace changed. Reload file recovery.")
    if payload is not None:
        _require_same_origin(request)
        if payload.confirm is not True or not hmac.compare_digest(payload.context, context):
            raise HTTPException(409, "Review and confirm recovery in the current account and workspace.")
    world = _world()
    if goal_id is not None:
        goal = world.get_goal(goal_id)
        if goal is None or goal.owner != actor:
            raise HTTPException(404, "Task file history was not found.")
        for suite in suites_for_domain(goal.domain):
            require_suite(request, suite)
        if goal.project_id is not None:
            project = world.get_project(goal.project_id)
            if not project or project.get("owner") != actor:
                raise HTTPException(404, "Task file history was not found.")
    return world, actor, context


async def _call(request, response, operation, goal_id=None, payload=None):
    response.headers["Cache-Control"] = "private, no-store"
    _authority(request, goal_id, payload)
    try:
        return await run_in_threadpool(operation)
    except HTTPException:
        raise
    except PermissionError as exc:
        raise HTTPException(403, "Current task recovery authority is unavailable.") from exc
    except task_file_recovery.RecoveryConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, "File recovery could not be confirmed. Keep the reviewed request and refresh before retrying; no new task was started.") from exc


@router.get(BASE + "/{goal_id}")
async def status(request: Request, response: Response, goal_id: int):
    def operation():
        world, actor, context = _authority(request, goal_id)
        try:
            require_global_permission(request, "admin")
            can_enable = True
        except HTTPException:
            can_enable = False
        return {"context": context, "capture_enabled": workspace_journal.enabled() and workspace_journal.strict(), "strict": workspace_journal.strict(),
                "goal_id": goal_id, "can_enable": can_enable, "has_history": task_file_recovery._load(task_file_recovery._key(world, goal_id)) is not None}
    return await _call(request, response, operation, goal_id)


@router.get(BASE + "/{goal_id}/preview")
async def preview(request: Request, response: Response, goal_id: int):
    def operation():
        world, actor, context = _authority(request, goal_id)
        return {"context": context, **task_file_recovery.preview(world, goal_id, actor)}
    return await _call(request, response, operation, goal_id)


@router.post(BASE + "/{goal_id}/restore")
async def restore(request: Request, response: Response, goal_id: int, body: Restore):
    def operation():
        world, actor, context = _authority(request, goal_id, body)
        result = task_file_recovery.revert(world, goal_id, actor, version=body.version, request_id=body.request_id, confirm=body.confirm)
        return {"context": context, "operation": result}
    return await _call(request, response, operation, goal_id, body)


@router.post(BASE + "/enable")
async def enable(request: Request, response: Response, body: Reviewed):
    def operation():
        _authority(request, payload=body)
        require_global_permission(request, "admin")
        if config.config_source_errors(include_tenant=True):
            raise task_file_recovery.RecoveryConflict("Configuration is unavailable.")
        for prefix in ("MAVERICK_", "LIGHTWORK_"):
            for name in ("WORKSPACE_JOURNAL", "WORKSPACE_JOURNAL_STRICT"):
                if prefix + name in os.environ:
                    raise task_file_recovery.RecoveryConflict("Deployment settings manage file capture. An in-app choice cannot override them.")
        with settings_store._locked():
            before = settings_store._load_overlay_for_update()
            updated = {**before, "workspace": {**before.get("workspace", {}), "journal": True, "journal_strict": True}}
            settings_store._write(updated)
            config.reset_config_cache()
            if not workspace_journal.enabled() or not workspace_journal.strict():
                settings_store._write(before)
                config.reset_config_cache()
                raise task_file_recovery.RecoveryConflict("Higher-precedence deployment settings prevented capture. Nothing was enabled.")
        return {"context": context_for(request), "capture_enabled": True, "strict": True}
    return await _call(request, response, operation, payload=body)


@router.post(BASE + "/disable")
async def disable(request: Request, response: Response, body: Reviewed):
    """Turn file protection off for future task runs. Originals already saved
    for earlier runs are kept and can still be restored."""
    def operation():
        from maverick.audit import AuditRefused, EventKind, audit_event
        _, actor, _ = _authority(request, payload=body)
        require_global_permission(request, "admin")
        if config.config_source_errors(include_tenant=True):
            raise task_file_recovery.RecoveryConflict("Configuration is unavailable.")
        for prefix in ("MAVERICK_", "LIGHTWORK_"):
            for name in ("WORKSPACE_JOURNAL", "WORKSPACE_JOURNAL_STRICT"):
                if prefix + name in os.environ:
                    raise task_file_recovery.RecoveryConflict("Deployment settings manage file capture. An in-app choice cannot override them.")
        with settings_store._locked():
            before = settings_store._load_overlay_for_update()
            was = {"journal": workspace_journal.enabled(), "journal_strict": workspace_journal.strict()}
            updated = {**before, "workspace": {**before.get("workspace", {}), "journal": False, "journal_strict": False}}
            settings_store._write(updated)
            config.reset_config_cache()
            if workspace_journal.enabled() or workspace_journal.strict():
                settings_store._write(before)
                config.reset_config_cache()
                raise task_file_recovery.RecoveryConflict("Higher-precedence deployment settings keep file capture on. Nothing was turned off.")
            try:
                for key, old in was.items():
                    if old:
                        audit_event(EventKind.SETTING_CHANGED, agent="dashboard", _global=True, actor=actor,
                                    section="workspace", key=key, old=True, new=False, confirmed=True)
            except AuditRefused as exc:
                settings_store._write(before)
                config.reset_config_cache()
                raise HTTPException(503, "The change could not be recorded, so it was undone.") from exc
        return {"context": context_for(request), "capture_enabled": False, "strict": False}
    return await _call(request, response, operation, payload=body)


@router.get("/chat/goal/{goal_id}/files")
def page(request: Request, goal_id: int):
    from .app import templates
    world, _, _ = _authority(request, goal_id)
    return templates.TemplateResponse(request, "task_file_recovery.html", {"goal": world.get_goal(goal_id)}, headers={"Cache-Control": "private, no-store"})
