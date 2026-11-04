"""Administrator workbench for scoped plugin qualification; no install effects."""
from __future__ import annotations

import hmac
import json
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import caller_principal, can_access_goal, require_global_permission
from .draft_api import context_for

router = APIRouter(tags=["plugin-qualification"])


def _authority(request, context=None):
    from maverick.plugin_workbench import config

    require_global_permission(request, "admin")
    try:
        config()
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    if context is not None:
        from .app import _require_same_origin

        _require_same_origin(request)
        if not hmac.compare_digest(context, context_for(request)):
            raise HTTPException(409, "Account or workspace changed. Review the workbench again.")


def _dependencies(request):
    from maverick.paths import data_dir

    from .app import _world
    from .flows_api import _can_access_flow

    rows, coverage = [], []
    try:
        world = _world()
        directory = data_dir() / "plugin-task-pins"
        for path in sorted(directory.glob("*.json"))[:2000]:
            goal = world.get_goal(int(path.stem))
            if goal is not None and can_access_goal(request, goal):
                values = json.loads(path.read_text(encoding="utf-8"))
                for pin in values.values():
                    rows.append({**pin, "title": goal.title, "state": goal.status,
                                 "href": "/chat/goal/" + str(goal.id)})
        coverage.append("Task use is recorded from first governed plugin dispatch; unrelated and unauthorized task content is excluded.")
    except Exception:
        coverage.append("Task pin inventory is unavailable.")
    flows = []
    try:
        from maverick.flow import store

        for flow in store.list_flows():
            if _can_access_flow(request, flow):
                from .connection_dependencies import _tools

                flows.append({"id": flow.id, "name": flow.name, "tools": sorted(_tools(flow.to_dict())),
                              "revision": flow.revision, "href": "/flows"})
    except Exception:
        coverage.append("Saved-flow inventory is unavailable.")
    run_pins = []
    try:
        from maverick.flow import store
        for path in sorted((data_dir() / "plugin-flow-pins").glob("*.json"))[:2000]:
            run = store.load_run(path.stem, owner=caller_principal(request) or "")
            flow = store.load_flow(run.flow_id) if run is not None else None
            if run is None or flow is None or not _can_access_flow(request, flow):
                continue
            for pin in json.loads(path.read_text(encoding="utf-8")).values():
                run_pins.append({**pin, "state": run.status, "title": flow.name, "href": "/flows"})
        coverage.append("Direct workflow pins survive resumed runs. Each task and run inventory shows up to 2000 pin records; no version is silently migrated.")
    except Exception:
        coverage.append("Workflow pin inventory is unavailable.")
    coverage.append("Qualification executes actual Python tool, channel, skill, persona, bundled Node and local gRPC contracts inside the restricted image. Live-service acceptance remains separate.")
    return {"tasks": rows, "flows": flows, "runs": run_pins, "coverage": coverage}


@router.get("/api/v1/plugins/workbench")
async def get_workbench(request: Request):
    from maverick import plugin_workbench as workbench

    _authority(request)
    def read():
        context = context_for(request)
        value = {"context": context, "plugins": workbench.snapshot(),
                 **workbench.history(context), "dependencies": _dependencies(request)}
        require_global_permission(request, "admin")
        if not hmac.compare_digest(context, context_for(request)):
            raise HTTPException(409, "Account or workspace changed during review.")
        return value
    return await run_in_threadpool(read)


class CheckIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    operation_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    mode: str = Field(pattern=r"^(sample|timeout|cancellation)$")
    sample: dict = Field(default_factory=dict)
    expected: Any = None
    confirm: bool = False


@router.post("/api/v1/plugins/workbench/check")
async def check_plugin(request: Request, body: CheckIn):
    from maverick import plugin_workbench as workbench

    _authority(request, body.context)
    if not body.confirm:
        raise HTTPException(409, "Review the exact plugin version and sample before running its sandbox check.")
    try:
        result = await run_in_threadpool(workbench.run_check, body.context, body.operation_id,
            body.fingerprint, body.sample, body.mode, authorize=lambda: _authority(request, body.context), expected=body.expected)
        _authority(request, body.context)
        return result
    except (ValueError, PermissionError) as exc:
        raise HTTPException(409, str(exc)) from exc


class ContextIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context: str = Field(pattern=r"^[a-f0-9]{64}$")


@router.post("/api/v1/plugins/workbench/{operation}/cancel")
def cancel_plugin_check(request: Request, operation: str, body: ContextIn):
    from maverick import plugin_workbench as workbench

    _authority(request, body.context)
    try:
        return workbench.cancel(body.context, operation)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc


class PublishIn(ContextIn):
    fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    rollback: str = Field(min_length=10, max_length=2000)
    confirm: bool = False


@router.post("/api/v1/plugins/workbench/publish")
def publish_plugin_check(request: Request, body: PublishIn):
    from maverick import plugin_workbench as workbench

    _authority(request, body.context)
    if not body.confirm:
        raise HTTPException(409, "Review the affected work and rollback plan before publishing.")
    try:
        return workbench.publish(body.context, body.fingerprint, body.rollback,
                                 authorize=lambda: _authority(request, body.context))
    except (ValueError, PermissionError) as exc:
        raise HTTPException(409, str(exc)) from exc


class MigrateIn(ContextIn):
    goal_id: int = Field(ge=1)
    fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    previous: str = Field(pattern=r"^[a-f0-9]{64}$")
    operation_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    confirm: bool = False


@router.post("/api/v1/plugins/workbench/migrate")
def migrate_plugin_pin(request: Request, body: MigrateIn):
    from maverick import plugin_workbench as workbench
    from maverick.file_lock import atomic_read_text, atomic_write_text, cross_process_lock
    from maverick.paths import data_dir

    from .app import _world

    _authority(request, body.context)
    goal = _world().get_goal(body.goal_id)
    if goal is None or not can_access_goal(request, goal):
        raise HTTPException(404, "Task is unavailable in this account.")
    if not body.confirm or goal.status not in {"paused", "failed", "cancelled", "done"}:
        raise HTTPException(409, "Finish, pause or cancel the task before reviewing its plugin migration. No uncertain action can be resumed here.")
    try:
        selected = workbench.selected(body.fingerprint)
        if not any(row["fingerprint"] == body.fingerprint and row["current"] for row in workbench.history(body.context)["publications"]):
            raise ValueError("Publish current scoped sandbox readiness before migrating a task pin.")
        path = data_dir() / "plugin-task-pins" / (str(body.goal_id) + ".json")
        with cross_process_lock(path, strict=True):
            current_goal = _world().get_goal(body.goal_id)
            if (current_goal is None or not can_access_goal(request, current_goal)
                    or current_goal.status not in {"paused", "failed", "cancelled", "done"}):
                raise ValueError("Task authority or active state changed. Review migration again.")
            _authority(request, body.context)
            workbench.selected(body.fingerprint)
            pins = json.loads(atomic_read_text(path, encoding="utf-8"))
            from maverick.plugin_execution_pins import pin_key
            key = pin_key(selected["group"], selected.get("pin_name", selected["name"]), selected["distribution"])
            old = pins.get(key)
            if old and body.operation_id and old.get("migration_operations", {}).get(body.operation_id) == {"previous": body.previous, "current": selected["content_sha256"]} and old["owner"] == (caller_principal(request) or ""):
                return {"migrated": True, "task_resumed": False, "historical_actions_replayed": False}
            if not old or old["fingerprint"] != body.previous or old["owner"] != (caller_principal(request) or ""):
                raise ValueError("The reviewed task pin changed or belongs to a different owner.")
            old["prior_fingerprints"] = list(old.get("prior_fingerprints", [])) + [body.previous]
            old["fingerprint"] = selected["content_sha256"]
            if body.operation_id:
                old.setdefault("migration_operations", {})[body.operation_id] = {"previous": body.previous, "current": selected["content_sha256"]}
            atomic_write_text(path, json.dumps(pins, sort_keys=True))
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(409, str(exc)) from exc
    return {"migrated": True, "task_resumed": False, "historical_actions_replayed": False}


class MigrateFlowIn(ContextIn):
    run_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")
    fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    previous: str = Field(pattern=r"^[a-f0-9]{64}$")
    operation_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    confirm: bool = False


@router.post("/api/v1/plugins/workbench/migrate-flow")
def migrate_flow_plugin_pin(request: Request, body: MigrateFlowIn):
    from maverick import plugin_workbench as workbench
    from maverick.file_lock import atomic_read_text, atomic_write_text, cross_process_lock
    from maverick.flow import store
    from maverick.plugin_execution_pins import flow_path

    from .flows_api import _can_access_flow

    _authority(request, body.context)
    if not body.confirm:
        raise HTTPException(409, "Review the stopped workflow and earlier outcomes before migration.")
    try:
        # Same outer lock as execution: a running action cannot migrate underneath
        # its dispatch check. No run is resumed and no previous effect is replayed.
        with store.run_lock(body.run_id):
            run = store.load_run(body.run_id, owner=caller_principal(request) or "")
            flow = store.load_flow(run.flow_id) if run is not None else None
            if run is None or flow is None or not _can_access_flow(request, flow):
                raise HTTPException(404, "Workflow run is unavailable in this account.")
            if run.status not in {"paused_approval", "paused_delay", "paused_event", "failed", "budget_limited", "completed", "rejected"}:
                raise ValueError("Only a stopped, reconciled workflow may migrate; running or indeterminate work is blocked.")
            _authority(request, body.context)
            selected = workbench.selected(body.fingerprint)
            if not any(row["fingerprint"] == body.fingerprint and row["current"] for row in workbench.history(body.context)["publications"]):
                raise ValueError("Publish current scoped readiness before migrating this workflow pin.")
            path = flow_path(body.run_id)
            with cross_process_lock(path, strict=True):
                pins = json.loads(atomic_read_text(path, encoding="utf-8"))
                from maverick.plugin_execution_pins import pin_key
                key = pin_key(selected["group"], selected.get("pin_name", selected["name"]), selected["distribution"])
                old = pins.get(key)
                if old and body.operation_id and old.get("migration_operations", {}).get(body.operation_id) == {"previous": body.previous, "current": selected["content_sha256"]} and old["owner"] == run.owner:
                    return {"migrated": True, "workflow_resumed": False, "historical_actions_replayed": False}
                if (not old or old["fingerprint"] != body.previous or old["owner"] != run.owner
                        or old.get("revision") != run.definition_revision):
                    raise ValueError("The reviewed workflow pin changed. Refresh before migration.")
                _authority(request, body.context)
                workbench.selected(body.fingerprint)
                old["prior_fingerprints"] = list(old.get("prior_fingerprints", [])) + [body.previous]
                old["fingerprint"] = selected["content_sha256"]
                if body.operation_id:
                    old.setdefault("migration_operations", {})[body.operation_id] = {"previous": body.previous, "current": selected["content_sha256"]}
                atomic_write_text(path, json.dumps(pins, sort_keys=True))
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(409, str(exc)) from exc
    return {"migrated": True, "workflow_resumed": False, "historical_actions_replayed": False}
