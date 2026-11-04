"""Start, stop and restart Lightwork's services from Settings > Maintenance.

The background worker (``maverick worker``), the chat channel server
(``maverick serve``), the tool server for outside apps (``maverick mcp``) and,
while their setting is on, performance profiling, the kernel activity monitor
and the model proxy run as supervised child processes of this dashboard (see
:mod:`maverick_dashboard.service_supervisor`). Starting processes on the
server is an installation-wide action: every route needs the global ``admin``
permission, so a workspace administrator is refused. Changes are same-origin
checked, stopping needs an explicit confirmation, and each change adds one
activity-record row naming who made it (before the process is touched).
"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import service_supervisor
from .auth import require_global_permission

router = APIRouter(prefix="/api/v1/admin/services")


class ServiceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    service: Literal["worker", "channels", "tools", "profiling", "ebpf_monitor", "model_proxy"]
    confirm: bool = Field(default=False, strict=True)


def _mutation(request: Request) -> None:
    from . import app as app_module
    app_module._require_same_origin(request)
    require_global_permission(request, "admin")


def _record(request: Request, verb: str, **detail) -> None:
    from .system_checks_api import _record as record
    record(request, verb, **detail)


@router.get("")
async def services(request: Request) -> dict:
    require_global_permission(request, "admin")
    from . import dashboard_restart
    return {"services": await run_in_threadpool(service_supervisor.status),
            "dashboard": dashboard_restart.status(request.app)}


class RestartIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirm: bool = Field(default=False, strict=True)


@router.post("/dashboard/restart")
async def restart_dashboard(body: RestartIn, request: Request) -> dict:
    """Restart this dashboard, only where a supervisor will start it again."""
    _mutation(request)
    from . import dashboard_restart
    state = dashboard_restart.status(request.app)
    if not state["can_restart"]:
        raise HTTPException(409, state["note"])
    if body.confirm is not True:
        raise HTTPException(409, "Confirm to restart this app. Nothing was changed.")
    await run_in_threadpool(_record, request, "dashboard_restart", supervisor=state["supervisor"])
    dashboard_restart.request(request.app)
    return {"restarting": True,
            "summary": "Restarting. This page reconnects when the app is back, usually within a minute."}


async def _act(request: Request, body: ServiceIn, verb: str, action) -> dict:
    _mutation(request)
    await run_in_threadpool(_record, request, verb, service=body.service)
    try:
        row = await run_in_threadpool(action, body.service)
    except service_supervisor.ServiceError as exc:
        raise HTTPException(409, str(exc)) from exc
    return {"service": row}


@router.post("/start")
async def start_service(body: ServiceIn, request: Request) -> dict:
    return await _act(request, body, "service_start", service_supervisor.start)


@router.post("/stop")
async def stop_service(body: ServiceIn, request: Request) -> dict:
    if body.confirm is not True:
        _mutation(request)
        raise HTTPException(409, "Confirm to stop the service. Nothing was changed.")
    return await _act(request, body, "service_stop", service_supervisor.stop)


@router.post("/restart")
async def restart_service(body: ServiceIn, request: Request) -> dict:
    if body.confirm is not True:
        _mutation(request)
        raise HTTPException(409, "Confirm to restart the service. Nothing was changed.")
    return await _act(request, body, "service_restart", service_supervisor.restart)
