"""Workspaces page: set up a client in one step, and re-protect workspace keys.

* ``maverick tenant onboard``: create a workspace and make its first
  administrator's invitation link in one step. The workspace is created through
  the same route (and activity-record row) as "Create a workspace"; the link is
  made by the same invitation code as the People page and shown once.
* ``maverick tenant kms-rotate``: move every workspace's key from the current
  master key to a new one (``maverick.tenant.kms_fleet.rotate_local_fleet``).
  The administrator selects the two key files; a preview shows what would
  change, and the real run happens in the background with a status the page
  polls. Key material is used only in memory for that request or job: it is
  never stored, logged, recorded or returned.

Installation-wide: every route needs the global ``admin`` permission, changes
are same-origin checked and need an explicit confirmation.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import ops_admin_jobs as ops_jobs
from .auth import caller_principal, require_global_permission

router = APIRouter(prefix="/api/v1/admin/workspace-ops")
asset_router = APIRouter()
_STATIC = Path(__file__).parent / "static"
_KEY_CHARS = 512


@asset_router.get("/static/lightwork-tenant-ops.js", include_in_schema=False)
async def tenant_ops_script() -> FileResponse:
    return FileResponse(_STATIC / "lightwork-tenant-ops.js", media_type="application/javascript; charset=utf-8",
                        headers={"Cache-Control": "public, max-age=300"})


def _mutation(request: Request) -> None:
    from . import app as app_module
    app_module._require_same_origin(request)
    require_global_permission(request, "admin")


def _record(request: Request, verb: str, **detail: Any) -> None:
    from .system_checks_api import _record as record
    record(request, verb, **detail)


# ---- set up a client in one step (maverick tenant onboard) ---------------------

class OnboardIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display_name: str = Field(min_length=1, max_length=200)
    plan: str = Field("free", pattern="^(free|pro|enterprise)$")
    max_daily_dollars: float = Field(0.0, ge=0.0, le=1_000_000.0)
    admin_email: str = Field(min_length=3, max_length=254)
    role: str = Field("admin", min_length=2, max_length=64)


@router.get("/roles")
async def invitation_roles(request: Request) -> dict:
    require_global_permission(request, "admin")
    from . import invites, rbac
    return {"roles": [{"value": role, "label": role.replace("_", " ").replace("-", " ").capitalize()}
                      for role in rbac.known_roles()],
            "invitations_on": bool(invites.invites_enabled())}


@router.post("/onboard", status_code=201)
async def onboard(body: OnboardIn, request: Request) -> dict:
    _mutation(request)
    from . import api, invites, rbac
    from .api_schemas import TenantCreateIn
    if not rbac.is_known_role(body.role):
        raise HTTPException(422, "Choose a role from the list.")
    email = body.admin_email.strip().lower()
    if "@" not in email or any(c.isspace() for c in email):
        raise HTTPException(422, "Enter the administrator's email address.")
    if not invites.invites_enabled():
        raise HTTPException(409, "Invitations are turned off, so the first administrator can't be invited. "
                                 "Turn on invitations in Settings, then try again. No workspace was created.")
    created = await api.create_tenant(request, TenantCreateIn(
        display_name=body.display_name.strip(), plan=body.plan, max_daily_dollars=body.max_daily_dollars))
    invited_by = caller_principal(request) or "local-admin"
    try:
        invite, token = await run_in_threadpool(lambda: invites.create_invite(
            email, body.role, created_by=invited_by, tenant=created.id))
    except invites.ExistingAccountError as exc:
        raise HTTPException(409, f"The workspace {created.display_name or created.id} was created, but "
                                 f"{email} already has a sign-in here, so no invitation was made. Add them "
                                 "to the workspace on the People page instead.") from exc
    except ValueError as exc:
        raise HTTPException(409, f"The workspace {created.display_name or created.id} was created, but the "
                                 "invitation could not be made. Invite the administrator from the People "
                                 "page.") from exc
    link = str(request.base_url).rstrip("/") + f"/auth/invite/{token}"
    sent, _note = await run_in_threadpool(lambda: invites.send_invite_email(invite, link, invited_by=invited_by))
    await run_in_threadpool(_record, request, "workspace_onboarded", workspace=created.id, role=invite.role,
                            invitation_emailed=bool(sent))
    return {"workspace": {"id": created.id, "name": created.display_name or created.id, "plan": created.plan},
            "invite_email": invite.email, "invite_link": link, "emailed": bool(sent),
            "summary": f"Created {created.display_name or created.id} and invited {invite.email} as its "
                       f"{invite.role}. " + ("The invitation was emailed. " if sent else "")
                       + "Copy the invitation link now: it is shown only once."}


# ---- re-protect workspace keys (maverick tenant kms-rotate) --------------------

class KeysIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    current_key: str = Field(min_length=16, max_length=_KEY_CHARS)
    new_key: str = Field(min_length=16, max_length=_KEY_CHARS)
    confirm: bool = Field(default=False, strict=True)


def _names() -> dict[str, str]:
    from maverick.tenant.registry import list_tenants
    return {t.id: (t.display_name or t.id) for t in list_tenants()}


def _plain(report: dict[str, Any], *, preview: bool) -> dict[str, Any]:
    names = _names()
    rotated, skipped, failed = report["rotated"], report["skipped"], report["failed"]
    if preview:
        summary = (f"{len(rotated)} workspace{'s' if len(rotated) != 1 else ''} would be re-protected with the "
                   f"new key; {len(skipped)} already use it.")
    else:
        summary = (f"Re-protected {len(rotated)} workspace{'s' if len(rotated) != 1 else ''} with the new key; "
                   f"{len(skipped)} already used it.")
    if failed:
        summary += (f" {len(failed)} can't be unlocked with the current key. Keep using the current key "
                    "until they are fixed.")
    elif not preview:
        summary += " Your IT team can now switch the server to the new key."
    if not report["total"]:
        summary = "No workspace has its own key yet, so there is nothing to re-protect."
    return {
        "summary": summary, "total": report["total"],
        "rows": ([{"workspace": names.get(t, t), "result": "Would be re-protected" if preview else "Re-protected"}
                  for t in rotated]
                 + [{"workspace": names.get(t, t), "result": "Already uses the new key"} for t in skipped]
                 + [{"workspace": names.get(t, t), "result": "Can't be unlocked with the current key"}
                    for t in sorted(failed)]),
        "failed": len(failed),
        "technical": [{"level": "fail", "text": f"{names.get(t, t)}: {str(reason)[:200]}"}
                      for t, reason in sorted(failed.items())][:80],
    }


def _bad_keys(exc: BaseException) -> HTTPException:
    return HTTPException(422, "One of the key files isn't a valid Lightwork key. Check that you chose the "
                              "right files. Nothing was changed.")


def _record_key_result(actor: str, job: dict[str, Any]) -> None:
    """Record the observed result, without claiming a failed job changed no keys."""
    from maverick.audit import EventKind, audit_event

    result = job.get("result") if job["state"] == "done" else None
    failed = result.get("failed") if isinstance(result, dict) else None
    audit_event(
        EventKind.CONTROL_PLANE_ACTION, agent="dashboard", _global=True,
        verb="workspace_keys_reprotect_finished", principal="*", actor=actor,
        ok=job["state"] == "done" and failed == 0,
        job_id=job["id"], state=job["state"],
        reprotected=(sum(row.get("result") == "Re-protected" for row in result.get("rows", []))
                     if isinstance(result, dict) else None),
        failed=failed,
    )


@router.post("/keys/preview")
async def keys_preview(body: KeysIn, request: Request) -> dict:
    _mutation(request)
    from maverick.tenant.kms_fleet import rotate_local_fleet
    current, new = body.current_key.strip(), body.new_key.strip()
    if current == new:
        raise HTTPException(422, "Choose two different key files: the current key and the new one.")
    try:
        report = await run_in_threadpool(lambda: rotate_local_fleet(current, new, dry_run=True))
    except Exception as exc:  # noqa: BLE001 -- never echo key material
        raise _bad_keys(exc) from None
    return await run_in_threadpool(lambda: _plain(report, preview=True))


@router.post("/keys/rotate")
async def keys_rotate(body: KeysIn, request: Request) -> dict:
    _mutation(request)
    from .step_up import require_recent_mfa

    require_recent_mfa(request, "rotate_keys")
    if body.confirm is not True:
        raise HTTPException(409, "Confirm to re-protect the workspaces. Nothing was changed.")
    from maverick.tenant.kms_fleet import rotate_local_fleet
    current, new = body.current_key.strip(), body.new_key.strip()
    if current == new:
        raise HTTPException(422, "Choose two different key files: the current key and the new one.")
    actor = caller_principal(request) or "local administrator"
    try:
        await run_in_threadpool(_record, request, "workspace_keys_reprotect_requested")
    except HTTPException as exc:
        if exc.status_code == 503:
            raise HTTPException(503, "Nothing was changed because the activity record is unavailable. "
                                "Ask your administrator to check it before trying again.") from exc
        raise

    def work() -> dict[str, Any]:
        return _plain(rotate_local_fleet(current, new, dry_run=False), preview=False)

    def failure(exc: BaseException) -> str:
        return "The workspaces could not be re-protected. Check that you chose the right key files; " \
               "workspaces that were already done keep the new key."
    try:
        job = ops_jobs.start("workspace-keys", work, failure=failure,
                             on_finish=lambda finished: _record_key_result(actor, finished))
    except ops_jobs.JobBusy as exc:
        raise HTTPException(409, "Workspaces are already being re-protected. Wait for that to finish.") from exc
    return {"job": ops_jobs.public(job)}


@router.get("/jobs/{job_id}")
async def job_status(job_id: str, request: Request) -> dict:
    require_global_permission(request, "admin")
    job = ops_jobs.get(job_id[:32])
    if job is None or job["kind"] != "workspace-keys":
        raise HTTPException(404, "That task is no longer listed. Start it again if needed.")
    return {"job": ops_jobs.public(job)}
