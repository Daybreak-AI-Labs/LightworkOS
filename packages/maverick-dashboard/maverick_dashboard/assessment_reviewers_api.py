"""People an assessment can be assigned to, for the worklist's Assign picker.

The worklist marks a row "mine" when its assignee equals the signed-in
person's principal, so the picker must offer principals (not the opaque
references the task stores use). Lists the same people as the shared people
picker: global role holders, members of the active workspace, and the caller.
Read-only; same permission as assigning (``operate``).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from .auth import caller_principal, require_permission
from .identity_format import humanize_principal

router = APIRouter(prefix="/assess", tags=["assessments"])


def _active_workspace() -> str | None:
    from maverick.paths import current_tenant_id_strict

    return current_tenant_id_strict()


def _reviewers(caller: str | None) -> list[dict[str, object]]:
    from . import rbac

    principals: set[str] = set(rbac.list_users())
    workspace = _active_workspace()
    if workspace:
        principals.update(rbac.list_tenant_roles(workspace))
    if caller:
        principals.add(caller)
    out = []
    for principal in principals:
        if not isinstance(principal, str) or not principal.strip():
            continue
        who = humanize_principal(principal)
        label = who.name + (f" ({who.detail})" if who.detail and who.detail != "Email" else "")
        out.append({"principal": principal, "label": label, "is_you": principal == caller})
    out.sort(key=lambda row: (not row["is_you"], str(row["label"]).casefold(), row["principal"]))
    return out[:500]


@router.get("/reviewers")
async def assessment_reviewers(request: Request) -> dict[str, object]:
    """People who can be put down as an assessment's reviewer."""
    require_permission(request, "operate")
    try:
        items = await run_in_threadpool(_reviewers, caller_principal(request))
    except Exception as exc:  # the role store is unreadable: say so, never guess
        raise HTTPException(status_code=503, detail="people list is unavailable") from exc
    return {"items": items, "count": len(items)}


__all__ = ["router"]
