"""Read-only people list for assignee pickers.

Pages that assign work (AI entity tasks, governance roles) need a list of
people to choose from instead of a typed identifier. This lists the people
who can already act in the caller's workspace: global role holders, members
of the active workspace, and the caller. Nothing is written.

Task stores accept only compact opaque references, so each person is given a
stable ``ref``: the principal itself when it already fits that shape, else a
short one-way fingerprint of it. ``label`` is the display name.
"""

from __future__ import annotations

import hashlib
import re

from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from .auth import caller_principal, require_permission
from .identity_format import humanize_principal

_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")

router = APIRouter(prefix="/people", tags=["people-picker"])


def person_ref(principal: str) -> str:
    """The compact reference a task store accepts for ``principal``."""
    if _REF.match(principal):
        return principal
    return "person:" + hashlib.sha256(principal.encode("utf-8")).hexdigest()[:24]


def _active_workspace() -> str | None:
    from maverick.paths import current_tenant_id_strict

    return current_tenant_id_strict()


def _people(caller: str | None) -> list[dict[str, str]]:
    from . import rbac

    principals: set[str] = set(rbac.list_users())
    workspace = _active_workspace()
    if workspace:
        principals.update(rbac.list_tenant_roles(workspace))
    if caller:
        principals.add(caller)
    people = []
    for principal in principals:
        if not isinstance(principal, str) or not principal.strip():
            continue
        identity = humanize_principal(principal)
        label = identity.name + (f" ({identity.detail})" if identity.detail and identity.detail != "Email" else "")
        people.append({"ref": person_ref(principal), "label": label, "is_you": principal == caller})
    people.sort(key=lambda item: (not item["is_you"], item["label"].casefold(), item["ref"]))
    return people[:500]


@router.get("/assignable")
async def assignable_people(request: Request) -> dict[str, object]:
    """People who can be assigned work in this workspace, for pickers."""
    require_permission(request, "operate")
    try:
        items = await run_in_threadpool(_people, caller_principal(request))
    except Exception as exc:  # the role store is unreadable: say so, never guess
        raise HTTPException(status_code=503, detail="people list is unavailable") from exc
    return {"items": items, "count": len(items)}


__all__ = ["person_ref", "router"]
