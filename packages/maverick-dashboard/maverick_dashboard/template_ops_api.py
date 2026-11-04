"""Add task templates from the community library (``maverick template add``).

``GET /api/v1/templates/community`` lists what the configured libraries offer
(:func:`maverick.templates.browse_templates`). ``POST
/api/v1/templates/community/add`` installs one by name through
:func:`maverick.templates.install_template_from_catalog`, which fetches it,
checks its pinned fingerprint, removes spending settings, checks publisher
signatures when required and scans the text before saving. Installed templates
are shared by everyone on this installation and come from outside it, so adding
one needs an installation administrator, an explicit confirmation, the
same-origin guard and an audit row written first. Library fetches run off the
request thread.
"""
from __future__ import annotations

import logging
import re

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import (
    caller_principal,
    has_global_permission,
    require_global_permission,
    require_permission,
)

log = logging.getLogger(__name__)
router = APIRouter(tags=["templates"])
MAX_ENTRIES = 200
_NAME = r"^[a-z0-9][a-z0-9_-]{0,63}$"


class CommunityAddIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: str = Field(pattern=_NAME)
    confirm: bool = False


def _installed() -> set[str]:
    from maverick.templates import list_templates

    try:
        return set(list_templates())
    except Exception:
        return set()


@router.get("/api/v1/templates/community")
async def community_templates(request: Request) -> dict:
    """What the community libraries offer, and which are already here."""
    from maverick.templates import browse_templates

    require_permission(request, "operate")
    try:
        entries = await run_in_threadpool(browse_templates)
    except Exception:
        log.warning("template library unavailable", exc_info=True)
        return {"available": False, "templates": [], "can_add": False,
                "message": "The template library can't be reached right now. Try again later."}
    installed = _installed()
    rows = []
    for entry in list(entries or [])[:MAX_ENTRIES]:
        name = str(getattr(entry, "name", ""))
        if not re.fullmatch(_NAME, name):
            continue
        rows.append({"name": name, "summary": str(getattr(entry, "summary", "") or "")[:300],
                     "rating": float(getattr(entry, "rating", 0) or 0),
                     "ratings": int(getattr(entry, "ratings_count", 0) or 0),
                     "installed": name in installed})
    return {"available": True, "templates": rows, "can_add": has_global_permission(request, "admin")}


@router.post("/api/v1/templates/community/add")
async def add_community_template(request: Request, body: CommunityAddIn) -> dict:
    """Install one library template for everyone on this installation."""
    from maverick.audit import AuditRefused, audit_event
    from maverick.templates import install_template_from_catalog

    from .app import _require_same_origin

    require_global_permission(request, "admin")
    _require_same_origin(request)
    if body.confirm is not True:
        raise HTTPException(409, "Confirm that you want to add this template for everyone here.")
    try:
        audit_event("template_added_from_library", agent="dashboard", _global=True,
                    actor=caller_principal(request) or "local", template=body.name)
    except AuditRefused as exc:
        raise HTTPException(503, "The activity log couldn't record this, so nothing was added.") from exc
    try:
        template = await run_in_threadpool(install_template_from_catalog, body.name)
    except ValueError as exc:
        text = str(exc).lower()
        if "no template named" in text:
            message = "That template isn't in the library any more."
        elif "hash" in text or "signature" in text or "publisher" in text:
            message = "That template couldn't be confirmed as the library's genuine copy, so it wasn't added."
        else:
            message = "That template failed the safety check, so it wasn't added."
        return {"added": False, "message": message}
    except Exception:
        log.warning("template install failed", exc_info=True)
        return {"added": False, "message": "The template library can't be reached right now. Nothing was added."}
    return {"added": True, "name": template.name, "title": str(template.title or template.name)[:200]}
