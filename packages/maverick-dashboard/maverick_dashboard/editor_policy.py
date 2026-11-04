"""Shared authorization and installation policy for editing agent packs and roles."""
from __future__ import annotations

from fastapi import HTTPException, Request

from . import auth


def pack_editing_denial(request: Request, *, caller=None, is_admin=None, has_permission=None) -> str | None:
    """Explain why a caller cannot edit packs, or return None when allowed."""
    principal = (caller or auth.caller_principal)(request)
    if principal is not None and not (is_admin or auth.is_dashboard_admin)(principal):
        return "pack editing requires a dashboard admin"
    if principal is not None and not (has_permission or auth.has_permission)(request, "admin"):
        return "pack editing requires an API key with the administrator scope"
    from maverick.config import get_features

    if not get_features().get("pack_editing", True):
        return (
            "Editing agents and specialists is turned off by this installation's policy. "
            "Ask an installation administrator to turn it on."
        )
    return None


def require_pack_editing(request: Request, *, permission=None, denial=None) -> None:
    (permission or auth.require_permission)(request, "admin")
    reason = (denial or pack_editing_denial)(request)
    if reason is not None:
        raise HTTPException(status_code=403, detail=reason)


def require_role_editing(request: Request, *, caller=None, is_admin=None, permission=None) -> None:
    principal = (caller or auth.caller_principal)(request)
    if principal is not None and not (is_admin or auth.is_dashboard_admin)(principal):
        raise HTTPException(status_code=403, detail="role editing requires dashboard admin")
    (permission or auth.require_permission)(request, "admin")
    from maverick.config import get_features

    if not get_features().get("role_editing", True):
        raise HTTPException(
            status_code=403,
            detail=(
                "role editing is disabled ([features] role_editing = false). "
                "Edit roles.toml on the host, or re-enable it in config."
            ),
        )


def refuse_while_trial_live(name: str) -> None:
    """Keep the current definition stable until the trial is resolved."""
    from maverick import specialist_canary

    if specialist_canary.live(name) is not None:
        raise HTTPException(
            status_code=409,
            detail="A trial version of this specialist is live. Promote it or roll it back in Workforce first. Nothing was changed.",
        )
