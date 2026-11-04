"""Protected Microsoft mail setup through the existing native Connections form."""
from __future__ import annotations

from fastapi import HTTPException, Response
from maverick.governed_operations import digest

from . import auth, connection_setup_api
from .product_operations import Adapter, EmptyInput, Preview, Snapshot

PAGE = "/connections"


def _current(request, selection):
    from .app import require_page_visible

    if selection:
        raise HTTPException(422, "Open Connections to review your Microsoft 365 mail account.")
    auth.require_page_permission(request, PAGE)
    require_page_visible(request, PAGE)
    value = connection_setup_api.overview(request, Response())
    auth.require_page_permission(request, PAGE)
    require_page_visible(request, PAGE)
    return value


def snapshot(request, selection):
    value = _current(request, selection)
    available = any(profile.get("id") == "microsoft-mail" for profile in value.get("profiles", []))
    return Snapshot(digest(value), "Current Microsoft 365 account setup",
        "Open the protected account form to review your saved application and sign in with Microsoft. "
        "Choose that saved account separately in Channels. Opening the form saves nothing and contacts no email service.",
        blocked="Set up named sign-in and ask an administrator to allow Microsoft mail account setup." if not available else "")


def prepare(request, selection, _arguments):
    current = snapshot(request, selection)
    if current.blocked:
        raise HTTPException(403, current.blocked)
    value = _current(request, selection)
    if digest(value) != current.revision:
        raise HTTPException(409, "Your account setup or access changed. Open the current Connections controls again.")
    return Preview(current.summary, native={"mail_connection_review": {
        "scope": "current_page", "workspace_context": value["workspace_context"],
    }})


def entries():
    return (Adapter("connections.microsoft_mail_setup", "Set up Microsoft 365 email", "connections",
        PAGE + "#connection-setup", (PAGE,), EmptyInput, snapshot, prepare,
        aliases=("connect Outlook email", "Microsoft mail sign-in", "set up Outlook", "connect Microsoft 365 mail")),)
