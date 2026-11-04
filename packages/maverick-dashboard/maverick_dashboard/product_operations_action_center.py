"""Read-only handoff to the current native attention list and its review links."""
from __future__ import annotations

from fastapi import HTTPException
from maverick.governed_operations import digest

from . import action_center_api as native
from . import auth
from .draft_api import context_for
from .product_operations import Adapter, EmptyInput, Preview, Snapshot


def _current(request, selection):
    from .app import require_page_visible

    if selection:
        raise HTTPException(422, "Open Action Center to read the current decision list.")
    with auth.fresh_configuration():
        native.require_enabled(request)
        auth.require_page_permission(request, "/action-center")
        require_page_visible(request, "/action-center")
        context = context_for(request)
        model = native._model(request)
    with auth.fresh_configuration():
        native.require_enabled(request)
        auth.require_page_permission(request, "/action-center")
        require_page_visible(request, "/action-center")
        if context_for(request) != context:
            raise HTTPException(409, "Your account or workspace changed. Open the current Action Center again.")
    return context, model


def snapshot(request, selection):
    context, model = _current(request, selection)
    incomplete = any(row["status"] not in {"current", "disabled"} for row in model["coverage"])
    return Snapshot(digest([context, model["items"], model["coverage"]]), "Current Action Center",
        f"{len(model['items'])} current items need attention. "
        + ("Some sources could not be completely checked. " if incomplete else "")
        + "Open the complete private list to read each item and follow its existing review controls. Opening the list approves nothing.",
        details={"Items needing attention": len(model["items"]), "All sources checked": not incomplete})


def prepare(request, selection, _arguments):
    current = snapshot(request, selection)
    context, model = _current(request, selection)
    if digest([context, model["items"], model["coverage"]]) != current.revision:
        raise HTTPException(409, "The decision list changed. Read the current items before opening the controls.")
    return Preview(current.summary, native={"action_center_form": {"context": context}})


def entries():
    return (Adapter("reviews.action_center", "Open current decisions needing attention", "reviews",
        "/action-center#ac-items", ("/action-center",), EmptyInput, snapshot, prepare,
        aliases=("what needs my decision", "open current approvals", "read my action center",
                 "review pending evidence sources")),)
