"""Copilot hands people administration to its protected ordinary controls."""
from __future__ import annotations

from .invite_routes import workspace_people_context
from .product_operations import Adapter, EmptyInput, Preview, Snapshot


def snapshot(request, _selection):
    current = workspace_people_context(request)
    return Snapshot(current["context"], "Current workspace people controls",
        "Open Users to choose a workspace, invite a colleague, check original invitation results and manage current members. Copilot does not receive invitation links or send invitations.",
        details={"workspace_people": current})


def prepare(request, selection, _arguments):
    value = snapshot(request, selection)
    return Preview(value.summary, native=value.details)


def entries():
    return (Adapter("people.workspaces.manage", "Manage workspace invitations and members", "preferences",
        "/users#wi-title", ("/users", "/settings", "/workspace/tenant", "/tenants"),
        EmptyInput, snapshot, prepare, aliases=("invite someone", "workspace membership", "workspace people")),)
