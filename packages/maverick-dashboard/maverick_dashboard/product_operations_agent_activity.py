"""Protected Copilot handoff into the current native specialist work view."""
from fastapi import HTTPException

from . import agent_activity as native
from .product_operations import Adapter, EmptyInput, Preview, Snapshot


def _read(request, selection):
    name = selection.get("name")
    if not isinstance(name, str):
        raise HTTPException(409, "Choose a specialist on Agent Factory before reading recent work.")
    return native.read(request, name)


def _details(value):
    return {"Specialist": value["label"], "Scope": value["scope"], "Current task counts": value["counts"],
            "Tasks with unavailable recorded cost": value["cost_unknown"],
            "More recorded tasks": "This view stops at the newest 50 records." if value["more"] else "No older records were omitted by this limit.",
            "agent_activity_form": {key: value[key] for key in ("context", "name", "revision")}}


def snapshot(request, selection):
    value = _read(request, selection)
    return Snapshot(value["revision"], "Current authorized specialist task records", native.SCOPE, _details(value))


def prepare(request, selection, _arguments):
    value = _read(request, selection)
    return Preview("Open recent work to read named tasks, their current reasons and the task creation trend. No work is started or changed.", native=_details(value))


def entries():
    return (Adapter("agents.recent_work", "Read this specialist's recent work", "preferences", "/agents#agent-recent-work",
                    ("/agents",), EmptyInput, snapshot, prepare,
                    aliases=("show this specialist's recent tasks", "read this agent's recent work", "show this specialist's failures")),)
