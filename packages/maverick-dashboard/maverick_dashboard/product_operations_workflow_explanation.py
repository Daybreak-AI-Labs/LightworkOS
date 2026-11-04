"""Read-only Copilot access to the native saved-workflow explanation."""
from __future__ import annotations

from fastapi import HTTPException

from . import workflow_explanation as native
from .product_operations import Adapter, EmptyInput, Preview, Snapshot


def _target(selection):
    if not isinstance(selection, dict):
        raise HTTPException(404, "Open a saved workflow or run first.")
    if selection.get("kind") == "flow":
        if set(selection) - {"kind", "id", "node_id"} or not isinstance(selection.get("id"), str):
            raise HTTPException(404, "Open a saved workflow first.")
        return selection["id"], None
    if selection.get("kind") == "flow_run":
        if set(selection) != {"kind", "id", "flow_id"} or any(
                not isinstance(selection.get(key), str) for key in ("id", "flow_id")):
            raise HTTPException(404, "Open a workflow run first.")
        return selection["flow_id"], selection["id"]
    raise HTTPException(404, "Open a saved workflow or run first.")


def snapshot(request, selection):
    flow_id, run_id = _target(selection)
    revision, report = native.explain(request, flow_id, run_id)
    return Snapshot(revision, "Current authorized learning records, saved workflow and recorded run",
                    "See which examples support this saved version, current learning permission, publication, action approvals and any recorded run result. This does not authorize execution.",
                    details=report, blocked="This saved workflow was not learned from reviewed examples." if not report["is_learned"] else "")


def prepare(request, selection, _arguments):
    current = snapshot(request, selection)
    if current.blocked:
        raise HTTPException(409, current.blocked)
    return Preview(current.summary, native=current.details)


def entries():
    return (Adapter("learning.workflow_explanation", "Explain this learned workflow", "learning",
                    "/workflows", ("/flows/designer/*", "/workflow-builder", "/flows/*/runs/*"), EmptyInput,
                    snapshot, prepare,
                    aliases=("why can this workflow run", "explain this learned workflow", "show learning evidence", "why did this workflow run")),)
