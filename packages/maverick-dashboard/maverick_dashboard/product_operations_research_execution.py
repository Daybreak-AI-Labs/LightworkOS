"""Read-only handoff to the same ordinary, independently reviewed run controls."""
from __future__ import annotations

from fastapi import HTTPException, Response
from maverick.governed_operations import digest
from maverick.research_jobs import configured_profile

from . import auth
from .product_operations import Adapter, EmptyInput, Preview, Snapshot
from .research_workspace_api import _binding

PAGE = "/research"


def _current(request, selection):
    from .app import require_page_visible

    if selection:
        raise HTTPException(422, "Open Research to choose and review a run.")
    auth.require_page_permission(request, PAGE)
    require_page_visible(request, PAGE)
    _, _, context = _binding(request, Response())
    try:
        profile = configured_profile()
    except Exception as exc:
        raise HTTPException(503, "Complete Administrator setup in Research before opening execution controls.") from exc
    auth.require_page_permission(request, PAGE)
    require_page_visible(request, PAGE)
    if _binding(request, Response())[2] != context:
        raise HTTPException(409, "Your account, workspace or access changed. Open the current Research controls again.")
    return context, digest([context, profile.image_id, profile.limits.timeout_seconds])


def snapshot(request, selection):
    _, revision = _current(request, selection)
    return Snapshot(revision, "Run approved local research",
        "Choose a saved program and approved text snapshots in Research. A different administrator reads every file "
        "and approves the exact run; Start is separate. Actual container timing, result checks and cleanup are retained. "
        "Opening these controls starts nothing. Training, remote data and model execution require a separately supported executor.")


def prepare(request, selection, _arguments):
    current = snapshot(request, selection)
    context, revision = _current(request, selection)
    if current.revision != revision:
        raise HTTPException(409, "Research setup changed. Open the current controls again.")
    return Preview(current.summary, native={"research_execution_review": {
        "scope": "current_page", "context": context,
    }})


def entries():
    return (Adapter("artifacts.research_execution_controls", "Open complete research run controls", "artifacts",
        PAGE+"#research-run-form", (PAGE,), EmptyInput, snapshot, prepare,
        aliases=("run an experiment", "open research execution controls", "review and start a research run",
                 "open complete research run controls", "stop a research run", "read the original research run")),)
