"""Native saved-learning coverage and the ordinary restoration-form handoff."""
from __future__ import annotations

from fastapi import HTTPException
from maverick import dreaming
from maverick.governed_operations import digest
from pydantic import Field

from . import auth
from .learning_actions_api import current_cycle_activity, current_snapshot_coverage, snapshot_label
from .product_operations import Adapter, EmptyInput, Preview, Snapshot, StrictInput


class SavedPointInput(StrictInput):
    point: str = Field(pattern=r"^[A-Za-z0-9._-]{1,80}$")


def _points(request):
    auth.require_global_permission(request, "admin")
    names = dreaming.list_snapshots()
    return names, dreaming.settings()


def points_snapshot(request, _selection):
    names, settings = _points(request)
    offered = [{"value": name, "label": snapshot_label(name)} for name in reversed(names[-100:])]
    return Snapshot(digest([names, settings]), "Current saved learning points",
                    "Review the actual coverage of one saved learning point before deciding whether to restore it.",
                    details={"saved_points": [{"date": row["label"]} for row in offered[:35]],
                             "more_points": len(names) > 35,
                             "native_controls": {"href": "/learning#learning-review", "label": "Open learning review and restoration"}},
                    fields=[{"name": "point", "label": "Saved learning point", "kind": "select",
                             "required": True, "choices": offered}],
                    blocked="No saved learning point is available yet." if not offered else "")


def list_snapshot(request, selection):
    state = points_snapshot(request, selection)
    return Snapshot(state.revision, state.source, state.summary, details=state.details)


def list_prepare(request, selection, _arguments):
    return Preview("Current saved learning points. Open a selected point to check exactly which information it covers.",
                   native=list_snapshot(request, selection).details)


def point_prepare(request, selection, arguments):
    state = points_snapshot(request, selection)
    if arguments["point"] not in {choice["value"] for choice in state.fields[0]["choices"]}:
        raise HTTPException(409, "This saved point is no longer offered. Refresh the current saved points.")
    coverage = current_snapshot_coverage(request, arguments["point"])
    return Preview("Review this saved point in the ordinary Learning controls. Restoration requires a separate confirmation there.",
                   native={"saved_on": snapshot_label(arguments["point"]),
                           "information_covered": coverage["labels"], "saved_copy_check": coverage["notice"],
                           "current_source_check": coverage["source_notice"], "information_preserved": coverage["preserved"],
                           "learning_saved_point": {"name": arguments["point"], "revision": coverage["revision"]}})


def cycles_snapshot(request, _selection):
    current = current_cycle_activity(request)
    return Snapshot(digest(current), "Today's recorded learning",
                    "Read recorded cycle outcomes and check a saved point without repeating learning.",
                    details=current)


def cycles_prepare(request, selection, _arguments):
    return Preview("Read the current activity evidence. An unconfirmed completion is not proof that learning changed nothing.",
                   native=cycles_snapshot(request, selection).details)


def entries():
    common = {"family": "learning", "direct_ui": "/learning#learning-review", "pages": ("/learning",)}
    return (
        Adapter("learning.saved_points", "Review saved learning points", input_model=EmptyInput,
                snapshot=list_snapshot, prepare=list_prepare, aliases=("show learning safety copies",), **common),
        Adapter("learning.saved_point_coverage", "Open a saved learning point", input_model=SavedPointInput,
                snapshot=points_snapshot, prepare=point_prepare, aliases=("review learning restoration",), **common),
        Adapter("learning.recent_cycles", "Check recent learning", input_model=EmptyInput,
                snapshot=cycles_snapshot, prepare=cycles_prepare, aliases=("check learning completion",), **common),
    )
