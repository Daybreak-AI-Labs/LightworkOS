"""Copilot shows the "Sensitive data at the exit" record through the summary
behind the Safety monitoring page: the page's own audit permission and the task
titles the signed-in person may see. It reads the record and changes nothing."""
from __future__ import annotations

from maverick import ifc
from maverick.governed_operations import digest

from . import immune_console as native
from .identity_format import humanize
from .product_operations import Adapter, EmptyInput, Preview, Snapshot

_PAGES = (native.IMMUNE_PATH,)
# Kept in step with IFC_MODE and OUTCOME in static/lightwork-immune-console.js.
_MODE = {
    "off": "Protection: not checking sensitive data.",
    "audit": "Protection: recording when sensitive data leaves, without blocking it.",
    "approve": "Protection: a person must approve before sensitive data leaves.",
    "block": "Protection: sensitive data is blocked from leaving.",
}
_OUTCOME = {"blocked": "Blocked", "allowed": "Allowed", "approved": "Approved by a person",
            "denied": "Refused", "recorded": "Recorded", "held": "Held for approval"}
_UNAVAILABLE = "the record of where sensitive data went is unavailable"


def _label(label: object) -> str:
    if label == ifc.UNREADABLE_LABELS:
        return "Earlier labels unavailable"
    return humanize(str(label).removeprefix("data:"))


def _state(request) -> dict:
    native.require_permission(request, "audit")
    data = native._immune_summary(native.caller_principal(request))
    flow = data.get("ifc") or {}
    if flow.get("available") is not True:
        raise ValueError(_UNAVAILABLE)
    titles = data.get("goal_titles") or {}
    recent = []
    unreadable = 0
    for row in (flow.get("recent") or [])[:20]:
        labels = row.get("labels") or []
        unreadable += ifc.UNREADABLE_LABELS in labels
        task = row.get("goal_id")
        recent.append({
            "task": titles.get(str(task)) or ("—" if task is None else f"Task {task}"),
            "tool": humanize(row.get("tool")),
            "labels": [_label(label) for label in labels],
            "outcome": _OUTCOME.get(row.get("outcome"), humanize(row.get("outcome"))),
        })
    mode = flow.get("mode")
    return {
        "protection": _MODE.get(mode, f"Protection: {humanize(mode or 'unknown')}."),
        "times_recorded": int(flow.get("events") or 0),
        "by_result": {_OUTCOME.get(key, humanize(key)): count
                      for key, count in sorted((flow.get("by_outcome") or {}).items())},
        "earlier_labels_unreadable": unreadable,
        "earlier_labels_help": (flow.get("label_descriptions") or {}).get(ifc.UNREADABLE_LABELS, ""),
        "recent": recent,
    }


def _summary(state: dict) -> str:
    count = state["times_recorded"]
    if not count:
        return f"{state['protection']} No sensitive data has reached a tool that sends it outside."
    parts = [state["protection"],
             f"Labelled data reached a tool that sends it outside {count:,} time{'' if count == 1 else 's'}."]
    if state["earlier_labels_unreadable"] and state["earlier_labels_help"]:
        parts.append(state["earlier_labels_help"])
    return " ".join(parts)


def snapshot(request, _selection):
    state = _state(request)
    return Snapshot(digest(state), "Sensitive data at the exit", _summary(state), details=state)


def prepare(request, selection, _arguments):
    state = snapshot(request, selection)
    return Preview(state.summary, native=state.details)


def entries():
    return (Adapter("immune.sensitive_data_exit.show", "Show where sensitive data went", "reviews",
                    native.IMMUNE_PATH, _PAGES, EmptyInput, snapshot, prepare,
                    aliases=("sensitive data at the exit", "where did sensitive data go",
                             "earlier labels unavailable", "information flow labels")),)
