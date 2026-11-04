"""Copilot shares the exact native pending-question review and decision."""
from __future__ import annotations

from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict

from . import learning_pending_cases_api as native
from .product_operations import Adapter, Outcome, Preview, Snapshot


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    action: Literal["accept", "reject"]


def _selection(selection):
    if selection.get("kind") != "learning_pending_case":
        raise HTTPException(409, "Choose a suggested question in Learned before reviewing its use or rejection.")
    return {"model": selection.get("model"), "reference": selection.get("reference")}


def snapshot(request, selection):
    state = native.current(request)
    try:
        chosen = _selection(selection)
        reviewed = native.corpus.review_pending_decision(native.cases._scope(request)["path"], chosen["model"], chosen["reference"], "reject")
        checked = native.current(request)
        if (checked["revision"] != state["revision"] or chosen["model"] not in {row["value"] for row in state["models"]}
                or not native.corpus.case_current(reviewed["source_guard"])):
            raise HTTPException(409, "The suggestion changed. Choose it again.")
    except (HTTPException, ValueError, PermissionError, OSError):
        return Snapshot(state["revision"], "Current self-coaching suggestions", native.cases.SCOPE,
            blocked=state["blocked"] or "Choose a suggested question in Learned before reviewing its use or rejection.",
            details={"Open suggestions": {"href": native.PAGE, "label": "Review suggested questions"}})
    return Snapshot(state["revision"], "The exact selected suggested self-coaching question", native.cases.SCOPE,
        blocked=state["blocked"], details={"Question": reviewed["before"]["question"], "Expected answer": reviewed["before"]["expected"]},
        fields=[{"name": "action", "label": "What should happen to this suggestion?", "kind": "select", "required": True,
                 "choices": [{"value": "accept", "label": "Use in future checks"}, {"value": "reject", "label": "Reject this suggestion"}]}])


def prepare(request, selection, arguments):
    prepared = native.prepare(request, {**_selection(selection), **arguments})
    return Preview("Use or reject only this exact suggested question. No AI runs or spending occur.",
                   changes=native.changes(prepared), native=prepared)


def _check(selection, arguments, prepared):
    if native.DecisionIn.model_validate({**_selection(selection), **arguments}).model_dump() != prepared.get("decision"):
        raise HTTPException(409, "The selected question or decision changed. Review it again.")


def _outcome(row, replay=False):
    details = {"Current observation": row.get("current", "No original decision record is available."), "Scope": native.cases.SCOPE,
               "Open original decision": {"href": "/learned?learning_pending_request=" + row["operation"] + "#learning-suggested-questions", "label": "Open original decision"}}
    if row.get("question"):
        details.update({"Model": row["model"], "Question": row["question"], "Expected answer": row["expected"]})
    return Outcome(("replayed" if replay else "confirmed") if row["confirmed"] else "unconfirmed", row["message"], details)


def execute(request, selection, arguments, prepared, operation):
    _check(selection, arguments, prepared)
    return _outcome(native.apply(request, prepared, operation))


def recover(request, selection, arguments, prepared, operation, *, read_only=False):
    _check(selection, arguments, prepared)
    if not read_only and native._owned(request, operation) is None:
        return None
    return _outcome(native.original(request, operation, prepared), True)


def entries():
    return (Adapter("learning.decide_suggested_question", "Use or reject the selected suggested question", "learning", native.PAGE,
        ("/learning", "/learned"), Decision, snapshot, prepare, execute, recover,
        read_recovery=lambda r, s, a, p, o: recover(r, s, a, p, o, read_only=True)),)
