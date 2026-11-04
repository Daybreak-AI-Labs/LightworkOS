"""Source-authorized Learned lesson review and exact withdrawal for Copilot."""
from __future__ import annotations

import re

from fastapi import HTTPException
from maverick import self_harness
from maverick.governed_operations import digest
from pydantic import Field

from . import auth
from . import learning_loop_api as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput

_TOKEN = re.compile(r"[0-9a-f]{64}\Z")


class WithdrawInput(StrictInput):
    lesson: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: str = Field(min_length=10, max_length=1000)


def _model(selection):
    if (not isinstance(selection, dict) or set(selection) != {"kind", "id"}
            or selection["kind"] != "learning_model"
            or not isinstance(selection["id"], str)):
        raise HTTPException(404, "Choose a model on the Learned page first.")
    try:
        return native._model_choice(selection["id"])
    except HTTPException as exc:
        if exc.status_code == 422:
            raise HTTPException(409, "This model is no longer in the current Learned list. Choose a model again.") from exc
        raise


def _rows(request, selection, *, manage=False):
    if manage:
        auth.require_global_permission(request, "admin")
    else:
        auth.require_permission(request, "view")
    model = _model(selection)
    rows = self_harness.line_efficacy(model)
    return model, rows


def _details(model, rows):
    from .plain_labels import model_label
    return {"model": model_label(model), "lessons": [
        {"text": row["text"], "where_used": native._scope_label(row["scope"]),
         "went_well": row["success"], "did_not": row["failure"],
         "rate": row["rate"], "recent_rate": row["recent_rate"],
         "selection": row["token"]}
        for row in rows[:200]], "truncated": len(rows) > 200, "href": "/learned"}


def review_snapshot(request, selection):
    model, rows = _rows(request, selection)
    details = _details(model, rows)
    revision = digest([model, [(row["token"], row["success"], row["failure"],
                               row["recent_rate"]) for row in rows]])
    return Snapshot(revision, "Current shared lessons for the selected model",
                    "See what each lesson says, where it applies, and how often work went well or poorly. Counts are observations, not proof the lesson caused a result.",
                    details=details)


def review_prepare(request, selection, _arguments):
    return Preview("These are the current shared lessons. No change was made.",
                   native=review_snapshot(request, selection).details)


def withdraw_snapshot(request, selection):
    model, rows = _rows(request, selection, manage=True)
    details = _details(model, rows)
    choices = [{"value": row["token"],
                "label": row["text"] + " · " + native._scope_label(row["scope"])}
               for row in rows[:200]]
    return Snapshot(digest([model, [row["token"] for row in rows]]),
                    "Current shared lessons for the selected model",
                    "Choose one exact lesson and explain why it should stop being used on new work.",
                    details=details,
                    fields=[{"name": "lesson", "label": "Lesson", "kind": "select",
                             "required": True, "choices": choices},
                            {"name": "reason", "label": "Why remove it?", "kind": "textarea",
                             "required": True, "value": ""}],
                    blocked="No shared lessons are available to remove." if not choices else "")


def withdraw_prepare(request, selection, arguments):
    model, rows = _rows(request, selection, manage=True)
    if len(arguments["reason"].strip()) < 10:
        raise HTTPException(422, "Explain why this lesson should be removed in at least 10 characters.")
    token = arguments["lesson"]
    if _TOKEN.fullmatch(token) is None:
        raise HTTPException(422, "Choose a lesson from the current list.")
    row = next((item for item in rows if item["token"] == token), None)
    if row is None:
        raise HTTPException(409, "That lesson changed. Refresh the Learned page and review it again.")
    return Preview("Remove this exact lesson from future work. Past work remains recorded.",
                   changes=[{"label": "Lesson", "before": row["text"], "after": "Removed"},
                            {"label": "Where used", "before": native._scope_label(row["scope"]),
                             "after": "No longer used"},
                            {"label": "Reason", "before": "", "after": arguments["reason"]}],
                   native={"model": model, "token": token})


def withdraw_execute(request, selection, arguments, prepared, operation):
    del operation
    if prepared != {"model": _model(selection), "token": arguments["lesson"]}:
        raise HTTPException(409, "The selected lesson changed. Prepare a new review.")
    result = native.withdraw_current_lesson(
        request, prepared["model"], prepared["token"], arguments["reason"].strip())
    return Outcome("confirmed", "The lesson was removed. New work will no longer use it.", result)


def entries():
    common = {"family": "learning", "direct_ui": "/learned", "pages": ("/learned",)}
    return (
        Adapter("learning.lesson_results", "Review learned lessons", input_model=EmptyInput,
                snapshot=review_snapshot, prepare=review_prepare,
                aliases=("show lessons", "lesson results", "self learning lessons"), **common),
        Adapter("learning.withdraw_lesson", "Remove a learned lesson", input_model=WithdrawInput,
                snapshot=withdraw_snapshot, prepare=withdraw_prepare, execute=withdraw_execute,
                aliases=("remove lesson", "withdraw learned lesson", "forget lesson"), **common),
    )
