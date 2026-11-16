"""Copilot controls for decisions a run is waiting for.

Reading and answering go through :mod:`decision_requests_api`, the same path
and authorization as the Approvals page.
"""
from __future__ import annotations

import time

from fastapi import BackgroundTasks, HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import decision_requests_api as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput

PAGES = ("/approvals",)


class AnswerInput(StrictInput):
    option: int = Field(ge=1, le=5)
    note: str = Field(default="", max_length=2000)


def _selected_id(selection: dict) -> int:
    value = selection.get("id")
    if set(selection) != {"kind", "id"} or selection.get("kind") != "decision" \
            or type(value) is not int or value < 1:
        raise HTTPException(409, "Choose a decision's Review with Copilot button in Approvals.")
    return value


def _details(decision) -> dict:
    options = [f"{i}. {o['label']}: {o['effect']}" for i, o in enumerate(decision.options, 1)]
    return {"Question": decision.question, "Area": decision.area_label, "Options": options,
            "Recommended": f"Option {decision.recommended}. {decision.reason}",
            "Decide by": time.strftime("%d %b %Y %H:%M UTC", time.gmtime(decision.expires_at))}


def snapshot(request, selection, *, answering=False):
    decision_id = _selected_id(selection)
    saved = native.answered_by_me(request, decision_id)
    if saved is not None:
        return Snapshot(digest(saved.public()), "The decision you already answered",
                        "Your choice is saved.", _details(saved), [],
                        "You already answered this decision.")
    decision = native.selected(request, decision_id)
    reason, sentence = native.dr.refusal(decision, native.actor(request),
                                         is_admin=native.is_admin(request))
    fields = []
    if answering:
        fields = [{"name": "option", "label": "Which option do you choose?", "kind": "select",
                   "required": True,
                   "choices": [{"value": i, "label": o["label"]} for i, o in enumerate(decision.options, 1)]},
                  {"name": "note", "label": "Note for the run (optional)", "kind": "textarea",
                   "max_length": 2000}]
    return Snapshot(digest(decision.public()), "The current decision a run is waiting for",
                    "Choose one option. The run continues with your choice.", _details(decision),
                    fields, sentence if answering and reason else "")


def read_prepare(request, selection, _arguments):
    state = snapshot(request, selection)
    return Preview("A run is waiting for this decision. Nothing changes until someone chooses.",
                   native=state.details)


def prepare(request, selection, arguments):
    state = snapshot(request, selection, answering=True)
    if state.blocked:
        raise HTTPException(403, state.blocked)
    decision = native.selected(request, _selected_id(selection))
    chosen = decision.option(arguments["option"])
    if chosen is None:
        raise HTTPException(422, "Choose one of the listed options.")
    changes = [{"label": "Question", "after": decision.question},
               {"label": "Your choice", "after": f"{chosen['label']}: {chosen['effect']}"}]
    if arguments["note"].strip():
        changes.append({"label": "Your note", "after": arguments["note"].strip()})
    return Preview("Send this choice. The run continues with it.", changes,
                   {"decision_id": decision.id, "revision": state.revision})


def execute(request, selection, arguments, prepared, _operation_id):
    decision_id = _selected_id(selection)
    if decision_id != prepared["decision_id"]:
        raise HTTPException(409, "The decision changed. Review it again.")
    world = native._world()
    outcome = native.answer_for_request(request, decision_id, arguments["option"], arguments["note"],
                                        channel="copilot", world=world)
    background = BackgroundTasks()
    if outcome["resume"]:
        native.resume(background, world, outcome["decision"].goal_id)
    return Outcome("confirmed", native.outcome_message(outcome),
                   {"decision": decision_id, "option": arguments["option"]}, background=background)


def recover(request, selection, arguments, _prepared, _operation_id):
    decision = native.answered_by_me(request, _selected_id(selection))
    if decision is None:
        return None
    return Outcome("replayed", "Your earlier choice is already saved.",
                   {"decision": decision.id, "option": decision.chosen})


def entries():
    return (Adapter("reviews.decision_read", "Read the selected decision", "reviews", "/approvals", PAGES,
                    EmptyInput, snapshot, read_prepare, aliases=("read this decision",)),
            Adapter("reviews.decision_answer", "Answer the selected decision", "reviews", "/approvals",
                    PAGES, AnswerInput, lambda r, s: snapshot(r, s, answering=True), prepare, execute,
                    recover, aliases=("answer this decision", "choose an option"), read_recovery=recover))
