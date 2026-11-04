"""Copilot reviews and controls the same learned-skill admission as Skills."""
from __future__ import annotations

import time

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import auth
from . import learned_skill_changes as changes
from . import tools_ops_api as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class AdmitInput(StrictInput):
    candidate: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", max_length=96)
    name: str = Field(default="", max_length=96)


class WithdrawInput(StrictInput):
    name: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", max_length=96)


def _state(request):
    auth.require_permission(request, "admin")
    context = changes.authority(request)
    value = native._learned_candidates()
    changes.authority(request, context)
    return {**value, "context": context}


def snapshot(request, selection, kind="review"):
    value = _state(request)
    suggestions = value["suggestions"]
    added = value["added"]
    fields = []
    blocked = ""
    if kind == "admit":
        choices = [{"value": row["name"], "label": row["name"].replace("-", " ")}
                   for row in suggestions if row["ok"]]
        fields = [
            {"name": "candidate", "label": "Suggestion", "kind": "select",
             "required": True, "choices": choices},
            {"name": "name", "label": "Save as (optional)", "kind": "text", "value": ""},
        ]
        blocked = value["blocked"] or ("No suggestion is ready for review." if not choices else "")
    elif kind == "withdraw":
        fields = [{"name": "name", "label": "Added skill", "kind": "select",
                   "required": True, "choices": [{"value": row["name"],
                                                     "label": row["name"].replace("-", " ") +
                                                     (" (paused)" if row.get("source_shared") is False else "")}
                                                  for row in added]}]
        blocked = "No added suggestion is available." if not added else ""
    return Snapshot(
        digest(value), "Suggestions from completed shared work",
        "Read all instructions and source tasks before adding a suggestion. Nothing is used automatically.",
        details=value, fields=fields, blocked=blocked,
    )


def review_prepare(request, selection, arguments):
    return Preview("These suggestions have not been added to the agents' skills.",
                   native=_state(request))


def admit_prepare(request, selection, arguments):
    value = _state(request)
    row = next((item for item in value["suggestions"]
                if item["name"] == arguments["candidate"] and item["ok"]), None)
    if row is None or not value["can_add"]:
        raise HTTPException(409, "This suggestion is unavailable. Refresh the current review.")
    review = changes.prepare(request, row["name"], "admit", row["fingerprint"], arguments["name"])
    return Preview(
        review["message"], changes=review["changes"], native={"review": review, "expires": time.time() + changes.TTL},
    )


def admit_recover(request, selection, arguments, prepared, operation):
    result = changes.original_for_review(request, prepared["review"], operation)
    return _outcome(result, replay=True) if result else None


def _outcome(result, *, replay=False):
    # A confirmed original read back again was not repeated: report it as replayed.
    status = ("replayed" if replay else "confirmed") if result["confirmed"] else "unconfirmed"
    return Outcome(status, result["message"], result)


def admit_execute(request, selection, arguments, prepared, operation):
    result = changes.apply(request, prepared["review"], operation, expires=prepared["expires"])
    return _outcome(result)


def withdraw_prepare(request, selection, arguments):
    value = _state(request)
    row = next((item for item in value["added"] if item["name"] == arguments["name"]), None)
    if row is None:
        raise HTTPException(409, "This saved skill is unavailable. Refresh the current review.")
    review = changes.prepare(request, row["name"], "withdraw", row["fingerprint"])
    # A paused skill says why it is paused before its removal is reviewed.
    paused = row.get("status", "") + " " if row.get("source_shared") is False else ""
    return Preview(
        paused + review["message"], changes=review["changes"], native={"review": review, "expires": time.time() + changes.TTL},
    )


def withdraw_execute(request, selection, arguments, prepared, operation):
    return admit_execute(request, selection, arguments, prepared, operation)


def original_snapshot(request, selection):
    context = changes.authority(request)
    if selection.get("kind") != "learned_skill_change" or not selection.get("operation"):
        return Snapshot(digest([context, "no-selected-original"]), "Original learned-skill changes",
                        "Read the exact original result without adding or removing anything.",
                        blocked="Choose Read original change in the Skills page first.")
    row = changes.original(request, selection["operation"])
    return Snapshot(digest(row), "Original reviewed learned-skill change", row["message"])


def original_prepare(request, selection, arguments):
    row = changes.original(request, selection["operation"])
    return Preview(row["message"], native={"Original change": row["message"],
        "Current skills": row.get("current", "Current skills do not establish the original result."),
        "Open original result": {"href": "/skills?learned_request=" + row["operation"] + "#to-learned-skills",
                                 "label": "Read original skill change"}})


def entries():
    shared = {"family": "learning", "direct_ui": "/skills", "pages": ("/skills", "/learned")}
    return (
        Adapter("skills.review_suggestions", "Review suggested skills", input_model=EmptyInput,
                snapshot=snapshot, prepare=review_prepare, **shared),
        Adapter("skills.admit_suggestion", "Add a reviewed skill", input_model=AdmitInput,
                snapshot=lambda r, s: snapshot(r, s, "admit"), prepare=admit_prepare,
                execute=admit_execute, recover=admit_recover, read_recovery=admit_recover, **shared),
        Adapter("skills.withdraw_suggestion", "Remove an added suggested skill", input_model=WithdrawInput,
                snapshot=lambda r, s: snapshot(r, s, "withdraw"), prepare=withdraw_prepare,
                execute=withdraw_execute, recover=admit_recover, read_recovery=admit_recover, **shared),
        Adapter("skills.read_original_change", "Read the selected original skill change", input_model=EmptyInput,
                snapshot=original_snapshot, prepare=original_prepare, **shared),
    )
