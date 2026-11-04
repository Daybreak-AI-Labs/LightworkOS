"""Typed teaching-question controls use the same native guarded writer."""
from __future__ import annotations

from datetime import datetime
from functools import partial
from urllib.parse import quote

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import operator_acquisition as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class CreateInput(StrictInput):
    node: str = Field(min_length=1, max_length=256)
    reference: str = Field(default="", max_length=256)
    output: str = Field(default="", max_length=256)
    prior: list[str] = Field(default_factory=list, max_length=8)
    default_effort: int = Field(ge=1, le=1000)
    effort_unit: str = Field(min_length=1, max_length=100)
    allowed: bool
    allow_independent_artifact: bool
    purpose: str = Field(min_length=10, max_length=2000)
    expires_at: str = Field(min_length=1, max_length=64)


class ReviewInput(StrictInput):
    review: str = Field(pattern=r"^OAC-[a-f0-9]{32}$")


class PermissionInput(ReviewInput):
    allowed: bool
    allow_independent_artifact: bool
    purpose: str = Field(min_length=10, max_length=2000)
    expires_at: str = Field(min_length=1, max_length=64)


class ScopeInput(PermissionInput):
    reuse_recorded_answers: bool


class TestInput(PermissionInput):
    reported_effort: int = Field(ge=1, le=1000)


class AnswerInput(TestInput):
    answer: str = Field(default="", max_length=1024)
    boolean_choice: str = Field(default="", pattern=r"^(?:yes|no)?$")


class AcknowledgeInput(ReviewInput):
    acknowledge_unknown: bool


class OriginalInput(StrictInput):
    original: str = Field(pattern=r"^OAC-[a-f0-9]{32}\|[a-f0-9]{32}$")


def selected(selection):
    if type(selection) is not dict or set(selection) != {"kind", "id"} or selection.get("kind") != "flow" or type(selection.get("id")) is not str:
        raise HTTPException(409, "Choose your owned saved workflow in Plan teaching questions.")
    native_id = selection["id"]
    if not 1 <= len(native_id) <= 256:
        raise HTTPException(409, "Choose one complete current saved workflow.")
    return native_id


def _date(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.timestamp()
    except (ValueError, AttributeError) as exc:
        raise HTTPException(422, "Enter a complete future date including its time zone.") from exc


def _permission_fields():
    return [{"name": name, "label": label, "kind": kind, "required": True} for name, label, kind in (
        ("allowed", "I have current permission to use the complete displayed source and answers", "boolean"),
        ("allow_independent_artifact", "Permit this evidence to create a separately owned taught rule after another complete acceptance review", "boolean"),
        ("purpose", "Exact teaching and effort-report use purpose", "textarea"), ("expires_at", "Review permission again by", "datetime-local"))]


def fields(request, selection, action):
    if action == "original":
        return [{"name": "original", "label": "Your exact earlier request", "kind": "select", "required": True, "choices": native.history(request)["choices"]}]
    if action in {"history", "author"}:
        return []
    listing = native.history(request) if action in {"withdraw", "remove", "acknowledge"} else native.listing(request, selected(selection))
    if action == "create":
        rows = [{"name": "node", "label": "Saved taught step", "kind": "select", "required": True, "choices": listing["steps"]},
            {"name": "reference", "label": "Optional owned published local check rule", "kind": "select", "required": False, "choices": [{"value": "", "label": "No local check rule"}, *listing["references"]]},
            {"name": "output", "label": "Named answer from that local check rule", "kind": "select", "required": False,
                "choices": [{"value": "", "label": "No local check answer"}, *[{"value": item["value"], "label": row["label"] + " · " + item["label"]} for row in listing["references"] for item in row["outputs"]]]},
            {"name": "prior", "label": "Earlier owned answer reports with current consent in the same effort unit", "kind": "multiselect", "presentation": "checkboxes", "required": False, "max_selections": 8, "choices": listing["reviews"]},
            {"name": "default_effort", "label": "Default effort for a question without an earlier report", "kind": "number", "required": True},
            {"name": "effort_unit", "label": "One consistent effort unit, for example active minutes or review points", "kind": "text", "required": True}]
        return rows + _permission_fields()
    rows = [{"name": "review", "label": "Your retained teaching-question review", "kind": "select", "required": True,
        "choices": [row for row in listing["reviews"] if row["flow"] == selected(selection)]}]
    if action in {"answer", "test", "scope"}:
        rows.extend(_permission_fields())
    if action in {"answer", "test"}:
        rows.append({"name": "reported_effort", "label": "Reported active effort for this question in your stated unit", "kind": "number", "required": True})
    if action == "answer":
        rows.extend([{"name": "boolean_choice", "label": "Your Yes or No answer, when the selected question asks for one", "kind": "select", "required": False,
            "choices": [{"value": "", "label": "This is a whole-number or text answer"}, {"value": "yes", "label": "Yes"}, {"value": "no", "label": "No"}]},
            {"name": "answer", "label": "Your exact whole-number or text answer; leave empty for a Yes or No choice", "kind": "textarea", "required": False}])
    if action == "scope":
        rows.append({"name": "reuse_recorded_answers", "label": "Explicitly allow every displayed retained answer and effort report again under this new complete grant", "kind": "boolean", "required": True})
    if action == "acknowledge":
        rows.append({"name": "acknowledge_unknown", "label": "The original remains unknown and its admitted allowance stays spent", "kind": "boolean", "required": True})
    return rows


def snapshot(request, selection, *, action):
    value = native.history(request) if action in {"history", "original", "withdraw", "remove", "acknowledge"} else native.listing(request, selected(selection))
    return Snapshot(digest(value), "Current owned saved teaching source and permitted earlier effort reports", native.NOTICE, fields=fields(request, selection, action))


def prepare(request, selection, arguments, *, action):
    if action == "history":
        return Preview("Original history only; no policy or native test repeats.", native=native.history(request))
    if action == "original":
        identifier, operation = arguments["original"].split("|")
        return Preview("Read this exact original attribution only.", native=native.original(request, identifier, operation))
    flow_id = selected(selection)
    if action == "author":
        return Preview("Open the complete ordinary source and question form, preserving its entered draft. Nothing is saved or tested.",
            native={"operator_acquisition_author": native.author_handoff(request, flow_id)})
    arguments = dict(arguments)
    identifier = arguments.pop("review", "")
    if action == "read":
        value = native.view(request, identifier)
        return Preview(native.NOTICE, native=native.public(value))
    if action == "draft":
        value = native.draft(request, identifier)
        return Preview(value["note"], native={"open": {"href": "/flows/" + quote(flow_id, safe="") + "/teach?acquisition=" + identifier, "label": "Open the checked private unsaved draft in Teach"}})
    if action == "answer":
        choice = arguments.pop("boolean_choice", "")
        if choice:
            if arguments.get("answer"):
                raise HTTPException(422, "Choose either a Yes or No answer or a complete whole-number or text answer.")
            arguments["answer"] = "true" if choice == "yes" else "false"
    if "expires_at" in arguments:
        arguments["expires_at"] = _date(arguments["expires_at"])
    prepared = native.prepare(request, flow_id, identifier, action, arguments)
    return Preview(native.NOTICE, native.changes(prepared), prepared)


def outcome(value):
    return Outcome("confirmed" if value["confirmed"] else "unconfirmed", value["message"], {"original_result": value["receipt"]})


def execute(request, _selection, _arguments, prepared, operation):
    return outcome(native.apply(request, prepared, operation))


def recover(request, _selection, _arguments, prepared, operation):
    value = native.recover(request, prepared, operation)
    return outcome(value) if value else None


def entries():
    common = {"family": "learning", "pages": (native.PAGE,), "direct_ui": native.PAGE}
    writes = tuple(Adapter("learning.acquisition." + action, label, input_model=model, snapshot=partial(snapshot, action=action),
        prepare=partial(prepare, action=action), execute=execute, recover=recover, read_recovery=recover, **common) for action, label, model in (
            ("create", "Enter complete teaching-question source and permission", CreateInput), ("plan", "Plan every possible teaching-question branch", ReviewInput),
            ("answer", "Record a reviewed answer and active-effort report", AnswerInput), ("test", "Ask the owned published local reference", TestInput),
            ("qualify", "Check every declared situation against the local reference", ReviewInput), ("scope", "Review complete answer-use permission", ScopeInput),
            ("withdraw", "Withdraw teaching-question source use", ReviewInput), ("acknowledge", "Stop waiting for an unknown teaching original", AcknowledgeInput),
            ("remove", "Remove the current teaching-question review", ReviewInput)))
    readers = tuple(Adapter("learning.acquisition." + action, label, input_model=model, snapshot=partial(snapshot, action=action),
        prepare=partial(prepare, action=action), **common) for action, label, model in (
            ("read", "Read the current full question plan", ReviewInput), ("history", "Read earlier teaching-question requests", EmptyInput),
            ("original", "Read the exact original teaching-question result", OriginalInput), ("author", "Open all teaching-question controls", EmptyInput),
            ("draft", "Open the qualified private draft in Teach", ReviewInput)))
    return writes + readers
