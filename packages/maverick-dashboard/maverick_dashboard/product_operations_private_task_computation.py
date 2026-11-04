"""Typed controls for the same fixed private local check and complete native form."""
from __future__ import annotations

from datetime import datetime
from functools import partial

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import private_task_computation_store as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput

PAGE = "/private-task-computation"


class CreateInput(StrictInput):
    source: str = Field(pattern=r"^[1-9][0-9]*\|[1-9][0-9]*$")
    row: int = Field(ge=1, le=200)
    field_name: str = Field(min_length=1, max_length=100)
    expected: bool
    purpose: str = Field(min_length=1, max_length=500)
    basis: str = Field(min_length=10, max_length=2000)
    expires_at: str = Field(min_length=1, max_length=64)
    approved_result: str = Field(pattern=r"^(MEETS_ENTERED_CONDITIONS|DOES_NOT_MEET_ENTERED_CONDITIONS)$")


class EditInput(StrictInput):
    row: int = Field(ge=1, le=200)
    field_name: str = Field(min_length=1, max_length=100)
    expected: bool
    purpose: str = Field(min_length=1, max_length=500)
    basis: str = Field(min_length=10, max_length=2000)
    expires_at: str = Field(min_length=1, max_length=64)
    approved_result: str = Field(pattern=r"^(MEETS_ENTERED_CONDITIONS|DOES_NOT_MEET_ENTERED_CONDITIONS)$")
    acknowledge_new_intent: bool


class ReleaseInput(StrictInput):
    approved_result: str = Field(pattern=r"^(MEETS_ENTERED_CONDITIONS|DOES_NOT_MEET_ENTERED_CONDITIONS)$")
    acknowledge_release: bool


class ScopeInput(StrictInput):
    expires_at: str = Field(min_length=1, max_length=64)
    basis: str = Field(min_length=10, max_length=2000)
    acknowledge_source_rights: bool


class AcknowledgeInput(StrictInput):
    acknowledge_unknown: bool


class OriginalInput(StrictInput):
    original: str = Field(pattern=r"^PTC-[a-f0-9]{32}\|[a-f0-9]{32}$")


def _date(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.timestamp()
    except (ValueError, AttributeError) as exc:
        raise HTTPException(422, "Enter a complete future date with its time zone.") from exc


def selected(selection, *, optional=False):
    if optional and not selection:
        return None
    if type(selection) is not dict or set(selection) != {"kind", "id"} or selection.get("kind") != "private_task_check":
        raise HTTPException(409, "Open the owned private check you want to review.")
    return selection["id"]


def _model(arguments):
    return {"fields": [{"name": arguments["field_name"], "kind": "boolean"}],
        "conditions": [{"field": arguments["field_name"], "operator": "equal", "right": {"kind": "value", "value": arguments["expected"]}}],
        "mode": "all", "purpose": arguments["purpose"], "basis": arguments["basis"],
        "expires_at": _date(arguments["expires_at"]), "approved_result": arguments["approved_result"]}


def _arguments(action, arguments):
    if action in {"create", "edit"}:
        result = {"model": _model(arguments), "row": arguments["row"]}
        if action == "create":
            goal, attachment = arguments["source"].split("|")
            result.update(goal=int(goal), attachment=int(attachment))
        else:
            result["acknowledge_new_intent"] = arguments["acknowledge_new_intent"]
        return result
    if action == "scope":
        return {**arguments, "expires_at": _date(arguments["expires_at"])}
    return arguments


def _fields(action, request):
    if action == "original":
        return [{"name": "original", "label": "Exact earlier original request", "kind": "select", "required": True,
            "choices": native.history(request)["choices"]}]
    if action in {"create", "edit"}:
        fields = [{"name": name, "label": label, "kind": kind, "required": True} for name, label, kind in (
            ("row", "Only selected data row", "number"), ("field_name", "Exact CSV Yes/No column name", "text"),
            ("expected", "The condition requires true", "boolean"), ("purpose", "Fixed permitted purpose", "text"),
            ("basis", "Current basis for reuse and release rights", "textarea"), ("expires_at", "Review source permission again by", "datetime-local"))]
        fields.append({"name": "approved_result", "label": "The only result allowed into a file", "kind": "select", "required": True,
            "choices": [{"value": result, "label": "Meets entered conditions" if index == 0 else "Does not meet entered conditions"} for index, result in enumerate(native.RESULTS)]})
        if action == "create":
            fields[0:0] = [{"name": "source", "label": "Owned task and complete private CSV file", "kind": "select", "required": True,
                "choices": [{"value": str(row["goal"]) + "|" + str(row["attachment"]), "label": row["label"]} for row in native.choices(request)["choices"]]}]
        else:
            fields.append({"name": "acknowledge_new_intent", "label": "This is a separate fixed intent; earlier originals and spent allowances remain", "kind": "boolean", "required": True})
        return fields
    if action == "release":
        return [{"name": "approved_result", "label": "Exact single approved result", "kind": "select", "required": True,
            "choices": [{"value": result, "label": "Meets entered conditions" if index == 0 else "Does not meet entered conditions"} for index, result in enumerate(native.RESULTS)]},
            {"name": "acknowledge_release", "label": "I approve these fixed file bytes and current export rights; this uses the source's only release", "kind": "boolean", "required": True}]
    if action == "scope":
        return [{"name": name, "label": label, "kind": kind, "required": True} for name, label, kind in (
            ("expires_at", "Review permission again by", "datetime-local"), ("basis", "Current reuse and release rights", "textarea"),
            ("acknowledge_source_rights", "I reviewed current source rights; earlier checks cannot be reused", "boolean"))]
    if action == "acknowledge":
        return [{"name": "acknowledge_unknown", "label": "The earlier original remains unknown; its check and release allowances will not be refunded", "kind": "boolean", "required": True}]
    return []


def snapshot(request, selection, *, action):
    if action in {"original", "history"}:
        value = native.history(request)
    elif action in {"create", "author"}:
        value = native.author_handoff(request, selected(selection, optional=True) if action == "author" else None)
    else:
        value = native.view(request, selected(selection))
    return Snapshot(digest(value), "Current owned task, complete declared check and lifetime source allowance", native.NOTICE,
        fields=_fields(action, request), details={"meaning": "The complete native form supports all six fields and eight conditions. This typed short form enters one Yes/No condition only."} if action in {"create", "edit"} else {})


def prepare(request, selection, arguments, *, action):
    if action == "author":
        return Preview("Opening the complete ordinary form only; your entered draft is kept. Any later write needs its full current review.",
            native={"private_task_computation_author": native.author_handoff(request, selected(selection, optional=True))})
    if action == "history":
        return Preview("Reading only: original request history never repeats a private check or release.", native=native.history(request))
    if action == "original":
        identifier, operation = arguments["original"].split("|")
        return Preview("Reading the original only; current private source inputs are not reopened.", native=native.original(request, identifier, operation))
    if action == "read":
        value = native.view(request, selected(selection))
        return Preview(native.NOTICE, native={"status": "Current fixed private check", "usable": value["usable"], "allowance": value["allowance"],
            "result": value["result"], "downloadable": value["downloadable"], "open": {"href": PAGE + "?check=" + value["id"], "label": "Open complete private check"}})
    value = native.prepare(request, None if action == "create" else selected(selection), action, _arguments(action, arguments))
    return Preview("Review the complete fixed task, source, condition possibilities, permission and single allowed result. This local comparison does not verify business facts or guarantee against inference.", native.changes(value), value)


def outcome(value):
    return Outcome("confirmed" if value["confirmed"] else "unconfirmed", value["message"],
        {"original_result": value["receipt"], "open": {"href": PAGE + "?check=" + value["id"], "label": "Open this private check"}})


def execute(request, _selection, _arguments, prepared, operation):
    return outcome(native.apply(request, prepared, operation))


def recover(request, _selection, _arguments, prepared, operation):
    value = native.recover(request, prepared, operation)
    return outcome(value) if value else None


def entries():
    common = {"family": "tasks", "pages": (PAGE,), "direct_ui": PAGE}
    writes = tuple(Adapter("tasks.private_check." + action, label, input_model=model,
        snapshot=partial(snapshot, action=action), prepare=partial(prepare, action=action), execute=execute,
        recover=recover, read_recovery=recover, **common) for action, label, model in (
            ("create", "Save one private Yes/No condition", CreateInput), ("edit", "Replace with one private Yes/No condition", EditInput),
            ("run", "Run the complete fixed private local check", EmptyInput), ("release", "Review release of the single approved result", ReleaseInput),
            ("withdraw", "Withdraw private-source and release permission", EmptyInput), ("scope", "Review current private-source permission", ScopeInput),
            ("acknowledge", "Stop waiting for an unknown original without repeating it", AcknowledgeInput), ("remove", "Remove the current private check", EmptyInput)))
    readers = tuple(Adapter("tasks.private_check." + action, label, input_model=model,
        snapshot=partial(snapshot, action=action), prepare=partial(prepare, action=action), **common) for action, label, model in (
            ("read", "Read the current private-check result", EmptyInput), ("history", "Read earlier private-check requests", EmptyInput),
            ("original", "Read the exact original private-check result", OriginalInput), ("author", "Open the complete private-check form", EmptyInput)))
    return writes + readers
