"""Reviewed activation controls delegate to native private drafts and task admission."""
from __future__ import annotations

from functools import partial
from typing import Literal

import anyio
from fastapi import BackgroundTasks
from maverick.governed_operations import digest
from pydantic import Field

from . import employee_activation as native
from .draft_api import context_for
from .product_errors import product_error
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class Draft(StrictInput):
    job: str = Field(max_length=60)
    mode: Literal["sample", "real"] = "sample"
    material: str = Field(default="", max_length=10000)
    criteria: str = Field(min_length=1, max_length=2000)


def creation_snapshot(request, selection):
    native.actor(request, operate=True)
    choices = native.jobs(request)
    readiness = native.readiness(request)
    return Snapshot(digest({"jobs": choices, "readiness": readiness}), "Available tasks and your current access",
        "Save a private draft task with sample or real text. This does not start paid work.", {"readiness": readiness},
        [{"name": "job", "label": "Task", "kind": "select", "choices": [{"value": key, "label": value["label"]} for key, value in choices.items()]},
         {"name": "mode", "label": "Data choice", "kind": "select", "value": "sample", "choices": [{"value": "sample", "label": "Fictional practice"}, {"value": "real", "label": "Real text I provide"}]},
         {"name": "material", "label": "Real source text (unused for practice)", "kind": "textarea", "max_length": 10000},
         {"name": "criteria", "label": "My acceptance criteria", "kind": "textarea", "required": True, "max_length": 2000}])


def _body(request, arguments, operation):
    return native.DraftIn(context=context_for(request), operation_id=operation, source_kind="text", **arguments)


def prepare_creation(request, selection, arguments):
    values = native._validated(request, _body(request, arguments, "0" * 32))
    return Preview("Save an encrypted private activation draft. No task, connector fetch or model request starts.",
                   [{"field": "Draft", "before": "No new draft", "after": values}])


def _safe_result(value):
    source = value["values"].get("source", {})
    safe = {**value, "values": {**value["values"], "source": {key: source[key] for key in ("source", "name") if key in source}}}
    safe["open"] = {"label": "Open this exact activation draft", "href": value["return_href"]}
    return safe


def create(request, selection, arguments, review, operation):
    result = native.save(request, _body(request, arguments, operation))
    return Outcome("confirmed", "Private draft saved. Open it to review sources or repair a connection; starting work requires separate confirmation.", _safe_result(result))


def _row(request, selection):
    identity = selection.get("activation_id")
    if not isinstance(identity, str):
        raise product_error(404, "activation_selection_required", "Open one saved activation draft first.")
    return native._read(request, identity)


def snapshot(request, selection):
    row = _row(request, selection)
    value = native.public(request, row)
    result = value["result"]
    return Snapshot(digest([row["revision"], result["fingerprint"] if result else None]),
        "Your private activation draft and current owned task", "Current result acceptance is bound to the exact task result.", _safe_result(value))


def read(request, selection, arguments):
    return Preview("Current draft and task state. Sample acceptance remains labelled as practice; no paid work was started.", native=snapshot(request, selection).details)


def edit_snapshot(request, selection):
    row = _row(request, selection)
    if row["state"] != "draft" or native._result(request, row):
        raise product_error(409, "activation_already_started", "Started activation inputs are immutable. Create a new private draft for different work.")
    creation = creation_snapshot(request, selection)
    values = native._contents(row)
    return Snapshot(str(row["revision"]), creation.source, "Replace this unstarted draft with reviewed sample or real text inputs. A selected connected document is removed by this change.",
                    _safe_result(native.public(request, row)),
                    [{**field, "value": values.get(field["name"], field.get("value"))} for field in creation.fields])


def prepare_edit(request, selection, arguments):
    row = _row(request, selection)
    values = native._validated(request, _body(request, arguments, "0" * 32))
    return Preview("Replace only this private unstarted draft. No task starts; any connected-document selection is replaced with the reviewed text source.",
        [{"field": "Draft inputs", "before": _safe_result(native.public(request, row))["values"], "after": values}],
        {"revision": row["revision"]})


def edit(request, selection, arguments, review, operation):
    body = _body(request, arguments, operation).model_copy(update={"expected_revision": review["revision"]})
    result = native.save(request, body, draft=selection["activation_id"])
    return Outcome("confirmed", "The private unstarted draft was updated. Review it before starting work.", _safe_result(result))


def _prepare_action(action):
    def prepare(request, selection, arguments):
        row = _row(request, selection)
        native.actor(request, operate=True)
        result = native._result(request, row)
        if action in {"accept", "workflow"}:
            if not result or not result["complete"]:
                raise product_error(409, "activation_result_incomplete", "Wait for a completed current result, then review it.")
            if action == "workflow" and not result["accepted"]:
                raise product_error(409, "activation_acceptance_required", "Accept the current result before saving a reusable draft.")
        summary = {"launch": "Start this reviewed native task using existing governed model routes and budget. Provider usage may incur cost, including practice data.",
                   "accept": "Record your human acceptance of this exact current result against the saved criteria.",
                   "workflow": "Save a private reusable workflow draft with a new source input. Original source data, results and connection bindings are excluded."}[action]
        details = _safe_result(native.public(request, row)) if action != "workflow" else native._workflow_spec(row)
        return Preview(summary, [{"field": "Reviewed scope", "after": details}],
            {"revision": row["revision"], "fingerprint": result["fingerprint"] if result else ""})
    return prepare


def _execute_action(action):
    def execute(request, selection, arguments, review, operation):
        body = native.ActionIn(context=context_for(request), expected_revision=review["revision"], confirmed=True, result_fingerprint=review["fingerprint"])
        background = BackgroundTasks()
        if action == "launch":
            value = anyio.from_thread.run(partial(native.launch, request, selection["activation_id"], body, background))
        elif action == "workflow":
            value = native.workflow(request, selection["activation_id"], body)
        else:
            value = native.accept(request, selection["activation_id"], body)
        return Outcome("queued" if action == "launch" else "confirmed", value["message"], _safe_result(value), background=background)
    return execute


def _recover(action):
    def recover(request, selection, arguments, review, operation):
        row = _row(request, selection)
        result = native._result(request, row)
        recovered = bool(result) if action == "launch" else bool(result and result["accepted"] and result["fingerprint"] == review["fingerprint"]) if action == "accept" else bool(row.get("workflow"))
        if recovered:
            return Outcome("replayed", "Current native state recovered. No task or external effect was repeated.", _safe_result(native.public(request, row)))
        return None
    return recover


def entries():
    pages = ("/get-started/employee",)
    return [Adapter("activation.create", "Save a first-task draft", "tasks", pages[0], pages, Draft, creation_snapshot, prepare_creation, create),
            Adapter("activation.status", "Show this activation draft", "tasks", pages[0], pages, EmptyInput, snapshot, read),
            Adapter("activation.edit", "Edit unstarted activation draft", "tasks", pages[0], pages, Draft, edit_snapshot, prepare_edit, edit),
            *[Adapter("activation." + action, label, "tasks", pages[0], pages, EmptyInput, snapshot, _prepare_action(action), _execute_action(action), _recover(action))
              for action, label in (("launch", "Start the reviewed first task"), ("accept", "Accept the current result"), ("workflow", "Save reusable workflow draft"))]]
