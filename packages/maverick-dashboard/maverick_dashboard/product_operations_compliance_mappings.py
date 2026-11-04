"""Copilot authoring and independent review of real native task mappings."""
from __future__ import annotations

from functools import partial

from pydantic import Field

from . import compliance_mapping_builder as service
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class MappingInput(StrictInput):
    mapping: str = Field(min_length=3, max_length=140)


def choice_field(name, label, values):
    return {"name": name, "label": label, "kind": "select", "required": True,
            "choices": [{"value": key, "label": text} for key, text in values.items()]}


def snapshot(request, _selection, *, kind):
    state = service.state(request)
    fields, blocked = [], ""
    if kind == "create":
        service.authority(request, write=True)
        scopes = [row for row in state["scopes"] if row["supported"]]
        fields = [{"name": "scope", "label": "Final scope", "kind": "select", "required": True,
                   "choices": [{"value": row["value"], "label": row["label"]} for row in scopes]},
                  {"name": "name", "label": "Mapping name", "kind": "text", "required": True, "max_length": 80},
                  choice_field("control_state", "Initial control status", service.STATES),
                  choice_field("control_owner", "Control responsibility", {key: service.ROLES[key] for key in ("control_owner", "second_line")}),
                  choice_field("evidence_kind", "Evidence work for each control", service.KINDS),
                  choice_field("evidence_owner", "Evidence responsibility", service.ROLES),
                  choice_field("cadence", "Evidence frequency", service.CADENCES)]
        blocked = "Finish and finalize a scope first. This authoring path supports the native mapping limit of 1 to 2,000 controls." if not scopes else ""
    else:
        if kind == "approve":
            service.authority(request, write=True, approval=True)
        mappings = [row for row in state["mappings"] if kind != "approve" or row["can_approve"]]
        fields = [{"name": "mapping", "label": "Saved mapping", "kind": "select", "required": True,
                   "choices": [{"value": row["value"], "label": row["label"] + " · " + row["status"]} for row in mappings]}]
        blocked = "No mapping is available for this action. Your own mapping needs another administrator to approve it." if not mappings else ""
    return Snapshot(state["revision"], "Current final scopes and saved mapping versions", state["notice"],
                    {"notice": state["notice"], "record_list": state["listing_notice"],
                     "open_mapping": {"href": service.PAGE, "label": "Build and review task mappings"}}, fields, blocked)


def prepare(request, _selection, args, *, kind):
    if kind == "read":
        value = service.inspect_mapping(request, args["mapping"])
        value.pop("context")
        more = value.pop("next_offset")
        if more is not None:
            value["shown_controls"] = "The first 20 mapped controls are shown. Open the saved mapping to review the rest."
        return Preview("Read this mapping's saved business choices. Nothing changed.", native=value)
    if kind == "create":
        choices = service.Choices.model_validate(args)
        source = service.controls(request, choices.scope)
        value = service.review(request, choices, source["revision"])
    else:
        value = service.review_approval(request, args["mapping"])
    return Preview(value["message"], [{"label": key.replace("_", " ").capitalize(), "after": str(item)} for key, item in value["details"].items() if not isinstance(item, dict)],
                   {"review": value["token"]})


def execute(request, _selection, _args, prepared, _operation):
    value = service.apply(request, prepared["review"], confirmed=True)
    return Outcome("confirmed" if value["status"] == "confirmed" else "replayed", value["message"], value.get("details", {}))


def recover(request, _selection, _args, prepared, _operation):
    value = service.readback(request, prepared["review"])
    if value["status"] == "not_found":
        return None
    return Outcome("replayed", value["message"], value.get("details", {}))


def form_snapshot(request, _selection, *, mode):
    service.authority(request, write=True)
    value = service.state(request)
    return Snapshot(value["revision"], "Current final scopes and immutable task mappings",
                    "Open the protected mapping form, choose a final scope and named mapping, and review individual control and evidence work. This handoff saves or approves nothing.",
                    details={"compliance_mapping_form": {"context": value["context"], "mode": mode},
                             "open_mapping": {"href": service.PAGE, "label": "Build or revise a task mapping"}})


def form_prepare(request, selection, _arguments, *, mode):
    value = form_snapshot(request, selection, mode=mode)
    return Preview(value.summary, native=value.details)


def entries():
    pages = (service.PAGE, "/compliance/scope-actions", "/compliance/scoping")
    return (
        Adapter("compliance.mapping.design", "Choose individual control and evidence work", "tasks", service.PAGE, pages, EmptyInput,
                partial(form_snapshot, mode="create"), partial(form_prepare, mode="create"),
                aliases=("build a mixed task mapping", "choose work for each control")),
        Adapter("compliance.mapping.revise", "Revise the latest saved task mapping", "tasks", service.PAGE, pages, EmptyInput,
                partial(form_snapshot, mode="revise"), partial(form_prepare, mode="revise"),
                aliases=("update a compliance mapping", "revise control responsibilities and evidence work")),
        Adapter("compliance.mapping.create", "Build a task mapping from a final scope", "tasks", service.PAGE, pages, service.Choices,
                partial(snapshot, kind="create"), partial(prepare, kind="create"), execute, recover,
                aliases=("build a compliance mapping", "create a scope mapping", "map compliance evidence work")),
        Adapter("compliance.mapping.read", "Read a saved task mapping", "reviews", service.PAGE, pages, MappingInput,
                partial(snapshot, kind="read"), partial(prepare, kind="read")),
        Adapter("compliance.mapping.approve", "Approve another person's task mapping", "reviews", service.PAGE, pages, MappingInput,
                partial(snapshot, kind="approve"), partial(prepare, kind="approve"), execute, recover,
                aliases=("approve a compliance mapping", "review this task mapping")),
    )
