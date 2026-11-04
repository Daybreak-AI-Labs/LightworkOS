"""Typed Copilot controls for the same native Promise qualification path."""
from __future__ import annotations

from datetime import datetime
from functools import partial

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import commitment_capability_store as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput

PAGE = "/commitment-reviews"


class ModelInput(StrictInput):
    first_offer: str = Field(min_length=1, max_length=200)
    first_quantity: int = Field(ge=1, le=1000)
    second_offer: str = Field(min_length=1, max_length=200)
    second_quantity: int = Field(ge=1, le=1000)
    due_at: str = Field(min_length=1, max_length=64)
    material_low: int = Field(ge=1, le=100)
    material_high: int = Field(ge=1, le=100)
    capacity_low: int = Field(ge=1, le=100)
    capacity_high: int = Field(ge=1, le=100)
    setup_low: int = Field(ge=0, le=100)
    setup_high: int = Field(ge=0, le=100)
    material_addition: int = Field(ge=1, le=100000)
    capacity_addition: int = Field(ge=1, le=100000)
    material_cost: int = Field(ge=0, le=100000)
    capacity_cost: int = Field(ge=0, le=100000)
    ready_at: str = Field(min_length=1, max_length=64)
    max_addition_cost: int = Field(ge=0, le=100000)
    test_limit: int = Field(ge=0, le=8)
    test_effort: int = Field(ge=0, le=8000)
    test_cost: int = Field(ge=1, le=1000)
    expires_at: str = Field(min_length=1, max_length=64)
    basis: str = Field(min_length=10, max_length=2000)


class ReportInput(StrictInput):
    quantity: int = Field(ge=1, le=4000)
    offers: int = Field(ge=1, le=4)
    material: int = Field(ge=0, le=2000000)
    capacity: int = Field(ge=0, le=2000000)
    outcome: bool
    basis: str = Field(min_length=10, max_length=2000)
    expires_at: str = Field(min_length=1, max_length=64)


class TestInput(StrictInput):
    flow_id: str = Field(min_length=1, max_length=120)
    output: str = Field(min_length=1, max_length=120)
    meaning: str = Field(min_length=10, max_length=2000)


class ScopeInput(StrictInput):
    allowed: bool
    expires_at: str = Field(min_length=1, max_length=64)
    basis: str = Field(min_length=10, max_length=2000)


class WithdrawInput(StrictInput):
    observation: str = Field(pattern=r"^[a-f0-9]{32}$")


class ReleaseInput(StrictInput):
    acknowledge_unknown: bool


class OriginalInput(StrictInput):
    original: str = Field(pattern=r"^CCL-[a-f0-9]{32}\|[a-f0-9]{32}$")


def _date(value):
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError
        return result.timestamp()
    except (ValueError, AttributeError) as exc:
        raise HTTPException(422, "Choose a complete date with the current time zone.") from exc


def selected(selection):
    if type(selection) is not dict or set(selection) != {"kind", "id"} or selection.get("kind") != "commitment_review":
        raise HTTPException(409, "Open the owned Promise review whose accepted work this qualification must protect.")
    return selection["id"]


def model(arguments):
    return {"offers": [{"id": key, "label": arguments[label], "units": arguments[quantity], "due_at": _date(arguments["due_at"])}
        for key, label, quantity in (("offer-a", "first_offer", "first_quantity"), ("offer-b", "second_offer", "second_quantity"))],
        "requirements": {key: sorted({arguments[low], arguments[high]}) for key, low, high in (
            ("material_per_unit", "material_low", "material_high"), ("capacity_per_unit", "capacity_low", "capacity_high"), ("shared_setup", "setup_low", "setup_high"))},
        "additions": [{"id": kind + "-addition", "label": "Reported additional " + ("material" if kind == "material" else "work capacity"), "kind": kind,
            "units": arguments[kind + "_addition"], "ready_at": _date(arguments["ready_at"]), "cost": arguments[kind + "_cost"], "basis": arguments["basis"]}
            for kind in ("material", "capacity")],
        **{key: arguments[key] for key in ("max_addition_cost", "test_limit", "test_effort", "test_cost", "basis")}, "expires_at": _date(arguments["expires_at"])}


def arguments_for(action, arguments):
    if action in {"create", "edit"}:
        return model(arguments)
    if action == "report":
        return {"inputs": {key: arguments[key] for key in ("quantity", "offers", "material", "capacity")},
            "outcome": arguments["outcome"], "basis": arguments["basis"], "expires_at": _date(arguments["expires_at"])}
    if action == "scope":
        return {**arguments, "expires_at": _date(arguments["expires_at"])}
    return arguments


def snapshot(request, selection, *, action):
    if action == "original":
        value = native.history(request)
        return Snapshot(digest(value), "Your retained qualification originals", "Reading an original never repeats a test or changes an allowance.",
            fields=[{"name": "original", "label": "Exact original request", "kind": "select", "required": True, "choices": value["choices"]}])
    if action == "author":
        value = native.author_handoff(request, selected(selection))
        return Snapshot(digest(value), "The complete additional-work form for this owned Promise review",
            "Open the ordinary form for up to four offers, six possible additions and three possible requirements in each row. Your entered draft stays intact. Opening this form does not save or run anything.")
    value = native.view(request, selected(selection))
    fields = []
    if action in {"create", "edit"}:
        labels = (("first_offer", "First additional offer", "text"), ("first_quantity", "Its work quantity", "number"),
            ("second_offer", "Second additional offer", "text"), ("second_quantity", "Its work quantity", "number"), ("due_at", "Both additional offers due by", "datetime-local"),
            ("material_low", "First possible material units per work unit", "number"), ("material_high", "Second possible material units per work unit", "number"),
            ("capacity_low", "First possible capacity units per work unit", "number"), ("capacity_high", "Second possible capacity units per work unit", "number"),
            ("setup_low", "First possible setup capacity when offers are combined", "number"), ("setup_high", "Second possible shared setup capacity", "number"),
            ("material_addition", "Possible added material units", "number"), ("capacity_addition", "Possible added capacity units", "number"),
            ("material_cost", "Declared material addition cost points", "number"), ("capacity_cost", "Declared capacity addition cost points", "number"),
            ("ready_at", "Possible additions ready by", "datetime-local"), ("max_addition_cost", "Maximum declared addition cost points", "number"),
            ("test_limit", "Shared test allowance", "number"), ("test_effort", "Shared effort allowance", "number"), ("test_cost", "Effort points per test or trial report", "number"),
            ("expires_at", "Review source permission again by", "datetime-local"), ("basis", "Basis and exact scope of reported availability and permission", "textarea"))
        fields = [{"name": name, "label": label, "kind": kind, "required": True} for name, label, kind in labels]
    elif action == "test":
        choices = native.test_choices(request)
        fields = [{"name": "flow_id", "label": "Current owned published rules", "kind": "select", "required": True, "choices": choices["choices"]},
            {"name": "output", "label": "Exact named Yes/No result in these rules", "kind": "text", "required": True},
            {"name": "meaning", "label": "What this local rule test establishes and the source permission", "kind": "textarea", "required": True}]
    elif action == "report":
        fields = [{"name": key, "label": label, "kind": "number", "required": True} for key, label in (
            ("quantity", "Total additional work units in completed trial"), ("offers", "Number of combined offers in trial"),
            ("material", "Material units available after protecting accepted work"), ("capacity", "Work-capacity units available after protecting accepted work"))]
        fields += [{"name": "outcome", "label": "The completed trial supported this work", "kind": "select", "required": True,
            "choices": [{"value": True, "label": "Yes"}, {"value": False, "label": "No"}]},
            {"name": "basis", "label": "Trial outcome and source-permission basis (operator report)", "kind": "textarea", "required": True},
            {"name": "expires_at", "label": "Review this trial observation again by", "kind": "datetime-local", "required": True}]
    elif action == "scope":
        fields = [{"name": "allowed", "label": "Permission to use the current entered facts", "kind": "select", "required": True,
            "choices": [{"value": True, "label": "Allow"}, {"value": False, "label": "Withdraw"}]},
            {"name": "expires_at", "label": "Review this permission again by", "kind": "datetime-local", "required": True},
            {"name": "basis", "label": "Current permission, availability and scope basis", "kind": "textarea", "required": True}]
    elif action == "withdraw":
        fields = [{"name": "observation", "label": "Observation whose future use stops", "kind": "select", "required": True,
            "choices": [{"value": row["id"], "label": row["quality"].replace("_", " ") + " · " + row["basis"]} for row in value.get("observations", []) if row.get("consent") is True]}]
    elif action == "release":
        fields = [{"name": "acknowledge_unknown", "label": "The previous attempt remains unknown; any next test will be a separate intentional attempt", "kind": "boolean", "required": True}]
    return Snapshot(digest(value), "The complete accepted-work source, competing requirements and current qualification allowance", native.NOTICE,
        details=value.get("evaluation"), fields=fields, blocked="This qualification was removed." if value.get("removed") else "")


def prepare(request, selection, arguments, *, action):
    if action == "original":
        identifier, operation = arguments["original"].split("|")
        return Preview("Reading only: this never executes another test.", native=native.original(request, identifier, operation))
    if action == "read":
        return Preview(native.NOTICE, native=native.view(request, selected(selection)))
    if action == "author":
        return Preview("Opening the full ordinary form only. Review the complete current source before any later confirmation.",
            native={"commitment_capability_author": native.author_handoff(request, selected(selection))})
    value = native.prepare(request, selected(selection), action, arguments_for(action, arguments))
    return Preview("Review every accepted commitment, source, declared possibility and this exact local change. Conditional planning support does not verify physical availability or revenue.", native.changes(value), value)


def outcome(value):
    return Outcome("confirmed" if value["confirmed"] else "unconfirmed", value["message"],
        {"original_result": value["receipt"], "open": {"href": PAGE + "?review=" + value["parent"], "label": "Open this Promise review"}})


def execute(request, _selection, _arguments, prepared, operation):
    return outcome(native.apply(request, prepared, operation))


def recover(request, _selection, _arguments, prepared, operation):
    value = native.recover(request, prepared, operation)
    return outcome(value) if value else None


def entries():
    common = {"family": "commitments", "pages": (PAGE,), "direct_ui": PAGE}
    values = tuple(Adapter("commitments.capability." + action, label, input_model=model,
        snapshot=partial(snapshot, action=action), prepare=partial(prepare, action=action), execute=execute,
        recover=recover, read_recovery=recover, **common) for action, label, model in (
            ("create", "Review additions for two additional offers", ModelInput), ("edit", "Replace the additional-work review", ModelInput),
            ("report", "Record a completed local trial report", ReportInput), ("test", "Run one owned local qualification test", TestInput),
            ("scope", "Review qualification source permission and expiry", ScopeInput), ("withdraw", "Withdraw a trial observation", WithdrawInput),
            ("release", "Release waiting for an unknown local attempt", ReleaseInput), ("remove", "Remove current additional-work qualification", EmptyInput)))
    return values + (Adapter("commitments.capability.read", "Read additional-work support and useful next test", input_model=EmptyInput,
        snapshot=partial(snapshot, action="read"), prepare=partial(prepare, action="read"), **common),
        Adapter("commitments.capability.original", "Read the exact original qualification result", input_model=OriginalInput,
        snapshot=partial(snapshot, action="original"), prepare=partial(prepare, action="original"), **common),
        Adapter("commitments.capability.author", "Open the complete additional-work form", input_model=EmptyInput,
        snapshot=partial(snapshot, action="author"), prepare=partial(prepare, action="author"), **common))
