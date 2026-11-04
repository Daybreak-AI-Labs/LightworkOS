"""Typed ordinary financial fields for the complete bounded native comparison."""
from __future__ import annotations

from datetime import datetime
from functools import partial

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field, create_model

from . import commitment_economic_alternatives_store as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput

PAGE = "/commitment-reviews"


def _input_model():
    fields = {"currency": (str, Field(pattern=r"^[A-Z]{3}$")), "unit_scale": (int, Field(ge=1, le=100)),
        "shared_cost": (str, Field(pattern=r"^(?:0|[1-9][0-9]{0,15})(?:\.[0-9]{1,2})?$")), "maximum_outlay": (str, Field(pattern=r"^(?:0|[1-9][0-9]{0,15})(?:\.[0-9]{1,2})?$")),
        "all_costs_included": (bool, ...), "allowed": (bool, ...), "basis": (str, Field(min_length=10, max_length=2000)),
        "expires_at": (str, Field(min_length=1, max_length=64)), "acknowledge_new_intent": (bool, False)}
    for kind, count, money in (("offer", 4, ("unit_price", "unit_cost", "fixed_cost")), ("addition", 6, ("cost",))):
        for index in range(1, count + 1):
            prefix = kind + "_" + str(index) + "_"
            fields.update({prefix + key: (str | None, Field(default=None, pattern=r"^(?:0|[1-9][0-9]{0,15})(?:\.[0-9]{1,2})?$")) for key in money})
            fields.update({prefix + "allowed": (bool | None, None), prefix + "basis": (str | None, Field(default=None, min_length=10, max_length=2000)),
                prefix + "expires_at": (str | None, Field(default=None, min_length=1, max_length=64))})
    return create_model("EconomicFactsInput", __base__=StrictInput, **fields)


FactsInput = _input_model()


class ScopeInput(StrictInput):
    allowed: bool
    basis: str = Field(min_length=10, max_length=2000)
    expires_at: str = Field(min_length=1, max_length=64)


class AcknowledgeInput(StrictInput):
    acknowledge_unknown: bool


class OriginalInput(StrictInput):
    original: str = Field(pattern=r"^CEA-[a-f0-9]{32}\|[a-f0-9]{32}$")


def selected(selection):
    if type(selection) is not dict or set(selection) != {"kind", "id"} or selection.get("kind") != "commitment_review" or not re_parent(selection.get("id")):
        raise HTTPException(409, "Open the owned Promise review you want to compare.")
    return selection["id"]


def re_parent(value):
    import re
    return type(value) is str and re.fullmatch(r"CMV-[a-f0-9]{48}", value) is not None


def _date(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.timestamp()
    except (ValueError, AttributeError) as exc:
        raise HTTPException(422, "Enter a complete future date including its time zone.") from exc


def _model(arguments, source):
    keys = ("currency", "unit_scale", "shared_cost", "maximum_outlay", "all_costs_included", "allowed", "basis")
    model = {**{key: arguments[key] for key in keys}, "expires_at": _date(arguments["expires_at"])}
    for kind, name, bound in (("offer", "offers", 4), ("addition", "additions", 6)):
        rows = source["qualification_review"]["model"][name]
        result = []
        for index in range(1, bound + 1):
            fields = ("unit_price", "unit_cost", "fixed_cost", "allowed", "basis", "expires_at") if kind == "offer" else ("cost", "allowed", "basis", "expires_at")
            values = {key: arguments[kind + "_" + str(index) + "_" + key] for key in fields}
            if index > len(rows):
                if any(value is not None for value in values.values()):
                    raise HTTPException(422, "An entered financial row has no current offer or addition; nothing was dropped.")
                continue
            if any(value is None for value in values.values()):
                raise HTTPException(422, "Enter every price, cost and permission for each displayed current row.")
            values["expires_at"] = _date(values["expires_at"])
            result.append({"id": rows[index - 1]["id"], **values})
        model[name] = result
    return model


def _fields(action, request, value):
    if action == "original":
        return [{"name": "original", "label": "Your exact earlier request", "kind": "select", "required": True, "choices": native.history(request)["choices"]}]
    if action == "acknowledge":
        return [{"name": "acknowledge_unknown", "label": "The earlier original remains unknown and its comparison allowance stays spent", "kind": "boolean", "required": True}]
    if action not in {"create", "edit", "scope"}:
        return []
    fields = [{"name": key, "label": label, "kind": kind, "required": True} for key, label, kind in (
        ("allowed", "I have current permission to use these facts", "boolean"), ("basis", "Complete use-permission basis", "textarea"), ("expires_at", "Review use permission again by", "datetime-local"))]
    if action == "scope":
        return fields
    fields.extend([{"name": "currency", "label": "Single three-letter currency, for example USD", "kind": "text", "required": True},
        {"name": "unit_scale", "label": "Unit for every monetary amount", "kind": "select", "required": True,
            "choices": [{"value": 1, "label": "Whole currency amounts"}, {"value": 100, "label": "Currency amounts with up to two decimal places"}]}])
    fields.extend({"name": key, "label": label, "kind": kind, "required": True} for key, label, kind in (
        ("shared_cost", "All shared incremental costs", "text"), ("maximum_outlay", "Maximum total incremental outlay", "text"),
        ("all_costs_included", "I included every incremental expense without double counting", "boolean")))
    for kind, name in (("offer", "offers"), ("addition", "additions")):
        for index, row in enumerate(value["source"]["qualification_review"]["model"][name], 1):
            names = (("unit_price", "Reported price per work unit", "text"), ("unit_cost", "All variable cost per work unit", "text"), ("fixed_cost", "All fixed incremental cost for this offer", "text")) if kind == "offer" else (("cost", "All-in monetary cost for this addition", "text"),)
            names += (("allowed", "Current demand and cost-use permission" if kind == "offer" else "Current cost-use permission", "boolean"),
                ("basis", "Reported facts and permission basis", "textarea"), ("expires_at", "Review these facts again by", "datetime-local"))
            fields.extend({"name": kind + "_" + str(index) + "_" + key, "label": row["label"] + " · " + label, "kind": field_kind, "required": True} for key, label, field_kind in names)
    if action == "edit":
        fields.append({"name": "acknowledge_new_intent", "label": "Changed financial assumptions are a separate intent; earlier originals and spent allowance remain", "kind": "boolean", "required": True})
    return fields


def snapshot(request, selection, *, action):
    value = native.history(request) if action in {"history", "original"} else native.view(request, selected(selection))
    return Snapshot(digest(value), "Owned Promise, additional-work sources and exact financial assumptions", native.NOTICE,
        fields=_fields(action, request, value))


def prepare(request, selection, arguments, *, action):
    if action == "history":
        return Preview("Original history only; no calculation repeats.", native=native.history(request))
    if action == "original":
        identifier, operation = arguments["original"].split("|")
        return Preview("Read the exact original attribution only.", native=native.original(request, identifier, operation))
    parent = selected(selection)
    if action == "author":
        return Preview("Open the complete ordinary financial form, preserving its entered draft. Nothing is saved or calculated.",
            native={"commitment_economic_author": native.author_handoff(request, parent)})
    if action == "read":
        value = native.view(request, parent)
        return Preview(native.NOTICE, native={"current": value["current"], "remaining_checks": value["remaining_checks"], "result": value["result"],
            "open": {"href": PAGE + "?review=" + parent + "#cea-panel", "label": "Open full conditional comparison"}})
    if action in {"create", "edit"}:
        value = native.view(request, parent)
        arguments = {"model": _model(arguments, value["source"]), **({"acknowledge_new_intent": arguments["acknowledge_new_intent"]} if action == "edit" else {})}
    elif action == "scope":
        arguments = {**arguments, "expires_at": _date(arguments["expires_at"])}
    prepared = native.prepare(request, parent, action, arguments)
    return Preview(native.NOTICE, native.changes(prepared), prepared)


def outcome(value):
    return Outcome("confirmed" if value["confirmed"] else "unconfirmed", value["message"], {"original_result": value["receipt"]})


def execute(request, _selection, _arguments, prepared, operation):
    return outcome(native.apply(request, prepared, operation))


def recover(request, _selection, _arguments, prepared, operation):
    value = native.recover(request, prepared, operation)
    return outcome(value) if value else None


def entries():
    common = {"family": "commitments", "pages": (PAGE,), "direct_ui": PAGE}
    writes = tuple(Adapter("commitments.economics." + action, label, input_model=model, snapshot=partial(snapshot, action=action),
        prepare=partial(prepare, action=action), execute=execute, recover=recover, read_recovery=recover, **common) for action, label, model in (
            ("create", "Enter complete conditional financial assumptions", FactsInput), ("edit", "Replace conditional financial assumptions", FactsInput),
            ("check", "Compare jointly feasible conditional contributions", EmptyInput), ("scope", "Review financial use permission", ScopeInput),
            ("withdraw", "Withdraw financial fact use", EmptyInput), ("acknowledge", "Stop waiting for an unknown financial original", AcknowledgeInput),
            ("remove", "Remove the current financial comparison", EmptyInput)))
    readers = tuple(Adapter("commitments.economics." + action, label, input_model=model, snapshot=partial(snapshot, action=action),
        prepare=partial(prepare, action=action), **common) for action, label, model in (
            ("read", "Read current conditional alternatives", EmptyInput), ("history", "Read earlier financial requests", EmptyInput),
            ("original", "Read the exact original financial result", OriginalInput), ("author", "Open all financial comparison choices", EmptyInput)))
    return writes + readers
