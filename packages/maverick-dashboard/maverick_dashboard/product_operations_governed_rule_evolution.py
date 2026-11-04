"""Typed controls share the complete native rule and publication writer."""
from __future__ import annotations

from datetime import datetime
from functools import partial

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import governed_rule_evolution as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class CreateInput(StrictInput):
    fault_limit: int = Field(ge=1, le=8)
    allowed: bool
    allow_independent_artifact: bool
    purpose: str = Field(min_length=10, max_length=2000)
    expires_at: str = Field(min_length=1, max_length=64)
    time_limit_seconds: int = Field(ge=15, le=120)


class ReviewInput(StrictInput):
    review: str = Field(pattern=r"^GRE-[a-f0-9]{32}$")


class PermissionInput(ReviewInput):
    allowed: bool
    allow_independent_artifact: bool
    purpose: str = Field(min_length=10, max_length=2000)
    expires_at: str = Field(min_length=1, max_length=64)
    time_limit_seconds: int = Field(ge=15, le=120)


class ActivateInput(ReviewInput):
    alternative: str = Field(pattern=r"^(tree|direct)$")
    independent_acceptance: bool


class EvaluatorInput(ReviewInput):
    checking_order: str = Field(pattern=r"^(ordinary|evolved)$")
    independent_acceptance: bool


class AcknowledgeInput(ReviewInput):
    acknowledge_unknown: bool


class ReconcileInput(PermissionInput):
    acknowledge_unknown: bool


class OriginalInput(StrictInput):
    original: str = Field(pattern=r"^GRE-[a-f0-9]{32}\|[a-f0-9]{32}$")


def selected(selection):
    if type(selection) is not dict or set(selection) != {"kind", "id"} or selection["kind"] != "flow" or type(selection["id"]) is not str or not 1 <= len(selection["id"]) <= 256:
        raise HTTPException(409, "Choose one currently owned saved workflow in Rewrite and check rules.")
    return selection["id"]


def _date(value):
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if date.tzinfo is None:
            raise ValueError
        return date.timestamp()
    except (ValueError, AttributeError) as exc:
        raise HTTPException(422, "Enter the complete permission review date including its time zone.") from exc


def _permission_fields():
    return [{"name": key, "label": label, "kind": kind, "required": True} for key, label, kind in (
        ("allowed", "I have current permission to use every displayed source and answer", "boolean"),
        ("allow_independent_artifact", "Permit independently accepted owned rules and checking plans", "boolean"),
        ("purpose", "Complete source and rule-creation use purpose", "textarea"), ("expires_at", "Review this permission again by", "datetime-local"))] + [{"name": "time_limit_seconds", "label": "Shared total checking time allowance", "kind": "select", "required": True,
        "choices": [{"value": value, "label": label} for value, label in ((15, "Fifteen seconds"), (60, "One minute"), (120, "Two minutes"))]}]


def fields(request, selection, action):
    if action == "original":
        return [{"name": "original", "label": "Your exact earlier request", "kind": "select", "required": True, "choices": native.history(request)["choices"]}]
    if action in {"history", "author"}:
        return []
    if action == "create":
        return [{"name": "fault_limit", "label": "Declared wrong-answer variants, no more than the entered situations", "kind": "number", "required": True}] + _permission_fields()
    rows = [{"name": "review", "label": "Your retained rule review", "kind": "select", "required": True,
        "choices": [row for row in native.history(request)["reviews"] if row["flow"] == selected(selection)]}]
    if action in {"scope", "reconcile"}:
        rows += _permission_fields()
    if action == "activate":
        rows += [{"name": "alternative", "label": "Complete independently checked rule alternative", "kind": "select", "required": True,
            "choices": [{"value": "tree", "label": "Checked decision routes"}, {"value": "direct", "label": "Direct choice for each entered situation, one-input rules only"}]}]
    if action == "evaluator":
        rows += [{"name": "checking_order", "label": "Complete checking order to use", "kind": "select", "required": True,
            "choices": [{"value": "ordinary", "label": "Every situation in entered order"}, {"value": "evolved", "label": "Reordered known counterexample checks, then every remaining situation"}]}]
    if action in {"activate", "evaluator"}:
        rows += [{"name": "independent_acceptance", "label": "I independently accept every complete displayed change and its consequences", "kind": "boolean", "required": True}]
    if action in {"acknowledge", "reconcile"}:
        rows += [{"name": "acknowledge_unknown", "label": "The earlier effect may already exist; its original remains unknown and its allowance stays spent", "kind": "boolean", "required": True}]
    return rows


def snapshot(request, selection, *, action):
    value = native.history(request) if action in {"history", "original", *native.MANAGEMENT} else native.listing(request, selected(selection))
    return Snapshot(digest(value), "Current owned rule source, complete checks and original custody", native.NOTICE, fields=fields(request, selection, action))


def prepare(request, selection, arguments, *, action):
    if action == "history":
        history = native.history(request)
        return Preview("Your own original history only; no checking work repeats.", native={"Your exact earlier requests": "\n".join(row["label"] for row in history["choices"]) or "No earlier requests"})
    if action == "original":
        identifier, operation = arguments["original"].split("|")
        return Preview("Read this exact original attribution only.", native={"Exact original result": native.original_report(native.original(request, identifier, operation))})
    flow_id = selected(selection)
    if action == "author":
        return Preview("Open the complete ordinary source and publication form, preserving its entered draft. Nothing is saved or checked.",
            native={"governed_rule_evolution_author": native.author_handoff(request, flow_id)})
    arguments = dict(arguments)
    identifier = arguments.pop("review", "")
    if action == "read":
        value = native.view(request, identifier)
        return Preview(native.NOTICE, native={"current_rule_review": native.report(value)})
    if "expires_at" in arguments:
        arguments["expires_at"] = _date(arguments["expires_at"])
    prepared = native.prepare(request, flow_id, identifier, action, arguments)
    return Preview(native.NOTICE, native.changes(prepared), prepared)


def outcome(value):
    return Outcome("confirmed" if value["confirmed"] else "unconfirmed", value["message"], {"Exact original result": native.original_report(value)})


def execute(request, _selection, _arguments, prepared, operation):
    return outcome(native.apply(request, prepared, operation))


def recover(request, _selection, _arguments, prepared, operation):
    value = native.recover(request, prepared, operation)
    return outcome(value) if value else None


def entries():
    common = {"family": "learning", "pages": (native.PAGE,), "direct_ui": native.PAGE}
    writes = tuple(Adapter("learning.rule_evolution." + action, label, input_model=model, snapshot=partial(snapshot, action=action),
        prepare=partial(prepare, action=action), execute=execute, recover=recover, read_recovery=recover, **common) for action, label, model in (
        ("create", "Enter the complete rule source and permission", CreateInput), ("build", "Build and check every rule alternative", ReviewInput),
        ("activate", "Independently accept and publish the checked rules", ActivateInput), ("check", "Check every situation of the active rules", ReviewInput),
        ("evaluator", "Independently accept a complete checking order", EvaluatorInput), ("restore", "Restore the exact previous publication", ReviewInput),
        ("scope", "Review current complete source permission", PermissionInput), ("reconcile", "Review a separate complete current state after unknown work", ReconcileInput),
        ("withdraw", "Withdraw future rule evolution use", ReviewInput), ("acknowledge", "Stop waiting for an unknown original", AcknowledgeInput),
        ("remove", "Remove the current rule review", ReviewInput)))
    readers = tuple(Adapter("learning.rule_evolution." + action, label, input_model=model, snapshot=partial(snapshot, action=action),
        prepare=partial(prepare, action=action), **common) for action, label, model in (
        ("read", "Read the complete current rules and checking evidence", ReviewInput), ("history", "Read your earlier rule requests", EmptyInput),
        ("original", "Read the exact original rule result", OriginalInput), ("author", "Open all rule evolution controls", EmptyInput)))
    return writes + readers
