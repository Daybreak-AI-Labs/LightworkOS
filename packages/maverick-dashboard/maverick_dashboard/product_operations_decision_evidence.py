"""Typed Copilot controls for the native finite shared-decision service."""
from __future__ import annotations

from datetime import datetime
from functools import partial

from fastapi import HTTPException
from maverick.governed_operations import digest
from maverick.shared_decision_evidence import all_states
from pydantic import Field

from . import shared_decision_evidence_store as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput

PAGE = "/decision-evidence"


class CreateInput(StrictInput):
    title: str = Field(min_length=1, max_length=200)
    source: str = Field(min_length=1, max_length=160)
    fact_meaning: str = Field(min_length=1, max_length=1000)
    available_units: int = Field(ge=1, le=1_000_000)
    order_a: str = Field(min_length=1, max_length=200)
    order_a_units: int = Field(ge=1, le=1_000_000)
    order_b: str = Field(min_length=1, max_length=200)
    order_b_units: int = Field(ge=1, le=1_000_000)
    due_at: str = Field(min_length=1, max_length=64)
    question_budget: int = Field(ge=0, le=100)
    effort_budget: int = Field(ge=0, le=10000)
    observation_cost: int = Field(ge=1, le=1000)
    fresh_hours: int = Field(ge=1, le=168)


class ScopeInput(StrictInput):
    fact: str = Field(min_length=1, max_length=120)
    cases: list[str] = Field(min_length=1, max_length=16)


class AnswerInput(StrictInput):
    request: str = Field(pattern=r"^[a-f0-9]{32}$")
    value: int = Field(ge=0, le=1_000_000)
    basis: str = Field(min_length=10, max_length=2000)


class FactInput(StrictInput):
    fact: str = Field(min_length=1, max_length=120)


class OriginalInput(StrictInput):
    original: str = Field(pattern=r"^SDE-[a-f0-9]{32}\|[a-f0-9]{32}$")


def selected(selection):
    if not isinstance(selection, dict) or set(selection) != {"kind", "id"} or selection.get("kind") != "decision_evidence":
        raise HTTPException(409, "Open one saved decision review first.")
    return selection["id"]


def create_model(arguments):
    try:
        due = datetime.fromisoformat(arguments["due_at"].replace("Z", "+00:00"))
        if due.tzinfo is None:
            raise ValueError
    except ValueError as exc:
        raise HTTPException(422, "Choose a valid decision date.") from exc
    fact = {"id": "capacity", "name": "Reported shared capacity", "meaning": arguments["fact_meaning"], "source": arguments["source"],
            "values": [0, arguments["available_units"]], "cost": arguments["observation_cost"], "fresh_hours": arguments["fresh_hours"]}
    cases = [{"id": key, "name": arguments[name], "due_at": due.timestamp(), "actions": [
        {"id": "proceed", "name": "Reported quantity meets this case's entered threshold", "conditions": [{"fact": "capacity", "operator": "at_least", "value": arguments[units]}]},
        {"id": "wait", "name": "No quantity is reported for this case", "conditions": [{"fact": "capacity", "operator": "equals", "value": 0}]}]}
        for key, name, units in (("order-a", "order_a", "order_a_units"), ("order-b", "order_b", "order_b_units"))]
    return {"title": arguments["title"], "facts": [fact], "cases": cases, "states": all_states([fact]),
            "question_budget": arguments["question_budget"], "effort_budget": arguments["effort_budget"]}


def customer_status(value):
    """Complete ordinary case projection; research comparison stays engineering evidence."""
    evaluation = value["evaluation"]
    if evaluation is None:
        return {"review": value["model"]["title"], "state": "Removed" if value["removed"] else "Original admission unconfirmed", "meaning": native.NOTICE}
    facts = {row["id"]: row for row in value["model"]["facts"]}
    cases = {row["id"]: row for row in value["model"]["cases"]}
    decisions = []
    for check in evaluation["certificates"]:
        case = cases[check["case"]]
        decision = {"case": case["name"], "state": ("Reported facts support this choice" if check["observed_subset"] else "Entered situations support this choice")
            if check["status"] == "model_sufficient" else "Unknown"}
        if check["status"] == "model_sufficient":
            decision.update(choice=next(row["name"] for row in case["actions"] if row["id"] == check["action"]),
                information_needed=[facts[identity]["name"] for identity in check["observed_subset"]],
                source_permissions_needed=[facts[row["fact"]]["name"] for row in check["dependencies"]],
                recheck_before=datetime.fromtimestamp(check["decision_before"]).astimezone().isoformat())
        decisions.append(decision)
    selected = evaluation["acquisition"]["selected"]
    result = {"review": value["model"]["title"], "cases": decisions,
        "next_information": {"fact": facts[selected["fact"]]["name"], "cases_supported_in_least_helpful_entered_outcome": selected["worst_case_new_cases"],
            "effort_points": selected["cost"]} if selected else "No useful next question within the current permission and allowance",
        "remaining_shared_allowance": evaluation["budget"], "possible_situations_entered": evaluation["states"], "meaning": native.NOTICE,
        "complete_native_review": {"href": PAGE + "?review=" + value["id"], "label": "Open all entered situations, losses and current source permissions"}}
    if "robust" in value["model"]:
        result.pop("cases")
        result.pop("next_information")
        result.update(_robust_status(value, facts, cases))
    return result


def _robust_status(value, facts, cases):
    evaluation, model = value["evaluation"], value["model"]
    robust = evaluation["robust"]
    checks = []
    for row in robust["cases"]:
        case = cases[row["case"]]
        choices = [action["name"] for action in case["actions"] if action["id"] in row["choices"]]
        checks.append(case["name"] + ": " + ("Supported entered choices: " + "; ".join(choices) if choices else "Unknown. " + row["reason"]))
    batch = robust.get("batch")
    return {"entered_loss_check": "\n".join(checks) or robust.get("reason", "A complete current check is needed."),
        "observation_batch": ("; ".join(facts[key]["name"] for key in batch["facts"]) + "; cost " + batch["cost"] + " " + model["robust"]["unit"]
            if batch and batch["facts"] else "No additional observation is needed for the checked entered choices." if batch else "Unknown; no sufficient batch within current permissions and allowances."),
        "earlier_observation_costs": evaluation["cost_used"] + " " + model["robust"]["unit"],
        "complete_checks_used": str(evaluation["checks_used"]) + " of " + str(evaluation["check_limit"]),
        "extra_loss_allowed": model["robust"]["epsilon"] + " " + model["robust"]["unit"],
        "unconfirmed_check": "Read the earlier original, then separately acknowledge its hold; the allowance stays spent." if evaluation["check_hold"] else "None"}


def snapshot(request, selection, *, action):
    if action == "author":
        identifier = selected(selection) if selection else ""
        value = native.author_handoff(request, identifier)
        return Snapshot(digest(value), "Your current account, workspace and complete decision form", "Open all bounded fields without replacing entered work.")
    if action == "original":
        history = native.historical_requests(request)
        return Snapshot(digest(history), "Your own exact original requests in this workspace", "Reading history does not repeat a reviewed change or reserve another observation.",
            fields=[{"name": "original", "label": "Original reviewed request", "kind": "select", "required": True, "choices": history["choices"]}])
    if action == "create":
        _actor, context = native.authority(request)
        return Snapshot(digest(context), "Your account, workspace and review limits", native.NOTICE,
            fields=[{"name": key, "label": label, "kind": kind, "required": True} for key, label, kind in (
                ("title", "Review name", "text"), ("source", "Who supplies this capacity report", "text"),
                ("fact_meaning", "Exact meaning and scope of this capacity", "textarea"), ("available_units", "Possible available units (or zero)", "number"),
                ("order_a", "First case", "text"), ("order_a_units", "Required quantity for the first case", "number"),
                ("order_b", "Second case", "text"), ("order_b_units", "Required quantity for the second case", "number"),
                ("due_at", "Decide before", "datetime-local"), ("question_budget", "Global question limit", "number"),
                ("effort_budget", "Global effort-point limit", "number"), ("observation_cost", "Effort points per capacity report", "number"),
                ("fresh_hours", "Review source again after how many hours", "number"))])
    value = native.view(request, selected(selection))
    fields = []
    if action in {"consent", "withdraw", "refresh"}:
        fields = [{"name": "fact", "label": "Exact fact", "kind": "select", "required": True,
            "choices": [{"value": item["id"], "label": item["name"]} for item in value["model"]["facts"]]},
            {"name": "cases", "label": "Cases allowed to use this fact" if action == "consent" else "Cases whose permission to use this fact ends",
             "kind": "multiselect", "required": True, "choices": [{"value": item["id"], "label": item["name"]} for item in value["model"]["cases"]]}]
        if action == "refresh":
            fields = fields[:1]
    elif action == "answer":
        fields = [{"name": "request", "label": "Original observation request", "kind": "select", "required": True,
            "choices": [{"value": key, "label": value["model"]["title"] + " · " + next(f["name"] for f in value["model"]["facts"] if f["id"] == row["fact"])}
                        for key, row in value["pending"].items() if row["state"] == "awaiting_observation"]},
            {"name": "value", "label": "Reported possible quantity", "kind": "number", "required": True},
            {"name": "basis", "label": "Basis for your operator report", "kind": "textarea", "required": True}]
    evaluation = {key: child for key, child in (value["evaluation"] or {}).items() if key != "evaluated_at"}
    return Snapshot(digest([value["revision"], evaluation]), "Current choices, source permissions and expiry, and shared allowance", native.NOTICE,
        details=customer_status(value), fields=fields,
        blocked="This review was removed." if value["removed"] else "The original admission is unconfirmed. Read its original result and prepare a separate new decision review." if value["unconfirmed_admission"] else "")


def prepare(request, selection, arguments, *, action):
    if action == "author":
        identifier = selected(selection) if selection else ""
        return Preview("Open the complete decision form. This does not save, check losses, reserve observations or replace entered work.",
            native={"decision_evidence_author": native.author_handoff(request, identifier)})
    if action == "original":
        identifier, operation = arguments["original"].split("|")
        return Preview("This is the original recorded result, not permission to repeat it.", native=native.original(request, identifier, operation))
    if action == "read":
        return Preview(native.NOTICE, native=customer_status(native.view(request, selected(selection))))
    value = native.prepare(request, action, create_model(arguments) if action == "create" else arguments,
                           None if action == "create" else selected(selection))
    return Preview("Review all entered choices and this exact change. Reports remain operator assertions and no business action will execute.", native.review_changes(value), value)


def outcome(value):
    return Outcome("confirmed" if value["confirmed"] else "unconfirmed", value["message"],
                   {"original_result": value["receipt"], "open": {"href": PAGE + "?review=" + value["id"], "label": "Open this decision review"}})


def execute(request, _selection, _arguments, prepared, operation):
    return outcome(native.apply(request, prepared, operation))


def recover(request, _selection, _arguments, prepared, operation):
    value = native.recover(request, prepared, operation)
    return outcome(value) if value and value["receipt"] else None


def entries():
    common = {"family": "commitments", "pages": (PAGE,), "direct_ui": PAGE}
    values = tuple(Adapter("decisions." + action, label, input_model=model,
        snapshot=partial(snapshot, action=action), prepare=partial(prepare, action=action), execute=execute,
        recover=recover, read_recovery=recover, **common) for action, label, model in (
            ("create", "Create a decision review for two cases", CreateInput), ("consent", "Allow a fact to support selected cases", ScopeInput),
            ("withdraw", "Withdraw a fact from selected cases", ScopeInput), ("acquire", "Reserve one shared observation under the budget", EmptyInput),
            ("refresh", "Review a source again and clear its previous observation", FactInput),
            ("answer", "Record an operator observation", AnswerInput), ("remove", "Remove this decision review", EmptyInput)))
    values += tuple(Adapter("decisions." + action, label, input_model=EmptyInput,
        snapshot=partial(snapshot, action=action), prepare=partial(prepare, action=action), execute=execute,
        recover=recover, read_recovery=recover, **common) for action, label in (
            ("qualify", "Check every entered loss and joint observation answer"),
            ("acquire_batch", "Reserve the complete checked observation batch"),
            ("acknowledge", "Acknowledge an unconfirmed check without repeating it")))
    return values + (Adapter("decisions.read", "Read current choices and useful information", input_model=EmptyInput,
        snapshot=partial(snapshot, action="read"), prepare=partial(prepare, action="read"), **common),
        Adapter("decisions.original", "Read your exact original decision request", input_model=OriginalInput,
        snapshot=partial(snapshot, action="original"), prepare=partial(prepare, action="original"), **common),
        Adapter("decisions.author", "Open the complete decision form", input_model=EmptyInput,
            snapshot=partial(snapshot, action="author"), prepare=partial(prepare, action="author"), **common))
