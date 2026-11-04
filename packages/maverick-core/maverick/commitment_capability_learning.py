"""Bounded capability-model elimination and joint conditional additions.

This is ordinary finite version-space learning plus exhaustive abduction. It
does not establish physical availability, permission, revenue or a research
advantage. Every offer is an inquiry; accepted commitments remain unchanged.
"""
from __future__ import annotations

import itertools
from collections.abc import Mapping
from dataclasses import replace

from .budget import Budget
from .commitment_viability import (
    Commitment,
    Demand,
    Evidence,
    Lot,
    Snapshot,
    _effective_demands,
    assess,
)
from .governed_operations import digest

SCHEMA = "lightwork.commitment-capability.v1"
INPUTS = ("quantity", "offers", "material", "capacity")


def validate(model: dict) -> None:
    if type(model) is not dict or set(model) != {"offers", "requirements", "additions", "max_addition_cost", "test_limit", "test_effort", "test_cost", "expires_at", "basis"}:
        raise ValueError("Enter a complete additional-work review.")
    if type(model["offers"]) is not list or not 1 <= len(model["offers"]) <= 4:
        raise ValueError("Enter one to four additional offers.")
    due = None
    for row in model["offers"]:
        if type(row) is not dict or set(row) != {"id", "label", "units", "due_at"}:
            raise ValueError("Enter each complete additional offer.")
        _name(row["id"])
        _text(row["label"], 1, 200)
        _integer(row["units"], 1, 1000)
        _time(row["due_at"])
        if due is not None and row["due_at"] != due:
            raise ValueError("This bounded review supports additional offers due together.")
        due = row["due_at"]
    if len({row["id"] for row in model["offers"]}) != len(model["offers"]):
        raise ValueError("Additional offers need distinct identities.")
    requirements = model["requirements"]
    if type(requirements) is not dict or set(requirements) != {"material_per_unit", "capacity_per_unit", "shared_setup"}:
        raise ValueError("Enter competing material, capacity and shared-setup requirements.")
    for key, values in requirements.items():
        if type(values) is not list or not 1 <= len(values) <= 3 or len(set(values)) != len(values):
            raise ValueError("Enter one to three distinct possibilities for each requirement.")
        for value in values:
            _integer(value, 0 if key == "shared_setup" else 1, 100)
    if type(model["additions"]) is not list or not 1 <= len(model["additions"]) <= 6:
        raise ValueError("Enter one to six possible additions.")
    for row in model["additions"]:
        if type(row) is not dict or set(row) != {"id", "label", "kind", "units", "ready_at", "cost", "basis"}:
            raise ValueError("Enter every addition's quantity, timing, cost and reported availability basis.")
        _name(row["id"])
        _text(row["label"], 1, 200)
        _text(row["basis"], 10, 2000)
        if row["kind"] not in {"material", "capacity"}:
            raise ValueError("Choose material or work capacity.")
        _integer(row["units"], 1, 100000)
        _integer(row["cost"], 0, 100000)
        _time(row["ready_at"])
    if len({row["id"] for row in model["additions"]}) != len(model["additions"]):
        raise ValueError("Additions need distinct identities.")
    for key, lower, upper in (("max_addition_cost", 0, 100000), ("test_limit", 0, 8), ("test_effort", 0, 8000), ("test_cost", 1, 1000)):
        _integer(model[key], lower, upper)
    _time(model["expires_at"])
    _text(model["basis"], 10, 2000)


def _integer(value, lower, upper):
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError("Enter whole quantities within the displayed limits.")


def _text(value, lower, upper):
    if type(value) is not str or not lower <= len(value.strip()) <= upper:
        raise ValueError("Enter the complete bounded source description.")


def _name(value):
    import re
    if type(value) is not str or re.fullmatch(r"[a-z][a-z0-9-]{0,39}", value) is None:
        raise ValueError("Choose a supported named identity.")


def _time(value):
    import math
    if type(value) not in (float, int) or not math.isfinite(value) or value <= 0:
        raise ValueError("Enter a complete finite date.")


def models(model):
    fields = ("material_per_unit", "capacity_per_unit", "shared_setup")
    return [dict(zip(fields, values, strict=True)) for values in itertools.product(*(model["requirements"][key] for key in fields))]


def predicts(candidate, inputs):
    return (inputs["material"] >= candidate["material_per_unit"] * inputs["quantity"]
        and inputs["capacity"] >= candidate["capacity_per_unit"] * inputs["quantity"]
            + (candidate["shared_setup"] if inputs["offers"] > 1 else 0))


def current_observation(row, model, now):
    return (type(row) is dict and row.get("consent") is True and row.get("model") == digest(model)
        and type(row.get("outcome")) is bool and type(row.get("inputs")) is dict
        and set(row["inputs"]) == set(INPUTS)
        and all(type(row["inputs"][key]) is int and 0 <= row["inputs"][key] <= 2000000 for key in INPUTS)
        and 1 <= row["inputs"]["offers"] <= 4 and row["inputs"]["quantity"] >= row["inputs"]["offers"]
        and row.get("observed_at", now + 1) <= now < row.get("expires_at", 0)
        and row.get("source_current") is True)


def _subsets(rows, *, empty=False):
    for size in range(0 if empty else 1, len(rows) + 1):
        yield from itertools.combinations(rows, size)


def _spare(base, kind, due, revisions, now):
    """Largest consumption at due that preserves all accepted deadlines."""
    demands = _effective_demands(base)
    deadlines = sorted({due, *(item.due_at for item in base.commitments if item.due_at >= due)})
    key = "material" if kind == "material" else "work-center"
    return max(0, min(sum(lot.units for lot in base.lots if (lot.kind, lot.key) == (kind, key)
        and lot.certainty == "confirmed" and lot.ready_at <= deadline and lot.evidence.current(now, revisions))
        - sum(part.units for item in base.commitments if item.due_at <= deadline
            for part in demands[item.id] if (part.kind, part.key) == (kind, key)) for deadline in deadlines))


def _consistent_models(model, observations, budget):
    candidates = []
    for candidate in models(model):
        budget.check()
        consistent = True
        for row in observations:
            budget.check()
            if predicts(candidate, row["inputs"]) != row["outcome"]:
                consistent = False
                break
        if consistent:
            candidates.append(candidate)
    return candidates


def evaluate(base: Snapshot, revisions: Mapping[str, str], model: dict, observations: list[dict], *, now: float,
             consent: bool, tests_used: int = 0, effort_used: int = 0, budget: Budget | None = None):
    budget = budget or Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)
    budget.check()
    validate(model)
    if type(observations) is not list or len(observations) > 32:
        raise ValueError("This review supports at most thirty-two complete observations.")
    for value in (tests_used, effort_used):
        _integer(value, 0, 8000)
    accepted = assess(replace(base, options=()), now=now, current_source_revisions=revisions)
    live = [row for row in observations if current_observation(row, model, now)]
    candidates = _consistent_models(model, live, budget)
    remaining = {"tests": max(0, model["test_limit"] - tests_used), "effort_points": max(0, model["test_effort"] - effort_used)}
    result = {"accepted_state": accepted.status, "surviving_models": candidates, "current_observations": len(live),
        "allowance": remaining, "frontier": [], "already_supported": [], "next_test": None, "status": "unknown",
        "meaning": "Safe within the entered surviving models is conditional planning evidence. It does not verify stock, capacity, permission, purchase, fulfilment or revenue.",
        "comparison": {"method": "Complete exhaustive acquisition and addition enumeration on the same entered models, observations, sources and costs", "algorithm_advantage_claimed": False}}
    if (not consent or now >= model["expires_at"] or any(now >= row["due_at"] for row in model["offers"])
            or accepted.status != "feasible" or not candidates):
        result["reason"] = "Current source permission, accepted-work feasibility or a consistent current explanation is missing."
        return result
    due = model["offers"][0]["due_at"]
    vectors, frontier, already = {}, [], []
    for added in _subsets(model["additions"], empty=True):
        budget.check()
        cost = sum(row["cost"] for row in added)
        if cost > model["max_addition_cost"]:
            continue
        evidence = Evidence("n06-entered", digest(model), now, model["expires_at"])
        extra = tuple(Lot("n06-" + row["id"], row["kind"], "material" if row["kind"] == "material" else "work-center",
            row["units"], row["ready_at"], "confirmed", evidence) for row in added)
        extended = replace(base, lots=base.lots + extra, options=())
        current = dict(revisions, **{"n06-entered": digest(model)})
        # Proposed additions are hypothetically available here. Their operator
        # report and permission are separately displayed; this creates no lot.
        if assess(extended, now=now, current_source_revisions=current).status != "feasible":
            continue
        material, capacity = (_spare(extended, kind, due, current, now) for kind in ("material", "capacity"))
        for offers in _subsets(model["offers"]):
            budget.check()
            inputs = {"quantity": sum(row["units"] for row in offers), "offers": len(offers), "material": material, "capacity": capacity}
            answers = [predicts(candidate, inputs) for candidate in candidates]
            key = digest(inputs)
            vectors.setdefault(key, {"inputs": inputs, "offers": [row["id"] for row in offers], "additions": [row["id"] for row in added],
                "yes": sum(answers), "no": len(answers) - sum(answers), "cost": cost})
            if not all(answers):
                continue
            # Recheck joint fulfilment with N01's own deadline/resource engine.
            for candidate in candidates:
                budget.check()
                demands = []
                for kind, field, resource in (("material", "material_per_unit", "material"), ("capacity", "capacity_per_unit", "work-center")):
                    units = candidate[field] * inputs["quantity"] + (candidate["shared_setup"] if kind == "capacity" and len(offers) > 1 else 0)
                    demands.append(Demand(kind, resource, units))
                inquiry = Commitment("n06-inquiry", due, tuple(demands), evidence)
                if assess(replace(extended, commitments=base.commitments + (inquiry,)), now=now, current_source_revisions=current).status != "feasible":
                    raise ValueError("The complete accepted-work protection check disagreed; the result stays unknown.")
            item = {"offers": [row["id"] for row in offers], "additions": [row["id"] for row in added], "cost": cost,
                "quantity": inputs["quantity"], "safe_in_surviving_models": len(candidates), "business_verified": False}
            if not added:
                already.append(item)
                continue
            if any(row["offers"] == item["offers"] for row in already):
                continue
            # Inclusion minimal for these exact jointly offered inquiries.
            if not any(row["offers"] == item["offers"] and set(row["additions"]) <= set(item["additions"]) for row in frontier):
                frontier.append(item)
    result["frontier"] = frontier
    result["already_supported"] = already
    result["status"] = "conditional" if frontier or already else "unknown"
    unseen = [row for key, row in vectors.items() if not any(digest(old["inputs"]) == key for old in live) and row["yes"] and row["no"]]
    unseen.sort(key=lambda row: (-min(row["yes"], row["no"]), row["cost"], digest(row["inputs"])))
    if unseen and remaining["tests"] and remaining["effort_points"] >= model["test_cost"]:
        result["next_test"] = {**unseen[0], "effort_points": model["test_cost"],
            "objective": "Separate as many surviving entered explanations as possible in the less informative Yes/No outcome; then prefer lower declared addition cost.",
            "worst_case_models_eliminated": min(unseen[0]["yes"], unseen[0]["no"])}
    result["comparison"]["candidate_test_inputs"] = len(vectors)
    result["comparison"]["same_exhaustive_choice"] = result["next_test"]
    budget.check()
    return result
