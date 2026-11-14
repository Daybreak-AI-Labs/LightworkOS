"""Finite conditional opportunity construction; reported economics are not sales.

This is exhaustive abduction and integer accounting, compared with a complete
native feasibility reference on the same information. No research advantage is
claimed and no hypothetical lot or inquiry is written to the business store.
"""
from __future__ import annotations

import itertools
import math
import re
from dataclasses import replace

from .budget import Budget
from .commitment_capability_learning import (
    _consistent_models,
    _spare,
    current_observation,
    predicts,
)
from .commitment_capability_learning import validate as validate_capability
from .commitment_viability import Commitment, Demand, Evidence, Lot, assess
from .governed_operations import digest

SCHEMA = "lightwork.commitment-economic-alternatives.v1"
MAX_MONEY = 10**12


def _amount(value, maximum=MAX_MONEY):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("Enter a nonnegative whole monetary amount in the selected unit; fractions and floats are unsupported.")


def _permission(row):
    if type(row["allowed"]) is not bool or type(row["basis"]) is not str or not 10 <= len(row["basis"].strip()) <= 2000:
        raise ValueError("Enter current permission and the complete reported demand or cost basis.")
    value = row["expires_at"]
    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
        raise ValueError("Enter a finite source-permission review date.")


def validate(model, capability):
    validate_capability(capability)
    if type(model) is not dict or set(model) != {"currency", "unit_scale", "offers", "additions", "shared_cost", "maximum_outlay", "all_costs_included", "allowed", "basis", "expires_at"}:
        raise ValueError("Enter the complete financial assumptions and source permission.")
    if type(model["currency"]) is not str or re.fullmatch(r"[A-Z]{3}", model["currency"]) is None or type(model["unit_scale"]) is not int or model["unit_scale"] not in {1, 100}:
        raise ValueError("Choose one three-letter currency and whole units or hundredths for every amount.")
    if type(model["all_costs_included"]) is not bool:
        raise ValueError("Explicitly state whether every incremental cost is included.")
    _permission(model)
    _amount(model["shared_cost"])
    _amount(model["maximum_outlay"], 10**15)
    for name, fields in (("offers", {"id", "unit_price", "unit_cost", "fixed_cost", "allowed", "basis", "expires_at"}),
                         ("additions", {"id", "cost", "allowed", "basis", "expires_at"})):
        rows = model[name]
        if type(rows) is not list or len(rows) != len(capability[name]):
            raise ValueError("Enter every current offer and possible addition; none may be dropped from the review.")
        if any(type(row) is not dict or set(row) != fields or type(row["id"]) is not str for row in rows):
            raise ValueError("Enter every supported financial and permission field.")
        if {row["id"] for row in rows} != {row["id"] for row in capability[name]} or len({row["id"] for row in rows}) != len(rows):
            raise ValueError("Use each current offer and addition exactly once.")
        for row in rows:
            _permission(row)
            for key in ("unit_price", "unit_cost", "fixed_cost") if name == "offers" else ("cost",):
                _amount(row[key])


def permission_current(model, now):
    return model["all_costs_included"] and all(row["allowed"] and now < row["expires_at"]
        for row in (model, *model["offers"], *model["additions"]))


def _sets(rows, *, empty=False):
    for size in range(0 if empty else 1, len(rows) + 1):
        yield from itertools.combinations(rows, size)


def _extended(base, added, model, now, revisions):
    evidence = Evidence("p12-entered", digest(model), now, model["expires_at"])
    lots = tuple(Lot("p12-" + row["id"], row["kind"], "material" if row["kind"] == "material" else "work-center",
        row["units"], row["ready_at"], "confirmed", evidence) for row in added)
    return replace(base, lots=base.lots + lots, options=()), dict(revisions, **{"p12-entered": digest(model)}), evidence


def _native_feasible(base, current, evidence, offers, candidate, now, budget):
    budget.check()
    units = sum(row["units"] for row in offers)
    inquiry = Commitment("p12-inquiry", offers[0]["due_at"], (
        Demand("material", "material", candidate["material_per_unit"] * units),
        Demand("capacity", "work-center", candidate["capacity_per_unit"] * units + (candidate["shared_setup"] if len(offers) > 1 else 0))), evidence)
    result = assess(replace(base, commitments=base.commitments + (inquiry,)), now=now, current_source_revisions=current)
    budget.check()
    return result.status == "feasible"


def _candidate_sets(base, revisions, capability, candidates, now, budget, *, reference):
    found = set()
    for added in _sets(capability["additions"], empty=True):
        budget.check()
        if sum(row["cost"] for row in added) > capability["max_addition_cost"]:
            continue
        extended, current, evidence = _extended(base, added, capability, now, revisions)
        if assess(extended, now=now, current_source_revisions=current).status != "feasible":
            continue
        spare = None if reference else {kind: _spare(extended, kind, capability["offers"][0]["due_at"], current, now) for kind in ("material", "capacity")}
        for offers in _sets(capability["offers"]):
            budget.check()
            if spare is not None:
                inputs = {"quantity": sum(row["units"] for row in offers), "offers": len(offers), **spare}
                if not all(predicts(candidate, inputs) for candidate in candidates):
                    continue
            if all(_native_feasible(extended, current, evidence, offers, candidate, now, budget) for candidate in candidates):
                found.add((tuple(row["id"] for row in offers), tuple(row["id"] for row in added)))
    return found


def _money(offers, additions, model, capability):
    offer_facts = {row["id"]: row for row in model["offers"]}
    addition_facts = {row["id"]: row for row in model["additions"]}
    offer_units = {row["id"]: row["units"] for row in capability["offers"]}
    rows = [{"offer": key, "units": offer_units[key], "unit_price": offer_facts[key]["unit_price"],
        "revenue": offer_units[key] * offer_facts[key]["unit_price"], "unit_cost": offer_facts[key]["unit_cost"],
        "variable_cost": offer_units[key] * offer_facts[key]["unit_cost"], "fixed_cost": offer_facts[key]["fixed_cost"]} for key in offers]
    additions_cost = [{"addition": key, "all_in_cost": addition_facts[key]["cost"]} for key in additions]
    revenue = sum(row["revenue"] for row in rows)
    costs = sum(row["variable_cost"] + row["fixed_cost"] for row in rows) + sum(row["all_in_cost"] for row in additions_cost) + model["shared_cost"]
    return {"offers": list(offers), "additions": list(additions), "offer_breakdown": rows, "addition_breakdown": additions_cost,
        "shared_cost": model["shared_cost"], "revenue": revenue, "total_cost": costs, "contribution": revenue - costs,
        "within_outlay": costs <= model["maximum_outlay"], "positive_contribution": revenue > costs,
        "currency": model["currency"], "unit_scale": model["unit_scale"], "business_verified": False}


def evaluate(base, revisions, capability, observations, model, *, now, consent, budget=None):
    budget = budget or Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)
    budget.check()
    validate(model, capability)
    if type(observations) is not list or len(observations) > 32:
        raise ValueError("The complete observation set exceeds thirty-two; none was omitted.")
    result = {"status": "unknown", "alternatives": [], "best_positive": None, "surviving_explanations": 0,
        "meaning": "Conditional contribution under entered prices, costs, permissions and surviving explanations; no actual demand, availability, fulfilment or revenue is verified.",
        "comparison": {"method": "Complete native feasibility enumeration on the same sources and monetary assumptions", "advantage_claimed": False}}
    if not consent or not permission_current(model, now) or now >= capability["expires_at"] or any(now >= row["due_at"] for row in capability["offers"]):
        result["reason"] = "Complete current source permission, costs or future offer dates are missing."
        return result
    if assess(replace(base, options=()), now=now, current_source_revisions=revisions).status != "feasible":
        result["reason"] = "All already accepted work is not currently confirmed feasible."
        return result
    live = [row for row in observations if current_observation(row, capability, now)]
    candidates = _consistent_models(capability, live, budget)
    result["surviving_explanations"] = len(candidates)
    if not candidates:
        result["reason"] = "No current explanation agrees with the retained observations."
        return result
    found = _candidate_sets(base, revisions, capability, candidates, now, budget, reference=False)
    reference = _candidate_sets(base, revisions, capability, candidates, now, budget, reference=True)
    if found != reference:
        raise ValueError("The independent complete feasibility reference disagreed. No alternative is qualified.")
    minimal = []
    for offers, additions in sorted(found, key=lambda item: (len(item[1]), item)):
        budget.check()
        if not any(old_offers == offers and set(old_additions) < set(additions) for old_offers, old_additions in found):
            minimal.append(_money(offers, additions, model, capability))
    minimal.sort(key=lambda row: (-row["contribution"], row["total_cost"], row["offers"], row["additions"]))
    result.update(status="conditional" if minimal else "unknown", alternatives=minimal,
        best_positive=next((row for row in minimal if row["within_outlay"] and row["positive_contribution"]), None))
    result["comparison"].update(complete_feasible_combinations=len(reference), same_complete_feasibility=True, inclusion_minimal_alternatives=len(minimal))
    budget.check()
    return result
