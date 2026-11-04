"""Bounded robust choices and exact sufficient observation batches.

Losses, possible situations and source reports are entered premises. This is
an exhaustive finite calculation, not independent business verification or a
claim of an advance over robust optimization and acquisition algorithms.
"""
from __future__ import annotations

import itertools
import re

from .budget import Budget, BudgetExceeded
from .governed_operations import digest

_AMOUNT = re.compile(r"(0|[1-9][0-9]{0,12})(?:\.([0-9]{1,2}))?\Z")
SECTION_KEYS = {"unit", "epsilon", "cost_budget", "observation_costs", "losses"}
MEANING = "The losses and possible situations are entered assumptions. A supported choice has no more than the entered extra loss in every remaining situation. No business action is carried out."


def amount(value):
    """Exact hundredths; neither JSON numbers nor floating-point are accepted."""
    match = _AMOUNT.fullmatch(value) if isinstance(value, str) else None
    if not match or int(match[1]) > 10**12:
        raise ValueError("Enter a nonnegative amount with at most two decimal places, up to 1000000000000.")
    return int(match[1]) * 100 + int((match[2] or "").ljust(2, "0"))


def decimal(value):
    return f"{value // 100}.{value % 100:02d}"


def validate_section(model, section, *, check=lambda: None):
    if not isinstance(section, dict) or set(section) != SECTION_KEYS:
        raise ValueError("Enter the complete loss and observation-cost table.")
    if not isinstance(section["unit"], str) or not section["unit"].strip() or len(section["unit"]) > 40:
        raise ValueError("Name one consistent unit for every loss and observation cost.")
    amount(section["epsilon"])
    amount(section["cost_budget"])
    facts = {fact["id"] for fact in model["facts"]}
    costs = section["observation_costs"]
    if not isinstance(costs, dict) or set(costs) != facts:
        raise ValueError("Enter the exact cost of observing every fact.")
    for cost in costs.values():
        check()
        amount(cost)
    cases = {case["id"]: case for case in model["cases"]}
    losses = section["losses"]
    if not isinstance(losses, dict) or set(losses) != set(cases):
        raise ValueError("Every case needs its complete entered loss table.")
    for identity, rows in losses.items():
        _validate_rows(model, cases[identity], rows, check)
    return section


def _validate_rows(model, case, rows, check):
    if not isinstance(rows, list) or len(rows) != len(model["states"]):
        raise ValueError("Enter losses for every retained possible situation; none can be dropped.")
    actions = {action["id"] for action in case["actions"]}
    for row in rows:
        check()
        if not isinstance(row, dict) or set(row) != actions:
            raise ValueError("Every possible situation needs a loss for every named choice.")
        for value in row.values():
            amount(value)


def binding(model, sources, pending, questions_used, effort_used, cost_used):
    return digest([model, sources, pending, questions_used, effort_used, cost_used])


class Calculation:
    def __init__(self, model, sources, now, *, questions_used, effort_used, cost_used, pending_facts, budget, guard):
        from .shared_decision_evidence import Solver
        self.budget = budget or Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)
        self.guard = guard
        self.check()
        self.model, self.sources, self.now = model, sources, now
        self.solver = Solver(model, sources, now, questions_used=questions_used, effort_used=effort_used, pending_facts=pending_facts)
        self.section = validate_section(model, model["robust"], check=self.check)
        self.epsilon = amount(self.section["epsilon"])
        self.cost_left = max(0, amount(self.section["cost_budget"]) - amount(cost_used))
        self.costs = {fact: amount(value) for fact, value in self.section["observation_costs"].items()}
        self.losses = {case: [{action: amount(value) for action, value in row.items()} for row in rows]
                       for case, rows in self.section["losses"].items()}
        self.case_worlds = {}
        self.safe_masks = {}

    def check(self):
        self.budget.check()
        if self.guard is not None:
            self.guard()
        self.budget.check()

    def _current(self, case):
        return self.now < case["due_at"] and all(self.solver.source_current(fact, case["id"]) for fact in self.solver.facts)

    def _bounds(self, case, worlds):
        identity = case["id"]
        rows, masks = [], {}
        indices = [index for index in range(len(self.model["states"])) if worlds & (1 << index)]
        best = {}
        for index in indices:
            self.check()
            feasible = [self.losses[identity][index][action["id"]] for action in case["actions"]
                        if self.solver.actions[(identity, action["id"])] & (1 << index)]
            if not feasible:
                return None, {}
            best[index] = min(feasible)
        for action in case["actions"]:
            self.check()
            key = action["id"]
            allowed = self.solver.actions[(identity, key)]
            masks[key] = sum(1 << index for index in indices if allowed & (1 << index)
                             and self.losses[identity][index][key] - best[index] <= self.epsilon)
            feasible_all = not worlds & ~allowed
            regrets = {index: self.losses[identity][index][key] - best[index] for index in indices if allowed & (1 << index)}
            rows.append({"action": key, "feasible_all": feasible_all,
                         "worst_case_loss": decimal(max(self.losses[identity][index][key] for index in indices)) if feasible_all else None,
                         "worst_case_regret": decimal(max(regrets.values())) if feasible_all else None,
                         "counterexample_states": [index for index in indices if not masks[key] & (1 << index)]})
        return rows, masks

    def cases(self):
        result = []
        for case in self.model["cases"]:
            self.check()
            identity = case["id"]
            worlds = self.solver.worlds(self.solver.observations(identity))
            reason = "Current permission and source review are needed for every fact used by the entered loss table."
            if self._current(case) and worlds:
                bounds, masks = self._bounds(case, worlds)
                if bounds is not None:
                    self.case_worlds[identity] = worlds
                    self.safe_masks[identity] = masks
                    choices = [action for action, mask in masks.items() if not worlds & ~mask]
                    result.append({"case": identity, "status": "supported" if choices else "unknown", "choices": choices,
                                   "remaining_states": worlds.bit_count(), "action_bounds": bounds,
                                   "reason": "Entered losses support these choices in all remaining situations." if choices else
                                   "No single choice stays within the entered extra-loss limit in all remaining situations."})
                    continue
                reason = "At least one entered possible situation has no feasible choice. Edit the complete assumptions; no situation was excluded automatically."
            elif not worlds:
                reason = "Current reports contradict every entered possible situation."
            result.append({"case": identity, "status": "unknown", "choices": [], "reason": reason})
        return result

    def _cells(self, facts, identity):
        cells = {}
        for index, state in enumerate(self.model["states"]):
            if self.case_worlds[identity] & (1 << index):
                values = tuple(state[fact] for fact in facts)
                cells[values] = cells.get(values, 0) | (1 << index)
        return cells

    def _batch(self, facts, *, reference=False):
        cells = {}
        for case in self.model["cases"]:
            self.check()
            identity = case["id"]
            for values, mask in self._cells(facts, identity).items():
                choices = self._reference_choices(case, mask) if reference else [action for action, safe in self.safe_masks[identity].items() if not mask & ~safe]
                if not choices:
                    return None
                cells.setdefault(values, []).append({"case": identity, "choices": choices, "remaining_states": mask.bit_count()})
        return [{"answers": dict(zip(facts, values, strict=True)), "cases": rows} for values, rows in sorted(cells.items())]

    def _reference_choices(self, case, mask):
        """Complete direct state/action enumeration, independent of regret masks."""
        from .shared_decision_evidence import _holds
        indices = [index for index in range(len(self.model["states"])) if mask & (1 << index)]
        choices = []
        for action in case["actions"]:
            good = True
            for index in indices:
                self.check()
                state, losses = self.model["states"][index], self.losses[case["id"]][index]
                feasible = [candidate for candidate in case["actions"] if all(_holds(condition, state) for condition in candidate["conditions"])]
                if (action not in feasible or not feasible or losses[action["id"]] - min(losses[candidate["id"]] for candidate in feasible) > self.epsilon):
                    good = False
                    break
            if good:
                choices.append(action["id"])
        return choices

    def batches(self):
        if len(self.case_worlds) != len(self.model["cases"]):
            return None, {"checked": False, "meaning": "Current source permissions, complete feasible situations and deadlines are required before observation planning."}
        eligible = sorted(fact for fact in self.solver.facts if fact not in self.solver.pending_facts
                          and self.sources[fact].get("value") is None)
        candidates = []
        for size in range(min(len(eligible), self.solver.questions_left) + 1):
            for facts in itertools.combinations(eligible, size):
                self.check()
                cost = sum(self.costs[fact] for fact in facts)
                effort = sum(self.solver.facts[fact]["cost"] for fact in facts)
                if cost <= self.cost_left and effort <= self.solver.effort_left:
                    candidates.append(((cost, size, effort, facts), facts))
        candidates.sort()
        chosen, strong = None, None
        for order, facts in candidates:
            self.check()
            cells = self._batch(facts)
            if cells is not None:
                chosen = self._selection(order, cells)
                break
        for order, facts in candidates:
            self.check()
            cells = self._batch(facts, reference=True)
            if cells is not None:
                strong = self._selection(order, cells)
                break
        if chosen != strong:
            raise ValueError("The complete independent observation check disagreed; no plan was accepted.")
        return chosen, {"checked": True, "same_selection_and_every_cell": True,
            "candidate_batches": len(candidates), "method": "Independent complete situation/action enumeration with the same information, permissions, costs and allowance.",
            "claim": "Agreement establishes this bounded calculation, not novelty, superiority or business truth."}

    def _selection(self, order, cells):
        cost, questions, effort, facts = order
        return {"facts": list(facts), "cost": decimal(cost), "questions": questions, "effort_points": effort, "cells": cells}


def evaluate(model, sources, now, *, questions_used=0, effort_used=0, cost_used="0.00", pending_facts=(), budget=None, guard=None):
    try:
        calculation = Calculation(model, sources, now, questions_used=questions_used, effort_used=effort_used,
            cost_used=cost_used, pending_facts=pending_facts, budget=budget, guard=guard)
        cases = calculation.cases()
        selected, reference = calculation.batches()
        calculation.check()
        return {"status": "checked", "meaning": MEANING, "unit": calculation.section["unit"], "epsilon": decimal(calculation.epsilon),
                "cases": cases, "batch": selected, "reference": reference, "business_verified": False,
                "checked_before": min([case["due_at"] for case in model["cases"]] + [source["expires_at"] for source in sources.values()]),
                "budget": {"questions_left": calculation.solver.questions_left, "effort_points_left": calculation.solver.effort_left,
                           "cost_left": decimal(calculation.cost_left)},
                "objective": "Find the least entered observation cost whose every possible joint answer supports a choice within the extra-loss limit for every case; break ties by fewer questions, lower effort, then fact identity."}
    except BudgetExceeded:
        return {"status": "unknown", "meaning": MEANING, "reason": "The shared local calculation allowance was exhausted. No previous answer or partial observation plan is a current checked result.",
                "cases": [], "batch": None, "reference": {"checked": False}, "business_verified": False}
