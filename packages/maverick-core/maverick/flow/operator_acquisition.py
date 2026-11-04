"""Complete bounded question policies over actual retained teaching candidates.

Reported effort is an estimate, not independent business truth. The strong
reference uses exactly the same information; agreement is not a novelty claim.
"""
from __future__ import annotations

import copy
import itertools
import statistics
from functools import lru_cache

from ..budget import Budget
from ..governed_operations import digest
from . import learned_operator as scalar

SCHEMA = "lightwork.operator-acquisition.v1"
MAX_DOMAIN, MAX_BEHAVIORS, MAX_STATES = 32, 16, 4096


def domain(artifact, budget):
    budget.check()
    scalar.validate_artifact(artifact)
    fields = artifact["spec"]["inputs"]
    if not 1 <= len(fields) <= 3 or any(row["type"] not in {"boolean", "integer"} for row in fields.values()):
        raise ValueError("Choose a saved simple rule with one to three Yes/No or bounded whole-number inputs.")
    size = 1
    for row in fields.values():
        size *= 2 if row["type"] == "boolean" else row["max"] - row["min"] + 1
    if size > MAX_DOMAIN:
        raise ValueError("All declared situations must fit the complete thirty-two-situation check.")
    choices = [[False, True] if row["type"] == "boolean" else range(row["min"], row["max"] + 1) for row in fields.values()]
    result = []
    for values in itertools.product(*choices):
        budget.check()
        result.append(dict(zip(fields, values, strict=True)))
    return result


def feature(spec, inputs):
    """A declared structural category; never a task name or a hidden score."""
    fields = []
    for key, row in spec["inputs"].items():
        value = inputs[key]
        fields.append([row["type"], "yes" if value else "no"] if row["type"] == "boolean" else
            ["integer", "endpoint" if value in {row["min"], row["max"]} else "zero" if value == 0 else "interior"])
    return digest(sorted(fields))


def _matrix(artifact, values, budget):
    groups = {}
    for program in artifact["candidates"]:
        vector = []
        for inputs in values:
            budget.check()
            output = scalar._run(program, inputs)
            scalar._scalar(output, artifact["spec"]["output_type"], output=True)
            vector.append(copy.deepcopy(output))
        key = scalar._canonical(vector)
        entry = groups.setdefault(key, {"outputs": vector, "multiplicity": 0})
        entry["multiplicity"] += 1
    if len(groups) > MAX_BEHAVIORS:
        raise ValueError("More than sixteen different complete answers remain. Add examples in Teach first.")
    return [groups[key] for key in sorted(groups)]


def _costs(artifact, values, reports, default, budget):
    if type(default) is not int or not 1 <= default <= 1000 or type(reports) is not list or len(reports) > 128:
        raise ValueError("Enter one consistent effort unit and a default from one to one thousand points.")
    costs, evidence = [], []
    for inputs in values:
        budget.check()
        category = feature(artifact["spec"], inputs)
        matching = [row for row in reports if row["feature"] == category]
        if any(type(row["reported_effort"]) is not int or not 1 <= row["reported_effort"] <= 1000 for row in matching):
            raise ValueError("A retained active-effort report is incomplete.")
        # Lower median is exact integer accounting and a declared estimator.
        cost = int(statistics.median_low(row["reported_effort"] for row in matching)) if matching else default
        costs.append(cost)
        evidence.append({"feature": category, "estimated_effort": cost,
            "basis": "lower median of permitted reported active effort" if matching else "entered default; no matching retained effort",
            "reports": [row["id"] for row in matching]})
    return costs, evidence


def _indexed_partitions(behaviors, values):
    rows = []
    for index in range(len(values)):
        groups = {}
        for behavior, row in enumerate(behaviors):
            groups.setdefault(scalar._canonical(row["outputs"][index]), 0)
            groups[scalar._canonical(row["outputs"][index])] |= 1 << behavior
        rows.append(sorted(groups.items()))
    return rows


def _optimizer(partitions, costs, budget):
    choices, examined = {}, set()
    @lru_cache(maxsize=MAX_STATES)
    def solve(mask):
        budget.check()
        examined.add(mask)
        if len(examined) > MAX_STATES:
            raise ValueError("The complete adaptive policy exceeded its shared state allowance; its answer stays unknown.")
        if mask.bit_count() <= 1:
            return 0
        best = None
        for index, rows in enumerate(partitions):
            budget.check()
            children = [part & mask for _output, part in rows if part & mask]
            if len(children) < 2:
                continue
            proposal = (costs[index] + max(solve(child) for child in children), index)
            if best is None or proposal < best:
                best = proposal
        if best is None:
            raise ValueError("Some retained answers cannot be distinguished in the complete declared situations.")
        choices[mask] = best[1]
        return best[0]
    return solve, choices, examined


def _reference(behaviors, costs, budget):
    """Independent direct-vector complete Bellman search, without indexed masks."""
    examined = set()
    @lru_cache(maxsize=MAX_STATES)
    def solve(state):
        budget.check()
        examined.add(state)
        if len(examined) > MAX_STATES:
            raise ValueError("The complete same-information comparison exceeded its state allowance.")
        if len(state) <= 1:
            return 0
        totals = []
        for index, cost in enumerate(costs):
            budget.check()
            groups = {}
            for candidate in state:
                groups.setdefault(scalar._canonical(behaviors[candidate]["outputs"][index]), []).append(candidate)
            if len(groups) > 1:
                totals.append(cost + max(solve(tuple(group)) for group in groups.values()))
        if not totals:
            raise ValueError("The strong comparison has unresolved indistinguishable answers.")
        return min(totals)
    return solve, examined


def _greedy(mask, partitions, costs, behaviors, budget):
    if mask.bit_count() <= 1:
        return 0
    choices = []
    for index, rows in enumerate(partitions):
        budget.check()
        children = [part & mask for _output, part in rows if part & mask]
        if len(children) > 1:
            worst = max(sum(row["multiplicity"] for position, row in enumerate(behaviors) if child & 1 << position) for child in children)
            choices.append((worst, -len(children), index, children))
    _worst, _width, index, children = min(choices)
    return costs[index] + max(_greedy(child, partitions, costs, behaviors, budget) for child in children)


def plan(artifact, reports, *, default_effort, budget=None):
    budget = budget or Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)
    values = domain(artifact, budget)
    behaviors = _matrix(artifact, values, budget)
    costs, cost_evidence = _costs(artifact, values, reports, default_effort, budget)
    partitions = _indexed_partitions(behaviors, values)
    solve, choices, examined = _optimizer(partitions, costs, budget)
    initial = (1 << len(behaviors)) - 1
    optimum = solve(initial)
    reference, reference_states = _reference(behaviors, costs, budget)
    complete_reference = reference(tuple(range(len(behaviors))))
    if optimum != complete_reference:
        raise ValueError("The complete policy and independent reference disagree; no policy is qualified.")
    nodes = []
    seen = set()
    def retain(mask):
        budget.check()
        if mask in seen:
            return
        seen.add(mask)
        if mask.bit_count() == 1:
            nodes.append({"state": mask, "question": None, "remaining_behaviors": 1, "branches": [], "estimated_remaining_effort": 0})
            return
        index = choices[mask]
        branches = [{"answer": output, "state": part & mask} for output, part in partitions[index] if part & mask]
        nodes.append({"state": mask, "question": index, "inputs": values[index], "remaining_behaviors": mask.bit_count(),
            "estimated_effort": costs[index], "estimated_remaining_effort": solve(mask), "cost_basis": cost_evidence[index], "branches": branches})
        for row in branches:
            retain(row["state"])
    retain(initial)
    budget.check()
    return {"schema": SCHEMA, "artifact": artifact["artifact_sha256"], "status": "qualified" if len(behaviors) == 1 else "questions_ready",
        "domain": values, "behaviors": behaviors, "nodes": nodes, "initial": initial,
        "next": next(row for row in nodes if row["state"] == initial), "estimated_worst_effort": optimum,
        "comparison": {"existing_complete_minimax_estimated_effort": _greedy(initial, partitions, costs, behaviors, budget),
            "strong_complete_same_information_effort": complete_reference, "same_optimum": True,
            "optimized_states": len(examined), "reference_states": len(reference_states),
            "meaning": "Modeled effort from entered or reported costs. No observed saving or unfamiliar-operation improvement is established."}}


def answer(artifact, question, output, *, budget):
    budget.check()
    if question["question"] is None:
        raise ValueError("The complete declared situations already have one agreed answer behavior.")
    scalar._scalar(output, artifact["spec"]["output_type"], output=True)
    if scalar._canonical(output) not in {row["answer"] for row in question["branches"]}:
        raise ValueError("That answer disagrees with every retained rule. Correct the examples in Teach; nothing was silently discarded.")
    result = scalar.refine(artifact, [{"inputs": question["inputs"], "output": output}])
    budget.check()
    return result
