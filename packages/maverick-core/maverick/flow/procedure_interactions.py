"""Finite interactions of exact local procedures through the unchanged runner.

Only local values are resources here. No connector effect or approval decision
is replayed, deduplicated or inferred from a field name. Every surviving order
is retained, including different valid final states and failed calculations.
"""
from __future__ import annotations

import copy
import itertools
import time

from ..budget import Budget
from . import learned_operator as scalar
from . import runner
from .selective_qualification import digest, plan


def procedure(flow):
    components = plan(flow, {}, lambda _key: None)
    if not 1 <= len(components) <= 8 or any(flow.nodes[row["id"]].kind == "subflow" for row in components):
        raise ValueError("Choose a linear local rule with one to eight steps and no included workflows.")
    declarations, written, external = {}, set(), set()
    for row in components:
        node = flow.nodes[row["id"]]
        if node.kind == "agent":
            artifact = node.learned_operator["artifact"]
            scalar.validate_artifact(artifact)
            for name, value in artifact["spec"]["inputs"].items():
                declarations.setdefault(name, []).append(value)
        external.update(set(row["reads"]) - written)
        written.update(row["writes"])
    if any(name not in declarations for name in external):
        raise ValueError("Every starting value must have a declared whole-number or yes/no rule bound.")
    return {"components": components, "inputs": {name: declarations[name] for name in sorted(external)}, "writes": sorted(written)}


def domain(flows):
    procedures = [procedure(flow) for flow in flows]
    declarations = {}
    for item in procedures:
        for name, values in item["inputs"].items():
            declarations.setdefault(name, []).extend(values)
    if not 1 <= len(declarations) <= 3:
        raise ValueError("The combined check supports one to three starting values.")
    inputs, choices, count = {}, [], 1
    for name, values in sorted(declarations.items()):
        kind = values[0]["type"]
        if kind not in {"boolean", "integer"} or any(row["type"] != kind for row in values):
            raise ValueError("Shared starting values must have compatible whole-number or yes/no types.")
        declaration = {"type": kind}
        if kind == "integer":
            low, high = max(row["min"] for row in values), min(row["max"] for row in values)
            if low > high or high - low > 63:
                raise ValueError("Shared starting bounds must overlap within the displayed finite limit.")
            declaration.update(min=low, max=high)
            values = list(range(low, high + 1))
        else:
            values = [False, True]
        inputs[name] = declaration
        choices.append(values)
        count *= len(values)
        if count > 64:
            raise ValueError("Choose local rules with at most sixty-four combined starting-value combinations.")
    if count < 2:
        raise ValueError("At least two distinct combined starting states are required.")
    return procedures, inputs, [dict(zip(inputs, values, strict=True)) for values in itertools.product(*choices)]


class Work:
    def __init__(self, guard, original, *, seconds=30, ceiling=8192):
        self.guard, self.original, self.ceiling, self.steps, self.runs = guard, original, ceiling, 0, 0
        self.budget = Budget(max_dollars=0, max_tool_calls=0, max_wall_seconds=seconds)

    def check(self):
        self.budget.check()
        self.guard()
        self.budget.check()

    def observed(self, *_args):
        self.check()
        if self.steps >= self.ceiling:
            raise ValueError("The complete joint calculation reached its reviewed step allowance.")
        self.steps += 1

    def run(self, flow, values):
        def refuse(*_args):
            raise ValueError("Joint local checks cannot call AI, connected actions or approvals.")
        self.check()
        self.runs += 1
        result = runner.run_flow(flow, data=copy.deepcopy(values), run_id=self.original,
            agent_fn=refuse, action_fn=refuse, approve_fn=refuse, on_node=self.observed)
        self.check()
        return {"complete": result.status == runner.STATUS_COMPLETED, "status": result.status, "data": result.data}


def _outputs(result, definition):
    return {name: {"present": name in result["data"], "value": copy.deepcopy(result["data"].get(name))}
            for name in definition["writes"]}


def _ordered(work, flows, definitions, values, order):
    data, outputs, statuses, complete = copy.deepcopy(values), {}, [], True
    for index in order:
        result = work.run(flows[index], data)
        outputs[str(index)] = _outputs(result, definitions[index])
        statuses.append(result["status"])
        data = result["data"]
        if not result["complete"]:
            complete = False
            break
    return {"order": list(order), "complete": complete, "statuses": statuses, "outputs": outputs, "final": data}


def _safe(order, references):
    return order["complete"] and all(row["complete"] for row in references) and digest(order["outputs"]) == digest({
        str(index): row["outputs"] for index, row in enumerate(references)})


def _guard_rules(inputs, rows):
    artifacts, searches = [], 0
    for order in range(2):
        examples = [{"inputs": row["inputs"], "output": row["orders"][order]["safe"]} for row in rows]
        try:
            searches += 1
            artifact = scalar.synthesize({"inputs": inputs, "output_type": "boolean", "constants": [False, True, -1, 0, 1]}, examples)
        except ValueError:
            return None, searches
        for row in examples:
            decision = scalar.evaluate(artifact, row["inputs"])
            if not decision.applied or decision.value is not row["output"]:
                return None, searches
        artifacts.append(artifact)
    return artifacts, searches


def qualify(flows, *, guard, original, save_cell=lambda _row: None):
    began, work, rows = time.perf_counter(), Work(guard, original), []
    work.check()
    definitions, inputs, points = domain(flows)
    work.check()
    hazards = [{"first": first, "second": second,
                "changes_read_values": sorted(set(definitions[first]["writes"]) & set().union(*(set(row["reads"]) for row in definitions[second]["components"]))),
                "shared_updates": sorted(set(definitions[first]["writes"]) & set(definitions[second]["writes"]))}
               for first, second in ((0, 1), (1, 0))]
    for values in points:
        references, repeated = [], []
        for index, flow in enumerate(flows):
            one = work.run(flow, values)
            references.append({**one, "outputs": _outputs(one, definitions[index])})
            again = work.run(flow, one["data"])
            repeated.append({"procedure": index, "complete": one["complete"] and again["complete"],
                "same_local_state": one["complete"] and again["complete"] and digest(one["data"]) == digest(again["data"]),
                "first_outputs": _outputs(one, definitions[index]), "repeated_outputs": _outputs(again, definitions[index])})
        orders = []
        for order in ((0, 1), (1, 0)):
            candidate = _ordered(work, flows, definitions, values, order)
            candidate["safe"] = _safe(candidate, references)
            # The baseline performs new native runs. It never consumes the
            # candidate's results, cache, synthesized guards or component plan.
            baseline = _ordered(work, flows, definitions, copy.deepcopy(values), tuple(order))
            baseline["safe"] = _safe(baseline, references)
            if digest(candidate) != digest(baseline):
                raise ValueError("The separate complete order comparison disagreed. No joint rule can be qualified.")
            orders.append(candidate)
        survivors = [row for row in orders if row["safe"]]
        same = bool(survivors) and len({digest([row["outputs"], row["final"]]) for row in survivors}) == 1
        cell = {"inputs": values, "references": references, "orders": orders,
                "repeated": repeated, "unambiguous": same, "safe_orders": [row["order"] for row in survivors]}
        save_cell(cell)
        rows.append(cell)
    work.check()
    rules, searches = _guard_rules(inputs, rows)
    work.check()
    return {"inputs": inputs, "cells": rows, "hazards": hazards, "guard_rules": rules,
        "qualified": rules is not None and any(row["unambiguous"] for row in rows),
        "same_information_orders_matched": True, "native_runs": work.runs, "native_steps": work.steps,
        "guard_candidates": [len(row["candidates"]) for row in rules] if rules else [], "guard_searches": searches,
        "elapsed_ms": (time.perf_counter() - began) * 1000}


def run(flows, result, values, *, guard, original):
    work = Work(guard, original, ceiling=512)
    work.check()
    definitions, inputs, _points = domain(flows)
    if inputs != result["inputs"] or not result["guard_rules"]:
        raise ValueError("The checked local source or supported joint bounds changed.")
    scalar._inputs({"inputs": inputs}, values, exact=True)
    row = next((row for row in result["cells"] if row["inputs"] == values), None)
    if row is None or not row["unambiguous"]:
        raise ValueError("This combined starting state has no single qualified complete result.")
    safe = [scalar.evaluate(rule, values) for rule in result["guard_rules"]]
    if any(not decision.applied for decision in safe):
        raise ValueError("The learned order checks still disagree. This state remains unresolved.")
    order = (0, 1) if safe[0].value is True else (1, 0) if safe[1].value is True else None
    if order is None or list(order) not in row["safe_orders"]:
        raise ValueError("Neither order preserves both procedures' complete local results.")
    work.check()
    references = [{**(one := work.run(flow, values)), "outputs": _outputs(one, definitions[index])}
                  for index, flow in enumerate(flows)]
    combined = _ordered(work, flows, definitions, values, order)
    work.check()
    if not _safe(combined, references) or digest([combined["outputs"], combined["final"]]) != digest([row["orders"][order[0]]["outputs"], row["orders"][order[0]]["final"]]):
        raise ValueError("The fresh complete local comparison disagreed. No combined result is qualified.")
    return {"complete": True, "order": list(order), "results": combined["outputs"], "final": combined["final"],
        "native_runs": work.runs, "native_steps": work.steps}
