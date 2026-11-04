"""Conservative finite region learning with independent unchanged rule runs.

Labels establish only the displayed finite test states. A missing, conflicting
or unsuccessful answer cannot become a favorable route through compression.
"""
from __future__ import annotations

import copy
import itertools
import time
from functools import lru_cache

from ..budget import Budget
from . import competence_transport as finite
from . import learned_operator as scalar
from . import runner
from .selective_qualification import digest


class Work:
    def __init__(self, guard, original, *, seconds=30):
        self.guard, self.original = guard, original
        self.budget = Budget(max_dollars=0, max_tool_calls=0, max_wall_seconds=seconds)
        self.runs = self.steps = self.searches = 0

    def check(self):
        self.budget.check()
        self.guard()
        self.budget.check()

    def search(self):
        self.budget.check()
        self.searches += 1
        if self.searches > 100000:
            raise ValueError("The complete region search reached its reviewed allowance. Unresolved work stays unresolved.")

    def run(self, flow, values):
        def refuse(*_args):
            raise ValueError("These local checks cannot call AI, connected actions or approvals.")

        def observed(*_args):
            self.check()
            self.steps += 1
            if self.steps > 1024:
                raise ValueError("The complete local check reached its reviewed step allowance.")

        self.check()
        self.runs += 1
        result = runner.run_flow(flow, data=copy.deepcopy(values), run_id=self.original,
                                 agent_fn=refuse, action_fn=refuse, approve_fn=refuse, on_node=observed)
        self.check()
        output = flow.nodes[flow.start].output
        present = result.status == runner.STATUS_COMPLETED and output in result.data
        value = result.data.get(output) if present else None
        return {"complete": present, "status": result.status, "value": value,
                "receipt": digest([flow.to_dict(), values, result.status, present, value])}


def definitions(flows):
    if len(flows) != 2:
        raise ValueError("Choose exactly one current and one proposed local rule.")
    artifacts = []
    for flow in flows:
        if len(flow.nodes) != 1 or flow.start not in flow.nodes:
            raise ValueError("Choose a local rule with one taught answer step and no included work.")
        node = flow.nodes[flow.start]
        if (node.kind != "agent" or node.learned_fallback or not node.learned_operator or node.next
                or node.on_error or node.retries or node.retry_backoff or node.timeout or not node.output):
            raise ValueError("The selected step must finish through local rules alone, without retries or outside work.")
        artifact = node.learned_operator["artifact"]
        scalar.validate_artifact(artifact)
        if node.output in artifact["spec"]["inputs"]:
            raise ValueError("The produced answer must be separate from every starting input.")
        if artifact["schema"] != "lightwork.learned-operator.v1" or len(artifact["candidates"]) > 32:
            raise ValueError("Choose a supported simple taught rule with at most thirty-two remaining answers.")
        artifacts.append(artifact)
    left, right = (item["spec"] for item in artifacts)
    if left["inputs"] != right["inputs"] or left["output_type"] != right["output_type"]:
        raise ValueError("The two rules must have exactly the same starting fields, types, limits and answer type.")
    return left, finite.domain(left)


def route(tree, values):
    while "field" in tree:
        tree = tree["left"] if values[tree["field"]] <= tree["through"] else tree["right"]
    return tree["route"]


def learn(inputs, cells, work):
    """Minimum axis-split tree over the complete typed grid, including unknowns."""
    names = list(inputs)
    axes = [sorted({cell["inputs"][name] for cell in cells}) for name in names]
    points = {tuple(axis.index(cell["inputs"][name]) for axis, name in zip(axes, names, strict=True)): cell["route"]
              for cell in cells}

    @lru_cache(maxsize=2080)
    def split(bounds):
        work.search()
        choices = {points[point] for point in itertools.product(*(range(low, high + 1) for low, high in bounds))}
        if len(choices) == 1:
            return 0, {"route": choices.pop()}
        best = None
        for index, (low, high) in enumerate(bounds):
            for boundary in range(low, high):
                work.search()
                left, right = list(bounds), list(bounds)
                left[index], right[index] = (low, boundary), (boundary + 1, high)
                a, b = split(tuple(left)), split(tuple(right))
                candidate = (1 + a[0] + b[0], {"field": names[index], "through": axes[index][boundary],
                                              "left": a[1], "right": b[1]})
                if best is None or candidate[0] < best[0]:
                    best = candidate
        if best is None:
            raise ValueError("The complete starting-value partition cannot be checked.")
        return best

    cost, tree = split(tuple((0, len(axis) - 1) for axis in axes))
    return tree, cost, split.cache_info().currsize


def _classify(values, results, labels):
    selected = [item for item in labels if digest(item["inputs"]) == digest(values)]
    answers = {digest(item["expected"]) for item in selected}
    if not answers:
        return "unknown", "review"
    if len(answers) != 1:
        return "conflicting", "review"
    expected = selected[0]["expected"]
    matches = [row["complete"] and type(row["value"]) is type(expected) and row["value"] == expected for row in results]
    if matches == [True, True]:
        return "both_correct", "baseline"
    if matches == [True, False]:
        return "baseline_only", "baseline"
    if matches == [False, True]:
        return "candidate_only", "candidate"
    return "neither_correct", "review"


def qualify(flows, labels, *, work, save_cell=lambda _row: None):
    began = time.perf_counter()
    work.check()
    spec, points = definitions(flows)
    for label in labels:
        scalar._inputs(spec, label["inputs"], exact=True)
        scalar._scalar(label["expected"], spec["output_type"], output=True)
    cells = []
    for values in points:
        results = [work.run(flow, values) for flow in flows]
        classification, choice = _classify(values, results, labels)
        cell = {"inputs": values, "arms": results, "classification": classification, "route": choice,
                "reviewed_answers": [{key: label[key] for key in ("expected", "type", "source_version") if key in label}
                    for label in labels if digest(label["inputs"]) == digest(values)]}
        save_cell(cell)
        cells.append(cell)
    tree, splits, rectangles = learn(spec["inputs"], cells, work)
    # The comparator uses the entire labeled table and freshly executes its own
    # chosen immutable arm. It never consumes the split tree's execution result.
    for cell in cells:
        choice = route(tree, cell["inputs"])
        if choice != cell["route"]:
            raise ValueError("The separate complete routing comparison disagreed. No routing was qualified.")
        if choice != "review":
            index = 0 if choice == "baseline" else 1
            inferred = work.run(flows[index], cell["inputs"])
            independent = work.run(flows[index], copy.deepcopy(cell["inputs"]))
            if inferred != independent or inferred != cell["arms"][index]:
                raise ValueError("A separate unchanged local answer check disagreed. No routing was qualified.")
    unknown = [cell for cell in cells if cell["classification"] == "unknown"]
    question = max(unknown, key=lambda cell: (cell["arms"][0]["complete"] and cell["arms"][1]["complete"]
                    and digest(cell["arms"][0]["value"]) != digest(cell["arms"][1]["value"])), default=None)
    work.check()
    return {"inputs": spec["inputs"], "output_kind": spec["output_type"], "cells": cells, "tree": tree,
            "split_count": splits, "searched_rectangles": rectangles, "next_question": question,
            "independent_routing_matched": True, "native_runs": work.runs, "native_steps": work.steps,
            "search_steps": work.searches, "elapsed_ms": (time.perf_counter() - began) * 1000}


def run(flows, checked, values, *, work):
    spec, _points = definitions(flows)
    if spec["inputs"] != checked["inputs"] or spec["output_type"] != checked["output_kind"]:
        raise ValueError("The reviewed starting fields or answer type changed.")
    scalar._inputs(spec, values, exact=True)
    choice = route(checked["tree"], values)
    cell = next(row for row in checked["cells"] if digest(row["inputs"]) == digest(values))
    if choice != cell["route"]:
        raise ValueError("The retained routing cannot be checked.")
    if choice == "review":
        work.check()
        return {"route": choice, "complete": False, "message": "These starting values still need review. Neither version ran.", "native_runs": 0}
    selected = 0 if choice == "baseline" else 1
    result, independent = work.run(flows[selected], values), work.run(flows[selected], copy.deepcopy(values))
    if result != independent or result != cell["arms"][selected]:
        raise ValueError("The fresh separate answer check disagreed. The result remains unresolved.")
    return {"route": choice, **result, "native_runs": work.runs, "native_steps": work.steps, "independent_routing_matched": True}
