"""Closed native rule compilation and complete counterexample-check ordering.

The incumbent determines finite behavior, not business truth. Both evolving
artifacts remain below a separate, immutable complete-domain acceptance gate.
No generated Python, provider, plugin, tool or host source modification occurs.
"""
from __future__ import annotations

import copy
import json
from functools import cache

from ..budget import Budget
from ..governed_operations import digest
from . import Flow, FlowNode
from . import learned_operator as scalar
from .evolve import attach_learned_operator
from .operator_acquisition import domain

SCHEMA = "lightwork.governed-rule-evolution.v1"
MAX_DOMAIN, MAX_FAULTS, MAX_STATES, MAX_NODES = 32, 8, 4096, 64


def exact(value):
    if type(value) is bool:
        return {"kind": "boolean", "value": value}
    if type(value) is int:
        return {"kind": "integer", "text": str(value)}
    if type(value) is str:
        return {"kind": "text", "text": value}
    raise ValueError("Only complete typed scalar answers are supported.")


def key(value):
    return json.dumps(exact(value), sort_keys=True, separators=(",", ":"))


def source(flow, budget):
    budget.check()
    if (len(flow.nodes) != 1 or flow.start not in flow.nodes or flow.learned_recipe is not None
            or flow.validate() or flow.reachability_errors()):
        raise ValueError("Choose one isolated published taught step.")
    node = flow.nodes[flow.start]
    if (node.kind != "agent" or not node.learned_operator or node.learned_fallback is not False
            or node.next or node.on_error or node.retries or not node.output):
        raise ValueError("Choose a single taught rule with a named answer and no fallback, repeat or connected work.")
    artifact = node.learned_operator["artifact"]
    if node.output in artifact["spec"]["inputs"]:
        raise ValueError("For this bounded rewrite, the named answer must differ from every input name so input checks cannot change a route.")
    if artifact.get("schema") != scalar.SCHEMA:
        raise ValueError("Combined rules need their existing qualification controls.")
    values = domain(artifact, budget)
    if not values or len(values) > MAX_DOMAIN:
        raise ValueError("The entire declared domain must fit thirty-two situations.")
    return values


def _tests(values):
    result = []
    for field in sorted(values[0]):
        choices = sorted({row[field] for row in values})
        for threshold in choices[:-1]:
            mask = sum(1 << index for index, row in enumerate(values) if row[field] <= threshold)
            condition = field + (" == false" if type(threshold) is bool else " <= " + str(threshold))
            result.append((condition, mask))
    return result


def decision_tree(values, outputs, budget):
    """Smallest tree using the declared axis splits; not a smallest-DAG claim."""
    tests, states = _tests(values), [0]
    @cache
    def solve(mask):
        budget.check()
        states[0] += 1
        if states[0] > MAX_STATES:
            raise ValueError("Complete tree search exceeded its shared state allowance.")
        indices = [i for i in range(len(values)) if mask & (1 << i)]
        if len({key(outputs[i]) for i in indices}) == 1:
            return (1, 1, {"answer": outputs[indices[0]]})
        options = []
        for condition, partition in tests:
            budget.check()
            left, right = mask & partition, mask & ~partition
            if not left or not right:
                continue
            a, b = solve(left), solve(right)
            options.append((1 + a[0] + b[0], 1 + max(a[1], b[1]), condition,
                {"condition": condition, "yes": a[2], "no": b[2]}))
        if not options:
            raise ValueError("Declared native splits cannot distinguish every answer.")
        winner = min(options, key=lambda item: item[:3])
        return winner[0], winner[1], winner[3]
    nodes, depth, tree = solve((1 << len(values)) - 1)
    return {"tree": tree, "tree_nodes": nodes, "worst_tree_steps": depth, "searched_states": states[0],
        "meaning": "Smallest tree within the complete declared axis splits; repeated subtrees are merged afterward. No smallest-DAG or speed claim."}


def _constant_artifact(artifact, values, answer):
    spec = copy.deepcopy(artifact["spec"])
    spec.update(output_type=scalar._type(answer), constants=[answer])
    return scalar.synthesize(spec, [{"inputs": row, "output": answer} for row in values])


def compile_flow(incumbent, values, outputs, tree, budget, *, indexed=False):
    """Produce executable native nodes, including the strict typed input guard."""
    budget.check()
    original = incumbent.nodes[incumbent.start]
    artifact = original.learned_operator["artifact"]
    answer_name = original.output
    nodes, retained = {}, {}
    def leaf(value):
        identity = "leaf" + str(len(nodes) + 1)
        if type(value) is str:
            constant = _constant_artifact(artifact, values, value)
            node = FlowNode(id=identity, kind="agent", brief="Return this exact checked text answer", output=answer_name,
                label="Return the checked answer", learned_fallback=False)
            holder = Flow(id="temporary", name="Checked text answer", start=identity, nodes={identity: node})
            node = attach_learned_operator(holder, identity, constant).nodes[identity]
        else:
            node = FlowNode(id=identity, kind="setvar", assignments={answer_name: value}, label="Return the checked answer")
        nodes[identity] = node
        return identity
    def visit(item):
        budget.check()
        fingerprint = digest(item)
        if fingerprint in retained:
            return retained[fingerprint]
        if set(item) == {"answer"}:
            identity = leaf(item["answer"])
        else:
            yes, no = visit(item["yes"]), visit(item["no"])
            identity = "choice" + str(len(nodes) + 1)
            nodes[identity] = FlowNode(id=identity, kind="branch", condition=item["condition"], if_true=yes, if_false=no,
                label="Choose the checked answer route")
        retained[fingerprint] = identity
        return identity
    if indexed:
        if len(values[0]) != 1:
            raise ValueError("The native direct-choice alternative needs one input.")
        field = next(iter(values[0]))
        cases = [{"value": row[field], "to": visit({"answer": output})} for row, output in zip(values, outputs, strict=True)]
        entry = "directChoice"
        nodes[entry] = FlowNode(id=entry, kind="switch", condition=field, cases=cases, label="Find this entered situation directly")
    else:
        entry = visit(tree)
    guard = "inputGuard"
    nodes[guard] = FlowNode(id=guard, kind="agent", brief="Check the declared input kinds and bounds without computing the incumbent answer",
        output=answer_name, next=entry, label="Check the entered input limits", learned_fallback=False)
    flow = incumbent.copy()
    flow.start, flow.nodes = guard, nodes
    flow = attach_learned_operator(flow, guard, _constant_artifact(artifact, values, True))
    if len(flow.nodes) > MAX_NODES or flow.validate() or flow.reachability_errors():
        raise ValueError("The entire compiled native program exceeds its sixty-four-node bound.")
    budget.check()
    return flow


def alternatives(incumbent, values, outputs, budget):
    if len(values) != len(outputs) or not 1 <= len(values) <= MAX_DOMAIN:
        raise ValueError("Every declared situation needs one complete incumbent answer.")
    tree = decision_tree(values, outputs, budget)
    result = [{"key": "tree", "name": "Checked decision routes", "flow": compile_flow(incumbent, values, outputs, tree["tree"], budget).to_dict(), "construction": tree}]
    if len(values[0]) == 1:
        result.append({"key": "direct", "name": "Direct choice for each entered situation",
            "flow": compile_flow(incumbent, values, outputs, tree["tree"], budget, indexed=True).to_dict(),
            "construction": {"meaning": "Native direct choice with the same strict input guard; complete same-information alternative, no speed claim."}})
    return result


def faults(incumbent, values, outputs, count, budget):
    if type(count) is not int or not 1 <= count <= min(MAX_FAULTS, len(values)):
        raise ValueError("Choose one to eight wrong-answer variants, no more than the complete entered situations.")
    result = []
    for index in range(count):
        budget.check()
        changed = copy.deepcopy(outputs)
        value = changed[index]
        changed[index] = (not value if type(value) is bool else value - 1 if type(value) is int and value == 10**24
            else value + 1 if type(value) is int else value + "x" if len(value) < 1024 else value[:-1])
        tree = decision_tree(values, changed, budget)
        result.append({"name": "Declared wrong-answer variant " + str(index + 1), "changed_situation": index,
            "flow": compile_flow(incumbent, values, changed, tree["tree"], budget).to_dict()})
    return result


def check_order(mismatches, size, budget):
    """Exact finite first-failure objective; every remaining case is appended."""
    if (not 1 <= size <= MAX_DOMAIN or not 1 <= len(mismatches) <= MAX_FAULTS
            or any(len(row) != size or any(type(value) is not bool for value in row) or not any(row) for row in mismatches)):
        raise ValueError("Every known negative must have its complete actual mismatch matrix.")
    masks = [sum(1 << fault for fault, row in enumerate(mismatches) if row[case]) for case in range(size)]
    @cache
    def solve(remaining):
        budget.check()
        if not remaining:
            return 0, ()
        options = []
        for case, mask in enumerate(masks):
            budget.check()
            after = remaining & ~mask
            if after == remaining:
                continue
            cost, tail = solve(after)
            options.append((remaining.bit_count() + cost, (case, *tail)))
        return min(options)
    objective, prefix = solve((1 << len(mismatches)) - 1)
    order = [*prefix, *[case for case in range(size) if case not in prefix]]
    # Independent complete recursion using the literal list of still-passing
    # negatives, rather than the optimized mask representation.
    @cache
    def reference(remaining):
        budget.check()
        if not remaining:
            return 0
        choices = []
        for case in range(size):
            budget.check()
            after = tuple(fault for fault in remaining if not mismatches[fault][case])
            if after != remaining:
                choices.append(len(remaining) + reference(after))
        return min(choices)
    reference_cost = reference(tuple(range(len(mismatches))))
    if objective != reference_cost or sorted(order) != list(range(size)):
        raise ValueError("Complete independent evaluator-order comparison disagreed.")
    ordinary = sum(next(index + 1 for index, failed in enumerate(row) if failed) for row in mismatches)
    return {"order": order, "ordinary_order": list(range(size)), "known_negative_first_failure_checks": objective,
        "ordinary_known_negative_first_failure_checks": ordinary, "strong_same_information_first_failure_checks": reference_cost,
        "reference_agrees": True, "passing_program_checks": size, "complete_situations": size,
        "meaning": "Minimizes total first-failure checks over these equally weighted declared wrong-answer variants. Every remaining situation is still checked before a pass. No lower worst-case, unseen-defect, wall-time or general improvement claim."}


def indexed_reference(values, outputs, budget):
    """Conventional complete indexed lookup; not a fitted or supplied score."""
    table = {}
    for inputs, output in zip(values, outputs, strict=True):
        budget.check()
        identity = json.dumps(inputs, sort_keys=True, separators=(",", ":"))
        if identity in table:
            raise ValueError("Complete input identities must be unique.")
        table[identity] = exact(output)
    if len(table) != len(values):
        raise ValueError("The complete indexed reference is unavailable.")
    return table


def local_budget(max_wall_seconds=15):
    if type(max_wall_seconds) is not int or max_wall_seconds not in {15, 60, 120}:
        raise ValueError("Choose the complete shared checking allowance: fifteen seconds, one minute or two minutes.")
    return Budget(max_wall_seconds=max_wall_seconds, max_dollars=0, max_tool_calls=0)
