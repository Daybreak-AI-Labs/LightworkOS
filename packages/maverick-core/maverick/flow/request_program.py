"""Exhaustive bounded composition of actual native pure rule steps."""
from __future__ import annotations

import copy
import itertools
import time

from . import operator_artifacts, runner
from .ir import Flow, validate_learned_operator
from .selective_qualification import digest


def components(flow):
    result = []
    for node in flow.nodes.values():
        if node.kind != "agent" or not node.learned_operator or node.learned_fallback is not False:
            continue
        if node.on_error or node.retries or node.timeout or node.retry_backoff:
            continue
        validate_learned_operator(node)
        artifact = node.learned_operator["artifact"]
        operator_artifacts.validate_artifact(artifact)
        result.append({"id": node.id, "label": node.label or "Checked rule step", "output": node.output,
                       "kind": artifact["spec"]["output_type"], "inputs": artifact["spec"]["inputs"],
                       "alternatives": operator_artifacts.candidate_count(artifact)})
    return result


def sequences(selected, length):
    if not 1 <= len(selected) <= 3 or len(set(selected)) != len(selected) or type(length) is not int or not 1 <= length <= 3:
        raise ValueError("Choose one to three different checked steps and a limit of one to three steps.")
    return [list(row) for size in range(1, length + 1) for row in itertools.product(selected, repeat=size)]


def compile_flow(source, sequence, original, number):
    available = {row["id"] for row in components(source)}
    if not sequence or any(identity not in available for identity in sequence):
        raise ValueError("A selected step no longer has supported checked rules.")
    nodes = {}
    for index, identity in enumerate(sequence):
        node = copy.deepcopy(source.nodes[identity])
        node.id = "request_step_" + str(index + 1)
        node.next = "request_step_" + str(index + 2) if index + 1 < len(sequence) else None
        nodes[node.id] = node
    return Flow(id=original + "_" + str(number), name=source.name, owner=source.owner,
                start="request_step_1", nodes=nodes, max_seconds=20)


def run(source, choices, cases, *, guard, charge, budget, original):
    """Retain every sequence and every declared case; never stop at a winner."""
    all_sequences = sequences(choices["steps"], choices["length"])
    chosen = {row["id"]: row for row in components(source)}
    field = choices["result"]
    if field not in {chosen[key]["output"] for key in choices["steps"]}:
        raise ValueError("Choose a named result produced by a selected step.")
    started, rows, native_steps = time.perf_counter(), [], [0]
    def refuse(*_args):
        raise ValueError("This request never calls AI or connected tools.")
    def observe(node, event, _elapsed):
        native_steps[0] += 1
        guard()
        budget.check()
    def check(flow, inputs, reference):
        charge()
        # Reserve all possible rule evaluation work before the unchanged native
        # runner starts. Its telemetry is emitted after a step, not at dispatch.
        for node in flow.nodes.values():
            charge(1 + operator_artifacts.evaluation_cost(node.learned_operator["artifact"]))
        guard()
        value = runner.run_flow(flow, data=inputs, agent_fn=refuse, action_fn=refuse,
                                run_id=original + ":" + reference, on_node=observe)
        guard()
        budget.check()
        produced = value.status == runner.STATUS_COMPLETED and field in value.data and flow.nodes[next(reversed(flow.nodes))].output == field
        reason = "The final step produced the selected result." if produced else "These steps did not establish the selected final answer within their supported inputs."
        state = "answered" if produced else "unresolved" if value.status == runner.STATUS_COMPLETED else "not_answered"
        if not produced and value.cursor in flow.nodes:
            artifact = flow.nodes[value.cursor].learned_operator["artifact"]
            charge(1 + operator_artifacts.evaluation_cost(artifact))
            decision = operator_artifacts.evaluate(artifact, value.data)
            if decision.reason in {"ambiguity", "evaluation_limit"}:
                state, reason = "unresolved", "Retained rule alternatives did not establish one answer."
            elif decision.reason == "outside_domain":
                reason = "A step lacked a required value or received an input outside its supported range."
            guard()
        return {"state": state,
                "value": copy.deepcopy(value.data[field]) if produced else None,
                "reason": reason}
    for number, sequence in enumerate(all_sequences, 1):
        charge()
        unit = compile_flow(source, sequence, original, number)
        checks = []
        for index, case in enumerate(cases):
            outcome = check(unit, case["inputs"], str(number) + ":case:" + str(index))
            outcome.update(label=case["label"], inputs=copy.deepcopy(case["inputs"]), expected=case["expected"],
                           matches=outcome["state"] == "answered" and type(outcome["value"]) is type(case["expected"]) and outcome["value"] == case["expected"])
            checks.append(outcome)
        passes = all(row["matches"] for row in checks)
        answer = check(unit, choices["inputs"], str(number) + ":request") if passes else None
        rows.append({"number": number, "sequence": sequence, "steps": [chosen[key]["label"] for key in sequence],
                     "source_candidates": [chosen[key]["alternatives"] for key in sequence], "checks": checks,
                     "passes": passes, "answer": answer})
    survivors = [row for row in rows if row["passes"]]
    answers = [row["answer"] for row in survivors]
    agreed = bool(answers) and all(row["state"] == "answered" for row in answers) and len({digest(row["value"]) for row in answers}) == 1
    return {"complete": True, "candidates": rows, "passing": len(survivors), "agreement": agreed,
            "answer": copy.deepcopy(answers[0]["value"]) if agreed else None, "request": copy.deepcopy(choices["inputs"]),
            "native_steps": native_steps[0], "calculation_ms": (time.perf_counter() - started) * 1000}
