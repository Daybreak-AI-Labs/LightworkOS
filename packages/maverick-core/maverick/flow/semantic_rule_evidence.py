"""Complete finite behavior evidence for eligible local taught-rule components.

This intentionally uses exhaustive native evaluation. It offers no research
advantage over an ordinary indexed finite-function comparison.
"""
from __future__ import annotations

import copy
import json

from . import learned_operator, runner
from .ir import Flow

SCHEMA = "lightwork.finite-rule-behavior.v1"


def _refuse(*_args):
    raise ValueError("This complete rule check cannot call AI or connected actions.")


def behavior(flow, component, *, guard, budget, observe, original):
    from .competence_transport import domain

    node = flow.nodes[component["id"]]
    if node.kind != "agent" or node.learned_fallback or not node.learned_operator:
        return None
    artifact = node.learned_operator.get("artifact", {})
    if artifact.get("schema") != learned_operator.SCHEMA:
        return None
    learned_operator.validate_artifact(artifact)
    if artifact["spec"]["output_type"] not in {"boolean", "integer"}:
        return None
    try:
        points = domain(artifact["spec"])
    except ValueError:
        return None  # Unsupported finite bounds receive the ordinary rerun.
    single = copy.deepcopy(node)
    single.next = None
    unit = Flow(id=flow.id, name=flow.name, owner=flow.owner,
                version=flow.version, revision=flow.revision, start=node.id,
                nodes={node.id: single}, max_seconds=flow.max_seconds)
    cases = []
    for inputs in points:
        budget.check()
        guard()
        result = runner.run_flow(unit, data=copy.deepcopy(inputs),
                                 agent_fn=_refuse, action_fn=_refuse,
                                 run_id=original, on_node=observe)
        guard()
        budget.check()
        if result.status != runner.STATUS_COMPLETED or node.output not in result.data:
            return None
        cases.append({"inputs": inputs, "outputs": {node.output: result.data[node.output]}})
    return {"schema": SCHEMA, "inputs": artifact["spec"]["inputs"],
            "output_type": artifact["spec"]["output_type"], "writes": component["writes"],
            "cases": cases}


def matches(previous, current):
    if current is None or type(previous) is not dict:
        return False
    # Compare the complete typed material, not a source hash or Python's
    # True == 1 / False == 0 equality. Custody and current rights are separate.
    return json.dumps(previous, sort_keys=True, allow_nan=False, separators=(",", ":")) == json.dumps(
        current, sort_keys=True, allow_nan=False, separators=(",", ":"))
