"""Exact, bounded native graphs and observation bindings for learned workflows.

The learner chooses each next call and completion from actual retained history.
The graph supplies unique invocation identities and a separate native approval
before every call. This module dispatches no tools and authenticates no history.
"""
from __future__ import annotations

import copy

from . import action_recipe
from . import action_recipe_transforms as transforms

SCHEMA = "lightwork.workflow-transducer.v1"
HISTORY = "_recipe_workflow_history"
SELECTION = "_recipe_workflow_selection"


def nodes(artifact):
    from .ir import FlowNode

    result = {}
    for index in range(artifact["max_steps"] + 1):
        cases = [{"value": "complete", "to": None}]
        if index < artifact["max_steps"]:
            for ordinal, tool in enumerate(artifact["allowed_tools"]):
                gate, action = f"approval_{index}_{ordinal}", f"action_{index}_{ordinal}"
                cases.append({"value": "action:" + tool, "to": gate})
                result[gate] = FlowNode(gate, "approval", next=action,
                    prompt=f"Review learned workflow action {index + 1}: {tool}. "
                           "Exact proposed arguments are in _recipe_next_arguments.")
                result[action] = FlowNode(action, "action", tool=tool, recipe_step=index,
                    output=f"_recipe_step_{index}", next=f"decision_{index + 1}")
        key = f"decision_{index}"
        result[key] = FlowNode(key, "switch", condition=SELECTION + ".route", cases=cases)
    return result


def history(artifact, data, index):
    if (type(data) is not dict or type(data.get("input")) is not dict
            or type(index) is not int or not 0 <= index <= artifact["max_steps"]):
        raise ValueError("invalid learned workflow observation")
    steps = data.get(HISTORY)
    if type(steps) is not list or len(steps) != index:
        raise ValueError("learned workflow history does not match its invocation")
    # Preserve strict JSON types; true and 1 cannot alias in retained history.
    snapshot = copy.deepcopy(steps)
    for ordinal, step in enumerate(snapshot):
        if (type(step) is not dict or set(step) != {"tool", "arguments", "result"}
                or f"_recipe_step_{ordinal}" not in data
                or transforms._canonical(step["result"]) != transforms._canonical(data[f"_recipe_step_{ordinal}"])):
            raise ValueError("learned workflow result history changed")
    transforms._canonical(snapshot)
    return snapshot


def resolve(artifact, data, index):
    from .workflow_transducer import resolve_next

    if artifact.get("schema") == action_recipe.MEMORY_SCHEMA:
        from .workflow_memory import resolve_next

    try:
        steps = history(artifact, data, index)
    except (ValueError, TypeError, RecursionError, UnicodeError):
        from .workflow_transducer import WorkflowDecision
        return WorkflowDecision(False, reason="invalid_history")
    return resolve_next(artifact, data["input"], steps)


def binding(artifact, data, index, decision):
    steps = history(artifact, data, index)
    result = {"schema": "lightwork.workflow-transducer-selection.v1",
            "artifact_sha256": artifact["artifact_sha256"], "step_index": index,
            "history_sha256": transforms._digest({"input": data["input"], "steps": steps}),
            "kind": decision.kind, "tool": decision.tool,
            "route": "complete" if decision.kind == "complete" else "action:" + decision.tool,
            "arguments_sha256": transforms._digest(decision.arguments)}
    if artifact.get("schema") == action_recipe.MEMORY_SCHEMA:
        # Bind every surviving summary, never suggest one was selected as truth.
        # Raw summaries and observations remain in their governed stores.
        result.update(schema="lightwork.workflow-memory-selection.v1",
            memory_models_sha256=transforms._digest([model["summary"] for model in artifact["models"]]),
            memory_model_count=len(artifact["models"]))
    return result


def arguments_decision(artifact, data, index):
    """Adapt the next-call decision to the existing native action gate."""
    decision = resolve(artifact, data, index)
    reason = decision.reason
    if decision.applied and decision.kind != "action":
        reason = "workflow_already_complete"
    applied = decision.applied and decision.kind == "action" and reason == "agreement"
    return action_recipe.Decision(applied, decision.arguments if applied else None,
                                  reason, decision.artifact_digest, tool=decision.tool)


def selected_binding(artifact, data, index, tool):
    decision = resolve(artifact, data, index)
    if not decision.applied or decision.kind != "action" or decision.tool != tool:
        raise ValueError("learned workflow selection changed")
    current = binding(artifact, data, index, decision)
    if transforms._canonical(data.get(SELECTION)) != transforms._canonical(current):
        raise ValueError("learned workflow selection no longer matches actual history")
    return current


def retain_result(artifact, data, index, *, tool, arguments, result):
    """Append once after the action result and required receipt both succeeded."""
    steps = history(artifact, data, index)
    selected_binding(artifact, data, index, tool)
    steps.append({"tool": tool, "arguments": copy.deepcopy(arguments), "result": copy.deepcopy(result)})
    transforms._canonical(steps)
    data[HISTORY] = steps


def completed_memory_binding(artifact, data, index, *, tool, arguments, result):
    """Commit the observed result as well as the pre-call selection.

    This dispatches nothing and does not retain the result. The caller must
    successfully write this required receipt before appending native history.
    """
    if artifact.get("schema") != action_recipe.MEMORY_SCHEMA:
        raise ValueError("memory completion requires its exact artifact schema")
    selected = selected_binding(artifact, data, index, tool)
    if selected["arguments_sha256"] != transforms._digest(arguments):
        raise ValueError("completed memory arguments differ from selected arguments")
    steps = history(artifact, data, index)
    steps.append({"tool": tool, "arguments": copy.deepcopy(arguments), "result": copy.deepcopy(result)})
    return {**selected, "schema": "lightwork.workflow-memory-completion.v1",
            "result_sha256": transforms._digest(result),
            "completed_history_sha256": transforms._digest({"input": data["input"], "steps": steps})}


def clear_initial(data):
    for key in list(data):
        if key.startswith("_recipe_"):
            data.pop(key)
    data[HISTORY] = []
