"""Reviewable native Flow drafts for learned straight-line action dataflow.

This module never dispatches tools. Native action authorization, approvals and
the durable run lock remain in charge. Ambiguous bindings do not authorize a
guess or a restart of a previously executed prefix.
"""
from __future__ import annotations

import copy
import hashlib
import json

from . import action_recipe


def _nodes(artifact, *, teaching=False):
    from .ir import FlowNode

    if artifact.get("schema") in action_recipe.WORKFLOW_SCHEMAS:
        from .workflow_recipe_flow import nodes
        return nodes(artifact)
    if artifact.get("schema") == action_recipe.CHOICE_SCHEMA:
        return _choice_nodes(artifact, teaching=teaching)
    nodes = {}
    for index, step in enumerate(artifact["steps"]):
        gate, action = f"approval_{index}", f"action_{index}"
        nodes[gate] = FlowNode(
            gate, "approval", next=action,
            prompt=f"Review learned action {index + 1}: {step['tool']}. "
                   "The exact proposed arguments are in run data _recipe_next_arguments.",
        )
        nodes[action] = FlowNode(
            action, "action", tool=step["tool"], recipe_step=index,
            output=f"_recipe_step_{index}",
            next=f"approval_{index + 1}" if index + 1 < len(artifact["steps"]) else None,
        )
    return nodes


def _choice_nodes(artifact, *, teaching=False):
    from .ir import FlowNode

    prefix = artifact["steps"][0]
    nodes = {
        "approval_0": FlowNode("approval_0", "approval", next="action_0",
            prompt=f"Review learned action 1: {prefix['tool']}. "
                   "The exact proposed arguments are in run data _recipe_next_arguments."),
        "action_0": FlowNode("action_0", "action", tool=prefix["tool"], recipe_step=0,
            output="_recipe_step_0", next="choice"),
        "choice": FlowNode("choice", "switch", condition="_recipe_choice.route",
            cases=[{"value": branch["route"], "to": f"approval_1_{branch['route']}"}
                   for branch in artifact["branches"]]),
    }
    for branch in artifact["branches"]:
        gate, action = f"approval_1_{branch['route']}", f"action_1_{branch['route']}"
        nodes[gate] = FlowNode(gate, "approval", next=action,
            prompt=f"Review learned continuation: {branch['tool']}. "
                   "The selected route and exact arguments are in run data _recipe_choice and _recipe_next_arguments.")
        nodes[action] = FlowNode(action, "action", tool=branch["tool"], recipe_step=1, output="_recipe_step_1")
    if teaching:
        nodes["choice"].next = "teaching_review"
        nodes["teaching_review"] = FlowNode("teaching_review", "approval", next="teaching_choice",
            prompt="The reviewed examples disagree about this completed case. Choose its continuation. "
                   "Both exact proposed actions are in _recipe_teaching_question.options. "
                   "A separate action approval follows your choice.",
            choices=["route:0", "route:1"], output="_recipe_teaching_decision")
        nodes["teaching_choice"] = FlowNode("teaching_choice", "switch", condition="_recipe_teaching_decision",
            cases=[{"value": f"route:{branch['route']}", "to": f"approval_1_{branch['route']}"}
                   for branch in artifact["branches"]])
    return nodes


def make_flow(artifact: dict, *, flow_id: str, name: str, teaching=False):
    """Produce an unsaved draft with an approval before each native action."""
    from .ir import Flow

    action_recipe.validate_artifact(artifact)
    if type(teaching) is not bool or (teaching and artifact.get("schema") != action_recipe.CHOICE_SCHEMA):
        raise ValueError("teaching requires a strict Boolean choice-recipe option")
    if type(flow_id) is not str or not flow_id.strip() or type(name) is not str or not name.strip():
        raise ValueError("a nonempty flow_id and name are required")
    snapshot = copy.deepcopy(artifact)
    marker = {"schema": "lightwork.action-choice-teaching.v1"} if teaching else None
    start = "decision_0" if snapshot.get("schema") in action_recipe.WORKFLOW_SCHEMAS else "approval_0"
    flow = Flow(flow_id, name, start, nodes=_nodes(snapshot, teaching=teaching),
                learned_recipe=snapshot, recipe_teaching=marker)
    if snapshot.get("schema") == action_recipe.MEMORY_SCHEMA:
        from .store import _assert_safe_definition
        _assert_safe_definition(flow.to_dict())
    return flow


def validate_flow(flow) -> None:
    """Require the retained artifact's exact generated control/dataflow graph."""
    action_recipe.validate_artifact(flow.learned_recipe)
    teaching = flow.recipe_teaching is not None
    if teaching and (type(flow.recipe_teaching) is not dict
                     or flow.recipe_teaching != {"schema": "lightwork.action-choice-teaching.v1"}
                     or flow.learned_recipe.get("schema") != action_recipe.CHOICE_SCHEMA):
        raise ValueError("invalid recipe teaching marker")
    if flow.recipe_lineage is not None:
        from .recipe_lineage import validate_reference
        validate_reference(flow.recipe_lineage, flow.learned_recipe)
    expected = _nodes(flow.learned_recipe, teaching=teaching)
    start = "decision_0" if flow.learned_recipe.get("schema") in action_recipe.WORKFLOW_SCHEMAS else "approval_0"
    if flow.start != start or set(flow.nodes) != set(expected):
        raise ValueError("learned action recipe graph changed")
    for key, node in flow.nodes.items():
        actual, wanted = node.to_dict(), expected[key].to_dict()
        # Layout and descriptive labels grant no execution authority.
        for cosmetic in ("x", "y", "label"):
            actual.pop(cosmetic, None)
            wanted.pop(cosmetic, None)
        if actual != wanted or (node.kind == "action" and type(node.recipe_step) is not int):
            raise ValueError("learned action recipe nodes changed")
    if flow.inputs:
        raise ValueError("learned action recipe uses the explicit input object")


def check_lineage(artifact, reference, *, owner, live=True):
    """Enforce local evidence policy; a live check precedes each action.

    Persistence checks structure and policy only. Runtime checks current source
    eligibility without holding the definition lock across source run locks.
    """
    from ..config import get_flows
    from .recipe_lineage import runtime_reference, validate_reference

    settings = get_flows()
    if artifact.get("schema") in action_recipe.WORKFLOW_SCHEMAS:
        if (settings.get("action_workflow_learning") is not True
                or settings.get("action_recipe_transforms") is not True):
            raise ValueError("learned workflow feature is disabled")
        if (artifact.get("schema") == action_recipe.MEMORY_SCHEMA
                and settings.get("action_workflow_memory_learning") is not True):
            raise ValueError("learned workflow memory feature is disabled")
        if reference is None:
            raise ValueError("learned workflow requires admitted signed evidence")
    if reference is None:
        # A customer installation that collects or admits examples must never
        # execute an unbound derivative, even if its older optional-policy
        # setting still reads false. Otherwise withdrawing a source only stops
        # recipes created through the signed Teach page, while a raw artifact
        # saved through another entrance keeps running.
        if (settings.get("require_action_recipe_lineage", False) is not False
                or settings.get("action_episode_capture") is True
                or settings.get("action_recipe_lineage") is True):
            raise ValueError("learned action requires admitted signed evidence")
        return None
    if settings.get("action_recipe_lineage") is not True:
        raise ValueError("learned action evidence feature is disabled")
    validate_reference(reference, artifact)
    if live:
        return runtime_reference(reference, artifact, owner=owner)
    return None


def check_persisted_lineage(flow, *, owner=None) -> None:
    """Scoped policy check, including embedded graphs; preserve draft support."""
    owner = flow.owner if owner is None else owner
    if flow.recipe_lineage is not None and flow.owner and flow.owner != owner:
        raise ValueError("learned recipe owner differs from its authoritative execution owner")
    if flow.learned_recipe is not None:
        validate_flow(flow)
        if flow.recipe_teaching is not None and flow.recipe_lineage is None:
            raise ValueError("recipe teaching requires admitted signed evidence")
        check_lineage(flow.learned_recipe, flow.recipe_lineage, owner=owner, live=False)
    elif flow.recipe_lineage is not None or flow.recipe_teaching is not None:
        raise ValueError("recipe lineage requires its complete parent recipe")
    for node in flow.nodes.values():
        if node.body is not None:
            check_persisted_lineage(node.body, owner=owner)
        for branch in node.branches:
            check_persisted_lineage(branch, owner=owner)


def decision(artifact: dict, index: int, data: dict):
    """Resolve typed arguments from the original input and completed results."""
    if artifact.get("schema") in action_recipe.WORKFLOW_SCHEMAS:
        from .workflow_recipe_flow import arguments_decision
        return arguments_decision(artifact, data, index)
    if type(data) is not dict or type(data.get("input")) is not dict:
        return action_recipe.Decision(False, reason="outside_domain")
    try:
        prior = [data[f"_recipe_step_{step}"] for step in range(index)]
    except KeyError:
        return action_recipe.Decision(False, reason="outside_domain")
    return action_recipe.resolve_step(artifact, index, data["input"], prior)


def choice_binding(artifact, data, tool):
    """Bind a mechanically selected continuation to the retained actual prefix."""
    raw = json.dumps({"input": data["input"], "prior_results": [data["_recipe_step_0"]]},
                     sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    route = next(branch["route"] for branch in artifact["branches"] if branch["tool"] == tool)
    return {"artifact_sha256": artifact["artifact_sha256"], "route": route,
            "tool": tool, "guard_artifact_sha256": artifact["guard"]["artifact"]["artifact_sha256"],
            "prefix_sha256": hashlib.sha256(raw).hexdigest()}


def validate_teaching_question(artifact, data):
    """Require a complete question bound to the exact retained observations."""
    from . import choice_teaching
    from .action_provenance import canonical

    question = data.get("_recipe_teaching_question")
    choice_teaching.validate_question(artifact, question)
    if canonical(question["observation"]) != canonical(
            {"inputs": data.get("input"), "prefix_result": data.get("_recipe_step_0")}):
        raise ValueError("teaching observations changed")
    return copy.deepcopy(question)


def record_decision(artifact, *, flow_id, run_id, node_id, index, status, reason,
                    arguments=None, lineage=None, choice=None, teaching=None, workflow=None):
    """Require durable receipts, and strict signing for learned workflows.

    Arguments and examples stay out of the receipt. Import the public writer at
    call time so native audit instrumentation and the audit-contract gate see
    the same entry point.
    """
    from ..audit import EventKind, record
    from ..audit.errors import AuditRefused
    from ..budget import BudgetExceeded
    from ..killswitch import Halted

    params_digest = ""
    if arguments is not None:
        raw = json.dumps(arguments, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
        params_digest = hashlib.sha256(raw).hexdigest()
    try:
        written = record(
            EventKind.FLOW_ACTION_RECIPE_DECISION, agent="flow:action_recipe",
            _require_signed=artifact.get("schema") in action_recipe.WORKFLOW_SCHEMAS,
            flow_id=flow_id, flow_run_id=run_id, node_id=node_id, step_index=index,
            status=status, reason=reason, artifact_sha256=artifact["artifact_sha256"],
            arguments_sha256=params_digest,
            **({"recipe_lineage": copy.deepcopy(lineage)} if lineage is not None else {}),
            **({"recipe_choice": copy.deepcopy(choice)} if choice is not None else {}),
            **({"recipe_teaching": copy.deepcopy(teaching)} if teaching is not None else {}),
            **({"recipe_workflow": copy.deepcopy(workflow)} if workflow is not None else {}),
        )
    except (AuditRefused, BudgetExceeded, Halted):
        raise
    except Exception as exc:
        raise AuditRefused("learned action decision audit failed") from exc
    if written is not True:
        raise AuditRefused("learned action decision requires a durable audit receipt")
