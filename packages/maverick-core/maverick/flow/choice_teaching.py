"""Bind a human teaching choice to one supplied, complete native prefix.

This pure helper neither authenticates the supplied observation nor executes or
learns from a choice. The native runtime must establish its actual observation,
human approval and capture authority separately. Questions exist only when both
terminal routes remain possible and every argument alternative within each
route agrees. A human may choose a route, never invent its tool or arguments.
"""
from __future__ import annotations

import copy
import json

from . import action_choice as choice
from . import action_recipe as recipe
from . import action_recipe_transforms as transforms
from . import composed_operator as composed

TEACHING_SCHEMA = "lightwork.action-choice-teaching.v1"
QUESTION_SCHEMA = "lightwork.action-choice-teaching-question.v1"
MAX_QUESTION_BYTES = 262_144
MAX_EVALUATIONS = 100_000
_INVALID = (ValueError, TypeError, RecursionError, UnicodeError)


class TeachingUnavailable(ValueError):
    """No complete, bounded human choice can be offered for this observation."""

    def __init__(self, reason):
        self.reason = reason
        super().__init__(f"choice teaching unavailable: {reason}")


def _canonical(value):
    raw = choice._canonical(value)
    if len(raw.encode("utf-8")) > MAX_QUESTION_BYTES:
        raise ValueError("teaching question exceeds its whole-object byte limit")
    return raw


def _artifact(artifact):
    try:
        return choice._validated(choice._canonical(artifact))
    except _INVALID as exc:
        raise TeachingUnavailable("invalid_artifact") from exc


def _propose(verified, inputs, prefix_result):
    try:
        inputs, prior = choice._runtime(verified, 1, inputs, [prefix_result])
    except _INVALID as exc:
        raise TeachingUnavailable("outside_domain") from exc
    guard = verified["guard"]["artifact"]
    cost = composed.evaluation_cost(guard)
    if cost > MAX_EVALUATIONS:
        raise TeachingUnavailable("evaluation_limit")
    flat = {source["name"]: recipe._bound_value(source, inputs, prior)
            for source in verified["guard"]["catalog"]}
    partitions = composed.partitions(guard, flat)
    if partitions is None:
        raise TeachingUnavailable("predictions_unavailable")
    if len(partitions) == 1:
        raise TeachingUnavailable("guard_agreement")
    if (len(partitions) != 2 or any(type(row["output"]) is not bool for row in partitions)
            or {row["output"] for row in partitions} != {False, True}
            or sum(row["candidate_count"] for row in partitions) != verified["guard_candidate_count"]):
        raise TeachingUnavailable("predictions_unavailable")
    cost += sum(choice._cost(branch) for branch in verified["branches"])
    if cost > MAX_EVALUATIONS:
        raise TeachingUnavailable("evaluation_limit")
    options = []
    for branch in verified["branches"]:
        arguments, reason = choice._arguments(verified, branch, 1, inputs, prior)
        if arguments is None:
            raise TeachingUnavailable("argument_" + reason if reason in {"ambiguity", "outside_domain"} else reason)
        options.append({"route": branch["route"], "tool": branch["tool"], "arguments": arguments})
    try:
        for option in options:
            option["arguments_sha256"] = transforms._digest(option["arguments"])
        question = {"schema": QUESTION_SCHEMA, "artifact_sha256": verified["artifact_sha256"],
                    "guard_artifact_sha256": guard["artifact_sha256"],
                    "observation": {"inputs": inputs, "prefix_result": prior[0]},
                    "input_sha256": transforms._digest(inputs),
                    "prefix_sha256": transforms._digest({"input": inputs, "prior_results": prior}),
                    "guard_candidate_count": verified["guard_candidate_count"],
                    "guard_partitions": partitions, "options": options}
        question["question_sha256"] = transforms._digest(question)
        return json.loads(_canonical(question))
    except _INVALID as exc:
        raise TeachingUnavailable("question_limit") from exc


def propose(artifact, inputs, prefix_result):
    """Offer both real supported continuations, or raise TeachingUnavailable.

    The complete guard partitions are exact syntax-tree counts, not confidence
    or probabilities. Inputs and prefix values are independent snapshots; their
    presence here alone provides no evidence of an actual native execution.
    """
    return _propose(_artifact(artifact), inputs, prefix_result)


def _question(verified, question):
    try:
        raw = _canonical(question)
        snapshot = json.loads(raw)
        if (type(snapshot) is not dict or type(snapshot.get("observation")) is not dict
                or set(snapshot["observation"]) != {"inputs", "prefix_result"}):
            raise ValueError("invalid teaching observation")
        observation = snapshot["observation"]
        expected = _propose(verified, observation["inputs"], observation["prefix_result"])
        if _canonical(expected) != raw:
            raise ValueError("teaching question differs from complete reconstructed alternatives")
        return expected
    except _INVALID as exc:
        raise ValueError("invalid teaching question") from exc


def validate_question(artifact, question):
    """Rebuild every option and commitment; changing and rehashing is insufficient."""
    _question(_artifact(artifact), question)


def _option(question, route):
    if type(route) is not str or route not in {"0", "1"}:
        raise ValueError("teaching route must be the exact offered route string")
    return next(option for option in question["options"] if option["route"] == route)


def select(artifact, question, route, inputs, prefix_result):
    """Resolve an offered choice against the exact current observation.

    Applied means the supplied route is structurally available. It conveys no
    human identity, approval, permission to dispatch or newly learned fact.
    """
    try:
        verified = _artifact(artifact)
    except TeachingUnavailable:
        return recipe.Decision(False, reason="invalid_artifact")
    metadata = {"artifact_digest": verified["artifact_sha256"],
                "candidate_binding_count": verified["candidate_binding_count"]}
    try:
        checked = _question(verified, question)
    except _INVALID:
        return recipe.Decision(False, reason="invalid_question", **metadata)
    try:
        option = _option(checked, route)
    except ValueError:
        return recipe.Decision(False, reason="invalid_route", **metadata)
    try:
        inputs, prior = choice._runtime(verified, 1, inputs, [prefix_result])
    except _INVALID:
        return recipe.Decision(False, reason="outside_domain", **metadata)
    if _canonical({"inputs": inputs, "prefix_result": prior[0]}) != _canonical(checked["observation"]):
        return recipe.Decision(False, reason="observation_changed", **metadata)
    return recipe.Decision(True, copy.deepcopy(option["arguments"]), "teaching_selection",
                           tool=option["tool"], **metadata)


def selection_binding(artifact, question, route):
    """Digest-only structural binding; the caller must authenticate the decision."""
    checked = _question(_artifact(artifact), question)
    option = _option(checked, route)
    return {**{key: checked[key] for key in ("artifact_sha256", "guard_artifact_sha256", "question_sha256",
                                           "input_sha256", "prefix_sha256")},
            "route": route, "tool": option["tool"], "arguments_sha256": option["arguments_sha256"]}
