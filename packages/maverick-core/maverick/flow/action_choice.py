"""Learn one binary native continuation from complete observed action episodes.

Route labels derive only from sorted observed terminal tool names. The complete
composed Boolean guard and every argument alternative survive; no candidate is
chosen by score. Prefix results are observations, never instructions to replay.
Raw episodes assert review locally; this mathematical artifact authenticates no
review or execution. Signed lineage is a separate governed wrapper.
"""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from functools import lru_cache

from . import action_recipe as recipe
from . import action_recipe_transforms as transforms
from . import composed_operator as composed

SCHEMA = "lightwork.action-choice.v1"
MAX_ARTIFACT_BYTES = 262_144
MAX_STEP_EVALUATIONS = 100_000


@dataclass(frozen=True)
class ChoiceDecision:
    applied: bool
    tool: str | None = None
    route: str | None = None
    reason: str = ""
    artifact_digest: str = ""
    candidate_binding_count: int = 0
    guard_candidate_count: int = 0


def _canonical(value):
    raw = transforms._canonical(value)
    if len(raw.encode("utf-8")) > MAX_ARTIFACT_BYTES:
        raise ValueError("choice artifact exceeds its whole-artifact byte limit")
    return raw


def _episodes(raw, allowed_tools):
    if type(raw) is not list or not 4 <= len(raw) <= recipe.MAX_EPISODES:
        raise ValueError("choice learning requires four to 32 reviewed episodes")
    snapshots = json.loads(_canonical(raw))
    groups, identities = {}, set()
    for episode in snapshots:
        if type(episode) is not dict or set(episode) != {"id", "inputs", "steps"}:
            raise ValueError("invalid choice episode fields")
        identity, steps = episode["id"], episode["steps"]
        if type(identity) is not str or not identity.strip() or identity in identities:
            raise ValueError("choice episode IDs must be nonempty and unique")
        identities.add(identity)
        if type(steps) is not list or len(steps) != 2:
            raise ValueError("choice episodes require exactly two observed steps")
        for step in steps:
            if (type(step) is not dict or set(step) != {"tool", "arguments", "result"}
                    or type(step["tool"]) is not str):
                raise ValueError("invalid choice step fields")
        groups.setdefault(steps[1]["tool"], []).append(episode)
    if len(groups) != 2:
        raise ValueError("choice requires exactly two distinct terminal tools")
    validated = {}
    for tool, episodes in sorted(groups.items()):
        if len(episodes) < 2:
            raise ValueError("each continuation requires at least two reviewed episodes")
        checked, tools = transforms._episodes(episodes, allowed_tools)
        validated[tool] = checked
    episodes = sorted((episode for group in validated.values() for episode in group), key=lambda ep: ep["id"])
    first = recipe._episode_shape(episodes[0])
    if any((shape := recipe._episode_shape(episode))[0] != first[0] or shape[1][0] != first[1][0]
           for episode in episodes[1:]):
        raise ValueError("choice inputs and shared prefix must have identical tools and typed shapes")
    return episodes, tools, validated


def _domain(raw, groups):
    if type(raw) is not dict or set(raw) not in ({"inputs", "prefix", "branches"}, {"inputs", "prefix", "branches", "guard_fields"}):
        raise ValueError("choice domain requires exact inputs, prefix and branches")
    if "guard_fields" in raw and (type(raw["guard_fields"]) is not list or not 1 <= len(raw["guard_fields"]) <= 6
            or any(type(name) is not str for name in raw["guard_fields"])
            or len(set(raw["guard_fields"])) != len(raw["guard_fields"])):
        raise ValueError("choice guard fields must be one to six distinct observable fields")
    if type(raw["branches"]) is not dict or set(raw["branches"]) != set(groups):
        raise ValueError("choice domain must describe exactly the observed continuations")
    branches = {}
    for tool, episodes in groups.items():
        normalized = transforms._domain({"inputs": raw["inputs"], "steps": [raw["prefix"], raw["branches"][tool]]}, episodes)
        branches[tool] = normalized["steps"][1]
    result = {"inputs": normalized["inputs"], "prefix": normalized["steps"][0], "branches": branches}
    if "guard_fields" in raw:
        result["guard_fields"] = sorted(raw["guard_fields"])
    return result


def _grammar(max_operations, operators, constants, seed_ids):
    return {**composed._grammar(max_operations, operators), "constants": transforms._constants(constants),
            "unsupported_types": "copy_only", "constant_policy": "explicit_plus_stable_seed_target",
            "seed_episode_ids": seed_ids}


def _build(episodes, tools, groups, domain, grammar):
    normalized = _domain(json.loads(_canonical(domain)), groups)
    prefix_domain = {"inputs": normalized["inputs"], "steps": [normalized["prefix"]]}
    all_steps = [episodes[0]["steps"][0], *(group[0]["steps"][1] for group in groups.values())]
    if sum(len(recipe._leaves(step["arguments"])) for step in all_steps) > transforms.MAX_ARGUMENT_LEAVES:
        raise ValueError("choice exceeds eight total argument leaves across prefix and both continuations")
    catalog, definitions, columns = transforms._catalog(episodes, 1, prefix_domain)
    if "guard_fields" in normalized:
        chosen = set(normalized["guard_fields"])
        if not chosen <= columns.keys():
            raise ValueError("choice guard fields must name available supported observations")
        catalog = [source for source in catalog if source["name"] in chosen]
        definitions = {name: decl for name, decl in definitions.items() if name in chosen}
        columns = {name: values for name, values in columns.items() if name in chosen}
    rows = [{"inputs": {name: values[index] for name, values in columns.items()},
             "output": episode["steps"][1]["tool"] == list(groups)[1]} for index, episode in enumerate(episodes)]
    for tool in groups:
        distinct = {_canonical(row["inputs"]) for row, episode in zip(rows, episodes, strict=True)
                    if episode["steps"][1]["tool"] == tool}
        if len(distinct) < 2:
            raise ValueError("each continuation requires two distinct observable fork inputs")
    guard = composed.synthesize({"inputs": definitions, "output_type": "boolean", "constants": grammar["constants"]},
                                rows, max_operations=grammar["max_operations"], operators=grammar["operators"])
    budget = recipe._Budget()
    prefix = transforms._learn_step(episodes, 0, prefix_domain, grammar, budget)
    branches = []
    for index, (tool, group) in enumerate(groups.items()):
        branch_domain = {"inputs": normalized["inputs"], "steps": [normalized["prefix"], normalized["branches"][tool]]}
        learned = transforms._learn_step(group, 1, branch_domain, grammar, budget)
        branches.append({"route": str(index), **learned})
    artifact = {"schema": SCHEMA, "allowed_tools": tools, "episodes": episodes, "episode_count": len(episodes),
                "episodes_sha256": transforms._digest(episodes), "input_shape": recipe._shape(episodes[0]["inputs"]),
                "domain": normalized, "grammar": grammar, "steps": [prefix], "branches": branches,
                "guard": {"catalog": catalog, "artifact": guard}, "guard_candidate_count": guard["candidate_count"],
                "candidate_binding_count": sum(binding["candidate_count"] for step in [prefix, *branches]
                                               for binding in step["bindings"])}
    artifact["artifact_sha256"] = transforms._digest(artifact)
    _canonical(artifact)
    return artifact


def synthesize_choice(episodes, *, allowed_tools, domain, max_operations=2, operators=None, constants=None):
    """Infer a binary continuation and all arguments without supplied labels/guards."""
    episodes, tools, groups = _episodes(episodes, allowed_tools)
    grammar = _grammar(max_operations, operators, [] if constants is None else constants,
                       [episode["id"] for episode in episodes])
    return _build(episodes, tools, groups, domain, grammar)


@lru_cache(maxsize=16)
def _validated(raw):
    artifact = json.loads(raw)
    required = {"schema", "allowed_tools", "episodes", "episode_count", "episodes_sha256", "input_shape", "domain",
                "grammar", "steps", "branches", "guard", "guard_candidate_count", "candidate_binding_count", "artifact_sha256"}
    if type(artifact) is not dict or set(artifact) != required or artifact["schema"] != SCHEMA:
        raise ValueError("invalid choice artifact schema")
    episodes, tools, groups = _episodes(artifact["episodes"], artifact["allowed_tools"])
    grammar = artifact["grammar"]
    if (type(grammar) is not dict or set(grammar) != transforms._GRAMMAR_FIELDS
            or grammar["constant_policy"] != "explicit_plus_stable_seed_target" or grammar["unsupported_types"] != "copy_only"):
        raise ValueError("invalid choice grammar")
    seeds = grammar["seed_episode_ids"]
    if (type(seeds) is not list or len(seeds) < 4 or any(type(identity) is not str for identity in seeds)
            or seeds != sorted(set(seeds)) or not set(seeds) <= {episode["id"] for episode in episodes}
            or any(sum(episode["id"] in seeds for episode in group) < 2 for group in groups.values())):
        raise ValueError("choice grammar requires original retained seeds for both continuations")
    normalized = _grammar(grammar["max_operations"], grammar["operators"], grammar["constants"], seeds)
    expected = _build(episodes, tools, groups, artifact["domain"], normalized)
    if _canonical(expected) != raw:
        raise ValueError("choice artifact does not match its complete learned alternatives")
    return expected


def validate_artifact(artifact):
    _validated(_canonical(artifact))


def refine(artifact, episodes):
    verified = _validated(_canonical(artifact))
    if type(episodes) is not list:
        raise ValueError("new episodes must be a list")
    combined, tools, groups = _episodes([*verified["episodes"], *episodes], verified["allowed_tools"])
    if list(groups) != [branch["tool"] for branch in verified["branches"]]:
        raise ValueError("choice refinement cannot change continuation topology")
    return _build(combined, tools, groups, verified["domain"], copy.deepcopy(verified["grammar"]))


def _runtime(verified, index, inputs, prior_results):
    if type(index) is not int or index not in (0, 1):
        raise ValueError("choice step index must be zero or one")
    if type(inputs) is not dict or type(prior_results) is not list or len(prior_results) != index:
        raise ValueError("choice requires exactly the observed shared prefix results")
    inputs, prior_results = json.loads(recipe._canonical(inputs)), json.loads(recipe._canonical(prior_results))
    if recipe._shape(inputs) != verified["input_shape"]:
        raise ValueError("choice input shape changed")
    transforms._matches(inputs, verified["domain"]["inputs"])
    if index:
        recipe.require_complete_result(prior_results[0])
        if recipe._shape(prior_results[0]) != verified["steps"][0]["result_shape"]:
            raise ValueError("choice prefix result shape changed")
        transforms._matches(prior_results[0], verified["domain"]["prefix"]["result"])
    return inputs, prior_results


def _selection(verified, inputs, prior_results):
    flat = {source["name"]: recipe._bound_value(source, inputs, prior_results) for source in verified["guard"]["catalog"]}
    if composed.evaluation_cost(verified["guard"]["artifact"]) > MAX_STEP_EVALUATIONS:
        return None, "evaluation_limit"
    decision = composed.evaluate(verified["guard"]["artifact"], flat)
    if not decision.applied:
        return None, decision.reason
    return verified["branches"][int(decision.value)], "agreement"


def resolve_choice(artifact, inputs, prior_results):
    try:
        verified = _validated(_canonical(artifact))
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return ChoiceDecision(False, reason="invalid_artifact")
    metadata = {"artifact_digest": verified["artifact_sha256"], "candidate_binding_count": verified["candidate_binding_count"],
                "guard_candidate_count": verified["guard_candidate_count"]}
    try:
        inputs, prior_results = _runtime(verified, 1, inputs, prior_results)
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return ChoiceDecision(False, reason="outside_domain", **metadata)
    selected, reason = _selection(verified, inputs, prior_results)
    if selected is None:
        return ChoiceDecision(False, reason=reason, **metadata)
    return ChoiceDecision(True, selected["tool"], selected["route"], "agreement", **metadata)


def _cost(step):
    return sum(composed.evaluation_cost(binding["artifact"]) if binding["kind"] == "composed" else len(binding["choices"])
               for binding in step["bindings"])


def _arguments(verified, step, index, inputs, prior_results):
    flat = {source["name"]: recipe._bound_value(source, inputs, prior_results) for source in step["catalog"]}
    episode = next(episode for episode in verified["episodes"] if episode["steps"][index]["tool"] == step["tool"])
    arguments = copy.deepcopy(episode["steps"][index]["arguments"])
    for binding in step["bindings"]:
        if binding["kind"] == "composed":
            decision = composed.evaluate(binding["artifact"], flat)
            if not decision.applied:
                return None, decision.reason
            value = decision.value
        else:
            values = [recipe._bound_value(choice, inputs, prior_results) for choice in binding["choices"]]
            if any(not recipe._same(values[0], value) for value in values[1:]):
                return None, "ambiguity"
            value = values[0]
        parent = recipe._lookup(arguments, binding["path"][:-1])
        parent[binding["path"][-1]] = value
    declared = verified["domain"]["prefix"] if index == 0 else verified["domain"]["branches"][step["tool"]]
    try:
        transforms._matches(arguments, declared["arguments"])
    except ValueError:
        return None, "outside_domain"
    return arguments, "agreement"


def resolve_step(artifact, index, inputs, prior_results):
    try:
        verified = _validated(_canonical(artifact))
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return recipe.Decision(False, reason="invalid_artifact")
    metadata = {"artifact_digest": verified["artifact_sha256"], "candidate_binding_count": verified["candidate_binding_count"]}
    try:
        inputs, prior_results = _runtime(verified, index, inputs, prior_results)
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return recipe.Decision(False, reason="outside_domain", **metadata)
    step, guard_cost = verified["steps"][0], 0
    if index:
        step, reason = _selection(verified, inputs, prior_results)
        if step is None:
            return recipe.Decision(False, reason=reason, **metadata)
        guard_cost = composed.evaluation_cost(verified["guard"]["artifact"])
    if guard_cost + _cost(step) > MAX_STEP_EVALUATIONS:
        return recipe.Decision(False, reason="evaluation_limit", tool=step["tool"], **metadata)
    arguments, reason = _arguments(verified, step, index, inputs, prior_results)
    return recipe.Decision(arguments is not None, arguments, reason, tool=step["tool"], **metadata)


def validate_result(artifact, index, result, *, tool=None):
    verified = _validated(_canonical(artifact))
    if type(index) is not int or index not in (0, 1):
        raise ValueError("choice step index must be zero or one")
    if index == 0:
        step, declared = verified["steps"][0], verified["domain"]["prefix"]
        if tool is not None and tool != step["tool"]:
            raise ValueError("choice prefix tool identity changed")
    else:
        step = next((branch for branch in verified["branches"] if type(tool) is str and branch["tool"] == tool), None)
        if step is None:
            raise ValueError("choice terminal result requires the actual selected tool")
        declared = verified["domain"]["branches"][tool]
    recipe.require_complete_result(result)
    if recipe._shape(result) != step["result_shape"]:
        raise ValueError("choice result has changed its exact typed shape")
    transforms._matches(result, declared["result"])
