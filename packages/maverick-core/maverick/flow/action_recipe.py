"""Infer bounded typed action dataflow from human-supplied reviewed episodes.

Each argument leaf retains EVERY matching input path, earlier-result path and
constant. Runtime disagreement abstains; no representative binding is chosen.
This module never dispatches tools, renders templates, or authenticates review.
Artifacts retain raw episodes so validation can reconstruct all alternatives.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

SCHEMA = "lightwork.action-recipe.v1"
CHOICE_SCHEMA = "lightwork.action-choice.v1"
TRANSFORM_SCHEMA = "lightwork.action-recipe.v2"
WORKFLOW_SCHEMA = "lightwork.workflow-transducer.v1"
MEMORY_SCHEMA = "lightwork.workflow-memory.v1"
WORKFLOW_SCHEMAS = frozenset({WORKFLOW_SCHEMA, MEMORY_SCHEMA})
MAX_ARTIFACT_BYTES = 262_144
MAX_DEPTH = 12
MAX_LEAVES = 512
MAX_STRING_LENGTH = 1024
MAX_EPISODES = 32
MAX_STEPS = 8
MAX_MATCH_EVALUATIONS = 2_000_000
MAX_ALLOWED_TOOLS = 64


class SynthesisLimit(ValueError):
    """Complete binding inference exceeded its fixed resource limit."""


@dataclass(frozen=True)
class Decision:
    applied: bool
    arguments: dict | None = None
    reason: str = ""
    artifact_digest: str = ""
    candidate_binding_count: int = 0
    tool: str | None = None


def _canonical(value: Any) -> str:
    remaining = MAX_ARTIFACT_BYTES
    active = set()

    def walk(item, depth=0):
        nonlocal remaining
        remaining -= 8
        if remaining < 0 or depth > MAX_DEPTH:
            raise ValueError("recipe JSON exceeds size or depth limit")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_LENGTH:
                raise ValueError("recipe JSON string exceeds length limit")
            remaining -= len(item.encode("utf-8"))
        elif kind is int:
            if item.bit_length() > MAX_ARTIFACT_BYTES * 4:
                raise ValueError("recipe JSON integer exceeds size limit")
        elif kind is float:
            if not math.isfinite(item):
                raise ValueError("recipe JSON numbers must be finite")
        elif item is None or kind is bool:
            pass
        elif kind in (dict, list):
            if id(item) in active:
                raise ValueError("recipe JSON must not contain cycles")
            active.add(id(item))
            if kind is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise ValueError("recipe JSON object keys must be strings")
                    walk(key, depth + 1)
                    walk(child, depth + 1)
            else:
                for child in item:
                    walk(child, depth + 1)
            active.remove(id(item))
        else:
            raise ValueError("recipe values must be strict JSON types")
        if remaining < 0:
            raise ValueError("recipe JSON exceeds size limit")

    walk(value)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    if len(raw.encode("utf-8")) > MAX_ARTIFACT_BYTES:
        raise ValueError("recipe JSON exceeds size limit")
    return raw


def _digest(value) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key in tool result")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("tool result JSON numbers must be finite")


def _kind(value) -> str:
    return {dict: "object", list: "array", str: "string", int: "integer", float: "number",
            bool: "boolean", type(None): "null"}[type(value)]


def _nodes(value, path=()):
    yield path, value
    if type(value) is dict:
        for key in sorted(value):
            yield from _nodes(value[key], (*path, key))
    elif type(value) is list:
        for index, child in enumerate(value):
            yield from _nodes(child, (*path, index))


def _shape(value) -> list[dict]:
    # Canonical validation runs first; callers never traverse unbounded input.
    rows, leaves = [], 0
    for path, item in _nodes(value):
        row = {"path": list(path), "kind": _kind(item)}
        if type(item) is dict:
            row["keys"] = sorted(item)
        elif type(item) is list:
            row["length"] = len(item)
        else:
            leaves += 1
            if leaves > MAX_LEAVES:
                raise ValueError("recipe JSON tree exceeds leaf limit")
        rows.append(row)
    return rows


def require_complete_result(value: Any) -> None:
    """Reject reserved incomplete/preview markers in a bounded parsed JSON tree.

    These four literal boolean markers are a result-envelope contract shared
    with native episode capture. Arbitrary business fields such as accepted or
    status are not interpreted as success/failure by this helper.
    """
    _canonical(value)
    _shape(value)
    for _path, item in _nodes(value):
        if type(item) is dict and (item.get("pending") is True or item.get("truncated") is True
                                  or item.get("complete") is False or item.get("dry_run") is True):
            raise ValueError("recipe excludes incomplete or preview results")


def parse_result(raw: Any) -> Any:
    """Parse one raw JSON response exactly once, returning an independent value.

Strings are JSON text here: a scalar string response must itself be quoted.
Pass the returned typed value directly to resolve_step/validate_result; those
functions do not interpret strings as JSON text again.
    """
    from ..tool_results import ToolResultText, tool_result_failed

    if isinstance(raw, ToolResultText):
        if tool_result_failed(raw):
            raise ValueError("tool result is not a completed success")
        raw = str(raw)
    if type(raw) is str:
        if len(raw.encode("utf-8")) > MAX_ARTIFACT_BYTES:
            raise ValueError("tool result JSON exceeds size limit")
        try:
            raw = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
        except RecursionError as exc:
            raise ValueError("tool result JSON exceeds depth limit") from exc
    snapshot = json.loads(_canonical(raw))
    require_complete_result(snapshot)
    return snapshot


def _lookup(value, path):
    for part in path:
        value = value[part]
    return value


def _leaves(value):
    return [(list(path), item) for path, item in _nodes(value) if type(item) not in (dict, list)]


def _same(left, right):
    return type(left) is type(right) and left == right


def _episodes(episodes: list[dict], allowed_tools: list[str]) -> tuple[list[dict], list[str]]:
    if (type(allowed_tools) is not list or not 1 <= len(allowed_tools) <= MAX_ALLOWED_TOOLS
            or any(type(tool) is not str or not tool.strip() for tool in allowed_tools)
            or len(set(allowed_tools)) != len(allowed_tools)):
        raise ValueError("allowed_tools must be an explicit nonempty unique list")
    if type(episodes) is not list or not 2 <= len(episodes) <= MAX_EPISODES:
        raise ValueError("recipe requires two to 32 reviewed episodes")
    snapshots = json.loads(_canonical(episodes))
    _canonical(allowed_tools)
    identities = set()
    for episode in snapshots:
        if type(episode) is not dict or set(episode) != {"id", "inputs", "steps"}:
            raise ValueError("invalid recipe episode fields")
        identity = episode["id"]
        if type(identity) is not str or not identity.strip() or identity in identities:
            raise ValueError("episode IDs must be nonempty and unique")
        identities.add(identity)
        if type(episode["inputs"]) is not dict:
            raise ValueError("episode inputs must be an object")
        _shape(episode["inputs"])
        steps = episode["steps"]
        if type(steps) is not list or not 2 <= len(steps) <= MAX_STEPS:
            raise ValueError("recipe requires two to eight steps")
        for step in steps:
            if type(step) is not dict or set(step) != {"tool", "arguments", "result"}:
                raise ValueError("invalid recipe step fields")
            if type(step["tool"]) is not str or step["tool"] not in allowed_tools:
                raise ValueError("episode tool is outside allowed_tools")
            if type(step["arguments"]) is not dict:
                raise ValueError("step arguments must be an object")
            _shape(step["arguments"])
            require_complete_result(step["result"])
    snapshots.sort(key=lambda episode: episode["id"])
    first = snapshots[0]
    signature = _episode_shape(first)
    if any(_episode_shape(episode) != signature for episode in snapshots[1:]):
        raise ValueError("recipe episodes must have identical tool sequences and typed shapes")
    return snapshots, sorted(allowed_tools)


def _episode_shape(episode):
    return (_shape(episode["inputs"]),
            [(step["tool"], _shape(step["arguments"]), _shape(step["result"])) for step in episode["steps"]])


@dataclass
class _Budget:
    used: int = 0

    def matching(self, values, expected):
        for value, target in zip(values, expected, strict=True):
            self.used += 1
            if self.used > MAX_MATCH_EVALUATIONS:
                raise SynthesisLimit("complete recipe binding search exceeds evaluation limit")
            if not _same(value, target):
                return False
        return True


def _sources(episodes, index):
    for path, _ in _leaves(episodes[0]["inputs"]):
        yield {"source": "input", "path": path}, [_lookup(ep["inputs"], path) for ep in episodes]
    for prior in range(index):
        for path, _ in _leaves(episodes[0]["steps"][prior]["result"]):
            yield {"source": "result", "step": prior, "path": path}, [
                _lookup(ep["steps"][prior]["result"], path) for ep in episodes]


def _learn_step(episodes, index, budget):
    first = episodes[0]["steps"][index]
    sources = list(_sources(episodes, index))
    bindings = []
    for path, value in _leaves(first["arguments"]):
        expected = [_lookup(ep["steps"][index]["arguments"], path) for ep in episodes]
        choices = [copy.deepcopy(binding) for binding, values in sources if budget.matching(values, expected)]
        if budget.matching([value] * len(episodes), expected):
            choices.append({"source": "constant", "value": value})
        if not choices:
            raise ValueError("argument has no consistent input, earlier-result or constant binding")
        bindings.append({"path": path, "choices": choices})
    return {"tool": first["tool"], "arguments_shape": _shape(first["arguments"]),
            "result_shape": _shape(first["result"]), "bindings": bindings}


def synthesize(episodes: list[dict], *, allowed_tools: list[str]) -> dict:
    """Retain all matching typed bindings; fail rather than truncate a search."""
    episodes, allowed_tools = _episodes(episodes, allowed_tools)
    budget = _Budget()
    steps = [_learn_step(episodes, index, budget) for index in range(len(episodes[0]["steps"]))]
    artifact = {"schema": SCHEMA, "allowed_tools": allowed_tools, "episodes": episodes,
                "episode_count": len(episodes), "episodes_sha256": _digest(episodes),
                "input_shape": _shape(episodes[0]["inputs"]), "steps": steps,
                "candidate_binding_count": sum(len(binding["choices"]) for step in steps
                                               for binding in step["bindings"])}
    artifact["artifact_sha256"] = _digest(artifact)
    _canonical(artifact)
    return artifact


@lru_cache(maxsize=16)
def _validated(raw: str) -> dict:
    artifact = json.loads(raw)
    fields = {"schema", "allowed_tools", "episodes", "episode_count", "episodes_sha256",
              "input_shape", "steps", "candidate_binding_count", "artifact_sha256"}
    if type(artifact) is not dict or set(artifact) != fields or artifact["schema"] != SCHEMA:
        raise ValueError("invalid action recipe artifact schema")
    expected = synthesize(artifact["episodes"], allowed_tools=artifact["allowed_tools"])
    if _canonical(expected) != raw:
        raise ValueError("recipe artifact does not match its complete learned bindings")
    return expected


def validate_artifact(artifact: dict) -> None:
    """Rebuild the complete derivation; a digest does not authenticate review."""
    if type(artifact) is dict and artifact.get("schema") == MEMORY_SCHEMA:
        from . import workflow_memory

        return workflow_memory.validate_artifact(artifact)
    if type(artifact) is dict and artifact.get("schema") == WORKFLOW_SCHEMA:
        from . import workflow_transducer

        return workflow_transducer.validate_artifact(artifact)
    if type(artifact) is dict and artifact.get("schema") == CHOICE_SCHEMA:
        from . import action_choice

        return action_choice.validate_artifact(artifact)
    if type(artifact) is dict and artifact.get("schema") == TRANSFORM_SCHEMA:
        from . import action_recipe_transforms

        return action_recipe_transforms.validate_artifact(artifact)
    _validated(_canonical(artifact))


def refine(artifact: dict, episodes: list[dict]) -> dict:
    """Add reviewed episodes without mutating or discarding previous evidence."""
    if type(artifact) is dict and artifact.get("schema") == MEMORY_SCHEMA:
        from . import workflow_memory

        return workflow_memory.refine(artifact, episodes)
    if type(artifact) is dict and artifact.get("schema") == WORKFLOW_SCHEMA:
        from . import workflow_transducer

        return workflow_transducer.refine(artifact, episodes)
    if type(artifact) is dict and artifact.get("schema") == CHOICE_SCHEMA:
        from . import action_choice

        return action_choice.refine(artifact, episodes)
    if type(artifact) is dict and artifact.get("schema") == TRANSFORM_SCHEMA:
        from . import action_recipe_transforms

        return action_recipe_transforms.refine(artifact, episodes)
    verified = _validated(_canonical(artifact))
    if type(episodes) is not list:
        raise ValueError("new episodes must be a list")
    return synthesize([*verified["episodes"], *episodes], allowed_tools=verified["allowed_tools"])


def _step(verified, index):
    if type(index) is not int or not 0 <= index < len(verified["steps"]):
        raise ValueError("recipe step index is outside its declared sequence")
    return verified["steps"][index]


def validate_result(artifact: dict, index: int, result: Any, *, tool: str | None = None) -> None:
    """Check an already parsed result, including the last step's exact shape."""
    if type(artifact) is dict and artifact.get("schema") == MEMORY_SCHEMA:
        from . import workflow_memory

        return workflow_memory.validate_observation(artifact, tool, result)
    if type(artifact) is dict and artifact.get("schema") == WORKFLOW_SCHEMA:
        from . import workflow_transducer

        return workflow_transducer.validate_observation(artifact, tool, result)
    if type(artifact) is dict and artifact.get("schema") == CHOICE_SCHEMA:
        from . import action_choice

        return action_choice.validate_result(artifact, index, result, tool=tool)
    if type(artifact) is dict and artifact.get("schema") == TRANSFORM_SCHEMA:
        from . import action_recipe_transforms

        return action_recipe_transforms.validate_result(artifact, index, result)
    verified = _validated(_canonical(artifact))
    step = _step(verified, index)
    require_complete_result(result)
    if _shape(result) != step["result_shape"]:
        raise ValueError("recipe result does not match the step's exact typed shape")


def _runtime(verified, index, inputs, prior_results):
    _step(verified, index)
    if type(inputs) is not dict or type(prior_results) is not list or len(prior_results) != index:
        raise ValueError("recipe requires declared inputs and exactly the completed prior results")
    # Take an independent snapshot before checking or reading any binding.
    inputs = json.loads(_canonical(inputs))
    prior_results = json.loads(_canonical(prior_results))
    if _shape(inputs) != verified["input_shape"]:
        raise ValueError("recipe inputs have changed shape")
    for prior, result in enumerate(prior_results):
        require_complete_result(result)
        if _shape(result) != verified["steps"][prior]["result_shape"]:
            raise ValueError("recipe prior result has changed shape")
    return inputs, prior_results


def _bound_value(binding, inputs, prior_results):
    if binding["source"] == "constant":
        return binding["value"]
    root = inputs if binding["source"] == "input" else prior_results[binding["step"]]
    return _lookup(root, binding["path"])


def resolve_step(artifact: dict, index: int, inputs: dict, prior_results: list) -> Decision:
    """Resolve native arguments only on complete binding agreement; dispatch nothing."""
    if type(artifact) is not dict or type(artifact.get("schema")) is not str:
        return Decision(False, reason="invalid_artifact")
    if type(artifact) is dict and artifact.get("schema") in WORKFLOW_SCHEMAS:
        # A transducer requires the exact tools, arguments and results of the
        # completed prefix. Positional results alone cannot identify its state.
        return Decision(False, reason="workflow_history_required")
    if type(artifact) is dict and artifact.get("schema") == CHOICE_SCHEMA:
        from . import action_choice

        return action_choice.resolve_step(artifact, index, inputs, prior_results)
    if type(artifact) is dict and artifact.get("schema") == TRANSFORM_SCHEMA:
        from . import action_recipe_transforms

        return action_recipe_transforms.resolve_step(artifact, index, inputs, prior_results)
    try:
        verified = _validated(_canonical(artifact))
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return Decision(False, reason="invalid_artifact")
    identity, count = verified["artifact_sha256"], verified["candidate_binding_count"]
    try:
        inputs, prior_results = _runtime(verified, index, inputs, prior_results)
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return Decision(False, reason="outside_domain", artifact_digest=identity, candidate_binding_count=count)
    arguments = copy.deepcopy(verified["episodes"][0]["steps"][index]["arguments"])
    for binding in verified["steps"][index]["bindings"]:
        values = [_bound_value(choice, inputs, prior_results) for choice in binding["choices"]]
        if any(not _same(values[0], value) for value in values[1:]):
            return Decision(False, reason="ambiguity", artifact_digest=identity, candidate_binding_count=count)
        parent = _lookup(arguments, binding["path"][:-1])
        parent[binding["path"][-1]] = values[0]
    return Decision(True, arguments, "agreement", identity, count)
