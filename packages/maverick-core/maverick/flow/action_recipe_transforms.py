"""Complete bounded transformed dataflow from reviewed raw action episodes.

Every eligible original-input and earlier-result path enters each step's source
catalog. Each supported argument leaf retains the entire composed expression
space; float/null leaves retain typed copies and stable constants only. Marginal
unanimity determines the whole argument object. Counts sum marginal alternatives,
not full recipes or probabilities. This module dispatches no tools and does not
authenticate the supplied episodes or their review.

Original seed episode IDs fix each inferred literal pool. Refinement filters the
same grammar against more evidence; it never removes a still-consistent program
merely because its original stable target later varies.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
from functools import lru_cache

from . import composed_operator as composed
from . import learned_operator as scalar

SCHEMA = "lightwork.action-recipe.v2"
MAX_ARTIFACT_BYTES = 262_144
MAX_ARGUMENT_LEAVES = 8
MAX_SOURCE_LEAVES = 6
MAX_STEP_EVALUATIONS = 100_000
_SUPPORTED = {"integer", "string", "boolean"}
_GRAMMAR_FIELDS = {"max_operations", "operators", "constants", "unsupported_types", "constant_policy", "seed_episode_ids"}


def _canonical(value):
    """Bound metadata independently of the stricter business-tree admission."""
    remaining, active = MAX_ARTIFACT_BYTES, set()

    def walk(item, depth=0):
        nonlocal remaining
        remaining -= 8
        if remaining < 0 or depth > 32:
            raise ValueError("transformed recipe JSON exceeds size or metadata depth limit")
        kind = type(item)
        if kind is str:
            if len(item) > 1024:
                raise ValueError("transformed recipe string exceeds length limit")
            remaining -= len(item.encode("utf-8"))
        elif kind is int:
            if item.bit_length() > MAX_ARTIFACT_BYTES * 4:
                raise ValueError("transformed recipe integer exceeds size limit")
        elif kind is float:
            if not math.isfinite(item):
                raise ValueError("transformed recipe requires finite numbers")
        elif item is None or kind is bool:
            pass
        elif kind in (dict, list):
            if id(item) in active:
                raise ValueError("transformed recipe JSON must not contain cycles")
            active.add(id(item))
            if kind is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise ValueError("transformed recipe keys must be strings")
                    walk(key, depth + 1)
                    walk(child, depth + 1)
            else:
                for child in item:
                    walk(child, depth + 1)
            active.remove(id(item))
        else:
            raise ValueError("transformed recipe requires strict JSON data")
        if remaining < 0:
            raise ValueError("transformed recipe JSON exceeds size limit")

    walk(value)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    if len(raw.encode("utf-8")) > MAX_ARTIFACT_BYTES:
        raise ValueError("transformed recipe JSON exceeds byte limit")
    return raw


def _digest(value):
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _schema(value, *, depth=0, remaining=None):
    """Normalize the closed retention-schema subset without executing validators."""
    remaining = [512] if remaining is None else remaining
    remaining[0] -= 1
    if type(value) is not dict or depth > 8 or remaining[0] < 0:
        raise ValueError("domain schema exceeds structural limit")
    kind = value.get("type")
    allowed = {"object": {"type", "properties", "required", "additionalProperties"},
               "array": {"type", "items", "minItems", "maxItems"},
               "integer": {"type", "minimum", "maximum"}, "number": {"type", "minimum", "maximum"},
               "string": {"type", "minLength", "maxLength"}, "boolean": {"type"}, "null": {"type"}}
    if type(kind) is not str or kind not in allowed or set(value) - allowed[kind]:
        raise ValueError("unsupported domain schema type or keyword")
    result = {"type": kind}
    if kind == "object":
        props, required = value.get("properties"), value.get("required")
        if (type(props) is not dict or len(props) > 64 or type(required) is not list
                or any(type(key) is not str for key in required) or len(set(required)) != len(required)
                or set(required) != set(props) or value.get("additionalProperties") is not False
                or any(type(key) is not str or not key or len(key) > 1024 for key in props)):
            raise ValueError("domain objects must require all declared fields and reject extras")
        result.update(properties={key: _schema(child, depth=depth + 1, remaining=remaining)
                                  for key, child in sorted(props.items())},
                      required=sorted(required), additionalProperties=False)
    elif kind == "array":
        low, high = value.get("minItems"), value.get("maxItems")
        if type(low) is not int or type(high) is not int or low != high or not 0 <= low <= 64:
            raise ValueError("domain arrays require a fixed bounded length")
        result.update(items=_schema(value.get("items"), depth=depth + 1, remaining=remaining),
                      minItems=low, maxItems=high)
    elif kind in {"integer", "number"}:
        low, high = value.get("minimum"), value.get("maximum")
        for bound in (low, high):
            if (type(bound) not in (int, float) or (type(bound) is float and not math.isfinite(bound))
                    or (kind == "integer" and type(bound) is not int)):
                raise ValueError("domain numeric bounds must have strict finite types")
        if not -10**24 <= low <= high <= 10**24:
            raise ValueError("domain numeric bounds exceed limits")
        result.update(minimum=low, maximum=high)
    elif kind == "string":
        low, high = value.get("minLength", 0), value.get("maxLength")
        if type(low) is not int or type(high) is not int or not 0 <= low <= high <= 1024 or high < 1:
            raise ValueError("domain strings require bounded lengths")
        result.update(minLength=low, maxLength=high)
    return result


def _matches(value, schema):
    kind = schema["type"]
    expected = {"object": dict, "array": list, "integer": int, "number": float,
                "string": str, "boolean": bool, "null": type(None)}[kind]
    if type(value) is not expected:
        raise ValueError("value does not match its strict domain type")
    if kind == "object":
        if set(value) != set(schema["properties"]):
            raise ValueError("domain object has missing or extra fields")
        for key, child in value.items():
            _matches(child, schema["properties"][key])
    elif kind == "array":
        if len(value) != schema["minItems"]:
            raise ValueError("domain array has changed length")
        for child in value:
            _matches(child, schema["items"])
    elif kind in {"integer", "number"} and not schema["minimum"] <= value <= schema["maximum"]:
        raise ValueError("value is outside numeric domain")
    elif kind == "string" and not schema["minLength"] <= len(value) <= schema["maxLength"]:
        raise ValueError("value is outside string domain")


def _domain(raw, episodes):
    if type(raw) is not dict or set(raw) != {"inputs", "steps"}:
        raise ValueError("domain requires exact inputs and steps schemas")
    if type(raw["steps"]) is not list or len(raw["steps"]) != len(episodes[0]["steps"]):
        raise ValueError("domain must describe every step")
    normalized = {"inputs": _schema(raw["inputs"]), "steps": []}
    if normalized["inputs"]["type"] != "object":
        raise ValueError("domain inputs require an object schema")
    for step in raw["steps"]:
        if type(step) is not dict or set(step) != {"arguments", "result"}:
            raise ValueError("domain step requires exact argument and result schemas")
        pair = {key: _schema(step[key]) for key in ("arguments", "result")}
        if pair["arguments"]["type"] != "object":
            raise ValueError("domain arguments require an object schema")
        normalized["steps"].append(pair)
    for episode in episodes:
        _matches(episode["inputs"], normalized["inputs"])
        for observed, declared in zip(episode["steps"], normalized["steps"], strict=True):
            _matches(observed["arguments"], declared["arguments"])
            _matches(observed["result"], declared["result"])
    return normalized


def _episodes(raw, allowed_tools):
    from . import action_recipe as recipe

    if (type(allowed_tools) is not list or not 1 <= len(allowed_tools) <= recipe.MAX_ALLOWED_TOOLS
            or any(type(tool) is not str or not tool.strip() for tool in allowed_tools)
            or len(set(allowed_tools)) != len(allowed_tools)):
        raise ValueError("allowed_tools must be an explicit nonempty unique list")
    if type(raw) is not list or not 2 <= len(raw) <= recipe.MAX_EPISODES:
        raise ValueError("recipe requires two to 32 reviewed episodes")
    episodes = json.loads(_canonical(raw))
    _canonical(allowed_tools)
    identities = set()
    for episode in episodes:
        if type(episode) is not dict or set(episode) != {"id", "inputs", "steps"}:
            raise ValueError("invalid recipe episode fields")
        identity = episode["id"]
        if type(identity) is not str or not identity.strip() or identity in identities:
            raise ValueError("episode IDs must be nonempty and unique")
        identities.add(identity)
        if type(episode["inputs"]) is not dict:
            raise ValueError("episode inputs must be an object")
        steps = episode["steps"]
        if type(steps) is not list or not 2 <= len(steps) <= recipe.MAX_STEPS:
            raise ValueError("recipe requires two to eight steps")
        values = [episode["inputs"]]
        for step in steps:
            if type(step) is not dict or set(step) != {"tool", "arguments", "result"}:
                raise ValueError("invalid recipe step fields")
            if type(step["tool"]) is not str or step["tool"] not in allowed_tools:
                raise ValueError("episode tool is outside allowed_tools")
            if type(step["arguments"]) is not dict:
                raise ValueError("step arguments must be an object")
            recipe.require_complete_result(step["result"])
            values.extend((step["arguments"], step["result"]))
        for value in values:
            recipe._shape(value)
            if any(len(path) > 8 for path, _item in recipe._nodes(value)):
                raise ValueError("recipe business value exceeds depth limit")
    episodes.sort(key=lambda episode: episode["id"])
    signature = recipe._episode_shape(episodes[0])
    if any(recipe._episode_shape(episode) != signature for episode in episodes[1:]):
        raise ValueError("recipe episodes must have identical tool sequences and typed shapes")
    return episodes, sorted(allowed_tools)


def _constants(values):
    if type(values) is not list or len(values) > 8:
        raise ValueError("transformed recipe permits at most eight constants per leaf")
    unique = {}
    for value in values:
        scalar._scalar(value, scalar._type(value))
        unique[scalar._canonical(value)] = value
    return [unique[key] for key in sorted(unique)]


def _declaration(schema, path):
    for part in path:
        schema = schema["properties"][part] if type(part) is str else schema["items"]
    kind = schema["type"]
    result = {"type": kind}
    if kind == "integer":
        if not -10**12 <= schema["minimum"] <= schema["maximum"] <= 10**12:
            raise ValueError("composed source integer domain exceeds 10^12; no source may be omitted")
        result.update(min=schema["minimum"], max=schema["maximum"])
    elif kind == "string":
        result["max_length"] = schema["maxLength"]
    return result


def _catalog(episodes, index, domain):
    from . import action_recipe as recipe

    catalog, definitions, columns = [], {}, {}
    for source, values in recipe._sources(episodes, index):
        if recipe._kind(values[0]) not in _SUPPORTED:
            continue
        name = f"v{len(catalog):03d}"
        if len(catalog) >= MAX_SOURCE_LEAVES:
            raise ValueError("transformed recipe step exceeds six eligible source leaves")
        schema = (domain["inputs"] if source["source"] == "input"
                  else domain["steps"][source["step"]]["result"])
        definitions[name] = _declaration(schema, source["path"])
        catalog.append({"name": name, **source})
        columns[name] = values
    return catalog, definitions, columns


def _learn_step(episodes, index, domain, grammar, budget):
    from . import action_recipe as recipe

    first = episodes[0]["steps"][index]
    catalog, definitions, columns = _catalog(episodes, index, domain)
    seeds = [episode for episode in episodes if episode["id"] in grammar["seed_episode_ids"]]
    bindings = []
    for path, value in recipe._leaves(first["arguments"]):
        expected = [recipe._lookup(ep["steps"][index]["arguments"], path) for ep in episodes]
        if recipe._kind(value) in _SUPPORTED:
            constants = list(grammar["constants"])
            seed_values = [recipe._lookup(episode["steps"][index]["arguments"], path) for episode in seeds]
            seed_value = seed_values[0]
            if all(recipe._same(seed_value, output) for output in seed_values):
                # A coincident constant remains a distinct explanation. Deduplicate
                # the literal pool, but never remove it in favor of a copy.
                if not any(recipe._same(seed_value, item) for item in constants):
                    constants.append(seed_value)
            constants = _constants(constants)
            spec = {"inputs": definitions, "output_type": recipe._kind(value), "constants": constants}
            examples = [{"inputs": {name: values[row] for name, values in columns.items()}, "output": output}
                        for row, output in enumerate(expected)]
            artifact = composed.synthesize(spec, examples, max_operations=grammar["max_operations"],
                                           operators=grammar["operators"])
            bindings.append({"path": path, "kind": "composed", "candidate_count": artifact["candidate_count"],
                             "artifact": artifact})
        else:
            choices = [copy.deepcopy(source) for source, values in recipe._sources(episodes, index)
                       if budget.matching(values, expected)]
            if budget.matching([value] * len(episodes), expected):
                choices.append({"source": "constant", "value": value})
            if not choices:
                raise ValueError("copy-only argument has no matching source or stable constant")
            bindings.append({"path": path, "kind": "copy", "candidate_count": len(choices), "choices": choices})
    return {"tool": first["tool"], "arguments_shape": recipe._shape(first["arguments"]),
            "result_shape": recipe._shape(first["result"]), "catalog": catalog, "bindings": bindings}


def synthesize_transformed(episodes, *, allowed_tools, domain, max_operations=2, operators=None, constants=None):
    """Retain every bounded expression/copy explanation, or produce no artifact."""
    episodes, tools = _episodes(episodes, allowed_tools)
    grammar = {**composed._grammar(max_operations, operators),
               "constants": _constants([] if constants is None else constants),
               "unsupported_types": "copy_only", "constant_policy": "explicit_plus_stable_seed_target",
               "seed_episode_ids": [episode["id"] for episode in episodes]}
    return _build(episodes, tools, domain, grammar)


def _build(episodes, tools, domain, grammar):
    from . import action_recipe as recipe

    normalized = _domain(json.loads(_canonical(domain)), episodes)
    if sum(len(recipe._leaves(step["arguments"])) for step in episodes[0]["steps"]) > MAX_ARGUMENT_LEAVES:
        raise ValueError("transformed recipe exceeds eight total argument leaves")
    budget = recipe._Budget()
    steps = [_learn_step(episodes, index, normalized, grammar, budget) for index in range(len(episodes[0]["steps"]))]
    artifact = {"schema": SCHEMA, "allowed_tools": tools, "episodes": episodes,
                "episode_count": len(episodes), "episodes_sha256": _digest(episodes),
                "domain": normalized, "grammar": grammar, "input_shape": recipe._shape(episodes[0]["inputs"]),
                "steps": steps, "candidate_binding_count": sum(binding["candidate_count"]
                    for step in steps for binding in step["bindings"])}
    artifact["artifact_sha256"] = _digest(artifact)
    _canonical(artifact)
    return artifact


@lru_cache(maxsize=16)
def _validated(raw):
    artifact = json.loads(raw)
    fields = {"schema", "allowed_tools", "episodes", "episode_count", "episodes_sha256", "domain", "grammar",
              "input_shape", "steps", "candidate_binding_count", "artifact_sha256"}
    if type(artifact) is not dict or set(artifact) != fields or artifact["schema"] != SCHEMA:
        raise ValueError("invalid transformed recipe artifact schema")
    grammar = artifact["grammar"]
    if (type(grammar) is not dict or set(grammar) != _GRAMMAR_FIELDS
            or grammar["unsupported_types"] != "copy_only"
            or grammar["constant_policy"] != "explicit_plus_stable_seed_target"):
        raise ValueError("invalid transformed recipe grammar")
    episodes, tools = _episodes(artifact["episodes"], artifact["allowed_tools"])
    seeds = grammar["seed_episode_ids"]
    if (type(seeds) is not list or len(seeds) < 2 or any(type(identity) is not str for identity in seeds)
            or seeds != sorted(set(seeds)) or not set(seeds) <= {episode["id"] for episode in episodes}):
        raise ValueError("transformed recipe grammar requires retained original seed episode IDs")
    normalized_grammar = {**composed._grammar(grammar["max_operations"], grammar["operators"]),
                          "constants": _constants(grammar["constants"]), "unsupported_types": "copy_only",
                          "constant_policy": "explicit_plus_stable_seed_target", "seed_episode_ids": seeds}
    expected = _build(episodes, tools, artifact["domain"], normalized_grammar)
    if _canonical(expected) != raw:
        raise ValueError("transformed recipe does not match its complete learned alternatives")
    return expected


def validate_artifact(artifact):
    _validated(_canonical(artifact))


def refine(artifact, episodes):
    """Add reviewed raw evidence with the original domain and grammar unchanged."""
    verified = _validated(_canonical(artifact))
    if type(episodes) is not list:
        raise ValueError("new episodes must be a list")
    combined, tools = _episodes([*verified["episodes"], *episodes], verified["allowed_tools"])
    return _build(combined, tools, verified["domain"], copy.deepcopy(verified["grammar"]))


def validate_result(artifact, index, result):
    """Validate a parsed actual result, including completeness and declared bounds."""
    from . import action_recipe as recipe

    verified = _validated(_canonical(artifact))
    step = recipe._step(verified, index)
    recipe.require_complete_result(result)
    if recipe._shape(result) != step["result_shape"]:
        raise ValueError("recipe result does not match the step's exact typed shape")
    _matches(result, verified["domain"]["steps"][index]["result"])


def resolve_step(artifact, index, inputs, prior_results):
    """Resolve a complete typed argument object only when every alternative agrees."""
    from . import action_recipe as recipe

    try:
        verified = _validated(_canonical(artifact))
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return recipe.Decision(False, reason="invalid_artifact")
    identity, count = verified["artifact_sha256"], verified["candidate_binding_count"]

    def abstain(reason):
        return recipe.Decision(False, reason=reason, artifact_digest=identity, candidate_binding_count=count)

    try:
        inputs, prior_results = recipe._runtime(verified, index, inputs, prior_results)
        _matches(inputs, verified["domain"]["inputs"])
        for prior, result in enumerate(prior_results):
            _matches(result, verified["domain"]["steps"][prior]["result"])
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return abstain("outside_domain")
    step = verified["steps"][index]
    cost = sum(composed.evaluation_cost(binding["artifact"]) if binding["kind"] == "composed"
               else len(binding["choices"]) for binding in step["bindings"])
    if cost > MAX_STEP_EVALUATIONS:
        return abstain("evaluation_limit")
    flat = {source["name"]: recipe._bound_value(source, inputs, prior_results) for source in step["catalog"]}
    arguments = copy.deepcopy(verified["episodes"][0]["steps"][index]["arguments"])
    for binding in step["bindings"]:
        if binding["kind"] == "composed":
            decision = composed.evaluate(binding["artifact"], flat)
            if not decision.applied:
                return abstain(decision.reason)
            value = decision.value
        else:
            values = [recipe._bound_value(choice, inputs, prior_results) for choice in binding["choices"]]
            if any(not recipe._same(values[0], other) for other in values[1:]):
                return abstain("ambiguity")
            value = values[0]
        parent = recipe._lookup(arguments, binding["path"][:-1])
        parent[binding["path"][-1]] = value
    try:
        _matches(arguments, verified["domain"]["steps"][index]["arguments"])
    except ValueError:
        return abstain("outside_domain")
    return recipe.Decision(True, arguments, "agreement", identity, count)
