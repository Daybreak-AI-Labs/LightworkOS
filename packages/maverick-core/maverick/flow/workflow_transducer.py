"""Bounded next-action programs learned from complete, supplied action traces.

The explicit state abstraction is (last tool, set of tools already observed).
Every original-input leaf and latest-result leaf is available; previous results
and occurrence counters are not in this grammar. All consistent typed composed
expressions survive. State topology comes from observed histories, including END;
it is not arbitrary automaton inference or proof of a business policy.

Scalar argument constants must be explicit. Next-action expressions additionally
receive the fixed allowed-tool labels and END, so refinement does not quietly
change a literal pool. Float/null arguments support typed copies only. Search or
evaluation exhaustion never licenses a partial result. Revalidation interprets
history without dispatching or repeating any tool. Supplied traces/results have
no authenticated provenance here; native execution and signed lineage own that.
"""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from functools import lru_cache

from . import action_recipe as recipe
from . import action_recipe_transforms as transforms
from . import composed_operator as composed

SCHEMA = "lightwork.workflow-transducer.v1"
MAX_STEPS = 8
MAX_EPISODES = 32
MAX_TOOLS = 8
MAX_STATES = 32
MAX_SOURCE_LEAVES = 12
MAX_ARGUMENT_LEAVES = 8
MAX_PRODUCTIONS = 250_000
MAX_TRAINING_EVALUATIONS = 4_000_000
MAX_PACKED_STATES = 40_000
MAX_RESOLVE_EVALUATIONS = 200_000
_SUPPORTED = {"integer", "string", "boolean"}
_END = "complete"
_STATE_MODEL = "last_tool+available_latest_results.v1"
_FIELDS = {"schema", "allowed_tools", "domain", "max_steps", "episodes", "episode_count",
           "episodes_sha256", "grammar", "states", "candidate_binding_count",
           "guard_candidate_count", "artifact_sha256"}
_GRAMMAR_FIELDS = {"max_operations", "operators", "constants", "state_model",
                   "argument_constants", "guard_constants"}


@dataclass(frozen=True)
class WorkflowDecision:
    applied: bool
    kind: str = "refused"
    tool: str | None = None
    arguments: dict | None = None
    reason: str = ""
    artifact_digest: str = ""


class _Limit(ValueError):
    pass


def _snapshot(value):
    return json.loads(transforms._canonical(value))


def _tools(raw):
    if (type(raw) is not list or not 1 <= len(raw) <= MAX_TOOLS
            or any(type(tool) is not str or not tool.strip() or len(tool) > 128 for tool in raw)
            or len(set(raw)) != len(raw)):
        raise ValueError("workflow requires one to eight explicit unique tool names")
    return sorted(raw)


def _steps_limit(value):
    if type(value) is not int or not 1 <= value <= MAX_STEPS:
        raise ValueError("workflow max_steps must be an integer from one to eight")
    return value


def _grammar(max_operations, operators, constants):
    if type(max_operations) is not int or not 1 <= max_operations <= 2:
        raise ValueError("workflow grammar supports one or two operations per expression")
    return {**composed._grammar(max_operations, operators),
            "constants": transforms._constants([] if constants is None else constants),
            "state_model": _STATE_MODEL, "argument_constants": "explicit_only",
            "guard_constants": "explicit_plus_allowed_tools_and_end"}


def _domain(raw, tools):
    if type(raw) is not dict or set(raw) != {"inputs", "tools"}:
        raise ValueError("workflow domain requires exact inputs and tools schemas")
    if type(raw["tools"]) is not dict or set(raw["tools"]) != set(tools):
        raise ValueError("workflow domain must describe exactly the allowed tools")
    result = {"inputs": transforms._schema(raw["inputs"]), "tools": {}}
    if result["inputs"]["type"] != "object":
        raise ValueError("workflow inputs must be objects")
    for tool in tools:
        pair = raw["tools"][tool]
        if type(pair) is not dict or set(pair) != {"arguments", "result"}:
            raise ValueError("each workflow tool requires arguments and result schemas")
        checked = {key: transforms._schema(pair[key]) for key in ("arguments", "result")}
        if any(value["type"] != "object" for value in checked.values()):
            raise ValueError("workflow arguments and results must be complete objects")
        result["tools"][tool] = checked
    return result


def _observation(domain, tool, result):
    if type(tool) is not str or tool not in domain["tools"]:
        raise ValueError("workflow observation names an undeclared tool")
    recipe.require_complete_result(result)
    transforms._matches(result, domain["tools"][tool]["result"])


def _step(domain, step):
    if type(step) is not dict or set(step) != {"tool", "arguments", "result"}:
        raise ValueError("workflow history requires exact tool, arguments and result fields")
    _observation(domain, step["tool"], step["result"])
    transforms._matches(step["arguments"], domain["tools"][step["tool"]]["arguments"])


def _episodes(raw, domain, max_steps):
    if type(raw) is not list or not 2 <= len(raw) <= MAX_EPISODES:
        raise ValueError("workflow requires two to 32 complete episodes")
    episodes = _snapshot(raw)
    identities = set()
    for episode in episodes:
        if type(episode) is not dict or set(episode) != {"id", "inputs", "steps"}:
            raise ValueError("workflow episode has invalid fields")
        identity = episode["id"]
        if (type(identity) is not str or not identity.strip() or len(identity) > 128
                or identity in identities):
            raise ValueError("workflow episode identities must be nonempty and unique")
        identities.add(identity)
        transforms._matches(episode["inputs"], domain["inputs"])
        steps = episode["steps"]
        if type(steps) is not list or not 1 <= len(steps) <= max_steps:
            raise ValueError("complete workflow trace exceeds declared step bound")
        for step in steps:
            _step(domain, step)
    return sorted(episodes, key=lambda episode: episode["id"])


def _state(prior):
    return {"last_tool": prior[-1]["tool"] if prior else None,
            "available_results": sorted({step["tool"] for step in prior})}


def _state_id(state):
    return transforms._digest(state)


def _leaves(schema, path=()):
    kind = schema["type"]
    if kind == "object":
        for key, child in schema["properties"].items():
            yield from _leaves(child, (*path, key))
    elif kind == "array":
        for index in range(schema["minItems"]):
            yield from _leaves(schema["items"], (*path, index))
    else:
        yield list(path), kind


def _catalog(state, domain):
    catalog = []
    roots = [("input", None, domain["inputs"])]
    roots.extend(("latest_result", tool, domain["tools"][tool]["result"])
                 for tool in state["available_results"])
    for source, tool, schema in roots:
        for path, kind in _leaves(schema):
            catalog.append({"name": f"v{len(catalog):03d}", "source": source, "tool": tool,
                            "path": path, "type": kind})
    if len(catalog) > MAX_SOURCE_LEAVES:
        raise ValueError("workflow state exceeds twelve sources; no fields were omitted")
    return catalog


def _flat(catalog, inputs, prior):
    latest = {step["tool"]: step["result"] for step in prior}
    return {source["name"]: recipe._lookup(inputs if source["source"] == "input"
            else latest[source["tool"]], source["path"]) for source in catalog}


class _TrainingBudget:
    def __init__(self):
        self.productions = self.evaluations = self.states = 0

    def charge(self, rows):
        self.productions += 1
        self.evaluations += rows
        if self.productions > MAX_PRODUCTIONS or self.evaluations > MAX_TRAINING_EVALUATIONS:
            raise composed.SynthesisLimit("whole workflow synthesis limit; no partial artifact")


class _Builder(composed._Builder):
    def __init__(self, rows, budget):
        super().__init__(rows)
        self.budget = budget

    def add(self, kind, cost, production):
        self.budget.charge(len(self.examples))
        previous = len(self.states)
        super().add(kind, cost, production)
        self.budget.states += len(self.states) - previous
        if self.budget.states > MAX_PACKED_STATES:
            raise composed.SynthesisLimit("whole workflow packed-state limit; no partial artifact")


def _expression(kind, examples, catalog, grammar, constants, budget):
    # Empty source sets and a single distinct observation require no invented
    # inputs. The underlying complete finite builder supports these directly.
    definitions = {source["name"]: {"type": source["type"]}
                   for source in catalog if source["type"] in _SUPPORTED}
    unique = {}
    for values, output in examples:
        row = {"inputs": {name: values[name] for name in definitions}, "output": output}
        unique[transforms._canonical(row)] = row
    rows = [unique[key] for key in sorted(unique)]
    spec = {"inputs": definitions, "output_type": kind, "constants": constants}
    states, roots = _Builder(rows, budget).build(spec, grammar)
    return {"output_type": kind, "states": states, "roots": roots,
            "candidate_count": sum(states[index]["count"] for index in roots)}


def _learn_state(state, samples, domain, grammar, guard_constants, budget):
    catalog = _catalog(state, domain)
    rows = [(_flat(catalog, sample["inputs"], sample["prior"]), sample["next"]) for sample in samples]
    guard = _expression("string", [(values, _END if following is None else "action:" + following["tool"])
                                    for values, following in rows], catalog, grammar, guard_constants, budget)
    branches = []
    for tool in sorted({following["tool"] for _, following in rows if following is not None}):
        selected = [(values, following) for values, following in rows
                    if following is not None and following["tool"] == tool]
        leaves = list(_leaves(domain["tools"][tool]["arguments"]))
        if len(leaves) > MAX_ARGUMENT_LEAVES:
            raise ValueError("workflow action exceeds eight argument leaves")
        bindings = []
        for path, kind in leaves:
            examples = [(values, recipe._lookup(following["arguments"], path)) for values, following in selected]
            if kind in _SUPPORTED:
                child = _expression(kind, examples, catalog, grammar, grammar["constants"], budget)
                bindings.append({"path": path, "kind": "composed", "artifact": child,
                                 "candidate_count": child["candidate_count"]})
            else:
                choices = []
                for source in catalog:
                    budget.charge(len(examples))
                    if all(recipe._same(values[source["name"]], output) for values, output in examples):
                        choices.append(source["name"])
                if not choices:
                    raise ValueError("copy-only workflow argument has no consistent typed source")
                bindings.append({"path": path, "kind": "copy", "choices": choices,
                                 "candidate_count": len(choices)})
        branches.append({"tool": tool, "bindings": bindings})
    return {"id": _state_id(state), **state, "catalog": catalog, "guard": guard, "branches": branches}


def _build(episodes, tools, domain, grammar, max_steps):
    grouped = {}
    for episode in episodes:
        for index in range(len(episode["steps"]) + 1):
            prior = episode["steps"][:index]
            state = _state(prior)
            key = _state_id(state)
            if key not in grouped:
                grouped[key] = (state, [])
            grouped[key][1].append({"inputs": episode["inputs"], "prior": prior,
                "next": episode["steps"][index] if index < len(episode["steps"]) else None})
    if len(grouped) > MAX_STATES:
        raise ValueError("workflow exceeds its inferred-state limit")
    constants = {transforms._canonical(value): value for value in
                 [*grammar["constants"], _END, *("action:" + tool for tool in tools)]}
    guard_constants = [constants[key] for key in sorted(constants)]
    budget = _TrainingBudget()
    states = [_learn_state(state, rows, domain, grammar, guard_constants, budget)
              for _, (state, rows) in sorted(grouped.items())]
    artifact = {"schema": SCHEMA, "allowed_tools": tools, "domain": domain, "max_steps": max_steps,
        "episodes": episodes, "episode_count": len(episodes), "episodes_sha256": transforms._digest(episodes),
        "grammar": grammar, "states": states,
        "guard_candidate_count": sum(state["guard"]["candidate_count"] for state in states),
        "candidate_binding_count": sum(binding["candidate_count"] for state in states
                                       for branch in state["branches"] for binding in branch["bindings"])}
    artifact["artifact_sha256"] = transforms._digest(artifact)
    transforms._canonical(artifact)
    return artifact


def synthesize(episodes, *, allowed_tools, domain, max_operations=1, operators=None, constants=None, max_steps=8):
    """Learn the complete bounded history model; this authenticates no examples."""
    tools, limit = _tools(allowed_tools), _steps_limit(max_steps)
    checked_domain = _domain(_snapshot(domain), tools)
    grammar = _grammar(max_operations, operators, constants)
    checked = _episodes(episodes, checked_domain, limit)
    return _build(checked, tools, checked_domain, grammar, limit)


@lru_cache(maxsize=16)
def _validated(raw):
    artifact = json.loads(raw)
    if type(artifact) is not dict or set(artifact) != _FIELDS or artifact["schema"] != SCHEMA:
        raise ValueError("invalid workflow transducer artifact fields")
    grammar = artifact["grammar"]
    if type(grammar) is not dict or set(grammar) != _GRAMMAR_FIELDS:
        raise ValueError("invalid workflow transducer grammar fields")
    expected = synthesize(artifact["episodes"], allowed_tools=artifact["allowed_tools"], domain=artifact["domain"],
        max_operations=grammar["max_operations"], operators=grammar["operators"], constants=grammar["constants"],
        max_steps=artifact["max_steps"])
    if transforms._canonical(expected) != raw:
        raise ValueError("workflow artifact does not contain its complete inferred alternatives")
    return expected


def validate_artifact(artifact):
    _validated(transforms._canonical(artifact))


def refine(artifact, episodes):
    verified = _validated(transforms._canonical(artifact))
    if type(episodes) is not list:
        raise ValueError("workflow refinement requires an episode list")
    grammar = verified["grammar"]
    return synthesize([*verified["episodes"], *episodes], allowed_tools=verified["allowed_tools"],
        domain=verified["domain"], max_operations=grammar["max_operations"], operators=grammar["operators"],
        constants=grammar["constants"], max_steps=verified["max_steps"])


def validate_observation(artifact, tool, result):
    verified = _validated(transforms._canonical(artifact))
    _observation(verified["domain"], tool, _snapshot(result))


class _ResolveBudget:
    def __init__(self):
        self.used = 0

    def charge(self):
        self.used += 1
        if self.used > MAX_RESOLVE_EVALUATIONS:
            raise _Limit("whole workflow history evaluation limit")


class _Distribution(composed._Distribution):
    def __init__(self, artifact, values, budget):
        super().__init__(artifact, values)
        self.budget = budget

    def add(self, destination, value, count):
        self.budget.charge()
        super().add(destination, value, count)


def _agree(child, values, budget):
    outputs = _Distribution(child, values, budget).roots(child["roots"])
    if ("invalid",) in outputs:
        return False, None, "outside_domain"
    if len(outputs) != 1:
        return False, None, "ambiguity"
    return True, next(iter(outputs.values()))[0], "agreement"


def _template(schema):
    if schema["type"] == "object":
        return {key: _template(child) for key, child in schema["properties"].items()}
    if schema["type"] == "array":
        return [_template(schema["items"]) for _ in range(schema["minItems"])]
    return None


def _arguments(branch, values, schema, budget):
    result = _template(schema)
    for binding in branch["bindings"]:
        if binding["kind"] == "composed":
            applied, value, reason = _agree(binding["artifact"], values, budget)
            if not applied:
                return False, None, reason
        else:
            for _ in binding["choices"]:
                budget.charge()
            options = [values[name] for name in binding["choices"]]
            if any(not recipe._same(options[0], value) for value in options[1:]):
                return False, None, "ambiguity"
            value = options[0]
        target = result
        for part in binding["path"][:-1]:
            target = target[part]
        target[binding["path"][-1]] = copy.deepcopy(value)
    transforms._matches(result, schema)
    return True, result, "agreement"


def _refused(identity, reason):
    return WorkflowDecision(False, reason=reason, artifact_digest=identity)


def _next(verified, inputs, prior, budget):
    identity = verified["artifact_sha256"]
    key = _state_id(_state(prior))
    state = next((state for state in verified["states"] if state["id"] == key), None)
    if state is None:
        return _refused(identity, "unknown_state")
    values = _flat(state["catalog"], inputs, prior)
    applied, label, reason = _agree(state["guard"], values, budget)
    if not applied:
        return _refused(identity, reason)
    if label == _END:
        return WorkflowDecision(True, "complete", reason="agreement", artifact_digest=identity)
    branch = next((branch for branch in state["branches"] if label == "action:" + branch["tool"]), None)
    if branch is None:
        return _refused(identity, "unobserved_transition")
    if len(prior) >= verified["max_steps"]:
        return _refused(identity, "step_limit")
    applied, arguments, reason = _arguments(branch, values,
        verified["domain"]["tools"][branch["tool"]]["arguments"], budget)
    if not applied:
        return _refused(identity, reason)
    return WorkflowDecision(True, "action", branch["tool"], arguments, "agreement", identity)


def resolve_next(artifact, inputs, prior_steps):
    """Resolve only after checking every supplied historical call against consensus.

    The single evaluation budget covers the entire prefix and next decision.
    Matching results are bounded observations, not proof that a tool ran.
    """
    try:
        verified = _validated(transforms._canonical(artifact))
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return WorkflowDecision(False, reason="invalid_artifact")
    identity = verified["artifact_sha256"]
    try:
        snapshot = _snapshot({"inputs": inputs, "history": prior_steps})
        inputs, history = snapshot["inputs"], snapshot["history"]
        transforms._matches(inputs, verified["domain"]["inputs"])
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return _refused(identity, "outside_domain")
    if type(history) is not list or len(history) > verified["max_steps"]:
        return _refused(identity, "invalid_history")
    prefix, budget = [], _ResolveBudget()
    try:
        for observed in history:
            _step(verified["domain"], observed)
            expected = _next(verified, inputs, prefix, budget)
            if (not expected.applied or expected.kind != "action" or expected.tool != observed["tool"]
                    or not recipe._same(expected.arguments, observed["arguments"])):
                return _refused(identity, "invalid_history")
            prefix.append(observed)
        return _next(verified, inputs, prefix, budget)
    except (_Limit, composed._PredictionLimit):
        return _refused(identity, "evaluation_limit")
    except (ValueError, TypeError, KeyError, IndexError, RecursionError, UnicodeError):
        return _refused(identity, "invalid_history" if history else "outside_domain")
