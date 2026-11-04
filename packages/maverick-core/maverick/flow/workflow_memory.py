"""Jointly learn one bounded integer history program and its decision rules.

The fixed family includes the ordinary no-memory model, plus initial zero/each
integer input leaf, optionally updated on one tool/result integer leaf by
replace/add/subtract/min/max. Retain is one initializer-only model. Every
consistent summary is kept with its own complete packed decision expressions;
summaries never exchange values or decision rules. This is a declared finite
history abstraction, not arbitrary latent-state or business-policy inference.

Native provenance and permission remain separate. Supplied history is replayed
as data, never by dispatching tools. No caller checkpoint is trusted. Exhausted
search fails the entire family; it cannot remove inconvenient interpretations.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
from functools import lru_cache

from . import action_recipe as recipe
from . import action_recipe_transforms as transforms
from . import composed_operator as composed
from . import workflow_transducer as workflow
from .workflow_transducer import WorkflowDecision

SCHEMA = "lightwork.workflow-memory.v1"
MAX_SUMMARY_MODELS = 256
MAX_SOURCE_LEAVES = 13  # The unchanged twelve ordinary leaves plus one cell.
MAX_INTEGER = 10**24
MAX_ARTIFACT_BYTES = 1024 * 1024
MAX_PRODUCTIONS = 1_000_000
MAX_TRAINING_EVALUATIONS = 16_000_000
MAX_PACKED_STATES = 160_000
MAX_RESOLVE_EVALUATIONS = 1_000_000
_FAMILY = "zero_or_integer_input+single_tool_integer_leaf.v1"
_STATE_MODEL = "last_tool+available_latest_results+optional_integer_memory.v1"
_OPS = ("replace", "add", "subtract", "min", "max")
_FIELDS = {"schema", "allowed_tools", "domain", "max_steps", "episodes", "episode_count",
           "episodes_sha256", "grammar", "models", "enumerated_model_count", "model_count",
           "guard_candidate_count", "candidate_binding_count", "artifact_sha256"}
_GRAMMAR_FIELDS = {"max_operations", "operators", "constants", "state_model", "memory_family",
                   "memory_integer_limit", "argument_constants", "guard_constants"}
_NO_ROOT = "no composed program in the declared grammar matches all examples"


class _Contradiction(ValueError):
    """A complete search or concrete trace proves this model inconsistent."""


class _MemoryOverflow(ValueError):
    pass


def _canonical(value):
    remaining, active = MAX_ARTIFACT_BYTES, set()

    def walk(item, depth=0):
        nonlocal remaining
        remaining -= 8
        if depth > 40 or remaining < 0:
            raise ValueError("workflow memory JSON exceeds structural limit")
        kind = type(item)
        if kind is str:
            if len(item) > 1024:
                raise ValueError("workflow memory string exceeds limit")
            remaining -= len(item.encode("utf-8"))
        elif kind is int:
            if item.bit_length() > 256:
                raise ValueError("workflow memory integer exceeds JSON limit")
        elif kind is float:
            if not math.isfinite(item):
                raise ValueError("workflow memory requires finite numbers")
        elif item is None or kind is bool:
            pass
        elif kind in (list, dict):
            if id(item) in active:
                raise ValueError("workflow memory requires acyclic JSON")
            active.add(id(item))
            if kind is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise ValueError("workflow memory keys must be strings")
                    walk(key, depth + 1)
                    walk(child, depth + 1)
            else:
                for child in item:
                    walk(child, depth + 1)
            active.remove(id(item))
        else:
            raise ValueError("workflow memory requires strict JSON")
        if remaining < 0:
            raise ValueError("workflow memory JSON exceeds byte limit")

    walk(value)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    if len(raw.encode("utf-8")) > MAX_ARTIFACT_BYTES:
        raise ValueError("workflow memory artifact exceeds byte limit")
    return raw


def _digest(value):
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _grammar(max_operations, operators, constants):
    return {**workflow._grammar(max_operations, operators, constants), "state_model": _STATE_MODEL,
            "memory_family": _FAMILY, "memory_integer_limit": MAX_INTEGER}


def _family(domain):
    initializers = [{"source": "zero"}, *({"source": "input", "path": path}
                    for path, kind in workflow._leaves(domain["inputs"]) if kind == "integer")]
    sources = [{"tool": tool, "path": path} for tool, pair in domain["tools"].items()
               for path, kind in workflow._leaves(pair["result"]) if kind == "integer"]
    size = 1 + len(initializers) * (1 + len(sources) * len(_OPS))
    if size > MAX_SUMMARY_MODELS:
        raise composed.SynthesisLimit("complete workflow memory family exceeds model cap")
    result = [{"kind": "none"}]
    for initial in initializers:
        result.append({"kind": "integer", "initial": initial, "update": None})
        for source in sources:
            result.extend({"kind": "integer", "initial": initial, "update": {**source, "op": op}}
                          for op in _OPS)
    return result


def _integer(value):
    if type(value) is not int or abs(value) > MAX_INTEGER:
        raise _MemoryOverflow("integer memory overflow")
    return value


def _initial(summary, inputs):
    if summary["kind"] == "none":
        return None
    initial = summary["initial"]
    return _integer(0 if initial["source"] == "zero" else recipe._lookup(inputs, initial["path"]))


def _advance(summary, value, observed, budget):
    budget.charge()
    update = summary.get("update")
    if update is None or observed["tool"] != update["tool"]:
        return value
    incoming = recipe._lookup(observed["result"], update["path"])
    op = update["op"]
    if op == "replace":
        return _integer(incoming)
    if op == "add":
        return _integer(value + incoming)
    if op == "subtract":
        return _integer(value - incoming)
    if op == "min":
        return _integer(min(value, incoming))
    return _integer(max(value, incoming))


class _TrainingBudget:
    def __init__(self):
        self.productions = self.evaluations = self.states = 0

    def charge(self, rows=1, *, production=False):
        self.productions += int(production)
        self.evaluations += rows
        if self.productions > MAX_PRODUCTIONS or self.evaluations > MAX_TRAINING_EVALUATIONS:
            raise composed.SynthesisLimit("whole memory family synthesis limit; no partial artifact")


class _Builder(composed._Builder):
    def __init__(self, rows, budget):
        super().__init__(rows)
        self.budget = budget

    def add(self, kind, cost, production):
        self.budget.charge(len(self.examples), production=True)
        previous = len(self.states)
        super().add(kind, cost, production)
        self.budget.states += len(self.states) - previous
        if self.budget.states > MAX_PACKED_STATES:
            raise composed.SynthesisLimit("whole memory family packed-state limit; no partial artifact")


def _expression(kind, examples, catalog, grammar, constants, budget):
    definitions = {source["name"]: {"type": source["type"]}
                   for source in catalog if source["type"] in workflow._SUPPORTED}
    unique, targets = {}, {}
    for values, output in examples:
        inputs = {name: values[name] for name in definitions}
        key, target = _canonical(inputs), _canonical(output)
        if key in targets and targets[key] != target:
            raise _Contradiction("identical observable state has conflicting targets")
        targets[key] = target
        row = {"inputs": inputs, "output": output}
        unique[_canonical(row)] = row
    rows = [unique[key] for key in sorted(unique)]
    spec = {"inputs": definitions, "output_type": kind, "constants": constants}
    try:
        states, roots = _Builder(rows, budget).build(spec, grammar)
    except ValueError as exc:
        # Resource errors are subclasses, and must abort the WHOLE family.
        # Only the builder's completed no-root search proves inconsistency.
        if type(exc) is ValueError and str(exc) == _NO_ROOT:
            raise _Contradiction(_NO_ROOT) from exc
        raise
    return {"output_type": kind, "states": states, "roots": roots,
            "candidate_count": sum(states[index]["count"] for index in roots)}


def _catalog(state, domain, summary):
    catalog = workflow._catalog(state, domain)
    if summary["kind"] != "none":
        catalog.append({"name": "memory", "source": "memory", "tool": None, "path": [], "type": "integer"})
    if len(catalog) > MAX_SOURCE_LEAVES:
        raise composed.SynthesisLimit("memory sources exceed cap; no fields omitted")
    return catalog


def _values(catalog, inputs, prior, memory):
    ordinary = [source for source in catalog if source["source"] != "memory"]
    values = workflow._flat(ordinary, inputs, prior)
    if len(ordinary) != len(catalog):
        values["memory"] = memory
    return values


def _bindings(tool, selected, catalog, domain, grammar, budget):
    bindings = []
    for path, kind in workflow._leaves(domain["tools"][tool]["arguments"]):
        examples = [(values, recipe._lookup(following["arguments"], path)) for values, following in selected]
        if kind in workflow._SUPPORTED:
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
                raise _Contradiction("no consistent typed copy source")
            bindings.append({"path": path, "kind": "copy", "choices": choices, "candidate_count": len(choices)})
    return bindings


def _learn_state(state, samples, domain, summary, grammar, guard_constants, budget):
    catalog = _catalog(state, domain, summary)
    rows = [(_values(catalog, sample["inputs"], sample["prior"], sample["memory"]), sample["next"])
            for sample in samples]
    guard = _expression("string", [(values, workflow._END if following is None else "action:" + following["tool"])
                                    for values, following in rows], catalog, grammar, guard_constants, budget)
    branches = []
    for tool in sorted({following["tool"] for _, following in rows if following is not None}):
        selected = [(values, following) for values, following in rows
                    if following is not None and following["tool"] == tool]
        branches.append({"tool": tool, "bindings": _bindings(tool, selected, catalog, domain, grammar, budget)})
    return {"id": workflow._state_id(state), **state, "catalog": catalog, "guard": guard, "branches": branches}


def _samples(episodes, summary, budget):
    grouped = {}
    for episode in episodes:
        memory, prior = _initial(summary, episode["inputs"]), []
        for index in range(len(episode["steps"]) + 1):
            state = workflow._state(prior)
            key = workflow._state_id(state)
            if key not in grouped:
                grouped[key] = (state, [])
            following = episode["steps"][index] if index < len(episode["steps"]) else None
            grouped[key][1].append({"inputs": episode["inputs"], "prior": prior[:],
                                   "next": following, "memory": memory})
            if following is not None:
                memory = _advance(summary, memory, following, budget)
                prior.append(following)
    return grouped


def _model(episodes, summary, domain, grammar, guard_constants, budget):
    try:
        grouped = _samples(episodes, summary, budget)
    except _MemoryOverflow as exc:
        raise _Contradiction("concrete training history overflows this memory program") from exc
    states = [_learn_state(state, rows, domain, summary, grammar, guard_constants, budget)
              for _, (state, rows) in sorted(grouped.items())]
    return {"summary": copy.deepcopy(summary), "states": states,
            "guard_candidate_count": sum(state["guard"]["candidate_count"] for state in states),
            "candidate_binding_count": sum(binding["candidate_count"] for state in states
                for branch in state["branches"] for binding in branch["bindings"])}


def synthesize(episodes, *, allowed_tools, domain, max_operations=1, operators=None, constants=None, max_steps=8):
    return _synthesize(episodes, allowed_tools=allowed_tools, domain=domain, max_operations=max_operations,
                       operators=operators, constants=constants, max_steps=max_steps)


def _synthesize(episodes, *, allowed_tools, domain, max_operations=1, operators=None, constants=None,
                max_steps=8, budget=None):
    """Private reconstruction seam; callers may share one complete search budget."""
    tools, limit = workflow._tools(allowed_tools), workflow._steps_limit(max_steps)
    declared = workflow._domain(workflow._snapshot(domain), tools)
    grammar = _grammar(max_operations, operators, constants)
    examples = workflow._episodes(episodes, declared, limit)
    summaries = _family(declared)
    budget = _TrainingBudget() if budget is None else budget
    # Structural/search limits are family-wide, never grounds to prune a model.
    baseline = _samples(examples, {"kind": "none"}, budget)
    if len(baseline) > workflow.MAX_STATES:
        raise composed.SynthesisLimit("memory workflow exceeds observed-state cap")
    for state, _ in baseline.values():
        _catalog(state, declared, {"kind": "integer"})
    if any(len(list(workflow._leaves(pair["arguments"]))) > workflow.MAX_ARGUMENT_LEAVES
           for pair in declared["tools"].values()):
        raise composed.SynthesisLimit("memory workflow exceeds action-argument cap")
    labels = {_canonical(value): value for value in
              [*grammar["constants"], workflow._END, *("action:" + tool for tool in tools)]}
    guard_constants = [labels[key] for key in sorted(labels)]
    models = []
    for summary in summaries:
        try:
            models.append(_model(examples, summary, declared, grammar, guard_constants, budget))
        except _Contradiction:
            continue
    if not models:
        raise ValueError("no memory model in the complete declared family matches all episodes")
    artifact = {"schema": SCHEMA, "allowed_tools": tools, "domain": declared, "max_steps": limit,
                "episodes": examples, "episode_count": len(examples), "episodes_sha256": _digest(examples),
                "grammar": grammar, "models": models, "enumerated_model_count": len(summaries),
                "model_count": len(models),
                "guard_candidate_count": sum(model["guard_candidate_count"] for model in models),
                "candidate_binding_count": sum(model["candidate_binding_count"] for model in models)}
    artifact["artifact_sha256"] = _digest(artifact)
    _canonical(artifact)
    return artifact


@lru_cache(maxsize=8)
def _validated(raw):
    artifact = json.loads(raw)
    if type(artifact) is not dict or set(artifact) != _FIELDS or artifact["schema"] != SCHEMA:
        raise ValueError("invalid workflow memory artifact fields")
    grammar = artifact["grammar"]
    if type(grammar) is not dict or set(grammar) != _GRAMMAR_FIELDS:
        raise ValueError("invalid workflow memory grammar fields")
    expected = synthesize(artifact["episodes"], allowed_tools=artifact["allowed_tools"], domain=artifact["domain"],
        max_operations=grammar["max_operations"], operators=grammar["operators"], constants=grammar["constants"],
        max_steps=artifact["max_steps"])
    if _canonical(expected) != raw:
        raise ValueError("workflow memory artifact omits or changes complete paired alternatives")
    return expected


def validate_artifact(artifact):
    _validated(_canonical(artifact))


def refine(artifact, episodes):
    checked = _validated(_canonical(artifact))
    if type(episodes) is not list:
        raise ValueError("memory refinement requires an episode list")
    grammar = checked["grammar"]
    return synthesize([*checked["episodes"], *episodes], allowed_tools=checked["allowed_tools"],
        domain=checked["domain"], max_operations=grammar["max_operations"], operators=grammar["operators"],
        constants=grammar["constants"], max_steps=checked["max_steps"])


def validate_observation(artifact, tool, result):
    checked = _validated(_canonical(artifact))
    workflow._observation(checked["domain"], tool, workflow._snapshot(result))


class _ResolveBudget:
    def __init__(self):
        self.used = 0

    def charge(self):
        self.used += 1
        if self.used > MAX_RESOLVE_EVALUATIONS:
            raise workflow._Limit("whole memory family history evaluation limit")


def _next_model(artifact, model, inputs, prior, memory, budget):
    identity = artifact["artifact_sha256"]
    key = workflow._state_id(workflow._state(prior))
    state = next((state for state in model["states"] if state["id"] == key), None)
    if state is None:
        return workflow._refused(identity, "unknown_state")
    values = _values(state["catalog"], inputs, prior, memory)
    applied, label, reason = workflow._agree(state["guard"], values, budget)
    if not applied:
        return workflow._refused(identity, reason)
    if label == workflow._END:
        return WorkflowDecision(True, "complete", reason="agreement", artifact_digest=identity)
    branch = next((branch for branch in state["branches"] if label == "action:" + branch["tool"]), None)
    if branch is None:
        return workflow._refused(identity, "unobserved_transition")
    if len(prior) >= artifact["max_steps"]:
        return workflow._refused(identity, "step_limit")
    applied, arguments, reason = workflow._arguments(branch, values,
        artifact["domain"]["tools"][branch["tool"]]["arguments"], budget)
    return (WorkflowDecision(True, "action", branch["tool"], arguments, "agreement", identity) if applied
            else workflow._refused(identity, reason))


def _next_all(artifact, inputs, prior, memories, budget):
    decision = None
    for model, memory in zip(artifact["models"], memories, strict=True):
        current = _next_model(artifact, model, inputs, prior, memory, budget)
        if not current.applied:
            return current
        if decision is not None and (current.kind != decision.kind or current.tool != decision.tool
                or _canonical(current.arguments) != _canonical(decision.arguments)):
            return workflow._refused(artifact["artifact_sha256"], "ambiguity")
        decision = current
    return decision


def resolve_next(artifact, inputs, prior_steps):
    try:
        checked = _validated(_canonical(artifact))
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return WorkflowDecision(False, reason="invalid_artifact")
    identity = checked["artifact_sha256"]
    try:
        snapshot = workflow._snapshot({"inputs": inputs, "history": prior_steps})
        inputs, history = snapshot["inputs"], snapshot["history"]
        transforms._matches(inputs, checked["domain"]["inputs"])
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return workflow._refused(identity, "outside_domain")
    if type(history) is not list or len(history) > checked["max_steps"]:
        return workflow._refused(identity, "invalid_history")
    budget, prefix = _ResolveBudget(), []
    try:
        memories = [_initial(model["summary"], inputs) for model in checked["models"]]
        for observed in history:
            workflow._step(checked["domain"], observed)
            expected = _next_all(checked, inputs, prefix, memories, budget)
            if (not expected.applied or expected.kind != "action" or expected.tool != observed["tool"]
                    or _canonical(expected.arguments) != _canonical(observed["arguments"])):
                return workflow._refused(identity, "invalid_history")
            memories = [_advance(model["summary"], value, observed, budget)
                        for model, value in zip(checked["models"], memories, strict=True)]
            prefix.append(observed)
        return _next_all(checked, inputs, prefix, memories, budget)
    except (workflow._Limit, composed._PredictionLimit):
        return workflow._refused(identity, "evaluation_limit")
    except _MemoryOverflow:
        return workflow._refused(identity, "memory_overflow")
    except (ValueError, TypeError, KeyError, IndexError, RecursionError, UnicodeError):
        return workflow._refused(identity, "invalid_history" if history else "outside_domain")
