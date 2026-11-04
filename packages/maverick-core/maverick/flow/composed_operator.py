"""Learn composed expressions without discarding observational alternatives.

The grammar contains directed typed expression trees with a bounded number of
operations. Training-equivalent trees share a state, but EVERY production is
retained. A packed state is a union of trees, not a representative expression.
Runtime partitions count their complete derivations; agreement never comes from
discarding a competing tree. No model, generated Python or tool execution occurs.
"""
from __future__ import annotations

import itertools
import json
from functools import lru_cache

from . import learned_operator as scalar

SCHEMA = "lightwork.composed-operator.v1"
MAX_OPERATIONS = 4
MAX_PRODUCTIONS = 250_000
MAX_STATES = 40_000
MAX_TRAINING_EVALUATIONS = 4_000_000
MAX_PREDICTION_EVALUATIONS = 100_000
MAX_PREDICTION_VALUES = 4096
_KINDS = ("boolean", "integer", "string")
_UNARY = {"strip": "string", "lower": "string", "upper": "string", "not": "boolean"}
_ARITHMETIC = frozenset({"add", "sub", "mul", "min", "max"})
_COMPARISONS = frozenset({"eq", "lt", "le"})
_OPERATORS = frozenset(_UNARY) | _ARITHMETIC | _COMPARISONS | {"if"}
_INVALID = object()


class SynthesisLimit(ValueError):
    """The complete declared grammar cannot be searched within fixed limits."""


class _PredictionLimit(ValueError):
    pass


def _grammar(max_operations, operators) -> dict:
    if type(max_operations) is not int or not 1 <= max_operations <= MAX_OPERATIONS:
        raise ValueError(f"max_operations must be an integer between 1 and {MAX_OPERATIONS}")
    if operators is None:
        operators = sorted(_OPERATORS)
    if (type(operators) is not list or not operators
            or any(type(op) is not str or op not in _OPERATORS for op in operators)
            or len(operators) != len(set(operators))):
        raise ValueError("operators must be a nonempty unique list of supported instructions")
    return {"max_operations": max_operations, "operators": sorted(operators)}


def _key(value):
    if value is _INVALID:
        return ("invalid",)
    return (scalar._type(value), value)


def _apply(op: str, args: tuple):
    if op == "if":
        if args[0] is _INVALID:
            return _INVALID
        return args[1] if args[0] else args[2]
    if any(value is _INVALID for value in args):
        return _INVALID
    left = args[0]
    if op == "strip":
        value = left.strip()
    elif op == "lower":
        value = left.lower()
    elif op == "upper":
        value = left.upper()
    elif op == "not":
        value = not left
    elif op == "add":
        value = left + args[1]
    elif op == "sub":
        value = left - args[1]
    elif op == "mul":
        value = left * args[1]
    elif op == "min":
        value = min(args)
    elif op == "max":
        value = max(args)
    elif op == "eq":
        value = left == args[1]
    elif op == "lt":
        value = left < args[1]
    elif op == "le":
        value = left <= args[1]
    else:
        raise ValueError("unknown composed instruction")
    try:
        scalar._scalar(value, scalar._type(value), output=True)
    except ValueError:
        return _INVALID
    return value


class _Builder:
    def __init__(self, examples):
        self.examples = examples
        self.states = []
        self.groups = {}
        self.layers = {}
        self.productions = 0
        self.evaluations = 0

    def add(self, kind, cost, production):
        self.productions += 1
        self.evaluations += len(self.examples)
        if (self.productions > MAX_PRODUCTIONS
                or self.evaluations > MAX_TRAINING_EVALUATIONS):
            raise SynthesisLimit("composed grammar search limit exceeded; no partial artifact produced")
        op = production[0]
        if op == "field":
            vector = tuple(row["inputs"][production[1]] for row in self.examples)
            count = 1
        elif op == "literal":
            vector = (production[1],) * len(self.examples)
            count = 1
        else:
            children = [self.states[index] for index in production[1:]]
            vector = tuple(_apply(op, args) for args in zip(*(state["values"] for state in children), strict=True))
            count = 1
            for state in children:
                count *= state["count"]
        key = (kind, cost, tuple(map(_key, vector)))
        index = self.groups.get(key)
        if index is None:
            if len(self.states) >= MAX_STATES:
                raise SynthesisLimit("composed grammar state limit exceeded; no partial artifact produced")
            index = len(self.states)
            self.groups[key] = index
            self.layers.setdefault((cost, kind), []).append(index)
            self.states.append({"kind": kind, "cost": cost, "values": vector,
                                "alternatives": [], "count": 0})
        state = self.states[index]
        state["alternatives"].append(production)
        state["count"] += count
        if state["count"] > 10**24:
            raise SynthesisLimit("composed program count exceeds exact artifact limit")

    def binary(self, op, cost):
        kinds = _KINDS if op == "eq" else ("integer",)
        for kind in kinds:
            output = "boolean" if op in _COMPARISONS else kind
            for left_cost in range(cost):
                left = self.layers.get((left_cost, kind), [])
                right = self.layers.get((cost - 1 - left_cost, kind), [])
                for a, b in itertools.product(left, right):
                    self.add(output, cost, [op, a, b])

    def conditional(self, cost):
        for predicate_cost in range(cost):
            predicates = self.layers.get((predicate_cost, "boolean"), [])
            if not predicates:
                continue
            for left_cost in range(cost - predicate_cost):
                right_cost = cost - 1 - predicate_cost - left_cost
                for kind in _KINDS:
                    left = self.layers.get((left_cost, kind), [])
                    right = self.layers.get((right_cost, kind), [])
                    for p, a, b in itertools.product(predicates, left, right):
                        self.add(kind, cost, ["if", p, a, b])

    def build(self, spec, grammar):
        for name, declaration in spec["inputs"].items():
            self.add(declaration["type"], 0, ["field", name])
        for value in spec["constants"]:
            self.add(scalar._type(value), 0, ["literal", value])
        for cost in range(1, grammar["max_operations"] + 1):
            for op in grammar["operators"]:
                if op in _UNARY:
                    kind = _UNARY[op]
                    for index in self.layers.get((cost - 1, kind), []):
                        self.add(kind, cost, [op, index])
                elif op == "if":
                    self.conditional(cost)
                else:
                    self.binary(op, cost)
        target = tuple(_key(row["output"]) for row in self.examples)
        roots = [index for cost in range(grammar["max_operations"] + 1)
                 for index in self.layers.get((cost, spec["output_type"]), [])
                 if tuple(map(_key, self.states[index]["values"])) == target]
        if not roots:
            raise ValueError("no composed program in the declared grammar matches all examples")
        return self.pack(roots)

    def pack(self, roots):
        reachable, pending = set(), list(roots)
        while pending:
            index = pending.pop()
            if index in reachable:
                continue
            reachable.add(index)
            for production in self.states[index]["alternatives"]:
                if production[0] not in {"field", "literal"}:
                    pending.extend(production[1:])
        remap = {old: new for new, old in enumerate(sorted(reachable))}
        packed = []
        for old in sorted(reachable):
            state = self.states[old]
            productions = [list(p) if p[0] in {"field", "literal"}
                           else [p[0], *(remap[index] for index in p[1:])]
                           for p in state["alternatives"]]
            packed.append({"kind": state["kind"], "cost": state["cost"],
                           "alternatives": productions, "count": state["count"]})
        return packed, [remap[index] for index in roots]


def synthesize(spec: dict, examples: list[dict], *, max_operations=3, operators=None) -> dict:
    """Infer complete bounded expression trees from final input/output examples."""
    grammar = _grammar(max_operations, operators)
    snapshot = json.loads(scalar._canonical({"spec": spec, "examples": examples}))
    normalized = scalar._spec(snapshot["spec"])
    rows = scalar._examples(normalized, snapshot["examples"])
    states, roots = _Builder(rows).build(normalized, grammar)
    count = sum(states[index]["count"] for index in roots)
    payload = {"schema": SCHEMA, "spec": normalized, "grammar": grammar,
               "examples": rows, "example_count": len(rows), "examples_sha256": scalar._digest(rows),
               "states": states, "roots": roots, "candidate_count": count}
    payload["artifact_sha256"] = scalar._digest(payload)
    scalar._canonical(payload)
    return payload


@lru_cache(maxsize=16)
def _validated(raw: str) -> dict:
    artifact = json.loads(raw)
    required = {"schema", "spec", "grammar", "examples", "example_count", "examples_sha256",
                "states", "roots", "candidate_count", "artifact_sha256"}
    if type(artifact) is not dict or set(artifact) != required or artifact["schema"] != SCHEMA:
        raise ValueError("invalid composed operator artifact schema")
    grammar = artifact["grammar"]
    if type(grammar) is not dict or set(grammar) != {"max_operations", "operators"}:
        raise ValueError("invalid composed operator grammar")
    expected = synthesize(artifact["spec"], artifact["examples"], **grammar)
    if scalar._canonical(expected) != raw:
        raise ValueError("composed artifact does not match its complete learned version space")
    return expected


def validate_artifact(artifact: dict) -> None:
    _validated(scalar._canonical(artifact))


def candidate_count(artifact: dict) -> int:
    return _validated(scalar._canonical(artifact))["candidate_count"]


class _Distribution:
    def __init__(self, artifact, values):
        self.states = artifact["states"]
        self.values = values
        self.cache = {}
        self.steps = 0

    def add(self, destination, value, count):
        self.steps += 1
        if self.steps > MAX_PREDICTION_EVALUATIONS:
            raise _PredictionLimit("composed evaluation budget exhausted")
        key = _key(value)
        if key in destination:
            destination[key][1] += count
        else:
            if len(destination) >= MAX_PREDICTION_VALUES:
                raise _PredictionLimit("composed output partition limit exceeded")
            destination[key] = [value, count]

    def branch(self, destination, production):
        _, predicate, yes, no = production
        for value, count in self.state(predicate).values():
            if value is _INVALID:
                self.add(destination, _INVALID, count * self.states[yes]["count"] * self.states[no]["count"])
                continue
            selected, unused = (yes, no) if value else (no, yes)
            for output, ways in self.state(selected).values():
                self.add(destination, output, count * ways * self.states[unused]["count"])

    def state(self, index):
        if index in self.cache:
            return self.cache[index]
        state = self.states[index]
        distribution = {}
        for production in state["alternatives"]:
            op = production[0]
            if op == "field":
                self.add(distribution, self.values[production[1]], 1)
            elif op == "literal":
                self.add(distribution, production[1], 1)
            elif op == "if":
                self.branch(distribution, production)
            else:
                children = [self.state(child).values() for child in production[1:]]
                for combination in itertools.product(*children):
                    count = 1
                    for _, ways in combination:
                        count *= ways
                    output = _apply(op, tuple(value for value, _ in combination))
                    self.add(distribution, output, count)
        if sum(count for _, count in distribution.values()) != state["count"]:
            raise ValueError("composed partition lost a represented expression")
        self.cache[index] = distribution
        return distribution

    def roots(self, roots):
        result = {}
        for index in roots:
            for value, count in self.state(index).values():
                self.add(result, value, count)
        return result


def _partitions(verified, inputs):
    values = scalar._inputs(verified["spec"], inputs, exact=False)
    distribution = _Distribution(verified, values).roots(verified["roots"])
    if ("invalid",) in distribution:
        return None
    return [{"output": value, "candidate_count": count}
            for value, count in sorted(distribution.values(), key=lambda row: scalar._canonical(row[0]))]


def partitions(artifact: dict, inputs: dict) -> list[dict] | None:
    """Exact weighted predictions; None means the complete partition is unavailable."""
    verified = _validated(scalar._canonical(artifact))
    try:
        return _partitions(verified, inputs)
    except (ValueError, TypeError):
        return None


def evaluation_cost(artifact: dict) -> int:
    """Conservative bound on distribution insertions per evaluated input.

    Each state's partitions/productions use no more additions than represented
    trees. Root merging adds at most another candidate_count. The interpreter
    stops at its hard budget even when that theoretical bound is larger.
    """
    verified = _validated(scalar._canonical(artifact))
    bound = sum(state["count"] for state in verified["states"]) + verified["candidate_count"]
    return min(MAX_PREDICTION_EVALUATIONS, bound)


def evaluate(artifact: dict, data: dict) -> scalar.Decision:
    try:
        verified = _validated(scalar._canonical(artifact))
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return scalar.Decision(False, reason="invalid_artifact")
    identity, count = verified["artifact_sha256"], verified["candidate_count"]
    try:
        result = _partitions(verified, data)
    except _PredictionLimit:
        return scalar.Decision(False, reason="evaluation_limit", artifact_digest=identity, candidate_count=count)
    except (ValueError, TypeError):
        return scalar.Decision(False, reason="outside_domain", artifact_digest=identity, candidate_count=count)
    if result is None:
        return scalar.Decision(False, reason="outside_domain", artifact_digest=identity, candidate_count=count)
    if len(result) != 1:
        return scalar.Decision(False, reason="ambiguity", artifact_digest=identity, candidate_count=count)
    return scalar.Decision(True, result[0]["output"], "agreement", identity, count)


def refine(artifact: dict, examples: list[dict]) -> dict:
    verified = _validated(scalar._canonical(artifact))
    if type(examples) is not list:
        raise ValueError("new examples must be a list")
    return synthesize(verified["spec"], [*verified["examples"], *examples], **verified["grammar"])
