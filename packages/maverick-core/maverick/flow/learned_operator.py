"""Bounded executable learning from operator-supplied scalar examples.

The version space contains EVERY matching program in the documented finite
grammar, not a ranked winner. An unseen input is executable only when every
surviving program agrees. This is agreement within a grammar, never proof that
the examples, grammar or answer represent the intended business rule.

Artifacts contain their examples so an importer can independently reconstruct
the complete version space. SHA-256 binds contents; it is not authentication.
No generated Python, eval, network, model, tool, or credential access occurs.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

SCHEMA = "lightwork.learned-operator.v1"
MAX_ARTIFACT_BYTES = 262_144
MAX_EXAMPLES = 64
MAX_CANDIDATES = 1024
_MAX_SEARCH = 200_000
_MAX_INTEGER = 10**12
_MAX_RESULT_INTEGER = 10**24
_TYPES = frozenset({"integer", "string", "boolean"})
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}\Z")


@dataclass(frozen=True)
class Decision:
    applied: bool
    value: Any = None
    reason: str = ""
    artifact_digest: str = ""
    candidate_count: int = 0


def _canonical(value: Any) -> str:
    """Bound traversal BEFORE JSON encoding; reject subclasses and cycles too."""
    remaining = MAX_ARTIFACT_BYTES

    def walk(item, depth=0):
        nonlocal remaining
        remaining -= 8
        if remaining < 0 or depth > 14:
            raise ValueError("operator JSON exceeds size or depth limit")
        if type(item) is str:
            remaining -= len(item.encode("utf-8"))
        elif type(item) is int:
            if abs(item) > _MAX_RESULT_INTEGER:
                raise ValueError("operator integer exceeds limit")
        elif item is None or type(item) is bool:
            pass
        elif type(item) is list:
            for child in item:
                walk(child, depth + 1)
        elif type(item) is dict:
            for key, child in item.items():
                if type(key) is not str:
                    raise ValueError("operator JSON keys must be strings")
                walk(key, depth + 1)
                walk(child, depth + 1)
        else:
            raise ValueError("operator values must be strict finite JSON scalars/containers")
        if remaining < 0:
            raise ValueError("operator JSON exceeds size limit")

    walk(value)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if len(raw.encode("utf-8")) > MAX_ARTIFACT_BYTES:
        raise ValueError("operator JSON exceeds size limit")
    return raw


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _type(value: Any) -> str:
    if type(value) is bool:
        return "boolean"
    if type(value) is int:
        return "integer"
    if type(value) is str:
        return "string"
    raise ValueError("operator scalar must be integer, string or boolean")


def _scalar(value: Any, expected: str, *, output=False) -> None:
    if _type(value) != expected:
        raise ValueError("operator scalar type does not match declaration")
    if expected == "integer" and abs(value) > (_MAX_RESULT_INTEGER if output else _MAX_INTEGER):
        raise ValueError("operator integer exceeds limit")
    if expected == "string" and len(value) > 1024:
        raise ValueError("operator string exceeds limit")
    if expected == "string":
        try:
            value.encode("utf-8")
        except UnicodeError as exc:
            raise ValueError("operator string must be valid Unicode") from exc


def _spec(raw: dict) -> dict:
    if type(raw) is not dict or set(raw) - {"inputs", "output_type", "constants"}:
        raise ValueError("invalid operator specification")
    inputs = raw.get("inputs")
    if type(inputs) is not dict or not 1 <= len(inputs) <= 6:
        raise ValueError("operator requires one to six named inputs")
    output = raw.get("output_type")
    if type(output) is not str or output not in _TYPES:
        raise ValueError("invalid operator output type")
    normalized = {}
    for name, declaration in sorted(inputs.items()):
        if type(name) is not str or not _NAME.fullmatch(name):
            raise ValueError("operator input names must be simple identifiers")
        if type(declaration) is not dict:
            raise ValueError("operator input declaration must be an object")
        kind = declaration.get("type")
        if type(kind) is not str or kind not in _TYPES:
            raise ValueError("invalid operator input type")
        required = {"type"}
        if kind == "integer":
            required |= {"min", "max"}
            low, high = declaration.get("min"), declaration.get("max")
            _scalar(low, "integer")
            _scalar(high, "integer")
            if low > high:
                raise ValueError("operator integer bounds are reversed")
        elif kind == "string":
            required.add("max_length")
            length = declaration.get("max_length")
            if type(length) is not int or not 1 <= length <= 1024:
                raise ValueError("operator max_length must be between 1 and 1024")
        if set(declaration) != required:
            raise ValueError("operator input declaration has missing or unknown fields")
        normalized[name] = dict(declaration)
    constants = raw.get("constants", [])
    if type(constants) is not list or len(constants) > 8:
        raise ValueError("operator permits at most eight explicit constants")
    unique = {}
    for value in constants:
        _scalar(value, _type(value))
        unique[_canonical(value)] = value
    return {"inputs": normalized, "output_type": output,
            "constants": [unique[key] for key in sorted(unique)]}


def _inputs(spec: dict, raw: Any, *, exact: bool) -> dict:
    if type(raw) is not dict:
        raise ValueError("operator inputs must be an object")
    definitions = spec["inputs"]
    if exact and set(raw) != set(definitions):
        raise ValueError("example inputs must exactly match the declared fields")
    result = {}
    for name, declaration in definitions.items():
        if name not in raw:
            raise ValueError("operator input is missing")
        value = raw[name]
        kind = declaration["type"]
        _scalar(value, kind)
        if kind == "integer" and not declaration["min"] <= value <= declaration["max"]:
            raise ValueError("operator input is outside numeric bounds")
        if kind == "string" and len(value) > declaration["max_length"]:
            raise ValueError("operator input is outside string bounds")
        result[name] = value
    return result


def _examples(spec: dict, raw: list) -> list:
    if type(raw) is not list or not 2 <= len(raw) <= MAX_EXAMPLES:
        raise ValueError("operator requires two to 64 examples")
    rows, seen = [], {}
    for row in raw:
        if type(row) is not dict or set(row) != {"inputs", "output"}:
            raise ValueError("example must contain only inputs and output")
        inputs = _inputs(spec, row["inputs"], exact=True)
        _scalar(row["output"], spec["output_type"], output=True)
        key, target = _canonical(inputs), _canonical(row["output"])
        if key in seen and seen[key] != target:
            raise ValueError("conflicting outputs for the same example inputs")
        seen[key] = target
        rows.append({"inputs": inputs, "output": row["output"]})
    if len(seen) < 2:
        raise ValueError("operator requires at least two distinct input records")
    # Duplicated demonstrations must not manufacture support or change identity.
    return [{"inputs": json.loads(key), "output": json.loads(seen[key])}
            for key in sorted(seen)]


def _run(program: list, values: dict) -> Any:
    op = program[0]
    if op == "field":
        return values[program[1]]
    if op == "literal":
        return program[1]
    if op == "if":
        return _run(program[2] if _run(program[1], values) else program[3], values)
    left = _run(program[1], values)
    if op == "strip":
        return left.strip()
    if op == "lower":
        return left.lower()
    if op == "upper":
        return left.upper()
    if op == "not":
        return not left
    right = _run(program[2], values)
    if op == "add":
        return left + right
    if op == "sub":
        return left - right
    if op == "mul":
        return left * right
    if op == "min":
        return min(left, right)
    if op == "max":
        return max(left, right)
    if op == "eq":
        return left == right
    if op == "lt":
        return left < right
    if op == "le":
        return left <= right
    raise ValueError("unknown operator instruction")


def _base_programs(atoms: dict, output: str):
    yield from atoms[output]
    if output in {"string", "boolean"}:
        for atom in atoms[output]:
            for op in (("strip", "lower", "upper") if output == "string" else ("not",)):
                yield [op, atom]
    if output == "integer":
        for left in atoms[output]:
            for right in atoms[output]:
                if left[0] == right[0] == "literal":
                    continue
                for op in ("add", "sub", "mul", "min", "max"):
                    if op != "sub" and _canonical(left) > _canonical(right):
                        continue
                    yield [op, left, right]


def _predicates(atoms: dict):
    yield from atoms["boolean"]
    for kind, group in sorted(atoms.items()):
        for left in group:
            for right in group:
                if left[0] == right[0] == "literal":
                    continue
                for op in (("eq", "lt", "le") if kind == "integer" else ("eq",)):
                    if op == "eq" and _canonical(left) > _canonical(right):
                        continue
                    yield [op, left, right]


def _conditional_programs(predicates: list, arms: list, vector, target: tuple):
    for predicate in predicates:
        tests = vector(predicate)
        true_arms, false_arms = [], []
        for arm in arms:
            results = tuple(_canonical(value) for value in vector(arm))
            if all(results[i] == target[i] for i, test in enumerate(tests) if test):
                true_arms.append(arm)
            if all(results[i] == target[i] for i, test in enumerate(tests) if not test):
                false_arms.append(arm)
        for left in true_arms:
            for right in false_arms:
                if left != right:
                    yield ["if", predicate, left, right]


def _space(spec: dict, examples: list) -> list:
    """Exhaustively enumerate the scalar-v1 grammar, with sound pruning only.

    Atoms: declared inputs/constants. Programs: atoms; one string transform or
    boolean negation; one binary integer operation; atomic comparison; or a
    single conditional with an atomic predicate/comparison and atomic arms.
    Constant-only arithmetic/comparisons and syntactically identical arms are
    excluded by the grammar. No ranking or sample-equivalence pruning occurs.
    """
    atoms: dict[str, list] = {kind: [] for kind in _TYPES}
    for name, declaration in spec["inputs"].items():
        atoms[declaration["type"]].append(["field", name])
    for value in spec["constants"]:
        atoms[_type(value)].append(["literal", value])
    candidates, vectors = {}, {}
    examined = 0
    target = tuple(_canonical(row["output"]) for row in examples)

    def vector(program):
        key = _canonical(program)
        if key not in vectors:
            vectors[key] = tuple(_run(program, row["inputs"]) for row in examples)
        return vectors[key]

    def consider(program):
        nonlocal examined
        examined += 1
        if examined > _MAX_SEARCH:
            raise ValueError("operator grammar search limit exceeded; no artifact produced")
        results = vector(program)
        if tuple(_canonical(value) for value in results) != target:
            return
        for value in results:
            _scalar(value, spec["output_type"], output=True)
        candidates[_canonical(program)] = program
        if len(candidates) > MAX_CANDIDATES:
            raise ValueError("too many consistent programs; add distinguishing examples")

    output = spec["output_type"]
    for program in _base_programs(atoms, output):
        consider(program)
    predicates = list(_predicates(atoms))
    if output == "boolean":
        for predicate in predicates:
            consider(predicate)
    for program in _conditional_programs(predicates, atoms[output], vector, target):
        consider(program)
    if not candidates:
        raise ValueError("no program in the supported grammar matches all examples")
    return [candidates[key] for key in sorted(candidates)]


def synthesize(spec: dict, examples: list[dict]) -> dict:
    """Build a portable artifact; does not persist, activate or call a model."""
    # Snapshot caller-owned objects and bound their traversal before computation.
    raw = json.loads(_canonical({"spec": spec, "examples": examples}))
    normalized = _spec(raw["spec"])
    rows = _examples(normalized, raw["examples"])
    payload = {"schema": SCHEMA, "spec": normalized, "examples": rows,
               "candidates": _space(normalized, rows),
               "examples_sha256": _digest(rows), "example_count": len(rows)}
    payload["artifact_sha256"] = _digest(payload)
    _canonical(payload)
    return payload


@lru_cache(maxsize=16)
def _validated(raw: str) -> dict:
    artifact = json.loads(raw)
    required = {"schema", "spec", "examples", "candidates", "examples_sha256",
                "example_count", "artifact_sha256"}
    if type(artifact) is not dict or set(artifact) != required or artifact["schema"] != SCHEMA:
        raise ValueError("invalid learned operator artifact schema")
    if type(artifact["example_count"]) is not int:
        raise ValueError("invalid learned operator example count")
    if type(artifact["candidates"]) is not list or not 1 <= len(artifact["candidates"]) <= MAX_CANDIDATES:
        raise ValueError("invalid learned operator candidate count")
    # A digest alone would let a caller delete disagreeing candidates and create
    # false consensus. Reconstruct, compare, and cache only the validated bytes.
    expected = synthesize(artifact["spec"], artifact["examples"])
    if _canonical(expected) != raw:
        raise ValueError("operator artifact does not match its complete learned version space")
    return expected


def validate_artifact(artifact: dict) -> None:
    """Verify complete grammar coverage and integrity, not reviewer identity."""
    _validated(_canonical(artifact))


def evaluate(artifact: dict, data: dict) -> Decision:
    """Evaluate strict declared inputs, abstaining on ambiguity or invalid data."""
    try:
        verified = _validated(_canonical(artifact))
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return Decision(False, reason="invalid_artifact")
    digest = verified["artifact_sha256"]
    count = len(verified["candidates"])
    try:
        values = _inputs(verified["spec"], data, exact=False)
    except (ValueError, TypeError):
        return Decision(False, reason="outside_domain", artifact_digest=digest,
                        candidate_count=count)
    answer, encoded = None, None
    for program in verified["candidates"]:
        value = _run(program, values)
        try:
            _scalar(value, verified["spec"]["output_type"], output=True)
        except ValueError:
            return Decision(False, reason="outside_domain", artifact_digest=digest,
                            candidate_count=count)
        current = _canonical(value)
        if encoded is not None and current != encoded:
            return Decision(False, reason="ambiguity", artifact_digest=digest,
                            candidate_count=count)
        answer, encoded = value, current
    return Decision(True, answer, "agreement", digest, count)


def refine(artifact: dict, examples: list[dict]) -> dict:
    """Add reviewed counterexamples and rebuild without mutating the old asset.

    A contradictory label requires deliberate replacement of the old evidence;
    it must not silently erase previously approved observations.
    """
    verified = _validated(_canonical(artifact))
    if type(examples) is not list:
        raise ValueError("new examples must be a list")
    return synthesize(verified["spec"], [*verified["examples"], *examples])
