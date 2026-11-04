"""Schema dispatch for bounded pure operators, without migrating artifact bytes.

Scalar-v1 keeps its original representation and validation. Packed composed
artifacts expose counts and complete output partitions instead of expanded
program lists. No caller may select one representative from a packed state.
"""
from __future__ import annotations

import json

from . import learned_operator as scalar

COMPOSED_SCHEMA = "lightwork.composed-operator.v1"


def _engine(artifact: dict):
    if type(artifact) is not dict:
        raise ValueError("operator artifact must be an object")
    if artifact.get("schema") == scalar.SCHEMA:
        return scalar
    if artifact.get("schema") == COMPOSED_SCHEMA:
        from . import composed_operator

        return composed_operator
    raise ValueError("unsupported operator artifact schema")


def validate_artifact(artifact: dict) -> None:
    """Check the original schema's complete version space and content binding."""
    _engine(artifact).validate_artifact(artifact)


def validated_artifact(artifact: dict) -> dict:
    """Return a validated independent snapshot, preserving the original schema."""
    snapshot = json.loads(scalar._canonical(artifact))
    validate_artifact(snapshot)
    return snapshot


def candidate_count(artifact: dict) -> int:
    engine = _engine(artifact)
    if engine is scalar:
        return len(scalar._validated(scalar._canonical(artifact))["candidates"])
    return engine.candidate_count(artifact)


def evaluation_cost(artifact: dict) -> int:
    """Bound one query evaluation; packed cost is independent of program count."""
    engine = _engine(artifact)
    cost = candidate_count(artifact) if engine is scalar else engine.evaluation_cost(artifact)
    if type(cost) is not int or cost < 1:
        raise ValueError("operator evaluation cost must be a positive integer")
    return cost


def partitions(artifact: dict, inputs: dict) -> list[dict] | None:
    """Return every output and its multiplicity, or None on incomplete evaluation."""
    engine = _engine(artifact)
    if engine is not scalar:
        return engine.partitions(artifact, inputs)
    verified = scalar._validated(scalar._canonical(artifact))
    try:
        values = scalar._inputs(verified["spec"], inputs, exact=False)
    except (ValueError, TypeError):
        return None
    groups = {}
    for program in verified["candidates"]:
        value = scalar._run(program, values)
        try:
            scalar._scalar(value, verified["spec"]["output_type"], output=True)
        except ValueError:
            return None
        key = scalar._canonical(value)
        entry = groups.setdefault(key, {"output": value, "candidate_count": 0})
        entry["candidate_count"] += 1
    return [groups[key] for key in sorted(groups)]


def evaluate(artifact: dict, data: dict) -> scalar.Decision:
    try:
        engine = _engine(artifact)
    except (ValueError, TypeError):
        return scalar.Decision(False, reason="invalid_artifact")
    return engine.evaluate(artifact, data)


def refine(artifact: dict, examples: list[dict]) -> dict:
    """Keep the artifact's grammar and old evidence while adding reviewed labels."""
    return _engine(artifact).refine(artifact, examples)
