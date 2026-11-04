"""Ask bounded, discriminating questions of an executable operator's reviewer.

The score minimizes the largest surviving syntactic-candidate partition among
the inputs actually examined. It is not a probability or an information-gain
guarantee. Only an exhaustive census of a finite integer/boolean domain can
establish agreement everywhere in that declared domain. Other searches report
their budget and coverage explicitly, even when no disagreement is found.
"""
from __future__ import annotations

import hashlib
import itertools
import json
from collections import deque
from functools import lru_cache
from typing import Any

from . import learned_operator as engine
from . import operator_artifacts

SCHEMA = "lightwork.operator-question.v1"
MAX_PROBES = 4096
MAX_EVALUATIONS = 1_000_000
_MAX_POOL = 64


def _budget(value: int) -> int:
    if type(value) is not int or not 1 <= value <= MAX_PROBES:
        raise ValueError(f"max_probes must be an integer between 1 and {MAX_PROBES}")
    return value


def _cardinality(spec: dict) -> int | None:
    count = 1
    for field in spec["inputs"].values():
        if field["type"] == "string":
            return None
        count *= 2 if field["type"] == "boolean" else field["max"] - field["min"] + 1
        if count > 10**24:
            return None
    return count


def _unique(values, *, limit=_MAX_POOL):
    seen, result = set(), []
    for value in values:
        key = engine._canonical(value)
        if key not in seen:
            seen.add(key)
            result.append(value)
            if len(result) >= limit:
                break
    return result


def _numeric_seeds(artifact: dict) -> list[int]:
    seeds = [0, 1, -1, 2]
    seeds.extend(value for value in artifact["spec"]["constants"] if type(value) is int)
    for row in artifact["examples"]:
        seeds.extend(value for value in row["inputs"].values() if type(value) is int)
        if type(row["output"]) is int and abs(row["output"]) <= 10**12:
            seeds.append(row["output"])
    for declaration in artifact["spec"]["inputs"].values():
        if declaration["type"] == "integer":
            seeds.extend([declaration["min"], declaration["max"],
                          (declaration["min"] + declaration["max"]) // 2])
    return _unique(seeds, limit=512)


def _field_pools(artifact: dict) -> dict[str, list]:
    seeds = _numeric_seeds(artifact)
    pools = {}
    for name, field in artifact["spec"]["inputs"].items():
        kind = field["type"]
        if kind == "boolean":
            pools[name] = [False, True]
        elif kind == "integer":
            low, high = field["min"], field["max"]
            ordered = [low, high, (low + high) // 2]
            ordered.extend(value + shift for value in seeds for shift in (0, -1, 1))
            pools[name] = _unique(value for value in ordered if low <= value <= high)
        else:
            texts = [row["inputs"][name] for row in artifact["examples"]]
            texts += [value for value in artifact["spec"]["constants"] if type(value) is str]
            texts += ["", "a", "A", " a ", "ß", "0", "é", "fresh", "UNKNOWN"]
            variants = (version for text in texts for version in
                        (text, text.strip(), text.upper(), text.lower(), " " + text + " "))
            pools[name] = _unique(text[:field["max_length"]] for text in variants)
    return pools


def _equal_pair_probes(spec: dict, anchors: list[dict], pools: dict):
    for left, right in itertools.combinations(spec["inputs"], 2):
        a, b = spec["inputs"][left], spec["inputs"][right]
        if a["type"] != b["type"]:
            continue
        if a["type"] == "integer":
            low, high = max(a["min"], b["min"]), min(a["max"], b["max"])
            if low > high:
                continue
            values = _unique(value for value in [low, high, (low + high) // 2,
                                                 *pools[left], *pools[right]] if low <= value <= high)
        else:
            values = _unique([*pools[left], *pools[right]])
        for value in values:
            for anchor in anchors:
                for shift in ((0, -1, 1) if a["type"] == "integer" else (0,)):
                    trial = dict(anchor)
                    trial[left] = value
                    trial[right] = value + shift if a["type"] == "integer" else value
                    try:
                        yield engine._inputs(spec, trial, exact=True)
                    except ValueError:
                        continue


def _single_field_probes(anchors: list[dict], pools: dict):
    # Interleave fields and anchors to avoid spending the entire budget on the
    # first field when another one contains the relevant decision boundary.
    width = max(map(len, pools.values()))
    for offset in range(width):
        for name, values in pools.items():
            if offset < len(values):
                for anchor in anchors:
                    yield {**anchor, name: values[offset]}


def _round_robin(streams):
    pending = deque(map(iter, streams))
    while pending:
        current = pending.popleft()
        try:
            yield next(current)
        except StopIteration:
            continue
        pending.append(current)


def _bounded_inputs(artifact: dict, budget: int):
    spec, pools = artifact["spec"], _field_pools(artifact)
    names = list(pools)
    anchors = [dict(row["inputs"]) for row in artifact["examples"][:4]]
    anchors.append({name: values[0] for name, values in pools.items()})
    combinations = (dict(zip(names, values, strict=True))
                    for values in itertools.product(*(pools[name] for name in names)))
    streams = [_equal_pair_probes(spec, anchors, pools),
               _single_field_probes(anchors, pools), combinations]
    seen = set()
    # Bound generation work as well as actual evaluations when streams overlap.
    for values in itertools.islice(_round_robin(streams), budget * 32):
        key = hashlib.sha256(engine._canonical(values).encode("utf-8")).digest()
        if key in seen:
            continue
        seen.add(key)
        yield values
        if len(seen) >= budget:
            return


def _exhaustive_inputs(spec: dict):
    # Caller MUST establish that the entire Cartesian product fits the budget
    # before constructing product(), which eagerly materializes each range.
    names, domains = [], []
    for name, declaration in spec["inputs"].items():
        names.append(name)
        domains.append([False, True] if declaration["type"] == "boolean"
                       else range(declaration["min"], declaration["max"] + 1))
    for values in itertools.product(*domains):
        yield dict(zip(names, values, strict=True))


def _partitions(artifact: dict, inputs: dict) -> list[dict] | None:
    return operator_artifacts.partitions(artifact, inputs)


@lru_cache(maxsize=16)
def _proposal(raw: str, max_probes: int) -> str:
    artifact = operator_artifacts.validated_artifact(json.loads(raw))
    candidate_count = operator_artifacts.candidate_count(artifact)
    budget = min(max_probes, MAX_EVALUATIONS // operator_artifacts.evaluation_cost(artifact))
    domain_size = _cardinality(artifact["spec"])
    exhaustive = domain_size is not None and domain_size <= budget
    values = (_exhaustive_inputs(artifact["spec"]) if exhaustive
              else _bounded_inputs(artifact, budget))
    examined, invalid, best = 0, 0, None
    for inputs in values:
        examined += 1
        partitions = _partitions(artifact, inputs)
        if partitions is None:
            invalid += 1
            continue
        if len(partitions) < 2:
            continue
        worst = max(row["candidate_count"] for row in partitions)
        score = (worst, -len(partitions), engine._canonical(inputs))
        if best is None or score < best[0]:
            best = (score, inputs, partitions)
    complete = exhaustive and examined == domain_size and invalid == 0
    question = {
        "schema": SCHEMA, "artifact_sha256": artifact["artifact_sha256"],
        "status": "found" if best else ("equivalent" if complete else "search_exhausted"),
        "candidate_count": candidate_count,
        "predictions": [],
        "worst_case_candidates": best[0][0] if best else None,
        "coverage": {"strategy": "exhaustive" if exhaustive else "bounded",
                     "domain_size": domain_size, "examined": examined, "complete": complete,
                     "requested_probe_budget": max_probes, "effective_probe_budget": budget,
                     "invalid_probes": invalid},
    }
    if best:
        question.update(inputs=best[1], predictions=best[2])
    question["question_sha256"] = engine._digest(question)
    return engine._canonical(question)


def propose_question(artifact: dict, *, max_probes: int = 256) -> dict:
    """Propose a distinguishing input, without assigning its correct answer.

    A full finite-domain census can establish equivalence within that domain and
    this grammar only. Returned objects are independent copies, including when
    deterministic query computation was served from the bounded content cache.
    """
    return json.loads(_proposal(engine._canonical(artifact), _budget(max_probes)))


def validate_question(artifact: dict, question: dict) -> None:
    """Reconstruct the complete proposal, including claimed search coverage."""
    raw = engine._canonical(question)
    snapshot = json.loads(raw)
    if type(snapshot) is not dict or type(snapshot.get("coverage")) is not dict:
        raise ValueError("invalid operator question")
    budget = _budget(snapshot["coverage"].get("requested_probe_budget"))
    expected = _proposal(engine._canonical(artifact), budget)
    if raw != expected:
        raise ValueError("operator question does not match the artifact and search coverage")


def answer_question(artifact: dict, question: dict, output: Any) -> dict:
    """Apply one reviewed label, preserving the previous artifact and evidence.

    Caller authentication and review lineage belong to the governed service.
    A label outside every surviving hypothesis rejects the refinement rather
    than silently enlarging the grammar or discarding earlier examples.
    """
    artifact = json.loads(engine._canonical(artifact))
    question = json.loads(engine._canonical(question))
    validate_question(artifact, question)
    if question["status"] != "found":
        raise ValueError("only a found distinguishing question can be answered")
    return operator_artifacts.refine(artifact, [{"inputs": question["inputs"], "output": output}])
