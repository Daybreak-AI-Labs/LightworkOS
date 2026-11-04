"""The ``model-improvement`` read-outs as plain data: control posture and
taskset readiness (``status``), planning candidates for a role and memory
envelope (``models``) and deterministic taskset scoring (``score``).

The CLI prints these documents as JSON; the dashboard's Learning page shows
the same documents as tables. Nothing here trains, promotes or calls a model.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any


def strict_json_object(raw: str) -> dict:
    """Decode one finite JSON object without silently collapsing duplicate keys."""
    def reject_constant(token: str) -> object:
        raise ValueError(f"non-standard JSON constant {token!r}")

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
        decoded: dict[str, object] = {}
        for key, value in pairs:
            if key in decoded:
                raise ValueError(f"duplicate JSON field {key!r}")
            decoded[key] = value
        return decoded

    value = json.loads(
        raw,
        parse_constant=reject_constant,
        object_pairs_hook=reject_duplicate_keys,
    )
    if not isinstance(value, dict):
        raise ValueError("outputs must be a CASE_ID-to-output JSON object")
    return value


def status_report() -> dict[str, Any]:
    """Control posture, taskset readiness, and catalog identity."""
    from ..config import get_model_improvement
    from .environments import list_environment_ids, load_environment, promotion_readiness
    from .specialist_models import load_catalog

    settings = get_model_improvement()
    catalog = load_catalog()
    environments = []
    for environment_id in list_environment_ids():
        pack = load_environment(environment_id)
        environments.append(promotion_readiness(
            pack,
            minimum_train_families=settings["minimum_train_families"],
            minimum_holdout_families=settings["minimum_holdout_families"],
        ))
    return {
        "config": settings,
        "catalog": {
            "as_of": catalog.as_of,
            "sha256": catalog.digest,
            "candidates": len(catalog.models),
            "claim": "planning candidates; no model is production-qualified",
        },
        "environments": environments,
    }


def candidates_report(role: str, *, memory_gib: float, context_tokens: int = 16_384,
                      concurrency: int = 1) -> dict[str, Any]:
    """Planning candidates for one role and memory envelope."""
    from .specialist_models import candidate_matrix, load_catalog

    catalog = load_catalog()
    rows = []
    for candidate, estimate in candidate_matrix(
        role,
        available_memory_gib=memory_gib,
        context_tokens=context_tokens,
        concurrency=concurrency,
        catalog=catalog,
    ):
        rows.append({
            "catalog_id": candidate.catalog_id,
            "model_id": candidate.model_id,
            "upstream_revision": candidate.upstream_revision,
            "license": candidate.license,
            "status": candidate.status,
            "planning_priority": candidate.planning_priority,
            "estimate": asdict(estimate),
        })
    return {
        "catalog_sha256": catalog.digest,
        "role": role,
        "planning_only": True,
        "candidates": rows,
    }


def score_report(environment_id: str, outputs: dict, *, split: str = "holdout") -> dict[str, Any]:
    """Score a CASE_ID-to-output object against one taskset, without an LLM judge."""
    from .environments import evaluate_outputs, load_environment

    evaluation = evaluate_outputs(load_environment(environment_id), outputs, split=split)
    return {
        "schema": evaluation.schema,
        "environment_id": evaluation.environment_id,
        "environment_digest": evaluation.environment_digest,
        "split": evaluation.split,
        "score": evaluation.score,
        "pass_rate": evaluation.pass_rate,
        "evaluation_sha256": evaluation.digest,
        "missing_case_ids": list(evaluation.missing_case_ids),
        "extra_case_ids": list(evaluation.extra_case_ids),
        "results": [asdict(result) for result in evaluation.results],
    }


__all__ = ["candidates_report", "score_report", "status_report", "strict_json_object"]
