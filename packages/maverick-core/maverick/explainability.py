"""Model-agnostic explainability: importance, dependence, reason codes.

Dependency-free implementations of the explainability battery a technical
evaluation asks for, sized for governed use rather than research: seeded
permutation importance (model reliance) and partial dependence for any
caller-supplied scoring callable, Spearman global sensitivity for logged
feature/score pairs when no callable is available, and standardized-deviation
reason codes for single decisions (the adverse-action style regulated
verticals expect). Every report can be recorded as bounded, digest-scoped
``explainability`` evidence against a governed asset. Decision support only —
never a fairness certification, a causal claim, or legal advice.
"""
from __future__ import annotations

import hashlib
import json
import math
import random
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from . import model_risk_assurance as mra

REPORT_SCHEMA = "lightwork.explainability-report.v1"
NON_CERTIFICATION_NOTICE = (
    "Model-agnostic attribution for the operator's own review; not a "
    "fairness certification, causal analysis, or legal advice."
)

_MAX_FEATURES = 64
_MAX_ROWS = 50_000
_MAX_GRID = 64
_MAX_REPEATS = 20


class ExplainabilityError(RuntimeError):
    """Base failure for governed explainability."""


class ExplainabilityConfigError(ExplainabilityError):
    """The feature is not enabled or configured safely."""


def get_explainability_config() -> dict[str, Any]:
    from .config import load_global_config

    try:
        config = load_global_config()
    except Exception as exc:
        raise ExplainabilityConfigError(
            "explainability configuration is unavailable"
        ) from exc
    section = (config or {}).get("explainability") or {}
    if not isinstance(section, dict):
        raise ExplainabilityConfigError("explainability must be a table")
    flag = section.get("enable", False)
    if not isinstance(flag, bool):
        raise ExplainabilityConfigError("explainability.enable must be a boolean")
    return {"enable": flag}


def enabled() -> bool:
    try:
        return get_explainability_config()["enable"] is True
    except Exception:
        return False


def _require_enabled() -> None:
    if not enabled():
        raise ExplainabilityConfigError(
            "explainability requires [explainability] enable = true"
        )


def _finite(value: object, label: str) -> float:
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a number") from exc
    if not math.isfinite(number):
        raise ValueError(f"{label} must be finite")
    return number


def _series(values: object, label: str, *, minimum: int = 2) -> list[float]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes, bytearray)):
        raise ValueError(f"{label} must be a bounded list of numbers")
    if len(values) < minimum or len(values) > _MAX_ROWS:
        raise ValueError(f"{label} must contain between {minimum} and {_MAX_ROWS} values")
    return [_finite(value, f"{label}[{index}]") for index, value in enumerate(values)]


def _feature_table(features: object) -> dict[str, list[float]]:
    if not isinstance(features, Mapping) or not features or len(features) > _MAX_FEATURES:
        raise ValueError("features must be a bounded, non-empty mapping")
    table: dict[str, list[float]] = {}
    length: int | None = None
    for raw_name in sorted(features, key=str):
        name = str(raw_name).strip()
        if not name or len(name) > 128:
            raise ValueError("feature names must be short non-empty strings")
        series = _series(features[raw_name], f"feature {name}")
        if length is None:
            length = len(series)
        elif len(series) != length:
            raise ValueError("every feature must have the same number of rows")
        table[name] = series
    return table


def _ranks(values: Sequence[float]) -> list[float]:
    order = sorted(range(len(values)), key=lambda index: values[index])
    ranks = [0.0] * len(values)
    position = 0
    while position < len(order):
        tied_end = position
        while (
            tied_end + 1 < len(order)
            and values[order[tied_end + 1]] == values[order[position]]
        ):
            tied_end += 1
        average = (position + tied_end) / 2.0 + 1.0
        for index in range(position, tied_end + 1):
            ranks[order[index]] = average
        position = tied_end + 1
    return ranks


def _pearson(left: Sequence[float], right: Sequence[float]) -> float:
    count = len(left)
    mean_left = sum(left) / count
    mean_right = sum(right) / count
    cov = sum(
        (a - mean_left) * (b - mean_right) for a, b in zip(left, right, strict=True)
    )
    var_left = sum((a - mean_left) ** 2 for a in left)
    var_right = sum((b - mean_right) ** 2 for b in right)
    if var_left <= 0 or var_right <= 0:
        return 0.0
    return cov / math.sqrt(var_left * var_right)


def spearman_correlation(left: Sequence[object], right: Sequence[object]) -> float:
    """Spearman rank correlation with average-rank tie handling."""

    a = _series(left, "left series")
    b = _series(right, "right series")
    if len(a) != len(b):
        raise ValueError("series must have the same length")
    return round(_pearson(_ranks(a), _ranks(b)), 12)


def global_sensitivity(
    features: Mapping[str, Sequence[object]],
    scores: Sequence[object],
) -> dict[str, Any]:
    """Rank features by |Spearman| against logged scores — no callable needed."""

    _require_enabled()
    table = _feature_table(features)
    outcome = _series(scores, "scores")
    any_length = len(next(iter(table.values())))
    if len(outcome) != any_length:
        raise ValueError("scores must align with the feature rows")
    rows = [
        {
            "feature": name,
            "spearman": spearman_correlation(values, outcome),
        }
        for name, values in table.items()
    ]
    rows.sort(key=lambda row: (-abs(row["spearman"]), row["feature"]))
    for position, row in enumerate(rows, start=1):
        row["rank"] = position
    return {
        "schema": REPORT_SCHEMA,
        "method": "spearman_global_sensitivity",
        "sample_count": any_length,
        "features": rows,
        "notice": NON_CERTIFICATION_NOTICE,
    }


def permutation_importance(
    predict: Callable[[Mapping[str, Sequence[float]]], Sequence[object]],
    features: Mapping[str, Sequence[object]],
    *,
    labels: Sequence[object] | None = None,
    repeats: int = 3,
    seed: int = 0,
) -> dict[str, Any]:
    """Seeded permutation importance (model reliance) for any scoring callable.

    Without labels the importance is the mean absolute score change under
    permutation; with labels it is the accuracy drop. Deterministic for a
    given seed so the recorded evidence is reproducible.
    """

    _require_enabled()
    if not callable(predict):
        raise ValueError("predict must be callable")
    if not isinstance(repeats, int) or isinstance(repeats, bool) or not 1 <= repeats <= _MAX_REPEATS:
        raise ValueError(f"repeats must be between 1 and {_MAX_REPEATS}")
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise ValueError("seed must be an integer")
    table = _feature_table(features)
    count = len(next(iter(table.values())))
    base_scores = _series(predict(table), "baseline predictions", minimum=count)
    if len(base_scores) != count:
        raise ValueError("predict must return one score per row")
    truth: list[float] | None = None
    base_accuracy = None
    if labels is not None:
        truth = _series(labels, "labels", minimum=count)
        if len(truth) != count:
            raise ValueError("labels must align with the feature rows")
        base_accuracy = _accuracy(base_scores, truth)
    rng = random.Random(seed)
    rows = []
    for name in table:
        deltas: list[float] = []
        for _ in range(repeats):
            permuted = list(table[name])
            rng.shuffle(permuted)
            trial = {**table, name: permuted}
            scores = _series(predict(trial), "permuted predictions", minimum=count)
            if len(scores) != count:
                raise ValueError("predict must return one score per row")
            if truth is None:
                deltas.append(
                    sum(
                        abs(a - b)
                        for a, b in zip(scores, base_scores, strict=True)
                    )
                    / count
                )
            else:
                deltas.append(max(0.0, (base_accuracy or 0.0) - _accuracy(scores, truth)))
        rows.append(
            {
                "feature": name,
                "importance": round(sum(deltas) / len(deltas), 12),
                "repeats": repeats,
            }
        )
    rows.sort(key=lambda row: (-row["importance"], row["feature"]))
    for position, row in enumerate(rows, start=1):
        row["rank"] = position
    return {
        "schema": REPORT_SCHEMA,
        "method": (
            "permutation_accuracy_drop" if truth is not None else "permutation_score_change"
        ),
        "sample_count": count,
        "seed": seed,
        "baseline_accuracy": base_accuracy,
        "features": rows,
        "notice": NON_CERTIFICATION_NOTICE,
    }


def _accuracy(scores: Sequence[float], labels: Sequence[float]) -> float:
    hits = sum(
        1
        for score, label in zip(scores, labels, strict=True)
        if round(score) == round(label)
    )
    return hits / len(labels)


def partial_dependence(
    predict: Callable[[Mapping[str, Sequence[float]]], Sequence[object]],
    features: Mapping[str, Sequence[object]],
    feature: str,
    *,
    grid: Sequence[object] | None = None,
    grid_points: int = 10,
) -> dict[str, Any]:
    """Average prediction as one feature sweeps its observed range."""

    _require_enabled()
    if not callable(predict):
        raise ValueError("predict must be callable")
    table = _feature_table(features)
    name = str(feature).strip()
    if name not in table:
        raise ValueError(f"feature has no data: {name}")
    count = len(table[name])
    if grid is None:
        if not isinstance(grid_points, int) or isinstance(grid_points, bool) or not 2 <= grid_points <= _MAX_GRID:
            raise ValueError(f"grid_points must be between 2 and {_MAX_GRID}")
        low = min(table[name])
        high = max(table[name])
        if low == high:
            high = low + 1.0
        step = (high - low) / (grid_points - 1)
        points = [low + step * index for index in range(grid_points)]
    else:
        points = _series(grid, "grid")
        if len(points) > _MAX_GRID:
            raise ValueError(f"grid must contain at most {_MAX_GRID} points")
    curve = []
    for value in points:
        trial = {**table, name: [value] * count}
        scores = _series(predict(trial), "grid predictions", minimum=count)
        if len(scores) != count:
            raise ValueError("predict must return one score per row")
        curve.append(
            {"value": round(value, 12), "average_score": round(sum(scores) / count, 12)}
        )
    return {
        "schema": REPORT_SCHEMA,
        "method": "partial_dependence",
        "feature": name,
        "sample_count": count,
        "curve": curve,
        "notice": NON_CERTIFICATION_NOTICE,
    }


def reason_codes(
    features: Mapping[str, Sequence[object]],
    instance: Mapping[str, object],
    *,
    top_k: int = 4,
) -> dict[str, Any]:
    """Standardized-deviation reason codes for one decision.

    The adverse-action style: which of this instance's inputs sit furthest
    from the population norm, in plain language, ranked. Population statistics
    come from the caller's own reference sample.
    """

    _require_enabled()
    if not isinstance(top_k, int) or isinstance(top_k, bool) or not 1 <= top_k <= _MAX_FEATURES:
        raise ValueError(f"top_k must be between 1 and {_MAX_FEATURES}")
    table = _feature_table(features)
    if not isinstance(instance, Mapping):
        raise ValueError("instance must be a mapping of feature values")
    unknown = set(map(str, instance)) - set(table)
    if unknown:
        raise ValueError(f"instance features have no reference: {', '.join(sorted(unknown))}")
    rows = []
    for name, values in table.items():
        if name not in instance:
            continue
        value = _finite(instance[name], f"instance {name}")
        mean = sum(values) / len(values)
        variance = sum((sample - mean) ** 2 for sample in values) / max(1, len(values) - 1)
        deviation = math.sqrt(variance)
        z_score = 0.0 if deviation <= 0 else (value - mean) / deviation
        rows.append(
            {
                "feature": name,
                "value": round(value, 12),
                "population_mean": round(mean, 12),
                "z_score": round(z_score, 12),
                "direction": "above" if z_score >= 0 else "below",
                "statement": (
                    f"{name} is {abs(round(z_score, 2))} standard deviations "
                    f"{'above' if z_score >= 0 else 'below'} the reference population."
                ),
            }
        )
    if not rows:
        raise ValueError("instance shares no features with the reference sample")
    rows.sort(key=lambda row: (-abs(row["z_score"]), row["feature"]))
    return {
        "schema": REPORT_SCHEMA,
        "method": "standardized_deviation_reason_codes",
        "reasons": rows[:top_k],
        "notice": NON_CERTIFICATION_NOTICE,
    }


def _prepare_evidence(
    asset_id: str,
    report: Mapping[str, Any],
    *,
    expected_schema: str,
    schema_label: str,
    observed_at: float | None,
    validity_seconds: int,
) -> tuple[Any, dict[str, Any], float, str]:
    """The recorders' shared gate: schema, validity bounds, an observed
    asset, a positive timestamp, and the canonical report digest."""

    _require_enabled()
    if not isinstance(report, Mapping) or report.get("schema") != expected_schema:
        raise ValueError(f"report must be {schema_label}")
    if (
        not isinstance(validity_seconds, int)
        or isinstance(validity_seconds, bool)
        or not 3600 <= validity_seconds <= 366 * 24 * 60 * 60
    ):
        raise ValueError("validity_seconds must be between an hour and a year")
    officer = mra.ModelRiskAssuranceOfficer()
    observation = officer.get_observation(str(asset_id or ""))
    if observation is None:
        raise ExplainabilityError("evidence requires an observed AI asset")
    now = time.time() if observed_at is None else _finite(observed_at, "observed_at")
    if now <= 0:
        raise ValueError("observed_at must be positive")
    digest = hashlib.sha256(
        json.dumps(report, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()
    return officer, observation, now, digest


def record_explainability_evidence(
    asset_id: str,
    report: Mapping[str, Any],
    *,
    source_id: str,
    actor: str,
    observed_at: float | None = None,
    validity_seconds: int = 90 * 24 * 60 * 60,
) -> dict[str, Any]:
    """Record one report as digest-scoped ``explainability`` evidence."""

    officer, observation, now, digest = _prepare_evidence(
        asset_id, report,
        expected_schema=REPORT_SCHEMA,
        schema_label="an explainability report",
        observed_at=observed_at,
        validity_seconds=validity_seconds,
    )
    return officer.record_evidence(
        str(asset_id),
        source_id=f"explainability:{str(source_id or '').strip() or 'report'}",
        evidence_kind="explainability",
        result="passed",
        scope_digest=digest,
        artifact_digest=observation["version_digest"],
        actor=str(actor or ""),
        observed_at=now,
        valid_until=now + validity_seconds,
        summary=f"Explainability report recorded ({report.get('method')}).",
        metrics={"method": report.get("method"), "report_sha256": digest},
    )


def record_fairness_evidence(
    asset_id: str,
    report: Mapping[str, Any],
    *,
    source_id: str,
    actor: str,
    observed_at: float | None = None,
    validity_seconds: int = 90 * 24 * 60 * 60,
) -> dict[str, Any]:
    """Record one fairness-metrics report as digest-scoped evidence.

    The report comes from :func:`maverick.fairness_monitor.metrics_report`
    (four-fifths impact ratios, demographic parity, equal opportunity).
    The evidence result is honest: ``passed`` only when no group fails
    the threshold — a failing report records as ``failed`` evidence, it
    is never suppressed. A screening record, not a fairness certification.
    """

    from .fairness_monitor import FAIRNESS_REPORT_SCHEMA

    officer, observation, now, digest = _prepare_evidence(
        asset_id, report,
        expected_schema=FAIRNESS_REPORT_SCHEMA,
        schema_label="a fairness metrics report",
        observed_at=observed_at,
        validity_seconds=validity_seconds,
    )
    ratio = _finite(report.get("min_impact_ratio"), "report min_impact_ratio")
    passed = report.get("passed") is True
    return officer.record_evidence(
        str(asset_id),
        source_id=f"fairness:{str(source_id or '').strip() or 'report'}",
        evidence_kind="fairness",
        result="passed" if passed else "failed",
        scope_digest=digest,
        artifact_digest=observation["version_digest"],
        actor=str(actor or ""),
        observed_at=now,
        valid_until=now + validity_seconds,
        summary=(
            "Group-fairness metrics recorded "
            f"(min impact ratio {ratio:.3f}, "
            f"{'no failing groups' if passed else 'FAILING groups: ' + ', '.join(report.get('failing_groups') or [])})."
        ),
        metrics={
            "min_impact_ratio": ratio,
            "demographic_parity_diff": report.get("demographic_parity_diff"),
            "samples": report.get("samples"),
            "report_sha256": digest,
        },
    )


__all__ = [
    "ExplainabilityConfigError",
    "ExplainabilityError",
    "NON_CERTIFICATION_NOTICE",
    "REPORT_SCHEMA",
    "enabled",
    "get_explainability_config",
    "global_sensitivity",
    "partial_dependence",
    "permutation_importance",
    "reason_codes",
    "record_explainability_evidence",
    "record_fairness_evidence",
    "spearman_correlation",
]
