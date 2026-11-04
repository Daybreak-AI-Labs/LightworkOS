"""The trusted fitness function.

You cannot safely evolve an agent without a metric you believe. This scores an
agent (any ``async (prompt) -> str``) against a held-out set of cases. A case
either carries its own ``check`` predicate (ground truth — the strongest signal)
or a ``reference`` answer scored by an injected ``scorer`` (default: substring
containment). Keep ground-truth cases where you can; that is what makes the
fitness signal ungameable enough to evolve against.

Pure + dependency-injected (you supply the agent and, optionally, the scorer),
so it runs in tests without a live model. Pair with ``maverick.calibration`` to
freeze evolution when the judge drifts.
"""
from __future__ import annotations

import asyncio
import json
import logging
import math
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from hashlib import sha256
from typing import Literal

from maverick.budget import BudgetExceeded, UsageAccountingError
from maverick.killswitch import Halted, HaltGenerationChanged

log = logging.getLogger(__name__)
EXECUTION_STOPS = (BudgetExceeded, UsageAccountingError, Halted, HaltGenerationChanged)


@dataclass
class EvalCase:
    prompt: str
    check: Callable[[str], bool] | None = None  # ground-truth predicate (preferred)
    reference: str | None = None                # else scored against this
    weight: float = 1.0


@dataclass
class EvalReport:
    n: int
    passed: float          # weighted sum of per-case scores
    total_weight: float
    observations: tuple[EvalObservation, ...] = ()

    @property
    def score(self) -> float:
        """Weighted pass rate in [0,1]."""
        return self.passed / self.total_weight if self.total_weight > 0 else 0.0


@dataclass(frozen=True)
class EvalObservation:
    """One exposure, with execution failure kept separate from answer quality.

    IDs bind visible case data and the declared evaluator, not an introspected
    version of arbitrary Python check code. An unversioned custom evaluator is
    explicitly labeled. No prompt, answer, exception text or sealed grade is
    included in operational logs.
    """

    case_id: str
    evaluator_id: str
    exposure_id: str
    execution_status: Literal[
        "succeeded", "failed", "timed_out", "cancelled", "stopped", "invalid_output"]
    grade: float | None
    diagnostic: str = "none"

    @property
    def score(self) -> float:
        """Compatibility fitness: an ungraded execution contributes zero."""
        return self.grade if self.grade is not None else 0.0


def _identity(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _record(observation: EvalObservation) -> EvalObservation:
    log.info(
        "eval_observation case=%s evaluator=%s exposure=%s execution=%s diagnostic=%s",
        observation.case_id, observation.evaluator_id, observation.exposure_id,
        observation.execution_status, observation.diagnostic,
    )
    return observation


def _contains_scorer(output: str, reference: str) -> float:
    """Default reference scorer: 1.0 if the reference appears in the output."""
    if not reference:
        return 0.0
    return 1.0 if reference.strip().lower() in (output or "").lower() else 0.0


async def evaluate(
    agent: Callable[[str], Awaitable[str]],
    cases: list[EvalCase],
    *,
    scorer: Callable[[str, str], float] | None = None,
    evaluator_id: str | None = None,
) -> EvalReport:
    """Run ``agent`` over ``cases`` and return a weighted fitness report.

    A case's ``check`` (ground truth) wins when present; otherwise the output is
    scored against ``reference`` via ``scorer`` (default substring containment).
    An agent that raises on a case scores 0 for that case (robustness counts).
    """
    weights: list[float] = []
    for case in cases:
        raw_weight = case.weight
        if (isinstance(raw_weight, bool)
                or not isinstance(raw_weight, (int, float))):
            raise ValueError("case weight must be numeric, not boolean")
        weight = float(raw_weight)
        if not math.isfinite(weight) or weight < 0.0:
            raise ValueError("case weight must be finite and non-negative")
        weights.append(weight)
    total = sum(weights)
    if cases and (not math.isfinite(total) or total <= 0.0):
        raise ValueError(
            "evaluation cases must have finite positive total weight")
    passed = 0.0
    total_weight = 0.0
    observations: list[EvalObservation] = []
    for case, weight in zip(cases, weights, strict=True):
        total_weight += weight
        observation = await observe_case(
            agent, case, scorer=scorer, evaluator_id=evaluator_id)
        observations.append(observation)
        passed += weight * observation.score
    return EvalReport(
        n=len(cases), passed=passed, total_weight=total_weight,
        observations=tuple(observations))


async def evaluate_case(
    agent: Callable[[str], Awaitable[str]],
    case: EvalCase,
    *,
    scorer: Callable[[str, str], float] | None = None,
) -> float:
    """Evaluate one agent/case exposure and return its bounded outcome.

    DGM's risk-limited confirmation uses this seam to interleave the seed and
    frozen champion case by case. Each arm still receives exactly one exposure
    per sealed case, while alternating order avoids giving one arm every cold or
    every warm evaluator/provider position.
    """
    return (await observe_case(agent, case, scorer=scorer)).score


async def observe_case(
    agent: Callable[[str], Awaitable[str]],
    case: EvalCase,
    *,
    scorer: Callable[[str, str], float] | None = None,
    evaluator_id: str | None = None,
    exposure_id: str = "",
) -> EvalObservation:
    """Run once; grade successful strings only, including legitimate abstention.

    Ordinary agent failures return ungraded observations. Cancellation, budget
    and halt signals are recorded then propagated unchanged. Evaluator failures
    are also recorded and propagated, retaining the existing fail-closed API.
    The caller owns deadlines; this function never retries or creates a budget.
    """
    case_id = _identity(json.dumps({
        "prompt": case.prompt, "reference": case.reference,
        "weight": case.weight, "uses_callable_check": case.check is not None,
    }, sort_keys=True, ensure_ascii=False, allow_nan=False))
    evaluator = evaluator_id or (
        "unversioned-check" if case.check is not None else
        "unversioned-scorer" if scorer is not None else "contains-v1")
    # Only bounded digests enter logs, even if caller-supplied labels contain
    # sensitive data. A versioned evaluator's declared digest is preserved.
    evaluator = (evaluator if evaluator in {
        "unversioned-check", "unversioned-scorer", "contains-v1"} or len(evaluator) == 64
                 and all(ch in "0123456789abcdef" for ch in evaluator)
                 else _identity(evaluator))
    exposure = _identity(exposure_id) if exposure_id else "unbound-development"

    def result(status, grade=None, diagnostic="none") -> EvalObservation:
        return _record(EvalObservation(
            case_id, evaluator, exposure, status, grade, diagnostic))

    try:
        out = await agent(case.prompt)
    except asyncio.CancelledError:
        result("cancelled", diagnostic="task_cancelled")
        raise
    except EXECUTION_STOPS:
        result("stopped", diagnostic="execution_stop")
        raise
    except (TimeoutError, asyncio.TimeoutError):
        return result("timed_out", diagnostic="agent_timeout")
    except Exception:
        return result("failed", diagnostic="agent_exception")
    if not isinstance(out, str):
        return result("invalid_output", diagnostic="non_string_output")
    try:
        grade = _grade_output(out, case, scorer or _contains_scorer)
    except BaseException:
        result("succeeded", diagnostic="evaluator_exception")
        raise
    return result("succeeded", grade)


def _grade_output(
    out: str, case: EvalCase, scorer: Callable[[str, str], float],
) -> float:
    if case.check is not None:
        checked = case.check(out)
        if not isinstance(checked, bool):
            raise ValueError("ground-truth check must return an exact boolean")
        return 1.0 if checked else 0.0
    if case.reference is not None:
        raw_score = scorer(out, case.reference)
        if isinstance(raw_score, bool):
            raise ValueError("evaluator score must be numeric, not boolean")
        try:
            score = float(raw_score)
        except (TypeError, ValueError) as exc:
            raise ValueError("evaluator score must be numeric") from exc
        # Python's min/max handling of NaN is order-dependent; the historical
        # clamp turned NaN into 1.0 and could manufacture a perfect champion.
        if not math.isfinite(score) or not 0.0 <= score <= 1.0:
            raise ValueError("evaluator score must be finite and in [0, 1]")
        return score
    return 0.0


__all__ = [
    "EvalCase", "EvalReport", "EvalObservation", "evaluate", "evaluate_case",
    "observe_case",
]
