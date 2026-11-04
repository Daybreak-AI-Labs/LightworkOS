"""Sealed comparison execution and promotion math.

The caller supplies the observer and logger so the runner keeps its existing
injection points. This module has no access to search archives or authority
issuance, and only receives already validated, authorized comparison inputs.
"""
from __future__ import annotations

import logging
import math
from collections.abc import Awaitable, Callable
from hashlib import sha256
from statistics import NormalDist
from typing import Protocol

from .archive import Candidate
from .eval_harness import EvalCase, EvalObservation
from .experiment_state import _CandidateSnapshot, _ConfirmationAdmission, _PairedEvidence

AgentFactory = Callable[[dict], Callable[[str], Awaitable[str]]]
OutputScorer = Callable[[str, str], float]


class _Observer(Protocol):
    async def __call__(
        self, agent: Callable[[str], Awaitable[str]], case: EvalCase, *,
        scorer: OutputScorer | None, evaluator_id: str | None, exposure_id: str,
    ) -> EvalObservation: ...


async def collect_paired_evidence(
    seed: Candidate, champion: Candidate,
    seed_snapshot: _CandidateSnapshot, champion_snapshot: _CandidateSnapshot,
    cases: tuple[EvalCase, ...], factory: AgentFactory, *,
    admission: _ConfirmationAdmission, scorer: OutputScorer | None,
    evaluator_id: str | None, observer: _Observer, logger: logging.Logger,
) -> _PairedEvidence:
    """Expose the two fixed candidates once per case in counterbalanced order."""
    seed_config = seed_snapshot.config_copy()
    champion_config = champion_snapshot.config_copy()
    seed_agent = factory(seed_config)
    champion_agent = factory(champion_config)

    def require_same_candidates() -> None:
        if not (seed_snapshot.matches(seed) and champion_snapshot.matches(champion)
                and seed_snapshot.matches_config(seed_config)
                and champion_snapshot.matches_config(champion_config)):
            raise ValueError("candidate changed during sealed confirmation")

    require_same_candidates()
    seed_outcomes: list[float] = []
    champion_outcomes: list[float] = []
    execution_failed = False

    async def expose(agent, candidate_id: str, case: EvalCase, index: int) -> EvalObservation:
        require_same_candidates()
        exposure_id = f"{admission.comparison_id}:{candidate_id}:{index}"
        logger.info(
            "sealed_exposure comparison=%s candidate=%s case_index=%d exposure=%s",
            admission.comparison_id, candidate_id, index,
            sha256(exposure_id.encode("utf-8")).hexdigest())
        observation = await observer(
            agent, case, scorer=scorer, evaluator_id=evaluator_id,
            exposure_id=exposure_id)
        require_same_candidates()
        return observation

    # Ordinary execution errors retain paired exposure; cancellation, budget,
    # halt and changed identity stop before another case can be observed.
    for index, case in enumerate(cases):
        if index % 2 == 0:
            seed_observation = await expose(seed_agent, seed_snapshot.candidate_id, case, index)
            champion_observation = await expose(champion_agent, champion_snapshot.candidate_id, case, index)
        else:
            champion_observation = await expose(champion_agent, champion_snapshot.candidate_id, case, index)
            seed_observation = await expose(seed_agent, seed_snapshot.candidate_id, case, index)
        execution_failed |= any(
            observation.execution_status != "succeeded" or observation.grade is None
            for observation in (seed_observation, champion_observation))
        seed_outcomes.append(seed_observation.score)
        champion_outcomes.append(champion_observation.score)
    return _PairedEvidence(tuple(seed_outcomes), tuple(champion_outcomes), execution_failed)


def promotes(
    cases: tuple[EvalCase, ...], evidence: _PairedEvidence, *,
    margin: float, confidence_z: float, logger: logging.Logger,
) -> bool:
    """Apply the existing strict weighted lift and paired confidence bound."""
    weights = [float(case.weight) for case in cases]
    total_weight = sum(weights)
    seed_score = sum(weight * value for weight, value in zip(
        weights, evidence.seed_scores, strict=True)) / total_weight
    champion_score = sum(weight * value for weight, value in zip(
        weights, evidence.champion_scores, strict=True)) / total_weight
    delta = champion_score - seed_score
    if confidence_z > 0.0:
        alpha = 2.0 * (1.0 - NormalDist().cdf(float(confidence_z)))
        if not 0.0 < alpha < 1.0:
            logger.error("confirmation critical value is numerically unsupported")
            return False
        normalized = [weight / total_weight for weight in weights if weight > 0.0]
        radius = math.sqrt(2.0 * sum(weight * weight for weight in normalized)
                           * math.log(1.0 / alpha))
        lower = delta - radius
        if lower > margin:
            return True
        logger.info(
            "sealed confirmation lower bound %.6f did not clear margin %.6f; "
            "keeping seed", lower, margin)
        return False
    if champion_score > seed_score + margin:
        return True
    logger.info("sealed confirmation did not clear required margin; keeping seed")
    return False
