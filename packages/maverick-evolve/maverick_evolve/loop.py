"""A continuous evolution loop with a persistent diverse archive.

Single-shot ``evolve`` improves within one call; real self-improvement is
*continuous* -- it accumulates across rounds (and process restarts) in a
persisted, diverse archive, branching from the whole population so it doesn't
collapse onto one lineage. This module is that driver.

Each round is independently **calibration-gated**: if the verifier has drifted,
the round is SKIPPED (not failed) -- evolution pauses until the judge is
trustworthy again, then resumes from the saved archive. That's the trust
thermostat applied to a long-running loop. Config-only throughout; no code
mutation. Dependency-injected ``agent_factory`` so it runs (and tests) without a
live model.
"""
from __future__ import annotations

import logging
import random
from collections.abc import Callable
from pathlib import Path

from .archive import Archive, Candidate
from .eval_harness import EvalCase
from .runner import (
    AgentFactory,
    EvolutionFrozen,
    OutputScorer,
    _prepare_confirmation,
    calibration_frozen,
    confirm_candidate,
    evolve_with_eval,
    strict_calibration_ready,
)

log = logging.getLogger(__name__)


async def evolve_continuous(
    seed_config: dict,
    cases: list[EvalCase],
    agent_factory: AgentFactory,
    *,
    rounds: int = 3,
    generations_per_round: int = 10,
    archive_path: str | Path | None = None,
    scorer: OutputScorer | None = None,
    rng: random.Random | None = None,
    space: dict[str, tuple] | None = None,
    on_round: Callable[[int, Candidate, Archive], None] | None = None,
    confirmation_cases: list[EvalCase] | tuple[EvalCase, ...] | None = None,
    confirmation_scorer: OutputScorer | None = None,
    confirmation_margin: float = 0.0,
    risk_limited: bool = False,
    confirmation_min_cases: int | None = None,
    confirmation_confidence_z: float | None = None,
    confirmation_authorize=None,
    confirmation_family_id: str | None = None,
    confirmation_evaluator_id: str | None = None,
) -> tuple[Candidate | None, list[dict]]:
    """Run ``rounds`` of evolution against a persistent, accumulating archive.

    Returns ``(best_candidate, history)`` where ``history`` has one entry per
    round (with ``skipped: true`` for rounds paused by a frozen calibration).
    The archive is loaded from ``archive_path`` if given (so a prior run's
    population continues) and saved after each productive round. Each round
    seeds the search from the running best, so progress compounds.

    ``confirmation_cases`` is a sealed, one-shot promotion set. It is never
    passed into any development round. After all adaptive search is complete,
    the fixed archive champion is compared once with the original seed. While
    confirmation is enabled, archive persistence is deferred until that check
    passes so a rejected development winner is not published as adoptable.
    """
    rng = rng or random.Random()
    sealed_cases = _prepare_confirmation(
        confirmation_cases,
        confirmation_scorer,
        confirmation_margin,
    )
    # Validate the complete sealed/query-budget contract before spending one
    # adaptive development evaluation. Import stays private to avoid widening
    # the public runner surface solely for this continuous driver.
    from .runner import _confirmation_policy
    resolved_min_cases, resolved_confidence_z = _confirmation_policy(
        sealed_cases, risk_limited=risk_limited,
        minimum_cases=confirmation_min_cases,
        confidence_z=confirmation_confidence_z,
        authorize=confirmation_authorize,
        case_family_id=confirmation_family_id,
        evaluator_id=confirmation_evaluator_id)
    if risk_limited and not strict_calibration_ready(
            evaluator_id=confirmation_evaluator_id):
        raise EvolutionFrozen(
            "risk-limited evolution requires a fresh adequate calibration receipt")
    archive_was_loaded = False
    if archive_path:
        from maverick.file_lock import cross_process_lock
        with cross_process_lock(archive_path):
            archive_was_loaded = Path(archive_path).exists()
            archive = Archive.load(archive_path)
            if archive.confirmed_candidate_id is not None:
                # Confirmation belongs to the frozen artifact/evaluator study
                # that produced it. Starting revalidation revokes publication
                # authority durably before any adaptive evaluation can fail,
                # crash, or leave the old on-disk marker adoptable.
                archive.confirmed_candidate_id = None
                archive.save(archive_path)
    else:
        archive = Archive()
    archive_revalidated = not archive_was_loaded
    history: list[dict] = []
    current = dict(seed_config)
    # Round 0's seed is genuinely unscored; later rounds seed from the prior
    # round's best, whose score we already paid for.
    prior_best_score: float | None = None
    productive_rounds = 0

    # Seed the archive up front so best() always returns a valid candidate --
    # even when every round is SKIPPED by a frozen calibration (otherwise the
    # archive stays empty and best() is None). add() dedups by config id, so a
    # loaded archive already containing the seed is unaffected, and a productive
    # round that re-scores this config updates it in place.
    if archive.best() is None:
        archive.add(Candidate(config=dict(seed_config)))

    for r in range(max(0, rounds)):
        if ((risk_limited and not strict_calibration_ready(
                evaluator_id=confirmation_evaluator_id))
                or (not risk_limited and calibration_frozen())):
            history.append({"round": r, "skipped": True, "reason": "calibration frozen"})
            log.info("evolution round %d skipped: calibration frozen", r)
            continue
        best = await evolve_with_eval(
            current, cases, agent_factory,
            generations=generations_per_round, scorer=scorer, rng=rng,
            archive=archive, space=space, seed_score=prior_best_score,
            revalidate_archive=not archive_revalidated,
        )
        just_revalidated = not archive_revalidated
        archive_revalidated = True
        productive_rounds += 1
        current = dict(best.config)  # compound: next round branches from the best
        # The next round seeds from this scored best; passing its score down
        # skips re-paying a full |cases| evaluation just to re-learn it.
        prior_best_score = best.score
        # With sealed confirmation, persisting now would expose an adaptively
        # selected but unconfirmed winner through Archive.best()/adopt_best().
        if archive_path and sealed_cases is None:
            archive.save(archive_path)
        history.append({
            "round": r, "best_score": best.score,
            "archive_size": len(archive.candidates),
            "archive_revalidated": just_revalidated,
        })
        if on_round is not None:
            try:
                # Callbacks receive a detached, explicitly development-only
                # view. They cannot poison the active search or publish an
                # archive that official adoption mistakes for confirmed.
                callback_archive = Archive.from_dict(archive.to_dict())
                callback_archive.confirmed_candidate_id = None
                on_round(r, Candidate(config=best.config, score=best.score),
                         callback_archive)
            except Exception:  # pragma: no cover -- callback must not break the loop
                pass

    development_best = archive.best()
    if sealed_cases is None or development_best is None:
        return development_best, history

    seed = Candidate(config=dict(seed_config))
    archived_seed = next((c for c in archive.candidates if c.id == seed.id), None)
    if archived_seed is not None:
        seed.score = archived_seed.score

    # If every round was frozen, do not consult or consume the sealed set: no
    # new champion was validly selected, so the safe result is simply the seed.
    if productive_rounds == 0:
        return seed, history

    confirmed = await confirm_candidate(
        seed,
        development_best,
        sealed_cases,
        agent_factory,
        scorer=confirmation_scorer,
        margin=confirmation_margin,
        min_cases=resolved_min_cases,
        confidence_z=resolved_confidence_z,
        authorize=confirmation_authorize,
        require_authorization=risk_limited,
        case_family_id=confirmation_family_id,
        evaluator_id=confirmation_evaluator_id,
    )
    passed = confirmed.id == development_best.id
    if history:
        history[-1]["confirmation"] = "passed" if passed else "rejected"
    if passed:
        archive.mark_confirmed(development_best.id)
        if archive_path:
            archive.save(archive_path)
    return confirmed, history


__all__ = ["evolve_continuous"]
