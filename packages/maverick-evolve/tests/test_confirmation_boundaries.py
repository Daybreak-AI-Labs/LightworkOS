"""The extracted comparison boundary retains the runner's public contracts."""
from __future__ import annotations

import logging

import pytest
from maverick_evolve import ConfirmationPermit, ConfirmationRequest, runner
from maverick_evolve.archive import Candidate
from maverick_evolve.confirmation import promotes
from maverick_evolve.eval_harness import EvalCase, EvalObservation
from maverick_evolve.experiment_state import ConfirmationPermit as StatePermit
from maverick_evolve.experiment_state import ConfirmationRequest as StateRequest
from maverick_evolve.experiment_state import _PairedEvidence


def test_existing_confirmation_imports_are_the_same_contracts():
    assert ConfirmationRequest is runner.ConfirmationRequest is StateRequest
    assert ConfirmationPermit is runner.ConfirmationPermit is StatePermit


@pytest.mark.parametrize("margin, expected", [(0.49, True), (0.5, False), (0.51, False)])
def test_extracted_promotion_requires_strict_weighted_lift(margin, expected):
    cases = (EvalCase("first", weight=3), EvalCase("second", weight=1))
    evidence = _PairedEvidence((0.0, 1.0), (1.0, 0.0), False)

    assert promotes(
        cases, evidence, margin=margin, confidence_z=0.0,
        logger=logging.getLogger(__name__),
    ) is expected


@pytest.mark.asyncio
async def test_runner_observer_injection_retains_paired_sealed_exposure(monkeypatch):
    events = []

    async def observer(agent, case, *, scorer, evaluator_id, exposure_id):
        arm = await agent(case.prompt)
        events.append((arm, case.prompt, exposure_id))
        return EvalObservation(
            case_id="case", evaluator_id="evaluator", exposure_id=exposure_id,
            execution_status="succeeded", grade=float(arm == "champion"),
        )

    def factory(config):
        async def agent(prompt):
            return config["arm"]
        return agent

    monkeypatch.setattr(runner, "observe_case", observer)
    seed = Candidate({"arm": "seed"})
    champion = Candidate({"arm": "champion"})
    result = await runner.confirm_candidate(
        seed, champion, [EvalCase("one"), EvalCase("two")], factory,
    )

    assert result is champion
    assert [(arm, prompt) for arm, prompt, _ in events] == [
        ("seed", "one"), ("champion", "one"),
        ("champion", "two"), ("seed", "two"),
    ]
    assert len({exposure_id for _, _, exposure_id in events}) == 4
