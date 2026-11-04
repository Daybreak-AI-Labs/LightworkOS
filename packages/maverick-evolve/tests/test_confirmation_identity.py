"""Sealed comparison identity and exposure must remain bound to fixed inputs."""
from __future__ import annotations

import pytest
from maverick_evolve.archive import Candidate
from maverick_evolve.eval_harness import EvalCase
from maverick_evolve.runner import (
    ConfirmationPermit,
    confirm_candidate,
    evolve_metaproductive_with_eval,
    evolve_with_eval,
)


@pytest.mark.asyncio
async def test_mutated_candidate_is_rejected_before_authorization_or_exposure():
    seed = Candidate({"nested": {"value": 0}})
    champion = Candidate({"nested": {"value": 1}})
    champion.config["nested"]["value"] = 9
    events = []

    with pytest.raises(ValueError, match="candidate id"):
        await confirm_candidate(
            seed, champion, [EvalCase("sealed")],
            lambda config: events.append("factory"),
            authorize=lambda *args: events.append("authorize") or 1.96,
        )
    assert not events


@pytest.mark.asyncio
async def test_candidate_changed_during_authorization_never_reaches_sealed_cases():
    seed = Candidate({"nested": {"value": 0}})
    champion = Candidate({"nested": {"value": 1}})
    exposures = []

    def authorize(_seed, _champion, _cases):
        champion.config["nested"]["value"] = 9
        return 1.96

    def factory(config):
        async def agent(prompt):
            exposures.append((config, prompt))
            return "yes"
        return agent

    result = await confirm_candidate(
        seed, champion, [EvalCase("sealed")], factory, authorize=authorize,
    )
    assert result is seed
    assert exposures == []


@pytest.mark.asyncio
async def test_factory_cannot_mutate_the_authorized_configuration_before_exposure():
    seed = Candidate({"nested": {"value": 0}})
    champion = Candidate({"nested": {"value": 1}})
    calls = []

    def factory(config):
        config["nested"]["value"] = 9
        async def agent(prompt):
            calls.append(prompt)
            return "yes"
        return agent

    result = await confirm_candidate(seed, champion, [EvalCase("sealed")], factory)
    assert result is seed
    assert seed.config == {"nested": {"value": 0}}
    assert champion.config == {"nested": {"value": 1}}
    assert calls == []


@pytest.mark.asyncio
async def test_legacy_authorizer_cannot_mutate_the_actual_case_snapshot():
    seed = Candidate({"arm": "seed"})
    champion = Candidate({"arm": "champion"})
    prompts = []

    def authorize(_seed, _champion, cases):
        cases[0].prompt = "substituted"
        return 1.0

    def factory(config):
        async def agent(prompt):
            prompts.append(prompt)
            return "yes" if config["arm"] == "champion" else "no"
        return agent

    await confirm_candidate(
        seed, champion, [EvalCase("sealed", check=lambda out: out == "yes")],
        factory, authorize=authorize,
    )
    assert prompts == ["sealed", "sealed"]


@pytest.mark.asyncio
async def test_factory_mutation_during_an_exposure_stops_further_exposures():
    seed = Candidate({"nested": {"value": 0}})
    champion = Candidate({"nested": {"value": 1}})
    calls = []

    def factory(config):
        async def agent(prompt):
            calls.append(prompt)
            config["nested"]["value"] = 9
            return "yes"
        return agent

    result = await confirm_candidate(
        seed, champion, [EvalCase("first"), EvalCase("second")], factory,
    )
    assert result is seed
    assert calls == ["first"]
    assert seed.config == {"nested": {"value": 0}}


@pytest.mark.asyncio
async def test_risk_limited_confirmation_cannot_lower_the_confidence_floor(monkeypatch):
    import time

    monkeypatch.setattr("maverick_evolve.runner.strict_calibration_ready", lambda **kwargs: True)
    seed = Candidate({"arm": "seed"})
    champion = Candidate({"arm": "champion"})
    cases = [EvalCase(f"case-{i}", check=lambda output: output == "yes") for i in range(20)]

    def factory(config):
        async def agent(prompt):
            return "yes" if config["arm"] == "champion" and int(prompt[5:]) < 5 else "no"
        return agent

    def authorize(request):
        now = time.time()
        return ConfirmationPermit(
            request_sha256=request.request_sha256, critical_z=0.1,
            authorization_id="auth", ledger_tip_sha256="c" * 64,
            issued_at=now, expires_at=now + 60,
        )

    result = await confirm_candidate(
        seed, champion, cases, factory, confidence_z=0.0,
        authorize=authorize, require_authorization=True,
        case_family_id="a" * 64, evaluator_id="b" * 64,
    )
    assert result is seed


@pytest.mark.asyncio
@pytest.mark.parametrize("strategy", ["standard", "metaproductive"])
async def test_development_factory_cannot_rewrite_scored_candidate(monkeypatch, strategy):
    from maverick_evolve.metaproductive import MetaproductiveSearchError

    monkeypatch.setattr("maverick_evolve.runner.calibration_frozen", lambda: False)
    seed = {"nested": {"value": 0}}
    calls = []

    def factory(config):
        config["nested"]["value"] = 9
        async def agent(prompt):
            calls.append(prompt)
            return "yes"
        return agent

    cases = [EvalCase("development", check=lambda output: output == "yes")]
    expected = ValueError if strategy == "standard" else MetaproductiveSearchError
    with pytest.raises(expected) as error:
        if strategy == "standard":
            await evolve_with_eval(seed, cases, factory, generations=0)
        else:
            await evolve_metaproductive_with_eval(seed, cases, factory, evaluation_budget=1)
    underlying = error.value if strategy == "standard" else error.value.__cause__
    assert isinstance(underlying, ValueError)
    assert "candidate changed" in str(underlying)
    assert seed == {"nested": {"value": 0}}
    assert calls == []
