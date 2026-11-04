from __future__ import annotations

import builtins
import random
import time

import pytest
from maverick_evolve import (
    ConfirmationPermit,
    EvalCase,
    EvolutionFrozen,
    MetaproductiveArchive,
    MetaproductiveSearchError,
    evolve_metaproductive_with_eval,
    evolve_with_eval,
)

_FAMILY_ID = "a" * 64
_EVALUATOR_ID = "b" * 64


def _risk_permit(request, *, request_sha256=None, critical_z=1.96):
    now = time.time()
    return ConfirmationPermit(
        request_sha256=request_sha256 or request.request_sha256,
        critical_z=critical_z,
        authorization_id="holdout-query-1",
        ledger_tip_sha256="c" * 64,
        issued_at=now,
        expires_at=now + 60.0,
    )


def _factory_threshold(knob: str, threshold: int):
    """Agent factory whose output passes only when config[knob] >= threshold."""
    def factory(config: dict):
        async def agent(prompt: str) -> str:
            return "GOOD" if config.get(knob, 0) >= threshold else "BAD"
        return agent
    return factory


@pytest.mark.asyncio
async def test_evolve_climbs_to_passing_config(monkeypatch):
    monkeypatch.setattr("maverick_evolve.runner.calibration_frozen", lambda: False)
    cases = [EvalCase(prompt="x", check=lambda o: o == "GOOD")]
    space = {"max_swarm_fanout": ("int", 1, 16)}  # single knob -> deterministic climb
    best = await evolve_with_eval(
        {"max_swarm_fanout": 8},
        cases,
        _factory_threshold("max_swarm_fanout", 12),
        generations=60,
        rng=random.Random(0),
        space=space,
    )
    assert best.score == 1.0
    assert best.config["max_swarm_fanout"] >= 12


@pytest.mark.asyncio
async def test_evolve_refused_when_calibration_frozen(monkeypatch):
    monkeypatch.setattr("maverick_evolve.runner.calibration_frozen", lambda: True)
    cases = [EvalCase(prompt="x", check=lambda o: True)]
    with pytest.raises(EvolutionFrozen):
        await evolve_with_eval(
            {"max_swarm_fanout": 8}, cases,
            _factory_threshold("max_swarm_fanout", 12),
            generations=5, rng=random.Random(0),
        )


def test_calibration_gate_errors_fail_closed(monkeypatch):
    # An unreadable calibration verdict is unknown, never an implicit approval.
    import maverick_evolve.runner as runner

    def _boom():
        raise OSError("calibration verdict unreadable")

    monkeypatch.delenv("MAVERICK_LEARNING_FROZEN", raising=False)
    monkeypatch.setattr("maverick.calibration.learning_frozen", _boom)
    assert runner.calibration_frozen() is True


def test_calibration_import_error_fails_closed(monkeypatch):
    import maverick_evolve.runner as runner

    real_import = builtins.__import__

    def fail_calibration_import(name, *args, **kwargs):
        if name == "maverick.calibration":
            raise ImportError("calibration package unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.delenv("MAVERICK_LEARNING_FROZEN", raising=False)
    monkeypatch.setattr(builtins, "__import__", fail_calibration_import)
    assert runner.calibration_frozen() is True


def test_calibration_error_honors_existing_explicit_override(monkeypatch):
    import maverick_evolve.runner as runner

    def _boom():
        raise OSError("calibration verdict unreadable")

    monkeypatch.setenv("MAVERICK_LEARNING_FROZEN", "0")
    monkeypatch.setattr("maverick.calibration.learning_frozen", _boom)
    assert runner.calibration_frozen() is False


def test_strict_calibration_requires_fresh_complete_receipt_and_ignores_override(
    monkeypatch,
):
    import maverick.calibration as calibration
    import maverick_evolve.runner as runner

    monkeypatch.setenv("MAVERICK_LEARNING_FROZEN", "0")
    monkeypatch.setattr(calibration, "_settings", lambda: {"min_samples": 20})
    monkeypatch.setattr(calibration, "_load_verdict", lambda: None)
    assert runner.strict_calibration_ready(evaluator_id=_EVALUATOR_ID) is False

    receipt = {
        "schema": "maverick-calibration-receipt-v2",
        "evaluator_id": _EVALUATOR_ID,
        "ts": 1_000.0,
        "sample_min_ts": 999.0,
        "sample_max_ts": 999.5,
        "n": 20,
        "n_correct": 10,
        "n_incorrect": 10,
        "discrimination": 0.4,
        "brier": 0.1,
        "adequate": True,
    }
    monkeypatch.setattr(calibration, "_load_verdict", lambda: receipt)
    monkeypatch.setattr(runner.time, "time", lambda: 1_001.0)
    assert runner.strict_calibration_ready(evaluator_id=_EVALUATOR_ID) is True
    assert runner.strict_calibration_ready() is False
    assert runner.strict_calibration_ready(evaluator_id="c" * 64) is False

    # Total n may include adversarial probes; only the natural cohort supports
    # the discrimination statistic that authorizes strict evolution.
    receipt.update(n=100, n_correct=1, n_incorrect=1)
    assert runner.strict_calibration_ready(evaluator_id=_EVALUATOR_ID) is False
    receipt.update(n=20, n_correct=10, n_incorrect=10)

    stale = 1_001.0 - 24.0 * 3600.0 - 1.0
    receipt.update(
        ts=stale, sample_min_ts=stale - 1.0, sample_max_ts=stale)
    assert runner.strict_calibration_ready(evaluator_id=_EVALUATOR_ID) is False


@pytest.mark.asyncio
async def test_risk_limited_refuses_missing_receipt_before_factory_even_with_override(
    monkeypatch,
):
    import maverick.calibration as calibration

    calls = []

    def factory(config):
        calls.append(config)
        return _factory_threshold("v", 1)(config)

    monkeypatch.setenv("MAVERICK_LEARNING_FROZEN", "0")
    monkeypatch.setattr(calibration, "_load_verdict", lambda: None)
    with pytest.raises(EvolutionFrozen):
        await evolve_with_eval(
            {"v": 0},
            [EvalCase(prompt="dev", check=lambda _out: True)],
            factory,
            generations=1,
            confirmation_cases=[
                EvalCase(prompt=f"sealed-{index}", check=lambda _out: True)
                for index in range(20)
            ],
            confirmation_authorize=_risk_permit,
            confirmation_family_id=_FAMILY_ID,
            confirmation_evaluator_id=_EVALUATOR_ID,
            risk_limited=True,
        )

    assert calls == []


@pytest.mark.asyncio
async def test_evolve_refuses_when_calibration_backend_errors(monkeypatch):
    def _boom():
        raise OSError("calibration verdict unreadable")

    monkeypatch.delenv("MAVERICK_LEARNING_FROZEN", raising=False)
    monkeypatch.setattr("maverick.calibration.learning_frozen", _boom)
    with pytest.raises(EvolutionFrozen):
        await evolve_with_eval(
            {"v": 0},
            [EvalCase(prompt="dev", check=lambda _out: True)],
            _factory_threshold("v", 1),
            generations=1,
            mutate=lambda _cfg: {"v": 1},
        )


@pytest.mark.asyncio
async def test_sealed_confirmation_never_reaches_development_scorer(monkeypatch):
    monkeypatch.setattr("maverick_evolve.runner.calibration_frozen", lambda: False)
    development_references: list[str] = []
    confirmation_references: list[str] = []
    prompts: list[str] = []

    def factory(config: dict):
        async def agent(prompt: str) -> str:
            prompts.append(prompt)
            return "PASS" if config["v"] == 1 else "FAIL"
        return agent

    def development_scorer(output: str, reference: str) -> float:
        development_references.append(reference)
        assert reference == "development-case-id"
        return 1.0 if output == "PASS" else 0.0

    def confirmation_scorer(output: str, reference: str) -> float:
        confirmation_references.append(reference)
        assert reference == "sealed-confirmation-case-id"
        return 1.0 if output == "PASS" else 0.0

    best = await evolve_with_eval(
        {"v": 0},
        [EvalCase(prompt="development-prompt", reference="development-case-id")],
        factory,
        generations=1,
        mutate=lambda _cfg: {"v": 1},
        scorer=development_scorer,
        confirmation_cases=[
            EvalCase(
                prompt="sealed-confirmation-prompt",
                reference="sealed-confirmation-case-id",
            )
        ],
        confirmation_scorer=confirmation_scorer,
    )

    assert best.config == {"v": 1}
    assert set(development_references) == {"development-case-id"}
    # One sealed evaluation for the fixed seed and one for the fixed champion.
    assert confirmation_references == [
        "sealed-confirmation-case-id",
        "sealed-confirmation-case-id",
    ]
    first_sealed = prompts.index("sealed-confirmation-prompt")
    assert set(prompts[:first_sealed]) == {"development-prompt"}
    assert prompts[first_sealed:] == [
        "sealed-confirmation-prompt",
        "sealed-confirmation-prompt",
    ]


@pytest.mark.asyncio
async def test_noisy_development_winner_rejected_on_flat_confirmation(monkeypatch):
    monkeypatch.setattr("maverick_evolve.runner.calibration_frozen", lambda: False)

    def factory(config: dict):
        async def agent(prompt: str) -> str:
            if prompt == "development":
                return "PASS" if config["v"] == 1 else "FAIL"
            return "SAME"
        return agent

    best = await evolve_with_eval(
        {"v": 0},
        [EvalCase(prompt="development", check=lambda out: out == "PASS")],
        factory,
        generations=1,
        mutate=lambda _cfg: {"v": 1},
        confirmation_cases=[
            EvalCase(prompt="sealed", check=lambda out: out == "SAME")
        ],
    )

    assert best.config == {"v": 0}
    assert best.score == 0.0


@pytest.mark.asyncio
async def test_confirmation_rejects_finite_weight_sum_overflow_before_factory(
    monkeypatch,
):
    monkeypatch.setattr("maverick_evolve.runner.calibration_frozen", lambda: False)
    calls = []

    def factory(config):
        calls.append(config)
        return _factory_threshold("v", 1)(config)

    with pytest.raises(ValueError, match="finite positive total weight"):
        await evolve_with_eval(
            {"v": 0},
            [EvalCase(prompt="dev", check=lambda _out: True)],
            factory,
            confirmation_cases=[
                EvalCase(
                    prompt=f"sealed-{index}", check=lambda _out: True,
                    weight=1e308,
                )
                for index in range(2)
            ],
        )
    assert calls == []


@pytest.mark.asyncio
async def test_true_lift_clears_one_shot_confirmation_margin(monkeypatch):
    monkeypatch.setattr("maverick_evolve.runner.calibration_frozen", lambda: False)
    sealed_calls: list[tuple[int, str]] = []

    def factory(config: dict):
        async def agent(prompt: str) -> str:
            if prompt == "sealed":
                sealed_calls.append((config["v"], prompt))
            return "PASS" if config["v"] == 1 else "FAIL"
        return agent

    best = await evolve_with_eval(
        {"v": 0},
        [EvalCase(prompt="development", check=lambda out: out == "PASS")],
        factory,
        generations=1,
        mutate=lambda _cfg: {"v": 1},
        confirmation_cases=[
            EvalCase(prompt="sealed", check=lambda out: out == "PASS")
        ],
        confirmation_margin=0.25,
    )

    assert best.config == {"v": 1}
    assert sealed_calls == [(0, "sealed"), (1, "sealed")]


@pytest.mark.asyncio
async def test_risk_limited_requires_authorization_before_development_spend(monkeypatch):
    monkeypatch.setattr("maverick_evolve.runner.calibration_frozen", lambda: False)
    monkeypatch.setattr(
        "maverick_evolve.runner.strict_calibration_ready",
        lambda **_kwargs: True)
    calls = []

    def factory(config):
        calls.append(config)
        return _factory_threshold("v", 1)(config)

    with pytest.raises(ValueError, match="durable confirmation authorization"):
        await evolve_with_eval(
            {"v": 0},
            [EvalCase(prompt="dev", check=lambda _out: True)],
            factory,
            generations=1,
            mutate=lambda _config: {"v": 1},
            confirmation_cases=[
                EvalCase(prompt=f"sealed-{index}", check=lambda _out: True)
                for index in range(20)
            ],
            risk_limited=True,
        )
    assert calls == []


def test_risk_limited_confirmation_overrides_can_only_tighten():
    from maverick_evolve.runner import _confirmation_policy

    cases = tuple(
        EvalCase(prompt=f"sealed-{index}", check=lambda _out: True)
        for index in range(20)
    )
    minimum, critical = _confirmation_policy(
        cases,
        risk_limited=True,
        minimum_cases=0,
        confidence_z=0.0,
        authorize=_risk_permit,
        case_family_id=_FAMILY_ID,
        evaluator_id=_EVALUATOR_ID,
    )

    assert minimum == 20
    assert critical == 1.96


@pytest.mark.asyncio
async def test_risk_limited_authorizes_before_sealed_access_and_clears_bound(monkeypatch):
    monkeypatch.setattr("maverick_evolve.runner.calibration_frozen", lambda: False)
    monkeypatch.setattr(
        "maverick_evolve.runner.strict_calibration_ready",
        lambda **_kwargs: True)
    calls: list[tuple[int, str]] = []
    authorized = []

    def factory(config):
        async def agent(prompt):
            calls.append((config["v"], prompt))
            return "PASS" if config["v"] == 1 else "FAIL"
        return agent

    def authorize(request):
        assert request.seed_candidate_id != request.champion_candidate_id
        assert request.case_count == 20
        assert request.case_family_id == _FAMILY_ID
        assert request.evaluator_id == _EVALUATOR_ID
        assert not any(prompt.startswith("sealed-") for _, prompt in calls)
        authorized.append((request.seed_candidate_id, request.champion_candidate_id))
        return _risk_permit(request)

    best = await evolve_with_eval(
        {"v": 0},
        [EvalCase(prompt="dev", check=lambda out: out == "PASS")],
        factory,
        generations=1,
        mutate=lambda _config: {"v": 1},
        confirmation_cases=[
            EvalCase(prompt=f"sealed-{index}", check=lambda out: out == "PASS")
            for index in range(20)
        ],
        risk_limited=True,
        confirmation_authorize=authorize,
        confirmation_family_id=_FAMILY_ID,
        confirmation_evaluator_id=_EVALUATOR_ID,
    )
    assert best.config == {"v": 1}
    assert len(authorized) == 1
    sealed = [(v, prompt) for v, prompt in calls if prompt.startswith("sealed-")]
    assert len(sealed) == 40
    for index in range(20):
        pair = [v for v, prompt in sealed if prompt == f"sealed-{index}"]
        assert pair == ([0, 1] if index % 2 == 0 else [1, 0])


@pytest.mark.asyncio
async def test_risk_limited_rechecks_calibration_after_sealed_evaluation(
    monkeypatch,
):
    readiness = iter((True, True, False))
    checked_ids = []

    def ready(*, evaluator_id=None):
        checked_ids.append(evaluator_id)
        return next(readiness)

    monkeypatch.setattr(
        "maverick_evolve.runner.strict_calibration_ready", ready)
    sealed_calls = []

    def factory(config):
        async def agent(prompt):
            if prompt.startswith("sealed-"):
                sealed_calls.append((config["v"], prompt))
            return "PASS" if config["v"] == 1 else "FAIL"
        return agent

    best = await evolve_with_eval(
        {"v": 0},
        [EvalCase(prompt="dev", check=lambda out: out == "PASS")],
        factory,
        generations=1,
        mutate=lambda _config: {"v": 1},
        confirmation_cases=[
            EvalCase(prompt=f"sealed-{index}", check=lambda out: out == "PASS")
            for index in range(20)
        ],
        risk_limited=True,
        confirmation_authorize=_risk_permit,
        confirmation_family_id=_FAMILY_ID,
        confirmation_evaluator_id=_EVALUATOR_ID,
    )

    assert best.config == {"v": 0}
    assert len(sealed_calls) == 40  # receipt failed only after sealed evaluation
    assert checked_ids == [_EVALUATOR_ID] * 3


@pytest.mark.asyncio
async def test_risk_limited_rejects_replayed_permit_before_sealed_access(monkeypatch):
    monkeypatch.setattr(
        "maverick_evolve.runner.strict_calibration_ready",
        lambda **_kwargs: True)
    prompts = []

    def factory(config):
        async def agent(prompt):
            prompts.append(prompt)
            return "PASS" if config["v"] == 1 else "FAIL"

        return agent

    best = await evolve_with_eval(
        {"v": 0},
        [EvalCase(prompt="dev", check=lambda out: out == "PASS")],
        factory,
        generations=1,
        mutate=lambda _config: {"v": 1},
        confirmation_cases=[
            EvalCase(prompt=f"sealed-{index}", check=lambda out: out == "PASS")
            for index in range(20)
        ],
        risk_limited=True,
        confirmation_authorize=lambda request: _risk_permit(
            request, request_sha256="d" * 64),
        confirmation_family_id=_FAMILY_ID,
        confirmation_evaluator_id=_EVALUATOR_ID,
    )

    assert best.config == {"v": 0}
    assert prompts and set(prompts) == {"dev"}


@pytest.mark.asyncio
async def test_risk_limited_rejects_duplicate_confirmation_prompts_before_spend(
    monkeypatch,
):
    monkeypatch.setattr(
        "maverick_evolve.runner.strict_calibration_ready",
        lambda **_kwargs: True)
    factory_calls = []

    def factory(config):
        factory_calls.append(config)
        return _factory_threshold("v", 1)(config)

    with pytest.raises(ValueError, match="distinct positive-weight prompts"):
        await evolve_with_eval(
            {"v": 0},
            [EvalCase(prompt="dev", check=lambda _out: True)],
            factory,
            confirmation_cases=[
                EvalCase(prompt="duplicate", check=lambda _out: True)
                for _index in range(20)
            ],
            risk_limited=True,
            confirmation_authorize=_risk_permit,
            confirmation_family_id=_FAMILY_ID,
            confirmation_evaluator_id=_EVALUATOR_ID,
        )

    assert factory_calls == []


@pytest.mark.asyncio
async def test_confirmation_confidence_rejects_one_lucky_case(monkeypatch):
    monkeypatch.setattr("maverick_evolve.runner.calibration_frozen", lambda: False)
    best = await evolve_with_eval(
        {"v": 0},
        [EvalCase(prompt="dev", check=lambda out: out == "PASS")],
        _factory_threshold("v", 1),
        generations=1,
        mutate=lambda _config: {"v": 1},
        confirmation_cases=[
            EvalCase(prompt="sealed", check=lambda out: out == "GOOD")
        ],
        confirmation_min_cases=1,
        confirmation_confidence_z=1.96,
    )
    assert best.config == {"v": 0}


@pytest.mark.asyncio
async def test_metaproductive_search_spends_exact_dev_budget_before_confirmation(
    monkeypatch,
):
    monkeypatch.setattr("maverick_evolve.runner.calibration_frozen", lambda: False)
    calls: list[tuple[int, str]] = []

    def factory(config: dict):
        async def agent(prompt: str) -> str:
            calls.append((config["v"], prompt))
            return "PASS" if config["v"] == 1 else "FAIL"
        return agent

    archive = MetaproductiveArchive(capacity=2)
    best = await evolve_metaproductive_with_eval(
        {"v": 0},
        [EvalCase(prompt=f"dev-{index}", check=lambda out: out == "PASS")
         for index in range(4)],
        factory,
        evaluation_budget=6,
        expansion_budget=1,
        evaluations_per_expansion=1,
        best_belief_z=0.0,
        mutate=lambda _config: {"v": 1},
        archive=archive,
        rng=random.Random(4),
        confirmation_cases=[
            EvalCase(prompt="sealed", check=lambda out: out == "PASS")
        ],
    )

    assert best.config == {"v": 1}
    assert len(calls) == 8
    assert all(prompt.startswith("dev-") for _, prompt in calls[:6])
    assert calls[6:] == [(0, "sealed"), (1, "sealed")]
    assert sum(node.observations for node in archive.nodes.values()) == 6


@pytest.mark.asyncio
async def test_metaproductive_search_rejects_zero_weight_development_case(monkeypatch):
    monkeypatch.setattr("maverick_evolve.runner.calibration_frozen", lambda: False)
    with pytest.raises(ValueError, match="finite and positive"):
        await evolve_metaproductive_with_eval(
            {"v": 0},
            [EvalCase(prompt="dev", check=lambda _out: True, weight=0.0)],
            _factory_threshold("v", 1),
            evaluation_budget=1,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("second_weight", [2.0, 1.0 + 5e-13])
async def test_metaproductive_search_rejects_unequal_case_weights(
    monkeypatch, second_weight,
):
    monkeypatch.setattr("maverick_evolve.runner.calibration_frozen", lambda: False)
    with pytest.raises(ValueError, match="equal development case weights"):
        await evolve_metaproductive_with_eval(
            {"v": 0},
            [
                EvalCase(prompt="dev-a", check=lambda _out: True, weight=1.0),
                EvalCase(
                    prompt="dev-b", check=lambda _out: True,
                    weight=second_weight,
                ),
            ],
            _factory_threshold("v", 1),
            evaluation_budget=1,
        )


@pytest.mark.asyncio
async def test_metaproductive_runner_is_binary_by_default(monkeypatch):
    monkeypatch.setattr("maverick_evolve.runner.calibration_frozen", lambda: False)
    cases = [EvalCase(prompt="dev", reference="reference")]

    with pytest.raises(MetaproductiveSearchError, match="evaluator failed"):
        await evolve_metaproductive_with_eval(
            {"v": 0}, cases, _factory_threshold("v", 1),
            evaluation_budget=1, expansion_budget=0,
            scorer=lambda _output, _reference: 0.5,
        )

    heuristic_archive = MetaproductiveArchive(
        capacity=1, allow_fractional_outcomes=True)
    best = await evolve_metaproductive_with_eval(
        {"v": 0}, cases, _factory_threshold("v", 1),
        evaluation_budget=1, expansion_budget=0,
        scorer=lambda _output, _reference: 0.5,
        allow_fractional_outcomes=True,
        archive=heuristic_archive,
    )
    assert best.score == pytest.approx(0.5)


@pytest.mark.asyncio
async def test_metaproductive_runner_binds_resumed_case_family(monkeypatch):
    monkeypatch.setattr("maverick_evolve.runner.calibration_frozen", lambda: False)
    archive = MetaproductiveArchive(capacity=1)
    cases = [
        EvalCase(prompt="dev-1", check=lambda _out: True),
        EvalCase(prompt="dev-2", check=lambda _out: True),
    ]

    await evolve_metaproductive_with_eval(
        {"v": 0}, cases, _factory_threshold("v", 1),
        evaluation_budget=1, expansion_budget=0,
        case_family_id="d" * 64,
        archive=archive, rng=random.Random(1),
    )
    await evolve_metaproductive_with_eval(
        {"v": 0}, cases, _factory_threshold("v", 1),
        evaluation_budget=2, expansion_budget=0,
        case_family_id="d" * 64,
        archive=archive, rng=random.Random(1),
    )
    assert sum(node.observations for node in archive.nodes.values()) == 2

    changed_cases = [
        EvalCase(prompt="dev-1", check=lambda _out: True),
        EvalCase(prompt="changed", check=lambda _out: True),
    ]
    with pytest.raises(ValueError, match="different case family"):
        await evolve_metaproductive_with_eval(
            {"v": 0}, changed_cases, _factory_threshold("v", 1),
            evaluation_budget=2, expansion_budget=0,
            case_family_id="d" * 64,
            archive=archive, rng=random.Random(1),
        )

    with pytest.raises(ValueError, match="different case family"):
        await evolve_metaproductive_with_eval(
            {"v": 0}, cases, _factory_threshold("v", 1),
            evaluation_budget=2, expansion_budget=0,
            case_family_id="e" * 64,
            archive=archive, rng=random.Random(1),
        )


@pytest.mark.asyncio
async def test_resumed_archive_rejects_undeclared_config_keys(monkeypatch):
    from maverick_evolve.archive import Archive, Candidate

    monkeypatch.setattr("maverick_evolve.runner.calibration_frozen", lambda: False)
    archive = Archive()
    archive.add(Candidate(
        config={"v": 1, "allow_shell": True}, score=1.0))
    with pytest.raises(ValueError, match="undeclared config keys"):
        await evolve_with_eval(
            {"v": 0},
            [EvalCase(prompt="dev", check=lambda _out: True)],
            _factory_threshold("v", 1), generations=0, archive=archive,
            space={"v": ("int", 0, 1)}, revalidate_archive=True,
        )


@pytest.mark.asyncio
async def test_rejected_confirmation_does_not_mutate_caller_archive(monkeypatch):
    from maverick_evolve.archive import Archive, Candidate

    monkeypatch.setattr("maverick_evolve.runner.calibration_frozen", lambda: False)
    archive = Archive()
    seed = archive.add(Candidate(config={"v": 0}, score=0.25))
    archive.mark_confirmed(seed.id)
    before = archive.to_dict()

    result = await evolve_with_eval(
        {"v": 0},
        [EvalCase(prompt="dev", check=lambda out: out == "GOOD")],
        _factory_threshold("v", 1),
        generations=1,
        mutate=lambda _config: {"v": 1},
        archive=archive,
        confirmation_cases=[
            EvalCase(prompt="sealed", check=lambda _out: True),
        ],
    )

    assert result.config == {"v": 0}
    assert archive.to_dict() == before


@pytest.mark.asyncio
async def test_passed_confirmation_qualifies_caller_archive(monkeypatch):
    from maverick_evolve.archive import Archive

    monkeypatch.setattr("maverick_evolve.runner.calibration_frozen", lambda: False)
    archive = Archive()
    result = await evolve_with_eval(
        {"v": 0},
        [EvalCase(prompt="dev", check=lambda out: out == "GOOD")],
        _factory_threshold("v", 1),
        generations=1,
        mutate=lambda _config: {"v": 1},
        archive=archive,
        confirmation_cases=[
            EvalCase(prompt="sealed", check=lambda out: out == "GOOD"),
        ],
    )

    assert result.config == {"v": 1}
    assert archive.confirmed_best().id == result.id
