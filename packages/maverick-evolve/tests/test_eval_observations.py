from __future__ import annotations

import asyncio
import logging
import time

import pytest
from maverick.budget import BudgetExceeded, UsageAccountingError
from maverick.killswitch import Halted, HaltGenerationChanged
from maverick_evolve import (
    Candidate,
    ConfirmationPermit,
    EvalCase,
    confirm_candidate,
    evaluate,
    evaluate_case,
    observe_case,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("reference_rubric", [False, True])
async def test_crash_never_enters_a_rubric_that_would_reward_empty(reference_rubric):
    checks = []

    async def crash(_prompt):
        raise RuntimeError("provider credentials must never enter diagnostics")

    def negative_check(answer):
        checks.append(answer)
        return "payment released" not in answer

    def permissive_scorer(answer, _reference):
        checks.append(answer)
        return 1.0

    case = EvalCase("private prompt", **(
        {"reference": "private reference"} if reference_rubric
        else {"check": negative_check}))
    report = await evaluate(crash, [case], scorer=permissive_scorer)
    assert report.score == 0.0
    assert report.observations[0].execution_status == "failed"
    assert report.observations[0].grade is None
    assert report.observations[0].diagnostic == "agent_exception"
    assert await evaluate_case(crash, case, scorer=permissive_scorer) == 0.0
    assert checks == []


@pytest.mark.asyncio
@pytest.mark.parametrize("answer", ["", "I cannot verify this claim."])
async def test_legitimate_empty_or_abstaining_answer_is_a_successful_execution(answer):
    async def abstain(_prompt):
        return answer

    observation = await observe_case(
        abstain, EvalCase("case", check=lambda out: "payment released" not in out))
    assert observation.execution_status == "succeeded"
    assert observation.grade == 1.0
    assert observation.evaluator_id == "unversioned-check"


@pytest.mark.asyncio
async def test_timeout_and_invalid_output_are_explicit_without_rubric_or_retry(caplog):
    calls = []

    async def agent(prompt):
        calls.append(prompt)
        if prompt == "timeout":
            raise asyncio.TimeoutError("private provider error")
        return None

    def must_not_grade(_out):
        pytest.fail("failed or non-string execution reached grader")

    with caplog.at_level(logging.INFO, logger="maverick_evolve.eval_harness"):
        report = await evaluate(agent, [
            EvalCase("timeout", check=must_not_grade),
            EvalCase("non-string", check=must_not_grade),
        ])
    assert calls == ["timeout", "non-string"]
    assert [o.execution_status for o in report.observations] == ["timed_out", "invalid_output"]
    assert all(o.grade is None for o in report.observations)
    assert "private provider error" not in caplog.text


@pytest.mark.asyncio
async def test_real_task_cancellation_is_recorded_then_propagated(caplog):
    started = asyncio.Event()
    calls = []

    async def wait_forever(prompt):
        calls.append(prompt)
        started.set()
        await asyncio.Event().wait()
        return "unreachable"

    with caplog.at_level(logging.INFO, logger="maverick_evolve.eval_harness"):
        task = asyncio.create_task(evaluate(wait_forever, [
            EvalCase("first-private-prompt"), EvalCase("never-exposed")]))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert task.cancelled()
    assert calls == ["first-private-prompt"]
    assert "execution=cancelled" in caplog.text
    assert "first-private-prompt" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("signal", [
    BudgetExceeded, UsageAccountingError, Halted, HaltGenerationChanged,
])
async def test_execution_stop_is_not_turned_into_fitness_or_further_exposure(signal, caplog):
    stop = (Halted("stop-secret", "operator") if signal is Halted
            else signal("stop-secret"))
    calls = []

    async def agent(prompt):
        calls.append(prompt)
        raise stop

    with caplog.at_level(logging.INFO, logger="maverick_evolve.eval_harness"):
        with pytest.raises(signal) as caught:
            await evaluate(agent, [EvalCase("first"), EvalCase("second")])
    assert caught.value is stop
    assert calls == ["first"]
    assert "execution=stopped" in caplog.text
    assert "stop-secret" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("failing_arm", ["seed", "champion"])
async def test_failed_sealed_execution_rejects_with_exact_counterbalanced_exposures(
    failing_arm, monkeypatch, caplog,
):
    monkeypatch.setattr("maverick_evolve.runner.strict_calibration_ready", lambda **_: True)
    seed = Candidate({"arm": "seed"})
    champion = Candidate({"arm": "champion"}, score=1.0)
    exposures = []
    authorizations = []

    def factory(config):
        async def agent(prompt):
            arm = config["arm"]
            exposures.append((arm, prompt))
            if arm == failing_arm and prompt == "case-0":
                raise RuntimeError("sensitive execution error")
            return "PASS" if arm == "champion" else "FAIL"
        return agent

    def authorize(request):
        authorizations.append(request)
        assert not exposures
        now = time.time()
        return ConfirmationPermit(
            request_sha256=request.request_sha256, critical_z=1.96,
            authorization_id="single-exposure-permit", ledger_tip_sha256="c" * 64,
            issued_at=now, expires_at=now + 60,
        )

    cases = [EvalCase(f"case-{i}", check=lambda out: out == "PASS") for i in range(20)]
    with caplog.at_level(logging.INFO, logger="maverick_evolve"):
        result = await confirm_candidate(
            seed, champion, cases, factory, authorize=authorize,
            require_authorization=True, min_cases=20, confidence_z=1.96,
            case_family_id="a" * 64, evaluator_id="b" * 64,
        )
    assert result is seed
    assert len(authorizations) == 1
    assert exposures == [
        (arm, f"case-{i}") for i in range(20)
        for arm in (("seed", "champion") if i % 2 == 0 else ("champion", "seed"))
    ]
    assert caplog.text.count("eval_observation") == 40
    assert caplog.text.count("execution=failed") == 1
    assert "sensitive execution error" not in caplog.text
    assert authorizations[0].request_sha256 in caplog.text
    assert "grade=" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("stop", [asyncio.CancelledError, BudgetExceeded])
async def test_sealed_cancellation_or_stop_never_spends_next_exposure(stop):
    calls = []

    def factory(config):
        async def agent(prompt):
            calls.append((config["arm"], prompt))
            raise stop()
        return agent

    with pytest.raises(stop):
        await confirm_candidate(
            Candidate({"arm": "seed"}), Candidate({"arm": "champion"}),
            [EvalCase("first"), EvalCase("second")], factory)
    assert calls == [("seed", "first")]


@pytest.mark.asyncio
async def test_evaluator_failure_records_execution_success_and_preserves_error(caplog):
    async def agent(_prompt):
        return "valid answer"

    with caplog.at_level(logging.INFO, logger="maverick_evolve.eval_harness"):
        with pytest.raises(ValueError, match="finite"):
            await observe_case(
                agent, EvalCase("case", reference="reference"),
                scorer=lambda *_: float("nan"))
    assert "execution=succeeded diagnostic=evaluator_exception" in caplog.text


@pytest.mark.asyncio
async def test_case_and_evaluator_identity_are_bound_without_logging_secrets(caplog):
    async def agent(_prompt):
        return "answer-secret"

    with caplog.at_level(logging.INFO, logger="maverick_evolve.eval_harness"):
        a = await observe_case(
            agent, EvalCase("prompt-secret", reference="reference-secret"),
            evaluator_id="evaluator-secret", exposure_id="exposure-secret")
        b = await observe_case(
            agent, EvalCase("changed", reference="reference-secret"),
            evaluator_id="b" * 64)
    assert a.case_id != b.case_id
    assert len(a.evaluator_id) == len(a.exposure_id) == 64
    assert b.evaluator_id == "b" * 64
    assert "-secret" not in caplog.text
