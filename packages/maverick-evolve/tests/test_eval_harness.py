from __future__ import annotations

import pytest
from maverick_evolve.eval_harness import EvalCase, evaluate, evaluate_case


@pytest.mark.asyncio
async def test_ground_truth_check_scores():
    async def agent(prompt: str) -> str:
        return "42" if "answer" in prompt else "?"

    cases = [
        EvalCase(prompt="the answer", check=lambda o: o == "42"),
        EvalCase(prompt="nope", check=lambda o: o == "42"),
    ]
    rep = await evaluate(agent, cases)
    assert rep.n == 2
    assert rep.score == 0.5


@pytest.mark.asyncio
async def test_reference_contains_scorer():
    async def agent(prompt: str) -> str:
        return "the capital is Paris."

    cases = [EvalCase(prompt="capital of France?", reference="Paris")]
    rep = await evaluate(agent, cases)
    assert rep.score == 1.0


@pytest.mark.asyncio
async def test_agent_exception_scores_zero():
    async def agent(prompt: str) -> str:
        raise RuntimeError("boom")

    cases = [EvalCase(prompt="x", check=lambda o: o == "ok")]
    rep = await evaluate(agent, cases)
    assert rep.score == 0.0  # Failed execution is ungraded and contributes zero.


@pytest.mark.asyncio
async def test_weighting():
    async def agent(prompt: str) -> str:
        return "good" if prompt == "easy" else "bad"

    cases = [
        EvalCase(prompt="easy", check=lambda o: o == "good", weight=1.0),
        EvalCase(prompt="hard", check=lambda o: o == "good", weight=3.0),
    ]
    rep = await evaluate(agent, cases)
    # only the weight-1 case passes -> 1/4
    assert rep.score == 0.25


@pytest.mark.asyncio
@pytest.mark.parametrize("weight", [True, -1.0, float("nan"), float("inf")])
async def test_invalid_case_weight_fails_before_agent_access(weight):
    calls = []

    async def agent(prompt):
        calls.append(prompt)
        return "good"

    with pytest.raises(ValueError, match="weight"):
        await evaluate(
            agent, [EvalCase(prompt="unsafe", check=lambda _out: True, weight=weight)])
    assert calls == []


@pytest.mark.asyncio
async def test_finite_weights_with_infinite_total_fail_before_agent_access():
    calls = []

    async def agent(prompt):
        calls.append(prompt)
        return "good"

    cases = [
        EvalCase(prompt=f"case-{index}", check=lambda _out: True, weight=1e308)
        for index in range(2)
    ]
    with pytest.raises(ValueError, match="finite positive total weight"):
        await evaluate(agent, cases)
    assert calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad_score",
    [float("nan"), float("inf"), True, "bad", -0.01, 1.01, 999.0],
)
async def test_reference_scorer_rejects_invalid_numeric_evidence(bad_score):
    async def agent(_prompt: str) -> str:
        return "output"

    with pytest.raises(ValueError, match="evaluator score"):
        await evaluate_case(
            agent,
            EvalCase(prompt="case", reference="reference"),
            scorer=lambda _out, _reference: bad_score,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_result", [1, 0, "false", None])
async def test_ground_truth_check_rejects_non_boolean_result(bad_result):
    async def agent(_prompt: str) -> str:
        return "output"

    with pytest.raises(ValueError, match="exact boolean"):
        await evaluate_case(
            agent,
            EvalCase(prompt="case", check=lambda _out: bad_result),
        )
