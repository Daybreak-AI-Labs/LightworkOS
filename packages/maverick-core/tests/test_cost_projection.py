"""Plan-time cost projection: deterministic math against pinned price/role
tables, role output defaults, the iterations multiplier, budget verdicts, the
unknown-model fallback, and render contents. Fully offline."""
from __future__ import annotations

import pytest
from maverick import llm as llm_mod
from maverick.cost import projection as cp

PRICES = {
    "m-coder":  (2.0, 10.0),
    "m-writer": (4.0, 20.0),
    "m-cheap":  (0.5, 1.0),
}
ROLES = {
    "coder":      "m-coder",
    "writer":     "m-writer",
    "summarizer": "m-cheap",
    "researcher": "m-coder",
}


@pytest.fixture
def pinned(monkeypatch):
    """Pin the model/price tables and silence every other resolution layer."""
    for var in (
        "MAVERICK_MODEL_OVERRIDE", "MAVERICK_COST_ROUTING",
        "MAVERICK_MODEL_OVERRIDE_CODER", "MAVERICK_MODEL_OVERRIDE_WRITER",
        "MAVERICK_MODEL_OVERRIDE_SUMMARIZER", "MAVERICK_MODEL_OVERRIDE_RESEARCHER",
        "MAVERICK_MODEL_OVERRIDE_MYSTERY",
    ):
        monkeypatch.delenv(var, raising=False)
    import maverick.config as config_mod
    monkeypatch.setattr(config_mod, "load_config", lambda *a, **k: {})
    monkeypatch.setattr(llm_mod, "MODEL_PRICES", dict(PRICES))
    monkeypatch.setattr(llm_mod, "ROLE_MODELS", dict(ROLES))


def test_estimate_step_math(pinned):
    est = cp.estimate_step("coder", "x" * 4000, expected_output_tokens=500)
    assert est.role == "coder"
    assert est.model == "m-coder"
    assert est.in_tokens == 1000 + cp.STEP_OVERHEAD_TOKENS
    assert est.out_tokens == 500
    expected = (est.in_tokens / 1e6) * 2.0 + (500 / 1e6) * 10.0
    assert est.dollars == pytest.approx(expected)


def test_overhead_override(pinned):
    est = cp.estimate_step("coder", "x" * 4000, expected_output_tokens=0, overhead_tokens=0)
    assert est.in_tokens == 1000
    assert est.out_tokens == 0
    assert est.dollars == pytest.approx((1000 / 1e6) * 2.0)


def test_role_output_defaults(pinned):
    writer = cp.estimate_step("writer", "")
    summarizer = cp.estimate_step("summarizer", "")
    assert writer.out_tokens == cp.ROLE_OUTPUT_TOKENS["writer"]
    assert summarizer.out_tokens == cp.ROLE_OUTPUT_TOKENS["summarizer"]
    assert writer.out_tokens > summarizer.out_tokens  # output-heavy roles heavier
    # A role missing from the table gets the documented default.
    unknown_role = cp.estimate_step("qa-bot", "")
    assert unknown_role.out_tokens == cp.DEFAULT_OUTPUT_TOKENS


def test_project_plan_totals_and_by_role(pinned):
    steps = [
        {"role": "coder", "text": "x" * 4000},   # in 3000, out 3000
        {"role": "writer", "text": ""},          # in 2000, out 3000
    ]
    proj = cp.project_plan(steps)
    coder_d = (3000 / 1e6) * 2.0 + (3000 / 1e6) * 10.0
    writer_d = (2000 / 1e6) * 4.0 + (3000 / 1e6) * 20.0
    assert proj.total_dollars == pytest.approx(coder_d + writer_d)
    assert proj.total_tokens == 3000 + 3000 + 2000 + 3000
    assert proj.by_role["coder"] == pytest.approx(coder_d)
    assert proj.by_role["writer"] == pytest.approx(writer_d)
    assert proj.iterations == 1
    assert len(proj.steps) == 2


def test_iterations_multiplier(pinned):
    steps = [{"role": "coder", "text": "x" * 4000}]
    once = cp.project_plan(steps)
    thrice = cp.project_plan(steps, iterations=3)
    assert thrice.total_dollars == pytest.approx(once.total_dollars * 3)
    assert thrice.total_tokens == once.total_tokens * 3
    assert thrice.by_role["coder"] == pytest.approx(once.by_role["coder"] * 3)
    assert len(thrice.steps) == 1  # per-step table stays single-iteration
    with pytest.raises(ValueError):
        cp.project_plan(steps, iterations=0)


def test_default_step_role(pinned):
    proj = cp.project_plan([{"text": "hello"}])
    assert proj.steps[0].role == cp.DEFAULT_STEP_ROLE


def test_budget_verdicts(pinned):
    proj = cp.project_plan([{"role": "coder", "text": "x" * 4000}])  # ~$0.036
    ok = cp.compare_against_budget(proj, 1.0)
    tight = cp.compare_against_budget(proj, 0.045)   # > 70%, <= 100%
    over = cp.compare_against_budget(proj, 0.01)
    assert ok.verdict == "OK"
    assert tight.verdict == "TIGHT"
    assert over.verdict == "OVER"
    for verdict in (ok, tight, over):
        assert verdict.recommendation
        assert "\n" not in verdict.recommendation  # one line
        assert verdict.projected_dollars == pytest.approx(proj.total_dollars)
    # A non-positive budget is OVER for any projected spend.
    assert cp.compare_against_budget(proj, 0.0).verdict == "OVER"


def test_unknown_model_falls_back_to_documented_rate(pinned, monkeypatch):
    monkeypatch.setattr(llm_mod, "MODEL_PRICES", {})
    monkeypatch.setattr(llm_mod, "ROLE_MODELS", {"mystery": "model-nobody-prices-xyz"})
    from maverick.budget import _FALLBACK_PRICE_IN, _FALLBACK_PRICE_OUT
    est = cp.estimate_step("mystery", "x" * 4000, expected_output_tokens=1000)
    expected = (est.in_tokens / 1e6) * _FALLBACK_PRICE_IN + (1000 / 1e6) * _FALLBACK_PRICE_OUT
    assert est.model == "model-nobody-prices-xyz"
    assert est.dollars == pytest.approx(expected)


def test_render_contents(pinned):
    proj = cp.project_plan(
        [{"role": "coder", "text": "x" * 4000}, {"role": "writer", "text": ""}],
        iterations=2,
    )
    out = cp.render(proj)
    assert "coder" in out and "writer" in out
    assert "m-coder" in out and "m-writer" in out
    assert "x2 iterations" in out
    assert f"${proj.total_dollars:.4f}" in out
    assert "estimate" in out.lower()  # labeled as an estimate, not a bill
