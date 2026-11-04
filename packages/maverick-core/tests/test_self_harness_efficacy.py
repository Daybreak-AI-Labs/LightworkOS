"""End-to-end EFFICACY battery: does the self-harness loop actually learn and
improve -- not merely stay safe, correct, and bounded?

Every other self-harness battery tests a SAFETY property (no crash, no
corruption, determinism, no injection, bounded cost). None tests the value
proposition itself: that mining a model's failures, proposing guidance, and
recalling it into the prompt MEASURABLY raises success on tasks it failed
before -- generalising to unseen cases and without harming unrelated ones.

This closes the loop with a simulated agent oracle at the injected scoring
seam (``score_with``/``score_without`` exist precisely so a live A/B can be
swapped in; here a deterministic, seeded agent stands in). The agent's
competence on a failure CLASS is low until guidance naming that class is in its
prompt, at which point it jumps -- exactly the dynamic the loop is meant to
exploit. The tests then assert the OUTCOME the platform is sold on:

  * a learning CURVE: each pass that learns a new failure class steps overall
    held-out success up, monotonically (the closed lifecycle only adds);
  * GENERALISATION: improvement is measured on a fresh held-out test set,
    disjoint from the cases learning was validated against;
  * SPECIFICITY: an untaught control class never improves (no learning theater)
    and is never regressed;
  * ATTRIBUTION: with the loop DISABLED, nothing is learned and success stays at
    baseline -- so the lift comes from the loop, not the harness scaffolding;
  * HONESTY: when candidate guidance does NOT actually help, the gate refuses
    it -- the loop promotes real improvements, not any improvement.
"""
from __future__ import annotations

import random

import pytest
from maverick import self_harness as sh
from maverick import self_improvement as si

CLASSES = ["auth_timeout", "schema_drift", "rate_limit", "pagination_bug", "retry_storm"]
CONTROL = "unmined_flake"          # never taught -> must never improve
BASE_P, GUIDED_P = 0.15, 0.90      # competence without / with the right guidance


@pytest.fixture(autouse=True)
def _enabled(monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_HARNESS", "1")
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")


def _solves(cls, guidance, rng):
    return rng.random() < (GUIDED_P if cls in (guidance or "") else BASE_P)


def _scorer(seed):
    # (guidance_text, cases) -> success rate; cases tagged "<class>::id".
    def score(text, cases):
        rng = random.Random(seed)
        if not cases:
            return 0.0
        return sum(_solves(c.split("::")[0], text, rng) for c in cases) / len(cases)
    return score


def _cases(cls, n, tag):
    return [f"{cls}::{tag}{i}" for i in range(n)]


def _learn(cls, store):
    ctrl = si.SelfImprovementController(frozen_fn=lambda: False, ledger=si.PromotionLedger())
    recs = [{"owner": "", "goal_id": 0, "model_id": "M", "failure_class": cls, "goal_text": f"{cls} task variant",
             "failure_msg": f"{cls} precondition missed", "channel": None, "user_id": None}
            for _ in range(5)]
    return sh.run_self_harness(
        recs, model_id="M", min_support=3,
        held_in=_cases(cls, 10, "hi"), held_out=_cases(cls, 20, "ho"),
        score_with=_scorer(1), score_without=_scorer(2), controller=ctrl, path=store)


def _overall(store, test_set):
    block = sh.recall_addendum("M", store)
    rng = random.Random(999)
    ok = total = 0
    for cls, cases in test_set.items():
        for _ in cases:
            ok += _solves(cls, block, rng)
            total += 1
    return ok / total


def _fresh_test_set():
    # unseen at learning time (tag "test" != "hi"/"ho"); includes the control.
    return {c: _cases(c, 40, "test") for c in CLASSES + [CONTROL]}


def test_learning_curve_rises_monotonically_and_generalizes(tmp_path):
    store = tmp_path / "addenda.json"
    test = _fresh_test_set()
    curve = [_overall(store, test)]
    for cls in CLASSES:
        rep = _learn(cls, store)
        assert rep.promoted == 1, f"{cls}: expected to learn one guidance line"
        curve.append(_overall(store, test))

    # baseline is low; the loop drives it up substantially on UNSEEN tasks.
    assert curve[0] < 0.25, f"baseline unexpectedly high: {curve[0]}"
    assert curve[-1] > 0.65, f"loop failed to improve held-out success: {curve[-1]}"
    assert curve[-1] - curve[0] > 0.45, f"insufficient lift: {curve}"
    # monotonic non-decreasing within sampling tolerance (the lifecycle only adds)
    assert all(curve[i + 1] >= curve[i] - 0.03 for i in range(len(curve) - 1)), curve
    # every taught class contributed a distinct accumulated line
    bullets = [b for b in sh.recall_addendum("M", store).splitlines() if b.startswith("- ")]
    assert len(bullets) == len(CLASSES)


def test_learning_is_specific_to_taught_classes(tmp_path):
    store = tmp_path / "addenda.json"
    for cls in CLASSES:
        _learn(cls, store)
    block = sh.recall_addendum("M", store)
    rng = random.Random(7)
    taught = sum(_solves("auth_timeout", block, rng) for _ in range(400)) / 400
    control = sum(_solves(CONTROL, block, rng) for _ in range(400)) / 400
    assert taught > 0.7, f"taught class not improved: {taught}"
    assert control < 0.3, f"untaught control spuriously improved: {control}"
    assert taught - control > 0.45


def test_disabled_loop_learns_nothing(tmp_path, monkeypatch):
    # Attribution control: with the loop off, no addendum, success stays baseline.
    monkeypatch.setenv("MAVERICK_SELF_HARNESS", "0")
    store = tmp_path / "addenda.json"
    test = _fresh_test_set()
    before = _overall(store, test)
    rep = _learn("auth_timeout", store)
    assert rep.promoted == 0
    assert sh.recall_addendum("M", store) == ""
    assert abs(_overall(store, test) - before) < 0.02


def test_gate_refuses_guidance_that_does_not_help(tmp_path):
    # Honesty control: a candidate that does NOT raise success is rejected, so the
    # loop only promotes REAL improvements (no learning theater).
    store = tmp_path / "addenda.json"
    ctrl = si.SelfImprovementController(frozen_fn=lambda: False, ledger=si.PromotionLedger())
    recs = [{"owner": "", "goal_id": 0, "model_id": "M", "failure_class": "auth_timeout",
             "goal_text": "auth_timeout task", "failure_msg": "missed",
             "channel": None, "user_id": None} for _ in range(5)]
    flat = _scorer(3)                      # same scorer both sides -> zero delta
    rep = sh.run_self_harness(
        recs, model_id="M", min_support=3, held_in=_cases("auth_timeout", 10, "hi"),
        held_out=_cases("auth_timeout", 20, "ho"),
        score_with=flat, score_without=flat, controller=ctrl, path=store)
    assert rep.promoted == 0
    assert any("no improvement" in s for s in rep.skipped)
    assert sh.recall_addendum("M", store) == ""
