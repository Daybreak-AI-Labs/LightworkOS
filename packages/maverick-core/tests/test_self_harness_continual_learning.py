"""Continual-learning battery: does acquiring new lessons destroy old ones?

The efficacy batteries test ACQUISITION -- does the loop promote good guidance
and refuse bad. This tests a different dimension entirely: RETENTION over a long
sequence of lessons. Catastrophic forgetting is the classic failure of any
continual learner, and the self-harness addendum is a BOUNDED store (the
per-model line cap), so the question is sharp: when more failure classes are
learned than fit, what is lost, and can it be protected?

Characterised here (with the agent oracle measuring per-class success from the
recalled block):

  1. NO FORGETTING WITHIN CAPACITY -- learning up to the cap retains every
     lesson at full strength; the block filling up does not degrade earlier
     lessons.
  2. GRACEFUL, RECENCY-WEIGHTED FORGETTING -- beyond the cap, exactly the newest
     ``cap`` lessons survive and the OLDEST are evicted first (newest-wins),
     never a random or corrupting loss. This is the desirable bounded-memory
     behaviour, and it depends on the char-budget eviction fix dropping whole
     oldest bullets.
  3. REHEARSAL PREVENTS FORGETTING -- a lesson that keeps being re-reinforced
     (re-promoted) is refreshed to newest each time and survives indefinitely,
     even against many competitors. Spaced repetition, for free, from the
     refresh-on-re-promote rule.
  4. NO INTERFERENCE -- with the block full, every retained lesson still helps
     simultaneously; accumulated guidance does not blunt itself.
"""
from __future__ import annotations

import random

import pytest
from maverick import self_harness as sh
from maverick import self_improvement as si

CAP = sh._MAX_LINES_PER_MODEL
BASE_P, GUIDED_P = 0.15, 0.90


@pytest.fixture(autouse=True)
def _enabled(monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_HARNESS", "1")
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")


def _cue(c):
    return f"[{c}]"


def _learn(store, cls):
    ctrl = si.SelfImprovementController(frozen_fn=lambda: False, ledger=si.PromotionLedger())
    recs = [{"owner": "", "goal_id": 0, "model_id": "M", "failure_class": cls, "goal_text": f"{cls} variant {i}",
             "failure_msg": f"{cls} precondition missed", "channel": None, "user_id": None}
            for i in range(4)]
    return sh.run_self_harness(
        recs, model_id="M", min_support=3,
        held_in=[f"{cls}::hi{i}" for i in range(10)], held_out=[f"{cls}::ho{i}" for i in range(20)],
        score_with=lambda t, c: 0.9, score_without=lambda t, c: 0.15,
        propose_fn=lambda s, _c=cls: f"for failures {_cue(_c)} verify the precondition",
        controller=ctrl, path=store)


def _success(store, cls, n=4000):
    rng = random.Random(hash(cls) % 10_000)
    block = sh.recall_addendum("M", store)
    return sum(rng.random() < (GUIDED_P if _cue(cls) in block else BASE_P) for _ in range(n)) / n


def _retained(store, classes):
    block = sh.recall_addendum("M", store)
    return [c for c in classes if _cue(c) in block]


def test_no_forgetting_within_capacity(tmp_path):
    store = tmp_path / "a.json"
    classes = [f"cls{i:02d}" for i in range(CAP)]
    for c in classes:
        _learn(store, c)
    # all CAP lessons retained, each at full strength, no degradation
    assert _retained(store, classes) == classes
    for c in classes:
        assert _success(store, c) > 0.8, f"{c} degraded while still within capacity"


def test_graceful_recency_weighted_forgetting_beyond_capacity(tmp_path):
    store = tmp_path / "a.json"
    classes = [f"cls{i:02d}" for i in range(CAP + 4)]
    # track the moment the first lesson is forgotten
    forgot_at = None
    for i, c in enumerate(classes):
        _learn(store, c)
        if _cue("cls00") not in sh.recall_addendum("M", store) and forgot_at is None:
            forgot_at = i
    # it survives exactly until the (cap+1)-th lesson pushes it out
    assert forgot_at == CAP, f"cls00 forgotten at {forgot_at}, expected {CAP}"
    # exactly the newest CAP survive -- ordered eviction, not random loss
    assert _retained(store, classes) == classes[-CAP:]
    block = sh.recall_addendum("M", store)
    assert len([b for b in block.splitlines() if b.startswith("- ")]) == CAP
    # the evicted ones are truly gone (back to baseline), the kept ones full
    assert _success(store, "cls00") < 0.25
    assert _success(store, classes[-1]) > 0.8


def test_rehearsal_prevents_forgetting(tmp_path):
    store = tmp_path / "a.json"
    classes = [f"cls{i:02d}" for i in range(CAP + 6)]
    for i, c in enumerate(classes):
        _learn(store, c)
        if i % 2 == 1:
            _learn(store, "cls00")          # rehearse the first lesson periodically
    # despite far more than CAP competitors, the rehearsed lesson survives
    assert _cue("cls00") in sh.recall_addendum("M", store)
    assert _success(store, "cls00") > 0.8
    # and a NON-rehearsed early lesson is gone, confirming rehearsal is what saved it
    assert _success(store, "cls01") < 0.25


def test_no_interference_across_retained_lessons(tmp_path):
    store = tmp_path / "a.json"
    classes = [f"cls{i:02d}" for i in range(CAP)]
    for c in classes:
        _learn(store, c)
    # the full block helps EVERY retained class at once -- no mutual blunting
    assert all(_success(store, c) > 0.8 for c in classes)
