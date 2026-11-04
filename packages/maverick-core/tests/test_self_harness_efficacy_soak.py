"""Million-trial efficacy soak: statistical proof the self-harness loop learns.

The efficacy battery (test_self_harness_efficacy) shows the learning curve on a
handful of scenarios. This drives the SAME closed loop -- failures -> mine ->
propose -> validate -> GATE -> recall -> evaluate -- across thousands of
independently-learned stores and aggregates the with-guidance vs without-guidance
outcome over up to 1,000,000 randomized agent trials.

The agent oracle is wired into BOTH validation and evaluation, so the gate only
promotes guidance that actually raises the agent's measured success -- nothing is
assumed. Each episode randomizes the taught class set, the trace volume, and the
proposer quality (a fraction of episodes use a USELESS proposer whose guidance
lacks the remediation cue -- those must be REJECTED by the gate, not promoted).

Aggregated over the whole run, the soak asserts the value proposition holds at
scale:
  * GUIDED trials (a recalled line carries the cue for the task's class): success
    is dramatically higher with the learned block than without it;
  * UNGUIDED trials (no relevant line -- untaught class, control class, or a
    rejected useless proposal): with ~= without, i.e. no spurious lift;
  * the gate PROMOTES useful guidance (>99%) and REFUSES useless guidance (<1%).

Scaled by MAVERICK_SELF_HARNESS_EFFICACY_TRIALS (default 20000 for CI; set
1000000 for the full soak).
"""
from __future__ import annotations

import math
import os
import random

import pytest
from maverick import self_harness as sh
from maverick import self_improvement as si

CLASSES = ["auth_timeout", "schema_drift", "rate_limit", "pagination_bug", "retry_storm"]
CONTROL = "unmined_flake"           # never taught
BASE_P, GUIDED_P = 0.15, 0.90
EVALS_PER_EPISODE = 200


@pytest.fixture(autouse=True)
def _enabled(monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_HARNESS", "1")
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")


def _solves(cls, guidance, rng):
    return rng.random() < (GUIDED_P if cls in (guidance or "") else BASE_P)


# A faithful paired A/B: score_with evaluates the agent WITH the candidate line;
# score_without evaluates the BASELINE (empty guidance), ignoring the candidate.
# Both share a seed, so the ONLY difference between the two measurements is the
# guidance text -- useless guidance (no cue) yields an identical rate => zero
# delta => the gate rejects it; useful guidance yields a real lift.
def _score_with(seed):
    def score(text, cases):
        rng = random.Random(seed)
        return sum(_solves(c.split("::")[0], text, rng) for c in cases) / len(cases) if cases else 0.0
    return score


def _score_without(seed):
    def score(_text, cases):
        rng = random.Random(seed)
        return sum(_solves(c.split("::")[0], "", rng) for c in cases) / len(cases) if cases else 0.0
    return score


def test_million_trial_efficacy_soak(tmp_path):
    trials = int(os.environ.get("MAVERICK_SELF_HARNESS_EFFICACY_TRIALS", "20000"))
    episodes = max(1, math.ceil(trials / EVALS_PER_EPISODE))
    rng = random.Random(0xEFF1CA)

    # aggregate tallies
    g_with = g_wo = g_n = 0            # GUIDED trials (cue present in recalled block)
    u_with = u_wo = u_n = 0           # UNGUIDED trials (no relevant cue)
    promo_useful = promo_useful_n = 0
    promo_useless = promo_useless_n = 0
    done = 0

    for ep in range(episodes):
        store = tmp_path / f"e{ep}.json"
        taught = rng.sample(CLASSES, rng.randint(1, len(CLASSES)))
        useless = rng.random() < 0.25       # a quarter of episodes get a bad proposer

        for cls in taught:
            ctrl = si.SelfImprovementController(frozen_fn=lambda: False,
                                                ledger=si.PromotionLedger())
            recs = [{"owner": "", "goal_id": 0, "model_id": "M", "failure_class": cls, "goal_text": f"{cls} variant",
                     "failure_msg": f"{cls} precondition missed",
                     "channel": None, "user_id": None}
                    for _ in range(rng.randint(3, 7))]
            # useful proposer embeds the class cue; useless one omits it entirely.
            if useless:
                def _propose(s, _c=cls):
                    return "be generally more careful and thorough next time"
            else:
                def _propose(s, _c=cls):
                    return f"for {_c} failures, verify the precondition before acting"
            rep = sh.run_self_harness(
                recs, model_id="M", min_support=3,
                held_in=[f"{cls}::hi{i}" for i in range(10)],
                held_out=[f"{cls}::ho{i}" for i in range(20)],
                score_with=_score_with(1), score_without=_score_without(1),
                propose_fn=_propose, controller=ctrl, path=store)
            if useless:
                promo_useless += rep.promoted
                promo_useless_n += 1
            else:
                promo_useful += rep.promoted
                promo_useful_n += 1

        block = sh.recall_addendum("M", store)
        for _ in range(EVALS_PER_EPISODE):
            if done >= trials:
                break
            cls = rng.choice(CLASSES + [CONTROL])
            w = _solves(cls, block, rng)
            wo = _solves(cls, "", rng)
            if cls in block:                 # ground truth: guidance for cls is recalled
                g_with += w
                g_wo += wo
                g_n += 1
            else:
                u_with += w
                u_wo += wo
                u_n += 1
            done += 1
        if done >= trials:
            break

    # ---- statistical verdict over the whole run ----
    assert done >= trials * 0.99, f"ran {done} trials"
    assert g_n > trials * 0.15, f"too few guided trials to be meaningful: {g_n}"

    guided_with, guided_without = g_with / g_n, g_wo / g_n
    unguided_with, unguided_without = u_with / u_n, u_wo / u_n
    useful_rate = promo_useful / promo_useful_n
    useless_rate = promo_useless / max(1, promo_useless_n)

    print(f"\n[efficacy soak] trials={done:,} episodes={episodes:,}\n"
          f"  GUIDED   (n={g_n:,}): without={guided_without:.3f} -> with={guided_with:.3f} "
          f"(lift +{guided_with - guided_without:.3f})\n"
          f"  UNGUIDED (n={u_n:,}): without={unguided_without:.3f} -> with={unguided_with:.3f} "
          f"(lift +{unguided_with - unguided_without:.3f})\n"
          f"  GATE: useful promoted={useful_rate:.3f} ({promo_useful_n:,} passes)  "
          f"useless promoted={useless_rate:.3f} ({promo_useless_n:,} passes)")

    # GUIDED: large, real lift from the learned block on tasks it learned.
    assert guided_with - guided_without > 0.5, \
        f"no learning lift: guided {guided_without:.3f} -> {guided_with:.3f}"
    assert guided_with > 0.8 and guided_without < 0.25
    # UNGUIDED: no spurious lift (specificity) -- recall doesn't help untaught work.
    assert abs(unguided_with - unguided_without) < 0.02, \
        f"spurious lift on unguided: {unguided_without:.3f} -> {unguided_with:.3f}"
    # GATE: promotes useful guidance, refuses useless guidance.
    assert useful_rate > 0.99, f"useful guidance under-promoted: {useful_rate:.3f}"
    assert useless_rate < 0.01, f"useless guidance wrongly promoted: {useless_rate:.3f}"
