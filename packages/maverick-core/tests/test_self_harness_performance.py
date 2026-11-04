"""Algorithmic-complexity / resource-exhaustion battery for the self-harness loop.

Every other battery checks WHAT mining computes; this one checks HOW IT SCALES.
mine_failures greedily clusters traces by goal-text Jaccard overlap, which is
worst-case O(n*clusters) -- O(n^2) when every trace is a distinct goal. Two
hazards live there:

  1. A naive inner loop re-tokenizes the cluster HEAD on every comparison, so
     the pass becomes tokenize-bound O(n^2) (measured: ~69s on 8k traces). The
     head text never changes, so its token set is cached once -- this battery
     pins that with a DETERMINISTIC tokenization-count assertion (no wall-clock
     flakiness): one tokenization per trace, not one per comparison.

  2. The greedy comparison count is still quadratic, so an unbounded trace list
     could hang a pass. mine_failures caps at _MAX_MINE_TRACES (well above the
     runner's recent-500 feed) and keeps the most recent slice -- a DoS backstop
     for a pathological direct caller.

The memoization must not change results: a brute-force reference clustering is
checked for exact equivalence across randomized inputs.
"""
from __future__ import annotations

import random
import time

from maverick import self_harness as sh


def _recs(goals, *, fclass="timeout"):
    return [{"owner": "", "goal_id": 0, "model_id": "M", "failure_class": fclass, "goal_text": g,
             "failure_msg": "x", "channel": None, "user_id": None} for g in goals]


# ---- 1. deterministic complexity guard: tokenize once per trace -------------

def test_clustering_tokenizes_each_trace_once_not_per_comparison(monkeypatch):
    # All-distinct goals = worst case: n clusters, so the OLD per-comparison
    # re-tokenization would call _tokens ~ n + n*(n-1)/2 times. Memoized, it's
    # one tokenization per trace. Counting calls is exact and CI-stable.
    calls = {"n": 0}
    real = sh._tokens

    def counting(t, _r=real):
        calls["n"] += 1
        return _r(t)

    monkeypatch.setattr(sh, "_tokens", counting)
    n = 300
    sh.mine_failures(_recs([f"distinct goal alpha{i} beta{i}" for i in range(n)]),
                     model_id="M", min_support=3)
    # one per trace (+ tiny slack); a regression to O(n^2) would be ~45,000 here.
    assert calls["n"] <= n + 5, (
        f"{calls['n']} tokenizations for {n} traces -- head re-tokenization regressed")


# ---- 2. memoization preserves clustering semantics exactly -----------------

def _bruteforce_supports(recs, sim=0.3, ms=3):
    clusters: list[list[dict]] = []
    for r in recs:
        rt = sh._tokens(str(r.get("goal_text", "")))
        for c in clusters:
            if sh._jaccard(rt, sh._tokens(str(c[0].get("goal_text", "")))) >= sim:
                c.append(r)
                break
        else:
            clusters.append([r])
    return sorted(len(c) for c in clusters if len(c) >= ms)


def test_memoized_clustering_matches_bruteforce_reference():
    rng = random.Random(0xC0FFEE)
    for _ in range(300):
        base = rng.choice(["deploy the service", "export the ledger",
                            "refactor the module", "rotate the keys"])
        goals = [base if rng.random() < 0.6 else f"unrelated {i} {rng.random()}"
                 for i in range(rng.randint(5, 40))]
        recs = _recs(goals)
        got = sorted(s.support for s in
                     sh.mine_failures(recs, model_id="M", min_support=3))
        assert got == _bruteforce_supports(recs)


# ---- 3. DoS backstop: bounded input, most-recent kept ----------------------

def test_dos_cap_bounds_input_and_keeps_most_recent(monkeypatch):
    monkeypatch.setattr(sh, "_MAX_MINE_TRACES", 10)   # small cap for a fast test
    # 10 "ancient" then 10 "recent" -> total 20 > cap 10 -> keep last 10 (recent).
    ancient = _recs(["ancient recurring failure pattern"] * 10)
    recent = _recs(["recent recurring failure pattern"] * 10)
    sigs = sh.mine_failures(ancient + recent, model_id="M", min_support=3)
    blob = " ".join(s.signature + " " + " ".join(s.examples) for s in sigs)
    joined_examples = " ".join(e for s in sigs for e in s.examples)
    assert "recent recurring failure pattern" in joined_examples
    assert "ancient recurring failure pattern" not in joined_examples
    # exactly the recent cluster survives (10 kept, all identical -> one cluster)
    assert sum(s.support for s in sigs) <= 10
    assert blob  # sanity: something was mined


def test_huge_input_is_bounded_not_hung():
    # 50k all-distinct traces would be many minutes uncapped; the cap makes it
    # finish. Generous wall-clock ceiling (coarse net; the real guard is test 1).
    recs = _recs([f"unique goal {i} x{i} y{i}" for i in range(50_000)])
    t0 = time.perf_counter()
    sh.mine_failures(recs, model_id="M", min_support=3)
    assert time.perf_counter() - t0 < 30.0


# ---- 4. realistic volume stays cheap ---------------------------------------

def test_runner_sized_volume_is_fast():
    # The runner feeds <=500 recent traces; even all-distinct that must be quick.
    recs = _recs([f"goal number {i} token{i}" for i in range(500)])
    t0 = time.perf_counter()
    sh.mine_failures(recs, model_id="M", min_support=3)
    assert time.perf_counter() - t0 < 5.0      # ~0.1s actual; 50x margin
