"""Metamorphic property battery for self-harness mining.

A different methodology again: rather than checking an exact output or a safety
bound, this asserts ALGEBRAIC relations that must hold when the INPUT is
transformed -- permute it, add noise, add other-model / scoped records, raise the
threshold. These catch order-dependence, non-determinism, and leakage that
example-based tests miss. (It caught that the greedy clustering was fully
permutation-variant -- the same failures in a different log order mined different
weaknesses -- now fixed by canonicalizing record order.)

Scales with MAVERICK_SELF_HARNESS_FUZZ_ROUNDS (default 1000).
"""
from __future__ import annotations

import os
import random as R

from maverick import self_harness as sh

_CLASSES = ["timeout", "auth", "tool_error", "shield", "parse", "network"]
_FAMILIES = ["export the ledger report", "reconcile partner invoices",
             "deploy the billing service", "audit access logs",
             "migrate the staging database", "close the monthly books"]


def _gen_unscoped(rng, model="M"):
    """A random set of unscoped failures: several classes x goal families,
    with within-family variation so clustering has real work to do."""
    recs = []
    for _ in range(rng.randint(1, 5)):
        fc = rng.choice(_CLASSES)
        fam = rng.choice(_FAMILIES)
        for i in range(rng.randint(1, 6)):
            recs.append({"owner": "", "goal_id": 0, "model_id": model, "failure_class": fc,
                         "goal_text": f"{fam} variant {i % 3}",
                         "failure_msg": rng.choice([f"{fc} boom", "timed out", "err"])})
    return recs


def _scoped(rng, model="M"):
    return [{"owner": "", "goal_id": 0, "model_id": model, "failure_class": rng.choice(_CLASSES),
             "goal_text": f"{rng.choice(_FAMILIES)} {i}", "failure_msg": "evil",
             "channel": rng.choice(["slack:x", "email:y"]),
             "user_id": rng.choice([None, "u1"])}
            for i in range(rng.randint(1, 6))]


def _other_model(rng):
    return [{"owner": "", "goal_id": 0, "model_id": rng.choice(["X", "Y", "Z"]),
             "failure_class": rng.choice(_CLASSES),
             "goal_text": f"{rng.choice(_FAMILIES)} {i}", "failure_msg": "m"}
            for i in range(rng.randint(1, 6))]


def _noise(rng, model="M"):
    # Unique, mutually-dissimilar one-offs (random tokens -> jaccard ~0), so each
    # is its own singleton cluster and is dropped below any min_support >= 2.
    out = []
    for _ in range(rng.randint(0, 6)):
        toks = " ".join(f"z{rng.randrange(10**9)}" for _ in range(5))
        out.append({"owner": "", "goal_id": 0, "model_id": model, "failure_class": rng.choice(_CLASSES),
                    "goal_text": toks, "failure_msg": "noise"})
    return out


def test_self_harness_metamorphic():
    rounds = max(1, int(os.environ.get("MAVERICK_SELF_HARNESS_FUZZ_ROUNDS", "1000")))
    viol: list[str] = []

    def ck(n, cond, msg):
        if not cond:
            viol.append(f"[r{n}] {msg}")

    for n in range(rounds):
        rng = R.Random(2_000_000 + n)        # disjoint seed space
        recs = _gen_unscoped(rng)
        ms = rng.randint(2, 4)
        base = sh.mine_failures(recs, model_id="M", min_support=ms)

        # P1 determinism: same input twice -> identical output.
        ck(n, sh.mine_failures(recs, model_id="M", min_support=ms) == base,
           "non-deterministic on identical input")

        # P2 permutation invariance: order must not change what is mined.
        shuf = recs[:]
        rng.shuffle(shuf)
        ck(n, sh.mine_failures(shuf, model_id="M", min_support=ms) == base,
           "permutation changed the mined signatures")

        # P3 model partition: other models' records cannot affect M's mining.
        ck(n, sh.mine_failures(recs + _other_model(rng), model_id="M", min_support=ms) == base,
           "another model's records changed M's mining")

        # P4 scope additivity: scoped (remote-user) records are dropped, so they
        # cannot change the mined set.
        mixed = recs + _scoped(rng)
        rng.shuffle(mixed)
        ck(n, sh.mine_failures(mixed, model_id="M", min_support=ms) == base,
           "scoped records changed the mined signatures")

        # P5 noise immunity: dissimilar one-offs below the support floor add no
        # signatures and change none.
        noisy = recs + _noise(rng)
        rng.shuffle(noisy)
        ck(n, sh.mine_failures(noisy, model_id="M", min_support=ms) == base,
           "sub-threshold noise changed the mined signatures")

        # P6 min_support monotonicity: raising the floor only ever drops
        # signatures -- every signature at ms+1 also appears at ms.
        higher = sh.mine_failures(recs, model_id="M", min_support=ms + 1)
        ck(n, set(higher) <= set(base), "higher min_support produced a new signature")
        ck(n, len(higher) <= len(base), "higher min_support produced MORE signatures")
        ck(n, all(s.support >= ms + 1 for s in higher), "min_support floor not honored")

    assert not viol, (f"{len(viol)} metamorphic violations across {rounds} rounds:\n"
                      + "\n".join(viol[:40]))
