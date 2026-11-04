"""Mutation-surfaced coverage battery for the self-harness loop.

Mutation testing (mutate a critical predicate, run the suite, confirm a test
dies) was run over self_harness.py. 10 of 12 mutants were killed by the existing
batteries -- including every correctness/security predicate (scope guard, support
floor, the Cc/Cf sanitizer set, the score-range and regression/no-op validation
gates, the per-model cap, the minimal-length bound) and the strongest-first
signature ordering. Two mutants SURVIVED, exposing real gaps; this file closes
them so those mutants now die too.

  M10  Dropping the in-process ``_lock`` (leaving only the cross-process flock)
       did NOT fail the concurrency battery -- because on POSIX ``flock``
       happens to serialize threads as well, so it masked the loss. But
       ``file_lock`` documents that ``flock`` DEGRADES TO A NO-OP where it is
       unavailable on a POSIX/exotic FS, and there the in-process ``_lock`` is
       the ONLY thing serializing concurrent passes. That fallback path had
       no test. ``test_in_process_lock_is_sole_serializer_without_flock`` makes
       the cross-process lock a no-op (simulating that platform) and proves the
       in-process lock alone loses no updates -- so removing it now fails here.

  M9   The signature summarizer's documented behavior -- pick the MOST FREQUENT
       failure message for the cluster's signature -- was never asserted, so a
       tie-break swapped to "longest" survived. ``test_signature_uses_most_*``
       pins it.

(A third mutant -- removing ``math.isfinite`` from validation -- is a genuine
EQUIVALENT mutant: the ``0.0 <= s <= 1.0`` range check already rejects inf/nan,
since every comparison against them is False. It cannot be killed by behavior
and is kept only as defensive/self-documenting code.)
"""
from __future__ import annotations

import threading
import time

import pytest
from maverick import self_harness as sh
from maverick import self_improvement as si

MAX = sh._MAX_LINES_PER_MODEL


# ---- signature summarizer pins MOST-FREQUENT message -------------------

def test_signature_uses_most_frequent_not_longest_message():
    # Frequency and length deliberately disagree: "short" occurs twice, the
    # longer message once. The signature must reflect the FREQUENT one.
    cluster = [{"failure_class": "timeout", "failure_msg": "short"},
               {"failure_class": "timeout", "failure_msg": "short"},
               {"failure_class": "timeout", "failure_msg": "a much longer message"}]
    sig = sh._summarize_signature(cluster)
    assert "short" in sig
    assert "much longer message" not in sig


def test_signature_frequency_through_mine_failures():
    # Same property end-to-end through mining, so the kill isn't tied to the
    # private helper's name.
    recs = [{"owner": "", "goal_id": 0, "model_id": "M", "failure_class": "timeout", "goal_text": "do the task",
             "failure_msg": m, "channel": None, "user_id": None}
            for m in ["frequent", "frequent", "frequent", "a rare long message"]]
    sigs = sh.mine_failures(recs, model_id="M", min_support=3)
    assert len(sigs) == 1
    assert "frequent" in sigs[0].signature
    assert "rare long message" not in sigs[0].signature


# ---- the in-process lock is the sole serializer without flock ----------

def _promote(model, line_key, store):
    ctrl = si.SelfImprovementController(frozen_fn=lambda: False, ledger=si.PromotionLedger())
    recs = [{"owner": "", "goal_id": 0, "model_id": model, "failure_class": line_key,
             "goal_text": f"task run {i}", "failure_msg": line_key,
             "channel": None, "user_id": None} for i in range(3)]
    sh.run_self_harness(
        recs, model_id=model, min_support=3, held_in=["a", "b"],
        held_out=["c", "d", "e", "f", "g"], score_with=lambda a, c: 0.95,
        score_without=lambda a, c: 0.4, controller=ctrl, path=store)


def _bullets(store, model):
    return [ln for ln in sh.recall_addendum(model, store).splitlines()
            if ln.startswith("- ")]


@pytest.fixture
def _enabled(monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_HARNESS", "1")
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")


def test_in_process_lock_is_sole_serializer_without_flock(_enabled, monkeypatch, tmp_path):
    # Simulate a POSIX filesystem where flock is unavailable: file_lock's cross_process
    # lock degrades to a no-op (it catches ImportError/OSError around fcntl).
    # Force that degradation by making fcntl.flock raise OSError, so ONLY the
    # in-process threading.Lock can serialize the load-modify-save.
    fcntl = pytest.importorskip("fcntl")

    def _no_flock(*_a, **_k):
        raise OSError("flock unavailable on this platform")

    monkeypatch.setattr(fcntl, "flock", _no_flock)

    # Widen the read-modify-write window so an UNSERIALIZED store reliably loses
    # updates -- with the in-process lock intact, every promotion must survive.
    orig = sh.load_addenda
    monkeypatch.setattr(sh, "load_addenda",
                        lambda p=None, _o=orig: (_o(p), time.sleep(0.001))[0])

    store = tmp_path / "addenda.json"
    threads = [threading.Thread(target=_promote, args=("M", f"cls{k}", store))
               for k in range(MAX)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    bullets = _bullets(store, "M")
    assert len(bullets) == MAX, f"lost updates without flock -> {len(bullets)}/{MAX}"
    assert len(set(bullets)) == MAX
