"""Concurrency battery for the self-harness store.

The store does a load-modify-save (read the addenda, compose, write). Without
serialization two concurrent passes both read the old store and both write back,
losing one's addendum. This battery runs many batches of CONCURRENT distinct
promotions with a deliberately WIDENED read-modify-write window, so a missing
lock loses updates reliably -- it's a regression guard for the in-process +
cross-process locking, not a flake.

(Scaled by thread/operation count, not 100k rounds: concurrency bugs surface
with parallel writers, not sequential volume.)
"""
from __future__ import annotations

import json
import os
import threading
import time

import pytest
from maverick import self_harness as sh
from maverick import self_improvement as si

MAX = sh._MAX_LINES_PER_MODEL


@pytest.fixture(autouse=True)
def _enabled(monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_HARNESS", "1")
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    # Widen the load-modify-save window so an UNLOCKED store reliably loses
    # updates -- the lock must still serialize and keep every promotion.
    orig = sh.load_addenda
    monkeypatch.setattr(sh, "load_addenda",
                        lambda p=None, _o=orig: (_o(p), time.sleep(0.001))[0])


def _promote(model, line_key, store):
    ctrl = si.SelfImprovementController(frozen_fn=lambda: False, ledger=si.PromotionLedger())
    recs = [{"owner": "", "goal_id": 0, "model_id": model, "failure_class": line_key,
             "goal_text": f"task run {i}", "failure_msg": line_key} for i in range(3)]
    sh.run_self_harness(
        recs, model_id=model, min_support=3, held_in=["a", "b"],
        held_out=["c", "d", "e", "f", "g"], score_with=lambda a, c: 0.95,
        score_without=lambda a, c: 0.4, controller=ctrl, path=store)


def _bullets(store, model):
    return [ln for ln in sh.recall_addendum(model, store).splitlines()
            if ln.startswith("- ")]


def test_concurrent_distinct_promotions_lose_nothing(tmp_path):
    # Each batch: MAX threads concurrently promote MAX distinct lines to ONE
    # model on a fresh store. All MAX must survive (== cap) -- a lost update
    # would leave fewer.
    batches = int(os.environ.get("MAVERICK_SELF_HARNESS_CONC_BATCHES", "50"))
    for b in range(batches):
        store = tmp_path / f"b{b}.json"
        threads = [threading.Thread(target=_promote, args=("M", f"cls{k}", store))
                   for k in range(MAX)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        bullets = _bullets(store, "M")
        assert len(bullets) == MAX, f"batch {b}: lost updates -> {len(bullets)}/{MAX}"
        assert len(set(bullets)) == MAX, f"batch {b}: duplicate/garbled lines"
        # store is always valid JSON of str values
        data = json.loads(store.read_text())
        assert isinstance(data, dict) and all(isinstance(v, str) for v in data.values())


def test_concurrent_writes_across_models_stay_isolated(tmp_path):
    # Many models promoted concurrently to ONE shared store: every model's line
    # lands, none clobbers another.
    store = tmp_path / "shared.json"
    models = [f"m{k}" for k in range(12)]
    threads = [threading.Thread(target=_promote, args=(m, f"cls{i}", store))
               for i, m in enumerate(models)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    addenda = json.loads(store.read_text())
    assert set(addenda) == set(models)                    # every model present
    for i, m in enumerate(models):
        assert f"cls{i}" in addenda[m]                    # its own line, isolated
        assert len([ln for ln in addenda[m].splitlines() if ln.startswith("- ")]) == 1


def test_repeated_concurrent_same_line_is_idempotent(tmp_path):
    # MAX threads concurrently promote the SAME line to one model: dedup holds
    # under concurrency -> exactly one bullet, never duplicated or lost.
    store = tmp_path / "dup.json"
    threads = [threading.Thread(target=_promote, args=("M", "samecls", store))
               for _ in range(MAX)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(_bullets(store, "M")) == 1
