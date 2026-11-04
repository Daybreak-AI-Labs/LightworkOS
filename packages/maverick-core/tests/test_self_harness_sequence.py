"""Stateful model-based sequence battery for the self-harness store.

The single-pass model-based oracle (test_self_harness_battery) checks ONE pass
against an exact-state model. This drives LONG RANDOM SEQUENCES of passes --
promote a new line, re-promote an existing one (refresh), fill past the line
cap (evict), overflow the char budget with long lines, interleave several
models, and intersperse rejected (no-op) passes -- and asserts the persisted
store stays in exact lockstep with an INDEPENDENT reference model of the
documented semantics after every single op.

State accumulation (re-promotion eviction, ordering) is where this loop's
hardest bugs live. This battery generalises the single-shot checks to arbitrary
histories, against a reference that is a fresh reimplementation (not a call
into the code under test), so any divergence is a real discrepancy -- not a
tautology.

The char budget drops whole OLDEST bullets to fit. A plain
``block[:_MAX_ADDENDUM_CHARS]`` truncation would drop the NEWEST bullets
(inverting the newest-wins cap) and could sever a bullet mid-line, corrupting
the last stored line so a later re-promote of it would not dedupe. The
reference encodes the whole-bullet rule and the sequences confirm lockstep.
"""
from __future__ import annotations

import os
import random

import pytest
from maverick import self_harness as sh
from maverick import self_improvement as si

HEADER = "Operating guidance learned for this model:"
MAXL = sh._MAX_LINES_PER_MODEL
MAXC = sh._MAX_ADDENDUM_CHARS


@pytest.fixture(autouse=True)
def _enabled(monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_HARNESS", "1")
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")


# ---- independent reference model of the per-model addendum store -----------

class Ref:
    def __init__(self):
        self.m: dict[str, list[str]] = {}

    @staticmethod
    def _render(ls: list[str]) -> str:
        return HEADER + "\n" + "\n".join(f"- {x}" for x in ls) if ls else HEADER

    def apply(self, model: str, line: str) -> None:
        ls = self.m.setdefault(model, [])
        if line in ls:              # dedup + refresh-to-newest
            ls.remove(line)
        ls.append(line)
        del ls[:-MAXL]              # keep last MAXL (newest-wins)
        while len(ls) > 1 and len(self._render(ls)) > MAXC:
            ls.pop(0)               # drop oldest whole bullet to fit char budget

    def recall(self, model: str) -> str:
        ls = self.m.get(model)
        return self._render(ls) if ls else ""


# ---- drive a real promoting (or rejected) pass for one chosen line ---------

def _pass(store, model, line, *, promote=True):
    ctrl = si.SelfImprovementController(frozen_fn=lambda: False, ledger=si.PromotionLedger())
    recs = [{"owner": "", "goal_id": 0, "model_id": model, "failure_class": "timeout",
             "goal_text": "export the ledger", "failure_msg": "timed out",
             "channel": None, "user_id": None} for _ in range(3)]
    # promote=True -> A/B clears the gate; promote=False -> a flat no-op (rejected),
    # which must leave the store byte-identical.
    sw, swo = (0.95, 0.4) if promote else (0.5, 0.5)
    sh.run_self_harness(
        recs, model_id=model, min_support=3, held_in=["a", "b"],
        held_out=["c", "d", "e", "f", "g"], score_with=lambda a, c, _v=sw: _v,
        score_without=lambda a, c, _v=swo: _v, controller=ctrl,
        propose_fn=lambda s, _l=line: _l, path=store)


def test_random_operation_sequences_track_a_reference_model(tmp_path):
    ops = int(os.environ.get("MAVERICK_SELF_HARNESS_SEQ_OPS", "400"))
    rng = random.Random(0x5E0)
    store = tmp_path / "addenda.json"
    ref = Ref()
    models = ["model-a", "model-b", "model-c"]
    # A line pool mixing SHORT (cap is line-count bound) and LONG (cap is char
    # bound) lines, with reuse so dedup/refresh and both eviction modes all fire.
    short = [f"verify precondition {k} before acting" for k in range(14)]
    long = [f"slow down on case {k} " + "detail " * 34 for k in range(6)]  # ~250 chars
    pool = short + long

    for i in range(ops):
        model = rng.choice(models)
        if rng.random() < 0.12:
            # rejected no-op pass: state must not move
            before = sh.recall_addendum(model, store)
            _pass(store, model, rng.choice(pool), promote=False)
            assert sh.recall_addendum(model, store) == before, f"op {i}: no-op pass mutated state"
        else:
            line = rng.choice(pool)
            _pass(store, model, line, promote=True)
            # the proposer's raw line is sanitized before storage, so the
            # reference tracks what is ACTUALLY stored, not the raw text.
            ref.apply(model, sh._sanitize_line(line))

        # lockstep on EVERY model after EVERY op
        for m in models:
            got = sh.recall_addendum(m, store)
            want = ref.recall(m)
            assert got == want, (
                f"op {i}: divergence for {m}\n--- got ---\n{got!r}\n--- want ---\n{want!r}")
            # structural invariants that must always hold
            bullets = [b for b in got.splitlines() if b.startswith("- ")]
            assert len(bullets) <= MAXL
            assert len(got) <= MAXC
            assert len(bullets) == len(set(bullets)), f"op {i}: duplicate bullet for {m}"


def test_long_lines_keep_newest_not_oldest(tmp_path):
    # Targeted regression for the char-budget bug: promote 8 distinct LONG lines;
    # the survivors must be the NEWEST that fit, in order, never a severed bullet.
    store = tmp_path / "s.json"
    ref = Ref()
    raw = [f"guidance {k} " + "x " * 120 for k in range(8)]   # ~250 chars each
    lines = [sh._sanitize_line(r) for r in raw]               # as actually stored
    for r, ln in zip(raw, lines, strict=True):
        _pass(store, "M", r, promote=True)
        ref.apply("M", ln)
    got = sh.recall_addendum("M", store)
    assert got == ref.recall("M")
    bullets = [b[2:] for b in got.splitlines() if b.startswith("- ")]
    # every surviving bullet is a WHOLE original line (no mid-line truncation)
    assert all(b in lines for b in bullets), "a bullet was severed by the char cap"
    # and they are the NEWEST contiguous suffix that fits (oldest dropped)
    assert bullets == lines[len(lines) - len(bullets):], "kept the wrong lines"
    assert len(got) <= MAXC
