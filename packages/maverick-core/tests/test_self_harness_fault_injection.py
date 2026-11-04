"""Fault-injection / chaos battery for the self-harness loop.

A learning pass must NEVER perturb the run that hosts it: its docstring promises
it "never raises", and the store it persists must never end up corrupt, partially
written, or littered with stray temp files -- even when the machinery underneath
it is actively failing (disk full, read-only FS, a corrupt store on disk, the
gate throwing, audit/secrets/proposer throwing).

The earlier batteries (example / fuzz / model-based / metamorphic / concurrency)
all assumed the I/O and the injected seams SUCCEED. This one assumes they fail.
It injects an exception (or a corrupt store) at each fault boundary and asserts
the contract holds regardless:

  C1  run_self_harness NEVER raises -- a fault becomes a skipped entry, not a
      propagated exception.
  C2  The harness never WRITES corruption. A corrupt pre-existing store is
      quarantined in place and the defensive recall path yields no prompt data.
  C3  No stale temp file is ever left next to the store.
  C4  On a WRITE fault the store is unchanged from its pre-pass content -- the
      publication is atomic, so it's all-or-nothing, never a torn write.

This is the battery that found the stale-``.tmp`` leak: the old ``_write_addenda``
hand-rolled a fixed ``<name>.tmp`` with no cleanup, so a failed publication left
``addenda.tmp`` behind (and an unlocked rollback racing a locked apply could
collide on that shared name). Routing through ``file_lock.atomic_write_text``
(unique private temp + cleanup-on-failure) closed both. Faults are injected at
that writer's active platform boundary: POSIX uses a path rename, while Windows
uses handle-bound publication so an attacker cannot swap the staged path.
"""
from __future__ import annotations

import json
import os
import random

import pytest
from maverick import audit, file_lock
from maverick import secrets as secrets_mod
from maverick import self_harness as sh
from maverick import self_improvement as si

ORIG = {"M": "Operating guidance learned for this model:\n- seeded line"}


@pytest.fixture(autouse=True)
def _enabled(monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_HARNESS", "1")
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")


def _boom(msg, exc=OSError):
    def _raise(*_a, **_k):
        raise exc(msg)
    return _raise


def _fail_publication(monkeypatch, msg="ENOSPC"):
    """Fault the atomic writer's actual publication seam on this platform."""
    seam = "_windows_replace_open_fd" if os.name == "nt" else "_replace_with_retry"
    monkeypatch.setattr(file_lock, seam, _boom(msg))


def _seed(store):
    sh._write_addenda(dict(ORIG), store)
    return store


def _tmps(d):
    """Any stray temp file next to the store (fixed .tmp or unique mkstemp one)."""
    return [p.name for p in d.iterdir() if p.name.endswith(".tmp")]


def _store_ok(store):
    """C2: absent, or valid JSON dict of str values."""
    if not store.exists():
        return True
    try:
        data = json.loads(store.read_text())
    except ValueError:
        return False
    return isinstance(data, dict) and all(isinstance(v, str) for v in data.values())


def _promote(store, *, model="M", n=4):
    """A pass that WOULD promote one line (passes mine/propose/validate/gate)."""
    ctrl = si.SelfImprovementController(frozen_fn=lambda: False,
                                        ledger=si.PromotionLedger())
    recs = [{"owner": "", "goal_id": 0, "model_id": model, "failure_class": "timeout",
             "goal_text": f"do the thing {i}", "failure_msg": "timed out"}
            for i in range(n)]
    return sh.run_self_harness(
        recs, model_id=model, min_support=3, held_in=["a", "b"],
        held_out=["c", "d", "e", "f", "g"], score_with=lambda a, c: 0.95,
        score_without=lambda a, c: 0.4, controller=ctrl, path=store)


# ---- direct write-fault on the store I/O ----------------------------------

def test_publish_failure_leaves_no_stale_tmp_and_keeps_store_intact(tmp_path, monkeypatch):
    # The regression this battery was written for: publication fails AFTER the
    # temp is written. The store must stay exactly as it was and NO temp may
    # linger (the old fixed-name writer leaked addenda.tmp here).
    store = _seed(tmp_path / "addenda.json")
    _fail_publication(monkeypatch, "ENOSPC: no space left on device")
    with pytest.raises(OSError):
        sh._write_addenda({"M": "x", "N": "y"}, store)   # low-level: this one DOES raise
    assert _tmps(tmp_path) == [], "a failed replace left a stale temp file"
    assert json.loads(store.read_text()) == ORIG, "torn/partial write to the store"


def test_write_fault_during_pass_never_raises_and_store_unchanged(tmp_path, monkeypatch):
    # Same fault, but through the public entry point: the pass swallows it
    # (C1), promotes nothing, leaves the store byte-identical (C4), no temp (C3).
    store = _seed(tmp_path / "addenda.json")
    _fail_publication(monkeypatch)
    rep = _promote(store)                                  # must NOT raise
    assert rep.promoted == 0
    assert any("artifact application" in s for s in rep.skipped)
    assert json.loads(store.read_text()) == ORIG
    assert _tmps(tmp_path) == []


def test_mkstemp_failure_during_pass_never_raises(tmp_path, monkeypatch):
    # The temp can't even be created (read-only dir / fd exhaustion). Still no
    # raise, still no corruption, store untouched.
    store = _seed(tmp_path / "addenda.json")
    monkeypatch.setattr(
        file_lock, "_secure_mkstemp", _boom("EROFS: read-only file system"))
    rep = _promote(store)
    assert rep.promoted == 0 and json.loads(store.read_text()) == ORIG
    assert _tmps(tmp_path) == []


# ---- faults at the injected seams -----------------------------------------

def test_gate_prepare_raising_never_raises_and_store_untouched(tmp_path, monkeypatch):
    store = _seed(tmp_path / "addenda.json")
    monkeypatch.setattr(
        si, "prepare_promotion", _boom("gate kaboom", RuntimeError))
    rep = _promote(store)                                  # gate explodes mid-pass
    assert rep.promoted == 0
    assert json.loads(store.read_text()) == ORIG          # nothing written
    assert _tmps(tmp_path) == []


def test_audit_failure_does_not_block_promotion(tmp_path, monkeypatch):
    # Audit is best-effort: a logging failure must not lose an already-gated
    # promotion nor corrupt the store.
    store = _seed(tmp_path / "addenda.json")
    monkeypatch.setattr(audit, "record", _boom("audit sink down", RuntimeError))
    rep = _promote(store)
    assert rep.promoted == 1                               # write still happened
    assert _store_ok(store)
    data = json.loads(store.read_text())
    assert any("- " in ln for ln in data["M"].splitlines())


def test_scrub_failure_is_swallowed(tmp_path, monkeypatch):
    store = _seed(tmp_path / "addenda.json")
    monkeypatch.setattr(secrets_mod, "scrub", _boom("scrub boom", RuntimeError))
    rep = _promote(store)                                  # sanitize must absorb it
    assert rep.promoted == 1 and _store_ok(store)


def test_proposer_raising_is_swallowed(tmp_path):
    store = _seed(tmp_path / "addenda.json")

    def _bad_propose(_sig):
        raise RuntimeError("proposer exploded")

    rep = _promote_with(store, propose_fn=_bad_propose)
    assert rep.promoted == 0                               # no proposal -> no write
    assert any("no proposal" in s for s in rep.skipped)
    assert json.loads(store.read_text()) == ORIG


def _promote_with(store, **kw):
    ctrl = si.SelfImprovementController(frozen_fn=lambda: False,
                                        ledger=si.PromotionLedger())
    recs = [{"owner": "", "goal_id": 0, "model_id": "M", "failure_class": "timeout",
             "goal_text": f"do the thing {i}", "failure_msg": "timed out"}
            for i in range(4)]
    return sh.run_self_harness(
        recs, model_id="M", min_support=3, held_in=["a", "b"],
        held_out=["c", "d", "e", "f", "g"], score_with=lambda a, c: 0.95,
        score_without=lambda a, c: 0.4, controller=ctrl, path=store, **kw)


# ---- a corrupt / hostile store already on disk ----------------------------

@pytest.mark.parametrize("content", [
    "{ this is not json",          # truncated/garbage
    "[]",                          # valid JSON, wrong type
    "null",                        # valid JSON null
    '{"M": 123}',                  # dict with non-str value
    '{"M": null}',                 # dict with null value
    "",                            # empty file
])
def test_corrupt_store_on_disk_fails_closed(tmp_path, content):
    # Repairing operator data implicitly would erase forensic evidence and let a
    # malformed baseline choose its own replacement. Quarantine it in place,
    # refuse promotion, and keep the defensive recall path empty.
    store = tmp_path / "addenda.json"
    store.write_text(content, encoding="utf-8")
    rep = _promote(store)                                  # must NOT raise
    assert rep.promoted == 0
    assert store.read_text(encoding="utf-8") == content
    assert any("addenda state" in reason for reason in rep.skipped)
    # the corrupt prior value never survives into a recalled prompt
    assert "123" not in sh.recall_addendum("M", store)
    assert _tmps(tmp_path) == []


def test_store_path_is_a_directory_is_handled(tmp_path):
    store = tmp_path / "addenda.json"
    store.mkdir()                                          # can never be written
    rep = _promote(store)                                  # must NOT raise
    assert rep.promoted == 0
    assert any("addenda state" in s for s in rep.skipped)
    assert store.is_dir()                                  # untouched


# ---- the chaos sweep: random fault at a random seam, many rounds ----------

def test_chaos_sweep_holds_the_contract(tmp_path, monkeypatch):
    """Randomly inject ONE fault per round at a random seam and assert the four
    invariants hold every single round. Scaled by round count, env-overridable.

    Unlike the targeted tests above, this catches a fault *combination* or an
    ordering we didn't think to enumerate: the point of chaos testing is the
    faults we didn't write a named test for."""
    rounds = int(os.environ.get("MAVERICK_SELF_HARNESS_CHAOS_ROUNDS", "2000"))
    rng = random.Random(20260626)

    faults = [
        ("publish", lambda mp: _fail_publication(mp)),
        ("chmod", lambda mp: mp.setattr(os, "chmod", _boom("EPERM"))),
        ("prepare", lambda mp: mp.setattr(
            si, "prepare_promotion", _boom("gate", RuntimeError))),
        ("audit", lambda mp: mp.setattr(audit, "record", _boom("audit", RuntimeError))),
        ("scrub", lambda mp: mp.setattr(secrets_mod, "scrub", _boom("scrub", RuntimeError))),
        ("none", lambda mp: None),          # control: a clean round must still pass
    ]
    corruptions = [None, "{bad", "[]", "null", '{"M": 7}', '{"M": null}', ""]

    for i in range(rounds):
        d = tmp_path / f"r{i}"
        d.mkdir()
        store = d / "addenda.json"
        # Sometimes start from a corrupt/hostile store, sometimes a clean one.
        corrupt = rng.choice(corruptions)
        pre = None
        if corrupt is None:
            _seed(store)
            pre = store.read_text()
        else:
            store.write_text(corrupt, encoding="utf-8")

        name, inject = rng.choice(faults)
        with pytest.MonkeyPatch.context() as mp:
            mp.setenv("MAVERICK_SELF_HARNESS", "1")
            mp.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
            inject(mp)
            rep = _promote(store)          # C1: never raises (no try/except here)

        assert rep is not None
        # C2 (the real safety contract): the recall path is ALWAYS safe whatever
        # the on-disk state -- load_addenda is defensive, never raises, never
        # yields a non-str value into a prompt. This holds even when a hostile
        # pre-seeded store ("null", '{"M": 7}') could not be repaired because the
        # injected write fault blocked the rewrite.
        loaded = sh.load_addenda(store)
        assert isinstance(loaded, dict) and all(isinstance(v, str) for v in loaded.values()), \
            f"round {i} [{name}/{corrupt!r}]: recall path unsafe"
        assert _tmps(d) == [], f"round {i} [{name}]: stray temp left"
        if pre is not None:
            # Started from a CLEAN store: the code must never WRITE corruption,
            # so the raw file stays a valid whole dict (unchanged or wholly
            # rewritten) -- never torn.
            assert _store_ok(store), f"round {i} [{name}]: wrote corruption"
            # C4: a WRITE-path fault must leave that clean store byte-identical.
            if name in {"publish", "chmod"}:
                assert store.read_text() == pre, f"round {i} [{name}]: torn write"
