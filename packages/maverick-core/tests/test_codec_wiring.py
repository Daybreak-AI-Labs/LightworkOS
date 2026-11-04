"""The live codec seam: the blackboard MEASURES the token-aware codec on real
coordination renders without ever changing what agents or the Shield see, and only
once an operator opts in AND a codebook is learned."""
from __future__ import annotations

import pytest
from maverick import codec_telemetry as ct
from maverick import emergent_tokens as et
from maverick.blackboard import Blackboard


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ct.reset()
    ct.set_token_counter(None)
    et.reset_shared()
    monkeypatch.delenv("MAVERICK_EMERGENT_CODEC", raising=False)
    yield
    ct.reset()
    ct.set_token_counter(None)
    et.reset_shared()


def _learned_store(tmp_path):
    msgs = ["spawning sub agent for research", "spawning sub agent for review"] * 6
    markers = [chr(c) for c in range(0x21, 0x40)]
    book = et.learn(msgs, escape="\x1b", markers=markers)
    store = et.TokenCodebookStore(path=tmp_path / "tb.json")
    store.update(book)
    return store


def test_render_unchanged_and_no_telemetry_when_off(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_EMERGENT_CODEC", "off")
    monkeypatch.setattr(et, "shared", lambda: _learned_store(tmp_path))
    bb = Blackboard()
    bb.post("planner", "plan", "spawning sub agent for research")
    out = bb.render()
    assert "spawning sub agent for research" in out      # plain English, verbatim
    assert ct.snapshot().n_blocks == 0                   # OFF -> measured nothing


def test_render_measures_but_does_not_apply_when_on(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_EMERGENT_CODEC", "on")
    store = _learned_store(tmp_path)
    assert store.book().size > 0
    monkeypatch.setattr(et, "shared", lambda: store)
    ct.set_token_counter(lambda s: len(s.split()))

    bb = Blackboard()
    bb.post("planner", "plan", "spawning sub agent for research")
    out = bb.render()

    # The rendered text the agents/Shield see is unchanged -- no codes leak in.
    assert "spawning sub agent for research" in out
    assert "\x1b" not in out
    # But telemetry recorded the would-be compression on this real block.
    snap = ct.snapshot()
    assert snap.n_blocks == 1
    assert snap.byte_savings_pct > 0
    assert snap.token_blocks == 1
    assert snap.token_savings_pct > 0


def test_no_telemetry_when_codebook_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_EMERGENT_CODEC", "on")
    empty = et.TokenCodebookStore(path=tmp_path / "empty.json")  # never learned
    monkeypatch.setattr(et, "shared", lambda: empty)
    bb = Blackboard()
    bb.post("planner", "plan", "nothing learned yet so identity")
    bb.render()
    assert ct.snapshot().n_blocks == 0


def test_store_round_trips_on_disk(tmp_path):
    msgs = ["alpha beta gamma", "alpha beta"] * 5
    book = et.learn(msgs, escape="\x1b", markers=["A", "B", "C"])
    et.TokenCodebookStore(path=tmp_path / "tb.json").update(book)
    reloaded = et.TokenCodebookStore(path=tmp_path / "tb.json").book()
    assert reloaded.escape == "\x1b"
    assert reloaded.forward == book.forward
    # The reloaded book still decodes exactly.
    msg = "alpha beta gamma"
    assert et.decode(et.encode(msg, reloaded), reloaded) == msg
