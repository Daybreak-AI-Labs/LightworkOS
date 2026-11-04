"""Live captions: rolling window, segment coercion, stream, source registry."""
from __future__ import annotations

import asyncio

import pytest
from maverick import live_captions as lc


def test_window_accumulates_finalized_segments():
    w = lc.CaptionWindow(max_chars=100)
    assert w.push(lc.Segment("hello there")) == "hello there"
    assert w.push(lc.Segment("general kenobi")) == "hello there general kenobi"


def test_inflight_partial_is_replaced_then_finalized():
    w = lc.CaptionWindow(max_chars=100)
    w.push(lc.Segment("first sentence."))
    assert w.push(lc.Segment("sec", final=False)) == "first sentence. sec"
    assert w.push(lc.Segment("second", final=False)) == "first sentence. second"
    # The final replaces the partial — no duplicated 'second'.
    assert w.push(lc.Segment("second sentence.")) == "first sentence. second sentence."


def test_window_trims_left_at_word_boundary():
    w = lc.CaptionWindow(max_chars=20)
    w.push(lc.Segment("alpha bravo charlie"))
    out = w.push(lc.Segment("delta"))
    assert out == "bravo charlie delta"
    assert len(out) <= 20
    assert not out.startswith(" ")


def test_window_max_chars_floor_and_whitespace_normalized():
    w = lc.CaptionWindow(max_chars=1)
    assert w.max_chars == 16
    assert w.push(lc.Segment("  spaced \n out  ")) == "spaced out"


def test_long_stream_prunes_old_finalized_segments():
    w = lc.CaptionWindow(max_chars=24)
    for i in range(500):
        w.push(lc.Segment(f"word{i}"))
    assert len(w._final) < 10  # O(window), not O(transcript)
    assert w.text.endswith("word499")


def test_as_segment_coerces_dict_tuple_str():
    s = lc.as_segment({"text": "hi", "final": False, "ts": 3.5})
    assert (s.text, s.final, s.ts) == ("hi", False, 3.5)
    s = lc.as_segment(("yo", False))
    assert (s.text, s.final) == ("yo", False)
    s = lc.as_segment("plain")
    assert (s.text, s.final) == ("plain", True)
    seg = lc.Segment("x")
    assert lc.as_segment(seg) is seg


def test_caption_stream_yields_one_frame_per_segment():
    async def _source():
        yield lc.Segment("the quick", final=False, ts=1.0)
        yield lc.Segment("the quick brown fox", ts=2.0)
        yield {"text": "jumps", "ts": 3.0}

    async def _collect():
        return [f async for f in lc.caption_stream(_source(), max_chars=80)]

    frames = asyncio.run(_collect())
    assert [f["caption"] for f in frames] == [
        "the quick", "the quick brown fox", "the quick brown fox jumps",
    ]
    assert [f["final"] for f in frames] == [False, True, True]
    assert frames[2]["ts"] == 3.0


def test_source_registry_lifecycle():
    async def _factory():  # pragma: no cover - never iterated here
        yield lc.Segment("x")

    assert lc.get_source("mic1") is None
    lc.register_source("mic1", _factory)
    try:
        assert lc.get_source("mic1") is _factory
        assert "mic1" in lc.available_sources()
    finally:
        assert lc.unregister_source("mic1") is True
    assert lc.unregister_source("mic1") is False
    assert lc.get_source("mic1") is None


def test_register_source_validates_inputs():
    with pytest.raises(ValueError):
        lc.register_source("", lambda: None)
    with pytest.raises(ValueError):
        lc.register_source("x", "not-callable")  # type: ignore[arg-type]
