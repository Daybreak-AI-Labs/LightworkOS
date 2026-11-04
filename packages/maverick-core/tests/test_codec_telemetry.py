"""Live codec telemetry: bytes always, tokens only when a counter is registered."""
from __future__ import annotations

import pytest
from maverick import codec_telemetry as ct


@pytest.fixture(autouse=True)
def _clean():
    ct.reset()
    ct.set_token_counter(None)
    yield
    ct.reset()
    ct.set_token_counter(None)


def test_bytes_measured_without_a_tokenizer():
    ct.record("hello world", "hi")
    snap = ct.snapshot()
    assert snap.n_blocks == 1
    assert snap.original_bytes == len("hello world")
    assert snap.encoded_bytes == len("hi")
    assert snap.byte_savings_pct > 0
    # No tokenizer -> tokens untouched, and the report says so.
    assert snap.token_blocks == 0
    assert snap.to_dict()["tokens_measured"] is False


def test_tokens_measured_when_counter_registered():
    ct.set_token_counter(lambda s: len(s.split()))
    ct.record("alpha beta gamma", "alpha")          # 3 -> 1 words
    snap = ct.snapshot()
    assert snap.original_tokens == 3
    assert snap.encoded_tokens == 1
    assert snap.token_blocks == 1
    assert snap.token_savings_pct == pytest.approx((1 - 1 / 3) * 100)
    assert snap.to_dict()["tokens_measured"] is True


def test_flaky_tokenizer_never_breaks_recording():
    def _boom(_s):
        raise RuntimeError("tokenizer down")

    ct.set_token_counter(_boom)
    ct.record("a b c", "a")          # bytes still recorded; tokens skipped
    snap = ct.snapshot()
    assert snap.n_blocks == 1
    assert snap.token_blocks == 0
    assert snap.original_bytes > 0


def test_snapshot_is_a_copy():
    ct.record("xxxx", "x")
    s1 = ct.snapshot()
    ct.record("yyyy", "y")
    assert s1.n_blocks == 1          # earlier snapshot is frozen
    assert ct.snapshot().n_blocks == 2
