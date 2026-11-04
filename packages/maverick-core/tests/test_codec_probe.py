"""The codec token probe: does the emergent shorthand save TOKENS, not just bytes?

These tests pin the measurement math with a deterministic stub counter (a word
counter), so CI needs no real tokenizer. The point they enforce is the one the
real experiment surfaced: bytes and tokens diverge, and the probe must report the
token truth -- including when the codec costs *more* tokens than it saves."""
from __future__ import annotations

from click.testing import CliRunner
from maverick import codec_probe as cp
from maverick.cli import main
from maverick.emergent_protocol import Codebook


def _words(text: str) -> int:
    """Deterministic stand-in tokenizer: one token per whitespace word."""
    return len(text.split())


def _book(mapping: dict) -> Codebook:
    return Codebook(forward=dict(mapping), reverse={v: k for k, v in mapping.items()})


def test_measure_counts_tokens_and_bytes():
    # "alpha beta" -> "X": one phrase, two words, collapses to a one-word code.
    book = _book({"alpha beta": "X"})
    msgs = ["alpha beta gamma", "alpha beta"]
    d = cp.measure(msgs, book, count_tokens=_words)
    assert d.n_messages == 2
    # originals: 3 + 2 = 5 words; encoded "X gamma" + "X" = 2 + 1 = 3 words.
    assert d.original_tokens == 5
    assert d.encoded_tokens == 3
    assert d.pays_off is True
    assert d.token_savings_pct == (1 - 3 / 5) * 100


def test_codec_can_cost_more_tokens_than_it_saves():
    # A code that is itself multi-"token" (mirrors a sentinel that tokenizes badly):
    # replacing a 1-word phrase with a 3-word code makes the message LONGER.
    book = _book({"sync": "aa bb cc"})
    d = cp.measure(["sync now", "sync"], book, count_tokens=_words)
    assert d.encoded_tokens > d.original_tokens
    assert d.pays_off is False
    assert d.token_savings_pct < 0
    assert d.breakeven_messages == float("inf")  # never repays a negative saving


def test_codebook_token_cost_and_breakeven():
    book = _book({"alpha beta": "X"})
    # preamble is "X=alpha beta" -> "X=alpha", "beta" -> 2 words.
    assert cp.codebook_token_cost(book, count_tokens=_words) == 2
    d = cp.measure(["alpha beta", "alpha beta"], book, count_tokens=_words)
    # 2 words -> 1 word saves 1 token/msg; 2-token codebook / 1 = 2 reuses.
    assert d.breakeven_messages == 2.0


def test_empty_codebook_is_identity():
    d = cp.measure(["nothing to compress here"], Codebook(), count_tokens=_words)
    assert d.original_tokens == d.encoded_tokens
    assert d.pays_off is False  # no strict reduction
    assert d.codebook_tokens == 0


class _World:
    def recent_event_contents(self, limit: int = 5000) -> list[str]:
        return ["spawning sub-agent for research task"] * 6


def test_codec_probe_cli(tmp_path, monkeypatch):
    monkeypatch.setattr("maverick.cli.open_world", lambda db: _World())
    # Inject the stub counter so the CLI needs no real tokenizer.
    monkeypatch.setattr("maverick.codec_probe.resolve_counter",
                        lambda **kw: _words)
    res = CliRunner().invoke(main, ["--db", str(tmp_path / "w.db"), "codec-probe"])
    assert res.exit_code == 0, res.output
    assert "tokens:" in res.output
    assert "bytes :" in res.output


def test_codec_probe_cli_empty(tmp_path, monkeypatch):
    monkeypatch.setattr("maverick.cli.open_world",
                        lambda db: type("E", (), {"recent_event_contents": lambda s, limit=5000: []})())
    res = CliRunner().invoke(main, ["--db", str(tmp_path / "w.db"), "codec-probe"])
    assert res.exit_code == 0, res.output
    assert "no coordination messages" in res.output
