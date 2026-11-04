"""`maverick codec-learn` learns + persists the token-aware codebook and reports
the token savings on real coordination -- with an injected tokenizer so CI needs
no tiktoken."""
from __future__ import annotations

from click.testing import CliRunner
from maverick import emergent_tokens as et
from maverick.cli import main


class _World:
    def recent_event_contents(self, limit: int = 5000) -> list[str]:
        return ["spawning sub agent for research task"] * 5 + \
               ["verification passed with high confidence"] * 5


def _stub_counter(**_kw):
    # 1 "token" per character: single-char candidates qualify as markers, and a
    # coded phrase collapses to 2 chars so token_savings is positive.
    return len


def test_codec_learn_persists_and_reports(tmp_path, monkeypatch):
    monkeypatch.setattr("maverick.cli.open_world", lambda db: _World())
    monkeypatch.setattr("maverick.codec_probe.resolve_counter", _stub_counter)
    store = et.TokenCodebookStore(path=tmp_path / "tb.json")
    monkeypatch.setattr("maverick.emergent_tokens.shared", lambda: store)

    res = CliRunner().invoke(main, ["--db", str(tmp_path / "w.db"), "codec-learn"])
    assert res.exit_code == 0, res.output
    assert "token-aware codes" in res.output
    assert "token savings" in res.output
    # The codebook was persisted and still round-trips exactly.
    book = store.book()
    assert book.size > 0
    msg = "spawning sub agent for research task"
    assert et.decode(et.encode(msg, book), book) == msg


def test_codec_learn_clean_error_without_tokenizer(tmp_path, monkeypatch):
    # No tiktoken + no model: a clean ClickException, not a raw traceback.
    monkeypatch.setattr("maverick.cli.open_world", lambda db: _World())

    def _no_counter(**_kw):
        raise RuntimeError("no token counter available: `pip install tiktoken`")

    monkeypatch.setattr("maverick.codec_probe.resolve_counter", _no_counter)
    res = CliRunner().invoke(main, ["--db", str(tmp_path / "w.db"), "codec-learn"])
    assert res.exit_code != 0
    assert "pip install tiktoken" in res.output
    assert res.exc_info is None or not isinstance(res.exception, RuntimeError)


def test_codec_learn_no_messages(tmp_path, monkeypatch):
    monkeypatch.setattr("maverick.cli.open_world",
                        lambda db: type("E", (), {"recent_event_contents": lambda s, limit=5000: []})())
    res = CliRunner().invoke(main, ["--db", str(tmp_path / "w.db"), "codec-learn"])
    assert res.exit_code == 0, res.output
    assert "no coordination messages" in res.output
