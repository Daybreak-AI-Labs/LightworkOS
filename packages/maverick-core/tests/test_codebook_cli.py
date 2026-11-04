"""`maverick codebook` learns the swarm's coordination shorthand from its real
messages -- and every learned code still decodes EXACTLY back to English (the
audit contract holds on whatever the corpus produces)."""
from __future__ import annotations

from click.testing import CliRunner
from maverick import emergent_protocol as ep
from maverick.cli import main
from maverick.world_model import open_world


class _World:
    """Stand-in world exposing the same read-only accessor the command uses."""

    def __init__(self, messages):
        self._messages = messages

    def recent_event_contents(self, limit: int = 5000) -> list[str]:
        return list(self._messages[:limit])


_CORPUS = (
    ["spawning sub-agent for research task"] * 4
    + ["verification passed with high confidence"] * 4
    + ["handing off to the reviewer agent"] * 3
)


def test_codebook_learns_and_round_trips(tmp_path, monkeypatch):
    monkeypatch.setattr("maverick.cli.open_world", lambda db: _World(_CORPUS))
    store = ep.CodebookStore(path=tmp_path / "cb.json")
    monkeypatch.setattr("maverick.emergent_protocol.shared", lambda: store)

    res = CliRunner().invoke(main, ["--db", str(tmp_path / "w.db"), "codebook"])
    assert res.exit_code == 0, res.output
    assert "learned" in res.output

    book = store.book()
    assert book.size > 0
    # The audit contract: every repeated phrase decodes back to exact English.
    for msg in set(_CORPUS):
        assert ep.decode(ep.encode(msg, book), book) == msg


def test_codebook_show_without_relearning(tmp_path, monkeypatch):
    # Seed a store, then `--show` must read it without touching the world.
    store = ep.CodebookStore(path=tmp_path / "cb.json")
    store.update(ep.learn(_CORPUS))
    seeded = store.book().size
    monkeypatch.setattr("maverick.emergent_protocol.shared", lambda: store)

    def _boom(db):  # --show must not open the world
        raise AssertionError("--show should not read the world")

    monkeypatch.setattr("maverick.cli.open_world", _boom)

    res = CliRunner().invoke(main, ["--db", str(tmp_path / "w.db"), "codebook", "--show"])
    assert res.exit_code == 0, res.output
    assert f"codebook: {seeded} codes" in res.output


def test_recent_event_contents_accessor(tmp_path):
    # The real corpus the command learns from: coordination bodies, newest first.
    w = open_world(tmp_path / "world.db")
    gid = w.create_goal("g", "d", owner="")
    w.append_event(gid, "planner", "note", "first message")
    w.append_event(gid, "worker", "note", "second message")
    contents = w.recent_event_contents(limit=10)
    assert "first message" in contents and "second message" in contents
    # Newest-first ordering.
    assert contents.index("second message") < contents.index("first message")
    # Honours the limit.
    assert w.recent_event_contents(limit=1) == ["second message"]


def test_codebook_empty_corpus(tmp_path, monkeypatch):
    monkeypatch.setattr("maverick.cli.open_world", lambda db: _World([]))
    store = ep.CodebookStore(path=tmp_path / "cb.json")
    monkeypatch.setattr("maverick.emergent_protocol.shared", lambda: store)

    res = CliRunner().invoke(main, ["--db", str(tmp_path / "w.db"), "codebook"])
    assert res.exit_code == 0, res.output
    assert "learned 0 codes from 0 messages" in res.output
