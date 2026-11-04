"""The Emergent Substrate: learn a shorthand for repeated coordination, compress
with it, and -- the contract that makes it deployable -- decode EXACTLY back to
English so nothing is ever hidden.
"""
from __future__ import annotations

from maverick import emergent_protocol as ep

CORPUS = [
    "spawning sub-agent for research task",
    "spawning sub-agent for analysis task",
    "spawning sub-agent for research task",
    "verification passed with high confidence",
    "verification passed with high confidence",
    "blocked on user approval for high-risk action",
    "blocked on user approval for high-risk action",
]


def test_learn_codes_the_repeated_boilerplate():
    book = ep.learn(CORPUS)
    assert book.size > 0
    # the most-repeated phrases earn codes
    assert any("spawning sub-agent for" in p for p in book.forward)
    assert any("verification passed" in p for p in book.forward)


def test_encoding_actually_compresses():
    book = ep.learn(CORPUS)
    assert ep.compression_ratio(CORPUS, book) < 1.0
    one = "verification passed with high confidence"
    assert len(ep.encode(one, book)) < len(one)


def test_round_trip_is_exact_for_every_message():
    book = ep.learn(CORPUS)
    # in-corpus, novel, overlapping, and substring-y messages all round-trip
    probes = CORPUS + [
        "a totally novel message the codebook never saw",
        "verification passed with high confidence and verification passed again",
        "spawning sub-agents (note: 'spawning sub-agent for' appears mid-word-ish)",
        "",
    ]
    for m in probes:
        assert ep.decode(ep.encode(m, book), book) == m


def test_empty_codebook_is_identity():
    book = ep.Codebook()
    assert ep.encode("anything at all", book) == "anything at all"
    assert ep.decode("anything at all", book) == "anything at all"
    assert ep.compression_ratio(["abc"], book) == 1.0


def test_store_roundtrip_and_audit(tmp_path):
    store = ep.CodebookStore(path=tmp_path / "cb.json")
    store.update(ep.learn(CORPUS))
    book = store.book()
    msg = "verification passed with high confidence"
    coded = ep.encode(msg, book)
    # persisted codebook still decodes the compressed form back to plain English
    reloaded = ep.CodebookStore(path=tmp_path / "cb.json").book()
    assert ep.decode(coded, reloaded) == msg


def test_enabled_off_by_default(monkeypatch):
    monkeypatch.delenv("MAVERICK_EMERGENT_PROTOCOL", raising=False)
    monkeypatch.setattr("maverick.config.get_emergent_protocol", lambda: {"enable": False})
    assert ep.enabled() is False
    monkeypatch.setenv("MAVERICK_EMERGENT_PROTOCOL", "1")
    assert ep.enabled() is True


def test_round_trip_holds_when_content_contains_sentinels():
    """The audit contract decode(encode(x)) == x must hold even when x itself
    contains the sentinel brackets -- a literal '⟦0⟧' in coordination content used
    to be misread as a code and corrupted on round-trip."""
    book = ep.learn(["alpha beta gamma", "alpha beta", "gamma delta"] * 5)
    for msg in [
        "alpha beta ⟦0⟧ gamma",       # literal that collides with a real code
        "⟦999⟧ alpha beta",           # code-shaped literal, out of range
        "alpha ⟦ beta ⟧ gamma",       # lone brackets
        "⟦⟦⟦ nested opens",
        "⟦0⟧⟦1⟧ back to back",
    ]:
        assert ep.decode(ep.encode(msg, book), book) == msg


def test_round_trip_fuzz_with_sentinel_alphabet():
    import random
    book = ep.learn(["alpha beta gamma", "alpha beta", "gamma delta"] * 5)
    alphabet = list("alpha beta gamma delta ") + ["⟦", "⟧", "0", "1", "9"]
    rng = random.Random(7)
    for _ in range(3000):
        s = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 30)))
        assert ep.decode(ep.encode(s, book), book) == s


def test_store_concurrent_updates_stay_valid(tmp_path):
    """Separate stores at one path updating the whole codebook concurrently
    must leave a valid, fully-readable book and no stray temp."""
    import threading

    from maverick import emergent_protocol as ep

    p = tmp_path / "codebook.json"
    n = 12

    def worker(i: int):
        store = ep.CodebookStore(path=p)
        store.update(ep.Codebook(forward={f"phrase{i}": f"c{i}"}))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    final = ep.CodebookStore(path=p).book()
    assert isinstance(final.forward, dict) and final.forward
    assert list(tmp_path.glob("*.tmp")) == []
