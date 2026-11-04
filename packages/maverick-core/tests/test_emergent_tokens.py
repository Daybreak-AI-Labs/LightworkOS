"""Tokenizer-aware codec: codes that save tokens, with the audit contract intact.

The contract is ``decode(encode(x)) == x`` for ANY input -- including content that
literally contains the escape and marker bytes. These tests fuzz that property
hard (a naive str.replace decode fails it), then pin the token-saving behaviour
with a deterministic stub tokenizer so CI needs no real BPE."""
from __future__ import annotations

import random

from maverick import emergent_tokens as et

ESC = "\x1b"  # reserved escape byte


def _chars(s: str) -> int:
    """Deterministic stub tokenizer: one token per character."""
    return len(s)


def _book(escape=ESC, markers=("A", "B", "C", "D")):
    # Train on a corpus with clear repetition so phrases get coded.
    msgs = ["alpha beta gamma", "alpha beta", "gamma delta epsilon"] * 4
    return et.learn(msgs, escape=escape, markers=list(markers))


def test_round_trip_basic():
    book = _book()
    assert book.size > 0
    for m in ["alpha beta gamma", "gamma delta epsilon", "alpha beta and gamma delta epsilon"]:
        assert et.decode(et.encode(m, book), book) == m


def test_round_trip_adversarial():
    # Markers deliberately chosen as ordinary letters that ALSO appear in content,
    # and content that literally contains the escape and code byte-sequences.
    book = _book(markers=("a", "b", "g", "d"))  # collide with alpha/beta/gamma/delta
    cases = [
        f"a literal escape {ESC} here",
        f"{ESC}{ESC}{ESC}{ESC} runs of escapes",
        f"a code lookalike {ESC}a and {ESC}b",
        "alpha beta" + ESC + "gamma delta epsilon",
        ESC,                       # lone trailing escape
        "",                        # empty
        "no codeable phrases at all",
    ]
    for m in cases:
        assert et.decode(et.encode(m, book), book) == m, repr(m)


def test_round_trip_fuzz():
    book = _book(markers=("A", "B", "C", "D", "E"))
    alphabet = list("alpha beta gamma delta epsilon ") + [ESC, "A", "B", "C", "x", "y"]
    rng = random.Random(1234)
    for _ in range(2000):
        s = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
        assert et.decode(et.encode(s, book), book) == s, repr(s)


def test_empty_pool_is_identity():
    msgs = ["alpha beta", "alpha beta"]
    for bad in (et.learn(msgs, escape="", markers=["A"]),
                et.learn(msgs, escape=ESC, markers=[])):
        assert bad.size == 0
        assert et.encode("alpha beta", bad) == "alpha beta"
        assert et.decode("alpha beta", bad) == "alpha beta"


def test_marker_equal_escape_is_skipped():
    book = et.learn(["alpha beta"] * 4, escape=ESC, markers=[ESC, "A"])
    # ESC marker is dropped; only "A" remains usable.
    assert ESC not in book.reverse
    assert all(code.startswith(ESC) for code in book.forward.values())


def test_codes_are_cheap_and_save_tokens():
    # Stub tokenizer: 1 token per character. A coded phrase ("alpha beta" = 10 chars)
    # collapses to ESC+marker = 2 chars -> 2 "tokens": a real saving.
    book = _book()
    msgs = ["alpha beta gamma"] * 10
    saved = et.token_savings(msgs, book, count_tokens=_chars)
    assert saved > 0


def test_single_token_markers_filters():
    # 1 "token" iff single char (stub); exclude escape and corpus members.
    cands = ["A", "B", "CC", "D", ESC, "E"]
    out = et.single_token_markers(_chars, cands, escape=ESC, corpus=["B occurs here"])
    assert "A" in out and "D" in out and "E" in out
    assert "CC" not in out      # 2 tokens
    assert ESC not in out       # the escape
    assert "B" not in out       # present in corpus


def _toks(s: str) -> int:
    # A "tokenizer" where a 4-char word is ONE token -- the dangerous case: a
    # multi-character string that is nonetheless a single token (like " the").
    return len(s.split()) or len(s)


def test_single_token_markers_rejects_multichar_single_tokens():
    # " the" is 1 token but 4 chars; decode reads one char past escape, so it
    # MUST be rejected or the round-trip (audit contract) breaks.
    out = et.single_token_markers(_toks, [" the", "Z"], escape=ESC)
    assert " the" not in out
    assert "Z" in out


def test_multichar_marker_dropped_round_trip_safe():
    # A multi-char marker passed straight to learn is dropped, never producing a
    # codebook that would corrupt meaning -- it degrades to "no compression".
    book = et.learn(["alpha beta gamma"] * 4, escape=ESC, markers=[" the", "QQ"])
    assert book.size == 0
    msg = "alpha beta gamma"
    assert et.decode(et.encode(msg, book), book) == msg


def test_multichar_escape_yields_identity():
    book = et.learn(["alpha beta gamma"] * 4, escape="ESC", markers=["A", "B"])
    assert book.size == 0
    assert book.escape == ""            # invalid escape not retained
    msg = "alpha beta gamma"
    assert et.decode(et.encode(msg, book), book) == msg


def test_phrase_containing_escape_does_not_corrupt_round_trip():
    # Regression: a learned phrase that itself contains the escape character
    # broke decode(encode(x)) == x. encode() byte-stuffs every literal escape
    # (E -> EE) BEFORE replacing phrases, so a phrase like "deploy #prod"
    # (escape "#") got its own escape stuffed and either no longer matched or
    # collided with the stuffed escapes, corrupting the audit round-trip.
    # learn() must drop such phrases (degrade to no-compression, never corrupt).
    msgs = ["deploy #prod now", "deploy #prod fast"] * 3
    book = et.learn(msgs, escape="#", markers=["A", "B", "C", "D"])
    assert all("#" not in phrase for phrase in book.forward)
    for m in msgs:
        assert et.decode(et.encode(m, book), book) == m


def test_encode_skips_escape_bearing_phrase_from_stale_codebook():
    # Defense-in-depth: a codebook loaded from disk (predating the learn() fix)
    # may still hold an escape-bearing phrase. encode() must skip it rather than
    # corrupt the round-trip.
    book = et.TokenCodebook(
        escape="#",
        forward={"a#b": "#A"},
        reverse={"A": "a#b"},
    )
    msg = "a#b and plain #text"
    assert et.decode(et.encode(msg, book), book) == msg


def test_audit_contract_holds_for_mixed_valid_invalid_markers():
    # Valid single-char markers still code; invalid ones are silently skipped;
    # the round-trip is exact regardless.
    book = et.learn(["alpha beta gamma", "alpha beta"] * 5,
                    escape=ESC, markers=["A", " the", "B", "CC", "C"])
    assert book.size > 0
    assert all(len(code) == 2 for code in book.forward.values())  # esc + 1 char
    for m in ["alpha beta gamma", "alpha beta", "alpha beta gamma and more"]:
        assert et.decode(et.encode(m, book), book) == m


def test_store_concurrent_updates_stay_valid(tmp_path):
    """update() replaces the whole codebook; with the fixed ".tmp" two
    concurrent writers collided. Separate stores at one path updating
    concurrently must leave a valid, fully-readable book and no temp."""
    import threading

    p = tmp_path / "codebook.json"
    n = 12

    def worker(i: int):
        store = et.TokenCodebookStore(path=p)
        book = et.TokenCodebook(escape="␛",
                                forward={f"phrase{i}": f"␛m{i}"})
        store.update(book)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # A fresh load sees a complete, valid codebook (one of the writers' books).
    final = et.TokenCodebookStore(path=p).book()
    assert isinstance(final.forward, dict) and final.forward
    assert list(tmp_path.glob("*.tmp")) == []
