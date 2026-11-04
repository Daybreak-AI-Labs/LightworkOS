"""Tokenizer-aware emergent codec -- codes that actually save *tokens*.

The token probe (``codec_probe``) proved the audit-safe sentinel codes ``⟦n⟧``
cost ~5 tokens each, because the guillemets are rare unicode. On realistic
coordination traffic the sentinel codec saves ~50% of *bytes* but *loses* tokens
-- so the Rust->WASM carve (which only makes encode/decode faster) optimizes the
wrong axis. The measured ceiling is ~+41% tokens if each code is a single token
in the target model's vocabulary. This module chases that ceiling.

The tension it resolves: token-cheap characters are *common* (so they collide
with real message text), while collision-proof characters are *rare* (so they
tokenize expensively -- exactly why the sentinels fail). The fix is
**byte-stuffing**, which keeps the audit contract ``decode(encode(x)) == x``
exact for *any* input while letting codes be cheap, ~2-token strings:

    code_i  = ESCAPE + MARKER[i]            # 2 tokens when ESCAPE/MARKER are 1 token
    encode  : double every literal ESCAPE (E -> EE), then replace phrases by codes
    decode  : left-to-right scan -- EE is a literal escape, E+MARKER is a code

``ESCAPE`` and the ``MARKER`` pool are *injected* single-token strings (the
caller picks them from the model's tokenizer), so this module stays pure and
tokenizer-agnostic. With no usable pool, ``learn`` returns an empty codebook --
the identity transform -- so it is never worse than sending plain English.

Audit layer preserved: ``decode`` expands every code back to exact English, so
the Shield / a human still reads plain text while agents move the compressed
form. The round-trip is property-tested against adversarial inputs (content that
literally contains the escape and marker characters).
"""
from __future__ import annotations

import json
import logging
import threading
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .config import env_flag
from .emergent_protocol import learn as _learn_phrases

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class TokenCodebook:
    """A token-aware phrase<->code map. ``escape`` is the reserved stuffing byte;
    each code is ``escape + marker``. The reverse map is the audit layer."""

    escape: str = ""
    forward: dict = field(default_factory=dict)   # phrase -> code (escape+marker)
    reverse: dict = field(default_factory=dict)   # marker -> phrase

    @property
    def size(self) -> int:
        return len(self.forward)

    def to_dict(self) -> dict:
        return {"escape": self.escape, "forward": dict(self.forward)}


def learn(messages, *, escape: str, markers, max_codes: int = 128,
          min_count: int = 2, max_words: int = 6) -> TokenCodebook:
    """Learn a token-aware codebook from a coordination corpus.

    Reuses the phrase-scoring of the sentinel codec (the phrases worth coding are
    the same), then assigns each a cheap ``escape + marker`` code. ``escape`` and
    each ``marker`` MUST be a single character: ``decode`` scans one character past
    the escape, so a multi-character escape or marker would silently break the
    round-trip (the audit contract). Multi-character or duplicate markers, and any
    equal to the escape, are dropped; a non-single-character escape yields the
    identity transform. So a misuse degrades to "no compression", never to a codec
    that corrupts meaning.
    """
    if not escape or len(escape) != 1 or not markers:
        return TokenCodebook(escape=escape if len(escape) == 1 else "")

    phrase_book = _learn_phrases(messages, max_codes=max_codes,
                                 min_count=min_count, max_words=max_words)
    # Single-character markers only -- the invariant decode() relies on.
    pool = [m for m in dict.fromkeys(markers) if len(m) == 1 and m != escape]

    # A phrase that itself contains the escape character cannot be coded
    # safely: encode() byte-stuffs every literal escape (E -> EE) *before*
    # replacing phrases, so the phrase's own escape gets stuffed and either
    # no longer matches or collides with the stuffed escapes -- corrupting the
    # decode() round-trip (e.g. corpus phrase "deploy #prod" with escape "#").
    # Drop such phrases: degrade to no-compression, never to corruption.
    codable = [p for p in phrase_book.forward if escape not in p]

    forward, reverse = {}, {}
    for phrase, marker in zip(codable, pool, strict=False):  # pool may be shorter
        forward[phrase] = escape + marker
        reverse[marker] = phrase
    return TokenCodebook(escape=escape, forward=forward, reverse=reverse)


def encode(text: str, book: TokenCodebook) -> str:
    """Compress ``text``: stuff literal escapes, then replace phrases by codes.

    Doubling every literal ``escape`` first guarantees that, in the output, a lone
    ``escape`` (one not paired with another) can only be the start of a code -- the
    property ``decode`` relies on. An empty codebook is the identity."""
    if not book.forward or not book.escape:
        return text
    text = text.replace(book.escape, book.escape + book.escape)  # byte-stuff literals
    for phrase in sorted(book.forward, key=len, reverse=True):    # longest phrase wins
        # Skip any phrase containing the escape: stuffing it above would make
        # the phrase un-matchable / collide with stuffed escapes and corrupt
        # the round-trip. learn() already drops these; this guards a codebook
        # loaded from disk that predates that fix.
        if book.escape in phrase:
            continue
        text = text.replace(phrase, book.forward[phrase])
    return text


def decode(text: str, book: TokenCodebook) -> str:
    """The audit layer: expand codes to exact English and un-stuff literal escapes.

    A left-to-right scan is required (not ``str.replace``): ``escape+escape`` is a
    literal escape, while ``escape+marker`` is a code -- a naive replace would
    mis-handle content that itself contains the code bytes."""
    esc = book.escape
    if not esc or not book.reverse:
        return text
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == esc and i + 1 < n:
            nxt = text[i + 1]
            if nxt == esc:               # EE -> a literal escape
                out.append(esc)
                i += 2
                continue
            phrase = book.reverse.get(nxt)
            if phrase is not None:        # E + marker -> a code
                out.append(phrase)
                i += 2
                continue
        out.append(c)
        i += 1
    return "".join(out)


def token_savings(messages, book: TokenCodebook, *, count_tokens) -> float:
    """Percent of tokens saved over ``messages`` (negative == the codec costs more).
    The honest scoreboard: the whole reason this module exists is to make this
    positive where the sentinel codec couldn't."""
    orig = enc = 0
    for m in messages:
        m = str(m)
        orig += count_tokens(m)
        enc += count_tokens(encode(m, book))
    return (1.0 - enc / orig) * 100.0 if orig else 0.0


def single_token_markers(count_tokens, candidates, *, escape: str,
                         corpus=(), limit: int = 256) -> list[str]:
    """Pick collision-cheap markers: single-CHARACTER, single-token ``candidates``
    absent from the corpus (so they never need stuffing), excluding the escape.
    Pure -- the tokenizer is injected via ``count_tokens``.

    Single-character is a correctness requirement, not just thrift: ``decode``
    scans exactly one character past the escape, so a multi-character marker (even
    one that is a single *token*, like `` the``) would break the round-trip. The
    ``corpus`` absence is the thrift part -- byte-stuffing keeps decode exact even
    if a marker appears in content.
    """
    seen = Counter()
    for m in corpus:
        seen.update(str(m))
    out: list[str] = []
    for cand in candidates:
        if cand == escape or cand in out:
            continue
        if len(cand) != 1:
            continue                      # decode reads one char past escape
        if seen.get(cand):
            continue                      # in the corpus -> would force stuffing
        if count_tokens(cand) != 1:
            continue                      # not a 1-token marker -> not cheap
        out.append(cand)
        if len(out) >= limit:
            break
    return out


@dataclass
class TokenCodebookStore:
    """Persisted token-aware codebook (atomic, 0600). Mirrors the sentinel codec's
    store so the wiring can load a learned codebook without relearning per run."""

    path: Path | None = None
    _book: TokenCodebook = None  # type: ignore[assignment]
    _lock: threading.Lock = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self._lock is None:
            self._lock = threading.Lock()
        if self._book is None:
            self._book = TokenCodebook()
        if self.path is not None:
            self._load()

    def _cplock(self):
        # Cross-process lock ordering the full-codebook writes; no-op for a
        # path-less store. (The codebook is recomputed and replaced wholesale by
        # the caller, so this orders the writes rather than merging deltas.)
        if self.path is None:
            from contextlib import nullcontext
            return nullcontext()
        from .file_lock import cross_process_lock
        return cross_process_lock(self.path)

    def update(self, book: TokenCodebook) -> None:
        with self._lock, self._cplock():
            self._book = book
            self._save()

    def book(self) -> TokenCodebook:
        with self._lock:
            return self._book

    def _load(self) -> None:
        try:
            raw = json.loads(Path(self.path).read_text(encoding="utf-8"))
            esc = str(raw.get("escape") or "")
            fwd = {str(k): str(v) for k, v in (raw.get("forward") or {}).items()}
            # reverse maps marker (code minus escape) -> phrase.
            rev = {code[len(esc):]: phrase for phrase, code in fwd.items()} if esc else {}
            self._book = TokenCodebook(escape=esc, forward=fwd, reverse=rev)
        except (OSError, ValueError, AttributeError):
            return

    def _save(self) -> None:
        if self.path is None:
            return
        try:
            # Unique temp + os.replace: a fixed ".tmp" collides between processes.
            from .file_lock import atomic_write_text
            atomic_write_text(self.path, json.dumps(self._book.to_dict(), sort_keys=True))
        except Exception:  # pragma: no cover -- best-effort
            log.debug("token codebook save failed", exc_info=True)


_shared: dict = {}
_shared_lock = threading.Lock()


def enabled() -> bool:
    """Whether the live token-aware codec may measure on the coordination stream.
    OFF by default; env var overrides config."""
    _v = env_flag("MAVERICK_EMERGENT_CODEC")
    if _v is not None:
        return _v
    try:
        from .config import get_emergent_codec

        return bool(get_emergent_codec().get("enable", False))
    except Exception:  # pragma: no cover -- config never blocks a run
        return False


def shared() -> TokenCodebookStore:
    from .paths import data_dir

    path = data_dir("token_codebook.json")
    with _shared_lock:
        store = _shared.get(path)
        if store is None:
            store = TokenCodebookStore(path=path)
            _shared[path] = store
        return store


def reset_shared() -> None:
    with _shared_lock:
        _shared.clear()


def learn_from_messages(messages, *, count_tokens) -> tuple[TokenCodebook, float] | None:
    """Learn the token-aware codebook from real coordination ``messages``,
    persist it to the shared store, and return ``(book, savings_pct)`` on that
    corpus -- or ``None`` when the tokenizer offers too few token-cheap markers
    for the codec to help (nothing is saved then). Shared by ``codec-learn``
    and the dashboard's Learning page.

    Candidate codes: printable ASCII + Latin/symbol ranges, filtered to the
    tokenizer's single-token chars that don't occur in the corpus. First
    viable one is the reserved escape; the rest are markers."""
    msgs = list(messages)
    candidates = [chr(c) for c in list(range(0x21, 0x7f)) + list(range(0xa1, 0x600))]
    pool = single_token_markers(count_tokens, candidates, escape="", corpus=msgs, limit=200)
    if len(pool) < 2:
        return None
    escape, markers = pool[0], pool[1:]
    book = learn(msgs, escape=escape, markers=markers)
    shared().update(book)
    return book, token_savings(msgs, book, count_tokens=count_tokens)


__all__ = [
    "TokenCodebook", "learn", "encode", "decode",
    "token_savings", "single_token_markers", "learn_from_messages",
    "TokenCodebookStore", "enabled", "shared", "reset_shared",
]
