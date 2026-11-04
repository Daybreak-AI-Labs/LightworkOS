"""The Emergent Substrate -- a learned, auditable coordination shorthand.

Lightwork's swarms coordinate in English: every handoff, every blackboard post is
tokens through a frontier model. Most of that traffic is boilerplate the agents
say over and over. So let them **evolve their own shorthand** -- a codebook
learned from the swarm's *actual* messages (the phrases they repeat get short
codes) -- and pay frontier tokens only for what's genuinely new.

The reason this is deployable where emergent communication usually isn't: it's
**not** an opaque neural language. Every code decodes, exactly, back to the
English it stands for -- the auditable translation layer *is* the product. A
regulator (or the Shield, or a human) reads the plain text; the agents move the
compressed form. ``decode(encode(x)) == x`` is the contract, enforced by the
tests, so the shorthand can never hide meaning.

This is the codec + codebook learning. The hot encode/decode path is the natural
Rust->WASM carve (per the language plan) and wiring it into the blackboard /
channels is a seam; the learned, round-trip-safe core is here. Pure + OFF by
default (``learn`` only runs on an opt-in message corpus; an empty codebook is
the identity transform -- no behaviour change).
"""
from __future__ import annotations

import json
import logging
import threading
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .config import env_flag

log = logging.getLogger(__name__)

# Code sentinels use guillemet brackets, which don't occur in normal coordination
# text -- so a code can never collide with message content and round-trip is safe.
_OPEN, _CLOSE = "⟦", "⟧"  # ⟦ ⟧


def _code(i: int) -> str:
    return f"{_OPEN}{i}{_CLOSE}"


@dataclass(frozen=True)
class Codebook:
    """A learned phrase<->code mapping. The reverse map is the audit layer."""

    forward: dict = field(default_factory=dict)   # phrase -> code
    reverse: dict = field(default_factory=dict)   # code -> phrase

    @property
    def size(self) -> int:
        return len(self.forward)

    def to_dict(self) -> dict:
        return {"forward": dict(self.forward)}


def learn(messages, *, max_codes: int = 128, min_count: int = 2,
          max_words: int = 6) -> Codebook:
    """Learn a codebook from a coordination corpus.

    Counts word n-grams (length 1..``max_words``) across ``messages`` and codes
    the ones that save the most -- ``count * (len(phrase) - len(code))`` -- giving
    the swarm short codes for the boilerplate it repeats. Phrases that wouldn't
    shrink (shorter than a code) are skipped.
    """
    counts: Counter = Counter()
    for msg in messages:
        words = str(msg).split()
        for n in range(1, max_words + 1):
            for i in range(len(words) - n + 1):
                counts[" ".join(words[i:i + n])] += 1

    code_len = len(_code(0))
    scored = [
        (phrase, cnt * (len(phrase) - code_len))
        for phrase, cnt in counts.items()
        if cnt >= min_count and len(phrase) > code_len
    ]
    scored.sort(key=lambda kv: (kv[1], len(kv[0])), reverse=True)

    forward, reverse = {}, {}
    for i, (phrase, _) in enumerate(scored[:max_codes]):
        c = _code(i)
        forward[phrase] = c
        reverse[c] = phrase
    return Codebook(forward=forward, reverse=reverse)


def encode(text: str, codebook: Codebook) -> str:
    """Compress ``text`` with the codebook. Longest phrases first so a longer
    coded phrase wins over a sub-phrase; an empty codebook is the identity.

    Any literal ``_OPEN`` already in ``text`` is first doubled (``⟦`` -> ``⟦⟦``),
    so that in the output a *single* ``_OPEN`` can only begin a real code. Without
    this, content that itself contained a sentinel (e.g. an agent emitting the
    literal ``⟦0⟧``) would be misread as a code on ``decode`` -- silently breaking
    the round-trip, which is the whole audit guarantee."""
    if not codebook.forward:
        return text
    text = text.replace(_OPEN, _OPEN + _OPEN)   # escape literal sentinels first
    for phrase in sorted(codebook.forward, key=len, reverse=True):
        text = text.replace(phrase, codebook.forward[phrase])
    return text


def decode(text: str, codebook: Codebook) -> str:
    """The audit layer: expand every code back to its exact English.

    A left-to-right scan (not ``str.replace``): a doubled ``_OPEN`` is a literal
    sentinel character, a single ``_OPEN`` + digits + ``_CLOSE`` is a code. This is
    what makes ``decode(encode(x)) == x`` hold even when ``x`` itself contains the
    sentinel brackets."""
    if not codebook.reverse:
        return text
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == _OPEN:
            if i + 1 < n and text[i + 1] == _OPEN:   # ⟦⟦ -> literal ⟦
                out.append(_OPEN)
                i += 2
                continue
            j = i + 1                                 # try to read a code ⟦digits⟧
            while j < n and text[j].isdigit():
                j += 1
            if j > i + 1 and j < n and text[j] == _CLOSE:
                phrase = codebook.reverse.get(text[i:j + 1])
                if phrase is not None:
                    out.append(phrase)
                    i = j + 1
                    continue
            out.append(_OPEN)                         # malformed -> literal open
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def compression_ratio(messages, codebook: Codebook) -> float:
    """Encoded length / original length over ``messages`` (lower is better; 1.0
    means no savings). Empty corpus -> 1.0."""
    orig = enc = 0
    for m in messages:
        m = str(m)
        orig += len(m)
        enc += len(encode(m, codebook))
    return (enc / orig) if orig else 1.0


@dataclass
class CodebookStore:
    """Persisted learned codebook (atomic, 0600)."""

    path: Path | None = None
    _book: Codebook = None  # type: ignore[assignment]
    _lock: threading.Lock = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self._lock is None:
            self._lock = threading.Lock()
        if self._book is None:
            self._book = Codebook()
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

    def update(self, codebook: Codebook) -> None:
        with self._lock, self._cplock():
            self._book = codebook
            self._save()

    def book(self) -> Codebook:
        with self._lock:
            return self._book

    def _load(self) -> None:
        try:
            raw = json.loads(Path(self.path).read_text(encoding="utf-8"))
            fwd = {str(k): str(v) for k, v in (raw.get("forward") or {}).items()}
            self._book = Codebook(forward=fwd, reverse={v: k for k, v in fwd.items()})
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
            log.debug("codebook save failed", exc_info=True)


_shared: dict = {}
_shared_lock = threading.Lock()


def enabled() -> bool:
    """Whether the emergent protocol may compress coordination. OFF by default."""
    _v = env_flag("MAVERICK_EMERGENT_PROTOCOL")
    if _v is not None:
        return _v
    try:
        from .config import get_emergent_protocol

        return bool(get_emergent_protocol().get("enable", False))
    except Exception:  # pragma: no cover -- config never blocks a run
        return False


def shared() -> CodebookStore:
    from .paths import data_dir

    path = data_dir("codebook.json")
    with _shared_lock:
        store = _shared.get(path)
        if store is None:
            store = CodebookStore(path=path)
            _shared[path] = store
        return store


def reset_shared() -> None:
    with _shared_lock:
        _shared.clear()


__all__ = [
    "Codebook", "learn", "encode", "decode", "compression_ratio",
    "CodebookStore", "enabled", "shared", "reset_shared",
]
