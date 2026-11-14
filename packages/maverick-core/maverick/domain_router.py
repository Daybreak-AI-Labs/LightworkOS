"""Specialist routing: rank packs by relevance to a task.

The roster is 2,031 specialists. ``list_specialists`` lets the orchestrator
drill down suite-by-suite, but there was no way to search the whole roster by
what the task actually IS -- so an ambiguous or cross-suite request forced the
model to guess the suite and browse it. This module is the deterministic
pre-filter: a dependency-free lexical retriever (weighted TF-IDF over each
pack's name, description, and persona) that narrows 2,031 packs to the handful
worth showing. The LLM still makes the final pick; it just picks from a relevant
shortlist instead of a haystack.

Pure and offline (no embeddings, no provider key), so it is testable and always
available. Embeddings would rank better on paraphrase and are a natural upgrade,
but the lexical baseline is what makes routing measurable today.
"""
from __future__ import annotations

import math
import re
from collections import Counter

from .domain import DomainProfile, available_domains

# Minimal stopword set: articles, pronouns, auxiliaries, and the words that
# appear in almost every persona (so they carry no routing signal). Deliberately
# small -- dropping a discriminative term ("review", "audit") would hurt.
_STOP = frozenset("""
a an the this that these those of for to in on at by with from into over under
and or but not no you your we our they it its is are be been being as do does
did have has had will would can could should may might must your you yours
i me my mine he she him her his hers them their there here what which who whom
specialist assistant business company companys agent pack draft drafts review
help helps team teams work works task tasks provide provides use uses make makes
""".split())

# Field weights -- a term in the pack NAME is the strongest routing signal, the
# description next, the persona last (it is long and dilutes).
_W_NAME, _W_DESC, _W_PERSONA = 4, 3, 1

_TOKEN = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> list[str]:
    out = []
    for tok in _TOKEN.findall((text or "").lower()):
        if tok in _STOP or len(tok) < 2:
            continue
        # light stemming: collapse a trailing plural 's' so "contracts"~"contract"
        if len(tok) > 3 and tok.endswith("s") and not tok.endswith("ss"):
            tok = tok[:-1]
        out.append(tok)
    return out


def _doc_terms(p: DomainProfile) -> Counter:
    """Field-weighted term frequencies for one pack."""
    tf: Counter = Counter()
    for tok in _tokens(p.name.replace("_", " ")):
        tf[tok] += _W_NAME
    for tok in _tokens(p.description):
        tf[tok] += _W_DESC
    for tok in _tokens(p.persona):
        tf[tok] += _W_PERSONA
    return tf


class DomainRouter:
    """A lexical TF-IDF index over the roster. Build once, query many times."""

    def __init__(self, domains: dict[str, DomainProfile]):
        self.names = sorted(domains)
        self._docs = {n: _doc_terms(domains[n]) for n in self.names}
        n_docs = max(len(self.names), 1)
        df: Counter = Counter()
        for tf in self._docs.values():
            df.update(tf.keys())
        # Smoothed IDF: a term in every pack ("finance") is near-zero; a rare term
        # ("escheatment") is high -- exactly the discriminative weighting we want.
        self._idf = {t: math.log((n_docs + 1) / (c + 1)) + 1.0 for t, c in df.items()}

    def score_all(self, query: str) -> dict[str, float]:
        """Raw lexical score for every pack (0 for no overlap)."""
        q = _tokens(query)
        if not q:
            return {}
        qw = {t: self._idf.get(t, 0.0) for t in set(q)}
        out: dict[str, float] = {}
        for name in self.names:
            tf = self._docs[name]
            s = sum(tf.get(t, 0) * w * w for t, w in qw.items())  # tf * idf^2
            if s > 0:
                out[name] = s
        return out

    def rank(self, query: str, k: int = 10) -> list[tuple[str, float]]:
        """The top-``k`` packs for ``query`` as ``(name, score)``, best first.
        Scoreless (all-zero) results are dropped, so an off-roster query returns
        fewer than ``k`` rather than padding with noise."""
        scored = sorted(self.score_all(query).items(), key=lambda x: (-x[1], x[0]))
        return scored[:k]


def _cosine(a: list[float], b: list[float]) -> float:
    if len(a) != len(b) or not a:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


class EmbeddingRouter:
    """Semantic index over the roster: cosine similarity of a query to each
    pack's embedded text. Mirrors maverick.skill.embeddings -- uses a real
    sentence-transformer when one is installed, and is a no-op otherwise (so the
    caller falls back to lexical). The embedder is injectable for testing."""

    def __init__(self, domains: dict[str, DomainProfile], embed_fn=None):
        if embed_fn is None:
            from .skill.embeddings import embed as embed_fn  # lazy: optional dep
        self.names = sorted(domains)
        texts = [_doc_text(domains[n]) for n in self.names]
        vecs = embed_fn(texts) if texts else None
        # available iff the embedder produced a vector per pack.
        self.vectors = (dict(zip(self.names, vecs, strict=False))
                        if vecs and len(vecs) == len(self.names) else None)
        self._embed_fn = embed_fn

    @property
    def available(self) -> bool:
        return self.vectors is not None

    def score_all(self, query: str) -> dict[str, float]:
        if not self.available or not (query or "").strip():
            return {}
        qv = self._embed_fn([query])
        if not qv:
            return {}
        q = qv[0]
        return {n: c for n in self.names
                if (c := _cosine(q, self.vectors[n])) > 0}


def _doc_text(p: DomainProfile) -> str:
    """The text embedded for a pack -- name, description, then persona."""
    return f"{p.name.replace('_', ' ')}. {p.description} {p.persona}"


def _blend(lexical: dict[str, float], semantic: dict[str, float],
           alpha: float) -> dict[str, float]:
    """Max-normalise each score set to [0,1] and blend: alpha*semantic +
    (1-alpha)*lexical over the union of candidates. With no semantic scores this
    returns the lexical ranking unchanged."""
    if not semantic:
        return lexical
    lmax = max(lexical.values(), default=0.0) or 1.0
    smax = max(semantic.values(), default=0.0) or 1.0
    out: dict[str, float] = {}
    for n in set(lexical) | set(semantic):
        out[n] = alpha * (semantic.get(n, 0.0) / smax) + \
            (1 - alpha) * (lexical.get(n, 0.0) / lmax)
    return out


# Default blend weight: semantic leads (paraphrase), lexical keeps exact
# name/term matches influential.
_ALPHA = 0.6

# One published (key, lexical, embedding) entry, replaced as a single tuple so
# a concurrent build for another roster can never pair this key with that
# roster's index.
_CACHE: tuple[tuple, DomainRouter, EmbeddingRouter | None] | None = None


def _indexes(domains: dict[str, DomainProfile]):
    """Build (and process-cache) the lexical + embedding indexes for a roster."""
    global _CACHE
    # A workspace can edit a custom pack without changing its ID. Keying only
    # on names kept the previous tenant's text in the process-wide index and
    # made JD matches stale until restart.
    key = tuple(
        (name, profile.description, profile.persona)
        for name, profile in sorted(domains.items())
    )
    cached = _CACHE
    if cached is not None and cached[0] == key:
        return cached[1], cached[2]
    lex = DomainRouter(domains)
    emb: EmbeddingRouter | None
    try:
        emb = EmbeddingRouter(domains)
    except Exception:  # embeddings are best-effort; lexical always works
        emb = None
    _CACHE = (key, lex, emb)
    return lex, emb


def rank_specialists(query: str, k: int = 10,
                     domains: dict[str, DomainProfile] | None = None,
                     *, alpha: float = _ALPHA) -> list[tuple[str, float]]:
    """Rank the roster for ``query``, hybrid (semantic + lexical) when an
    embedding model is installed, pure lexical otherwise. Cached per roster."""
    if domains is None:
        domains = available_domains()
    lex, emb = _indexes(domains)
    lexical = lex.score_all(query)
    semantic = emb.score_all(query) if (emb and emb.available) else {}
    blended = _blend(lexical, semantic, alpha)
    scored = sorted(((n, s) for n, s in blended.items() if s > 0),
                    key=lambda x: (-x[1], x[0]))
    return scored[:k]


__all__ = ["DomainRouter", "EmbeddingRouter", "rank_specialists"]
