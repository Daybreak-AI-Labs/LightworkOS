"""Long-context retrieval router.

When a *single* assembled payload (a pasted document, a multi-MB tool result,
a concatenated knowledge bundle) blows past the model's context window, feeding
it whole either 400s the provider or burns a fortune in tokens. This router
shards the payload, ranks the shards against the active query, and returns only
the most relevant ones — so a 500k-token document collapses to the handful of
shards that actually answer the question.

This is **complementary** to :mod:`maverick.context_compactor`, which compacts
multi-turn *history* toward a budget. The router operates on one oversized
*payload*, at the model-window boundary, not on the turn history.

Design (matches the rest of the kernel):
  - **Default-OFF, opt-in** via ``[context] retrieval_router = true`` or
    ``MAVERICK_RETRIEVAL_ROUTER=1``.
  - **Zero-dep by default**: ranking falls back to lexical token overlap
    (Jaccard), so the feature works with nothing installed.
  - **Vector store optional**: pass any object implementing the vector-store
    contract (``add(documents, ids=, metadatas=)`` + ``query(text, top_k=)``)
    — the shipped :class:`~maverick.vector_store.ChromaStore` /
    :class:`~maverick.vector_store.QdrantStore` satisfy it — and ranking uses
    embedding similarity instead. Use a *fresh, ephemeral* collection; the
    router indexes per call and does not clean up a persistent store for you.
  - **Pure decisions are unit-tested** (``shard`` / ``rank`` / ``route_text``);
    ``route`` is the config-reading convenience the assembly path calls.

Token counts are approximated as ``len(text) // 4`` (the same rule-of-thumb the
compactor uses) so we don't drag tiktoken into the kernel.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

from ._envparse import env_bool

# A 200k-token window is the current high-context default (Claude/GPT long
# context). Above this a single payload is the router's problem to solve.
_DEFAULT_THRESHOLD_TOKENS = 200_000
# Shard size in characters (~500 tokens). Small enough that retrieval is
# fine-grained, large enough that a shard carries a coherent idea.
_DEFAULT_SHARD_CHARS = 2_000
_DEFAULT_TOP_K = 12

_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_]+")
_MARKER = "[long-context router: {kept} of {total} shards retained by relevance]"


def _env_true(name: str) -> bool:
    return env_bool(name)


def enabled() -> bool:
    """Whether the retrieval router is active. Off by default."""
    if _env_true("MAVERICK_RETRIEVAL_ROUTER"):
        return True
    try:
        from .config import load_config
        return bool(load_config().get("context", {}).get("retrieval_router", False))
    except Exception:  # pragma: no cover -- config never blocks a run
        return False


def _positive_int_config(key: str, env: str, default: int) -> int:
    raw: object = os.environ.get(env)
    if raw is None:
        try:
            from .config import load_config
            raw = load_config().get("context", {}).get(key, default)
        except Exception:  # pragma: no cover
            raw = default
    try:
        n = int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    return n if n >= 1 else default


def threshold_tokens(default: int = _DEFAULT_THRESHOLD_TOKENS) -> int:
    """Payload size (approx tokens) above which routing kicks in
    (``[context] router_threshold_tokens``)."""
    return _positive_int_config(
        "router_threshold_tokens", "MAVERICK_ROUTER_THRESHOLD_TOKENS", default
    )


def top_k(default: int = _DEFAULT_TOP_K) -> int:
    """How many shards to retain (``[context] router_top_k``)."""
    return _positive_int_config("router_top_k", "MAVERICK_ROUTER_TOP_K", default)


def _approx_tokens(text: str) -> int:
    if not text:
        return 0
    return (len(text) + 3) // 4  # 4 chars/token, round up


def _tokens(text: str) -> set[str]:
    return {t.lower() for t in _TOKEN_PATTERN.findall(text)}


@dataclass(frozen=True)
class RouteResult:
    """Outcome of a routing pass."""

    text: str
    routed: bool
    shards_total: int
    shards_kept: int
    tokens_in: int
    tokens_out: int


def shard(text: str, *, max_chars: int = _DEFAULT_SHARD_CHARS) -> list[str]:
    """Split ``text`` into coherent shards no larger than ``max_chars``.

    Prefers paragraph (blank-line) boundaries; a paragraph longer than
    ``max_chars`` is hard-split into ``max_chars`` windows so no shard exceeds
    the cap. Empty fragments are dropped.
    """
    if not text:
        return []
    max_chars = max(1, max_chars)
    shards: list[str] = []
    buf: list[str] = []
    buf_len = 0

    def flush() -> None:
        nonlocal buf, buf_len
        if buf:
            joined = "\n\n".join(buf).strip()
            if joined:
                shards.append(joined)
            buf = []
            buf_len = 0

    for para in re.split(r"\n\s*\n", text):
        para = para.strip("\n")
        if not para:
            continue
        if len(para) > max_chars:
            flush()
            for i in range(0, len(para), max_chars):
                piece = para[i : i + max_chars].strip()
                if piece:
                    shards.append(piece)
            continue
        # +2 for the "\n\n" separator we'll insert on join.
        if buf and buf_len + len(para) + 2 > max_chars:
            flush()
        buf.append(para)
        buf_len += len(para) + 2
    flush()
    return shards


def _lexical_rank(shards: list[str], query: str, k: int) -> list[int]:
    """Rank shards by Jaccard token overlap with the query. Returns the indices
    of the top-``k`` shards, **sorted ascending** to preserve original order."""
    q = _tokens(query)
    if not q:
        return list(range(min(k, len(shards))))
    scored: list[tuple[float, int]] = []
    for i, s in enumerate(shards):
        st = _tokens(s)
        if not st:
            scored.append((0.0, i))
            continue
        overlap = len(q & st)
        union = len(q | st)
        scored.append((overlap / union if union else 0.0, i))
    # Highest score first; stable on index for ties.
    scored.sort(key=lambda t: (-t[0], t[1]))
    keep = {i for _, i in scored[: max(1, k)]}
    return sorted(keep)


def _store_rank(shards: list[str], query: str, k: int, store) -> list[int]:
    """Index shards into ``store`` and rank by embedding similarity. Returns the
    indices of the retrieved shards, sorted ascending. Falls back to lexical
    ranking if the store misbehaves."""
    try:
        ids = [f"shard-{i}" for i in range(len(shards))]
        store.add(shards, ids=ids)
        hits = store.query(query, top_k=max(1, k))
        keep: set[int] = set()
        for h in hits or []:
            hid = h.get("id") if isinstance(h, dict) else None
            if isinstance(hid, str) and hid.startswith("shard-"):
                try:
                    keep.add(int(hid.split("-", 1)[1]))
                except ValueError:  # pragma: no cover
                    pass
        if not keep:  # store returned nothing usable
            return _lexical_rank(shards, query, k)
        return sorted(keep)
    except Exception:  # pragma: no cover -- never let retrieval break a run
        return _lexical_rank(shards, query, k)


def rank(shards: list[str], query: str, k: int, *, store=None) -> list[int]:
    """Indices of the ``k`` shards most relevant to ``query``, in original
    order. Uses ``store`` (embedding similarity) when given, else lexical."""
    if not shards:
        return []
    if store is not None:
        return _store_rank(shards, query, k, store)
    return _lexical_rank(shards, query, k)


def route_text(
    text: str,
    query: str,
    *,
    store=None,
    k: int = _DEFAULT_TOP_K,
    threshold: int = _DEFAULT_THRESHOLD_TOKENS,
    max_shard_chars: int = _DEFAULT_SHARD_CHARS,
) -> RouteResult:
    """Reduce an oversized ``text`` to the shards most relevant to ``query``.

    Passthrough (``routed=False``) when the payload is already under
    ``threshold`` tokens — small inputs are never degraded. Otherwise shard,
    rank, and reassemble the kept shards in original order with a one-line
    marker so the model knows retrieval happened.
    """
    tokens_in = _approx_tokens(text)
    if tokens_in < threshold:
        return RouteResult(
            text=text, routed=False, shards_total=0, shards_kept=0,
            tokens_in=tokens_in, tokens_out=tokens_in,
        )
    shards = shard(text, max_chars=max_shard_chars)
    if len(shards) <= 1:
        # Nothing to retrieve against; leave it for the compactor / provider.
        return RouteResult(
            text=text, routed=False, shards_total=len(shards), shards_kept=len(shards),
            tokens_in=tokens_in, tokens_out=tokens_in,
        )
    keep = rank(shards, query, k, store=store)
    kept = [shards[i] for i in keep]
    marker = _MARKER.format(kept=len(kept), total=len(shards))
    out = marker + "\n\n" + "\n\n".join(kept)
    return RouteResult(
        text=out, routed=True, shards_total=len(shards), shards_kept=len(kept),
        tokens_in=tokens_in, tokens_out=_approx_tokens(out),
    )


def route(text: str, query: str, *, store=None, model: str | None = None) -> str:
    """Config-reading convenience for the assembly path. No-op (returns ``text``
    unchanged) when the router is disabled. Reads threshold / top-k from config.

    The threshold DEFAULT scales with the driving model's context window
    (``context_scaling.router_threshold_tokens``): fire just before a payload
    would overflow whatever model is in charge — late on a 1M-window model,
    early on a 32k one. An explicit ``[context] router_threshold_tokens`` /
    ``MAVERICK_ROUTER_THRESHOLD_TOKENS`` still wins.
    """
    if not enabled():
        return text
    default = _DEFAULT_THRESHOLD_TOKENS
    try:
        from . import context_scaling
        default = context_scaling.router_threshold_tokens(model)
    except Exception:  # pragma: no cover -- sizing never blocks routing
        pass
    return route_text(
        text, query, store=store, k=top_k(), threshold=threshold_tokens(default)
    ).text


__all__ = [
    "RouteResult",
    "enabled",
    "threshold_tokens",
    "top_k",
    "shard",
    "rank",
    "route_text",
    "route",
]
