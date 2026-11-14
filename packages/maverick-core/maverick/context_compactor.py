"""Long-context compactor.

When a multi-turn message history exceeds a token budget, drop or
collapse the least-relevant older turns and keep the freshest +
most-similar-to-current turns. Cheap (no model call) and reversible
(the dropped turns are returned alongside so callers can persist
them to the world model for audit).

Strategy:
  1. Prioritise the system context AND the last K user turns
     (the active conversation tail), trimming oversized tail content
     when needed to keep history bounded.
  2. From the remaining (older) turns, score each by Jaccard token
     overlap with the most recent user message — the simplest
     decent relevance proxy that has zero deps.
  3. Keep top-N relevant older turns up to the token budget; drop
     the rest. Insert a one-line ``[N turns compacted]`` marker so
     the model sees a continuity hint.

Token counting uses a real BPE tokenizer (tiktoken, a free local proxy)
when it is installed, falling back to the ``len(text) // 4`` rule of thumb
otherwise. The heuristic is off by ~20% (worse on code), which shifts WHEN
compaction fires; the BPE count is far closer to the provider's real
accounting. Force the heuristic with ``MAVERICK_COMPACT_TIKTOKEN=0``.

Embedding-based ranking (cosine via :mod:`fastembed`) is opt-in and
slower; turn it on with ``use_embeddings=True`` when the embeddings
extra is installed.
"""
from __future__ import annotations

import logging
import os
import re
from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

log = logging.getLogger(__name__)

_TRUE = {"1", "true", "yes", "on"}


def enabled() -> bool:
    """Whether conversation-history compaction is active.

    Off by default — the orchestrator includes the last 10 turns verbatim.
    Turn it on with ``MAVERICK_COMPACT_HISTORY=1`` or ``[context] compact =
    true`` to instead include a larger window compacted to a token budget,
    keeping the most relevant older turns (better long-conversation recall).
    """
    if (os.environ.get("MAVERICK_COMPACT_HISTORY") or "").strip().lower() in _TRUE:
        return True
    try:
        from .config import load_config
        return bool(load_config().get("context", {}).get("compact", False))
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


def target_tokens(default: int = 1500) -> int:
    """Token budget to compact history toward (``[context] history_tokens``)."""
    return _positive_int_config("history_tokens", "MAVERICK_HISTORY_TOKENS", default)


def window(default: int = 50) -> int:
    """How many recent turns to consider before compaction
    (``[context] history_window``)."""
    return _positive_int_config("history_window", "MAVERICK_HISTORY_WINDOW", default)


_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_]+")


# Resolved lazily: a callable(str)->int when a real tokenizer is available,
# or False once we've confirmed none is (so we don't retry the import every
# call). None means "not yet resolved".
_token_counter: object = None


@dataclass(frozen=True)
class TextFeatures:
    """Query-independent features of an exact immutable text string."""

    tokens: int | None
    terms: frozenset[str]


_FEATURES: ContextVar[Mapping[str, TextFeatures] | None] = ContextVar(
    "compaction_text_features", default=None)


def feature_identity() -> tuple:
    """Invalidate cached work when tokenizer or feature implementation changes."""
    return (_resolve_token_counter(), _TOKEN_PATTERN, _message_text, prepare_features)


def prepare_features(text: str) -> TextFeatures:
    counter = _resolve_token_counter()
    try:
        count = counter(text) if counter and text else (len(text) + 3) // 4
    except Exception:
        # A transient tokenizer failure must not pin heuristic counts after
        # the tokenizer recovers. Lexical features remain safe to reuse.
        count = None
    return TextFeatures(count, frozenset(t.lower() for t in _TOKEN_PATTERN.findall(text)))


@contextmanager
def feature_scope(features: Mapping[str, TextFeatures]):
    """Use an immutable per-call view; no state leaks across threads or tasks."""
    token = _FEATURES.set(features)
    try:
        yield
    finally:
        _FEATURES.reset(token)


def _resolve_token_counter():
    """A real BPE token counter (local tiktoken) or False if unavailable.

    Fail-open and cached: any import/build error pins False so callers drop to
    the char heuristic. ``MAVERICK_COMPACT_TIKTOKEN=0`` forces the heuristic."""
    global _token_counter
    if _token_counter is not None:
        return _token_counter
    from .env_setting import env_or_config

    if (env_or_config("MAVERICK_COMPACT_TIKTOKEN", "context", "compact_tiktoken", "1")
            or "1").strip().lower() in {
            "0", "false", "no", "off"}:
        _token_counter = False
        return _token_counter
    try:
        from .codec_probe import tiktoken_counter
        _token_counter = tiktoken_counter()  # local cl100k_base BPE
    except Exception:  # pragma: no cover -- tiktoken not installed
        _token_counter = False
    return _token_counter


def _approx_tokens(text: str) -> int:
    features = _FEATURES.get()
    cached = features.get(text) if features is not None else None
    if cached is not None and cached.tokens is not None:
        return cached.tokens
    if not text:
        return 0
    counter = _resolve_token_counter()
    if counter:
        try:
            return counter(text)
        except Exception:  # pragma: no cover -- never let counting break compaction
            pass
    # 4 chars/token is the rule-of-thumb fallback; round up.
    return (len(text) + 3) // 4


def _message_text(msg: dict) -> str:
    """Flatten an Anthropic-style message to a single string."""
    content = msg.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                t = block.get("text") or block.get("content") or ""
                if isinstance(t, str) and t:
                    parts.append(t)
                elif isinstance(t, list):
                    for inner in t:
                        if isinstance(inner, dict):
                            parts.append(str(inner.get("text") or ""))
                else:
                    # tool_use carries its args under `input` (no text/content),
                    # and a structured tool_result may have a dict content; the
                    # old code counted these as 0 tokens, so token estimates
                    # under-counted multi-KB tool args and the cap was exceeded.
                    import json as _json
                    payload = block.get("input")
                    if payload is not None:
                        parts.append(_json.dumps(payload, default=str))
                    elif not isinstance(t, str):
                        parts.append(_json.dumps(t, default=str))
            elif isinstance(block, str):
                parts.append(block)
        return " ".join(parts)
    return ""


def _tokens(text: str) -> set[str] | frozenset[str]:
    features = _FEATURES.get()
    if features is not None and text in features:
        return features[text].terms
    return {t.lower() for t in _TOKEN_PATTERN.findall(text)}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    if union == 0:
        return 0.0
    return inter / union


@dataclass
class CompactResult:
    messages: list[dict]
    dropped: list[dict]
    tokens_before: int
    tokens_after: int
    kept_marker: str | None


def estimate_tokens(messages: Iterable[dict]) -> int:
    return sum(_approx_tokens(_message_text(m)) for m in messages)


def _with_text(msg: dict, text: str) -> dict:
    out = dict(msg)
    out["content"] = text
    return out


def _trim_message_to_tokens(msg: dict, max_tokens: int) -> dict:
    """Return ``msg`` with text content bounded to ``max_tokens``."""
    text = _message_text(msg)
    if max_tokens <= 0:
        return _with_text(msg, "")
    if _approx_tokens(text) <= max_tokens:
        return dict(msg)
    return _with_text(msg, text[: max_tokens * 4])


def _fit_recent_to_budget(messages: list[dict], budget_tokens: int) -> tuple[list[dict], int]:
    """Fit messages into a token budget, prioritising the newest content."""
    remaining = max(budget_tokens, 0)
    fitted_reversed: list[dict] = []
    for msg in reversed(messages):
        cost = _approx_tokens(_message_text(msg))
        if cost <= remaining:
            fitted_reversed.append(dict(msg))
            remaining -= cost
            continue
        if remaining <= 0:
            # Budget exhausted: stop here rather than appending
            # empty-content turns the model would see as blank user/
            # assistant messages. The older tail is dropped, not blanked.
            break
        fitted_reversed.append(_trim_message_to_tokens(msg, remaining))
        remaining = 0
    fitted_reversed.reverse()
    return fitted_reversed, remaining


def compact(
    messages: list[dict],
    *,
    target_tokens: int,
    preserve_tail: int = 4,
    use_embeddings: bool = False,
    embed_model: str | None = None,
) -> CompactResult:
    """Return a compacted message list under ``target_tokens``.

    Args:
        messages: full message history (in order; oldest first).
        target_tokens: approximate token cap to compact toward.
        preserve_tail: number of most-recent messages to prioritise
            (the active conversation). Oversized tail content may be
            trimmed so the compacted history remains bounded.
        use_embeddings: if True, rank older turns by cosine to the
            most recent user message via :mod:`fastembed`. Requires
            the [embeddings] extra. Falls back to Jaccard on
            ImportError.
        embed_model: override the default embedding model.

    The returned :class:`CompactResult` carries the compacted list,
    the dropped messages (for audit), pre- and post- token counts,
    and a continuity marker that was inserted (if any).
    """
    if not messages:
        return CompactResult(
            messages=[], dropped=[], tokens_before=0,
            tokens_after=0, kept_marker=None,
        )
    before = estimate_tokens(messages)
    if before <= target_tokens:
        return CompactResult(
            messages=list(messages), dropped=[],
            tokens_before=before, tokens_after=before, kept_marker=None,
        )

    tail = messages[-preserve_tail:] if preserve_tail > 0 else []
    head = messages[: -preserve_tail] if preserve_tail > 0 else list(messages)
    if not head:
        fitted, _ = _fit_recent_to_budget(list(messages), target_tokens)
        return CompactResult(
            messages=fitted, dropped=[],
            tokens_before=before, tokens_after=estimate_tokens(fitted), kept_marker=None,
        )

    most_recent_user = ""
    for m in reversed(messages):
        if m.get("role") == "user":
            most_recent_user = _message_text(m)
            break

    scored: list[tuple[float, int, dict]] = []
    if use_embeddings:
        try:
            scored = _score_by_embedding(head, most_recent_user, embed_model)
        except ImportError:
            scored = _score_by_jaccard(head, most_recent_user)
    else:
        scored = _score_by_jaccard(head, most_recent_user)

    scored.sort(reverse=True)
    marker_budget = _approx_tokens(
        f"[{len(head)} earlier turn(s) compacted to save context]"
    )
    fitted_tail, budget_remaining = _fit_recent_to_budget(
        tail, target_tokens - marker_budget,
    )

    # Always preserve system messages regardless of relevance score --
    # the documented contract ("Always preserve the system context") and
    # because dropping the system prompt corrupts the run. They are kept
    # unconditionally and not subject to the budget cull below.
    forced_idx = {i for i, m in enumerate(head) if m.get("role") == "system"}
    kept_by_idx: dict[int, dict] = {i: head[i] for i in forced_idx}
    used = sum(_approx_tokens(_message_text(head[i])) for i in forced_idx)
    for _score, idx, msg in scored:
        if idx in kept_by_idx:
            continue
        cost = _approx_tokens(_message_text(msg))
        if used + cost > budget_remaining:
            continue
        kept_by_idx[idx] = msg
        used += cost

    dropped = [m for i, m in enumerate(head) if i not in kept_by_idx]
    if not dropped:
        # Nothing in the head could go, but the tail may still have been
        # trimmed to fit; return that rather than the over-budget original.
        kept = list(head) + fitted_tail
        return CompactResult(
            messages=kept, dropped=[],
            tokens_before=before, tokens_after=estimate_tokens(kept), kept_marker=None,
        )

    kept_head = [kept_by_idx[i] for i in sorted(kept_by_idx)]
    marker_msg = {
        "role": "user",
        "content": f"[{len(dropped)} earlier turn(s) compacted to save context]",
    }
    new_messages = kept_head + [marker_msg] + fitted_tail
    return CompactResult(
        messages=new_messages,
        dropped=dropped,
        tokens_before=before,
        tokens_after=estimate_tokens(new_messages),
        kept_marker=marker_msg["content"],
    )


def _score_by_jaccard(head: list[dict], query: str) -> list[tuple[float, int, dict]]:
    q = _tokens(query)
    out: list[tuple[float, int, dict]] = []
    for i, m in enumerate(head):
        out.append((_jaccard(_tokens(_message_text(m)), q), i, m))
    return out


def _score_by_embedding(
    head: list[dict], query: str, model_name: str | None,
) -> list[tuple[float, int, dict]]:
    """Embedding-based ranking. Raises ImportError if fastembed missing."""
    from fastembed import TextEmbedding
    name = model_name or "BAAI/bge-small-en-v1.5"
    m = TextEmbedding(model_name=name)
    qv = next(iter(m.embed([query])), None)
    if qv is None:
        return _score_by_jaccard(head, query)

    def _cos(a, b) -> float:
        import math
        ax = list(a)
        bx = list(b)
        if not ax or not bx or len(ax) != len(bx):
            return 0.0
        dot = sum(x * y for x, y in zip(ax, bx, strict=False))
        na = math.sqrt(sum(x * x for x in ax))
        nb = math.sqrt(sum(y * y for y in bx))
        if na == 0 or nb == 0:
            return 0.0
        return dot / (na * nb)

    texts = [_message_text(msg) for msg in head]
    vectors = list(m.embed(texts))
    out: list[tuple[float, int, dict]] = []
    for i, msg in enumerate(head):
        # The embedder may yield fewer vectors than head turns (empty
        # texts / batching). Drive the loop by head and, when a turn has
        # no vector, KEEP it (treat as max relevance) rather than letting
        # it be silently dropped and culled.
        if i < len(vectors):
            out.append((_cos(qv, vectors[i]), i, msg))
        else:
            out.append((float("inf"), i, msg))
    return out


__all__ = ["compact", "CompactResult", "estimate_tokens"]
