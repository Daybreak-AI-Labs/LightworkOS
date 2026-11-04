"""Opt-in, bounded feature reuse for conversation-history compaction.

The legacy background worker compacted an old prefix twice and could reuse a
lossy result under a changed query/budget. The compatibility API now retains
only immutable token counts and lexical features of exact text. Every call
ranks and trims the complete source with its current query and token budget.
There is no worker, queued work or cached compacted output.

Both [context] compact and async_compaction must be enabled in the orchestrator;
their existing environment overrides and default-off behavior are unchanged.
"""
from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from . import context_compactor as _cc
from .config import env_flag
from .paths import current_tenant_id_strict

TAIL_TURNS = 4  # Public compatibility constant; no prefix is removed from ranking.
_MAX_KEYS = 256
_MAX_BYTES = 8 * 1024 * 1024
_MAX_WINDOW_BYTES = 1024 * 1024


def enabled() -> bool:
    if env_flag("MAVERICK_ASYNC_COMPACTION"):
        return True
    try:
        from .config import load_config
        return bool((load_config() or {}).get("context", {}).get("async_compaction", False))
    except Exception:  # pragma: no cover -- config never blocks the hot path
        return False



@dataclass(frozen=True)
class _FeatureWindow:
    identity: tuple
    features: Mapping[str, _cc.TextFeatures]
    size: int


def _feature_size(text: str, feature: _cc.TextFeatures) -> int:
    # Conservative storage accounting, including worst-case Unicode and set
    # entries. It is a bound on retained features, not a process RSS promise.
    return 256 + 4 * len(text) + sum(64 + 4 * len(term) for term in feature.terms)


class BackgroundCompactor:
    """Compatibility name for a bounded cache; no background thread is started."""

    def __init__(self, executor: Callable[[Callable[[], None]], None] | None = None):
        # Retain the old constructor seam; no executor work is necessary now.
        del executor
        self._lock = threading.Lock()
        self._cache: OrderedDict[tuple, _FeatureWindow] = OrderedDict()
        self._bytes = 0
        self._closed = False

    def compact_with_precompute(
        self, key: str, messages: list[dict], *, target_tokens: int,
    ) -> list[dict]:
        """Reuse exact text features, always recomputing selection from source."""
        key = str(key)
        namespace = current_tenant_id_strict()
        cache_key = (namespace, key)
        identity = _cc.feature_identity()
        with self._lock:
            cached = self._cache.get(cache_key) if not self._closed else None
        previous = cached.features if cached is not None and cached.identity == identity else {}
        features = {}
        size = 256 + 4 * (len(key) + len(namespace or ""))
        retain = len(key) <= 512 and len(namespace or "") <= 512
        for message in messages:
            text = _cc._message_text(message)
            if text in features:
                continue
            if size + 256 + 4 * len(text) > _MAX_WINDOW_BYTES:
                retain = False
                features = {}
                break
            feature = previous.get(text)
            if feature is None:
                feature = _cc.prepare_features(text)
            size += _feature_size(text, feature)
            if size > _MAX_WINDOW_BYTES:
                # Do not build an unbounded temporary feature map for an
                # oversized caller. The normal compactor remains the fallback.
                retain = False
                features = {}
                break
            features[text] = feature
        immutable = MappingProxyType(features)
        with _cc.feature_scope(immutable):
            result = _cc.compact(messages, target_tokens=target_tokens).messages
        with self._lock:
            old = self._cache.pop(cache_key, None)
            if old is not None:
                self._bytes -= old.size
            if retain and not self._closed:
                self._cache[cache_key] = _FeatureWindow(identity, immutable, size)
                self._bytes += size
            while len(self._cache) > _MAX_KEYS or self._bytes > _MAX_BYTES:
                _, evicted = self._cache.popitem(last=False)
                self._bytes -= evicted.size
        return result

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {"cached_keys": len(self._cache), "pending": 0,
                    "retained_feature_bytes": self._bytes}

    def close(self) -> None:
        """Release retained history; subsequent calls remain correct and uncached."""
        with self._lock:
            self._closed = True
            self._cache.clear()
            self._bytes = 0


_shared: BackgroundCompactor | None = None
_shared_lock = threading.Lock()


def shared() -> BackgroundCompactor:
    global _shared
    with _shared_lock:
        if _shared is None:
            _shared = BackgroundCompactor()
        return _shared


def compact_with_precompute(key: str, messages: list[dict], *, target_tokens: int) -> list[dict]:
    """Module-level convenience over the process-shared compactor."""
    return shared().compact_with_precompute(key, messages, target_tokens=target_tokens)


__all__ = ["enabled", "BackgroundCompactor", "shared", "compact_with_precompute",
           "TAIL_TURNS"]
