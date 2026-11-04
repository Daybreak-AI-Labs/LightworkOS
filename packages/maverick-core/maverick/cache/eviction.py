"""Shared cache eviction/expiry *policy* (storage-agnostic).

The cache modules in this package back different stores -- ``llm`` is SQLite
rows, ``learning`` is a JSON-persisted dict -- so they cannot share a concrete
store base without migrating one's on-disk format. What they DO share is the
policy: TTL expiry plus a least-recently-used count cap. These pure helpers
capture that decision so each store applies the same rule at its own layer
(``learning`` calls them directly; the SQLite ``llm`` store expresses the same
LRU-by-``last_used`` selection in SQL and references this module for the policy).
"""
from __future__ import annotations


def is_expired(now: float, expires_at: float) -> bool:
    """True once ``now`` reaches an absolute ``expires_at`` timestamp."""
    return now >= float(expires_at)


def lru_keys_to_evict(last_used: dict[str, float], cap: int) -> list[str]:
    """Keys to drop so at most ``cap`` entries remain, least-recently-used
    first (ties broken by the dict's iteration order). Empty when under cap."""
    cap = max(0, int(cap))
    overflow = len(last_used) - cap
    if overflow <= 0:
        return []
    ordered = sorted(last_used, key=lambda k: float(last_used[k]))  # oldest first
    return ordered[:overflow]
