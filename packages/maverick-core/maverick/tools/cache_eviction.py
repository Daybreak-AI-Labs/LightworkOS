"""Cache eviction simulator.

Replay an access trace against a fixed-capacity cache under a chosen eviction
policy and report the hit-rate — the offline yardstick for "would a bigger /
smarter cache have paid off?". Deterministic and offline: two clean classic
policies are implemented in pure stdlib.

  - lru: evict the Least-Recently-Used key.
  - lfu: evict the Least-Frequently-Used key (ties broken by least-recently-used)
         — the frequency-aware baseline that adaptive schemes (ARC/LeCaR) blend.

ops:
  - simulate(capacity, accesses, [policy=lru])  — hits, misses, hit_rate, cache.
"""
from __future__ import annotations

from typing import Any

from . import Tool


def _simulate_lru(capacity: int, accesses: list) -> tuple[int, int, list]:
    # Insertion order tracks recency; move-to-end on hit, popitem(first) to evict.
    from collections import OrderedDict

    cache: OrderedDict[str, None] = OrderedDict()
    hits = misses = 0
    for key in accesses:
        k = str(key)
        if k in cache:
            hits += 1
            cache.move_to_end(k)
        else:
            misses += 1
            if len(cache) >= capacity:
                cache.popitem(last=False)
            cache[k] = None
    return hits, misses, list(cache.keys())


def _simulate_lfu(capacity: int, accesses: list) -> tuple[int, int, list]:
    # Per-key frequency + last-use tick; evict min frequency, then oldest use.
    freq: dict[str, int] = {}
    last_used: dict[str, int] = {}
    hits = misses = 0
    for tick, key in enumerate(accesses):
        k = str(key)
        if k in freq:
            hits += 1
        else:
            misses += 1
            if len(freq) >= capacity:
                victim = min(freq, key=lambda x: (freq[x], last_used[x]))
                del freq[victim]
                del last_used[victim]
            freq[k] = 0
        freq[k] += 1
        last_used[k] = tick
    # Report contents most-frequent first (ties: most-recent first).
    contents = sorted(freq, key=lambda x: (freq[x], last_used[x]), reverse=True)
    return hits, misses, contents


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "simulate"):
        return f"ERROR: unknown op {args.get('op')!r}"
    try:
        capacity = int(args.get("capacity"))
    except (TypeError, ValueError, OverflowError):
        return "ERROR: capacity (positive integer) is required"
    if capacity <= 0:
        return "ERROR: capacity must be > 0"
    accesses = args.get("accesses")
    if not isinstance(accesses, list):
        return "ERROR: accesses (list of keys) is required"
    policy = str(args.get("policy", "lru")).strip().lower()
    if policy == "lru":
        hits, misses, cache = _simulate_lru(capacity, accesses)
    elif policy == "lfu":
        hits, misses, cache = _simulate_lfu(capacity, accesses)
    else:
        return f"ERROR: unknown policy {policy!r}; choose lru or lfu"

    total = hits + misses
    rate = (hits / total) if total else 0.0
    shown = ", ".join(cache) if cache else "(empty)"
    return (f"OK policy={policy} capacity={capacity} "
            f"hits={hits} misses={misses} hit_rate={rate:.4f}\n"
            f"  cache: [{shown}]")


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["simulate"]},
        "capacity": {"type": "integer", "description": "Max keys the cache holds"},
        "accesses": {
            "type": "array",
            "description": "Ordered access trace (list of keys; coerced to strings)",
            "items": {"type": ["string", "number"]},
        },
        "policy": {"type": "string", "enum": ["lru", "lfu"], "description": "Eviction policy (default lru)"},
    },
    "required": ["capacity", "accesses"],
}


def cache_eviction() -> Tool:
    return Tool(
        name="cache_eviction",
        description=(
            "Cache eviction simulator. op=simulate with 'capacity', 'accesses' "
            "(ordered list of keys), and 'policy' (lru or lfu, default lru). "
            "Replays the trace and returns hits, misses, hit_rate, and the final "
            "cache contents. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
