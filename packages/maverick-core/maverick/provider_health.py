"""Provider health collector.

In-memory rolling stats per (provider, model): call count, error
count, p50/p95 latency, total dollars spent, last seen.

Designed to be cheap to update from the hot path (single dict insert
+ list append; bounded list) and cheap to read for the dashboard
``/providers`` page.

Stats reset on process restart. For long-running deployments the
dashboard's API serializes the current snapshot to JSON so it can be
scraped or piped into a TSDB.
"""
from __future__ import annotations

import statistics
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field

_WINDOW = 200  # last-N samples per (provider, model) for percentiles
_DEFAULT_TIMEOUT_S = 60.0


@dataclass
class ProviderStat:
    provider: str
    model: str
    calls: int = 0
    errors: int = 0
    total_dollars: float = 0.0
    last_seen: float = 0.0
    latencies_ms: deque = field(default_factory=lambda: deque(maxlen=_WINDOW))

    def p50(self) -> float | None:
        if not self.latencies_ms:
            return None
        return float(statistics.median(self.latencies_ms))

    def p95(self) -> float | None:
        if not self.latencies_ms:
            return None
        # statistics.quantiles(n=20) interpolates between the two highest
        # samples, so for a small window it reports a p95 *above every observed
        # latency* (with 3 samples it sits ~95% of the way to the max) — a
        # misleading number on the dashboard. Below 20 samples, fall back to the
        # nearest-rank value (the ceil(0.95*n)-th smallest), which is always a
        # real observation. At >=20 samples the interpolated estimate is sound.
        if len(self.latencies_ms) < 20:
            ordered = sorted(self.latencies_ms)
            rank = -(-95 * len(ordered) // 100)  # ceil(0.95 * n), >=1
            return float(ordered[rank - 1])
        cuts = statistics.quantiles(self.latencies_ms, n=20)
        return float(cuts[18])  # 95th of 20-quantile = idx 18

    def error_rate(self) -> float:
        return (self.errors / self.calls) if self.calls else 0.0

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "model": self.model,
            "calls": self.calls,
            "errors": self.errors,
            "error_rate": self.error_rate(),
            "total_dollars": round(self.total_dollars, 4),
            "p50_ms": self.p50(),
            "p95_ms": self.p95(),
            "last_seen": self.last_seen,
        }


class ProviderHealth:
    """Thread-safe collector. One global instance via :func:`get`."""

    # Cap distinct (provider, model) keys. Model names are caller-supplied,
    # so a misconfig or a provider that echoes per-request model IDs would
    # otherwise grow this dict without bound for the process lifetime. When
    # over the cap, evict the least-recently-seen key.
    _MAX_KEYS = 512

    def __init__(self) -> None:
        # OrderedDict for O(1) LRU eviction (move_to_end on use,
        # popitem(last=False) to drop the least-recently-used key) instead
        # of an O(N) min()-scan under the lock on every cold-key insert.
        self._stats: OrderedDict[tuple[str, str], ProviderStat] = OrderedDict()
        self._lock = threading.Lock()

    def _key(self, provider: str, model: str) -> tuple[str, str]:
        return (provider or "?", model or "?")

    def record(
        self,
        provider: str,
        model: str,
        *,
        latency_ms: float,
        dollars: float = 0.0,
        error: bool = False,
    ) -> None:
        if latency_ms < 0:
            latency_ms = 0.0
        with self._lock:
            k = self._key(provider, model)
            st = self._stats.get(k)
            if st is None:
                if len(self._stats) >= self._MAX_KEYS:
                    self._stats.popitem(last=False)  # evict least-recently-used
                st = ProviderStat(provider=k[0], model=k[1])
                self._stats[k] = st
            else:
                self._stats.move_to_end(k)  # mark recently used
            st.calls += 1
            if error:
                st.errors += 1
            st.total_dollars += float(dollars or 0.0)
            st.latencies_ms.append(float(latency_ms))
            st.last_seen = time.time()

    def snapshot(self) -> list[dict]:
        """List of {provider, model, ...} sorted by call count desc."""
        with self._lock:
            rows = [s.to_dict() for s in self._stats.values()]
        rows.sort(key=lambda r: r["calls"], reverse=True)
        return rows

    def reset(self) -> None:
        with self._lock:
            self._stats.clear()


_singleton: ProviderHealth | None = None
_singleton_lock = threading.Lock()


def get() -> ProviderHealth:
    """Lazy global singleton."""
    global _singleton
    if _singleton is None:
        with _singleton_lock:
            if _singleton is None:
                _singleton = ProviderHealth()
    return _singleton


__all__ = ["ProviderHealth", "ProviderStat", "get"]
