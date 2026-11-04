"""Network egress accounting: per-host bytes sent / received.

An always-on, in-memory tally of network usage per host so a run can report
where its bytes went (and a future budget layer can cap it). Bounded by the
number of distinct hosts (capped, with an ``(other)`` overflow bucket).
Thread-safe; recording never raises into the network path.
"""
from __future__ import annotations

import threading

_MAX_HOSTS = 512
_OVERFLOW = "(other)"
_lock = threading.Lock()
# host -> [sent_bytes, recv_bytes, requests]
_tally: dict[str, list[int]] = {}


def record(host: str, *, sent: int = 0, received: int = 0) -> None:
    """Record one request's byte counts against ``host``."""
    host = (host or "(unknown)").strip().lower() or "(unknown)"
    s = max(0, int(sent or 0))
    r = max(0, int(received or 0))
    with _lock:
        if host not in _tally and len(_tally) >= _MAX_HOSTS:
            host = _OVERFLOW
        row = _tally.setdefault(host, [0, 0, 0])
        row[0] += s
        row[1] += r
        row[2] += 1


def report() -> list[dict]:
    """Per-host ``{host, sent_bytes, recv_bytes, requests, total_bytes}``,
    largest total first."""
    with _lock:
        snapshot = {h: list(v) for h, v in _tally.items()}
    out = [
        {
            "host": h,
            "sent_bytes": s,
            "recv_bytes": r,
            "requests": n,
            "total_bytes": s + r,
        }
        for h, (s, r, n) in snapshot.items()
    ]
    out.sort(key=lambda d: -d["total_bytes"])
    return out


def totals() -> dict:
    """Aggregate ``{sent_bytes, recv_bytes, requests, total_bytes, hosts}``."""
    with _lock:
        s = sum(v[0] for v in _tally.values())
        r = sum(v[1] for v in _tally.values())
        n = sum(v[2] for v in _tally.values())
        hosts = len(_tally)
    return {
        "sent_bytes": s, "recv_bytes": r, "requests": n,
        "total_bytes": s + r, "hosts": hosts,
    }


def reset() -> None:
    """Clear all counters (tests / a fresh run)."""
    with _lock:
        _tally.clear()


__all__ = ["record", "report", "totals", "reset"]
