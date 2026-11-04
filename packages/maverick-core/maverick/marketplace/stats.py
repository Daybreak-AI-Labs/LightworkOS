"""Marketplace stats.

Aggregates the local ratings ledger (:mod:`maverick.marketplace_ratings`) into
the numbers a stats view wants: how many things you've rated, the average, the
1–5★ distribution, a per-kind breakdown (skills vs templates vs channels), and
your top-rated items. Self-host-first: this summarizes the operator's **own**
ledger (there is no hosted community service); the dashboard renders it and
``maverick template rate`` feeds it.

Pure and deterministic — a ledger in, a stats dict out — so it's tested without
disk or a server.
"""
from __future__ import annotations


def summarize(ledger, *, top_n: int = 10) -> dict:
    """Aggregate a ratings ledger into a stats dict."""
    data = ledger.all_ratings() or {}
    all_stars: list[int] = []
    by_kind: dict[str, dict] = {}
    rated: list[tuple[str, str, int]] = []
    for kind, items in data.items():
        kstars: list[int] = []
        for name, entry in (items or {}).items():
            try:
                s = int(entry.get("stars", 0))
            except (TypeError, ValueError, AttributeError):
                continue
            if 1 <= s <= 5:
                all_stars.append(s)
                kstars.append(s)
                rated.append((kind, str(name), s))
        if kstars:
            by_kind[kind] = {"count": len(kstars),
                             "average": round(sum(kstars) / len(kstars), 2)}
    distribution = {str(i): all_stars.count(i) for i in range(1, 6)}
    top = sorted(rated, key=lambda r: (-r[2], r[0], r[1]))[:max(0, top_n)]
    return {
        "total": len(all_stars),
        "average": round(sum(all_stars) / len(all_stars), 2) if all_stars else 0.0,
        "distribution": distribution,
        "by_kind": dict(sorted(by_kind.items())),
        "top_rated": [{"kind": k, "name": n, "stars": s} for k, n, s in top],
    }


__all__ = ["summarize"]
