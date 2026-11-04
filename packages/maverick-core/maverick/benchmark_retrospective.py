"""Longitudinal benchmark retrospective.

``continuous_benchmark`` answers "did the last run regress vs the recent
baseline?" — a short-window question. The retrospective answers the long one:
over the FULL recorded history (the intended cadence is a multi-year span,
e.g. the 3-year mark), how did each benchmark actually move? It slices the
history into **eras** (calendar quarters by default), computes per-era
medians, era-over-era deltas, the best/worst eras, net change first→last era,
and a trend verdict (improving / flat / declining by least-squares slope sign
with a flatness band) — rendered as the retrospective report.

Pure over ``continuous_benchmark``'s history rows (``{name, score, commit,
t}``); deterministic and offline; the history span is whatever the deployment
recorded — the report states its actual coverage rather than pretending.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from statistics import median

from .paths import data_dir

FLAT_BAND = 0.01   # |relative slope per era| under this = "flat"


def _era_of(epoch: float) -> str:
    d = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return f"{d.year}-Q{(d.month - 1) // 3 + 1}"


@dataclass
class BenchRetro:
    name: str
    eras: list[str] = field(default_factory=list)          # chronological
    era_median: dict[str, float] = field(default_factory=dict)
    runs: int = 0

    @property
    def net_change(self) -> float:
        """Relative change, first era median → last era median."""
        if len(self.eras) < 2:
            return 0.0
        first = self.era_median[self.eras[0]]
        last = self.era_median[self.eras[-1]]
        return (last - first) / abs(first) if first else 0.0

    @property
    def best_era(self) -> str | None:
        return max(self.eras, key=lambda e: self.era_median[e], default=None)

    @property
    def worst_era(self) -> str | None:
        return min(self.eras, key=lambda e: self.era_median[e], default=None)

    @property
    def trend(self) -> str:
        """least-squares slope over era medians, relative to the mean level."""
        if len(self.eras) < 2:
            return "insufficient data"
        ys = [self.era_median[e] for e in self.eras]
        n = len(ys)
        xs = list(range(n))
        mean_x = sum(xs) / n
        mean_y = sum(ys) / n
        denom = sum((x - mean_x) ** 2 for x in xs)
        slope = (sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys, strict=False)) / denom
                 if denom else 0.0)
        rel = slope / abs(mean_y) if mean_y else 0.0
        if rel > FLAT_BAND:
            return "improving"
        if rel < -FLAT_BAND:
            return "declining"
        return "flat"


def analyze(history: list[dict]) -> dict[str, BenchRetro]:
    """Slice the full history into per-benchmark, per-era medians."""
    by_bench: dict[str, dict[str, list[float]]] = {}
    counts: dict[str, int] = {}
    for row in history:
        name = row.get("name")
        score = row.get("score")
        t = row.get("t")
        if not name or not isinstance(score, (int, float)) or not t:
            continue
        by_bench.setdefault(name, {}).setdefault(_era_of(float(t)), []).append(
            float(score))
        counts[name] = counts.get(name, 0) + 1
    out: dict[str, BenchRetro] = {}
    for name, eras in by_bench.items():
        ordered = sorted(eras)
        out[name] = BenchRetro(
            name=name,
            eras=ordered,
            era_median={e: median(v) for e, v in eras.items()},
            runs=counts[name],
        )
    return out


def coverage(history: list[dict]) -> tuple[str, str] | None:
    """(first_era, last_era) actually covered, or None for an empty history."""
    ts = [float(r["t"]) for r in history if r.get("t")]
    if not ts:
        return None
    return _era_of(min(ts)), _era_of(max(ts))


def render(history: list[dict]) -> str:
    retros = analyze(history)
    span = coverage(history)
    if not retros or span is None:
        return "benchmark retrospective: no recorded history."
    lines = [f"benchmark retrospective — coverage {span[0]} → {span[1]} "
             f"({sum(r.runs for r in retros.values())} recorded runs)"]
    for name in sorted(retros):
        r = retros[name]
        lines.append(
            f"  {name}: {r.trend}; net {r.net_change:+.1%} "
            f"({r.eras[0]} → {r.eras[-1]}); best {r.best_era}, "
            f"worst {r.worst_era}; {r.runs} runs")
        for era in r.eras:
            lines.append(f"      {era}: median {r.era_median[era]:g}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:  # pragma: no cover -- CLI shell
    import argparse
    import json
    from pathlib import Path
    p = argparse.ArgumentParser(prog="maverick.benchmark_retrospective",
                                description="Longitudinal benchmark retrospective.")
    p.add_argument("--store", default=None,
                   help="benchmark history dir (default ~/.maverick/benchmarks)")
    args = p.parse_args(argv)
    store = Path(args.store) if args.store else data_dir("benchmarks")
    history: list[dict] = []
    if store.is_dir():
        for f in sorted(store.glob("*.json")):
            try:
                rows = json.loads(f.read_text(encoding="utf-8"))
                if isinstance(rows, list):
                    history.extend(r for r in rows if isinstance(r, dict))
            except (OSError, ValueError):
                continue
    print(render(history))
    return 0


__all__ = ["BenchRetro", "analyze", "coverage", "render", "FLAT_BAND"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
