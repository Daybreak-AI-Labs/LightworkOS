"""Continuous benchmarking: record benchmark scores over time, flag regressions.

The benchmark *harnesses* (eval_gaia, eval_tau2, eval_terminal_bench) score
a single run; this is the durable layer on top — append each run's score to a
per-benchmark history (keyed by name + commit) and detect when a new score
regresses materially below the recent baseline. Pure, dependency-free, JSON-backed
so it runs in CI and locally. ``record_result`` / ``detect_regression`` are the
unit-tested core; the ``bench_track`` tool persists history under
``~/.maverick/benchmarks/``.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from .paths import data_dir

_DEFAULT_BASELINE = 5   # runs to average for the baseline
_DEFAULT_THRESHOLD = 0.05  # 5% relative drop is a regression


def record_result(history: list[dict], name: str, score: float,
                  commit: str = "") -> list[dict]:
    """Append a scored run to ``history`` (in place) and return it.

    Higher score = better (the convention across the harnesses). ``score`` is
    coerced to float; a non-numeric score raises ``ValueError``.
    """
    try:
        s = float(score)
    except (TypeError, ValueError) as e:
        raise ValueError(f"score must be numeric, got {score!r}") from e
    history.append({
        "name": str(name),
        "score": s,
        "commit": str(commit or ""),
        "t": round(time.time(), 3),
    })
    return history


def _scores_for(history: list[dict], name: str) -> list[float]:
    # load_history accepts any JSON list: skip rows that are not a result.
    return [h["score"] for h in history
            if isinstance(h, dict) and h.get("name") == name
            and isinstance(h.get("score"), (int, float))]


def detect_regression(history: list[dict], name: str, *,
                      baseline: int = _DEFAULT_BASELINE,
                      threshold: float = _DEFAULT_THRESHOLD) -> dict:
    """Compare the latest score for ``name`` to the mean of the prior runs.

    Returns ``{regressed, latest, baseline_mean, delta, drop_pct, n}``. The
    baseline is the mean of up to ``baseline`` runs immediately preceding the
    latest. With no prior runs, ``regressed`` is False (nothing to compare).
    """
    scores = _scores_for(history, name)
    if len(scores) < 2:
        latest = scores[-1] if scores else 0.0
        return {"regressed": False, "latest": latest, "baseline_mean": None,
                "delta": 0.0, "drop_pct": 0.0, "n": len(scores)}
    latest = scores[-1]
    prior = scores[-(baseline + 1):-1]
    mean = sum(prior) / len(prior)
    delta = latest - mean
    drop_pct = (-delta / mean) if mean else 0.0
    return {
        "regressed": drop_pct > threshold,
        "latest": round(latest, 6),
        "baseline_mean": round(mean, 6),
        "delta": round(delta, 6),
        "drop_pct": round(drop_pct, 4),
        "n": len(scores),
    }


def load_history(path: str | Path) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else []


def save_history(path: str | Path, history: list[dict]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(history, indent=2), encoding="utf-8")


_SCHEMA = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["record", "check", "history"]},
        "name": {"type": "string", "description": "benchmark name"},
        "score": {"type": "number"},
        "commit": {"type": "string"},
        "threshold": {"type": "number", "description": "regression threshold (default 0.05)"},
    },
    "required": ["op"],
}


def _store_path() -> Path:
    # Resolved at CALL time, not bound to a module-level constant: the same
    # fix applied to donation._default_outbox() for the identical bug class.
    # data_dir("benchmarks") defaults to the ACTIVE tenant at the moment it
    # runs; binding it once at import time would freeze benchmark_regressed()
    # (dreaming.py's learning-side canary) onto whichever tenant happened to
    # be active during import, for the life of the process.
    return data_dir("benchmarks") / "history.json"


def _run(args: dict) -> str:
    op = args.get("op")
    path = _store_path()
    history = load_history(path)
    name = args.get("name") or ""
    try:
        if op == "record":
            if "score" not in args:
                return "ERROR: record requires a score"
            record_result(history, name, args["score"], args.get("commit") or "")
            save_history(path, history)
            return f"recorded {name}={args['score']}"
        if op == "check":
            r = detect_regression(
                history, name,
                threshold=float(args.get("threshold") or _DEFAULT_THRESHOLD))
            verdict = "REGRESSION" if r["regressed"] else "ok"
            return (f"{name}: {verdict} (latest={r['latest']}, "
                    f"baseline={r['baseline_mean']}, drop={r['drop_pct']:.1%}, "
                    f"n={r['n']})")
        if op == "history":
            rows = [h for h in history
                    if not name or (isinstance(h, dict) and h.get("name") == name)]
            return json.dumps(rows, indent=2) if rows else "(no history)"
    except ValueError as e:
        return f"ERROR: {e}"
    return f"ERROR: unknown op {op!r}"


def bench_track():
    from .tools import Tool
    return Tool(
        name="bench_track",
        description=(
            "Track benchmark scores over time and flag regressions. ops: record "
            "(name, score, commit), check (name, threshold) -> regression verdict "
            "vs the recent baseline, history (name). Persisted under "
            "~/.maverick/benchmarks."
        ),
        input_schema=_SCHEMA,
        fn=_run,
    )


__all__ = [
    "record_result", "detect_regression", "load_history", "save_history",
    "bench_track",
]
