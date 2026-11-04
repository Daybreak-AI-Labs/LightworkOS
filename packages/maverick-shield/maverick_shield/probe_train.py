"""Offline trainer for the Shield cheap-probe linear model.

Produces the JSON artifact ``probe_model.py`` already loads --
``{bias, weights, threshold, ngram_buckets, ngram_sizes}`` -- by fitting an
L2-regularised logistic regression over :func:`maverick_shield.probe_model.probe_features`
(the SAME extractor inference uses, so train/serve feature parity is guaranteed).

Deliberately pure-Python / stdlib-only: this is an OFFLINE dev tool, never
imported by the kernel at runtime, and the project ships no numpy/sklearn. It is
fast enough for the in-repo corpora and a worked example; a production run over
the large public corpora can reuse this exact code or export the same JSON shape from a heavier trainer.

Nothing here ships a model ON by default -- the artifact is only loaded when an
operator points ``[shield] probe_model`` at it. The cascade still ensembles it
with the heuristic by MAX, so a model can only raise recall.

CLI::

    python -m maverick_shield.probe_train --corpus data.jsonl --out model.json \\
        --ngram-buckets 256 --max-fp 0.01
"""
from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass
from pathlib import Path

from .probe_model import _sigmoid, probe_features

Sample = tuple[dict[str, float], int]


@dataclass
class TrainConfig:
    ngram_buckets: int = 256
    ngram_sizes: tuple[int, ...] = (3, 4, 5)
    epochs: int = 30
    lr: float = 0.5
    l2: float = 1e-4
    seed: int = 0


def load_corpus(path: str | Path) -> list[tuple[str, int]]:
    """Load ``(text, label)`` pairs. Supports JSONL (``{"text","label"}`` or the
    red-team corpus ``{"text","expected": block|allow}``) and plain-text files
    (one attack prompt per non-comment line -> label 1). Blank/``#`` lines skip."""
    p = Path(path)
    rows: list[tuple[str, int]] = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line[0] in "{[":
            obj = json.loads(line)
            text = obj.get("text", "")
            if "label" in obj:
                label = int(obj["label"])
            else:
                label = 1 if str(obj.get("expected", "")).lower() == "block" else 0
        else:
            text, label = line, 1
        if text:
            rows.append((text, label))
    return rows


def featurize(rows: list[tuple[str, int]], cfg: TrainConfig) -> list[Sample]:
    return [
        (probe_features(t, ngram_buckets=cfg.ngram_buckets,
                        ngram_sizes=cfg.ngram_sizes), y)
        for t, y in rows
    ]


def train(samples: list[Sample], cfg: TrainConfig) -> tuple[float, dict[str, float]]:
    """Fit sparse L2 logistic regression by SGD. Returns ``(bias, weights)``."""
    rng = random.Random(cfg.seed)
    bias = 0.0
    weights: dict[str, float] = {}
    order = list(range(len(samples)))
    for _ in range(cfg.epochs):
        rng.shuffle(order)
        for i in order:
            feats, y = samples[i]
            z = bias + sum(weights.get(f, 0.0) * x for f, x in feats.items())
            err = _sigmoid(z) - y
            bias -= cfg.lr * err
            for f, x in feats.items():
                w = weights.get(f, 0.0)
                weights[f] = w - cfg.lr * (err * x + cfg.l2 * w)
    # Drop ~zero weights so the artifact stays small and auditable.
    weights = {f: w for f, w in weights.items() if abs(w) > 1e-6}
    return bias, weights


def _score(bias: float, weights: dict[str, float], feats: dict[str, float]) -> float:
    return _sigmoid(bias + sum(weights.get(f, 0.0) * x for f, x in feats.items()))


def select_threshold(samples: list[Sample], bias: float, weights: dict[str, float],
                     max_fp: float = 0.01) -> tuple[float, dict[str, float]]:
    """Pick the lowest threshold whose benign false-positive rate is <= ``max_fp``
    (best recall under the FP ceiling). Returns ``(threshold, metrics)``."""
    scored = [(_score(bias, weights, f), y) for f, y in samples]
    pos = [s for s, y in scored if y == 1]
    neg = [s for s, y in scored if y == 0]
    best_t = 0.5
    for cand in sorted({round(s, 4) for s, _ in scored} | {0.5}):
        fp = (sum(1 for s in neg if s >= cand) / len(neg)) if neg else 0.0
        if fp <= max_fp:
            best_t = cand
            break
    metrics = _metrics(scored, best_t)
    metrics["benign_fp_rate"] = (
        sum(1 for s in neg if s >= best_t) / len(neg) if neg else 0.0)
    metrics["n_pos"], metrics["n_neg"] = len(pos), len(neg)
    return best_t, metrics


def _metrics(scored: list[tuple[float, int]], t: float) -> dict[str, float]:
    tp = sum(1 for s, y in scored if s >= t and y == 1)
    fp = sum(1 for s, y in scored if s >= t and y == 0)
    fn = sum(1 for s, y in scored if s < t and y == 1)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    return {"precision": prec, "recall": rec, "threshold": t}


def export(path: str | Path, bias: float, weights: dict[str, float],
           threshold: float, cfg: TrainConfig) -> None:
    artifact = {
        "bias": bias,
        "weights": weights,
        "threshold": threshold,
        "ngram_buckets": cfg.ngram_buckets,
        "ngram_sizes": list(cfg.ngram_sizes),
    }
    Path(path).write_text(json.dumps(artifact, indent=2, sort_keys=True),
                          encoding="utf-8")


def train_and_export(corpus: str | Path, out: str | Path, cfg: TrainConfig,
                     max_fp: float = 0.01) -> dict[str, float]:
    rows = load_corpus(corpus)
    samples = featurize(rows, cfg)
    bias, weights = train(samples, cfg)
    threshold, metrics = select_threshold(samples, bias, weights, max_fp=max_fp)
    export(out, bias, weights, threshold, cfg)
    metrics["n_features"] = float(len(weights))
    return metrics


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Train the Shield cheap-probe model.")
    ap.add_argument("--corpus", required=True, help="JSONL or text corpus path")
    ap.add_argument("--out", required=True, help="output model.json path")
    ap.add_argument("--ngram-buckets", type=int, default=256)
    ap.add_argument("--epochs", type=int, default=30)
    ap.add_argument("--max-fp", type=float, default=0.01,
                    help="benign false-positive ceiling for threshold selection")
    args = ap.parse_args(argv)
    cfg = TrainConfig(ngram_buckets=args.ngram_buckets, epochs=args.epochs)
    metrics = train_and_export(args.corpus, args.out, cfg, max_fp=args.max_fp)
    print(json.dumps(metrics, indent=2, sort_keys=True))
    if metrics.get("benign_fp_rate", 1.0) > args.max_fp:
        print(f"WARNING: benign FP rate {metrics['benign_fp_rate']:.3f} exceeds "
              f"--max-fp {args.max_fp}; do NOT ship this model ON by default.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
