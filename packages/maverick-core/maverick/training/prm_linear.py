"""Train a torch-free linear AgentPRM head from labeled trajectories.

A pure-Python (no torch, no numpy) linear head over the shared
``prm.step_features`` vector, fit by deterministic gradient descent and saved
as plain JSON loadable by :class:`maverick.prm.LinearPRM`. This is the
CPU-trainable, dependency-free complement to ``prm_train.py`` (which trains the
torch MLP head): same 12-feature contract, same JSON-vocabulary guard, no GPU,
no optional extras. Deterministic for a given dataset (weights start at zero,
the pass order is fixed), so a trained artifact is reproducible.

Usage:

    python -m maverick.training.prm_linear --data trajectories.jsonl \\
        --out prm_linear.json [--epochs 400 --lr 0.1 --l2 1e-4]

Input: Klear-format JSONL (``training/schema.py::to_klear_jsonl``) -- the same
input ``prm_train.py`` reads. Output: ``prm_linear.json``; then set
``MAVERICK_PRM=linear`` and ``MAVERICK_PRM_PATH=prm_linear.json`` to score every
agent step with it. Measure the lift with ``maverick prove-learning``.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

from ..prm import FEATURE_NAMES, ROLE_VOCAB
from .prm_train import load_klear, rows_to_examples


def _fit_head(
    examples: list[tuple[list[float], list[float]]], target: int, *,
    epochs: int, lr: float, l2: float,
) -> tuple[list[float], float]:
    """Fit ``tanh(w . x + b)`` to one label column by deterministic GD (MSE).

    Weights start at zero and the dataset is iterated in a fixed order, so the
    result is fully deterministic -- no seed needed.
    """
    dim = len(FEATURE_NAMES)
    w = [0.0] * dim
    b = 0.0
    pairs = [
        (feats, float(labels[target]))
        for feats, labels in examples
        if labels[target] is not None
    ]
    if not pairs:
        return w, b
    n = len(pairs)
    for _ in range(max(1, epochs)):
        gw = [0.0] * dim
        gb = 0.0
        for feats, y in pairs:
            z = sum(wi * xi for wi, xi in zip(w, feats, strict=True)) + b
            pred = math.tanh(z)
            # d/dz of 0.5*(tanh(z) - y)^2 = (pred - y) * (1 - pred^2)
            g = (pred - y) * (1.0 - pred * pred)
            for j in range(dim):
                gw[j] += g * feats[j]
            gb += g
        for j in range(dim):
            w[j] -= lr * (gw[j] / n + l2 * w[j])
        b -= lr * (gb / n)
    return w, b


def fit(
    examples: list[tuple[list[float], list[float]]], *,
    epochs: int = 400, lr: float = 0.1, l2: float = 1e-4,
) -> dict:
    """Fit promise + progress linear heads; return the JSON-serializable model
    artifact (the exact shape :class:`maverick.prm.LinearPRM` loads)."""
    pw, pb = _fit_head(examples, 0, epochs=epochs, lr=lr, l2=l2)
    gw, gb = _fit_head(examples, 1, epochs=epochs, lr=lr, l2=l2)
    return {
        "kind": "linear",
        "feature_names": list(FEATURE_NAMES),
        "role_vocab": list(ROLE_VOCAB),
        "input_dim": len(FEATURE_NAMES),
        "promise": {"w": pw, "b": pb},
        "progress": {"w": gw, "b": gb},
    }


def fit_from_klear(rows: list[dict], **kw) -> dict:
    """Convenience: Klear rows -> per-step examples -> fitted model."""
    return fit(rows_to_examples(rows), **kw)


def save(model: dict, path: str | Path) -> None:
    Path(path).expanduser().write_text(
        json.dumps(model, indent=2, sort_keys=True), encoding="utf-8")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m maverick.training.prm_linear",
        description="Train a torch-free linear AgentPRM head (plain JSON).",
    )
    p.add_argument("--data", required=True, help="Klear-format JSONL trajectories.")
    p.add_argument("--out", required=True, help="Output prm_linear.json path.")
    p.add_argument("--epochs", type=int, default=400)
    p.add_argument("--lr", type=float, default=0.1)
    p.add_argument("--l2", type=float, default=1e-4)
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    rows = load_klear(args.data)
    examples = rows_to_examples(rows)
    if not examples:
        print("no labeled step examples found in the trajectories", file=sys.stderr)
        return 1
    model = fit(examples, epochs=args.epochs, lr=args.lr, l2=args.l2)
    save(model, args.out)
    print(f"wrote {args.out} ({len(examples)} step examples, "
          f"{len(rows)} trajectories)")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
