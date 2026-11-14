"""Differential privacy on usage stats.

Release aggregate counts/sums with calibrated Laplace noise so an individual's
presence can't be inferred from a published statistic. Pure stdlib (no numpy):
the Laplace mechanism adds noise scaled to sensitivity/epsilon. Smaller epsilon
= more privacy, more noise. Counting queries have sensitivity 1; a bounded sum
has sensitivity = the per-record clamp bound.

ops:
  - count(value, epsilon)              — noisy count (sensitivity 1).
  - sum(values, epsilon, clamp)        — clamp each record to [0,clamp], noisy sum.
"""
from __future__ import annotations

import math
import random
from typing import Any

from . import Tool


def _laplace(scale: float, rng: random.Random) -> float:
    # Inverse-CDF sampling of Laplace(0, scale) from a uniform draw.
    # random() can return exactly 0.0, giving u == -0.5 and arg == 0, which
    # makes math.log() raise a domain error; floor the argument just above 0.
    u = rng.random() - 0.5
    arg = max(1 - 2 * abs(u), 2.2e-308)
    return -scale * math.copysign(1.0, u) * math.log(arg)


def _noisy(true_value: float, sensitivity: float, epsilon: float,
           seed: int | None) -> str:
    # epsilon=inf would add zero noise and label the true value as noisy;
    # NaN would pass every comparison.
    if not all(math.isfinite(v) for v in (true_value, sensitivity, epsilon)):
        return "ERROR: value, sensitivity and epsilon must be finite numbers"
    if epsilon <= 0:
        return "ERROR: epsilon must be > 0"
    scale = sensitivity / epsilon
    if not math.isfinite(scale):
        return "ERROR: sensitivity/epsilon is too large; raise epsilon"
    rng = random.Random(seed)
    noisy = true_value + _laplace(scale, rng)
    return (f"OK noisy={noisy:.4f} (epsilon={epsilon:g}, "
            f"sensitivity={sensitivity:g}, laplace_scale={scale:.4f})")


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    seed = args.get("seed")
    if seed is not None:
        try:
            seed = int(seed)
        except (TypeError, ValueError):
            return "ERROR: seed must be an integer"
    try:
        epsilon = float(args.get("epsilon", 1.0))
    except (TypeError, ValueError):
        return "ERROR: epsilon must be a number"

    if op in (None, "count"):
        try:
            value = float(args.get("value"))
        except (TypeError, ValueError):
            return "ERROR: value (the true count) is required"
        return _noisy(value, 1.0, epsilon, seed)

    if op == "sum":
        values = args.get("values")
        if not isinstance(values, list) or not values:
            return "ERROR: values (list of numbers) is required for sum"
        try:
            clamp = float(args.get("clamp"))
        except (TypeError, ValueError):
            return "ERROR: clamp (per-record bound = sensitivity) is required for sum"
        if clamp <= 0:
            return "ERROR: clamp must be > 0"
        total = sum(min(max(float(v), 0.0), clamp) for v in values)
        return _noisy(total, clamp, epsilon, seed)

    return f"ERROR: unknown op {op!r}"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["count", "sum"]},
        "value": {"type": "number", "description": "True count (op=count)"},
        "values": {"type": "array", "items": {"type": "number"},
                   "description": "Per-record values (op=sum)"},
        "clamp": {"type": "number", "description": "Per-record bound = sensitivity (op=sum)"},
        "epsilon": {"type": "number", "description": "Privacy budget (default 1.0)"},
        "seed": {"type": "integer", "description": "Optional RNG seed for reproducibility"},
    },
}


def dp_stats() -> Tool:
    return Tool(
        name="dp_stats",
        description=(
            "Differentially-private aggregate release via the Laplace "
            "mechanism. op=count(value,epsilon) for a noisy count; "
            "op=sum(values,epsilon,clamp) clamps each record then adds noise. "
            "Smaller epsilon = more privacy. Pure stdlib; optional 'seed' for "
            "reproducible noise."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
