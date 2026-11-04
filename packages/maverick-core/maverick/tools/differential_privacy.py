"""Differential privacy helper.

Adds calibrated Laplace noise to an aggregate statistic so a published number
(e.g. "how many users hit this feature") doesn't leak any single individual's
presence — the standard (ε)-differential-privacy mechanism. Deterministic when
a ``seed`` is supplied (reproducible for tests/audits); otherwise fresh noise.

ops:
  - noisy_count(value, epsilon[, seed])                — sensitivity 1, clamped >= 0.
  - noisy_sum(value, epsilon, sensitivity[, seed])     — arbitrary sensitivity.

Noise scale b = sensitivity / epsilon. Smaller epsilon = more privacy = more noise.
"""
from __future__ import annotations

import math
import random
from typing import Any

from . import Tool


def _laplace(rng: random.Random, scale: float) -> float:
    """Sample Laplace(0, scale) via inverse CDF.

    ``rng.random()`` can return exactly 0.0, giving ``u == -0.5`` and
    ``1 - 2*abs(u) == 0`` -> ``math.log(0)`` raises a domain error. Floor the
    argument just above 0 so the draw is always defined.
    """
    u = rng.random() - 0.5
    arg = max(1.0 - 2.0 * abs(u), 2.2e-308)
    return -scale * math.copysign(1.0, u) * math.log(arg)


def _numeric(args: dict, key: str) -> tuple[float | None, str]:
    v = args.get(key)
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None, f"ERROR: {key} must be a number"
    return float(v), ""


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op not in ("noisy_count", "noisy_sum"):
        return f"ERROR: unknown op {op!r} (expected noisy_count|noisy_sum)"

    value, err = _numeric(args, "value")
    if err:
        return err
    eps, err = _numeric(args, "epsilon")
    if err:
        return err
    if eps is None or eps <= 0:
        return "ERROR: epsilon must be > 0"

    if op == "noisy_sum":
        sens, err = _numeric(args, "sensitivity")
        if err:
            return err
        if sens is None or sens <= 0:
            return "ERROR: sensitivity must be > 0"
    else:
        sens = 1.0

    scale = sens / eps
    seed = args.get("seed")
    rng = random.Random(seed if isinstance(seed, int) else None)
    noisy = value + _laplace(rng, scale)

    if op == "noisy_count":
        result: float = max(0, round(noisy))  # counts are non-negative integers
    else:
        result = round(noisy, 4)

    return (
        f"{op}: {result}\n"
        f"(epsilon={eps:g}, sensitivity={sens:g}, laplace_scale={scale:g})\n"
        f"— {eps:g}-differentially-private noisy value; true aggregate omitted."
    )


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["noisy_count", "noisy_sum"]},
        "value": {"type": "number", "description": "the true aggregate to privatise"},
        "epsilon": {"type": "number", "description": "privacy budget (>0; smaller = more private)"},
        "sensitivity": {"type": "number", "description": "max one record can change the sum (noisy_sum)"},
        "seed": {"type": "integer", "description": "RNG seed for reproducible noise"},
    },
    "required": ["op", "value", "epsilon"],
}


def differential_privacy() -> Tool:
    return Tool(
        name="differential_privacy",
        description=(
            "Add calibrated Laplace noise to an aggregate for (epsilon)-"
            "differential privacy. ops: noisy_count (sensitivity 1, clamped "
            ">=0), noisy_sum (with 'sensitivity'). Pass 'value' + 'epsilon' "
            "(smaller = more private = more noise), optional 'seed' for "
            "reproducible noise. Publish the noisy value, not the true one."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
