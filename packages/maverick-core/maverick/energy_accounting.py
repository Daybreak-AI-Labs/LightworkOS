"""Energy/CO2 accounting for token usage — clearly labeled ESTIMATES
.

Sustainability reporting increasingly asks what an agent fleet's inference
*footprint* is, but vendors don't publish per-token energy. What exists are
public rough estimates (research papers, datacenter disclosures) that vary
widely by model size, hardware generation, batching and datacenter PUE. This
module does the only honest thing possible with that: multiply token volumes
by a single conservative, *documented and configurable* coefficient and label
every output as an estimate. It exists to give orders of magnitude for
reporting and comparisons between runs — not vendor-grade measurements.

Coefficients (override via ``[energy]`` config; env wins):

* :data:`WH_PER_1K_TOKENS_DEFAULT` (0.3 Wh per 1k weighted tokens) — a
  middle-of-road public estimate for serving a large frontier-class model,
  NOT vendor data. ``[energy] wh_per_1k_tokens`` /
  ``MAVERICK_ENERGY_WH_PER_1K_TOKENS``.
* :data:`GRID_CO2_G_PER_KWH_DEFAULT` (400 g CO2e/kWh, ~world-average grid
  intensity) — a datacenter on hydro or coal differs by an order of
  magnitude. ``[energy] grid_co2_g_per_kwh`` /
  ``MAVERICK_ENERGY_GRID_CO2_G_PER_KWH``.

Output tokens are weighted :data:`OUTPUT_TOKEN_WEIGHT` (3x) over input:
generation runs the full forward pass per token while prompt ingestion
batches, so an output token costs several input tokens' worth of compute.

:func:`render` ALWAYS includes the estimate disclaimer — these numbers must
never be quoted as measurements. Pure library, stdlib-only, nothing runs
unless called.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

# Wh per 1k WEIGHTED tokens (input + 3x output). A conservative public rough
# estimate for frontier-model inference; configurable because it is wrong for
# any specific deployment by construction.
WH_PER_1K_TOKENS_DEFAULT = 0.3

# Grid carbon intensity, g CO2e per kWh. ~world average; set yours.
GRID_CO2_G_PER_KWH_DEFAULT = 400.0

# Output tokens cost ~3x input: generation is one full forward pass per token,
# prompt ingestion amortizes across the whole prompt.
OUTPUT_TOKEN_WEIGHT = 3.0

DISCLAIMER = (
    "ESTIMATE ONLY: computed from a flat Wh-per-1k-token coefficient and a world-average "
    "grid intensity — public rough figures, not vendor data. Real per-token energy varies "
    "by model, hardware, batching and datacenter; tune [energy] wh_per_1k_tokens and "
    "grid_co2_g_per_kwh for your deployment."
)


@dataclass(frozen=True)
class EnergyEstimate:
    wh: float     # estimated watt-hours
    co2_g: float  # estimated grams CO2e


def _knob(env: str, key: str, default: float) -> float:
    """A positive-float knob: env wins, then ``[energy]`` config, then default.

    Non-numeric or non-positive values fall back to the default — a config
    typo must degrade to the documented estimate, not crash accounting.
    """
    raw: object = os.environ.get(env)
    if raw is None or str(raw).strip() == "":
        try:
            from .config import load_config
            raw = (load_config() or {}).get("energy", {}).get(key)
        except Exception:  # pragma: no cover -- config never blocks accounting
            raw = None
    if raw is None or str(raw).strip() == "":
        return default
    try:
        value = float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def wh_per_1k_tokens() -> float:
    """Effective Wh/1k-weighted-tokens coefficient (env > config > default)."""
    return _knob("MAVERICK_ENERGY_WH_PER_1K_TOKENS", "wh_per_1k_tokens",
                 WH_PER_1K_TOKENS_DEFAULT)


def grid_co2_g_per_kwh() -> float:
    """Effective grid intensity in g CO2e/kWh (env > config > default)."""
    return _knob("MAVERICK_ENERGY_GRID_CO2_G_PER_KWH", "grid_co2_g_per_kwh",
                 GRID_CO2_G_PER_KWH_DEFAULT)


def estimate(in_tokens: int, out_tokens: int) -> EnergyEstimate:
    """Estimate Wh and g CO2e for a token volume (output weighted 3x input)."""
    in_t = max(0, int(in_tokens or 0))
    out_t = max(0, int(out_tokens or 0))
    weighted_kilotokens = (in_t + OUTPUT_TOKEN_WEIGHT * out_t) / 1000.0
    wh = weighted_kilotokens * wh_per_1k_tokens()
    co2_g = (wh / 1000.0) * grid_co2_g_per_kwh()
    return EnergyEstimate(wh=wh, co2_g=co2_g)


def estimate_run(rows) -> EnergyEstimate:
    """Estimate over usage rows (duck-typed episodes).

    Rows may be objects or dicts carrying ``input_tokens``/``output_tokens``
    (the world model's ``EpisodeSpend`` shape) or ``in_tokens``/``out_tokens``.
    """
    total_in = 0
    total_out = 0
    for row in rows or []:
        if isinstance(row, dict):
            in_t = row.get("input_tokens", row.get("in_tokens", 0))
            out_t = row.get("output_tokens", row.get("out_tokens", 0))
        else:
            in_t = getattr(row, "input_tokens", None)
            if in_t is None:
                in_t = getattr(row, "in_tokens", 0)
            out_t = getattr(row, "output_tokens", None)
            if out_t is None:
                out_t = getattr(row, "out_tokens", 0)
        total_in += max(0, int(in_t or 0))
        total_out += max(0, int(out_t or 0))
    return estimate(total_in, total_out)


def gather_from_world(world, *, limit: int = 500) -> list:
    """Recent episodes from a world model, as :func:`estimate_run` rows.

    Duck-typed: needs ``list_episodes(limit=...)`` yielding objects with
    ``input_tokens``/``output_tokens`` (the SQLite backend's ``EpisodeSpend``).
    """
    return list(world.list_episodes(limit=limit))


def render(est: EnergyEstimate) -> str:
    """One-line summary — ALWAYS followed by the estimate disclaimer."""
    line = (
        f"Energy/CO2 estimate: ~{est.wh:.2f} Wh (~{est.wh / 1000.0:.5f} kWh), "
        f"~{est.co2_g:.2f} g CO2e"
    )
    return line + "\n" + DISCLAIMER


__all__ = [
    "WH_PER_1K_TOKENS_DEFAULT", "GRID_CO2_G_PER_KWH_DEFAULT", "OUTPUT_TOKEN_WEIGHT",
    "DISCLAIMER", "EnergyEstimate", "wh_per_1k_tokens", "grid_co2_g_per_kwh",
    "estimate", "estimate_run", "gather_from_world", "render",
]
