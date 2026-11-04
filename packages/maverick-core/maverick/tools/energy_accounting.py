"""Energy / CO2 accounting for inference.

Turn a workload (tokens processed, or raw GPU-seconds) into an estimated energy
draw in watt-hours and the resulting operational CO2e in grams, using openly
documented intensity defaults. Deterministic and offline: every figure is a
simple product of the input and a stated assumption, and the assumptions used
are reported alongside the answer so the estimate is auditable, not a black box.

ops:
  - estimate({tokens | gpu_seconds}, [wh_per_ktok], [gpu_watts], [grid_g_co2_per_kwh])

Defaults (overridable per call):
  - 0.3 Wh per 1,000 tokens          (wh_per_ktok)
  - 700 W average GPU draw           (gpu_watts, used with gpu_seconds)
  - 400 g CO2e per kWh grid average  (grid_g_co2_per_kwh)

The token and grid defaults are the deployment's own figures when set:
``[energy] wh_per_1k_tokens`` / ``grid_co2_g_per_kwh`` (Settings > All
settings; ``MAVERICK_ENERGY_*`` still wins), read through
:mod:`maverick.energy_accounting` so the tool and the kernel agree.
"""
from __future__ import annotations

from typing import Any

from . import Tool

_DEFAULT_WH_PER_KTOK = 0.3
_DEFAULT_GPU_WATTS = 700.0
_DEFAULT_GRID = 400.0  # gCO2e / kWh


def _configured_defaults() -> tuple[float, float]:
    """(Wh per 1k tokens, grid g CO2e/kWh): the deployment's figures, else built-ins."""
    try:
        from ..energy_accounting import grid_co2_g_per_kwh, wh_per_1k_tokens

        return wh_per_1k_tokens(), grid_co2_g_per_kwh()
    except Exception:  # pragma: no cover -- config never breaks an estimate
        return _DEFAULT_WH_PER_KTOK, _DEFAULT_GRID


def _estimate(args: dict[str, Any]) -> str:
    wh_default, grid_default = _configured_defaults()
    try:
        wh_per_ktok = float(args.get("wh_per_ktok", wh_default))
        gpu_watts = float(args.get("gpu_watts", _DEFAULT_GPU_WATTS))
        grid = float(args.get("grid_g_co2_per_kwh", grid_default))
    except (TypeError, ValueError):
        return "ERROR: factors must be numbers"
    if grid < 0 or wh_per_ktok < 0 or gpu_watts < 0:
        return "ERROR: factors must be non-negative"

    has_tokens = args.get("tokens") is not None
    has_gpu = args.get("gpu_seconds") is not None
    if has_tokens == has_gpu:
        return "ERROR: provide exactly one of 'tokens' or 'gpu_seconds'"

    if has_tokens:
        try:
            tokens = float(args.get("tokens"))
        except (TypeError, ValueError):
            return "ERROR: tokens must be a number"
        if tokens < 0:
            return "ERROR: tokens must be non-negative"
        wh = (tokens / 1000.0) * wh_per_ktok
        basis = f"tokens={tokens:g} @ {wh_per_ktok:g} Wh/1k tokens"
    else:
        try:
            gpu_seconds = float(args.get("gpu_seconds"))
        except (TypeError, ValueError):
            return "ERROR: gpu_seconds must be a number"
        if gpu_seconds < 0:
            return "ERROR: gpu_seconds must be non-negative"
        wh = gpu_watts * (gpu_seconds / 3600.0)
        basis = f"gpu_seconds={gpu_seconds:g} @ {gpu_watts:g} W"

    co2_g = (wh / 1000.0) * grid
    return (f"OK energy={wh:.4f} Wh  co2e={co2_g:.4f} g\n"
            f"  basis: {basis}\n"
            f"  grid: {grid:g} gCO2e/kWh")


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "estimate"):
        return f"ERROR: unknown op {args.get('op')!r}"
    return _estimate(args)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["estimate"]},
        "tokens": {"type": "number", "description": "Tokens processed (use this OR gpu_seconds)"},
        "gpu_seconds": {"type": "number", "description": "GPU-seconds (use this OR tokens)"},
        "wh_per_ktok": {"type": "number", "description": "Wh per 1k tokens (default: this deployment's figure, 0.3 unless set)"},
        "gpu_watts": {"type": "number", "description": "Avg GPU watts for gpu_seconds (default 700)"},
        "grid_g_co2_per_kwh": {"type": "number", "description": "Grid intensity gCO2e/kWh (default: this deployment's figure, 400 unless set)"},
    },
}


def energy_accounting() -> Tool:
    return Tool(
        name="energy_accounting",
        description=(
            "Estimate inference energy (Wh) and operational CO2e (grams). "
            "op=estimate with exactly one of 'tokens' or 'gpu_seconds', plus "
            "optional factors: wh_per_ktok (default 0.3), gpu_watts (default "
            "700), grid_g_co2_per_kwh (default 400). Returns the numbers plus "
            "the assumptions used. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
