"""Adaptive test-time compute: spend where the swarm is uncertain.

SOTA (arXiv 2602.01070): concentrate inference compute on high-uncertainty,
high-utility trajectories instead of scaling it uniformly. Lightwork already
*produces* the uncertainty signals (swarm disagreement entropy, verifier
confidence, PRM progress) but nothing spends on them. This module turns those
signals into a compute plan: shrink fan-out / search depth when the run is
confident, keep it full when uncertain.

Conservative by construction: it only ever *narrows* the existing safety caps
(``spawn._fanout_cap_for_depth``), never widens them, so concentrating compute
can't breach the fan-out / budget guards. Off by default + fail-open
(``[adaptive_compute] enable`` / ``MAVERICK_ADAPTIVE_COMPUTE=1``).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from .config import env_flag

log = logging.getLogger(__name__)

_DEFAULTS = {"enable": False, "low_uncertainty": 0.2, "min_width": 1}


def _settings() -> dict:
    try:
        from .config import get_adaptive_compute
        return get_adaptive_compute()
    except Exception:  # pragma: no cover -- config never blocks a run
        return dict(_DEFAULTS)


def enabled() -> bool:
    _v = env_flag("MAVERICK_ADAPTIVE_COMPUTE")
    if _v is not None:
        return _v
    return bool(_settings()["enable"])


@dataclass
class ComputePlan:
    width: int
    reason: str = ""


def _uncertainty(disagreement: float, verifier_confidence: float) -> float:
    """Combine signals into a [0,1] uncertainty estimate.

    High disagreement OR low verifier confidence => high uncertainty. We take
    the max so either signal alone can keep compute high (conservative).
    """
    d = max(0.0, min(1.0, float(disagreement or 0.0)))
    c = max(0.0, min(1.0, float(verifier_confidence)))
    return max(d, 1.0 - c)


def adjust_width(
    base_width: int,
    *,
    disagreement: float,
    verifier_confidence: float = 1.0,
    settings: dict | None = None,
) -> ComputePlan:
    """Return a (possibly reduced) fan-out width given run uncertainty.

    When uncertainty is low, scale the width down toward ``min_width`` (spend
    less on easy sub-problems); when high, keep the full safety cap. Never
    exceeds ``base_width``. Returns ``base_width`` unchanged when disabled.
    """
    s = settings if settings is not None else _settings()
    if not s["enable"] or base_width <= s["min_width"]:
        return ComputePlan(base_width)
    u = _uncertainty(disagreement, verifier_confidence)
    if u >= s["low_uncertainty"]:
        return ComputePlan(base_width, reason=f"uncertainty {u:.2f}: full width")
    # Confident: scale width down linearly toward min_width.
    scaled = round(s["min_width"] + (base_width - s["min_width"]) * (u / s["low_uncertainty"]))
    width = max(s["min_width"], min(base_width, int(scaled)))
    return ComputePlan(width, reason=f"low uncertainty {u:.2f}: width {base_width}->{width}")


__all__ = ["enabled", "ComputePlan", "adjust_width"]
