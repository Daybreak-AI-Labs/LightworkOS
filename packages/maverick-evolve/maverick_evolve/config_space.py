"""The mutable configuration space for config-only evolution.

Defines which Lightwork knobs an evolution run is allowed to perturb -- and ONLY
configuration (workflow params, thresholds, counts), never code, so a candidate
can't escape the sandbox. Each knob has explicit bounds; ``mutate`` perturbs one
knob at a time within those bounds, which keeps the search local and the diffs
auditable.

The default space targets the loop knobs added this cycle (fan-out width,
adaptive-compute threshold, best-of-N count, verifier accept floor, autonomy
disagreement threshold). Callers can pass their own ``space`` to widen/narrow it.
"""
from __future__ import annotations

import random

# knob -> spec. Specs: ("int", lo, hi) | ("float", lo, hi, step).
SPACE: dict[str, tuple] = {
    "max_swarm_fanout": ("int", 1, 16),
    "adaptive_compute.low_uncertainty": ("float", 0.05, 0.5, 0.05),
    "search.n": ("int", 1, 5),
    "verifier_confidence": ("float", 0.5, 0.95, 0.05),
    "autonomy.disagreement_high": ("float", 0.3, 0.8, 0.05),
}


def default_config(space: dict[str, tuple] | None = None) -> dict:
    """A neutral starting config: the midpoint of each knob's range."""
    space = space or SPACE
    cfg: dict = {}
    for knob, spec in space.items():
        if spec[0] == "int":
            _, lo, hi = spec
            cfg[knob] = (lo + hi) // 2
        else:
            _, lo, hi, _step = spec
            cfg[knob] = round((lo + hi) / 2, 4)
    return cfg


def _clamp(v, lo, hi):
    return max(lo, min(hi, v))


def mutate(config: dict, rng: random.Random | None = None,
           space: dict[str, tuple] | None = None) -> dict:
    """Return a copy of ``config`` with exactly one in-bounds knob perturbed.

    Ints step by ±1; floats step by ±the knob's step. Values are clamped to the
    knob's range, so a mutation can never produce an out-of-bounds config.
    Unknown knobs already in ``config`` are preserved untouched.
    """
    rng = rng or random.Random()
    space = space or SPACE
    out = dict(config)
    knob = rng.choice(list(space.keys()))
    spec = space[knob]
    cur = out.get(knob)
    if spec[0] == "int":
        _, lo, hi = spec
        base = cur if isinstance(cur, int) else (lo + hi) // 2
        out[knob] = _clamp(base + rng.choice([-1, 1]), lo, hi)
    else:
        _, lo, hi, step = spec
        base = cur if isinstance(cur, (int, float)) else (lo + hi) / 2
        out[knob] = round(_clamp(base + rng.choice([-step, step]), lo, hi), 4)
    return out


def in_bounds(config: dict, space: dict[str, tuple] | None = None) -> bool:
    """True iff every known knob in ``config`` is within its declared range."""
    space = space or SPACE
    for knob, spec in space.items():
        if knob not in config:
            continue
        v = config[knob]
        lo, hi = (spec[1], spec[2])
        if not (lo <= v <= hi):
            return False
    return True


def clamp_config(config: dict, space: dict[str, tuple] | None = None) -> dict:
    """Return a copy of ``config`` with every KNOWN knob clamped into range.

    Defense in depth for the resume-from-archive path: ``mutate`` clamps, but a
    hand-edited or legacy archive entry (or a swapped ``space``) can carry an
    out-of-bounds value straight through sampling into the run sinks
    (``env_for``/``overlay_for``). ``max_swarm_fanout`` maps to
    ``MAVERICK_MAX_SWARM_FANOUT``, the kernel's fan-out anomaly cap, so an
    out-of-bounds evolve config must never raise a safety limit on a live run.
    Unknown / non-numeric knobs pass through untouched.
    """
    space = space or SPACE
    out = dict(config)
    for knob, spec in space.items():
        if knob not in out:
            continue
        lo, hi = spec[1], spec[2]
        try:
            if spec[0] == "int":
                out[knob] = _clamp(int(out[knob]), lo, hi)
            else:
                out[knob] = round(_clamp(float(out[knob]), lo, hi), 4)
        except (TypeError, ValueError):
            continue  # non-numeric junk -> leave for the caller to reject
    return out


__all__ = ["SPACE", "default_config", "mutate", "in_bounds", "clamp_config"]
