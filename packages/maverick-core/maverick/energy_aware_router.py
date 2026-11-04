"""Energy-aware routing: downgrade to a cheaper model on low battery.

On a laptop running on battery, a long agent run can drain the pack; when the
charge is low this picks a cheaper/faster model (e.g. Sonnet over Opus) to extend
runtime, then reverts on wall power. Opt-in (``[routing] energy_aware`` /
``MAVERICK_ENERGY_AWARE=1``); default OFF so behavior is unchanged. ``should_downgrade``
/ ``pick_model`` are pure decisions (unit-tested); ``battery_state`` reads the OS
via the optional ``psutil`` dep and returns ``None`` when it's unavailable
(desktop / no psutil), in which case routing is a no-op.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

_DEFAULT_THRESHOLD = 20  # percent


def _env_true(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def enabled() -> bool:
    if _env_true("MAVERICK_ENERGY_AWARE"):
        return True
    try:
        from .config import load_config
        return bool((load_config() or {}).get("routing", {}).get("energy_aware", False))
    except Exception:  # pragma: no cover
        return False


@dataclass(frozen=True)
class BatteryState:
    on_battery: bool
    percent: float | None


def battery_state() -> BatteryState | None:
    """Current battery state via psutil, or ``None`` if unavailable."""
    try:
        import psutil
    except ImportError:
        return None
    try:
        b = psutil.sensors_battery()
    except Exception:  # pragma: no cover -- platform quirks
        return None
    if b is None:
        return None
    return BatteryState(on_battery=not b.power_plugged, percent=float(b.percent))


def should_downgrade(state: BatteryState | None, *, threshold: int = _DEFAULT_THRESHOLD) -> bool:
    """True iff on battery and charge is at/below ``threshold`` percent."""
    if state is None or not state.on_battery or state.percent is None:
        return False
    return state.percent <= threshold


def pick_model(default_model: str, cheaper_model: str, *,
               state: BatteryState | None,
               threshold: int = _DEFAULT_THRESHOLD) -> str:
    """Return ``cheaper_model`` when low on battery, else ``default_model``."""
    return cheaper_model if should_downgrade(state, threshold=threshold) else default_model


def route(default_model: str, cheaper_model: str) -> str:
    """Convenience: read live battery + config and pick a model. No-op when the
    feature is off or battery state is unavailable."""
    if not enabled():
        return default_model
    try:
        from .config import load_config
        thr = int((load_config() or {}).get("routing", {}).get(
            "battery_threshold_pct", _DEFAULT_THRESHOLD))
    except Exception:  # pragma: no cover
        thr = _DEFAULT_THRESHOLD
    return pick_model(default_model, cheaper_model, state=battery_state(), threshold=thr)


__all__ = [
    "BatteryState", "battery_state", "should_downgrade", "pick_model", "route",
    "enabled",
]
