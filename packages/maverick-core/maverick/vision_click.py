"""Vision-grounded clicking.

Resolve "click the <description>" to screen coordinates instead of making the
model eyeball pixel positions from a screenshot:

1. **Memory first** — consult the ``gui_element_memory`` store (the same
   caller-owned list of ``{app, screen, name, selector[, bbox]}`` entries the
   tool round-trips) for a locator remembered under ``(app, screen,
   description)``. A hit costs zero model calls.
2. **Vision fallback** — ask an *injected* vision callable
   (``vision(image_bytes, description) -> {"x", "y", "confidence"}``; the
   integrator wires the actual model, tests inject fakes) and remember the
   answer in the store, so the next click on this element is a memory hit.
3. **Refuse below the floor** — a low-confidence guess raises
   :class:`LowConfidenceError` rather than clicking the wrong thing. The floor
   is ``[computer_use] vision_min_confidence`` in config.toml (default 0.5).

Coordinates are stored RAW (model space, ``selector = "point:x,y"``) and the
computer-use calibration transform (:mod:`maverick.computer_calibration`) is
applied at resolve time, so recalibrating corrects remembered elements too.
Fully offline: no screenshots, no model calls — both are injected.
"""
from __future__ import annotations

import numbers
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .computer_calibration import CalibrationTransform, load_calibration

DEFAULT_MIN_CONFIDENCE = 0.5

# How vision-resolved coordinates are encoded in a gui_element_memory selector.
_POINT_RE = re.compile(r"^point:(-?\d+),(-?\d+)$")

# vision(image_bytes, description) -> {"x": int, "y": int, "confidence": float}
VisionFn = Callable[[bytes, str], Mapping[str, Any]]


class LowConfidenceError(ValueError):
    """The vision model wasn't sure enough; refuse rather than misclick."""

    def __init__(self, confidence: float, floor: float, description: str):
        super().__init__(
            f"vision confidence {confidence:.2f} for {description!r} is below "
            f"the floor {floor:.2f}; refusing to click"
        )
        self.confidence = confidence
        self.floor = floor


@dataclass(frozen=True)
class ClickResolution:
    """Where to click, how we knew, and the updated locator store."""

    x: int  # calibrated screen coordinates
    y: int
    source: str  # "memory" | "vision"
    confidence: float
    memory: list[dict[str, Any]]  # pass back into the next resolve / persist


def min_confidence_floor() -> float:
    """The confidence floor: ``[computer_use] vision_min_confidence`` or 0.5."""
    try:
        from .config import load_config

        raw = (load_config().get("computer_use") or {}).get("vision_min_confidence")
        if raw is not None:
            return float(raw)
    except Exception:  # pragma: no cover -- config must never block
        pass
    return DEFAULT_MIN_CONFIDENCE


def _key(entry: Mapping[str, Any]) -> tuple[str, str, str]:
    # Mirrors gui_element_memory._key so the stores stay interchangeable.
    return (str(entry.get("app", "")), str(entry.get("screen", "")), str(entry.get("name", "")))


def _coords_from_entry(entry: Mapping[str, Any]) -> tuple[int, int] | None:
    """Raw coordinates from a remembered locator: bbox center, else point:x,y."""
    bbox = entry.get("bbox")
    if (
        isinstance(bbox, (list, tuple))
        and len(bbox) == 4
        and all(isinstance(v, numbers.Real) for v in bbox)
    ):
        x, y, w, h = (float(v) for v in bbox)
        return (round(x + w / 2), round(y + h / 2))
    m = _POINT_RE.match(str(entry.get("selector", "")))
    if m:
        return (int(m.group(1)), int(m.group(2)))
    return None


def _vision_coords(
    vision: VisionFn | None, image: bytes | None, description: str, floor: float
) -> tuple[int, int, float]:
    if vision is None:
        raise ValueError(
            f"no remembered locator for {description!r} and no vision fn provided"
        )
    if image is None:
        raise ValueError("vision resolution needs image bytes (a screenshot)")
    result = vision(image, description)
    if not isinstance(result, Mapping):
        raise ValueError(f"vision fn must return a mapping; got {type(result).__name__}")
    try:
        x = float(result["x"])
        y = float(result["y"])
        confidence = float(result["confidence"])
    except (KeyError, TypeError, ValueError) as e:
        raise ValueError(f"vision fn result missing/invalid x/y/confidence: {e}") from e
    if confidence < floor:
        raise LowConfidenceError(confidence, floor, description)
    return (round(x), round(y), confidence)


def resolve_click(
    description: str,
    *,
    app: str,
    screen: str,
    memory: list[dict[str, Any]] | None = None,
    image: bytes | None = None,
    vision: VisionFn | None = None,
    min_confidence: float | None = None,
    calibration: CalibrationTransform | None = None,
) -> ClickResolution:
    """Resolve a natural-language click target to screen coordinates.

    Memory hits are trusted (they passed the floor when stored) and report
    confidence 1.0. ``calibration=None`` loads the saved transform (identity
    when none is saved); pass an explicit :class:`CalibrationTransform` to
    override it.
    """
    if not description or not app or not screen:
        raise ValueError("description, app and screen are all required")
    floor = float(min_confidence) if min_confidence is not None else min_confidence_floor()
    entries = [e for e in (memory or []) if isinstance(e, dict)]

    want = (str(app), str(screen), str(description))
    raw: tuple[int, int] | None = None
    source, confidence = "memory", 1.0
    for entry in entries:
        if _key(entry) == want:
            raw = _coords_from_entry(entry)
            break

    if raw is None:
        x, y, confidence = _vision_coords(vision, image, description, floor)
        raw, source = (x, y), "vision"
        new = {
            "app": str(app),
            "screen": str(screen),
            "name": str(description),
            "selector": f"point:{x},{y}",
        }
        entries = [e for e in entries if _key(e) != want]
        entries.append(new)
        entries.sort(key=_key)

    transform = calibration if calibration is not None else load_calibration()
    cx, cy = transform.apply(*raw) if transform is not None else (raw[0], raw[1])
    return ClickResolution(x=cx, y=cy, source=source, confidence=confidence, memory=entries)


__all__ = [
    "DEFAULT_MIN_CONFIDENCE",
    "ClickResolution",
    "LowConfidenceError",
    "VisionFn",
    "min_confidence_floor",
    "resolve_click",
]
