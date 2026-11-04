"""Computer-use coordinate calibration.

Vision models emit click coordinates in *their* view of the screen — a
screenshot that may be DPI-scaled (Retina/HiDPI), resized for the model, or
offset relative to the physical display. When model space and screen space
disagree, every click lands a little off and computer-use sessions degrade
into retry loops.

Calibration corrects this: show the operator (or the agent itself) a deterministic grid
of known targets (:func:`calibration_targets`), record where each click was
*expected* to land (the target's true screen position) versus what the model
*observed*/emitted, and fit a per-axis affine transform

    screen_x = scale_x * model_x + offset_x
    screen_y = scale_y * model_y + offset_y

by least squares (:func:`fit_calibration` — pure math, no deps, no screen).
:meth:`CalibrationTransform.apply` then corrects every subsequent click.
:func:`residual_report` measures how well the transform explains the pairs so
drift (a moved window server, changed scaling, new monitor) is detectable.

Persistence is injected: :func:`save_calibration` / :func:`load_calibration`
default to ``data_dir("computer_calibration.json")`` (atomic write, 0600) but
accept any path. Loading is fail-open — no file or a corrupt file means "no
calibration", never a crash.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .paths import data_dir

log = logging.getLogger(__name__)

# A point pair: (expected, observed) — where the click SHOULD land on screen
# vs. the coordinate the model emitted for it.
Point = tuple[float, float]
PointPair = tuple[Point, Point]

CALIBRATION_BASENAME = "computer_calibration.json"

# Max acceptable residual (px) before we call the calibration drifted.
DEFAULT_DRIFT_THRESHOLD = 5.0


@dataclass(frozen=True)
class CalibrationTransform:
    """Affine model->screen correction: per-axis scale + offset."""

    scale_x: float = 1.0
    scale_y: float = 1.0
    offset_x: float = 0.0
    offset_y: float = 0.0

    def apply(self, x: float, y: float) -> tuple[int, int]:
        """Map a model-space coordinate to the screen-space pixel to click."""
        return (
            round(self.scale_x * x + self.offset_x),
            round(self.scale_y * y + self.offset_y),
        )


def _fit_axis(observed: list[float], expected: list[float]) -> tuple[float, float]:
    """Least-squares fit of ``expected = scale * observed + offset`` for one axis.

    A degenerate axis (all observed values identical — e.g. targets in one
    column) cannot determine a scale; fall back to scale 1 + mean offset.
    """
    n = len(observed)
    mean_o = sum(observed) / n
    mean_e = sum(expected) / n
    var = sum((o - mean_o) ** 2 for o in observed)
    if var < 1e-9:
        return 1.0, mean_e - mean_o
    cov = sum((o - mean_o) * (e - mean_e) for o, e in zip(observed, expected, strict=False))
    scale = cov / var
    return scale, mean_e - scale * mean_o


def fit_calibration(pairs: Sequence[PointPair]) -> CalibrationTransform:
    """Fit the affine transform from ``(expected, observed)`` point pairs.

    ``expected`` is the true screen position of a known target; ``observed``
    is the coordinate the model emitted when asked to click it. Requires at
    least two pairs (one point can only determine an offset ambiguously).
    """
    if len(pairs) < 2:
        raise ValueError(f"need at least 2 point pairs to calibrate; got {len(pairs)}")
    expected = [(float(e[0]), float(e[1])) for e, _ in pairs]
    observed = [(float(o[0]), float(o[1])) for _, o in pairs]
    scale_x, offset_x = _fit_axis([o[0] for o in observed], [e[0] for e in expected])
    scale_y, offset_y = _fit_axis([o[1] for o in observed], [e[1] for e in expected])
    return CalibrationTransform(
        scale_x=scale_x, scale_y=scale_y, offset_x=offset_x, offset_y=offset_y
    )


@dataclass(frozen=True)
class DriftReport:
    """Residual errors of a transform over a set of point pairs."""

    residuals: tuple[float, ...]  # per-pair euclidean error, px
    mean_error: float
    max_error: float
    rmse: float

    def drifted(self, threshold: float = DEFAULT_DRIFT_THRESHOLD) -> bool:
        """True when any pair misses by more than ``threshold`` px."""
        return self.max_error > threshold


def residual_report(
    pairs: Sequence[PointPair], transform: CalibrationTransform
) -> DriftReport:
    """How far ``transform`` misses each pair — the drift-detection signal.

    Re-run the calibration targets later, feed the fresh pairs through the
    *stored* transform: a report that ``drifted()`` means scaling/layout
    changed and the operator should recalibrate.
    """
    if not pairs:
        raise ValueError("need at least 1 point pair for a residual report")
    residuals: list[float] = []
    for (ex, ey), (ox, oy) in pairs:
        px, py = transform.apply(float(ox), float(oy))
        residuals.append(((px - float(ex)) ** 2 + (py - float(ey)) ** 2) ** 0.5)
    n = len(residuals)
    return DriftReport(
        residuals=tuple(residuals),
        mean_error=sum(residuals) / n,
        max_error=max(residuals),
        rmse=(sum(r * r for r in residuals) / n) ** 0.5,
    )


def calibration_targets(
    width: int,
    height: int,
    *,
    rows: int = 3,
    cols: int = 3,
    margin_frac: float = 0.1,
) -> list[tuple[int, int]]:
    """Deterministic grid of on-screen target points for the operator to click.

    Points are inset by ``margin_frac`` of each dimension (clicks at the very
    edge get clamped by the OS and would poison the fit) and returned in
    row-major order, so the same (width, height, rows, cols) always produces
    the same sequence.
    """
    if width <= 0 or height <= 0:
        raise ValueError(f"screen size must be positive; got {width}x{height}")
    if rows < 2 or cols < 2:
        raise ValueError("need at least a 2x2 target grid to determine scale")
    if not 0 <= margin_frac < 0.5:
        raise ValueError(f"margin_frac must be in [0, 0.5); got {margin_frac}")
    x0 = width * margin_frac
    y0 = height * margin_frac
    x_span = width * (1 - 2 * margin_frac)
    y_span = height * (1 - 2 * margin_frac)
    return [
        (round(x0 + x_span * c / (cols - 1)), round(y0 + y_span * r / (rows - 1)))
        for r in range(rows)
        for c in range(cols)
    ]


def _default_path() -> Path:
    return data_dir(CALIBRATION_BASENAME)


def save_calibration(transform: CalibrationTransform, path: Path | None = None) -> Path:
    """Persist ``transform`` atomically with owner-only file permissions."""
    p = Path(path) if path is not None else _default_path()
    payload = {
        "scale_x": transform.scale_x,
        "scale_y": transform.scale_y,
        "offset_x": transform.offset_x,
        "offset_y": transform.offset_y,
    }
    from .file_lock import atomic_write_text, ensure_private_directory

    if path is None:
        ensure_private_directory(p.parent)
    atomic_write_text(p, json.dumps(payload))
    return p


def load_calibration(path: Path | None = None) -> CalibrationTransform | None:
    """Load the saved transform, or ``None`` (fail-open) if absent/corrupt."""
    p = path if path is not None else _default_path()
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        return CalibrationTransform(
            scale_x=float(raw["scale_x"]),
            scale_y=float(raw["scale_y"]),
            offset_x=float(raw["offset_x"]),
            offset_y=float(raw["offset_y"]),
        )
    except FileNotFoundError:
        return None
    except (OSError, ValueError, TypeError, KeyError) as e:
        log.warning("ignoring unreadable calibration %s (%s); clicks uncorrected", p, e)
        return None


def apply_saved(x: float, y: float, *, path: Path | None = None) -> tuple[int, int]:
    """Correct one click through the saved calibration; identity when none saved."""
    t = load_calibration(path)
    if t is None:
        return (round(x), round(y))
    return t.apply(x, y)


__all__ = [
    "CalibrationTransform",
    "DriftReport",
    "DEFAULT_DRIFT_THRESHOLD",
    "CALIBRATION_BASENAME",
    "fit_calibration",
    "residual_report",
    "calibration_targets",
    "save_calibration",
    "load_calibration",
    "apply_saved",
]
