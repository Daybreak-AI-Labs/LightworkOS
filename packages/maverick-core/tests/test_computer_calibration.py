"""Computer-use coordinate calibration: pure-math affine fit, drift report,
target grid, atomic 0600 persistence. No screen needed."""
from __future__ import annotations

import os
import subprocess

import pytest
from maverick.computer_calibration import (
    CalibrationTransform,
    apply_saved,
    calibration_targets,
    fit_calibration,
    load_calibration,
    residual_report,
    save_calibration,
)
from maverick.file_lock import private_path_is_restricted


def _make_shared_directory(path):
    path.mkdir(mode=0o777)
    if os.name == "nt":
        subprocess.run(
            ["icacls", str(path), "/grant", "*S-1-1-0:(OI)(CI)RX"],
            check=True,
            capture_output=True,
            text=True,
        )
    else:
        path.chmod(0o755)
    assert not private_path_is_restricted(path, 0o700)


def _security_snapshot(path):
    if os.name == "nt":
        import maverick.file_lock as file_lock

        return file_lock._windows_private_sddl(path)[0]
    return path.stat().st_mode & 0o777


def _pairs(transform_to_model, targets):
    """Build (expected, observed) pairs: model space distorts screen space."""
    return [(t, transform_to_model(t)) for t in targets]


def test_fit_identity_when_spaces_agree():
    pairs = _pairs(lambda p: p, [(100, 100), (500, 300), (900, 700)])
    t = fit_calibration(pairs)
    assert t.scale_x == pytest.approx(1.0)
    assert t.scale_y == pytest.approx(1.0)
    assert t.offset_x == pytest.approx(0.0)
    assert t.offset_y == pytest.approx(0.0)
    assert t.apply(123, 456) == (123, 456)


def test_fit_pure_offset():
    # Model coordinates land 10px right / 5px above the true targets.
    pairs = _pairs(lambda p: (p[0] + 10, p[1] - 5), [(100, 100), (800, 600)])
    t = fit_calibration(pairs)
    # Correcting a model click must land on the expected screen point.
    assert t.apply(110, 95) == (100, 100)
    assert t.apply(810, 595) == (800, 600)


def test_fit_scale_and_offset():
    # Screen is 2x the model's view plus a (100, -50) shift:
    # model = (screen - offset) / scale.
    def to_model(p):
        return ((p[0] - 100) / 2.0, (p[1] + 50) / 1.5)

    targets = [(192, 108), (960, 540), (1728, 972), (192, 972)]
    t = fit_calibration(_pairs(to_model, targets))
    assert t.scale_x == pytest.approx(2.0)
    assert t.scale_y == pytest.approx(1.5)
    assert t.offset_x == pytest.approx(100.0)
    assert t.offset_y == pytest.approx(-50.0)
    for target in targets:
        assert t.apply(*to_model(target)) == target


def test_fit_requires_two_pairs():
    with pytest.raises(ValueError):
        fit_calibration([])
    with pytest.raises(ValueError):
        fit_calibration([((1, 1), (1, 1))])


def test_fit_degenerate_axis_falls_back_to_offset():
    # All targets in one column: x scale is indeterminate -> scale 1 + offset.
    pairs = [((100, 100), (110, 90)), ((100, 500), (110, 490))]
    t = fit_calibration(pairs)
    assert t.scale_x == pytest.approx(1.0)
    assert t.offset_x == pytest.approx(-10.0)
    assert t.apply(110, 90) == (100, 100)


def test_apply_returns_ints():
    t = CalibrationTransform(scale_x=1.1, scale_y=0.9, offset_x=0.4, offset_y=-0.4)
    x, y = t.apply(100, 100)
    assert isinstance(x, int) and isinstance(y, int)
    assert (x, y) == (110, 90)


def test_residual_report_perfect_fit_no_drift():
    pairs = _pairs(lambda p: (p[0] + 7, p[1] + 7), [(100, 100), (500, 500)])
    t = fit_calibration(pairs)
    report = residual_report(pairs, t)
    assert report.max_error == pytest.approx(0.0)
    assert report.mean_error == pytest.approx(0.0)
    assert report.rmse == pytest.approx(0.0)
    assert not report.drifted()


def test_residual_report_detects_drift():
    t = CalibrationTransform()  # identity, but the screen has shifted 20px
    pairs = [((100, 100), (120, 100)), ((500, 500), (520, 500))]
    report = residual_report(pairs, t)
    assert report.max_error == pytest.approx(20.0)
    assert len(report.residuals) == 2
    assert report.drifted()  # default 5px threshold
    assert not report.drifted(threshold=25.0)
    with pytest.raises(ValueError):
        residual_report([], t)


def test_calibration_targets_deterministic_grid():
    pts = calibration_targets(1920, 1080)
    assert pts == calibration_targets(1920, 1080)  # deterministic
    assert len(pts) == 9
    assert pts[0] == (192, 108)  # 10% margin inset
    assert pts[-1] == (1728, 972)
    assert pts[4] == (960, 540)  # center of a 3x3 grid
    for x, y in pts:
        assert 0 < x < 1920 and 0 < y < 1080


def test_calibration_targets_custom_grid_and_validation():
    pts = calibration_targets(1000, 1000, rows=2, cols=4, margin_frac=0.0)
    assert len(pts) == 8
    assert pts[0] == (0, 0) and pts[-1] == (1000, 1000)
    with pytest.raises(ValueError):
        calibration_targets(0, 1080)
    with pytest.raises(ValueError):
        calibration_targets(1920, 1080, rows=1)
    with pytest.raises(ValueError):
        calibration_targets(1920, 1080, margin_frac=0.5)


def test_save_load_roundtrip_atomic_0600(tmp_path):
    t = CalibrationTransform(scale_x=2.0, scale_y=1.5, offset_x=100.0, offset_y=-50.0)
    path = tmp_path / "deep" / "calibration.json"
    saved_to = save_calibration(t, path)
    assert saved_to == path
    assert load_calibration(path) == t
    assert private_path_is_restricted(path)
    assert private_path_is_restricted(path.parent, 0o700)
    assert list(tmp_path.rglob("*.tmp")) == []  # no temp-file litter


def test_injected_calibration_path_preserves_shared_parent_access(tmp_path):
    shared = tmp_path / "shared"
    _make_shared_directory(shared)
    unrelated = shared / "team-report.txt"
    unrelated.write_text("still shared", encoding="utf-8")
    before = _security_snapshot(shared)

    path = shared / "calibration.json"
    save_calibration(CalibrationTransform(offset_x=4.0), path)

    assert _security_snapshot(shared) == before
    assert not private_path_is_restricted(shared, 0o700)
    assert unrelated.read_text(encoding="utf-8") == "still shared"
    assert private_path_is_restricted(path)


def test_load_missing_or_corrupt_fails_open(tmp_path):
    assert load_calibration(tmp_path / "nope.json") is None
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert load_calibration(bad) is None


def test_default_path_under_maverick_home(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    t = CalibrationTransform(offset_x=10.0, offset_y=-5.0)
    saved_to = save_calibration(t)
    assert saved_to == tmp_path / "computer_calibration.json"
    assert load_calibration() == t


def test_apply_saved_corrects_or_passes_through(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    assert apply_saved(110, 95) == (110, 95)  # nothing saved: identity
    save_calibration(CalibrationTransform(offset_x=-10.0, offset_y=5.0))
    assert apply_saved(110, 95) == (100, 100)
