"""Vision-grounded clicking: memory-first resolution, injected vision fallback,
confidence floor, calibration applied. Fully offline."""
from __future__ import annotations

import json

import pytest
from maverick.computer_calibration import CalibrationTransform, save_calibration
from maverick.tools.gui_element_memory import gui_element_memory
from maverick.vision_click import LowConfidenceError, resolve_click

IDENTITY = CalibrationTransform()


def _vision_stub(x, y, confidence):
    calls = {"n": 0}

    def vision(image, description):
        calls["n"] += 1
        assert isinstance(image, bytes) and description
        return {"x": x, "y": y, "confidence": confidence}

    return vision, calls


def _must_not_be_called(image, description):
    raise AssertionError("vision fn must not be consulted on a memory hit")


def test_memory_hit_skips_vision():
    memory = [{"app": "browser", "screen": "checkout", "name": "submit button",
               "selector": "point:100,200"}]
    res = resolve_click("submit button", app="browser", screen="checkout",
                        memory=memory, vision=_must_not_be_called,
                        calibration=IDENTITY)
    assert (res.x, res.y) == (100, 200)
    assert res.source == "memory"
    assert res.confidence == 1.0
    assert res.memory == memory


def test_memory_hit_uses_bbox_center():
    memory = [{"app": "ide", "screen": "editor", "name": "run",
               "selector": "#run", "bbox": [10, 20, 30, 40]}]
    res = resolve_click("run", app="ide", screen="editor", memory=memory,
                        vision=_must_not_be_called, calibration=IDENTITY)
    assert (res.x, res.y) == (25, 40)
    assert res.source == "memory"


def test_memory_keyed_by_app_and_screen():
    # Same name on a different screen must NOT hit.
    memory = [{"app": "browser", "screen": "login", "name": "submit",
               "selector": "point:1,2"}]
    vision, calls = _vision_stub(40, 50, 0.9)
    res = resolve_click("submit", app="browser", screen="checkout",
                        memory=memory, image=b"png", vision=vision,
                        calibration=IDENTITY)
    assert calls["n"] == 1
    assert (res.x, res.y) == (40, 50)


def test_vision_fallback_stores_then_hits_memory():
    vision, calls = _vision_stub(40, 50, 0.9)
    res = resolve_click("save icon", app="editor", screen="toolbar",
                        memory=[], image=b"png", vision=vision,
                        calibration=IDENTITY)
    assert res.source == "vision"
    assert res.confidence == 0.9
    assert res.memory == [{"app": "editor", "screen": "toolbar",
                           "name": "save icon", "selector": "point:40,50"}]
    # Round 2 with the returned store: memory hit, no second model call.
    res2 = resolve_click("save icon", app="editor", screen="toolbar",
                         memory=res.memory, vision=_must_not_be_called,
                         calibration=IDENTITY)
    assert calls["n"] == 1
    assert (res2.x, res2.y) == (40, 50)
    assert res2.source == "memory"


def test_store_roundtrips_through_gui_element_memory_tool():
    vision, _ = _vision_stub(40, 50, 0.9)
    res = resolve_click("save icon", app="editor", screen="toolbar",
                        image=b"png", vision=vision, calibration=IDENTITY)
    tool = gui_element_memory()
    got = tool.fn({"op": "get", "memory": res.memory, "app": "editor",
                   "screen": "toolbar", "name": "save icon"})
    assert json.loads(got)["selector"] == "point:40,50"
    # And entries put by the tool are readable here (bbox path).
    store = json.loads(tool.fn({
        "op": "put", "memory": res.memory, "app": "editor", "screen": "toolbar",
        "name": "menu", "selector": "#menu", "bbox": [0, 0, 20, 10]}))
    res2 = resolve_click("menu", app="editor", screen="toolbar", memory=store,
                         vision=_must_not_be_called, calibration=IDENTITY)
    assert (res2.x, res2.y) == (10, 5)


def test_low_confidence_refused_and_not_memorized():
    vision, _ = _vision_stub(40, 50, 0.2)
    with pytest.raises(LowConfidenceError) as exc:
        resolve_click("ghost button", app="a", screen="s",
                      image=b"png", vision=vision, calibration=IDENTITY)
    assert exc.value.confidence == 0.2
    assert exc.value.floor == 0.5  # default
    # Nothing was stored: a retry still consults vision.
    vision2, calls2 = _vision_stub(40, 50, 0.9)
    res = resolve_click("ghost button", app="a", screen="s",
                        image=b"png", vision=vision2, calibration=IDENTITY)
    assert calls2["n"] == 1 and res.source == "vision"


def test_floor_override_param_and_config(tmp_path, monkeypatch):
    vision, _ = _vision_stub(40, 50, 0.2)
    res = resolve_click("dim button", app="a", screen="s", image=b"png",
                        vision=vision, min_confidence=0.1, calibration=IDENTITY)
    assert res.confidence == 0.2
    # [computer_use] vision_min_confidence raises the floor above 0.8.
    cfg = tmp_path / "config.toml"
    cfg.write_text("[computer_use]\nvision_min_confidence = 0.9\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    vision08, _ = _vision_stub(40, 50, 0.8)
    with pytest.raises(LowConfidenceError):
        resolve_click("dim button", app="a", screen="s", image=b"png",
                      vision=vision08, calibration=IDENTITY)


def test_calibration_applied_but_memory_stores_raw():
    cal = CalibrationTransform(scale_x=2.0, scale_y=2.0, offset_x=10.0, offset_y=0.0)
    vision, _ = _vision_stub(40, 50, 0.9)
    res = resolve_click("save icon", app="e", screen="t", image=b"png",
                        vision=vision, calibration=cal)
    assert (res.x, res.y) == (90, 100)  # corrected click
    assert res.memory[0]["selector"] == "point:40,50"  # raw model space
    # Memory hits are corrected through the same transform.
    res2 = resolve_click("save icon", app="e", screen="t", memory=res.memory,
                         vision=_must_not_be_called, calibration=cal)
    assert (res2.x, res2.y) == (90, 100)


def test_saved_calibration_autoloaded(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    save_calibration(CalibrationTransform(offset_x=-10.0, offset_y=5.0))
    vision, _ = _vision_stub(110, 95, 0.9)
    res = resolve_click("ok", app="a", screen="s", image=b"png", vision=vision)
    assert (res.x, res.y) == (100, 100)


def test_no_saved_calibration_is_identity(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    vision, _ = _vision_stub(110, 95, 0.9)
    res = resolve_click("ok", app="a", screen="s", image=b"png", vision=vision)
    assert (res.x, res.y) == (110, 95)


def test_missing_vision_or_image_raises():
    with pytest.raises(ValueError, match="no vision fn"):
        resolve_click("x", app="a", screen="s", calibration=IDENTITY)
    vision, _ = _vision_stub(1, 2, 0.9)
    with pytest.raises(ValueError, match="image bytes"):
        resolve_click("x", app="a", screen="s", vision=vision, calibration=IDENTITY)


def test_invalid_vision_results_raise():
    for bad in ("not a mapping", {"x": 1, "y": 2}, {"x": "a", "y": 2, "confidence": 1}):
        with pytest.raises(ValueError):
            resolve_click("x", app="a", screen="s", image=b"png",
                          vision=lambda image, description, bad=bad: bad,
                          calibration=IDENTITY)


def test_required_fields_validated():
    for kwargs in ({"app": "", "screen": "s"}, {"app": "a", "screen": ""}):
        with pytest.raises(ValueError):
            resolve_click("x", calibration=IDENTITY, **kwargs)
    with pytest.raises(ValueError):
        resolve_click("", app="a", screen="s", calibration=IDENTITY)
