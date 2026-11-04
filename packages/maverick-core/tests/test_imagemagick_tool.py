"""Tests for the ImageMagick tool (maverick.tools.imagemagick_tool)."""
from __future__ import annotations

# ---------- ImageMagick ----------

def test_imagemagick_requires_op():
    from maverick.tools.imagemagick_tool import imagemagick_tool
    assert "op is required" in imagemagick_tool().fn({})


def test_imagemagick_missing(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda b: None)
    from maverick.tools.imagemagick_tool import imagemagick_tool
    out = imagemagick_tool().fn({"op": "resize",
                                   "input_path": "a.png",
                                   "output_path": "b.png"})
    assert "ImageMagick" in out


def test_imagemagick_resize(monkeypatch, tmp_path):
    monkeypatch.setattr("shutil.which",
                        lambda b: "/usr/bin/magick" if b == "magick" else None)
    import importlib
    from types import SimpleNamespace
    module = importlib.import_module("maverick.tools.imagemagick_tool")
    monkeypatch.setattr(module, "_run_cmd", lambda *a, **kw: (0, "", ""))
    out = module.imagemagick_tool(SimpleNamespace(workdir=tmp_path)).fn({
        "op": "resize", "input_path": "a.png",
        "output_path": "b.png", "width": 800,
    })
    assert "wrote " in out and "b.png" in out and "800" in out


def test_imagemagick_identify_parses(monkeypatch, tmp_path):
    monkeypatch.setattr("shutil.which",
                        lambda b: "/usr/bin/magick" if b == "magick" else None)
    import importlib
    from types import SimpleNamespace
    module = importlib.import_module("maverick.tools.imagemagick_tool")
    monkeypatch.setattr(module, "_run_cmd", lambda *a, **kw: (0, "1024 768 PNG 200KB image.png\n", ""))
    out = module.imagemagick_tool(SimpleNamespace(workdir=tmp_path)).fn({"op": "identify", "input_path": "a.png"})
    assert "1024x768" in out and "PNG" in out
