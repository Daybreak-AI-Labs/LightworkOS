"""Tests for the ffmpeg tool (maverick.tools.ffmpeg_tool)."""
from __future__ import annotations

# ---------- ffmpeg ----------

def test_ffmpeg_requires_op():
    from maverick.tools.ffmpeg_tool import ffmpeg_tool
    assert "op is required" in ffmpeg_tool().fn({})


def test_ffmpeg_missing(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda b: None)
    from maverick.tools.ffmpeg_tool import ffmpeg_tool
    out = ffmpeg_tool().fn({"op": "convert",
                              "input_path": "/tmp/a.mp4",
                              "output_path": "/tmp/b.mp4"})
    assert "ffmpeg" in out and "PATH" in out


def test_ffmpeg_convert_calls_binary(monkeypatch, tmp_path):
    monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/" + b)
    captured = {"cmd": None}

    def _run(sandbox, cmd, *a, **k):
        captured["cmd"] = cmd
        return 0, "", ""

    import importlib
    from types import SimpleNamespace
    module = importlib.import_module("maverick.tools.ffmpeg_tool")
    monkeypatch.setattr(module, "_run_cmd", _run)
    out = module.ffmpeg_tool(SimpleNamespace(workdir=tmp_path)).fn({
        "op": "convert", "input_path": "a.mp4",
        "output_path": "b.mp4",
    })
    assert "wrote " in out and "b.mp4" in out
    assert "ffmpeg" in captured["cmd"]


def test_ffmpeg_info_parses_ffprobe(monkeypatch, tmp_path):
    monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/" + b)
    import importlib
    import json
    from types import SimpleNamespace
    module = importlib.import_module("maverick.tools.ffmpeg_tool")
    output = json.dumps({
        "format": {"format_name": "mov,mp4", "duration": "10.0", "bit_rate": "1000"},
        "streams": [{"codec_type": "video", "codec_name": "h264", "width": 1920, "height": 1080}],
    })
    monkeypatch.setattr(module, "_run_cmd", lambda *a, **kw: (0, output, ""))
    out = module.ffmpeg_tool(SimpleNamespace(workdir=tmp_path)).fn({"op": "info", "input_path": "a.mp4"})
    assert "mov,mp4" in out and "1920x1080" in out
