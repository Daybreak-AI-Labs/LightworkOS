"""Tests for the view_video tool (maverick.tools.view_video)."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import maverick.tools.view_video as vv
from maverick.tools.view_video import _evenly_spaced, view_video

# ---------- mocked end-to-end dispatch ----------

class _FakeResp:
    def __init__(self, text):
        self.text = text


class _FakeLLM:
    last_messages = None
    last_model = None

    def __init__(self, model=None):
        _FakeLLM.last_model = model

    last_budget = None

    def complete(self, system, messages, max_tokens, budget=None):
        _FakeLLM.last_messages = messages
        _FakeLLM.last_budget = budget
        return _FakeResp("a cat plays the piano, then jumps down")


def _prep(monkeypatch, tmp_path, *, frames):
    vid = tmp_path / "v.mp4"
    vid.write_bytes(b"\x00")
    monkeypatch.setattr(vv, "_need", lambda b: None)
    monkeypatch.setattr(vv, "_probe_duration", lambda src, sandbox: 12.0)
    monkeypatch.setattr(vv, "_extract_frames", lambda src, ts, tmp, sandbox: frames)
    monkeypatch.setattr("maverick.llm.LLM", _FakeLLM)
    return vid


# ---------- pure helpers ----------

def test_evenly_spaced_midpoints():
    ts = _evenly_spaced(10.0, 4)
    assert ts == [1.25, 3.75, 6.25, 8.75]
    assert all(0 < t < 10 for t in ts)
    assert ts == sorted(ts)


# ---------- input validation (no ffmpeg / no mocking needed) ----------

def test_view_video_rejects_empty_source():
    assert "source is required" in view_video().fn({"source": ""}).lower()


def test_view_video_missing_ffmpeg(monkeypatch):
    monkeypatch.setattr(vv, "_need", lambda b: f"ERROR: {b} not on PATH. Install ffmpeg.")
    out = view_video().fn({"source": "clip.mp4"})
    assert out.startswith("ERROR") and "ffmpeg" in out


def test_view_video_missing_file(monkeypatch, tmp_path):
    monkeypatch.setattr(vv, "_need", lambda b: None)
    out = view_video(sandbox=SimpleNamespace(workdir=tmp_path)).fn({"source": str(tmp_path / "missing.mp4")})
    assert "video file not found" in out.lower()


def test_view_video_probe_failure(monkeypatch, tmp_path):
    vid = tmp_path / "v.mp4"
    vid.write_bytes(b"\x00")
    monkeypatch.setattr(vv, "_need", lambda b: None)
    monkeypatch.setattr(vv, "_probe_duration", lambda src, sandbox: None)
    out = view_video(sandbox=SimpleNamespace(workdir=tmp_path)).fn({"source": str(vid)})
    assert "could not probe video duration" in out.lower()


def test_view_video_no_frames_extracted(monkeypatch, tmp_path):
    vid = tmp_path / "v.mp4"
    vid.write_bytes(b"\x00")
    monkeypatch.setattr(vv, "_need", lambda b: None)
    monkeypatch.setattr(vv, "_probe_duration", lambda src, sandbox: 10.0)
    monkeypatch.setattr(vv, "_extract_frames", lambda src, ts, tmp, sandbox: [])
    out = view_video(sandbox=SimpleNamespace(workdir=tmp_path)).fn({"source": str(vid)})
    assert "extracted no frames" in out.lower()


def test_view_video_full_flow_builds_vision_blocks(monkeypatch, tmp_path):
    frames = [(2.0, b"\xff\xd8a"), (6.0, b"\xff\xd8b"), (10.0, b"\xff\xd8c")]
    vid = _prep(monkeypatch, tmp_path, frames=frames)
    out = view_video(sandbox=SimpleNamespace(workdir=tmp_path)).fn({"source": str(vid), "prompt": "What instrument?"})
    assert out == "a cat plays the piano, then jumps down"

    content = _FakeLLM.last_messages[0]["content"]
    images = [b for b in content if b.get("type") == "image"]
    texts = [b["text"] for b in content if b.get("type") == "text"]
    assert len(images) == 3
    assert images[0]["source"]["media_type"] == "image/jpeg"
    assert any("frame at" in t for t in texts)
    # The prompt is the trailing text block.
    assert content[-1] == {"type": "text", "text": "What instrument?"}


def test_view_video_passes_bound_budget_to_vision_call(monkeypatch, tmp_path):
    from maverick.budget import Budget

    budget = Budget(max_dollars=1.0)
    frames = [(2.0, b"\xff\xd8a")]
    vid = _prep(monkeypatch, tmp_path, frames=frames)

    out = view_video(sandbox=SimpleNamespace(workdir=tmp_path), budget=budget).fn({"source": str(vid)})

    assert out == "a cat plays the piano, then jumps down"
    assert _FakeLLM.last_budget is budget


def test_view_video_clamps_num_frames(monkeypatch, tmp_path):
    seen: dict[str, int] = {}

    def _capture(src, ts, tmp, sandbox):
        seen["n"] = len(ts)
        return [(float(i), b"\xff\xd8x") for i in range(len(ts))]

    vid = tmp_path / "v.mp4"
    vid.write_bytes(b"\x00")
    monkeypatch.setattr(vv, "_need", lambda b: None)
    monkeypatch.setattr(vv, "_probe_duration", lambda src, sandbox: 60.0)
    monkeypatch.setattr(vv, "_extract_frames", _capture)
    monkeypatch.setattr("maverick.llm.LLM", _FakeLLM)
    view_video(sandbox=SimpleNamespace(workdir=tmp_path)).fn({"source": str(vid), "num_frames": 100})
    assert seen["n"] == 20  # capped at _MAX_FRAMES


def test_view_video_includes_transcript_when_requested(monkeypatch, tmp_path):
    frames = [(3.0, b"\xff\xd8a")]
    vid = _prep(monkeypatch, tmp_path, frames=frames)
    monkeypatch.setattr(vv, "_transcribe_track", lambda src, tmp, sandbox: "hello from the clip")
    view_video(sandbox=SimpleNamespace(workdir=tmp_path)).fn({"source": str(vid), "transcribe": True})
    texts = [b["text"] for b in _FakeLLM.last_messages[0]["content"]
             if b.get("type") == "text"]
    assert any("hello from the clip" in t for t in texts)


def test_view_video_skips_transcript_by_default(monkeypatch, tmp_path):
    frames = [(3.0, b"\xff\xd8a")]
    vid = _prep(monkeypatch, tmp_path, frames=frames)

    def _boom(src, tmp, sandbox):
        raise AssertionError("_transcribe_track must not run when transcribe is false")

    monkeypatch.setattr(vv, "_transcribe_track", _boom)
    out = view_video(sandbox=SimpleNamespace(workdir=tmp_path)).fn({"source": str(vid)})
    assert out == "a cat plays the piano, then jumps down"


def test_view_video_schema_requires_source():
    tool = view_video()
    assert tool.input_schema["required"] == ["source"]
    assert "num_frames" in tool.input_schema["properties"]


def test_view_video_passes_sandbox_to_run_cmd(monkeypatch, tmp_path):
    # Regression: _probe_duration/_extract_frames/_transcribe_track must call
    # _run_cmd(sandbox, cmd, ...). The previous broken arity bound the argv list
    # to `sandbox`, leaving `cmd` unfilled, and raised TypeError on every call.
    # The other tests mock the three helpers, so they never exercised this path.
    vid = tmp_path / "v.mp4"
    vid.write_bytes(b"\x00")

    def _fake_run_cmd(sandbox, cmd, *, timeout=600.0):
        assert isinstance(cmd, list)  # sandbox first, cmd second
        if cmd and cmd[0] == "ffprobe":
            return (0, "5.0", "")
        if "image2" in cmd:  # frame extraction writes the -f image2 target
            Path(cmd[-1]).write_bytes(b"\xff\xd8jpeg")
        return (0, "", "")

    monkeypatch.setattr(vv, "_need", lambda b: None)
    monkeypatch.setattr(vv, "_run_cmd", _fake_run_cmd)
    monkeypatch.setattr("maverick.llm.LLM", _FakeLLM)

    class _SB:
        workdir = str(tmp_path)

    out = view_video(_SB()).fn({"source": "v.mp4", "num_frames": 2})
    assert out == "a cat plays the piano, then jumps down"


def test_video_audio_uses_its_private_generated_file(monkeypatch, tmp_path):
    from maverick.tools import voice

    def extract(_sandbox, cmd, *, timeout=600.0):
        Path(cmd[-1]).write_bytes(b"ID3audio")
        return 0, "", ""

    monkeypatch.setattr(vv, "_run_cmd", extract)
    monkeypatch.setattr(voice, "_default_stt_backend", lambda: "local")
    monkeypatch.setattr(voice, "_whisper_local", lambda path, _lang: path.read_bytes().decode())
    assert vv._transcribe_track("source.mp4", str(tmp_path), object()) == "ID3audio"
