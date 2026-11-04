"""Replay export to MP4: deterministic storyboard + manifest; best-effort encode."""
from __future__ import annotations

from pathlib import Path

from maverick.replay import video as rv
from maverick.replay.video import MAX_FRAME_SECONDS, MIN_FRAME_SECONDS, render, storyboard


def _evs():
    return [
        {"kind": "plan", "ts": 100.0, "content": "step one then step two"},
        {"kind": "tool", "ts": 102.0, "tool": "fs", "args": {"path": "."}},
        {"kind": "error", "ts": 130.0, "message": "boom"},  # big gap -> clamps to MAX
        {"kind": "done", "ts": 130.5, "result": "ok"},
    ]


def test_storyboard_durations_from_gaps():
    frames = storyboard(0, events=_evs())
    assert [f.kind for f in frames] == ["plan", "tool", "error", "done"]
    assert frames[0].seconds == 2.0                         # 102-100
    assert frames[1].seconds == MAX_FRAME_SECONDS           # 28s gap clamped
    assert frames[2].seconds == MIN_FRAME_SECONDS           # 0.5s -> min floor
    assert frames[3].seconds == MIN_FRAME_SECONDS           # last frame -> min


def test_storyboard_no_timestamps_uniform():
    frames = storyboard(0, events=[{"kind": "a", "content": "x"},
                                   {"kind": "b", "content": "y"}])
    assert all(f.seconds == MIN_FRAME_SECONDS for f in frames)


def test_storyboard_scrubs_secrets():
    frames = storyboard(0, events=[
        {"kind": "tool", "content": "key=sk-ant-api03-abcdefghijklmnopqrstuvwxyz012345"}])
    assert "sk-ant" not in frames[0].caption


def test_ffmpeg_command_shape(tmp_path):
    cmd = rv.ffmpeg_command(tmp_path / "f.ffconcat", tmp_path / "out.mp4")
    assert cmd[0] == "ffmpeg" and "-pix_fmt" in cmd and "yuv420p" in cmd
    assert str(tmp_path / "out.mp4") == cmd[-1]
    assert "concat" in cmd


def test_render_writes_manifest_and_command(tmp_path):
    out = tmp_path / "replay.mp4"
    result = render(7, out, events=_evs(), retain_staging=True)
    # The manifest (ffconcat) is always written; it lists every frame.
    assert result.concat_path.exists()
    manifest = result.concat_path.read_text()
    assert manifest.startswith("ffconcat version 1.0")
    assert manifest.count("duration") == 4
    assert result.frames == 4
    assert result.command[0] == "ffmpeg"
    # Encoding is best-effort: in this env (no ffmpeg) encoded is False but the
    # command is the deliverable.
    assert result.encoded in (True, False)


def test_render_empty_goal(tmp_path):
    result = render(7, tmp_path / "r.mp4", events=[])
    assert result.frames == 0 and not result.encoded
    assert "no events" in result.detail
    assert "cleaned" in result.detail
    assert not result.frame_dir.exists()


def test_render_encodes_when_ffmpeg_present(tmp_path, monkeypatch):
    """With Pillow + a fake ffmpeg, render reports an encode."""
    pil = __import__("importlib").util.find_spec("PIL")
    if pil is None:
        import pytest
        pytest.skip("Pillow not installed")

    import maverick.tools as tools_mod
    out = tmp_path / "replay.mp4"

    def fake_sandbox_run(sandbox, argv, **kw):
        Path(argv[-1]).write_bytes(b"\x00\x00fake mp4")
        return 0, "", ""

    monkeypatch.setattr(tools_mod, "sandbox_run", fake_sandbox_run)
    result = render(7, out, events=_evs())
    assert result.encoded is True and out.exists()
    # Successful publication removes private staging rather than leaving run
    # screenshots and manifests behind.
    assert not result.frame_dir.exists()
