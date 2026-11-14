"""Video-understanding tool.

Samples frames from a video at evenly-spaced timestamps, optionally
transcribes the audio track, and sends both to a vision-capable model
for analysis. Provider-agnostic: it builds Anthropic-format image blocks
(the providers' adapters translate to OpenAI / Gemini vision schemas) and
dispatches via the configured vision model.

Frame extraction reuses the local ffmpeg/ffprobe binaries (the same media
convention as ``ffmpeg_tool``); input paths are confined to the sandbox
workspace. The heavy lifting lives in small helpers (``_probe_duration``,
``_extract_frames``, ``_transcribe_track``) so tests can mock the binary
calls and the LLM.
"""
from __future__ import annotations

import base64
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

from ..budget import BudgetExceeded, UsageAccountingError
from ..killswitch import Halted
from . import Tool
from .ffmpeg_tool import _need, _run_cmd, _safe_path

log = logging.getLogger(__name__)


_MAX_FRAMES = 20
_DEFAULT_FRAMES = 8
_FRAME_WIDTH = 512  # downscale frames to bound vision token cost


_VIEW_VIDEO_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "source": {
            "type": "string",
            "description": "Local video file path (mp4/mov/webm/mkv/avi).",
        },
        "prompt": {
            "type": "string",
            "description": "What to look for. Default: 'Describe what happens in this video.'",
        },
        "num_frames": {
            "type": "integer",
            "description": f"Frames to sample evenly across the video (1-{_MAX_FRAMES}, default {_DEFAULT_FRAMES}).",
        },
        "transcribe": {
            "type": "boolean",
            "description": "Also transcribe the audio track and include it (needs a Whisper backend). Default false.",
        },
    },
    "required": ["source"],
}


def _probe_duration(src: str, sandbox) -> float | None:
    """Return the video duration in seconds via ffprobe, or None."""
    code, out, _err = _run_cmd(
        sandbox,
        ["ffprobe", "-v", "error", "-show_entries", "format=duration",
         "-of", "default=noprint_wrappers=1:nokey=1", src],
        timeout=30,
    )
    if code != 0:
        return None
    try:
        return float(out.strip())
    except ValueError:
        return None


def _evenly_spaced(duration: float, n: int) -> list[float]:
    """Midpoints of n equal segments — avoids the often-black first/last frame."""
    return [duration * (i + 0.5) / n for i in range(n)]


def _extract_frames(src: str, timestamps: list[float], tmpdir: str, sandbox) -> list[tuple[float, bytes]]:
    """Grab one downscaled JPEG per timestamp. Returns (ts, jpeg_bytes) pairs."""
    frames: list[tuple[float, bytes]] = []
    for i, ts in enumerate(timestamps):
        out = Path(tmpdir) / f"frame_{i:03d}.jpg"
        code, _o, _e = _run_cmd(
            sandbox,
            ["ffmpeg", "-y", "-ss", f"{ts:.3f}", "-i", src,
             "-frames:v", "1", "-vf", f"scale={_FRAME_WIDTH}:-1",
             "-f", "image2", str(out)],
            timeout=60,
        )
        if code == 0 and out.exists() and out.stat().st_size > 0:
            frames.append((ts, out.read_bytes()))
    return frames


def _transcribe_track(src: str, tmpdir: str, sandbox) -> str | None:
    """Extract the audio track and transcribe it via the voice tool. None on failure."""
    audio = Path(tmpdir) / "audio.mp3"
    code, _o, _e = _run_cmd(
        sandbox,
        ["ffmpeg", "-y", "-i", src, "-vn", "-b:a", "128k", str(audio)],
        timeout=300,
    )
    if code != 0 or not audio.exists():
        return None
    from ..tool_results import tool_result_failed
    from .voice import _run_transcribe_internal

    text = _run_transcribe_internal({"source": str(audio)})
    if not text or tool_result_failed(text):
        return None
    return text


def _run_view_video(args: dict[str, Any], sandbox, *, budget=None) -> str:
    source = (args.get("source") or "").strip()
    if not source:
        return "ERROR: source is required"
    prompt = (args.get("prompt") or "Describe what happens in this video.").strip()
    from ..llm import model_for_role
    if "model" in args:
        return "ERROR: the vision model is configured by the operator"
    model = os.environ.get("MAVERICK_VISION_MODEL") or model_for_role("vision")
    try:
        num_frames = int(args.get("num_frames") or _DEFAULT_FRAMES)
    except (TypeError, ValueError):
        num_frames = _DEFAULT_FRAMES
    num_frames = max(1, min(num_frames, _MAX_FRAMES))
    transcribe = bool(args.get("transcribe"))

    err = _need("ffmpeg") or _need("ffprobe")
    if err:
        return err

    try:
        src = _safe_path(sandbox, source)
    except ValueError as e:
        return f"ERROR: {e}"
    if not Path(src).is_file():
        return f"ERROR: video file not found: {source!r}"

    duration = _probe_duration(src, sandbox)
    if not duration or duration <= 0:
        return f"ERROR: could not probe video duration for {source!r}"

    timestamps = _evenly_spaced(duration, num_frames)
    with tempfile.TemporaryDirectory(prefix="maverick-view-video-") as tmp:
        frames = _extract_frames(src, timestamps, tmp, sandbox)
        if not frames:
            return f"ERROR: ffmpeg extracted no frames from {source!r}"
        transcript = _transcribe_track(src, tmp, sandbox) if transcribe else None

    # Anthropic format -- providers' adapters translate to OpenAI / Gemini.
    content: list[dict[str, Any]] = []
    for ts, jpeg in frames:
        content.append({"type": "text", "text": f"[frame at {ts:.1f}s]"})
        content.append({
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": "image/jpeg",
                "data": base64.b64encode(jpeg).decode("ascii"),
            },
        })
    if transcript:
        content.append({"type": "text", "text": f"Audio transcript:\n{transcript}"})
    content.append({"type": "text", "text": prompt})
    messages = [{"role": "user", "content": content}]

    try:
        from ..llm import LLM
    except ImportError as e:
        return f"ERROR: maverick.llm unavailable: {e}"

    try:
        llm = LLM(model=model)
        resp = llm.complete(
            system=(
                "You analyze a video by examining frames sampled in "
                "chronological order. Be concise and specific about what "
                "changes across the frames."
            ),
            messages=messages,
            max_tokens=1024,
            budget=budget,
        )
        return (resp.text or "").strip() or "(no description returned)"
    except (BudgetExceeded, UsageAccountingError, Halted):
        # Stop signals must propagate or the cap / kill switch is not enforced.
        raise
    except Exception as e:
        return f"ERROR: vision call failed: {type(e).__name__}: {e}"


def view_video(sandbox=None, *, budget=None) -> Tool:
    """Factory: builds the view_video tool."""
    return Tool(
        name="view_video",
        description=(
            "Watch a local video file: samples frames evenly across its "
            "duration and describes / analyzes them with a vision model. "
            "Set `num_frames` (1-20) to trade detail for cost, `transcribe` "
            "to include the audio transcript, and `prompt` to focus the "
            "analysis. Requires the ffmpeg + ffprobe binaries on PATH."
        ),
        input_schema=_VIEW_VIDEO_INPUT_SCHEMA,
        fn=lambda args: _run_view_video(args, sandbox, budget=budget),
    )
