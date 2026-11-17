"""Video-understanding tool.

Samples frames from a video at evenly-spaced timestamps, optionally
transcribes the audio track, and sends both to a vision-capable model
for analysis. Provider-agnostic: it builds Anthropic-format image blocks
(the providers' adapters translate to OpenAI / Gemini vision schemas) and
dispatches via the configured vision model.

Frame extraction runs ffmpeg/ffprobe through the sandbox; input paths are
confined to the sandbox workspace. A container sandbox mounts the workspace
at its own root, so every path given to a command is workspace-relative and
the frames are staged in a private folder inside the workspace. The agent can
write there too, so staged files are read back without following links and
only from inside the workspace. The heavy lifting lives in small helpers
(``_probe_duration``, ``_extract_frames``, ``_transcribe_track``) so tests
can mock the binary calls and the LLM.
"""
from __future__ import annotations

import base64
import logging
import os
import shutil
import stat
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
_MAX_FRAME_BYTES = 5 * 1024 * 1024
_MAX_AUDIO_BYTES = 256 * 1024 * 1024


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


def _runs_on_host(sandbox) -> bool:
    """Whether the sandbox runs commands as host processes (the local backend)."""
    from ..sandbox.local import LocalBackend

    return type(sandbox) is LocalBackend


def _relative(sandbox, path: Path) -> str:
    """``path`` as a command inside the sandbox names it: relative to the
    workspace, with a prefix so a name beginning with '-' is not an option.

    The one path outside the workspace is the private staging folder used when
    commands run on this machine and the workspace cannot be written."""
    resolved, workdir = path.resolve(), Path(sandbox.workdir).resolve()
    if not resolved.is_relative_to(workdir):
        return str(resolved)
    return "./" + resolved.relative_to(workdir).as_posix()


def _open_staged(sandbox, path: Path, limit: int):
    """Open a file a sandboxed command wrote into the staging folder, or None.

    The staging folder is inside the workspace, which the agent can write to.
    Neither the folder nor the file may be a link when it is opened, the file
    must be a regular file with one name and a sane size, and what was opened
    must still be inside the workspace."""
    from .fs import _fd_real_path, _open_contained

    workdir = Path(sandbox.workdir).resolve()
    if not path.parent.resolve().is_relative_to(workdir):
        workdir = path.parent.resolve()  # the private folder outside the workspace
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        if os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW"):
            folder = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                fd = os.open(path.name, flags | os.O_NOFOLLOW, dir_fd=folder)
            finally:
                os.close(folder)
            real = _fd_real_path(fd)
            if real is not None and not real.is_relative_to(workdir):
                os.close(fd)
                return None
        else:
            fd = _open_contained(workdir, path, flags)
    except (OSError, ValueError):
        return None
    handle = os.fdopen(fd, "rb")
    info = os.fstat(handle.fileno())
    # One name only: a hard link would be a second name for a file elsewhere.
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or not 0 < info.st_size <= limit):
        handle.close()
        return None
    return handle


def _extract_frames(src: str, timestamps: list[float], tmpdir: str, sandbox) -> list[tuple[float, bytes]]:
    """Grab one downscaled JPEG per timestamp. Returns (ts, jpeg_bytes) pairs."""
    frames: list[tuple[float, bytes]] = []
    for i, ts in enumerate(timestamps):
        out = Path(tmpdir) / f"frame_{i:03d}.jpg"
        code, _o, _e = _run_cmd(
            sandbox,
            ["ffmpeg", "-y", "-ss", f"{ts:.3f}", "-i", src,
             "-frames:v", "1", "-vf", f"scale={_FRAME_WIDTH}:-1",
             "-f", "image2", _relative(sandbox, out)],
            timeout=60,
        )
        staged = _open_staged(sandbox, out, _MAX_FRAME_BYTES) if code == 0 else None
        if staged is not None:
            with staged:
                frames.append((ts, staged.read(_MAX_FRAME_BYTES)))
    return frames


def _transcribe_track(src: str, tmpdir: str, sandbox, budget=None) -> str | None:
    """Extract the audio track and transcribe it via the voice tool. None on failure."""
    audio = Path(tmpdir) / "audio.mp3"
    code, _o, _e = _run_cmd(
        sandbox,
        ["ffmpeg", "-y", "-i", src, "-vn", "-b:a", "128k", _relative(sandbox, audio)],
        timeout=300,
    )
    staged = _open_staged(sandbox, audio, _MAX_AUDIO_BYTES) if code == 0 else None
    if staged is None:
        return None
    from ..tool_results import tool_result_failed
    from .voice import _run_transcribe_internal

    # The transcriber reads a path and may send the file to a speech service.
    # Give it a private copy, not a workspace path the agent could swap.
    with staged, tempfile.TemporaryDirectory(prefix="maverick-view-video-") as private:
        copy = Path(private) / "audio.mp3"
        with open(copy, "wb") as target:
            shutil.copyfileobj(staged, target)
        # A hosted speech service is charged to this run's budget.
        text = _run_transcribe_internal({"source": str(copy)}, budget=budget)
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
    if budget is None:
        # The vision call must be charged to, and stopped by, the run's budget.
        return "ERROR: video analysis requires an active run budget"
    model = os.environ.get("MAVERICK_VISION_MODEL") or model_for_role("vision")
    try:
        num_frames = int(args.get("num_frames") or _DEFAULT_FRAMES)
    except (TypeError, ValueError):
        num_frames = _DEFAULT_FRAMES
    num_frames = max(1, min(num_frames, _MAX_FRAMES))
    transcribe = bool(args.get("transcribe"))

    # The programs must be where the commands run: on this machine for the
    # local sandbox (or none), inside the sandbox otherwise.
    on_host = sandbox is None or _runs_on_host(sandbox)
    err = (_need("ffmpeg") or _need("ffprobe")) if on_host else None
    if err:
        return err

    try:
        host_src = Path(_safe_path(sandbox, source))
    except ValueError as e:
        return f"ERROR: {e}"
    if not host_src.is_file():
        return f"ERROR: video file not found: {source!r}"
    src = _relative(sandbox, host_src)

    duration = _probe_duration(src, sandbox)
    if not duration or duration <= 0:
        hint = "" if on_host else "; check that ffmpeg and ffprobe are installed in the sandbox"
        return f"ERROR: could not probe video duration for {source!r}{hint}"

    timestamps = _evenly_spaced(duration, num_frames)
    try:
        tmp = tempfile.mkdtemp(prefix=".mvk-view-video-", dir=Path(sandbox.workdir).resolve())
    except OSError as e:
        if not on_host:
            return f"ERROR: could not prepare a folder for the video frames: {e}"
        # Commands run on this machine, so a workspace that cannot be written
        # (read-only, full) can still be served from a private folder.
        tmp = tempfile.mkdtemp(prefix="maverick-view-video-")
    try:
        frames = _extract_frames(src, timestamps, tmp, sandbox)
        if not frames:
            return f"ERROR: ffmpeg extracted no frames from {source!r}"
        transcript = _transcribe_track(src, tmp, sandbox, budget) if transcribe else None
    finally:
        # Never leave the staged frames and audio in the workspace.
        shutil.rmtree(tmp, ignore_errors=True)

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
