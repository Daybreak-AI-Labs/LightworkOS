"""Bounded, private replay-video rendering.

Audit-backed storyboards carry an explicit evidence-proof status. Rendering is
performed in a unique private sibling directory, ffconcat references only
generated relative names, and a successful MP4 is atomically published under a
strict cross-process output lock. Staging is removed on every outcome unless a
caller explicitly opts into retaining private diagnostic artifacts.
"""
from __future__ import annotations

import json
import logging
import math
import os
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path

from ..file_lock import (
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
    prepare_private_directory,
)
from .export import _sanitize, load_goal_events

log = logging.getLogger(__name__)

MIN_FRAME_SECONDS = 1.0
MAX_FRAME_SECONDS = 6.0
MAX_VIDEO_FRAMES = 2_000
MAX_VIDEO_EVENT_BYTES = 256 * 1024
MAX_VIDEO_INPUT_BYTES = 32 * 1024 * 1024
MAX_VIDEO_OUTPUT_BYTES = 2 * 1024 * 1024 * 1024
MIN_FPS = 1
MAX_FPS = 120
_DEFAULT_FPS = 25
_W, _H = 1280, 720


@dataclass(frozen=True)
class Frame:
    index: int
    kind: str
    caption: str
    seconds: float


@dataclass
class RenderResult:
    frames: int
    frame_dir: Path
    concat_path: Path
    command: list[str]
    encoded: bool
    detail: str
    proof_status: str = "provided_events_unverified"


def _validate_fps(fps: int) -> int:
    if isinstance(fps, bool) or not isinstance(fps, int) or not MIN_FPS <= fps <= MAX_FPS:
        raise ValueError(f"fps must be an integer from {MIN_FPS} to {MAX_FPS}")
    return fps


def _event_ts(event: dict) -> float | None:
    timestamp = event.get("ts") or event.get("created_at")
    try:
        parsed = float(timestamp) if timestamp is not None else None
    except (TypeError, ValueError, OverflowError):
        return None
    return parsed if parsed is not None and math.isfinite(parsed) else None


def _event_json(event: dict) -> str:
    try:
        raw = json.dumps(event, default=str, ensure_ascii=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("video event cannot be serialized") from exc
    if len(raw.encode("utf-8")) > MAX_VIDEO_EVENT_BYTES:
        raise ValueError("video event exceeds the byte limit")
    return raw


def _caption(event: dict) -> str:
    body = {
        key: value
        for key, value in event.items()
        if key
        not in (
            "kind",
            "event",
            "ts",
            "created_at",
            "goal_id",
            "hash",
            "prev_hash",
            "sig",
            "key_id",
        )
    }
    try:
        text = _sanitize(json.dumps(body, default=str, ensure_ascii=False))
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("video event caption cannot be serialized") from exc
    return text.strip().strip("{}").strip()[:280]


def _validated_events(events: list[dict]) -> list[dict]:
    if not isinstance(events, list):
        raise ValueError("events must be a list")
    if len(events) > MAX_VIDEO_FRAMES:
        raise ValueError("video event count exceeds the frame limit")
    total = 0
    for event in events:
        if not isinstance(event, dict):
            raise ValueError("every video event must be an object")
        total += len(_event_json(event).encode("utf-8"))
        if total > MAX_VIDEO_INPUT_BYTES:
            raise ValueError("video events exceed the total input limit")
    return events


def storyboard(goal_id: int, *, events: list[dict] | None = None) -> list[Frame]:
    """Build a bounded deterministic storyboard.

    When ``events`` is omitted, the audit day chains and cross-day anchors are
    verified by :func:`load_goal_events` before any frame is derived.
    """
    source = load_goal_events(goal_id)[0] if events is None else events
    event_list = _validated_events(source)
    frames: list[Frame] = []
    for index, event in enumerate(event_list):
        kind = str(event.get("kind") or event.get("event") or "?")
        if not 1 <= len(kind) <= 128 or not kind.isprintable():
            raise ValueError("video event kind must be a bounded printable string")
        following = event_list[index + 1] if index + 1 < len(event_list) else None
        seconds = MIN_FRAME_SECONDS
        start = _event_ts(event)
        end = _event_ts(following) if following is not None else None
        if start is not None and end is not None and end > start:
            seconds = max(MIN_FRAME_SECONDS, min(MAX_FRAME_SECONDS, end - start))
        frames.append(
            Frame(
                index=index,
                kind=kind,
                caption=_caption(event),
                seconds=round(seconds, 3),
            )
        )
    return frames


def _validated_frames(frames: list[Frame]) -> list[Frame]:
    if len(frames) > MAX_VIDEO_FRAMES:
        raise ValueError("video frame count exceeds the limit")
    for expected, frame in enumerate(frames):
        if not isinstance(frame, Frame) or frame.index != expected:
            raise ValueError("video frames must have contiguous generated indexes")
        if (
            not isinstance(frame.seconds, (int, float))
            or not math.isfinite(float(frame.seconds))
            or not MIN_FRAME_SECONDS <= float(frame.seconds) <= MAX_FRAME_SECONDS
        ):
            raise ValueError("video frame duration is outside the allowed range")
        if not frame.kind.isprintable() or len(frame.kind) > 128:
            raise ValueError("video frame kind is invalid")
        if len(frame.caption) > 280:
            raise ValueError("video frame caption is invalid")
    return frames


def _ffmpeg_concat(
    frames: list[Frame],
    frame_dir: Path,
    *,
    proof_status: str = "provided_events_unverified",
) -> str:
    """Return a safe ffconcat manifest using generated relative filenames."""
    del frame_dir  # compatibility parameter; paths are intentionally relative
    checked = _validated_frames(frames)
    safe_status = "".join(
        char for char in str(proof_status)[:64] if char.isalnum() or char in "_-"
    ) or "unknown"
    lines = ["ffconcat version 1.0", f"# lightwork-proof-status: {safe_status}"]
    for frame in checked:
        name = f"frame_{frame.index:05d}.png"
        lines.append(f"file {name}")
        lines.append(f"duration {frame.seconds:g}")
    if checked:
        lines.append(f"file frame_{checked[-1].index:05d}.png")
    return "\n".join(lines) + "\n"


def ffmpeg_command(
    concat_path: Path,
    out_path: Path,
    *,
    fps: int = _DEFAULT_FPS,
) -> list[str]:
    """Build portable argv for the generated safe-relative concat manifest."""
    rate = _validate_fps(fps)
    concat = os.path.abspath(os.fspath(Path(concat_path)))
    output = os.path.abspath(os.fspath(Path(out_path)))
    return [
        "ffmpeg",
        "-nostdin",
        "-y",
        "-f",
        "concat",
        "-safe",
        "1",
        "-i",
        concat,
        "-vsync",
        "vfr",
        "-pix_fmt",
        "yuv420p",
        "-r",
        str(rate),
        "-vf",
        "scale=trunc(iw/2)*2:trunc(ih/2)*2",
        output,
    ]


def _render_png(frame: Frame, path: Path) -> bool:
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        return False
    image = Image.new("RGB", (_W, _H), (13, 17, 23))
    draw = ImageDraw.Draw(image)
    draw.rectangle([0, 0, _W, 64], fill=(22, 27, 34))
    draw.text((24, 22), f"[{frame.index + 1}] {frame.kind}", fill=(63, 185, 80))
    y = 110
    line = ""
    for word in frame.caption.split():
        if len(line) + len(word) + 1 > 84:
            draw.text((24, y), line, fill=(230, 237, 243))
            y += 28
            line = word
        else:
            line = f"{line} {word}".strip()
        if y > _H - 60:
            break
    if line and y <= _H - 60:
        draw.text((24, y), line, fill=(230, 237, 243))
    image.save(path, format="PNG")
    ensure_private_file(path)
    return True


def _validate_output_path(out_path: Path) -> Path:
    path = Path(out_path)
    if (
        path.name in {"", ".", ".."}
        or len(path.name) > 240
        or not path.name.isprintable()
    ):
        raise ValueError("video output filename is invalid")
    prepare_private_directory(path.parent)
    if path.exists():
        ensure_private_file(path)
    return path


def _new_staging(parent: Path) -> Path:
    for _ in range(32):
        candidate = parent / f".replay-video-{uuid.uuid4().hex}"
        try:
            candidate.mkdir(mode=0o700)
        except FileExistsError:
            continue
        return ensure_private_directory(candidate)
    raise FileExistsError("unable to allocate private replay-video staging")


def _cleanup_staging(staging: Path, parent: Path) -> None:
    """Remove only the generated direct child; never follow caller paths."""
    try:
        if staging.parent != parent or not staging.name.startswith(".replay-video-"):
            return
        shutil.rmtree(staging)
    except OSError:
        log.warning("replay video staging cleanup failed")


def render(
    goal_id: int,
    out_path: Path,
    *,
    sandbox=None,
    events: list[dict] | None = None,
    fps: int = _DEFAULT_FPS,
    retain_staging: bool = False,
) -> RenderResult:
    """Render a replay through private staging and atomically publish an MP4."""
    if not isinstance(retain_staging, bool):
        raise ValueError("retain_staging must be a boolean")
    rate = _validate_fps(fps)
    output = _validate_output_path(Path(out_path))
    if events is None:
        source_events, proof = load_goal_events(goal_id)
        proof_status = str(proof.get("status") or "unknown")
    else:
        source_events = events
        proof_status = "provided_events_unverified"
    frames = storyboard(goal_id, events=source_events)

    with cross_process_lock(output, strict=True):
        staging = _new_staging(output.parent)
        concat_path = staging / "frames.ffconcat"
        staged_output = staging / "encoded.mp4"
        try:
            atomic_write_text(
                concat_path,
                _ffmpeg_concat(frames, staging, proof_status=proof_status),
                mode=0o600,
            )
            ensure_private_file(concat_path)
            command = ffmpeg_command(concat_path, staged_output, fps=rate)
            if not frames:
                return RenderResult(
                    0,
                    staging,
                    concat_path,
                    command,
                    False,
                    "no events recorded for this goal; staging cleaned"
                    if not retain_staging
                    else "no events recorded for this goal; private staging retained by request",
                    proof_status,
                )

            rendered = all(
                _render_png(frame, staging / f"frame_{frame.index:05d}.png")
                for frame in frames
            )
            if not rendered:
                return RenderResult(
                    len(frames),
                    staging,
                    concat_path,
                    command,
                    False,
                    "Pillow is unavailable; staging cleaned"
                    if not retain_staging
                    else "Pillow is unavailable; private staging retained by request",
                    proof_status,
                )

            try:
                from ..tools import sandbox_run

                code, _stdout, _stderr = sandbox_run(sandbox, command, timeout=300)
            except Exception:
                return RenderResult(
                    len(frames),
                    staging,
                    concat_path,
                    command,
                    False,
                    "ffmpeg is unavailable; staging cleaned"
                    if not retain_staging
                    else "ffmpeg is unavailable; private staging retained by request",
                    proof_status,
                )
            if code != 0 or not staged_output.exists():
                return RenderResult(
                    len(frames),
                    staging,
                    concat_path,
                    command,
                    False,
                    "ffmpeg did not produce a valid staged output; staging cleaned"
                    if not retain_staging
                    else "ffmpeg did not produce a valid staged output; private staging retained by request",
                    proof_status,
                )
            ensure_private_file(staged_output)
            size = staged_output.stat().st_size
            if not 0 < size <= MAX_VIDEO_OUTPUT_BYTES:
                raise ValueError("staged video output size is invalid")
            if output.exists():
                ensure_private_file(output)
            os.replace(staged_output, output)
            ensure_private_file(output)
            return RenderResult(
                len(frames),
                staging,
                concat_path,
                command,
                True,
                f"encoded {len(frames)} frames",
                proof_status,
            )
        except Exception:
            raise RuntimeError("replay video rendering failed") from None
        finally:
            if not retain_staging:
                _cleanup_staging(staging, output.parent)


__all__ = [
    "Frame",
    "storyboard",
    "ffmpeg_command",
    "render",
    "RenderResult",
    "MIN_FRAME_SECONDS",
    "MAX_FRAME_SECONDS",
    "MAX_VIDEO_FRAMES",
]
