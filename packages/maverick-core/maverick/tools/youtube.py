"""YouTube transcript tool.

Fetches captions for a YouTube video (manual or auto-generated) via
the ``youtube-transcript-api`` library. Lets the agent feed video
content into prompts without watching the video.

ops:
  - transcript(video_id, lang)         — plain-text transcript
  - chapters(video_id)                 — chaptered transcript (one block per timestamp gap)

Accepts either a bare video id or a full youtube.com / youtu.be URL.

Requires::

    python -m pip install -e './packages/maverick-core[youtube]'
"""
from __future__ import annotations

import logging
import re
from typing import Any

from . import Tool

log = logging.getLogger(__name__)


_YT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["transcript", "chapters"]},
        "video_id": {"type": "string", "description": "Bare id or full URL."},
        "lang": {"type": "string", "description": "ISO 639-1 (default 'en')."},
        "max_chars": {"type": "integer"},
    },
    "required": ["op", "video_id"],
}


# 11-char video id at end of the most common share URLs.
_VIDEO_ID_RE = re.compile(
    r"(?:v=|youtu\.be/|/embed/|/v/)([A-Za-z0-9_-]{11})",
)


def _normalize_id(raw: str) -> str:
    raw = raw.strip()
    if len(raw) == 11 and re.fullmatch(r"[A-Za-z0-9_-]{11}", raw):
        return raw
    m = _VIDEO_ID_RE.search(raw)
    return m.group(1) if m else raw


def _fetch_transcript(video_id: str, lang: str) -> list[dict]:
    from youtube_transcript_api import YouTubeTranscriptApi
    try:
        return YouTubeTranscriptApi.get_transcript(video_id, languages=[lang, "en"])
    except Exception as e:
        raise RuntimeError(f"transcript fetch failed: {e}") from e


def _format_plain(entries: list[dict], max_chars: int) -> str:
    parts = []
    used = 0
    for e in entries:
        text = (e.get("text") or "").strip().replace("\n", " ")
        if not text:
            continue
        if used + len(text) + 1 > max_chars:
            parts.append("... (truncated)")
            break
        parts.append(text)
        used += len(text) + 1
    return " ".join(parts)


def _format_chapters(entries: list[dict], max_chars: int) -> str:
    """Naïve chaptering: break at >= 8s gaps OR every 30 entries."""
    chapters: list[list[dict]] = []
    cur: list[dict] = []
    prev_end = None
    for i, e in enumerate(entries):
        start = float(e.get("start") or 0.0)
        dur = float(e.get("duration") or 0.0)
        if prev_end is not None and (start - prev_end > 8.0 or i % 30 == 0):
            if cur:
                chapters.append(cur)
                cur = []
        cur.append(e)
        prev_end = start + dur
    if cur:
        chapters.append(cur)

    out: list[str] = []
    used = 0
    for blk in chapters:
        start = float(blk[0].get("start") or 0.0)
        h = int(start // 3600)
        m = int((start % 3600) // 60)
        s = int(start % 60)
        head = f"[{h:02d}:{m:02d}:{s:02d}]"
        body = " ".join((e.get("text") or "").strip() for e in blk)
        line = f"{head} {body}"
        if used + len(line) + 1 > max_chars:
            out.append("... (truncated)")
            break
        out.append(line)
        used += len(line) + 1
    return "\n".join(out)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    raw_id = (args.get("video_id") or "").strip()
    if not raw_id:
        return "ERROR: video_id is required"
    video_id = _normalize_id(raw_id)
    lang = (args.get("lang") or "en").strip()
    max_chars = int(args.get("max_chars") or 8000)
    try:
        import youtube_transcript_api  # noqa: F401
    except ImportError:
        return (
            "ERROR: youtube-transcript-api not installed. "
            "Run: python -m pip install -e './packages/maverick-core[youtube]'"
        )
    try:
        entries = _fetch_transcript(video_id, lang)
        if op == "transcript":
            return _format_plain(entries, max_chars)
        if op == "chapters":
            return _format_chapters(entries, max_chars)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: YouTube transcript failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def youtube() -> Tool:
    return Tool(
        name="youtube",
        description=(
            "Fetch a YouTube video's transcript. ops: transcript "
            "(flattened text), chapters (timestamped blocks). "
            "video_id accepts bare 11-char id or full URL. Lang "
            "defaults to 'en' with 'en' fallback."
        ),
        input_schema=_YT_SCHEMA,
        fn=_run,
    )
