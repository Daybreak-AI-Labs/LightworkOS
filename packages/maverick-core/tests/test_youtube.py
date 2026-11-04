"""Tests for the YouTube tool (maverick.tools.youtube)."""
from __future__ import annotations

import sys
import types

# ---------- YouTube tool ----------

def test_youtube_requires_op():
    from maverick.tools.youtube import youtube
    assert "op is required" in youtube().fn({})


def test_youtube_missing_lib(monkeypatch):
    monkeypatch.setitem(sys.modules, "youtube_transcript_api", None)
    from maverick.tools.youtube import youtube
    out = youtube().fn({"op": "transcript", "video_id": "dQw4w9WgXcQ"})
    assert "youtube-transcript-api not installed" in out


def test_youtube_normalize_id():
    from maverick.tools.youtube import _normalize_id
    assert _normalize_id("dQw4w9WgXcQ") == "dQw4w9WgXcQ"
    assert _normalize_id("https://youtu.be/dQw4w9WgXcQ") == "dQw4w9WgXcQ"
    assert _normalize_id("https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=42") == "dQw4w9WgXcQ"


def test_youtube_transcript_renders(monkeypatch):
    fake = types.ModuleType("youtube_transcript_api")

    class _API:
        @staticmethod
        def get_transcript(video_id, languages=None):
            return [
                {"text": "Never gonna", "start": 0.0, "duration": 1.0},
                {"text": "give you up", "start": 1.0, "duration": 1.0},
            ]

    fake.YouTubeTranscriptApi = _API
    monkeypatch.setitem(sys.modules, "youtube_transcript_api", fake)
    from maverick.tools.youtube import youtube
    out = youtube().fn({"op": "transcript", "video_id": "abc"})
    assert "Never gonna give you up" in out


def test_youtube_chapters_includes_timestamps(monkeypatch):
    fake = types.ModuleType("youtube_transcript_api")

    class _API:
        @staticmethod
        def get_transcript(video_id, languages=None):
            return [
                {"text": "intro", "start": 0.0, "duration": 1.0},
                # 10s gap forces a new chapter
                {"text": "verse one", "start": 11.0, "duration": 1.0},
            ]

    fake.YouTubeTranscriptApi = _API
    monkeypatch.setitem(sys.modules, "youtube_transcript_api", fake)
    from maverick.tools.youtube import youtube
    out = youtube().fn({"op": "chapters", "video_id": "abc"})
    assert "[00:00:00]" in out
    assert "[00:00:11]" in out
