"""Live captions over the voice transcript seam.

Turns a stream of transcript segments (the seam the voice tools' Whisper
backends produce: finalized utterances plus in-flight partials) into a rolling
caption line a UI can show live. Pure + injected: the segment *source* is any
async iterable handed in by the caller — tests drive scripted sources, a real
deployment registers its mic/ASR pipeline in the source registry — so nothing
here touches audio hardware or the network.

Pieces:
* :class:`CaptionWindow` — the rolling caption text: finalized segments
  accumulate, an in-flight partial replaces the previous partial, and the
  window trims from the left at word boundaries to ``max_chars``.
* :func:`caption_stream` — async iterator of caption frames
  ``{caption, final, ts}`` over an injected source.
* the **source registry** (``register_source``/``get_source``) — the injection
  point the dashboard's ``GET /api/v1/voice/captions`` endpoint reads.
  Default-empty, so the captions endpoint is off until an operator (or test)
  registers a source.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

DEFAULT_MAX_CHARS = 160
_MIN_MAX_CHARS = 16


@dataclass(frozen=True)
class Segment:
    """One transcript segment. ``final=False`` marks an in-flight partial that
    the next segment (partial or final) replaces."""

    text: str
    final: bool = True
    ts: float = 0.0


def as_segment(item) -> Segment:
    """Coerce a source item (Segment / dict / (text, final) / str) to a Segment."""
    if isinstance(item, Segment):
        return item
    if isinstance(item, dict):
        return Segment(
            text=str(item.get("text") or ""),
            final=bool(item.get("final", True)),
            ts=float(item.get("ts") or 0.0),
        )
    if isinstance(item, tuple) and len(item) >= 2:
        return Segment(text=str(item[0]), final=bool(item[1]))
    return Segment(text=str(item))


def _trim_words(text: str, max_chars: int) -> str:
    """Keep the freshest ``max_chars`` of ``text``, cut at a word boundary."""
    if len(text) <= max_chars:
        return text
    tail = text[-max_chars:]
    space = tail.find(" ")
    if space != -1:
        tail = tail[space + 1:]
    return tail


class CaptionWindow:
    """Rolling caption text over finalized + in-flight transcript segments."""

    def __init__(self, max_chars: int = DEFAULT_MAX_CHARS):
        self.max_chars = max(_MIN_MAX_CHARS, int(max_chars))
        self._final: list[str] = []
        self._inflight = ""

    def push(self, segment: Segment) -> str:
        """Apply one segment and return the current caption text."""
        text = " ".join(str(segment.text or "").split())
        if segment.final:
            self._inflight = ""
            if text:
                self._final.append(text)
        else:
            self._inflight = text
        self._prune()
        return self.text

    def _prune(self) -> None:
        # Drop finalized segments that can never re-enter the window so a
        # long-running stream stays O(window), not O(transcript).
        while len(self._final) > 1 and sum(len(s) + 1 for s in self._final[1:]) > self.max_chars:
            self._final.pop(0)

    @property
    def text(self) -> str:
        parts = list(self._final)
        if self._inflight:
            parts.append(self._inflight)
        return _trim_words(" ".join(parts), self.max_chars)


async def caption_stream(source, *, max_chars: int = DEFAULT_MAX_CHARS):
    """Async iterator of caption frames over an injected transcript source.

    Yields ``{"caption": <window text>, "final": bool, "ts": float}`` for each
    segment the source produces; ends when the source is exhausted.
    """
    window = CaptionWindow(max_chars=max_chars)
    async for item in source:
        seg = as_segment(item)
        yield {"caption": window.push(seg), "final": seg.final, "ts": seg.ts}


# ---- source registry (the dashboard endpoint's injection point) -------------

_SOURCES: dict[str, Callable[[], object]] = {}


def register_source(name: str, factory: Callable[[], object]) -> None:
    """Register a caption-source factory (a zero-arg callable returning an
    async iterable of segments) under ``name``."""
    key = str(name or "").strip()
    if not key:
        raise ValueError("source name is required")
    if not callable(factory):
        raise ValueError("factory must be callable")
    _SOURCES[key] = factory


def unregister_source(name: str) -> bool:
    return _SOURCES.pop(str(name or "").strip(), None) is not None


def get_source(name: str = "default") -> Callable[[], object] | None:
    return _SOURCES.get(str(name or "").strip())


def available_sources() -> list[str]:
    return sorted(_SOURCES)


__all__ = [
    "Segment", "CaptionWindow", "caption_stream", "as_segment",
    "register_source", "unregister_source", "get_source", "available_sources",
    "DEFAULT_MAX_CHARS",
]
