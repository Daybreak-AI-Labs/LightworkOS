"""Voice-only mode — a session loop where ALL interaction is speech.

Input is an injected source of transcribed utterances and output is an
injected ``speak(text)`` seam; every reply passes through a deterministic
speech-shaping pass (:func:`shape_for_speech`) that turns markdown/code into
something sayable ("I wrote 40 lines to app.py") before it reaches the
speaker.

Honesty notes:

* **There is no live-microphone module in this tree**, so the input seam is
  an iterable of already-transcribed utterances — the operator's mic loop
  (sounddevice + whisper, a phone bridge, ...) plugs in there.
* **The default ``speak`` adapter synthesizes, it does not play.** It routes
  through the existing TTS path (``maverick.tools.voice``, which also applies
  the voice-safety redaction pass) and writes an mp3; audio output hardware is
  the operator's. Inject your own ``speak`` to drive real playback. The
  kernel takes no audio dependencies.

Config knob (read via the standard ``maverick.config`` pattern)::

    [voice]
    only_mode = true   # default false

``run_voice_only`` refuses to start while the knob is off (pass
``force=True`` to bypass, e.g. for tests or programmatic embedding).
"""
from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterable

log = logging.getLogger(__name__)

# A session must not loop forever on a misbehaving (infinite, non-stopping)
# utterance source.
MAX_TURNS = 1000

# Speech is linear: cap how much of a long reply is spoken before summarising.
MAX_SPOKEN_CHARS = 600

DEFAULT_STOP_PHRASES = ("stop listening", "exit voice mode", "goodbye maverick")

_FENCE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)
_FILEISH = re.compile(r"[A-Za-z0-9_./~-]+\.[A-Za-z0-9]{1,8}\b")
# Only a token ending in one of these is spoken as a file name. Any dotted
# token used to count, so "e.g." and "version 2.0" were read out as files.
_FILE_EXTENSIONS = frozenset({
    "bash", "c", "cc", "cfg", "conf", "cpp", "cs", "css", "csv", "env", "go", "h", "hpp",
    "htm", "html", "ini", "java", "js", "json", "jsx", "kt", "lock", "lua", "md", "php",
    "pl", "ps1", "py", "r", "rb", "rs", "rst", "scss", "sh", "sql", "swift", "tf", "toml",
    "ts", "tsx", "txt", "vue", "xml", "yaml", "yml", "zsh",
})
_LINK = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")
_INLINE_CODE = re.compile(r"`([^`]*)`")
_HEADER = re.compile(r"^\s{0,3}#{1,6}\s*", re.MULTILINE)
_BULLET = re.compile(r"^\s*[-*+]\s+", re.MULTILINE)
_TABLE_LINE = re.compile(r"^\s*\|.*\|\s*$")


def voice_only_enabled() -> bool:
    """``[voice] only_mode`` from config; default OFF. Fail-soft to off."""
    try:
        from .config import load_config
        voice = (load_config() or {}).get("voice") or {}
        return bool(voice.get("only_mode", False))
    except Exception:  # pragma: no cover -- config never blocks speech
        return False


def _describe_code_block(body: str, context_before: str) -> str:
    """Spoken summary of a fenced code block: line count + target file if a
    file name (a path with a known extension) is mentioned just above the
    fence. Without one the block is described, with no claim of a write."""
    lines = [ln for ln in body.split("\n") if ln.strip()]
    n = len(lines)
    noun = "line" if n == 1 else "lines"
    # Look for a file name in the last couple of lines before the fence.
    tail = "\n".join(context_before.rstrip().split("\n")[-2:])
    names = [m.group(0) for m in _FILEISH.finditer(tail) if _is_file_name(m.group(0))]
    if names:
        # keep the last (closest) match before the fence
        return f"I wrote {n} {noun} to {names[-1]}."
    return f"(a code block of {n} {noun})"


def _is_file_name(token: str) -> bool:
    stem, _, extension = token.rpartition(".")
    return (extension.lower() in _FILE_EXTENSIONS and "//" not in token
            and any(ch.isalnum() for ch in stem))


def _summarize_tables(text: str) -> str:
    """Collapse each run of markdown table lines into a spoken summary."""
    out: list[str] = []
    run = 0
    for line in text.split("\n"):
        if _TABLE_LINE.match(line):
            run += 1
            continue
        if run:
            rows = max(0, run - 2)  # minus header + separator rows
            out.append(f"(a table with {rows} row{'s' if rows != 1 else ''})")
            run = 0
        out.append(line)
    if run:
        rows = max(0, run - 2)
        out.append(f"(a table with {rows} row{'s' if rows != 1 else ''})")
    return "\n".join(out)


def shape_for_speech(text: str, *, max_chars: int = MAX_SPOKEN_CHARS) -> str:
    """Deterministically reshape a text reply into something speakable.

    Fenced code blocks become "I wrote N lines to <file>." (or "(a code block
    of N lines)" when no file is named just above the fence); links keep their
    label; inline code, headers, bold markers, and bullet glyphs are stripped;
    tables collapse to a row-count summary; whitespace collapses; the result
    is capped at ``max_chars`` on a word boundary. Pure function, no model.
    """
    text = str(text or "")

    # Code blocks first (their bodies must not leak into later passes).
    def _replace_fence(m: re.Match[str]) -> str:
        return " " + _describe_code_block(m.group(1), text[: m.start()]) + " "

    out = _FENCE.sub(_replace_fence, text)
    out = _summarize_tables(out)
    out = _LINK.sub(r"\1", out)
    out = _INLINE_CODE.sub(r"\1", out)
    out = _HEADER.sub("", out)
    out = _BULLET.sub("", out)
    out = out.replace("**", "").replace("__", "")
    out = " ".join(out.split())
    if len(out) > max_chars:
        cut = out[:max_chars].rsplit(" ", 1)[0]
        out = cut + "… that's the short version."
    return out


def default_speak(text: str) -> str:
    """Synthesize ``text`` via the existing TTS tool path; returns its result.

    Synthesis only (writes an mp3; the TTS path applies the voice-safety
    redaction); playback is the operator's. Fail-soft: any error is logged and
    reported in the return string, never raised into the session loop.
    """
    try:
        from .tools.voice import _run_speak
        return _run_speak({"text": text})
    except Exception as e:
        log.warning("voice_only: default speak failed: %s", e)
        return f"ERROR: speak failed: {e}"


class VoiceOnlySession:
    """Drive a speech-in / speech-out loop over injected seams.

    ``utterances`` yields transcribed operator speech; ``respond`` is the
    brain (e.g. ``Supervisor(world).handle`` or an agent handler) mapping an
    utterance to a text reply; ``speak`` is the output seam (default:
    :func:`default_speak`). Every reply is shaped via ``shape`` before being
    spoken. A stop phrase ends the session with a spoken sign-off.
    """

    def __init__(
        self,
        utterances: Iterable[str],
        respond: Callable[[str], str],
        *,
        speak: Callable[[str], object] | None = None,
        shape: Callable[[str], str] = shape_for_speech,
        stop_phrases: tuple[str, ...] = DEFAULT_STOP_PHRASES,
        max_turns: int = MAX_TURNS,
    ):
        self.utterances = utterances
        self.respond = respond
        self.speak = speak if speak is not None else default_speak
        self.shape = shape
        self.stop_phrases = tuple(p.strip().lower() for p in stop_phrases)
        self.max_turns = max(1, int(max_turns))

    def run(self) -> int:
        """Run until the source ends, a stop phrase, or ``max_turns``.
        Returns the number of utterances handled."""
        turns = 0
        for utterance in self.utterances:
            text = " ".join(str(utterance or "").split())
            if not text:
                continue
            if text.lower().rstrip("?!. ") in self.stop_phrases:
                self.speak("Voice mode off. Goodbye.")
                break
            try:
                from .safety.voice_safety import scan_transcript
                verdict = scan_transcript(text)
            except Exception:  # safety scanner failures are explicitly fail-open
                log.warning("voice_only transcript safety scan failed", exc_info=True)
            else:
                if not verdict.ok:
                    log.warning("voice_only transcript blocked: %s", "; ".join(verdict.reasons))
                    self.speak("I can't process that request.")
                    turns += 1
                    if turns >= self.max_turns:
                        break
                    continue
            try:
                reply = self.respond(text)
            except Exception as e:
                log.warning("voice_only: respond failed: %s", e)
                self.speak("Sorry, that failed. Try again or rephrase.")
                turns += 1
                if turns >= self.max_turns:
                    break
                continue
            self.speak(self.shape(str(reply)))
            turns += 1
            if turns >= self.max_turns:
                break
        return turns


def run_voice_only(
    utterances: Iterable[str],
    respond: Callable[[str], str],
    *,
    speak: Callable[[str], object] | None = None,
    force: bool = False,
    **session_kwargs,
) -> int:
    """Gatekept entry point: runs a :class:`VoiceOnlySession` only when
    ``[voice] only_mode = true`` (or ``force=True``). Returns turns handled
    (0 when the knob is off)."""
    if not force and not voice_only_enabled():
        log.warning("voice_only: [voice] only_mode is off; not starting")
        return 0
    return VoiceOnlySession(
        utterances, respond, speak=speak, **session_kwargs,
    ).run()


__all__ = [
    "voice_only_enabled",
    "shape_for_speech",
    "default_speak",
    "VoiceOnlySession",
    "run_voice_only",
    "MAX_TURNS",
    "MAX_SPOKEN_CHARS",
    "DEFAULT_STOP_PHRASES",
]
