"""Audio understanding — zero-shot NON-SPEECH classification.

Whisper hears words; this hears *sounds*. A CLAP model (contrastive
language-audio pretraining) embeds audio and free-text labels into the same
space, so "glass breaking" / "dog barking" / "fire alarm" can be ranked
against a clip with no task-specific training — the audio analogue of
CLIP-style zero-shot image classification.

Seams: the embedders are **injected** (``audio_embed(bytes) -> vector``,
``text_embed(labels) -> vectors``) so the ranking math is testable offline.
The default adapters lazy-load transformers' ClapModel behind the ``[clap]``
extra (``python -m pip install -e './packages/maverick-core[clap]'``); model name comes from
``[models] clap`` / ``MAVERICK_CLAP_MODEL`` (default ``laion/clap-htsat-unfused``). Nothing is
downloaded until a default adapter is actually called.

ops:
  - classify(audio_path, labels)  — rank text labels against the clip
  - embed(audio_path)             — raw CLAP audio embedding (JSON vector)
"""
from __future__ import annotations

import io
import json
import math
import os
import threading
from pathlib import Path
from typing import Any

from . import Tool

DEFAULT_CLAP_MODEL = "laion/clap-htsat-unfused"

_clap = None  # lazy (model, processor) singleton
_clap_lock = threading.Lock()


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


# Cap raw audio bytes before materializing a Python float-per-sample waveform:
# a ~2 GB WAV expands to many GB of Python objects (in-process OOM DoS), and the
# decode runs unconditionally before any CLAP model load. 64 MiB default (a few
# minutes of 16-bit PCM); tunable for legitimately larger clips.
MAX_AUDIO_BYTES = _env_int("MAVERICK_AUDIO_MAX_BYTES", 64 * 1024 * 1024)


def _audio_limit() -> int:
    """The byte cap in force: ``MAVERICK_AUDIO_MAX_BYTES`` when set, else
    ``[attachments] audio_max_bytes`` (the All settings page), else the
    built-in 64 MiB. Read per call so a saved change applies to the next clip."""
    if os.environ.get("MAVERICK_AUDIO_MAX_BYTES", "").strip():
        return MAX_AUDIO_BYTES
    try:
        from ..config import load_config
        value = ((load_config() or {}).get("attachments") or {}).get("audio_max_bytes")
    except Exception:  # pragma: no cover - config never blocks the tool
        return MAX_AUDIO_BYTES
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return MAX_AUDIO_BYTES
    return value


# ---------- pure math (no model, no deps) ----------

def cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity; 0.0 for mismatched lengths or zero vectors."""
    if len(a) != len(b) or not a:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def rank_labels(
    audio_vec: list[float],
    labels: list[str],
    label_vecs: list[list[float]],
) -> list[tuple[str, float]]:
    """Rank ``labels`` by cosine similarity to ``audio_vec``, best first.

    Deterministic: ties break alphabetically by label.
    """
    if len(labels) != len(label_vecs):
        raise ValueError("labels and label_vecs must be the same length")
    scored = [(label, cosine(audio_vec, vec)) for label, vec in zip(labels, label_vecs, strict=False)]
    scored.sort(key=lambda x: (-x[1], x[0]))
    return scored


# ---------- WAV decoding (stdlib only) ----------

def decode_wav(data: bytes) -> tuple[list[float], int]:
    """Decode 16-bit PCM WAV bytes to (mono waveform in [-1, 1], sample rate).

    Stdlib ``wave`` only — the real CLAP adapter feeds this to the processor,
    so no librosa/soundfile dependency is needed for the common case.
    """
    import array
    import wave
    # ``wave`` raises wave.Error / EOFError on malformed or truncated input;
    # normalise those to ValueError so callers (the tool's _run) get the same
    # "bad audio" contract they already handle for the non-16-bit case.
    limit = _audio_limit()
    if len(data) > limit:
        raise ValueError(
            f"audio too large: {len(data)} bytes (limit {limit}); "
            "raise MAVERICK_AUDIO_MAX_BYTES if this is expected"
        )
    try:
        with wave.open(io.BytesIO(data)) as w:
            rate = w.getframerate()
            n_ch = w.getnchannels()
            width = w.getsampwidth()
            # Bound the PCM payload before readframes materializes it and the
            # per-sample float list below; getnframes/getnchannels are header
            # values, so reject a lying/huge header without allocating.
            if w.getnframes() * max(1, n_ch) * max(1, width) > limit:
                raise ValueError(
                    f"audio too large: declared PCM exceeds limit {limit}; "
                    "raise MAVERICK_AUDIO_MAX_BYTES if this is expected"
                )
            frames = w.readframes(w.getnframes())
    except (wave.Error, EOFError) as e:
        raise ValueError(f"not a valid WAV stream: {e}") from e
    if width != 2:
        raise ValueError(f"only 16-bit PCM WAV is supported (got {8 * width}-bit)")
    if n_ch < 1:
        raise ValueError(f"invalid channel count: {n_ch}")
    samples = array.array("h")
    try:
        samples.frombytes(frames)
    except ValueError as e:
        raise ValueError(f"truncated WAV PCM data: {e}") from e
    if n_ch > 1:  # average interleaved channels to mono
        mono = [
            sum(samples[i:i + n_ch]) / n_ch for i in range(0, len(samples), n_ch)
        ]
    else:
        mono = list(samples)
    return [s / 32768.0 for s in mono], rate


# ---------- real CLAP adapters (lazy; [clap] extra) ----------

def _load_clap():
    global _clap
    if _clap is not None:
        return _clap
    with _clap_lock:
        if _clap is not None:
            return _clap
        try:
            import torch  # noqa: F401
            from transformers import ClapModel, ClapProcessor
        except ImportError as e:
            raise ImportError(
                "CLAP audio understanding needs transformers + torch. "
                "Run: python -m pip install -e './packages/maverick-core[clap]'"
            ) from e
        name = clap_model_name()
        _clap = (ClapModel.from_pretrained(name), ClapProcessor.from_pretrained(name))
        return _clap


def clap_model_name() -> str:
    """``[models] clap`` (env ``MAVERICK_CLAP_MODEL`` wins), else the default."""
    from ..env_setting import env_or_config

    return (env_or_config("MAVERICK_CLAP_MODEL", "models", "clap") or "").strip() \
        or DEFAULT_CLAP_MODEL


def embed_waveform(waveform: list[float], rate: int) -> list[float]:
    """CLAP-embed a decoded waveform."""
    model, processor = _load_clap()
    import torch
    inputs = processor(audios=waveform, sampling_rate=rate, return_tensors="pt")
    with torch.no_grad():
        feats = model.get_audio_features(**inputs)
    return [float(x) for x in feats[0]]


def clap_audio_embed(audio: bytes) -> list[float]:
    """Default audio embedder: 16-bit PCM WAV bytes -> CLAP audio embedding."""
    _load_clap()  # fail fast with the [clap] install hint before decoding
    waveform, rate = decode_wav(audio)
    return embed_waveform(waveform, rate)


def clap_text_embed(labels: list[str]) -> list[list[float]]:
    """Default text embedder: labels -> CLAP text embeddings."""
    model, processor = _load_clap()
    import torch
    inputs = processor(text=list(labels), return_tensors="pt", padding=True)
    with torch.no_grad():
        feats = model.get_text_features(**inputs)
    return [[float(x) for x in row] for row in feats]


# ---------- tool ----------

def _read_audio(args: dict[str, Any], sandbox: Any) -> bytes | str:
    src = (args.get("audio_path") or "").strip()
    if not src:
        return "ERROR: audio_path is required"
    # Confine the model-supplied path to the workspace (same rationale as
    # voice.transcribe: an unconfined source is arbitrary host-file read).
    from .ffmpeg_tool import _safe_path
    try:
        path = Path(_safe_path(sandbox, src))
    except ValueError as e:
        return f"ERROR: {e}"
    if not path.exists() or not path.is_file():
        return f"ERROR: audio file not found: {src!r}"
    limit = _audio_limit()
    if path.stat().st_size > limit:
        return (
            f"ERROR: audio file too large: {path.stat().st_size} bytes "
            f"(limit {limit}); raise MAVERICK_AUDIO_MAX_BYTES if expected"
        )
    return path.read_bytes()


def _clean_labels(raw: Any) -> list[str] | str:
    if not isinstance(raw, list) or not raw:
        return "ERROR: classify requires labels (non-empty array of strings)"
    labels = [str(item).strip() for item in raw]
    if not all(labels):
        return "ERROR: labels must be non-empty strings"
    return labels


def _run(args: dict[str, Any], sandbox: Any, audio_embed, text_embed) -> str:
    op = args.get("op") or "classify"
    if op not in ("classify", "embed"):
        return f"ERROR: unknown op {op!r}"
    audio = _read_audio(args, sandbox)
    if isinstance(audio, str):
        return audio
    try:
        audio_vec = audio_embed(audio)
        if op == "embed":
            return json.dumps([round(float(x), 5) for x in audio_vec])
        labels = _clean_labels(args.get("labels"))
        if isinstance(labels, str):
            return labels
        ranked = rank_labels(audio_vec, labels, text_embed(labels))
    except ImportError as e:
        return f"ERROR: {e}"
    except ValueError as e:
        return f"ERROR: {e}"
    top, top_score = ranked[0]
    lines = [f"top: {top} ({top_score:.4f})"]
    lines.extend(f"  {label}  {score:.4f}" for label, score in ranked)
    return "\n".join(lines)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["classify", "embed"]},
        "audio_path": {
            "type": "string",
            "description": "Audio file path (16-bit PCM WAV for the default CLAP adapter).",
        },
        "labels": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Candidate text labels to rank, e.g. ['dog barking', 'siren'].",
        },
    },
    "required": ["audio_path"],
}


def audio_understanding(
    sandbox: Any = None,
    audio_embed=None,
    text_embed=None,
) -> Tool:
    """Tool factory. ``audio_embed``/``text_embed`` are injectable for tests
    and alternative backends; the defaults lazy-load CLAP ([clap] extra)."""
    return Tool(
        name="audio_understanding",
        description=(
            "Zero-shot NON-SPEECH audio classification (CLAP). op=classify "
            "ranks free-text labels ('glass breaking', 'dog barking', ...) "
            "against a clip; op=embed returns the raw audio embedding. "
            "Needs the [clap] extra unless custom embedders are injected."
        ),
        input_schema=_SCHEMA,
        fn=lambda args: _run(
            args, sandbox, audio_embed or clap_audio_embed, text_embed or clap_text_embed
        ),
        parallel_safe=True,
    )
