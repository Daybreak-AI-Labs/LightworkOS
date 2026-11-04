"""Voice biometric unlock — companion factor ONLY.

Speaker verification for voice channels: enroll a speaker's voice profile,
then score later utterances against it and gate *convenience* actions on a
match. Three hard stances, stated up front because biometrics invite
overreach:

1. **Never a sole factor.** A voice match may *unlock convenience* (skip
   re-typing a PIN for low-risk actions); it must never be the only gate on a
   sensitive action — replay/synthesis attacks are practical, and the
   docstring-level contract is that callers combine it with an existing
   factor (allowlist + consent). ``VoiceGate.decide`` therefore returns
   ``companion_ok``, never "authenticated".
2. **Local only, deletable, sealed.** Profiles are embeddings (never raw
   audio), each sealed with the deployment's at-rest key and bound to its
   person and workspace (``crypto_at_rest.seal_bound``), in a local 0600
   store; ``delete_profile`` is first-class (biometric data is erasable by
   design). A profile copied to another person does not open.
3. **Opt-in.** ``[voice] biometric_unlock = true`` (env
   ``MAVERICK_VOICE_UNLOCK`` wins, either way) required; default off.

The embedding comes from an ``embedder(audio_bytes) -> vector``
(:class:`SpeakerEmbedder`). The live one, :class:`EcapaEmbedder`, runs the
SpeechBrain ECAPA-TDNN speaker model from the folder at ``[voice]
speaker_model_path`` on this server (never downloaded at run time) and needs
the optional ``voice-unlock`` extra (``speechbrain``, ``torch``,
``torchaudio``); :func:`readiness` says plainly what is missing. Tests inject
a deterministic stub. The match threshold is ``[voice] unlock_threshold``
(default 0.6: the ECAPA model scored another recording of the enrolled
speaker around 0.7 and a different speaker around 0).
"""
from __future__ import annotations

import base64
import importlib.util
import io
import json
import math
import os
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

DEFAULT_THRESHOLD = 0.80
LIVE_DEFAULT_THRESHOLD = 0.6
_MIN_ENROLL_SAMPLES = 3
EXTRA = "voice-unlock"
_EXTRA_MODULES = ("speechbrain", "torch", "torchaudio")
_SAMPLE_RATE = 16_000

# embedder(audio_bytes) -> embedding vector.
SpeakerEmbedder = Callable[[bytes], Sequence[float]]


class VoiceUnlockUnavailable(RuntimeError):
    """Voice unlock can't run here; ``str(exc)`` is a sentence for people."""


def enabled() -> bool:
    raw = os.environ.get("MAVERICK_VOICE_UNLOCK", "").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    try:
        from .config import load_config
        return bool(((load_config() or {}).get("voice") or {})
                    .get("biometric_unlock", False))
    except Exception:  # pragma: no cover
        return False


def _voice_config() -> dict:
    try:
        from .config import load_config
        return (load_config() or {}).get("voice") or {}
    except Exception:  # pragma: no cover -- config never blocks
        return {}


def speaker_model_path() -> str:
    """``[voice] speaker_model_path``: the folder holding the speaker model."""
    return str(_voice_config().get("speaker_model_path") or "").strip()


def unlock_threshold() -> float:
    """``[voice] unlock_threshold`` (0.3 to 0.99), default 0.6."""
    raw = _voice_config().get("unlock_threshold", LIVE_DEFAULT_THRESHOLD)
    try:
        value = LIVE_DEFAULT_THRESHOLD if isinstance(raw, bool) else float(raw)
    except (TypeError, ValueError):
        value = LIVE_DEFAULT_THRESHOLD
    if not math.isfinite(value):
        value = LIVE_DEFAULT_THRESHOLD
    return min(max(value, 0.3), 0.99)


def extra_installed() -> bool:
    """The optional ``voice-unlock`` extra (speechbrain, torch, torchaudio)."""
    return all(importlib.util.find_spec(name) is not None for name in _EXTRA_MODULES)


def readiness(model_path: str | None = None) -> str | None:
    """None when voice unlock can run, else the plain reason it can't."""
    if not extra_installed():
        return ("Voice unlock needs the voice-unlock add-on, which is not installed on "
                "this server. Install it with: pip install 'maverick-agent[voice-unlock]'.")
    folder = (model_path if model_path is not None else speaker_model_path()).strip()
    if not folder:
        return ("Voice unlock needs a speaker-recognition model. Choose the folder that "
                "holds it under Settings > All settings > Speaker-recognition model.")
    if not (Path(folder).expanduser() / "hyperparams.yaml").is_file():
        return ("The speaker-recognition model folder has no model in it. Download "
                "speechbrain/spkrec-ecapa-voxceleb into that folder.")
    return None


def _wav_mono_16k(audio: bytes):
    """PCM WAV bytes -> a (1, samples) float tensor at 16 kHz. The dashboard
    records 16 kHz mono WAV; other WAV rates are resampled."""
    import wave

    import torch
    import torchaudio

    try:
        with wave.open(io.BytesIO(audio)) as clip:
            channels, width, rate = clip.getnchannels(), clip.getsampwidth(), clip.getframerate()
            frames = clip.readframes(clip.getnframes())
    except (wave.Error, EOFError) as exc:
        raise ValueError("send the recording as a WAV file") from exc
    if width != 2 or not frames:
        raise ValueError("send the recording as 16-bit WAV")
    samples = torch.frombuffer(bytearray(frames), dtype=torch.int16).float() / 32768.0
    samples = samples.view(-1, channels).mean(dim=1).unsqueeze(0)
    if rate != _SAMPLE_RATE:
        samples = torchaudio.functional.resample(samples, rate, _SAMPLE_RATE)
    return samples


class EcapaEmbedder:
    """SpeechBrain ECAPA-TDNN speaker embeddings from a local model folder.

    Loaded once per folder, CPU only, never fetched from the network: the
    model's ``pretrained_path`` is pointed at the folder itself.
    """

    def __init__(self, model_dir: str | Path):
        self.model_dir = str(Path(model_dir).expanduser())
        self._model = None
        self._lock = threading.Lock()

    def _load(self):
        with self._lock:
            if self._model is None:
                try:
                    from speechbrain.inference.speaker import EncoderClassifier
                except ImportError:  # speechbrain < 1.0
                    from speechbrain.pretrained import EncoderClassifier
                kwargs = {}
                try:
                    from speechbrain.utils.fetching import LocalStrategy
                    kwargs["local_strategy"] = LocalStrategy.NO_LINK
                except ImportError:  # pragma: no cover -- older speechbrain
                    pass
                self._model = EncoderClassifier.from_hparams(
                    source=self.model_dir, savedir=self.model_dir,
                    run_opts={"device": "cpu"},
                    overrides={"pretrained_path": self.model_dir}, **kwargs,
                )
            return self._model

    def __call__(self, audio: bytes) -> list[float]:
        import torch

        model = self._load()
        with torch.no_grad():
            return [float(x) for x in model.encode_batch(_wav_mono_16k(audio)).flatten()]


_embedders: dict[str, EcapaEmbedder] = {}
_embedders_lock = threading.Lock()


def configured_embedder() -> SpeakerEmbedder:
    """The live embedder, or :class:`VoiceUnlockUnavailable` with the reason."""
    reason = readiness()
    if reason:
        raise VoiceUnlockUnavailable(reason)
    folder = str(Path(speaker_model_path()).expanduser())
    with _embedders_lock:
        if folder not in _embedders:
            _embedders[folder] = EcapaEmbedder(folder)
        return _embedders[folder]


def live_gate(embedder: SpeakerEmbedder | None = None) -> VoiceGate:
    """The gate the dashboard uses: the configured embedder and threshold."""
    return VoiceGate(embedder or configured_embedder(), threshold=unlock_threshold())


def _seal_centroid(speaker: str, centroid: list[float]) -> str:
    from .crypto_at_rest import EncryptionUnavailable, seal_bound

    try:
        blob = seal_bound(json.dumps(centroid).encode("utf-8"), f"voice-profile:{speaker}")
    except EncryptionUnavailable as exc:
        raise VoiceUnlockUnavailable(
            "Voice profiles are stored encrypted, and encryption is not available on "
            "this server.") from exc
    return base64.b64encode(blob).decode("ascii")


def _open_centroid(speaker: str, entry: dict) -> list[float] | None:
    sealed = entry.get("sealed")
    if isinstance(sealed, str):
        from .crypto_at_rest import EncryptionUnavailable, unseal_bound

        try:
            raw = unseal_bound(base64.b64decode(sealed), f"voice-profile:{speaker}")
        except (EncryptionUnavailable, ValueError):
            return None  # another person's or workspace's profile never opens
        return [float(x) for x in json.loads(raw)]
    legacy = entry.get("centroid")  # written before profiles were sealed
    return [float(x) for x in legacy] if isinstance(legacy, list) else None


def _cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    return dot / (na * nb) if na and nb else 0.0


def _centroid(vecs: list[list[float]]) -> list[float]:
    n = len(vecs)
    return [sum(v[i] for v in vecs) / n for i in range(len(vecs[0]))]


@dataclass(frozen=True)
class GateDecision:
    companion_ok: bool        # the voice factor passed (NEVER sole auth)
    score: float
    reason: str


class VoiceGate:
    """Enrollment + scoring + policy over an injected speaker embedder."""

    def __init__(self, embedder, *, store_path: Path | None = None,
                 threshold: float = DEFAULT_THRESHOLD):
        self._embed = embedder
        self._threshold = float(threshold)
        self._owns_parent = store_path is None
        if self._owns_parent:
            from .paths import data_dir
            store_path = data_dir("voice_profiles.json")
        self._path = Path(store_path)
        # Serializes the profile-store load-modify-save in-process; the
        # cross_process_lock in _locked() extends it across processes.
        self._lock = threading.Lock()

    def _ensure_parent(self) -> None:
        # The profile dir holds biometric data: it must be 0700. Create it here
        # so it exists at 0700 BEFORE the lock sidecar / temp land in it -- the
        # lock's own mkdir would otherwise create it at the default 0755.
        from .file_lock import ensure_private_directory, require_private_directory

        if self._owns_parent or not self._path.parent.exists():
            ensure_private_directory(self._path.parent)
        else:
            require_private_directory(self._path.parent)

    def _locked(self):
        from contextlib import ExitStack

        from .file_lock import cross_process_lock
        self._ensure_parent()
        with ExitStack() as stack:
            stack.enter_context(self._lock)
            stack.enter_context(cross_process_lock(self._path, strict=True))
            return stack.pop_all()

    # -- store --------------------------------------------------------------

    def _load(self) -> dict:
        try:
            from .file_lock import atomic_read_text, ensure_private_file

            ensure_private_file(self._path)
            return json.loads(atomic_read_text(self._path))
        except (OSError, ValueError):
            return {}

    def _save(self, data: dict) -> None:
        self._ensure_parent()
        from .file_lock import atomic_write_text

        atomic_write_text(self._path, json.dumps(data))

    # -- enrollment ----------------------------------------------------------

    def enroll(self, speaker: str, samples: list[bytes]) -> int:
        """Enroll from >= 3 utterances (a single sample over-fits noise).
        Stores ONLY the embedding centroid, never audio."""
        if len(samples) < _MIN_ENROLL_SAMPLES:
            raise ValueError(
                f"enrollment needs >= {_MIN_ENROLL_SAMPLES} samples, "
                f"got {len(samples)}")
        vecs = [list(map(float, self._embed(s))) for s in samples]
        if len({len(v) for v in vecs}) != 1:
            raise ValueError("embedder returned inconsistent dimensions")
        # Whole load-modify-save under the lock so a concurrent enroll/delete of
        # another speaker can't clobber this one (last-writer-wins on the dict).
        sealed = _seal_centroid(speaker, _centroid(vecs))
        with self._locked():
            data = self._load()
            data[speaker] = {"sealed": sealed, "enrolled_at": time.time(),
                             "samples": len(samples)}
            self._save(data)
        return len(vecs[0])

    def delete_profile(self, speaker: str) -> bool:
        """Erase a speaker's biometric profile (first-class by design)."""
        with self._locked():
            data = self._load()
            if speaker not in data:
                return False
            del data[speaker]
            self._save(data)
        return True

    def profiles(self) -> list[str]:
        return sorted(self._load())

    # -- verification ----------------------------------------------------------

    def score(self, speaker: str, audio: bytes) -> float | None:
        """Cosine similarity vs the enrolled centroid; None if unenrolled."""
        entry = self._load().get(speaker)
        centroid = _open_centroid(speaker, entry) if isinstance(entry, dict) else None
        if not centroid:
            return None
        vec = list(map(float, self._embed(audio)))
        return _cosine(vec, centroid)

    def decide(self, speaker: str, audio: bytes) -> GateDecision:
        """The companion-factor decision. ``companion_ok`` is True only when
        the feature is enabled, the speaker is enrolled, and the score clears
        the threshold — and it NEVER means "authenticated" on its own."""
        if not enabled():
            return GateDecision(False, 0.0,
                                "voice unlock disabled ([voice] biometric_unlock)")
        s = self.score(speaker, audio)
        if s is None:
            return GateDecision(False, 0.0, f"{speaker!r} not enrolled")
        if s >= self._threshold:
            return GateDecision(True, round(s, 4),
                                "voice factor matched (companion factor only — "
                                "combine with an existing factor)")
        return GateDecision(False, round(s, 4),
                            f"score {s:.3f} below threshold {self._threshold}")


__all__ = [
    "DEFAULT_THRESHOLD", "EXTRA", "LIVE_DEFAULT_THRESHOLD", "EcapaEmbedder",
    "GateDecision", "SpeakerEmbedder", "VoiceGate", "VoiceUnlockUnavailable",
    "configured_embedder", "enabled", "extra_installed", "live_gate", "readiness",
    "speaker_model_path", "unlock_threshold",
]
