"""Voice persona presets + multi-language voice.

Two knobs the voice surface was missing:

* **Personas** — named TTS configurations an operator defines once and the
  agent (or a channel) selects by name: "concierge" is the warm ElevenLabs
  voice, "ops" is the terse OpenAI alloy. A persona bundles backend + voice
  id (+ optional language), so changing the deployment's sound is a config
  edit, not a prompt change::

      [voice.personas.concierge]
      backend = "elevenlabs"
      voice = "EXAVITQu4vr4xnSDxMaL"
      language = "en"

* **Multi-language voice** — a per-language voice map so spoken replies in
  French use a French-appropriate voice without the model micromanaging ids::

      [voice.languages]
      fr = { backend = "openai", voice = "alloy" }
      ja = { backend = "elevenlabs", voice = "<ja-voice-id>" }

The dashboard writes a voice picked from a list as ``voice = "openai:alloy"``
(backend and voice in one value); an explicit ``backend`` still wins.

Resolution order for a speak call: explicit ``voice``/``backend`` args win
(unchanged behavior) → ``persona`` → ``language`` map → defaults. Pure
config reading; fail-soft (an unknown persona returns None and the caller
falls back rather than erroring a goal)."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VoicePreset:
    name: str
    backend: str | None = None
    voice: str | None = None
    language: str | None = None


_TTS_BACKENDS = ("openai", "elevenlabs")


def _preset(name: str, raw: dict, language: str | None) -> VoicePreset:
    backend = str(raw.get("backend") or "") or None
    voice = str(raw.get("voice") or "") or None
    if voice:
        prefix, sep, rest = voice.partition(":")
        if sep and prefix in _TTS_BACKENDS and rest:
            voice = rest
            backend = backend or prefix
    return VoicePreset(name=name, backend=backend, voice=voice, language=language)


def _voice_cfg() -> dict:
    try:
        from .config import load_config
        return (load_config() or {}).get("voice") or {}
    except Exception:  # pragma: no cover -- config never blocks speech
        return {}


def get_persona(name: str) -> VoicePreset | None:
    """The named persona, or None (caller falls back; never raises)."""
    if not name:
        return None
    personas = _voice_cfg().get("personas") or {}
    raw = personas.get(str(name).strip())
    if not isinstance(raw, dict):
        return None
    return _preset(str(name).strip(), raw, str(raw.get("language") or "") or None)


def list_personas() -> list[VoicePreset]:
    personas = _voice_cfg().get("personas") or {}
    out = []
    for name, raw in sorted(personas.items()):
        if isinstance(raw, dict):
            p = get_persona(name)
            if p:
                out.append(p)
    return out


def voice_for_language(language: str) -> VoicePreset | None:
    """The configured voice for a BCP-47-ish language code (prefix match)."""
    if not language:
        return None
    langs = _voice_cfg().get("languages") or {}
    code = str(language).strip().lower()
    raw = langs.get(code) or langs.get(code.split("-")[0])
    if not isinstance(raw, dict):
        return None
    return _preset(f"lang:{code}", raw, code)


def resolve_speech_args(args: dict) -> dict:
    """Apply persona/language resolution to a speak-tool args dict.

    Explicit ``voice``/``backend`` always win (unchanged behavior). Returns a
    NEW dict; the original is untouched. Unknown persona/language resolve to
    no change — speech must degrade to defaults, never fail."""
    out = dict(args)
    preset = None
    if args.get("persona"):
        preset = get_persona(str(args["persona"]))
    if preset is None and args.get("language"):
        preset = voice_for_language(str(args["language"]))
    if preset is None:
        return out
    if not out.get("voice") and preset.voice:
        out["voice"] = preset.voice
    if (not out.get("backend") or out.get("backend") == "auto") and preset.backend:
        out["backend"] = preset.backend
    return out


__all__ = ["VoicePreset", "get_persona", "list_personas",
           "voice_for_language", "resolve_speech_args"]
