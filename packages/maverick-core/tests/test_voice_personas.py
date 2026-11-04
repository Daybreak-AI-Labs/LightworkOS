"""Voice persona presets + per-language voices, and the speak-tool wiring."""
from __future__ import annotations

import maverick.voice_personas as vp


def _cfg(monkeypatch, voice_table):
    import maverick.config as config_mod
    monkeypatch.setattr(config_mod, "load_config", lambda: {"voice": voice_table})


def test_persona_resolution(monkeypatch):
    _cfg(monkeypatch, {"personas": {
        "concierge": {"backend": "elevenlabs", "voice": "EXAV", "language": "en"},
    }})
    p = vp.get_persona("concierge")
    assert p.backend == "elevenlabs" and p.voice == "EXAV"
    assert vp.get_persona("ghost") is None
    assert [x.name for x in vp.list_personas()] == ["concierge"]


def test_language_map_prefix_match(monkeypatch):
    _cfg(monkeypatch, {"languages": {"fr": {"backend": "openai", "voice": "alloy"}}})
    assert vp.voice_for_language("fr").voice == "alloy"
    assert vp.voice_for_language("fr-CA").voice == "alloy"  # prefix
    assert vp.voice_for_language("ja") is None


def test_resolve_explicit_args_win(monkeypatch):
    _cfg(monkeypatch, {"personas": {"ops": {"backend": "elevenlabs", "voice": "V1"}}})
    out = vp.resolve_speech_args({"text": "hi", "persona": "ops", "voice": "explicit"})
    assert out["voice"] == "explicit"           # explicit wins
    assert out["backend"] == "elevenlabs"        # backend filled from persona
    out2 = vp.resolve_speech_args({"text": "hi", "persona": "ops"})
    assert out2["voice"] == "V1"


def test_resolve_language_fallback_and_unknown(monkeypatch):
    _cfg(monkeypatch, {"languages": {"de": {"voice": "DE1"}}})
    out = vp.resolve_speech_args({"text": "hallo", "language": "de"})
    assert out["voice"] == "DE1"
    untouched = {"text": "x", "persona": "ghost"}
    assert vp.resolve_speech_args(untouched) == untouched
    assert "persona" in untouched  # original not mutated


def test_speak_tool_applies_persona(monkeypatch, tmp_path):
    import maverick.tools.voice as voice_mod
    _cfg(monkeypatch, {"personas": {"ops": {"backend": "openai", "voice": "echo"}}})
    spoken = {}

    def _fake_tts(text, voice, output_path):
        spoken["voice"] = voice
        output_path.write_bytes(b"mp3")
        return True

    monkeypatch.setattr(voice_mod, "_tts_openai", _fake_tts)
    monkeypatch.setattr(voice_mod, "_next_output_path", lambda sb: tmp_path / "s.mp3")
    voice_mod.speak().fn({"text": "all clear", "persona": "ops"})
    assert spoken["voice"] == "echo"


def test_a_voice_picked_with_its_service_sets_both(monkeypatch):
    _cfg(monkeypatch, {"personas": {"desk": {"voice": "openai:nova"},
                                    "pinned": {"backend": "elevenlabs",
                                               "voice": "openai:nova"}},
                       "languages": {"de": {"voice": "elevenlabs:21m00Tcm4TlvDq8ikWAM"}}})
    desk = vp.get_persona("desk")
    assert (desk.backend, desk.voice) == ("openai", "nova")
    assert vp.get_persona("pinned").backend == "elevenlabs"  # an explicit service wins
    german = vp.voice_for_language("de-AT")
    assert (german.backend, german.voice) == ("elevenlabs", "21m00Tcm4TlvDq8ikWAM")
    assert vp.resolve_speech_args({"persona": "desk"})["backend"] == "openai"
