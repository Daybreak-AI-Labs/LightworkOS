"""tools/voice.py speech-to-text — whisper.cpp backend + backend routing."""
from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import maverick.tools as tools_pkg
import maverick.tools.voice as voice_mod


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    for env in ("OPENAI_API_KEY", "GROQ_API_KEY", "MAVERICK_WHISPER_CPP",
                "MAVERICK_WHISPER_CPP_MODEL", "MAVERICK_WHISPER_MODEL",
                "MAVERICK_VOICE_STT_BACKEND",
                "MAVERICK_WHISPER_OPENAI_MODEL",
                "MAVERICK_WHISPER_GROQ_MODEL",
                "MAVERICK_TTS_OPENAI_MODEL",
                "MAVERICK_TTS_ELEVENLABS_MODEL"):
        monkeypatch.delenv(env, raising=False)
    # Auto-fetch is default-ON in production; pinned off here so no unit test
    # can wander into a real ~150 MB model download.
    monkeypatch.setenv("MAVERICK_VOICE_AUTO_FETCH", "0")
    monkeypatch.setattr(voice_mod, "_LOCAL_STT_CACHE", {})


def _fake_binary(tmp_path) -> Path:
    b = tmp_path / "bin" / "whisper-cli"
    b.parent.mkdir(parents=True, exist_ok=True)
    b.write_text("#!/bin/sh\n")
    b.chmod(b.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return b


def _fake_model(monkeypatch, tmp_path) -> Path:
    m = tmp_path / "ggml-test.bin"
    m.write_bytes(b"weights")
    monkeypatch.setenv("MAVERICK_WHISPER_CPP_MODEL", str(m))
    return m


def test_hosted_voice_model_ids_are_operator_configurable(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    choices = {
        "MAVERICK_WHISPER_OPENAI_MODEL": "custom-openai-stt",
        "MAVERICK_WHISPER_GROQ_MODEL": "custom-groq-stt",
        "MAVERICK_TTS_OPENAI_MODEL": "custom-openai-tts",
        "MAVERICK_TTS_ELEVENLABS_MODEL": "custom-eleven-tts",
    }
    for environment, expected in choices.items():
        monkeypatch.setenv(environment, expected)
        assert voice_mod._hosted_model(environment, "fallback") == expected


def test_invalid_hosted_voice_model_id_uses_safe_default(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_TTS_OPENAI_MODEL", "bad\nmodel")
    assert (
        voice_mod._hosted_model("MAVERICK_TTS_OPENAI_MODEL", "tts-1")
        == "tts-1"
    )


def test_elevenlabs_voice_id_stays_one_path_segment(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("ELEVENLABS_API_KEY", "k")
    urls = []

    def _post(url, **_kw):
        urls.append(url)
        return SimpleNamespace(raise_for_status=lambda: None, content=b"mp3")

    monkeypatch.setattr(voice_mod, "_governed_sender", lambda _send: _post)
    assert voice_mod._tts_elevenlabs("hi", "../sound-generation?x=", tmp_path / "o.mp3")
    assert urls == ["https://api.elevenlabs.io/v1/text-to-speech/..%2Fsound-generation%3Fx%3D"]
    assert voice_mod._tts_elevenlabs("hi", "..", tmp_path / "p.mp3") is False


# ---- _find_whisper_cpp -------------------------------------------------------

def test_find_whisper_cpp_none_when_absent(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert voice_mod._find_whisper_cpp() is None


def test_find_whisper_cpp_env_wins(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    b = _fake_binary(tmp_path)
    monkeypatch.setenv("MAVERICK_WHISPER_CPP", str(b))
    assert voice_mod._find_whisper_cpp() == str(b)


def test_find_whisper_cpp_maverick_home_bin(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setattr("shutil.which", lambda name: None)
    b = _fake_binary(tmp_path)  # tmp_path IS maverick_home here
    assert voice_mod._find_whisper_cpp() == str(b)


# ---- _to_wav16k --------------------------------------------------------------

def test_to_wav16k_passthrough_wav_without_ffmpeg(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setattr("shutil.which", lambda name: None)
    wav = tmp_path / "clip.wav"
    wav.write_bytes(b"RIFFfake")
    assert voice_mod._to_wav16k(wav) == wav


def test_to_wav16k_none_for_webm_without_ffmpeg(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setattr("shutil.which", lambda name: None)
    webm = tmp_path / "clip.webm"
    webm.write_bytes(b"\x1aE\xdf\xa3fake")
    assert voice_mod._to_wav16k(webm) is None


def test_to_wav16k_converts_via_ffmpeg_chokepoint(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setattr("shutil.which",
                        lambda name: "/usr/bin/ffmpeg" if name == "ffmpeg" else None)
    seen: dict = {}

    def _fake_run(sandbox, argv, *, timeout=0.0, stdin=None):
        seen["argv"] = argv
        Path(argv[-1]).write_bytes(b"RIFFconverted")
        return 0, "", ""

    monkeypatch.setattr(tools_pkg, "sandbox_run", _fake_run)
    webm = tmp_path / "clip.webm"
    webm.write_bytes(b"fake")
    out = voice_mod._to_wav16k(webm)
    assert out is not None and out.suffix == ".wav" and out != webm
    assert seen["argv"][0] == "ffmpeg"
    # 16 kHz mono PCM args are present.
    joined = " ".join(seen["argv"])
    assert "-ar 16000" in joined and "-ac 1" in joined and "pcm_s16le" in joined
    out.unlink()


# ---- _whisper_cpp ------------------------------------------------------------

def _arm_whisper_cpp(monkeypatch, tmp_path, transcript="hello world"):
    """A discoverable binary + model, sandbox_run faked to emit a transcript."""
    b = _fake_binary(tmp_path)
    monkeypatch.setenv("MAVERICK_WHISPER_CPP", str(b))
    _fake_model(monkeypatch, tmp_path)
    monkeypatch.setattr(voice_mod, "_to_wav16k", lambda p: p)
    seen: dict = {}

    def _fake_run(sandbox, argv, *, timeout=0.0, stdin=None):
        seen["argv"] = argv
        assert sandbox is None
        prefix = argv[argv.index("-of") + 1]
        Path(prefix + ".txt").write_text(transcript + "\n", encoding="utf-8")
        return 0, "system info banners\n", ""

    monkeypatch.setattr(tools_pkg, "sandbox_run", _fake_run)
    return seen


def test_whisper_cpp_transcribes(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    seen = _arm_whisper_cpp(monkeypatch, tmp_path, "  hello\n whisper.cpp  ")
    audio = tmp_path / "clip.wav"
    audio.write_bytes(b"RIFFfake")
    assert voice_mod._whisper_cpp(audio, None) == "hello whisper.cpp"
    argv = seen["argv"]
    assert argv[argv.index("-l") + 1] == "auto"   # auto-detect by default
    assert argv[argv.index("-m") + 1].endswith("ggml-test.bin")


def test_whisper_cpp_passes_language(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    seen = _arm_whisper_cpp(monkeypatch, tmp_path)
    audio = tmp_path / "clip.wav"
    audio.write_bytes(b"RIFFfake")
    voice_mod._whisper_cpp(audio, "es")
    assert seen["argv"][seen["argv"].index("-l") + 1] == "es"


def test_whisper_cpp_none_without_binary(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setattr("shutil.which", lambda name: None)
    audio = tmp_path / "clip.wav"
    audio.write_bytes(b"RIFFfake")
    assert voice_mod._whisper_cpp(audio, None) is None


def test_whisper_cpp_none_without_model(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    b = _fake_binary(tmp_path / "elsewhere")
    monkeypatch.setenv("MAVERICK_WHISPER_CPP", str(b))
    audio = tmp_path / "clip.wav"
    audio.write_bytes(b"RIFFfake")

    def _boom(sandbox, argv, *, timeout=0.0, stdin=None):
        raise AssertionError("must not run without a model")

    monkeypatch.setattr(tools_pkg, "sandbox_run", _boom)
    assert voice_mod._whisper_cpp(audio, None) is None


def test_whisper_cpp_none_on_nonzero_exit(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _arm_whisper_cpp(monkeypatch, tmp_path)

    def _fail(sandbox, argv, *, timeout=0.0, stdin=None):
        return 1, "", "ggml: model load failed"

    monkeypatch.setattr(tools_pkg, "sandbox_run", _fail)
    audio = tmp_path / "clip.wav"
    audio.write_bytes(b"RIFFfake")
    assert voice_mod._whisper_cpp(audio, None) is None


# ---- _run_transcribe routing ---------------------------------------------------

def test_auto_falls_through_to_whisper_cpp(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setattr(voice_mod, "_whisper_openai", lambda p, lang: None)
    monkeypatch.setattr(voice_mod, "_whisper_groq", lambda p, lang: None)
    monkeypatch.setattr(voice_mod, "_whisper_local", lambda p, lang: None)
    monkeypatch.setattr(voice_mod, "_whisper_pywhispercpp", lambda p, lang: None)
    monkeypatch.setattr(voice_mod, "_whisper_cpp", lambda p, lang: "built-in works")
    audio = tmp_path / "clip.webm"
    audio.write_bytes(b"fake")
    assert voice_mod._run_transcribe({"source": str(audio)}, sandbox=SimpleNamespace(workdir=tmp_path)) == "built-in works"


def test_stt_backend_env_pins_local(monkeypatch, tmp_path):
    """[voice] stt_backend / env 'local' must keep audio off cloud APIs."""
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_VOICE_STT_BACKEND", "local")

    def _no_cloud(p, lang):
        raise AssertionError("cloud backend called despite stt_backend=local")

    monkeypatch.setattr(voice_mod, "_whisper_openai", _no_cloud)
    monkeypatch.setattr(voice_mod, "_whisper_groq", _no_cloud)
    monkeypatch.setattr(voice_mod, "_whisper_local", lambda p, lang: None)
    monkeypatch.setattr(voice_mod, "_whisper_pywhispercpp", lambda p, lang: None)
    monkeypatch.setattr(voice_mod, "_whisper_cpp", lambda p, lang: "local only")
    audio = tmp_path / "clip.wav"
    audio.write_bytes(b"RIFFfake")
    assert voice_mod._run_transcribe({"source": str(audio)}, sandbox=SimpleNamespace(workdir=tmp_path)) == "local only"
    # A per-call backend cannot widen the operator's on-machine pin.
    for backend in ("openai", "groq", "auto"):
        out = voice_mod._run_transcribe({"source": str(audio), "backend": backend},
                                        sandbox=SimpleNamespace(workdir=tmp_path))
        assert out.startswith("ERROR") and "pinned" in out
    # The operator's own CLI flag (trusted internal entry point) is not bound.
    monkeypatch.setattr(voice_mod, "_whisper_openai", lambda p, lang: "operator chose openai")
    assert voice_mod._run_transcribe_internal({"source": str(audio), "backend": "openai"}) == (
        "operator chose openai")


def test_explicit_arg_backend_beats_env_default(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_VOICE_STT_BACKEND", "openai")
    monkeypatch.setattr(voice_mod, "_whisper_local", lambda p, lang: None)
    monkeypatch.setattr(voice_mod, "_whisper_pywhispercpp", lambda p, lang: None)
    monkeypatch.setattr(voice_mod, "_whisper_cpp", lambda p, lang: "forced local")
    audio = tmp_path / "clip.wav"
    audio.write_bytes(b"RIFFfake")
    out = voice_mod._run_transcribe({"source": str(audio), "backend": "local"}, sandbox=SimpleNamespace(workdir=tmp_path))
    assert out == "forced local"


def test_unknown_env_backend_falls_back_to_auto(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_VOICE_STT_BACKEND", "esperanto-9000")
    assert voice_mod._default_stt_backend() == "auto"


def test_local_error_mentions_voice_setup(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setattr(voice_mod, "_whisper_local", lambda p, lang: None)
    monkeypatch.setattr(voice_mod, "_whisper_pywhispercpp", lambda p, lang: None)
    monkeypatch.setattr(voice_mod, "_whisper_cpp", lambda p, lang: None)
    audio = tmp_path / "clip.wav"
    audio.write_bytes(b"RIFFfake")
    out = voice_mod._run_transcribe({"source": str(audio), "backend": "local"}, sandbox=SimpleNamespace(workdir=tmp_path))
    assert out.startswith("ERROR:") and "maverick voice setup" in out


def test_no_backend_error_mentions_builtin_path(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setattr(voice_mod, "_whisper_openai", lambda p, lang: None)
    monkeypatch.setattr(voice_mod, "_whisper_groq", lambda p, lang: None)
    monkeypatch.setattr(voice_mod, "_whisper_local", lambda p, lang: None)
    monkeypatch.setattr(voice_mod, "_whisper_pywhispercpp", lambda p, lang: None)
    monkeypatch.setattr(voice_mod, "_whisper_cpp", lambda p, lang: None)
    audio = tmp_path / "clip.wav"
    audio.write_bytes(b"RIFFfake")
    out = voice_mod._run_transcribe({"source": str(audio)}, sandbox=SimpleNamespace(workdir=tmp_path))
    assert out.startswith("ERROR: no voice backend available")
    assert "maverick voice setup" in out


def test_temp_wav_cleaned_up_after_run(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    b = _fake_binary(tmp_path)
    monkeypatch.setenv("MAVERICK_WHISPER_CPP", str(b))
    _fake_model(monkeypatch, tmp_path)
    converted = tmp_path / "converted.wav"
    converted.write_bytes(b"RIFFconverted")
    monkeypatch.setattr(voice_mod, "_to_wav16k", lambda p: converted)

    def _fake_run(sandbox, argv, *, timeout=0.0, stdin=None):
        prefix = argv[argv.index("-of") + 1]
        Path(prefix + ".txt").write_text("ok", encoding="utf-8")
        return 0, "", ""

    monkeypatch.setattr(tools_pkg, "sandbox_run", _fake_run)
    audio = tmp_path / "clip.webm"
    audio.write_bytes(b"fake")
    assert voice_mod._whisper_cpp(audio, None) == "ok"
    assert not converted.exists()  # temp conversion product removed
    assert audio.exists()          # caller's input untouched


def test_whisper_cpp_keeps_passthrough_input(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _arm_whisper_cpp(monkeypatch, tmp_path)
    audio = tmp_path / "clip.wav"
    audio.write_bytes(b"RIFFfake")
    voice_mod._whisper_cpp(audio, None)
    assert audio.exists()  # passthrough (wav == input) must never be deleted


def test_run_transcribe_local_end_to_end(monkeypatch, tmp_path):
    """End-to-end through _run_transcribe with the real argv assembly."""
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setattr(voice_mod, "_whisper_local", lambda p, lang: None)
    monkeypatch.setattr(voice_mod, "_whisper_pywhispercpp", lambda p, lang: None)
    seen = _arm_whisper_cpp(monkeypatch, tmp_path, "end to end")
    audio = tmp_path / "clip.wav"
    audio.write_bytes(b"RIFFfake")
    out = voice_mod._run_transcribe(
        {"source": str(audio), "backend": "local", "language": "en"}, sandbox=SimpleNamespace(workdir=tmp_path))
    assert out == "end to end"
    assert seen["argv"][seen["argv"].index("-l") + 1] == "en"
    assert os.path.basename(seen["argv"][0]) == "whisper-cli"


def test_transcript_starting_with_error_marker_remains_successful_data(monkeypatch, tmp_path):
    from maverick import attachments
    from maverick.tool_results import ToolResultState, classify_tool_result

    _isolate(monkeypatch, tmp_path)
    monkeypatch.setattr(voice_mod, "_whisper_local", lambda _path, _lang: "ERROR: this is a spoken sentence")
    audio = tmp_path / "clip.wav"
    audio.write_bytes(b"RIFFfake")
    output = voice_mod._run_transcribe({"source": str(audio), "backend": "local"}, sandbox=SimpleNamespace(workdir=tmp_path))
    assert output == "ERROR: this is a spoken sentence"
    assert classify_tool_result(output) is ToolResultState.SUCCEEDED
    monkeypatch.setattr(voice_mod, "_default_stt_backend", lambda: "local")
    assert attachments._transcribe_media(audio) == "ERROR: this is a spoken sentence"


# ---- _whisper_pywhispercpp -----------------------------------------------------

class _FakeSegment:
    def __init__(self, text):
        self.text = text


class _FakePywhisperModel:
    instances = 0

    def __init__(self, model_path, **kwargs):
        type(self).instances += 1
        self.model_path = model_path
        self.kwargs = kwargs
        self.calls: list[tuple] = []

    def transcribe(self, media, language=""):
        self.calls.append((media, language))
        return [_FakeSegment(" hello "), _FakeSegment("pywhisper ")]


def _arm_pywhispercpp(monkeypatch, tmp_path):
    """Route `from pywhispercpp.model import Model` to the fake, with a model
    file on disk and no ffmpeg dependency."""
    import sys
    import types

    _FakePywhisperModel.instances = 0
    fake = types.ModuleType("pywhispercpp.model")
    fake.Model = _FakePywhisperModel
    monkeypatch.setitem(sys.modules, "pywhispercpp.model", fake)
    model_file = _fake_model(monkeypatch, tmp_path)
    monkeypatch.setattr(voice_mod, "_to_wav16k", lambda p: p)
    return model_file


def test_pywhispercpp_transcribes(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    model_file = _arm_pywhispercpp(monkeypatch, tmp_path)
    audio = tmp_path / "clip.wav"
    audio.write_bytes(b"RIFFfake")
    assert voice_mod._whisper_pywhispercpp(audio, None) == "hello  pywhisper"
    model = next(iter(voice_mod._LOCAL_STT_CACHE.values()))
    assert model.model_path == str(model_file)  # OUR pinned model, not its own downloader
    assert model.calls[0][1] == ""              # "" = whisper.cpp auto-detect


def test_pywhispercpp_caches_model_across_calls(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _arm_pywhispercpp(monkeypatch, tmp_path)
    audio = tmp_path / "clip.wav"
    audio.write_bytes(b"RIFFfake")
    voice_mod._whisper_pywhispercpp(audio, "en")
    voice_mod._whisper_pywhispercpp(audio, "en")
    assert _FakePywhisperModel.instances == 1  # weights loaded once, not per click


def test_pywhispercpp_none_without_model_file(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    import sys
    import types
    fake = types.ModuleType("pywhispercpp.model")
    fake.Model = _FakePywhisperModel
    monkeypatch.setitem(sys.modules, "pywhispercpp.model", fake)
    audio = tmp_path / "clip.wav"
    audio.write_bytes(b"RIFFfake")
    # No GGML anywhere and auto-fetch pinned off -> engine skipped, no crash.
    assert voice_mod._whisper_pywhispercpp(audio, None) is None


def test_run_transcribe_prefers_pywhispercpp_over_cli(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setattr(voice_mod, "_whisper_openai", lambda p, lang: None)
    monkeypatch.setattr(voice_mod, "_whisper_groq", lambda p, lang: None)
    monkeypatch.setattr(voice_mod, "_whisper_local", lambda p, lang: None)
    monkeypatch.setattr(voice_mod, "_whisper_pywhispercpp",
                        lambda p, lang: "wheel engine")

    def _cli_not_reached(p, lang):
        raise AssertionError("CLI binary tried before the in-process engine")

    monkeypatch.setattr(voice_mod, "_whisper_cpp", _cli_not_reached)
    audio = tmp_path / "clip.wav"
    audio.write_bytes(b"RIFFfake")
    assert voice_mod._run_transcribe({"source": str(audio)}, sandbox=SimpleNamespace(workdir=tmp_path)) == "wheel engine"


# ---- warm_up_local_stt / stt_warming -------------------------------------------

def test_warm_up_noop_with_cloud_key(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-x")

    def _boom():
        raise AssertionError("must not touch model store when a cloud key exists")

    monkeypatch.setattr("maverick.voice_models.locate_model", _boom)
    assert voice_mod.warm_up_local_stt() is True
    assert voice_mod.stt_warming() is False


def test_warm_up_preloads_pywhispercpp_engine(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _arm_pywhispercpp(monkeypatch, tmp_path)
    assert voice_mod.warm_up_local_stt() is True
    assert _FakePywhisperModel.instances == 1   # engine resident before first click
    assert voice_mod.stt_warming() is False     # flag cleared afterwards
    # The first real click reuses the warmed instance.
    audio = tmp_path / "clip.wav"
    audio.write_bytes(b"RIFFfake")
    voice_mod._whisper_pywhispercpp(audio, None)
    assert _FakePywhisperModel.instances == 1


def test_warm_up_sets_warming_flag_while_provisioning(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    observed: dict = {}

    def _slow_locate():
        observed["warming_during"] = voice_mod.stt_warming()
        return None

    monkeypatch.setattr("maverick.voice_models.locate_model", _slow_locate)
    monkeypatch.setattr("shutil.which", lambda name: None)
    import sys
    monkeypatch.setitem(sys.modules, "pywhispercpp.model", None)
    monkeypatch.setitem(sys.modules, "faster_whisper", None)
    assert voice_mod.warm_up_local_stt() is False  # nothing usable -> honest False
    assert observed["warming_during"] is True
    assert voice_mod.stt_warming() is False


def test_warm_up_never_raises(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)

    def _explode():
        raise RuntimeError("disk full")

    monkeypatch.setattr("maverick.voice_models.locate_model", _explode)
    assert voice_mod.warm_up_local_stt() is False
    assert voice_mod.stt_warming() is False


def test_voice_cli_transcribes_operator_selected_file(monkeypatch, tmp_path):
    from click.testing import CliRunner
    from maverick.cli import main

    _isolate(monkeypatch, tmp_path)
    audio = tmp_path / "clip.wav"
    audio.write_bytes(b"RIFFfake")
    monkeypatch.setattr(voice_mod, "_whisper_local", lambda path, _lang: path.read_bytes().decode())
    result = CliRunner().invoke(main, ["voice", "transcribe", str(audio), "--backend", "local"])
    assert result.exit_code == 0, result.output
    assert "RIFFfake" in result.output


# ---------- voice tools ----------

def test_voice_transcribe_requires_source():
    from maverick.tools.voice import transcribe_audio
    out = transcribe_audio().fn({"source": ""})
    assert "source is required" in out


def test_voice_transcribe_missing_file(tmp_path):
    from types import SimpleNamespace

    from maverick.tools.voice import transcribe_audio
    out = transcribe_audio(sandbox=SimpleNamespace(workdir=tmp_path)).fn(
        {"source": str(tmp_path / "missing.mp3")}
    )
    assert "not found" in out


def test_voice_speak_requires_text():
    from maverick.tools.voice import speak
    out = speak().fn({"text": ""})
    assert "text is required" in out


def test_voice_speak_caps_text_length():
    from maverick.tools.voice import speak
    out = speak().fn({"text": "x" * 5000})
    assert "too long" in out


def test_hosted_speech_from_the_tool_is_charged_per_character_and_needs_a_budget(monkeypatch, tmp_path):
    # Kernel rule 3: ElevenLabs speech made by the speak tool is charged to the
    # run at the [budget.tool_prices] per-character price. A speak tool with no
    # run budget refuses before sending; the dashboard's own use (no run) is
    # not charged.
    import pytest
    from maverick import config
    from maverick.budget import Budget

    _isolate(monkeypatch, tmp_path)
    (tmp_path / "config.toml").write_text(
        '[budget.tool_prices]\nelevenlabs = { dollars = 0.001, per = "character" }\n',
        encoding="utf-8")
    config.reset_config_cache()
    monkeypatch.setenv("ELEVENLABS_API_KEY", "k")
    sent = []

    def _post(url, **kw):
        sent.append(kw["json"]["text"])
        return SimpleNamespace(raise_for_status=lambda: None, content=b"mp3")

    monkeypatch.setattr(voice_mod, "_governed_sender", lambda _send: _post)
    sandbox = SimpleNamespace(workdir=str(tmp_path))
    budget = Budget()
    out = voice_mod.speak(sandbox, budget=budget).fn({"text": "hello there", "backend": "elevenlabs"})
    assert out.startswith("wrote") and budget.dollars == pytest.approx(0.011)
    out = voice_mod.speak(sandbox).fn({"text": "hello", "backend": "elevenlabs"})
    assert out.startswith("ERROR") and "nothing was sent" in out and len(sent) == 1
    assert voice_mod._tts_elevenlabs("unmetered", None, tmp_path / "d.mp3") and len(sent) == 2
    assert budget.dollars == pytest.approx(0.011)


def test_auto_speech_to_text_falls_back_to_local_when_the_run_cannot_pay(monkeypatch, tmp_path):
    # With the default auto backend, a hosted service the run cannot pay for
    # (here no run budget) is skipped for the local engine; a call that asks
    # for the hosted service by name is refused instead.
    from types import SimpleNamespace as NS

    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    audio = tmp_path / "a.wav"
    audio.write_bytes(b"RIFF")
    created = []

    class _OpenAI:
        def __init__(self, **_kw):
            self.audio = NS(transcriptions=NS(create=lambda **kw: created.append(kw) or NS(text="cloud")))

    import sys
    import types
    fake = types.ModuleType("openai")
    fake.OpenAI = _OpenAI
    monkeypatch.setitem(sys.modules, "openai", fake)
    monkeypatch.setattr(voice_mod, "_whisper_local", lambda p, lang: "local words")
    tool = voice_mod.transcribe_audio(NS(workdir=str(tmp_path)))
    assert "local words" in tool.fn({"source": "a.wav"})
    out = tool.fn({"source": "a.wav", "backend": "openai"})
    assert out.startswith("ERROR") and "nothing was sent" in out and created == []


def test_hosted_speech_to_text_holds_the_audio_length_and_reads_usage_seconds(monkeypatch, tmp_path):
    # The audio length is read from the file before sending, so the hold is
    # what the call can cost and a sibling call still fits. OpenAI reports
    # the seconds in usage.seconds (UsageDuration); the charge uses them.
    import sys
    import types
    import wave
    from types import SimpleNamespace as NS

    import pytest
    from maverick import config
    from maverick.budget import Budget
    from openai.types.audio import Transcription

    _isolate(monkeypatch, tmp_path)
    (tmp_path / "config.toml").write_text(
        '[budget.tool_prices]\nopenai_whisper = { dollars = 0.0001, per = "second" }\n',
        encoding="utf-8")
    config.reset_config_cache()
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    with wave.open(str(tmp_path / "a.wav"), "wb") as audio:
        audio.setnchannels(1)
        audio.setsampwidth(2)
        audio.setframerate(8000)
        audio.writeframes(b"\0\0" * 8000 * 12)
    budget = Budget(max_dollars=2.0)
    held = []

    def create(**_kw):
        held.append(budget._reserved)
        budget.release(budget.reserve(0.05))  # a sibling call still fits
        return Transcription.model_validate({"text": "twelve seconds",
                                             "usage": {"type": "duration", "seconds": 12}})

    class _OpenAI:
        def __init__(self, **_kw):
            self.audio = NS(transcriptions=NS(create=create))

    fake = types.ModuleType("openai")
    fake.OpenAI = _OpenAI
    monkeypatch.setitem(sys.modules, "openai", fake)
    tool = voice_mod.transcribe_audio(NS(workdir=str(tmp_path)), budget=budget)
    assert "twelve seconds" in tool.fn({"source": "a.wav", "backend": "openai"})
    # The hold is what the file's size allows at the lowest speech bitrate.
    size = (tmp_path / "a.wav").stat().st_size
    assert held == [pytest.approx(size * 8 / 6000 * 0.0001)]
    assert budget.dollars == pytest.approx(0.0012)


def _float32_wav(path, seconds: int, *, claimed_seconds: int | None = None) -> None:
    """A WAV in IEEE-float format (tag 3), which the wave module refuses.
    ``claimed_seconds`` writes a data-chunk size smaller than the data."""
    import struct

    rate = 8000
    data = b"\0\0\0\0" * rate * seconds
    claimed = len(data) if claimed_seconds is None else 4 * rate * claimed_seconds
    fmt = struct.pack("<HHIIHH", 3, 1, rate, rate * 4, 4, 32)
    body = b"WAVE" + b"fmt " + struct.pack("<I", len(fmt)) + fmt + b"data" + struct.pack("<I", claimed) + data
    path.write_bytes(b"RIFF" + struct.pack("<I", len(body)) + body)


def _fake_openai(monkeypatch, create):
    import sys
    import types
    from types import SimpleNamespace as NS

    class _OpenAI:
        def __init__(self, **_kw):
            self.audio = NS(transcriptions=NS(create=create))

    fake = types.ModuleType("openai")
    fake.OpenAI = _OpenAI
    monkeypatch.setitem(sys.modules, "openai", fake)


def test_audio_headers_never_crash_or_shrink_the_hold(monkeypatch, tmp_path):
    # A float32 WAV still transcribes for a caller outside a run; a malformed
    # MP3 does not crash the length reader; and a header claiming 1 second
    # over 600 seconds of audio cannot shrink the hold below its real cost.
    import io
    from types import SimpleNamespace as NS

    import pytest
    from maverick import config
    from maverick.budget import Budget
    from maverick.tools._audio_length import audio_seconds
    from openai.types.audio import Transcription

    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    _float32_wav(tmp_path / "f.wav", 2)
    _fake_openai(monkeypatch, lambda **_kw: Transcription.model_validate({"text": "float words"}))
    assert "float words" in voice_mod._run_transcribe_internal(
        {"source": str(tmp_path / "f.wav"), "backend": "openai"})
    bad_mp3 = b"\xff\xfb\xf0\x00" + b"\0" * 64  # bitrate index 15
    assert audio_seconds(io.BytesIO(bad_mp3), len(bad_mp3)) is None
    assert audio_seconds(io.BytesIO(b"fLaC"), 4) is None

    (tmp_path / "config.toml").write_text(
        '[budget.tool_prices]\nopenai_whisper = { dollars = 0.0001, per = "second" }\n',
        encoding="utf-8")
    config.reset_config_cache()
    _float32_wav(tmp_path / "long.wav", 600, claimed_seconds=1)
    budget = Budget(max_dollars=2.0)
    held = []

    def create(**_kw):
        held.append(budget._reserved)
        return Transcription.model_validate({"text": "long", "usage": {"type": "duration", "seconds": 600}})

    _fake_openai(monkeypatch, create)
    tool = voice_mod.transcribe_audio(NS(workdir=str(tmp_path)), budget=budget)
    assert "long" in tool.fn({"source": "long.wav", "backend": "openai"})
    assert held[0] >= 600 * 0.0001
    assert budget.dollars == pytest.approx(0.06)
