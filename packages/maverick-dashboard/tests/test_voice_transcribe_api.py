"""POST /api/v1/voice/transcribe — dashboard voice commands."""
from __future__ import annotations

import io

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_VOICE_COMMANDS", raising=False)
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")


def _post_audio(client, data: bytes = b"fake-webm-audio", **kw):
    return client.post(
        "/api/v1/voice/transcribe",
        files={"file": ("voice-command.webm", io.BytesIO(data), "audio/webm")},
        **kw,
    )


def test_transcribe_returns_text(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from pathlib import Path

    import maverick.tools.voice as voice_mod

    seen: dict = {}

    def _fake_transcribe(args, sandbox=None):
        seen.update(args)
        assert sandbox is None
        assert Path(args["source"]).read_bytes() == b"fake-webm-audio"
        return "  schedule a demo with acme on friday  "

    monkeypatch.setattr(voice_mod, "_run_transcribe", _fake_transcribe)
    r = _post_audio(_client())
    assert r.status_code == 200
    assert r.json() == {"text": "schedule a demo with acme on friday"}
    # The uploaded bytes were handed to the STT backend via a temp file...
    assert seen["source"].endswith(".webm")
    # ...and the temp file is gone afterwards.
    import os
    assert not os.path.exists(seen["source"])


def test_transcribe_passes_language(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    import maverick.tools.voice as voice_mod
    seen: dict = {}

    def _fake_transcribe(args, sandbox=None):
        seen.update(args)
        return "hola"

    monkeypatch.setattr(voice_mod, "_run_transcribe", _fake_transcribe)
    r = _post_audio(_client(), params={"language": "es"})
    assert r.status_code == 200
    assert seen.get("language") == "es"


def test_transcribe_503_when_no_backend(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    import maverick.tools.voice as voice_mod
    monkeypatch.setattr(
        voice_mod, "_run_transcribe",
        lambda args, sandbox=None: "ERROR: no voice backend available.",
    )
    r = _post_audio(_client())
    assert r.status_code == 503
    assert "Voice dictation isn't ready" in r.json()["detail"]
    assert "Settings > Models > Voice dictation on this computer" in r.json()["detail"]
    assert "/settings?focus=voice-model-setup" in r.json()["detail"]
    assert "pip install" not in r.json()["detail"]


def test_transcribe_rejects_empty_audio(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _post_audio(_client(), data=b"")
    assert r.status_code == 400
    assert "empty audio" in r.json()["detail"]


def test_transcribe_404_when_disabled(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_VOICE_COMMANDS", "0")
    r = _post_audio(_client())
    assert r.status_code == 404


def test_transcribe_rejects_oversized_audio(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_VOICE_MAX_BYTES", "10")
    r = _post_audio(_client(), data=b"x" * 11)
    assert r.status_code == 400
    assert "audio too large" in r.json()["detail"]


# ---- POST /api/v1/voice/speak (read-aloud) ----------------------------------

def test_speak_returns_mp3(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    import maverick.tools.voice as voice_mod

    def _fake_tts(text, voice, output):
        assert "the answer is 42" in text
        output.write_bytes(b"ID3fake-mp3-bytes")
        return True

    monkeypatch.setattr(voice_mod, "_tts_openai", _fake_tts)
    r = _client().post("/api/v1/voice/speak",
                       json={"text": "the answer is 42"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("audio/mpeg")
    assert r.content == b"ID3fake-mp3-bytes"


def test_speak_503_when_no_backend(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    import maverick.tools.voice as voice_mod
    monkeypatch.setattr(voice_mod, "_tts_openai", lambda *a: False)
    monkeypatch.setattr(voice_mod, "_tts_elevenlabs", lambda *a: False)
    r = _client().post("/api/v1/voice/speak", json={"text": "hello"})
    assert r.status_code == 503
    assert "text-to-speech" in r.json()["detail"]


def test_speak_rejects_empty_text(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _client().post("/api/v1/voice/speak", json={"text": "  "})
    assert r.status_code == 400


def test_speak_404_when_disabled(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_VOICE_COMMANDS", "0")
    r = _client().post("/api/v1/voice/speak", json={"text": "hello"})
    assert r.status_code == 404


def test_transcribe_uses_dashboard_rate_limit(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_GOALS_PER_MIN", "1")
    monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_GOALS_GLOBAL_PER_MIN", "100")
    from maverick_dashboard import app as app_mod
    app_mod._goal_times.clear()
    app_mod._goal_times_global.clear()

    import maverick.tools.voice as voice_mod
    calls = 0

    def _fake_transcribe(args, sandbox=None):
        nonlocal calls
        calls += 1
        return "ok"

    monkeypatch.setattr(voice_mod, "_run_transcribe", _fake_transcribe)
    client = _client()
    assert _post_audio(client).status_code == 200
    r = _post_audio(client)
    assert r.status_code == 429
    assert calls == 1


def test_transcribe_503_with_retry_after_while_warming(monkeypatch, tmp_path):
    """First-run warm-up in progress -> a RETRYABLE 503 (Retry-After header),
    distinct from the terminal no-backend 503 that triggers browser fallback."""
    _isolate(monkeypatch, tmp_path)
    import maverick.tools.voice as voice_mod

    def _not_reached(args, sandbox=None):
        raise AssertionError("backend dispatched while warming")

    monkeypatch.setattr(voice_mod, "_run_transcribe", _not_reached)
    voice_mod._WARMING.set()
    try:
        r = _post_audio(_client())
    finally:
        voice_mod._WARMING.clear()
    assert r.status_code == 503
    assert r.headers.get("Retry-After") == "5"
    assert "preparing" in r.json()["detail"]


def test_transcribe_no_retry_after_on_terminal_503(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    import maverick.tools.voice as voice_mod
    monkeypatch.setattr(
        voice_mod, "_run_transcribe",
        lambda args, sandbox=None: "ERROR: no voice backend available.",
    )
    r = _post_audio(_client())
    assert r.status_code == 503
    assert r.headers.get("Retry-After") is None
