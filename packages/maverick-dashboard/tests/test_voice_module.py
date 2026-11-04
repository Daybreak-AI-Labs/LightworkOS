"""The dashboard's browser-voice fallback goes through the natural-voice
layer (lightwork-voice.js), never the bare default utterance."""
from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
_TPL = Path(__file__).resolve().parents[1] / "maverick_dashboard"


def test_voice_module_served_with_ranking_and_humanizer():
    r = client.get("/static/lightwork-voice.js")
    assert r.status_code == 200
    for marker in ("lwVoice", "voiceschanged", "MAX_CHUNK",
                   "Article ", "G D P R"):
        assert marker in r.text


def test_base_loads_module_and_chat_fallback_uses_it():
    base = (_TPL / "templates" / "base.html").read_text(encoding="utf-8")
    assert "asset('lightwork-voice.js')" in base      # versioned /static/lightwork-voice.js link
    chat = (_TPL / "templates" / "chat_goal.html").read_text(encoding="utf-8")
    assert "asset('lightwork-read-aloud.js')" in chat
    controller = client.get("/static/lightwork-read-aloud.js")
    assert controller.status_code == 200
    # Only the result's own declared language may influence playback. Unknown
    # user content is never rewritten with the interface language's prose.
    assert "window.lwVoice.humanize(text, contentLanguage)" in controller.text
    assert "window.lwVoice.best(contentLanguage)" in controller.text
    assert "source.getAttribute('lang') || 'und'" in controller.text
    assert "utterance.voice = voice" in controller.text
