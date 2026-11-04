"""Tests for the anki tool. No network calls."""
from __future__ import annotations

from maverick.tools import anki


def test_missing_op_errors():
    assert anki.anki().fn({}).startswith("ERROR: op is required")


def test_unknown_op_errors():
    assert anki.anki().fn({"op": "nope"}).startswith("ERROR: unknown op")


def test_add_note_requires_deck():
    out = anki.anki().fn({"op": "add_note", "front": "f", "back": "b"})
    assert out.startswith("ERROR")
    assert "requires deck" in out


def test_add_note_requires_front_and_back():
    out = anki.anki().fn({"op": "add_note", "deck": "Default", "front": "f"})
    assert out.startswith("ERROR")
    assert "front and back" in out


def test_build_payload_basic():
    p = anki._build_payload("deckNames")
    assert p == {"action": "deckNames", "version": 6, "params": {}}


def test_build_add_note_payload():
    p = anki._build_add_note_payload("MyDeck", "Q", "A")
    assert p["action"] == "addNote"
    assert p["version"] == 6
    note = p["params"]["note"]
    assert note["deckName"] == "MyDeck"
    assert note["modelName"] == "Basic"
    assert note["fields"] == {"Front": "Q", "Back": "A"}
    assert note["options"]["allowDuplicate"] is False


def test_endpoint_env_override(monkeypatch):
    monkeypatch.delenv("ANKI_CONNECT_URL", raising=False)
    assert anki._endpoint() == "http://127.0.0.1:8765"
    monkeypatch.setenv("ANKI_CONNECT_URL", "http://host:9000")
    assert anki._endpoint() == "http://host:9000"


def test_add_note_uses_invoke(monkeypatch):
    seen = {}

    def fake_invoke(payload):
        seen["payload"] = payload
        return 1234567890, None

    monkeypatch.setattr(anki, "_invoke", fake_invoke)
    out = anki.anki().fn(
        {"op": "add_note", "deck": "D", "front": "f", "back": "b"}
    )
    assert "added note 1234567890 to D" in out
    assert seen["payload"]["action"] == "addNote"


def test_decks_surfaces_error(monkeypatch):
    monkeypatch.setattr(anki, "_invoke", lambda p: (None, "collection not open"))
    out = anki.anki().fn({"op": "decks"})
    assert out.startswith("ERROR: AnkiConnect")
    assert "collection not open" in out


def test_tool_is_not_parallel_safe():
    assert anki.anki().parallel_safe is False
