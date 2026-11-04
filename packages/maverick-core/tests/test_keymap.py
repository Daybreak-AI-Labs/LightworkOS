"""TUI keymap: validation rails, config merge, key->action mapping."""
from __future__ import annotations

from maverick import keymap as km


def test_defaults_cover_every_action():
    assert set(km.DEFAULTS) == set(km.ACTIONS)
    assert km.validate(km.DEFAULTS) == []


def test_validate_rejects_conflicts_and_unknowns():
    assert any("conflict" in p for p in km.validate(
        {"quit": "x", "refresh": "x"}))
    assert any("unknown action" in p for p in km.validate({"fly": "x"}))
    assert any("invalid key" in p for p in km.validate({"quit": "notakey"}))


def test_ctrl_c_is_reserved():
    problems = km.validate({"quit": "ctrl+c"})
    assert any("reserved" in p for p in problems)


def test_resolve_merges_valid_overrides(monkeypatch):
    monkeypatch.setenv("MAVERICK_TUI_KEYS", "quit=x,refresh=g")
    b = km.resolve()
    assert b["quit"] == "x" and b["refresh"] == "g"
    assert b["expand"] == "enter"  # untouched default


def test_resolve_drops_bad_override_set(monkeypatch):
    # an override that conflicts with a default falls back to stock entirely
    monkeypatch.setenv("MAVERICK_TUI_KEYS", "quit=r")  # collides with refresh
    assert km.resolve() == km.DEFAULTS


def test_handle_key_maps_to_action(monkeypatch):
    monkeypatch.delenv("MAVERICK_TUI_KEYS", raising=False)
    monkeypatch.setattr("maverick.config.load_config", dict)
    assert km.handle_key("q") == "quit"
    assert km.handle_key("DOWN") == "focus_next"
    assert km.handle_key("z") is None


def test_named_function_keys_valid():
    assert km.validate({"refresh": "f5"}) == []


def test_render_lists_reserved():
    out = km.render(km.DEFAULTS)
    assert "ctrl+c" in out and "not rebindable" in out
