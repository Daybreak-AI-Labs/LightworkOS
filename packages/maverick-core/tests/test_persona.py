"""Persona tests."""
from __future__ import annotations

import tempfile
from pathlib import Path

from maverick.persona import STYLES, load_persona, render_persona_prompt


def test_no_config_returns_empty(monkeypatch):
    monkeypatch.setenv("MAVERICK_CONFIG", "/nonexistent/path.toml")
    p = load_persona()
    assert p == {"name": "", "style": "", "addendum": "", "user_name": ""}
    assert render_persona_prompt() == ""


def test_full_persona(monkeypatch):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(
            '[persona]\n'
            'name = "Atlas"\n'
            'style = "concise"\n'
            'addendum = "Always cite sources with URLs."\n'
        )
        path = Path(f.name)
    try:
        monkeypatch.setenv("MAVERICK_CONFIG", str(path))
        prompt = render_persona_prompt()
        assert "Atlas" in prompt
        assert STYLES["concise"] in prompt
        assert "cite sources" in prompt
        assert prompt.startswith("\n\n# Persona\n\n")
    finally:
        path.unlink()


def test_partial_persona_name_only(monkeypatch):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write('[persona]\nname = "Lightwork"\n')
        path = Path(f.name)
    try:
        monkeypatch.setenv("MAVERICK_CONFIG", str(path))
        prompt = render_persona_prompt()
        assert "Lightwork" in prompt
        # No style or addendum content.
        for s in STYLES.values():
            assert s not in prompt
    finally:
        path.unlink()


def test_unknown_style_skipped_but_warns(monkeypatch, caplog):
    import logging

    import maverick.persona as persona
    persona._warned_styles.clear()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write('[persona]\nname = "X"\nstyle = "concice"\n')  # typo of "concise"
        path = Path(f.name)
    try:
        monkeypatch.setenv("MAVERICK_CONFIG", str(path))
        with caplog.at_level(logging.WARNING, logger="maverick.persona"):
            prompt = render_persona_prompt()
        # Name still present; unknown style dropped, but now with a nudge.
        assert "X" in prompt
        assert "concice" in caplog.text and "not recognized" in caplog.text
        # Valid values are listed so the typo is fixable.
        assert "concise" in caplog.text
    finally:
        path.unlink()


def test_unknown_style_warns_once(monkeypatch, caplog):
    import logging

    import maverick.persona as persona
    persona._warned_styles.clear()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write('[persona]\nstyle = "nope"\n')
        path = Path(f.name)
    try:
        monkeypatch.setenv("MAVERICK_CONFIG", str(path))
        with caplog.at_level(logging.WARNING, logger="maverick.persona"):
            render_persona_prompt()
            render_persona_prompt()
        # Misconfig logs at most once per process, not on every agent build.
        assert caplog.text.count("not recognized") == 1
    finally:
        path.unlink()


class TestPersonaStyleCasing:
    def test_style_case_insensitive(self, monkeypatch):
        from maverick import persona
        # Pick a real style key, upper-cased, and confirm it still applies.
        key = next(iter(persona.STYLES))
        monkeypatch.setattr(
            persona, "load_persona",
            lambda: {"name": "", "style": key.upper(), "addendum": ""},
        )
        rendered = persona.render_persona_prompt()
        assert persona.STYLES[key] in rendered
