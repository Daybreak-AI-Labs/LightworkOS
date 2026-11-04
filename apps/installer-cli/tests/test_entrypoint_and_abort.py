"""Regression tests for the standalone entry point and clean-abort handling.

Two bugs these pin:
  1. ``maverick-init --fast`` / ``--resume`` were silently ignored: the
     console script called ``run()`` with no argument parsing, so the
     flags did nothing.
  2. questionary returns ``None`` on Ctrl-C / Ctrl-D / no-TTY. Every
     prompt call site then did ``.split()`` / ``.strip()`` on it and
     crashed with an opaque ``AttributeError`` traceback instead of a
     clean abort.
"""
from __future__ import annotations

import pytest

# ---------- entry point flag parsing ----------

def test_main_passes_fast_flag(monkeypatch):
    from maverick_installer import main as m
    captured: dict = {}
    monkeypatch.setattr(m, "run", lambda **kw: captured.update(kw) or 0)
    assert m.main(["--fast"]) == 0
    assert captured == {"fast": True, "resume": False}


def test_main_passes_resume_flag(monkeypatch):
    from maverick_installer import main as m
    captured: dict = {}
    monkeypatch.setattr(m, "run", lambda **kw: captured.update(kw) or 0)
    assert m.main(["--resume"]) == 0
    assert captured == {"fast": False, "resume": True}


def test_main_defaults_no_flags(monkeypatch):
    from maverick_installer import main as m
    captured: dict = {}
    monkeypatch.setattr(m, "run", lambda **kw: captured.update(kw) or 0)
    assert m.main([]) == 0
    assert captured == {"fast": False, "resume": False}


def test_main_aborts_cleanly_on_keyboard_interrupt(monkeypatch, capsys):
    from maverick_installer import main as m

    def _boom(**kw):
        raise KeyboardInterrupt

    monkeypatch.setattr(m, "run", _boom)
    rc = m.main([])
    assert rc == 130
    assert "Aborted" in capsys.readouterr().out


def test_main_aborts_cleanly_on_eof(monkeypatch, capsys):
    from maverick_installer import main as m

    def _boom(**kw):
        raise EOFError

    monkeypatch.setattr(m, "run", _boom)
    rc = m.main([])
    assert rc == 130
    assert "Aborted" in capsys.readouterr().out


def test_main_rejects_unknown_flag(monkeypatch):
    from maverick_installer import main as m
    # argparse exits(2) on unknown args instead of silently ignoring them.
    with pytest.raises(SystemExit) as exc:
        m.main(["--nope"])
    assert exc.value.code == 2


# ---------- prompt primitives abort instead of crashing ----------

class _NullPrompt:
    """Mimics a questionary prompt whose .ask() returns None (abort)."""

    def ask(self):
        return None


@pytest.fixture
def _require_questionary():
    from maverick_installer import wizard
    if wizard.questionary is None:  # pragma: no cover -- questionary is a dep
        pytest.skip("questionary not installed")
    return wizard


def test_q_select_aborts_on_none(monkeypatch, _require_questionary):
    wizard = _require_questionary
    monkeypatch.setattr(wizard.questionary, "select", lambda *a, **k: _NullPrompt())
    with pytest.raises(KeyboardInterrupt):
        wizard._q_select("Pick one", ["a", "b"])


def test_q_text_aborts_on_none(monkeypatch, _require_questionary):
    wizard = _require_questionary
    monkeypatch.setattr(wizard.questionary, "text", lambda *a, **k: _NullPrompt())
    with pytest.raises(KeyboardInterrupt):
        wizard._q_text("Your name")


def test_q_confirm_aborts_on_none(monkeypatch, _require_questionary):
    wizard = _require_questionary
    monkeypatch.setattr(wizard.questionary, "confirm", lambda *a, **k: _NullPrompt())
    with pytest.raises(KeyboardInterrupt):
        wizard._q_confirm("Proceed?")


def test_q_checkbox_aborts_on_none(monkeypatch, _require_questionary):
    wizard = _require_questionary
    monkeypatch.setattr(wizard.questionary, "checkbox", lambda *a, **k: _NullPrompt())
    with pytest.raises(KeyboardInterrupt):
        wizard._q_checkbox("Pick some", ["a", "b"])


def test_pick_mode_aborts_cleanly_not_attributeerror(monkeypatch, _require_questionary):
    """The original crash: pick_mode().split() on a None result."""
    wizard = _require_questionary
    monkeypatch.setattr(wizard.questionary, "select", lambda *a, **k: _NullPrompt())
    with pytest.raises(KeyboardInterrupt):
        wizard.pick_mode()


# ---------- checkbox pre-checks its defaults ----------

class _ConstPrompt:
    """Mimics a questionary prompt whose .ask() returns a fixed value."""

    def __init__(self, value):
        self._value = value

    def ask(self):
        return self._value


def test_q_checkbox_prechecks_defaults(monkeypatch, _require_questionary):
    """Defaults must be passed to questionary as pre-checked Choice objects."""
    wizard = _require_questionary
    seen: dict = {}

    def fake_checkbox(message, choices, **kw):
        seen["choices"] = choices
        return _ConstPrompt(["a"])

    monkeypatch.setattr(wizard.questionary, "checkbox", fake_checkbox)
    out = wizard._q_checkbox("Pick", ["a", "b", "c"], default=["a"])
    assert out == ["a"]
    # The choice matching the default must be a checked Choice; the others not.
    by_title = {getattr(c, "title", c): c for c in seen["choices"]}
    assert getattr(by_title["a"], "checked", False) is True
    assert getattr(by_title["b"], "checked", False) is False
