"""Tests for the killswitch (maverick.killswitch)."""
from __future__ import annotations

import pytest

# ---------- killswitch ----------

def test_killswitch_no_halt_initially(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(tmp_path / "HALT"))
    import maverick.killswitch as ks
    ks._last_file_check_ts = 0.0  # bust the cache
    ks.clear()
    ks.check()  # should not raise


def test_killswitch_file_trigger(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(tmp_path / "HALT"))
    import maverick.killswitch as ks
    ks._last_file_check_ts = 0.0
    ks.clear()
    (tmp_path / "HALT").write_text("operator stop")
    with pytest.raises(ks.Halted) as exc:
        ks.check()
    assert exc.value.source == "file"


def test_killswitch_in_process_trigger(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(tmp_path / "HALT"))
    import maverick.killswitch as ks
    ks._last_file_check_ts = 0.0
    ks.clear()
    ks.halt("budget exceeded", source="manual")
    try:
        with pytest.raises(ks.Halted) as exc:
            ks.check()
        assert exc.value.reason == "budget exceeded"
    finally:
        ks.clear()


def test_killswitch_is_active(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(tmp_path / "HALT"))
    import maverick.killswitch as ks
    ks._last_file_check_ts = 0.0
    ks.clear()
    assert ks.is_active() is False
    ks.halt("test")
    try:
        assert ks.is_active() is True
    finally:
        ks.clear()


def test_killswitch_default_path_follows_current_home(tmp_path, monkeypatch):
    """The default HALT path must track the *current* home, not the home
    that happened to be set when the module was imported.

    Regression: ``DEFAULT_HALT_FILE`` was a module-level constant evaluated
    at import time, so a process (or test) that re-homed after import kept
    watching the stale home's HALT file -- silently defeating the killswitch
    in exactly the safety-critical module. With no ``MAVERICK_HALT_FILE``
    override, dropping a HALT file in the *new* home must halt.
    """
    import maverick.killswitch as ks

    monkeypatch.delenv("MAVERICK_HALT_FILE", raising=False)
    # The repo-root autouse fixture pins MAVERICK_HOME (which takes precedence
    # over HOME in maverick_home()). Clear it here so this test exercises the
    # HOME -> ~/.maverick resolution it is specifically about.
    monkeypatch.delenv("MAVERICK_HOME", raising=False)
    new_home = tmp_path / "rehomed"
    (new_home / ".maverick").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(new_home))
    monkeypatch.setenv("USERPROFILE", str(new_home))  # Windows home

    ks._last_file_check_ts = 0.0  # bust the 1s stat cache
    ks.clear()
    # Path is resolved against the new home, not a frozen import-time one.
    assert ks._halt_file_path() == new_home / ".maverick" / "HALT"

    (new_home / ".maverick" / "HALT").write_text("operator stop")
    ks._last_file_check_ts = 0.0
    with pytest.raises(ks.Halted) as exc:
        ks.check()
    assert exc.value.source == "file"
