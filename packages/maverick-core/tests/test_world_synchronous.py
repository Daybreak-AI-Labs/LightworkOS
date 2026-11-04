"""Durability knob: PRAGMA synchronous defaults to NORMAL but can be raised to
FULL for regulated deployments that treat the world DB as the Operating Record."""
from __future__ import annotations

import maverick.world_model as wm
from maverick.world_model import WorldModel, _synchronous_mode


def _pragma(db) -> int:
    w = WorldModel(db)
    try:
        return w.conn.execute("PRAGMA synchronous").fetchone()[0]
    finally:
        w.close()


def test_default_is_normal(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_WORLD_SYNCHRONOUS", raising=False)
    monkeypatch.setattr("maverick.config.load_config", dict)
    assert _synchronous_mode() == "NORMAL"
    assert _pragma(tmp_path / "w.db") == 1  # 1 == NORMAL


def test_env_full(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_WORLD_SYNCHRONOUS", "full")
    assert _synchronous_mode() == "FULL"
    assert _pragma(tmp_path / "w.db") == 2  # 2 == FULL


def test_config_full(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_WORLD_SYNCHRONOUS", raising=False)
    monkeypatch.setattr("maverick.config.load_config",
                        lambda: {"world_model": {"synchronous": "FULL"}})
    assert _synchronous_mode() == "FULL"
    assert _pragma(tmp_path / "w.db") == 2


def test_bad_value_falls_back_to_normal(monkeypatch):
    monkeypatch.setenv("MAVERICK_WORLD_SYNCHRONOUS", "OFF")  # not exposed
    assert _synchronous_mode() == "NORMAL"
    monkeypatch.setenv("MAVERICK_WORLD_SYNCHRONOUS", "garbage")
    assert _synchronous_mode() == "NORMAL"


def test_module_has_sync_modes():
    assert "FULL" in wm._SYNC_MODES and "OFF" not in wm._SYNC_MODES
