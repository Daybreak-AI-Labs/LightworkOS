"""`maverick encryption backup-key` and the strict-mode nudge after migrate."""
from __future__ import annotations

import importlib.util

import pytest
from click.testing import CliRunner
from maverick import crypto_at_rest as car
from maverick.cli import main

requires_crypto = pytest.mark.skipif(
    importlib.util.find_spec("cryptography") is None,
    reason="cryptography extra is not installed",
)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.delenv("MAVERICK_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("MAVERICK_ENCRYPT_STRICT", raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    monkeypatch.setattr(car, "_KEY_PATH", tmp_path / "keys" / "at_rest.key")


def test_backup_key_copies_material(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    car._load_or_create_key()
    dest = tmp_path / "escrow"
    res = CliRunner().invoke(main, ["encryption", "backup-key", "--to", str(dest)])
    assert res.exit_code == 0, res.output
    assert "at_rest.key" in res.output
    assert (dest / "at_rest.key").exists()


def test_backup_key_errors_without_key(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    res = CliRunner().invoke(main, ["encryption", "backup-key",
                                    "--to", str(tmp_path / "escrow")])
    assert res.exit_code != 0
    assert "no at-rest key material" in res.output


@requires_crypto
def test_migrate_nudges_strict_mode(monkeypatch, tmp_path):
    from maverick.world_model import WorldModel
    monkeypatch.setattr("maverick.world_model.DEFAULT_DB", tmp_path / "world.db")

    db = tmp_path / "world.db"
    wm = WorldModel(db)
    wm.create_goal("plain title", "d")     # plaintext (encryption off)
    wm.conn.close()

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    res = CliRunner().invoke(main, ["--db", str(db), "encryption", "migrate"])
    assert res.exit_code == 0, res.output
    assert "strict = true" in res.output


@requires_crypto
def test_migrate_dry_run_does_not_nudge_strict(monkeypatch, tmp_path):
    from maverick.world_model import WorldModel

    db = tmp_path / "world.db"
    wm = WorldModel(db)
    wm.create_goal("plain title", "d")
    wm.conn.close()

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    res = CliRunner().invoke(main, ["--db", str(db), "encryption", "migrate",
                                    "--dry-run"])
    assert res.exit_code == 0, res.output
    assert "strict = true" not in res.output
