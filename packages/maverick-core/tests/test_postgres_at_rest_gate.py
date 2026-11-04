"""open_world + Postgres encryption-at-rest.

The Postgres backend seals the same sensitive content columns as SQLite,
so selecting it with encryption-at-rest on OPENS the backend (and
seals on write) rather than failing closed. The full sealing round-trip +
ciphertext-on-disk proof lives in test_postgres_world.py (skipped without a DSN);
these cover the open_world dispatch without a live Postgres.
"""
from __future__ import annotations

from maverick import world_model as wm


def test_open_world_allows_postgres_with_encryption_at_rest(monkeypatch):
    # Postgres now supports at-rest sealing, so the old fail-closed gate is gone:
    # open_world proceeds to open the Postgres backend even with encryption on.
    sentinel = object()
    monkeypatch.setattr("maverick.world_model_backends.is_postgres_configured", lambda: True)
    monkeypatch.setattr("maverick.crypto_at_rest.at_rest_enabled", lambda: True)
    monkeypatch.setattr("maverick.world_model_backends.open_postgres_world", lambda: sentinel)
    assert wm.open_world() is sentinel


def test_open_world_allows_postgres_without_encryption(monkeypatch):
    sentinel = object()
    monkeypatch.setattr("maverick.world_model_backends.is_postgres_configured", lambda: True)
    monkeypatch.setattr("maverick.crypto_at_rest.at_rest_enabled", lambda: False)
    monkeypatch.setattr("maverick.world_model_backends.open_postgres_world", lambda: sentinel)
    assert wm.open_world() is sentinel


def test_open_world_sqlite_is_unaffected(tmp_path, monkeypatch):
    # The dispatch is Postgres-only; the default SQLite path is untouched.
    monkeypatch.setattr("maverick.world_model_backends.is_postgres_configured", lambda: False)
    w = wm.open_world(tmp_path / "world.db")
    try:
        assert isinstance(w, wm.WorldModel)
    finally:
        w.close()
