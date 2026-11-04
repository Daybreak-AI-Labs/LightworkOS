"""Tenant/principal isolation for LLM cache and browser credential vault."""
from __future__ import annotations

import sqlite3
import time

import pytest

pytest.importorskip("cryptography")

from maverick import browser_auth_vault as browser_vault  # noqa: E402
from maverick.cache import llm as llm_cache  # noqa: E402
from maverick.connections import bind_principal  # noqa: E402
from maverick.file_lock import (  # noqa: E402
    ensure_private_directory,
    private_path_is_restricted,
)
from maverick.paths import tenant_scope  # noqa: E402


def _store(cache: llm_cache.LLMCache, key: str, text: str) -> None:
    cache.store(key, provider="test", model="test", text=text)


def test_llm_default_db_and_registry_follow_context_switches(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))

    with tenant_scope(tenant="tenant-a"), bind_principal("user:alice"):
        cache_a = llm_cache.get()
        _store(cache_a, "same-prompt", "tenant-a")
        path_a = cache_a.db_path

    with tenant_scope(tenant="tenant-b"), bind_principal("user:alice"):
        cache_b = llm_cache.get()
        path_b = cache_b.db_path
        assert cache_b is not cache_a
        assert cache_b.lookup("same-prompt") is None
        _store(cache_b, "same-prompt", "tenant-b")

    assert path_a != path_b
    assert "tenant-a" in str(path_a)
    assert "tenant-b" in str(path_b)
    with tenant_scope(tenant="tenant-a"), bind_principal("user:alice"):
        assert llm_cache.get() is cache_a
        assert cache_a.lookup("same-prompt").text == "tenant-a"


def test_llm_explicit_shared_db_scopes_every_operation(tmp_path):
    db = tmp_path / "private-cache" / "responses.sqlite3"
    cache = llm_cache.LLMCache(db, ttl_seconds=1)

    with tenant_scope(tenant="tenant-a"), bind_principal("user:alice"):
        _store(cache, "same-prompt", "alice")
        assert cache.stats()["entries"] == 1

    # Reusing the exact same object and physical DB under another authority
    # must not grant access to the first authority's row.
    with tenant_scope(tenant="tenant-a"), bind_principal("user:alice "):
        assert cache.lookup("same-prompt") is None
        _store(cache, "same-prompt", "alice-with-space")
        assert cache.stats()["entries"] == 1
        assert cache.purge_expired(now=time.time() + 2) == 1
        assert cache.stats()["entries"] == 0

    with tenant_scope(tenant="tenant-a"), bind_principal("user:alice"):
        assert cache.lookup("same-prompt").text == "alice"
        assert cache.stats()["entries"] == 1
        cache.clear()
        assert cache.stats()["entries"] == 0


def test_llm_db_and_wal_parent_are_private(tmp_path):
    db = tmp_path / "private-cache" / "responses.sqlite3"
    cache = llm_cache.LLMCache(db)

    assert private_path_is_restricted(db.parent, 0o700)
    assert private_path_is_restricted(db)
    with cache._conn():
        sidecars = [path for path in (db.with_name(db.name + "-wal"),
                                     db.with_name(db.name + "-shm"))
                    if path.exists()]
        assert sidecars
        assert all(private_path_is_restricted(path) for path in sidecars)


def test_llm_legacy_unscoped_rows_are_not_adopted(tmp_path):
    parent = ensure_private_directory(tmp_path / "legacy-cache")
    db = parent / "responses.sqlite3"
    with sqlite3.connect(db) as conn:
        conn.executescript(
            """
            CREATE TABLE responses (
              key TEXT PRIMARY KEY,
              provider TEXT NOT NULL,
              model TEXT NOT NULL,
              text TEXT NOT NULL,
              thinking TEXT NOT NULL DEFAULT '',
              stop_reason TEXT NOT NULL DEFAULT '',
              created_at REAL NOT NULL,
              hit_count INTEGER NOT NULL DEFAULT 0
            );
            INSERT INTO responses
              (key, provider, model, text, created_at)
            VALUES ('legacy-key', 'test', 'test', 'legacy-secret', 1.0);
            """
        )

    cache = llm_cache.LLMCache(db)
    assert cache.lookup("legacy-key") is None
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM responses").fetchone()[0] == 0


def test_browser_vault_tenant_switch_never_reuses_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_VAULT_KEY", raising=False)

    with tenant_scope(tenant="tenant-a"), bind_principal("user:alice"):
        assert "sealed entry" in browser_vault._run(
            {"op": "store", "name": "reports", "data": {"cookie": "a"}}
        )
        key_a, data_a = browser_vault._default_paths()
        assert browser_vault._run({"op": "list"}) == "reports"

    with tenant_scope(tenant="tenant-b"), bind_principal("user:alice"):
        key_b, data_b = browser_vault._default_paths()
        assert browser_vault._run({"op": "list"}) == "(vault empty)"
        assert "sealed entry" in browser_vault._run(
            {"op": "store", "name": "reports", "data": {"cookie": "b"}}
        )

    assert key_a != key_b
    assert data_a != data_b
    with tenant_scope(tenant="tenant-a"), bind_principal("user:alice"):
        assert browser_vault._run({"op": "list"}) == "reports"
        assert "loaded 'reports'" in browser_vault._run(
            {"op": "load", "name": "reports"}
        )


def test_browser_vault_exact_principals_are_isolated_and_private(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_VAULT_KEY", raising=False)

    with tenant_scope(tenant="tenant-a"), bind_principal("user:alice"):
        browser_vault._run(
            {"op": "store", "name": "reports", "data": {"cookie": "a"}}
        )
        key_a, data_a = browser_vault._default_paths()

    with tenant_scope(tenant="tenant-a"), bind_principal("user:alice "):
        key_b, data_b = browser_vault._default_paths()
        assert browser_vault._run({"op": "list"}) == "(vault empty)"

    assert key_a != key_b
    assert data_a != data_b
    assert private_path_is_restricted(data_a.parent, 0o700)
    assert private_path_is_restricted(key_a)
    assert private_path_is_restricted(data_a)
