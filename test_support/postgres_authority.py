"""Reusable local least-privilege PostgreSQL fixture; never exposes its DSN."""
from __future__ import annotations

import hashlib
import secrets
import uuid

import pytest
from maverick import crypto_at_rest
from maverick import postgres_transactions as pt
from maverick.governed_records import PostgresGovernedRecordBackend


class _PrivateAuthority(tuple):
    def __repr__(self):
        return "<owned local Postgres authority>"


@pytest.fixture
def authority(postgres_test_dsn, monkeypatch):
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo
    monkeypatch.setattr(pt, "_POOLS", {})
    monkeypatch.setattr(pt, "_CLOSED", False)
    monkeypatch.setattr(pt, "_CLOSER", None)
    monkeypatch.setattr(pt, "_CLOSE_FAILED", False)
    crypto_at_rest._reset_shared_key_identity_for_testing()
    key = secrets.token_bytes(32)
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", key.hex())
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY_DIGEST", "sha256:" + hashlib.sha256(key).hexdigest())
    role = "mvk_pool_" + uuid.uuid4().hex[:16]
    password = secrets.token_urlsafe(32)
    with psycopg.connect(postgres_test_dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOBYPASSRLS").format(
            sql.Identifier(role), sql.Literal(password)))
        admin.execute(sql.SQL("CREATE SCHEMA {} AUTHORIZATION {}").format(sql.Identifier(role), sql.Identifier(role)))
    dsn = make_conninfo(postgres_test_dsn, user=role, password=password, options=f"-c search_path={role}")
    def backend(namespace="pooled_records", timeout=1, *, lookup_spec=None):
        return PostgresGovernedRecordBackend(namespace, "PRB", dsn=dsn,
                                             require_bound_tenant=True,
                                             pool_size=1, pool_timeout_seconds=timeout,
                                             lookup_spec=lookup_spec)
    try:
        yield _PrivateAuthority((backend, postgres_test_dsn, role))
    finally:
        pt.close_postgres_pools(timeout=5)
        with psycopg.connect(postgres_test_dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(role)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
        crypto_at_rest._reset_shared_key_identity_for_testing()
