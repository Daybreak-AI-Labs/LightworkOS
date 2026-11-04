"""Anonymization must be salted and tenant-scoped.

An unsalted sha256(value)[:12] would be rainbow-tableable for common
identifiers, and the SAME id under two tenants would produce identical hashes
(cross-tenant correlation in anonymized logs). anonymize_field is an HMAC keyed
with a persistent per-deployment salt and mixed with the active tenant -- still
deterministic within a deployment.
"""
from __future__ import annotations

import hashlib

import pytest
from maverick.file_lock import private_path_is_restricted
from maverick.privacy import _hash_id, anonymize_field


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    import maverick.privacy as privacy
    privacy._anon_salt_cache = None  # force a fresh salt under this tmp home
    yield
    privacy._anon_salt_cache = None


def test_anon_is_deterministic_within_deployment():
    assert anonymize_field("user_id", "alice123") == anonymize_field("user_id", "alice123")


def test_anon_is_not_the_unsalted_sha256():
    out = anonymize_field("user_id", "alice123")
    assert hashlib.sha256(b"alice123").hexdigest()[:12] not in out


def test_anon_differs_across_tenants():
    from maverick.paths import reset_tenant, set_tenant

    def _hash_under(tenant: str) -> str:
        tok = set_tenant(tenant)
        try:
            return _hash_id("alice123", "user")
        finally:
            reset_tenant(tok)

    # same id, different tenant -> no cross-tenant correlation
    assert _hash_under("acme") != _hash_under("beta")


def test_anon_salt_persisted_0600(tmp_path):
    anonymize_field("user_id", "alice123")  # triggers salt creation
    from maverick.paths import data_dir
    p = data_dir("keys", "anon.salt", tenant=None)
    assert p.exists() and private_path_is_restricted(p)
    assert private_path_is_restricted(p.parent, 0o700)
