"""Deployment recovery evidence can be inspected from another tenant context."""
from __future__ import annotations


def test_recovery_uses_deployment_key_and_context_only_binding(monkeypatch, tmp_path):
    from maverick import crypto_at_rest as crypto
    from maverick.paths import tenant_scope
    from maverick_dashboard import webhook_settings_recovery as recovery

    monkeypatch.setattr(recovery, "_directory", lambda: tmp_path / "recovery")
    monkeypatch.setattr(crypto, "per_tenant_at_rest", lambda: True)
    monkeypatch.setattr(crypto, "_active_keyring_key", lambda: None)
    monkeypatch.setattr(crypto, "_keyring_dir", lambda: tmp_path / "keyring")
    monkeypatch.setattr(crypto, "_load_or_create_key", lambda: b"d" * 32)
    monkeypatch.setattr(crypto, "_load_existing_key", lambda: b"d" * 32)
    monkeypatch.setattr("maverick.tenant.kms.tenant_dek", lambda tenant: b"t" * 32)
    row = {"id": "a" * 32, "purpose": recovery._PURPOSE, "revision": 1, "state": "prepared"}
    with tenant_scope(tenant="alpha"):
        recovery._save(row)
    with tenant_scope(tenant="beta"):
        assert recovery._load(row["id"]) == row
