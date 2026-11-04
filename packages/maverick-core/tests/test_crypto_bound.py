"""Context-bound sealing and the per-tenant key default."""
from __future__ import annotations

import pytest
from maverick import crypto_at_rest as c
from maverick.paths import tenant_scope


def test_bound_blob_opens_only_for_same_tenant_and_context():
    blob = c.seal_bound(b"payroll", "attachment/1/a.csv")
    assert c.is_bound(blob) and b"payroll" not in blob
    assert c.unseal_bound(blob, "attachment/1/a.csv") == b"payroll"
    with pytest.raises(c.EncryptionUnavailable):
        c.unseal_bound(blob, "attachment/2/a.csv")
    with tenant_scope(tenant="acme"), pytest.raises(c.EncryptionUnavailable):
        c.unseal_bound(blob, "attachment/1/a.csv")
    tampered = blob[:-1] + bytes([blob[-1] ^ 1])
    with pytest.raises(c.EncryptionUnavailable):
        c.unseal_bound(tampered, "attachment/1/a.csv")
    with pytest.raises(c.EncryptionUnavailable):
        c.unseal_bound(blob[:20], "attachment/1/a.csv")


def test_bound_blobs_survive_key_rotation():
    before = c.seal_bound(b"old", "ctx")
    c.rotate_at_rest_key()
    after = c.seal_bound(b"new", "ctx")
    assert before[8:16] != after[8:16]  # different embedded key ids
    assert c.unseal_bound(before, "ctx") == b"old"
    assert c.unseal_bound(after, "ctx") == b"new"


def test_per_tenant_mode_uses_the_tenant_key(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "1")
    monkeypatch.setenv("MAVERICK_KMS_KEK", "27" * 32)  # synthetic test key
    from maverick.tenant import kms
    monkeypatch.setattr(kms, "_dek_cache", {})
    with tenant_scope(tenant="acme"):
        blob = c.seal_bound(b"acme data", "ctx")
        assert blob[len(c._BOUND_MAGIC):len(c._BOUND_MAGIC) + 1] == b"T"
        assert c.unseal_bound(blob, "ctx") == b"acme data"
    with tenant_scope(tenant="beta"), pytest.raises(c.EncryptionUnavailable):
        c.unseal_bound(blob, "ctx")


@pytest.mark.parametrize("enterprise,config,env,expected", [
    (True, {}, None, False),                       # opt-in even in enterprise mode:
    (False, {}, None, False),                      # tenant DEKs are per host
    (True, {"per_tenant": True}, None, True),      # explicit config
    (False, {"per_tenant": "yes"}, None, True),
    (True, {"per_tenant": True}, "0", False),      # env wins over everything
])
def test_per_tenant_keys_are_opt_in(monkeypatch, enterprise, config, env, expected):
    import maverick.config as config_mod
    import maverick.enterprise as ent
    if env is None:
        monkeypatch.delenv("MAVERICK_ENCRYPT_PER_TENANT", raising=False)
    else:
        monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", env)
    monkeypatch.setattr(config_mod, "load_config", lambda: {"encryption": config})
    monkeypatch.setattr(ent, "enterprise_enabled", lambda: enterprise)
    assert c.per_tenant_at_rest() is expected


def test_portable_seals_use_the_deployment_key_even_in_per_tenant_mode(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "1")
    monkeypatch.setenv("MAVERICK_KMS_KEK", "27" * 32)  # synthetic test key
    from maverick.tenant import kms
    monkeypatch.setattr(kms, "_dek_cache", {})
    with tenant_scope(tenant="acme"):
        blob = c.seal_bound(b"mirror me", "ctx", portable=True)
        assert blob[len(c._BOUND_MAGIC):len(c._BOUND_MAGIC) + 1] == b"K"
        monkeypatch.setattr(kms, "_dek_cache", {})
        monkeypatch.setattr(kms, "tenant_dek", lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("another host has no tenant DEK")))
        assert c.unseal_bound(blob, "ctx") == b"mirror me"
    with tenant_scope(tenant="beta"), pytest.raises(c.EncryptionUnavailable):
        c.unseal_bound(blob, "ctx")                  # tenant still bound via AAD


def test_tenant_binding_uses_the_canonical_id_and_separates_unbound():
    import unicodedata
    nfd, nfc = unicodedata.normalize("NFD", "jos\u00e9"), "jos\u00e9"
    with tenant_scope(tenant=nfd):
        blob = c.seal_bound(b"x", "ctx")
    with tenant_scope(tenant=nfc):
        assert c.unseal_bound(blob, "ctx") == b"x"
    unbound = c.seal_bound(b"y", "ctx")
    with tenant_scope(tenant="__default__"), pytest.raises(c.EncryptionUnavailable):
        c.unseal_bound(unbound, "ctx")
