"""Per-tenant envelope encryption: DEK-per-tenant wrapped by a KMS KEK."""
from __future__ import annotations

import importlib.util

import pytest

requires_crypto = pytest.mark.skipif(
    importlib.util.find_spec("cryptography") is None,
    reason="cryptography extra is not installed",
)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_KMS_KEK", "ab" * 32)  # deterministic 32-byte KEK
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick.tenant import kms as tenant_kms
    tenant_kms._clear_cache()
    yield
    tenant_kms._clear_cache()


@requires_crypto
def test_seal_unseal_round_trip_per_tenant():
    from maverick.tenant import kms as k
    blob = k.seal_text_for_tenant("acme", "secret invoice")
    assert k.unseal_text_for_tenant("acme", blob) == "secret invoice"


def test_cloud_kms_provider_fails_closed_not_silent_local(monkeypatch):
    # Configuring an HSM-backed provider that isn't wired must REFUSE, not
    # silently hand back the in-process LocalKMS (a hidden at-rest downgrade).
    import maverick.config as cfg
    from maverick.crypto_at_rest import EncryptionUnavailable
    from maverick.tenant.kms import LocalKMS, get_kms
    monkeypatch.setattr(cfg, "load_config", dict)
    assert isinstance(get_kms(), LocalKMS)  # default stays local
    for provider in ("aws", "gcp", "vault"):
        monkeypatch.setattr(cfg, "load_config", lambda p=provider: {"kms": {"provider": p}})
        with pytest.raises(EncryptionUnavailable):
            get_kms()


@requires_crypto
def test_one_tenant_cannot_open_anothers_data(tmp_path):
    from maverick.tenant import kms as k
    blob = k.seal_for_tenant("acme", b"acme-only")
    k._clear_cache()
    # beta has a different DEK -> GCM auth fails.
    with pytest.raises(k.EncryptionUnavailable):
        k.unseal_for_tenant("beta", blob)


@requires_crypto
def test_wrapped_dek_is_authenticated_to_tenant_path(tmp_path):
    from maverick.tenant import kms as k
    blob = k.seal_for_tenant("acme", b"acme-only")
    # Ensure beta has its own key path, then replace it with acme's wrapped DEK.
    k.tenant_dek("beta")
    acme_wrapped = tmp_path / "tenants" / "acme" / "keys" / "dek.wrapped"
    beta_wrapped = tmp_path / "tenants" / "beta" / "keys" / "dek.wrapped"
    beta_wrapped.write_bytes(acme_wrapped.read_bytes())

    k._clear_cache()
    with pytest.raises(k.EncryptionUnavailable):
        k.unseal_for_tenant("beta", blob)


@requires_crypto
def test_sealed_data_is_authenticated_to_tenant_id(monkeypatch):
    from maverick.tenant import kms as k
    shared_dek = b"\x11" * 32
    monkeypatch.setattr(k, "tenant_dek", lambda tenant_id, *, kms=None: shared_dek)

    blob = k.seal_for_tenant("acme", b"acme-only")
    with pytest.raises(k.EncryptionUnavailable):
        k.unseal_for_tenant("beta", blob)


@requires_crypto
def test_dek_is_persisted_wrapped_not_plaintext(tmp_path):
    from maverick.file_lock import private_path_is_restricted
    from maverick.tenant import kms as k
    dek = k.tenant_dek("acme")
    wrapped_path = tmp_path / "tenants" / "acme" / "keys" / "dek.wrapped"
    assert wrapped_path.exists()
    on_disk = wrapped_path.read_bytes()
    # The stored DEK is wrapped (magic header) and never the raw DEK.
    assert on_disk.startswith(b"MVKDEK1\n")
    assert dek not in on_disk
    assert private_path_is_restricted(wrapped_path)
    assert private_path_is_restricted(wrapped_path.parent, 0o700)


@requires_crypto
def test_dek_is_stable_across_cache_clears():
    from maverick.tenant import kms as k
    d1 = k.tenant_dek("acme")
    k._clear_cache()
    d2 = k.tenant_dek("acme")  # reloaded + unwrapped from disk
    assert d1 == d2


@requires_crypto
def test_rotate_kek_keeps_data_readable():
    from maverick.tenant import kms as k
    blob = k.seal_for_tenant("acme", b"durable")
    old = k.LocalKMS()
    new = k.LocalKMS(kek=b"\x01" * 32)
    k.rotate_kek("acme", old_kms=old, new_kms=new)
    # The DEK is unchanged, so old ciphertext still opens — but only via the new KEK.
    assert k.unseal_for_tenant("acme", blob, kms=new) == b"durable"
    # The old KEK can no longer unwrap the re-wrapped DEK.
    k._clear_cache()
    with pytest.raises(k.EncryptionUnavailable):
        k.tenant_dek("acme", kms=old)


@requires_crypto
def test_rotate_missing_tenant_raises():
    from maverick.tenant import kms as k
    with pytest.raises(k.EncryptionUnavailable):
        k.rotate_kek("ghost", old_kms=k.LocalKMS(), new_kms=k.LocalKMS())


@requires_crypto
def test_local_kms_wrap_unwrap_round_trip():
    from maverick.tenant import kms as k
    kms = k.LocalKMS()
    dek = b"\x07" * 32
    assert kms.unwrap(kms.wrap(dek)) == dek
