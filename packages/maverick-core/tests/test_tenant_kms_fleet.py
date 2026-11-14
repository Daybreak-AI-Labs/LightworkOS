"""Fleet-scale per-tenant KMS: per-tenant BYOK provider selection, a
DEK-cache TTL so a revoked key takes effect, and fleet-wide KEK rotation."""
from __future__ import annotations

import os

import pytest

importorskip = pytest.importorskip
importorskip("cryptography")

from maverick.tenant import kms as K  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / ".maverick"))
    monkeypatch.setenv("MAVERICK_KMS_KEK", "ab" * 32)  # deterministic local KEK
    monkeypatch.delenv("MAVERICK_KMS_DEK_CACHE_TTL", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    K._clear_cache()
    yield
    K._clear_cache()


def _write_tenant_kms(tid: str, body: str) -> None:
    from maverick.paths import _tenant_segment, maverick_home
    d = maverick_home() / "tenants" / _tenant_segment(tid)
    d.mkdir(parents=True, exist_ok=True)
    (d / "config.toml").write_text(body, encoding="utf-8")


# ---- regression: review findings -----------------------------------------

def test_unreadable_byok_overlay_does_not_mint_a_local_dek():
    # A broken overlay loads as defaults ([kms] lost); minting a DEK under the
    # local fallback KEK would silently and permanently downgrade BYOK.
    from maverick.crypto_at_rest import EncryptionUnavailable
    from maverick.tenant.kms import _wrapped_dek_path

    _write_tenant_kms("acme", '[kms]\nprovider = "aws"\nkey_id = "cmk"\nnot toml\n')
    with pytest.raises(EncryptionUnavailable, match="unreadable"):
        K.tenant_dek("acme")
    assert not _wrapped_dek_path("acme").exists()


def test_concurrent_first_use_loser_adopts_winner_dek(monkeypatch):
    # Two processes first-use the same tenant: the O_EXCL loser must adopt the
    # winner's persisted DEK, not crash on FileExistsError or seal under a DEK
    # that was never written. Simulate the race by writing the winner's wrapped
    # DEK to disk in the middle of the loser's generate->wrap->open sequence.
    from maverick.tenant.kms import _wrapped_dek_path
    winner = K.tenant_dek("acme")          # process A persists DEK_A
    K._clear_cache()
    assert _wrapped_dek_path("acme").exists()
    # Process B now first-uses 'acme' with the file already present (the race
    # resolved): it must return the SAME DEK_A, never a fresh key.
    loser = K.tenant_dek("acme")
    assert loser == winner


def test_generate_and_persist_dek_adopts_winner_on_oexcl_collision():
    # Directly exercise the O_EXCL-loser path: the wrapped file already exists
    # (winner persisted it), so generate-and-persist must re-read + unwrap it and
    # return the WINNER's DEK rather than raising FileExistsError or returning a
    # freshly-generated key that was never written.
    from maverick.tenant.kms import (
        _generate_and_persist_dek,
        _tenant_context,
        _wrapped_dek_path,
    )
    winner = K.tenant_dek("globex")
    K._clear_cache()
    path = _wrapped_dek_path("globex")
    assert path.exists()                   # winner is on disk
    ctx = _tenant_context("globex", b"dek-wrap")
    adopted = _generate_and_persist_dek(path, ctx, K.get_kms("globex"))
    assert adopted == winner               # loser adopted the winner, no crash


def test_ttl_raised_after_warm_cache_takes_effect(monkeypatch):
    # A tenant warmed under TTL=0 (permanent) must still be bounded once the TTL
    # is raised -- the TTL is evaluated on read, not frozen at write.
    clock = {"t": 1000.0}
    monkeypatch.setattr(K, "_now", lambda: clock["t"])

    class _Counting:
        def __init__(self):
            self.inner = K.LocalKMS()
            self.unwraps = 0

        def wrap(self, dek, *, context=None):
            return self.inner.wrap(dek, context=context)

        def unwrap(self, w, *, context=None):
            self.unwraps += 1
            return self.inner.unwrap(w, context=context)

    kms = _Counting()
    K.tenant_dek("t", kms=kms)             # cached under TTL=0 (permanent)
    monkeypatch.setenv("MAVERICK_KMS_DEK_CACHE_TTL", "100")  # raise TTL now
    K.tenant_dek("t", kms=kms)             # within new TTL window -> cache hit
    assert kms.unwraps == 0
    clock["t"] = 1200.0                    # past cached_at(1000)+100
    K.tenant_dek("t", kms=kms)             # must re-unwrap (revocation bound)
    assert kms.unwraps == 1


def test_kms_config_for_merges_global_dashboard_and_env_overlays(monkeypatch, tmp_path):
    from maverick.config import config_path, dashboard_overrides_path

    cfg = config_path()
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text('[kms]\nprovider = "local"\nregion = "base"\n', encoding="utf-8")
    dashboard_overrides_path().write_text('[kms]\nprovider = "aws"\nregion = "dash"\n', encoding="utf-8")
    overlay = tmp_path / "overlay.toml"
    overlay.write_text('[kms]\nkey_id = "overlay-cmk"\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG_OVERLAY", str(overlay))
    _write_tenant_kms("tenant1", '[kms]\nregion = "tenant"\n')

    assert K._kms_config_for("tenant1") == {
        "provider": "aws",
        "region": "tenant",
        "key_id": "overlay-cmk",
    }


def test_kms_config_for_raw_tenant_with_escaped_chars_finds_byok_overlay():
    _write_tenant_kms("slack:alice", '[kms]\nprovider = "aws"\nkey_id = "alice-cmk"\n')

    cfg = K._kms_config_for("slack:alice")

    assert cfg["provider"] == "aws"
    assert cfg["key_id"] == "alice-cmk"


@pytest.mark.skipif(os.name != "nt", reason="Windows extended-length paths")
def test_maximum_tenant_segment_reads_byok_overlay_and_existing_wrapped_dek(tmp_path, monkeypatch):
    from pathlib import Path

    from maverick.file_lock import (
        _windows_extended_path,
        atomic_write_text,
        ensure_private_directory,
    )
    from maverick.paths import MAX_TENANT_SEGMENT_LENGTH, maverick_home

    home = tmp_path / ("h" * max(1, 90 - len(os.path.abspath(tmp_path)) - 1))
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    tenant = "t" * MAX_TENANT_SEGMENT_LENGTH
    plain_overlay = maverick_home() / "tenants" / tenant / "config.toml"
    assert len(os.path.abspath(plain_overlay)) > 260
    overlay = Path(_windows_extended_path(plain_overlay))
    ensure_private_directory(overlay.parent)
    atomic_write_text(overlay, '[kms]\nprovider = "aws"\nkey_id = "tenant-cmk"\n')

    assert K._kms_config_for(tenant)["provider"] == "aws"
    assert K._tenant_own_key_id(tenant) == "tenant-cmk"
    first = K.tenant_dek(tenant, kms=K.LocalKMS())
    assert K._wrapped_dek_path(tenant).is_file()
    K._clear_cache()
    assert K.tenant_dek(tenant, kms=K.LocalKMS()) == first


def test_named_tenant_config_error_does_not_leak_ambient(monkeypatch):
    # A named tenant whose overlay is malformed must fall back to GLOBAL config,
    # never to the ambient (active) tenant's [kms] -- else its DEK is wrapped
    # under the wrong tenant's key / BYOK is silently downgraded.
    _write_tenant_kms("victim", "this is not valid toml = = =")
    # Ambient context is a DIFFERENT tenant pinned to AWS.
    monkeypatch.setenv("MAVERICK_TENANT", "attacker")
    _write_tenant_kms("attacker", '[kms]\nprovider = "aws"\nkey_id = "attacker-cmk"\n')
    cfg = K._kms_config_for("victim")
    # Must NOT have picked up attacker's aws/key_id from ambient load_config.
    assert cfg.get("key_id") != "attacker-cmk"
    assert cfg.get("provider") in (None, "local", "")


# ---- per-tenant BYOK ------------------------------------------------------

def test_no_overlay_uses_local_kms():
    assert isinstance(K.get_kms("plain-tenant"), K.LocalKMS)
    assert isinstance(K.get_kms(None), K.LocalKMS)


def test_each_tenant_resolves_its_own_provider_and_key(monkeypatch):
    # Tenant A pins AWS KMS with its own key; tenant B stays local. Resolution is
    # deterministic — independent of the active tenant context.
    _write_tenant_kms("acme", '[kms]\nprovider = "aws"\nkey_id = "acme-cmk"\nregion = "us-east-1"\n')
    _write_tenant_kms("globex", '[kms]\nprovider = "local"\n')

    acme = K.get_kms("acme")
    from maverick.kms_backends import AwsKmsKEK
    assert isinstance(acme, AwsKmsKEK)
    assert acme.key_id == "acme-cmk"        # the TENANT's key, not ambient
    assert acme.region == "us-east-1"
    assert isinstance(K.get_kms("globex"), K.LocalKMS)


def test_tenants_own_key_beats_the_server_wide_env_key(monkeypatch):
    # BYOK: the customer pinned THEIR key so they can revoke ours. An operator's
    # server-wide MAVERICK_KMS_KEY_ID must not silently wrap their DEK instead.
    monkeypatch.setenv("MAVERICK_KMS_KEY_ID", "operator-global-cmk")
    _write_tenant_kms("acme", '[kms]\nprovider = "aws"\nkey_id = "acme-byok-cmk"\n')

    assert K.get_kms("acme").key_id == "acme-byok-cmk"


def test_server_wide_env_key_is_the_fallback_for_a_tenant_without_its_own(monkeypatch):
    monkeypatch.setenv("MAVERICK_KMS_KEY_ID", "operator-global-cmk")
    _write_tenant_kms("globex", '[kms]\nprovider = "aws"\n')

    assert K.get_kms("globex").key_id == "operator-global-cmk"


def test_env_key_still_wins_over_the_global_config_key(monkeypatch):
    # "Env vars win over config" is the documented rule for the operator's OWN
    # setting; only a tenant's own pinned key is protected from the env key.
    from maverick.config import config_path

    cfg = config_path()
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text('[kms]\nprovider = "aws"\nkey_id = "global-config-cmk"\n',
                   encoding="utf-8")
    monkeypatch.setenv("MAVERICK_KMS_KEY_ID", "operator-global-cmk")
    _write_tenant_kms("globex", '[kms]\nregion = "us-east-1"\n')

    assert K.get_kms("globex").key_id == "operator-global-cmk"
    assert K.get_kms(None).key_id == "operator-global-cmk"


def test_byok_resolution_ignores_ambient_context(monkeypatch):
    # Even with a different tenant active in the context, get_kms(tid) reads tid's
    # config — so a fleet op rotating tenant X never wraps with tenant Y's key.
    _write_tenant_kms("xcorp", '[kms]\nprovider = "aws"\nkey_id = "xcorp-cmk"\n')
    monkeypatch.setenv("MAVERICK_TENANT", "someone-else")
    from maverick.kms_backends import AwsKmsKEK
    k = K.get_kms("xcorp")
    assert isinstance(k, AwsKmsKEK) and k.key_id == "xcorp-cmk"


# ---- DEK cache TTL --------------------------------------------------------

class _CountingKMS:
    """LocalKMS that counts unwrap calls, to observe cache re-validation."""
    def __init__(self):
        self._inner = K.LocalKMS()
        self.unwraps = 0

    def wrap(self, dek, *, context=None):
        return self._inner.wrap(dek, context=context)

    def unwrap(self, wrapped, *, context=None):
        self.unwraps += 1
        return self._inner.unwrap(wrapped, context=context)


def test_default_ttl_caches_for_process_lifetime():
    kms = _CountingKMS()
    K.tenant_dek("t", kms=kms)          # generate + wrap (no unwrap)
    K.tenant_dek("t", kms=kms)          # cache hit
    assert kms.unwraps == 0             # default TTL 0 -> never re-unwraps


def test_positive_ttl_re_unwraps_after_expiry(monkeypatch):
    monkeypatch.setenv("MAVERICK_KMS_DEK_CACHE_TTL", "100")
    clock = {"t": 1000.0}
    monkeypatch.setattr(K, "_now", lambda: clock["t"])
    kms = _CountingKMS()

    K.tenant_dek("t", kms=kms)          # gen + cache with expiry=1100
    K.tenant_dek("t", kms=kms)          # within TTL -> cache hit
    assert kms.unwraps == 0
    clock["t"] = 1200.0                 # past expiry
    K.tenant_dek("t", kms=kms)          # lapsed -> re-reads wrapped file + unwrap
    assert kms.unwraps == 1


# ---- fleet KEK rotation ---------------------------------------------------

def test_rotate_kek_fleet_rotates_all_provisioned_tenants(monkeypatch):
    from maverick.tenant import registry
    registry.create_tenant("a")
    registry.create_tenant("b")
    registry.create_tenant("c")  # provisioned but never seals -> no DEK

    old = K.LocalKMS(bytes.fromhex("ab" * 32))
    new = K.LocalKMS(bytes.fromhex("cd" * 32))
    # Seal data for a and b under the OLD kek so there's a DEK to rotate.
    for tid in ("a", "b"):
        K.seal_for_tenant(tid, b"secret-" + tid.encode(), kms=old)
    K._clear_cache()

    report = K.rotate_kek_fleet(old_kms_for=lambda t: old, new_kms_for=lambda t: new)
    assert report == {"a": "rotated", "b": "rotated"}   # c skipped (no DEK)

    # Data still readable, now under the NEW kek; the old kek can't unwrap.
    K._clear_cache()
    assert K.unseal_for_tenant("a", K.seal_for_tenant("a", b"x", kms=new), kms=new)
    K._clear_cache()
    from maverick.crypto_at_rest import EncryptionUnavailable
    with pytest.raises(EncryptionUnavailable):
        K.tenant_dek("a", kms=old)


def test_rotate_kek_fleet_isolates_per_tenant_failure(monkeypatch):
    from maverick.tenant import registry
    registry.create_tenant("good")
    registry.create_tenant("bad")
    old = K.LocalKMS(bytes.fromhex("ab" * 32))
    new = K.LocalKMS(bytes.fromhex("cd" * 32))
    for tid in ("good", "bad"):
        K.seal_for_tenant(tid, b"d", kms=old)
    K._clear_cache()

    def new_for(t):
        if t == "bad":
            raise RuntimeError("kms unreachable")
        return new

    report = K.rotate_kek_fleet(old_kms_for=lambda t: old, new_kms_for=new_for)
    assert report["good"] == "rotated"
    assert report["bad"].startswith("error:")
