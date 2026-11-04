"""Native encrypted JSON compatibility, without changing legacy plaintext policy."""
from __future__ import annotations

import copy
import json
import secrets

import pytest
from maverick import crypto_at_rest as crypto
from maverick import file_lock, privacy_ops
from maverick.paths import tenant_scope
from maverick.tenant import kms


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_STRICT", "0")
    monkeypatch.setenv("MAVERICK_KMS_KEK", secrets.token_hex(32))
    monkeypatch.delenv("MAVERICK_ENCRYPTION_KEY", raising=False)
    monkeypatch.setattr("maverick.config.load_config", dict)
    monkeypatch.setattr(crypto, "_KEY_PATH", tmp_path / "shared-keys" / "at_rest.key")
    kms._clear_cache()
    yield
    kms._clear_cache()


def sealed_record(kind):
    store = privacy_ops._RecordStore("encrypted-fixture", "ENC")
    path = store._path("ENC-record")
    file_lock.ensure_private_directory(path.parent)
    value = {"id": "ENC-record", "revision": 3, "status": "ready", "payload": "sensitive body"}
    if kind == "v2":
        crypto.rotate_at_rest_key()
    raw = (kms.seal_for_tenant("acme", json.dumps(value).encode()) if kind == "tenant"
           else crypto.seal(json.dumps(value).encode()))
    file_lock.atomic_write_bytes(path, raw)
    return store, path, value, raw


@pytest.mark.parametrize("kind", ["v1", "v2", "tenant"])
def test_sealed_record_read_and_cas_update_retain_envelope_after_mode_toggle(kind, monkeypatch):
    with tenant_scope(tenant="acme"):
        store, path, value, original = sealed_record(kind)
        assert store.load(value["id"]) == value
        assert copy.deepcopy(store.load(value["id"])) == value
        assert store.list_bounded(limit=1) == [value]
        assert store.count_records() == 1
        if kind != "tenant":
            # The previous deployment envelope cannot silently become tenant-bound.
            monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "1")
        changed = store.update(value["id"], lambda row: row.update(status="done"), expected_revision=3)
        assert changed["revision"] == 4 and changed["status"] == "done"
        saved_raw = path.read_bytes()
        header_size = len(crypto._MAGIC_V2) + 8 if kind == "v2" else len(crypto._MAGIC)
        assert saved_raw[:header_size] == original[:header_size]
        assert crypto.is_sealed(saved_raw)
        assert json.loads(crypto.unseal(saved_raw)) == changed
        assert "sensitive body" not in saved_raw.decode("utf-8", errors="replace")
        assert not any(key.startswith("_sealed") for key in changed)
        with pytest.raises(privacy_ops.RecordConflict):
            store.save(changed, expected_revision=3)
        assert path.read_bytes() == saved_raw


@pytest.mark.parametrize("failure", ["tamper", "wrong-key"])
def test_bad_seal_cannot_be_read_or_replaced(failure, monkeypatch):
    with tenant_scope(tenant="acme"):
        store, path, value, original = sealed_record("v1")
        if failure == "tamper":
            file_lock.atomic_write_bytes(path, original[:-1] + bytes([original[-1] ^ 1]))
        else:
            monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", secrets.token_hex(32))
        damaged = path.read_bytes()
        with pytest.raises(privacy_ops.PrivacyStateError, match="authenticate"):
            store.load(value["id"])
        with pytest.raises(privacy_ops.PrivacyStateError, match="authenticate"):
            store.save({**value, "status": "replacement"}, expected_revision=3)
        assert path.read_bytes() == damaged


def test_tenant_envelope_rejects_other_tenant_even_on_same_private_path(monkeypatch):
    with tenant_scope(tenant="acme"):
        store, path, value, original = sealed_record("tenant")
    monkeypatch.setattr(store, "_dir", lambda: path.parent)
    with tenant_scope(tenant="other"):
        with pytest.raises(privacy_ops.PrivacyStateError, match="authenticate"):
            store.load(value["id"])
    assert path.read_bytes() == original


def test_plaintext_policy_is_unchanged_with_strict_flag(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_STRICT", "1")
    store = privacy_ops._RecordStore("legacy-fixture", "ENC")
    value = store.save({"id": "ENC-legacy", "status": "ready"}, expected_revision=0)
    assert not crypto.is_sealed(store._path(value["id"]).read_bytes())
    assert store.load(value["id"]) == value
    store.update(value["id"], lambda row: row.update(status="done"), expected_revision=1)
    assert not crypto.is_sealed(store._path(value["id"]).read_bytes())


def test_authenticated_decoded_size_is_bounded(monkeypatch):
    with tenant_scope(tenant="acme"):
        store, path, value, _ = sealed_record("v1")
        monkeypatch.setattr(privacy_ops, "_MAX_PRIVACY_JSON_BYTES", 80)
        raw = crypto.seal(json.dumps({**value, "payload": "x" * 90}).encode())
        file_lock.atomic_write_bytes(path, raw)
        with pytest.raises(privacy_ops.PrivacyStateError):
            store.load(value["id"])
