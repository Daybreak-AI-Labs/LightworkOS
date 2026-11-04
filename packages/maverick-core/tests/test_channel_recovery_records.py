"""Native plaintext/AEAD records and exact dispositions; no archive/build race."""
from __future__ import annotations

import copy
import json
import time

import pytest
from maverick import channel_recovery, crypto_at_rest, file_lock, workspace_recovery


@pytest.mark.parametrize("encrypted", [False, True])
def test_channel_record_reconciliation_keeps_unknown_effect_and_survives_marker_retry(tmp_path, encrypted):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = bytes(range(32))
    stage = file_lock.ensure_private_directory(tmp_path / "stage")
    directory = file_lock.ensure_private_directory(stage / "channel-deliveries")
    identity = "chd-" + "a" * 56
    original = {"id": identity, "revision": 1, "channel": "fixture", "account_sha256": "b" * 64,
                "external_id": "event", "execution_id": "run", "execution": "execution_unknown",
                "delivery": "delivery_unknown", "chunks": {"reply": {"state": "delivery_unknown",
                "payload_sha256": "c" * 64, "idempotency_key": "remote-key"}}}
    plain = json.dumps(original).encode()
    nonce = bytes(range(12))
    raw = crypto_at_rest._MAGIC + nonce + AESGCM(key).encrypt(nonce, plain, None) if encrypted else plain
    path = directory / (identity + ".json")
    file_lock.atomic_create_bytes(path, raw)
    decryptor = workspace_recovery._record_decryptor_from_keys({"at_rest.key": key}, "acme")
    items, _ = channel_recovery.stage_authorities(stage, decryptor=decryptor, tenant="acme", now=time.time(),
        make_item=workspace_recovery._reconciliation_item, blocked_item=lambda *args: pytest.fail("valid fixture blocked"))
    workspace_recovery._bind_reconciliation_sources(stage, items)
    item = items[0]
    readback = copy.deepcopy(item["readback_template"])
    readback.update(observed_at=time.time(), evidence_reference="provider-audit-123", outcome="confirmed",
                    execution="recorded", delivery="recorded", chunks={"reply": {"outcome": "recorded", "provider_id": "external-id"}})
    for change in ({"execution": "unknown"}, {"chunks": {}}, {"observed_at": time.time() - 3600},
                   {"record_id": "chd-" + "d" * 56}, {"binding_sha256": "d" * 64}):
        with pytest.raises(ValueError):
            channel_recovery.resolve(path, item, {**readback, **change}, actor="admin", decryptor=decryptor, tenant="acme", workspace=stage)
    kwargs = dict(actor="admin", decryptor=decryptor, tenant="acme", workspace=stage)
    digest, proof = channel_recovery.resolve(path, item, readback, **kwargs)
    # Simulate interruption after the sealed disposition but before its marker.
    fresh_decryptor = workspace_recovery._record_decryptor_from_keys({"at_rest.key": key}, "acme")
    assert channel_recovery.resolve(path, item, readback, **{**kwargs, "decryptor": fresh_decryptor}) == (digest, proof)
    saved_raw = path.read_bytes()
    assert crypto_at_rest.is_sealed(saved_raw) is encrypted
    saved = json.loads(fresh_decryptor(saved_raw, "acme", stage) if encrypted else saved_raw)
    assert {name: saved[name] for name in original if name != "revision"} == {name: original[name] for name in original if name != "revision"}
    assert saved["restore_hold"]["readback"]["chunks"]["reply"]["provider_id"] == "external-id"
    assert saved["restore_hold"]["automatic_replay_blocked"] is True
