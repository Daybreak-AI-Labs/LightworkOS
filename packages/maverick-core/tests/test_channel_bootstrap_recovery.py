"""Real local archive/bootstrap flow; synthetic channel states, no transports."""
from __future__ import annotations

import asyncio
import copy
import json
import time
from dataclasses import asdict
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from maverick import client, config, crypto_at_rest, file_lock
from maverick import workspace_recovery as recovery
from maverick.paths import data_dir
from maverick_channels.base import IncomingMessage
from maverick_channels.delivery import DeliveryJournal, process_message, send_chunk


@pytest.fixture(autouse=True)
def isolated_bootstrap_environment(monkeypatch):
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "acme")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    for name in ("MAVERICK_BACKUP_SIGNING_KEY", "MAVERICK_TENANT", "MAVERICK_WORLD_BACKEND",
                 "MAVERICK_GOVERNED_RECORDS_BACKEND", "MAVERICK_ALLOW_MULTIPLE_CONTROL_PLANES",
                 "MAVERICK_GRPC_DISPATCH_TARGET", "MAVERICK_PG_DSN", "MAVERICK_KNOWLEDGE_DSN",
                 "MAVERICK_QUEUE_REDIS_DSN", "MAVERICK_ENCRYPTION_KEY", "MAVERICK_KMS_KEK",
                 "QDRANT_URL", "REDIS_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(config, "load_config", dict)
    monkeypatch.setattr(config, "config_source_errors", lambda **_: [])
    monkeypatch.setattr(crypto_at_rest, "per_tenant_at_rest", lambda: False)
    client.reset_client_cache()
    yield
    client.reset_client_cache()


def _select_home(monkeypatch, home):
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setattr(crypto_at_rest, "_KEY_PATH", home / "shared-keys" / "at_rest.key")
    client.reset_client_cache()
    root = data_dir()
    root.mkdir(parents=True, exist_ok=True)
    return root


def _record(root, namespace, value, *, encrypted):
    directory = file_lock.ensure_private_directory(root / namespace)
    payload = json.dumps(value, sort_keys=True).encode()
    file_lock.atomic_create_bytes(directory / f"{value['id']}.json",
                                  crypto_at_rest.seal(payload) if encrypted else payload)


@pytest.mark.parametrize("encrypted", [False, True])
def test_restored_channel_authorities_remain_blocked_without_no_replay_reconciliation(
    monkeypatch, tmp_path, encrypted,
):
    source = _select_home(monkeypatch, tmp_path / "source")
    recovery_key = recovery.configure_key()["key"]
    paths = []
    for index, (execution, delivery) in enumerate((
        ("received", "not_ready"), ("completed", "ready"),
        ("completed", "retryable"), ("execution_started_unconfirmed", "not_ready"),
        ("execution_unknown", "delivery_unknown"), ("completed", "delivered"),
    )):
        identity = "chd-" + f"{index:056x}"
        _record(source, "channel-deliveries", {"id": identity,
                "execution": execution, "delivery": delivery}, encrypted=encrypted)
        paths.append(f"channel-deliveries/{identity}.json")
    for namespace, prefix in (("channel-delivery-cursors", "chc"),
                              ("channel-poll-cursors", "chp"),
                              ("imessage-intake-cursors", "imc")):
        identity = prefix + "-" + "a" * 56
        _record(source, namespace, {"id": identity, "cursor": "synthetic-provider-position"}, encrypted=encrypted)
        paths.append(f"{namespace}/{identity}.json")
    original = {path: (source / path).read_bytes() for path in paths}
    snapshot = recovery.create()
    exported = tmp_path / "channel-source.tgz"
    file_lock.atomic_create_bytes(exported, recovery.download_path(snapshot["id"]).read_bytes())

    target = _select_home(monkeypatch, tmp_path / "target")
    recovery.configure_key(imported=recovery_key)
    imported = recovery.import_archive(exported)
    recovery.prepare_bootstrap(isolated=True, actor="admin", source_offline=True)
    review = recovery.prepare_restore(imported["id"], isolated=True, actor="admin")
    restored = recovery.apply_restore(review["review"], review["target"], isolated=True, actor="admin")
    assert restored["state"] == "reconciliation_required"
    status = recovery.reconciliation_status(actor="admin")
    blocked = {item["source"]: item for item in status["items"]}
    assert set(paths) <= blocked.keys()
    for path in paths:
        item = blocked[path]
        assert item["safe_state"] == "global_start_blocked"
        assert item["state"] == "unresolved" and item["requires_external_readback"]
        assert (target / path).read_bytes() == original[path]
        with pytest.raises(recovery.RecoveryError, match="cannot be safely rewritten"):
            recovery.resolve_reconciliation(item["id"], "external_effect_absent",
                evidence_reference="synthetic authoritative readback", isolated=True, actor="admin")
    with pytest.raises(recovery.RecoveryError):
        recovery.complete_reconciliation(isolated=True, actor="admin")
    with pytest.raises(recovery.RecoveryError, match="reconciliation is unfinished"):
        recovery.assert_bootstrap_start_allowed()

    async def cannot_replay():
        handler, provider = AsyncMock(), AsyncMock()
        channel = type("SyntheticChannel", (), {"handler": handler})()
        message = IncomingMessage(user_id="owner", text="request", channel="fixture", message_id="event")
        with pytest.raises(recovery.RecoveryError, match="reconciliation is unfinished"):
            await process_message(channel, message, external_id="event", account="configured-account",
                                  authorize=lambda: True, send=provider)
        with pytest.raises(recovery.RecoveryError, match="reconciliation is unfinished"):
            await send_chunk("reply", {"text": "saved reply"}, provider)
        with pytest.raises(recovery.RecoveryError, match="reconciliation is unfinished"):
            DeliveryJournal().admit(message, external_id="new-event", account="configured-account")
        handler.assert_not_awaited()
        provider.assert_not_awaited()
    asyncio.run(cannot_replay())


@pytest.mark.parametrize("encrypted", [False, True])
def test_supported_channel_readback_completes_restore_without_replaying_old_receipts(monkeypatch, tmp_path, encrypted):
    from maverick.governed_records import GovernedRecordStore
    from maverick_channels import delivery

    source = _select_home(monkeypatch, tmp_path / "source")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1" if encrypted else "0")
    recovery_key = recovery.configure_key()["key"]
    original, messages = {}, {}
    for index, (execution, state) in enumerate((
        ("received", "not_ready"), ("completed", "ready"), ("completed", "retryable"),
        ("execution_started_unconfirmed", "not_ready"), ("execution_unknown", "delivery_unknown"),
        ("completed", "delivered"),
    )):
        message = IncomingMessage(user_id="owner", text=f"request {index}", channel="fixture", message_id=str(index))
        identity = delivery._record_id("fixture", "account", str(index))
        payload, _ = delivery._payload(message, identity)
        value = {"id": identity, "revision": 1, "created_at": time.time(), "updated_at": time.time(),
                 "channel": "fixture", "account_sha256": delivery._digest("account"), "external_id": str(index),
                 "execution_id": f"execution-{index}", "fingerprint": delivery._digest([payload, {}]),
                 "message": payload, "route": {}, "execution": execution, "delivery": state,
                 "reply": asdict(delivery.Reply("previous answer")), "chunks": {}}
        if state == "delivered":
            value["chunks"] = {"reply": {"state": "delivered", "provider_id": "remote-receipt", "payload_sha256": "a" * 64}}
        _record(source, "channel-deliveries", value, encrypted=encrypted)
        original[identity] = value
        messages[identity] = message
    for namespace, prefix, fields in (
        ("channel-delivery-cursors", "chc", {"cursor": "archived-position"}),
        ("channel-poll-cursors", "chp", {"channel": "mastodon", "cursor": "10", "seen_cursors": [], "status": "idle", "watermark": "5"}),
        ("imessage-intake-cursors", "imc", {"last_rowid": 50}),
    ):
        _record(source, namespace, {"id": prefix + "-" + "b" * 56, "revision": 1, **fields}, encrypted=encrypted)
    snapshot = recovery.create()
    exported = tmp_path / "valid-channel-source.tgz"
    file_lock.atomic_create_bytes(exported, recovery.download_path(snapshot["id"]).read_bytes())
    custody = recovery.export_encryption_keys() if encrypted else None
    target = _select_home(monkeypatch, tmp_path / "target")
    recovery.configure_key(imported=recovery_key)
    imported = recovery.import_archive(exported)
    recovery.prepare_bootstrap(isolated=True, actor="admin", source_offline=True)
    if encrypted:
        report = recovery.test_key_custody(imported["id"], custody, expected_sha256=imported["sha256"], actor="admin")
        recovery.install_retained_keys(imported["id"], custody, expected_sha256=imported["sha256"],
                                       report_id=report["report_id"], isolated=True, actor="admin")
    review = recovery.prepare_restore(imported["id"], isolated=True, actor="admin")
    recovery.apply_restore(review["review"], review["target"], isolated=True, actor="admin")
    status = recovery.reconciliation_status(actor="admin")
    items = [row for row in status["items"] if row["category"] == "channel_authority"]
    assert len(items) == 9 and status["unresolved"] == 9
    with pytest.raises(recovery.RecoveryError):
        recovery.assert_bootstrap_start_allowed()
    first = items[0]
    first_record = original[first["record_id"]]
    valid_first = copy.deepcopy(first["readback_template"])
    valid_first.update(observed_at=time.time(), evidence_reference="provider-log-123", outcome="confirmed",
        execution="recorded" if first_record["execution"] != "received" else "absent",
        delivery="recorded" if first_record["delivery"] == "delivered" else "absent")
    for chunk in valid_first["chunks"].values():
        chunk.update(outcome="recorded", provider_id="remote-receipt")
    for changes in ({"record_id": "other"}, {"namespace": "other"}, {"source_sha256": "0" * 64},
                    {"binding_sha256": "0" * 64}, {"observed_at": time.time() - 3600}, {"outcome": "unknown"}):
        invalid = {**valid_first, **changes}
        with pytest.raises(recovery.RecoveryError):
            recovery.resolve_reconciliation(first["id"], "channel_readback_confirmed", evidence_reference=None,
                channel_readback=invalid, isolated=True, actor="admin")
    with pytest.raises(recovery.RecoveryError):
        recovery.resolve_reconciliation(first["id"], "external_effect_absent", evidence_reference="generic-ref-123", isolated=True, actor="admin")
    for item in items:
        readback = copy.deepcopy(item["readback_template"])
        readback.update(observed_at=time.time(), evidence_reference="provider-log-123", outcome="confirmed")
        namespace = readback["namespace"]
        if namespace == "channel-deliveries":
            before = original[item["record_id"]]
            readback.update(execution="recorded" if before["execution"] != "received" else "absent",
                            delivery="recorded" if before["delivery"] == "delivered" else "absent")
            for chunk in readback["chunks"].values():
                chunk.update(outcome="recorded", provider_id="remote-receipt")
        elif namespace == "channel-poll-cursors":
            readback["checkpoint"] = {"watermark": "100"}
        elif namespace == "imessage-intake-cursors":
            readback["checkpoint"] = {"last_rowid": 100}
        kwargs = dict(evidence_reference=None, channel_readback=readback, isolated=True, actor="admin")
        recovery.resolve_reconciliation(item["id"], "channel_readback_confirmed", **kwargs)
        # Fresh reads, including the marker, prove an exact retry is idempotent.
        assert recovery.resolve_reconciliation(item["id"], "channel_readback_confirmed", **kwargs)["state"] == "resolved"
        modified = {**readback, "evidence_reference": "different-readback"}
        with pytest.raises(recovery.RecoveryError):
            recovery.resolve_reconciliation(item["id"], "channel_readback_confirmed", **{**kwargs, "channel_readback": modified})
    assert recovery.complete_reconciliation(isolated=True, actor="admin")["state"] == "completed"
    recovery.assert_bootstrap_start_allowed()
    journal = DeliveryJournal()
    for identity, before in original.items():
        row = journal.get(identity)
        assert {key: row[key] for key in ("execution", "delivery", "chunks")} == {key: before[key] for key in ("execution", "delivery", "chunks")}
        assert row["restore_hold"]["state"] == "resolved"
        handler, provider = AsyncMock(), AsyncMock()
        channel = type("FixtureChannel", (), {"handler": handler})()
        asyncio.run(process_message(channel, messages[identity], external_id=before["external_id"],
            account="account", authorize=lambda: True, send=provider, journal=DeliveryJournal()))
        handler.assert_not_awaited()
        provider.assert_not_awaited()
        if encrypted:
            assert crypto_at_rest.is_sealed((target / "channel-deliveries" / (identity + ".json")).read_bytes())
    poll = GovernedRecordStore("channel-poll-cursors", "chp", "channel_poll_cursor").get("chp-" + "b" * 56)
    assert poll["watermark"] == "100" and poll["cursor"] is None
    assert poll["restore_hold"]["prior_checkpoint"]["watermark"] == "5"


@pytest.mark.parametrize("encrypted", [False, True])
def test_native_form_review_survives_marker_interruption_without_replaying(monkeypatch, tmp_path, encrypted):
    source = _select_home(monkeypatch, tmp_path / "source")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1" if encrypted else "0")
    recovery_key = recovery.configure_key()["key"]
    identity = "chd-" + "b" * 56
    _record(source, "channel-deliveries", {"id": identity, "revision": 1, "channel": "slack",
        "account_sha256": "c" * 64, "external_id": "event", "execution_id": "work",
        "execution": "execution_unknown", "delivery": "delivery_unknown", "chunks": {}}, encrypted=encrypted)
    snapshot = recovery.create()
    exported = tmp_path / "forms-source.tgz"
    file_lock.atomic_create_bytes(exported, recovery.download_path(snapshot["id"]).read_bytes())
    custody = recovery.export_encryption_keys() if encrypted else None
    target = _select_home(monkeypatch, tmp_path / "target")
    recovery.configure_key(imported=recovery_key)
    imported = recovery.import_archive(exported)
    recovery.prepare_bootstrap(isolated=True, actor="admin", source_offline=True)
    if encrypted:
        report = recovery.test_key_custody(imported["id"], custody, expected_sha256=imported["sha256"], actor="admin")
        recovery.install_retained_keys(imported["id"], custody, expected_sha256=imported["sha256"],
            report_id=report["report_id"], isolated=True, actor="admin")
    review = recovery.prepare_restore(imported["id"], isolated=True, actor="admin")
    recovery.apply_restore(review["review"], review["target"], isolated=True, actor="admin")
    item = recovery.reconciliation_status(actor="admin")["items"][0]
    assert item["channel_review"]["source_label"] == "Slack"
    answers = {"kind": "message", "checked_at": datetime.now(timezone.utc).isoformat(),
               "evidence_reference": "reviewed-source-123", "execution": "recorded", "delivery": "absent", "chunks": {}}
    options = dict(evidence_reference=None, isolated=True, actor="admin", channel_answers=answers,
                   expected_review_token=item["channel_review"]["review_token"])
    for change in ({"actor": "someone-else"}, {"isolated": False}, {"expected_review_token": "0" * 64}):
        with pytest.raises(recovery.RecoveryError):
            recovery.resolve_reconciliation(item["id"], "channel_readback_confirmed", **{**options, **change})
    # The token check must happen against the authenticated marker under the lock.
    reader = recovery._read_bootstrap
    with monkeypatch.context() as patch:
        patch.setattr(recovery, "_read_bootstrap", lambda **kw: {**reader(**kw), "bootstrap_id": "different"})
        with pytest.raises(recovery.RecoveryError, match="changed"):
            recovery.resolve_reconciliation(item["id"], "channel_readback_confirmed", **options)
    with monkeypatch.context() as patch:
        def interrupt(_body):
            raise OSError("synthetic publication interruption")
        patch.setattr(recovery, "_write_bootstrap", interrupt)
        with pytest.raises(OSError):
            recovery.resolve_reconciliation(item["id"], "channel_readback_confirmed", **options)
    interrupted_bytes = (target / "channel-deliveries" / (identity + ".json")).read_bytes()
    current = recovery.reconciliation_status(actor="admin")
    pending = current["items"][0]["channel_review"]
    assert current["unresolved"] == 1 and pending["status"] == "recording_incomplete"
    assert pending["review_token"] == options["expected_review_token"]
    # A damaged interrupted channel must not hide the whole review inventory.
    from maverick import channel_recovery

    marker = recovery._read_bootstrap(actor="admin")
    decryptor = recovery._bootstrap_record_decryptor(marker) if encrypted else None
    record_path = target / "channel-deliveries" / (identity + ".json")
    record, raw, sealed = channel_recovery._load(record_path, decryptor=decryptor, tenant="acme", workspace=target)
    record["chunks"] = []
    channel_recovery._write(record_path, record, raw, sealed, decryptor=decryptor, tenant="acme", workspace=target)
    damaged = recovery.reconciliation_status(actor="admin")
    assert damaged["unresolved"] == 1 and len(damaged["items"]) == 1
    assert damaged["items"][0]["channel_review"]["status"] == "unavailable"
    for submitted in (answers, pending["retry_answers"]):
        with pytest.raises(recovery.RecoveryError):
            recovery.resolve_reconciliation(item["id"], "channel_readback_confirmed",
                **{**options, "channel_answers": submitted})
    file_lock.atomic_write_bytes(record_path, interrupted_bytes)
    result = recovery.resolve_reconciliation(item["id"], "channel_readback_confirmed",
        **{**options, "channel_answers": pending["retry_answers"]})
    assert result["state"] == "resolved" and result["item_id"] == item["id"]
    assert result["automatic_replay_blocked"] and result["normal_start_blocked"]
    assert (target / "channel-deliveries" / (identity + ".json")).read_bytes() == interrupted_bytes
    assert recovery.resolve_reconciliation(item["id"], "channel_readback_confirmed", **options)["state"] == "resolved"
    assert recovery.reconciliation_status(actor="admin")["items"][0]["channel_review"]["status"] == "recorded"
    with pytest.raises(recovery.RecoveryError):
        recovery.assert_bootstrap_start_allowed()
    assert recovery.complete_reconciliation(isolated=True, actor="admin")["state"] == "completed"
    recovery.assert_bootstrap_start_allowed()
