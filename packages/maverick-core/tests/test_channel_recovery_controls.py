"""Native held records and typed forms, including interrupted publication."""
from __future__ import annotations

import copy
import json
import time
from datetime import datetime, timezone

import pytest
from maverick import channel_recovery, file_lock, workspace_recovery
from maverick import channel_recovery_controls as controls


def setup_record(tmp_path, kind):
    fields = {
        "message": ("channel-deliveries", "chd", {"channel": "slack", "account_sha256": "b" * 64,
            "external_id": "event", "execution_id": "work", "execution": "completed", "delivery": "delivered",
            "chunks": {"reply": {"state": "delivered", "provider_id": "receipt-123"}}}),
        "delivery_restart": ("channel-delivery-cursors", "chc", {"cursor": "old"}),
        "imessage_position": ("imessage-intake-cursors", "imc", {"last_rowid": 9007199254740993}),
        "notification_position": ("channel-poll-cursors", "chp", {"channel": "mastodon", "cursor": None,
            "seen_cursors": [], "watermark": "10", "candidate": "12"}),
        "poll_time": ("channel-poll-cursors", "chp", {"channel": "threads", "cursor": None, "seen_cursors": []}),
    }
    namespace, prefix, extra = fields[kind]
    root = file_lock.ensure_private_directory(tmp_path / "state")
    folder = file_lock.ensure_private_directory(root / namespace)
    identity = prefix + "-" + "a" * 56
    path = folder / (identity + ".json")
    file_lock.atomic_create_bytes(path, json.dumps({"id": identity, "revision": 1, **extra}).encode())
    restored = time.time() - 1
    items, _ = channel_recovery.stage_authorities(root, decryptor=None, tenant="acme", now=restored,
        make_item=workspace_recovery._reconciliation_item, blocked_item=lambda *args: pytest.fail("valid record blocked"))
    workspace_recovery._bind_reconciliation_sources(root, items)
    marker = {"bootstrap_id": "recovery-one", "actor": "admin", "target": "local", "restored_at": restored}
    checked = datetime.now(timezone.utc).isoformat()
    answer = {"kind": kind, "checked_at": checked, "evidence_reference": "source-reviewed-123"}
    if kind == "message":
        answer.update(execution="recorded", delivery="recorded", chunks={"reply": {"outcome": "recorded", "provider_id": "receipt-123"}})
    elif kind == "imessage_position":
        answer["position"] = "9007199254740995"
    elif kind == "notification_position":
        answer["position"] = "15"
    elif kind == "poll_time":
        answer["resume_time"] = checked
    return root, path, items[0], marker, answer


@pytest.mark.parametrize("kind", ["message", "delivery_restart", "imessage_position", "notification_position", "poll_time"])
def test_all_typed_families_preserve_exact_authority_and_interrupted_retry(tmp_path, kind):
    root, path, item, marker, answers = setup_record(tmp_path, kind)
    options = dict(decryptor=None, tenant="acme", workspace=root)
    descriptor = controls.descriptor(marker, item, path, **options)
    assert descriptor["kind"] == kind and descriptor["status"] == "review_required"
    if kind == "message":
        assert descriptor["execution_choices"] == descriptor["delivery_choices"] == ["recorded"]
        assert descriptor["chunks"][0]["receipt_locked"] is True
        assert descriptor["chunks"][0]["receipt"] == "receipt-123"
    original = copy.deepcopy(item)
    readback = controls.readback(marker, item, answers, descriptor["review_token"], path, **options)
    assert item == original  # Nested chunk edits must not corrupt the original signed template.
    digest, proof = channel_recovery.resolve(path, item, readback, actor="admin", **options)
    pending = controls.descriptor(marker, item, path, **options)
    assert pending["status"] == "recording_incomplete"
    assert pending["review_token"] == descriptor["review_token"]
    retry = controls.readback(marker, item, pending["retry_answers"], pending["review_token"], path, **options)
    assert retry == readback
    assert channel_recovery.resolve(path, item, retry, actor="admin", **options) == (digest, proof)
    if kind == "imessage_position":
        assert json.loads(path.read_bytes())["last_rowid"] == 9007199254740995
    item.update(state="resolved", safe_source={"kind": "file_sha256", "sha256": digest})
    assert controls.descriptor(marker, item, path, **options)["status"] == "recorded"
    assert controls.review_token(marker, item) == descriptor["review_token"]
    with pytest.raises(ValueError):
        controls.readback(marker, item, {"kind": "finish_recording", "receipt": "0" * 64}, descriptor["review_token"], path, **options)
    # No previously completed review may silently become a new observation.
    changed = controls.readback(marker, item, {**answers, "evidence_reference": "other-source-456"}, descriptor["review_token"], path, **options)
    with pytest.raises(ValueError):
        channel_recovery.resolve(path, item, changed, actor="admin", **options)


@pytest.mark.parametrize("change", [
    {"kind": "delivery_restart"}, {"execution": "unknown"}, {"execution": True},
    {"checked_at": "2026-09-27T12:00:00"}, {"checked_at": 1790524800},
    {"checked_at": "2026-02-31T12:00:00Z"}, {"evidence_reference": "\nsource-123"},
    {"chunks": {}}, {"checkpoint": {}}, {"binding_sha256": "0" * 64},
])
def test_typed_forms_refuse_ambiguous_coerced_or_extra_values_without_writes(tmp_path, change):
    root, path, item, marker, answers = setup_record(tmp_path, "message")
    original = path.read_bytes()
    with pytest.raises(ValueError):
        controls.readback(marker, item, {**answers, **change}, controls.review_token(marker, item), path,
                          decryptor=None, tenant="acme", workspace=root)
    assert path.read_bytes() == original


@pytest.mark.parametrize("key", ["bootstrap_id", "actor", "target", "restored_at"])
def test_binding_rejects_new_recovery_even_at_same_item_and_workspace(tmp_path, key):
    root, path, item, marker, answers = setup_record(tmp_path, "message")
    token = controls.review_token(marker, item)
    changed = {**marker, key: "changed"}
    with pytest.raises(ValueError, match="review changed"):
        controls.readback(changed, item, answers, token, path, decryptor=None, tenant="acme", workspace=root)


def test_interrupted_legacy_readback_keeps_exact_float_and_original_time(tmp_path):
    root, path, item, marker, answers = setup_record(tmp_path, "message")
    options = dict(decryptor=None, tenant="acme", workspace=root)
    token = controls.review_token(marker, item)
    readback = controls.readback(marker, item, answers, token, path, **options)
    readback["observed_at"] = time.time() + 0.0000002
    _, original_proof = channel_recovery.resolve(path, item, readback, actor="admin", **options)
    pending = controls.descriptor(marker, item, path, **options)
    result = controls.readback(marker, item, pending["retry_answers"], token, path, **options)
    assert result["observed_at"] == readback["observed_at"]
    assert channel_recovery._digest(result) == original_proof


def test_non_ascii_finish_receipt_is_refused_not_a_crash(tmp_path):
    # The receipt is a submitted form value; non-ASCII text must not raise
    # TypeError from hmac.compare_digest instead of the refusal below.
    root, path, item, marker, answers = setup_record(tmp_path, "message")
    options = dict(decryptor=None, tenant="acme", workspace=root)
    token = controls.review_token(marker, item)
    readback = controls.readback(marker, item, answers, token, path, **options)
    channel_recovery.resolve(path, item, readback, actor="admin", **options)
    with pytest.raises(ValueError, match="recorded review changed"):
        controls.readback(marker, item, {"kind": "finish_recording", "receipt": "é" * 64},
                          token, path, **options)


def test_source_mutation_and_known_delivery_erasure_are_refused(tmp_path):
    root, path, item, marker, answers = setup_record(tmp_path, "message")
    options = dict(decryptor=None, tenant="acme", workspace=root)
    token = controls.review_token(marker, item)
    changed = controls.readback(marker, item, {**answers, "execution": "absent", "delivery": "absent"}, token, path, **options)
    with pytest.raises(ValueError):
        channel_recovery.resolve(path, item, changed, actor="admin", **options)
    file_lock.atomic_write_bytes(path, path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="changed"):
        controls.descriptor(marker, item, path, **options)


@pytest.mark.parametrize("malformed", [["reply"], {"reply": []}])
def test_damaged_interrupted_record_is_unavailable_to_old_form_and_saved_retry(tmp_path, malformed):
    root, path, item, marker, answers = setup_record(tmp_path, "message")
    options = dict(decryptor=None, tenant="acme", workspace=root)
    token = controls.review_token(marker, item)
    readback = controls.readback(marker, item, answers, token, path, **options)
    _, proof = channel_recovery.resolve(path, item, readback, actor="admin", **options)
    record = json.loads(path.read_bytes())
    record["chunks"] = malformed
    file_lock.atomic_write_bytes(path, json.dumps(record).encode())
    original = path.read_bytes()
    with pytest.raises(ValueError):
        controls.descriptor(marker, item, path, **options)
    for submitted in (answers, {"kind": "finish_recording", "receipt": proof}):
        with pytest.raises(ValueError):
            controls.readback(marker, item, submitted, token, path, **options)
    assert path.read_bytes() == original
