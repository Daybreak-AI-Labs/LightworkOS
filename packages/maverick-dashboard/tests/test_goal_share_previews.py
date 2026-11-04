"""Faults after dispatch preserve uncertainty and cannot blindly resend."""
import hashlib
import json
import time
from contextlib import nullcontext

import pytest
from maverick_dashboard import goal_share_previews as shares


@pytest.fixture
def prepared(monkeypatch, tmp_path):
    payload = {"public": False, "files": {"task.json": {"content": "reviewed bytes"}}}
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    record = {"context": "context", "goal_id": 7, "created_at": time.time(), "state": "prepared",
              "payload": payload, "sha256": digest, "token_hash": hashlib.sha256(b"test-token").hexdigest()}
    monkeypatch.setattr(shares, "_directory", lambda context: tmp_path)
    monkeypatch.setattr(shares, "_read", lambda path: dict(record))
    monkeypatch.setattr(shares, "_write", lambda path, value: record.update(value))
    monkeypatch.setattr(shares, "cross_process_lock", lambda *args, **kwargs: nullcontext())
    monkeypatch.setattr(shares, "resolve_token", lambda: "test-token")
    from maverick import audit

    monkeypatch.setattr(audit, "audit_event", lambda *args, **kwargs: True)
    return record, digest


def test_lost_provider_response_is_unknown_and_repeat_does_not_send(prepared, monkeypatch):
    record, digest = prepared
    calls = []

    def accepted_then_disconnected(payload, token):
        assert record["state"] == "dispatching"
        calls.append(payload)
        raise TimeoutError("response lost after remote acceptance")

    monkeypatch.setattr(shares, "upload_payload", accepted_then_disconnected)
    result = shares.send("context", 7, "a" * 32, digest)
    assert result["outcome"] == "unknown"
    assert "may already" in result["message"]
    assert shares.send("context", 7, "a" * 32, digest)["outcome"] == "unknown"
    assert len(calls) == 1


def test_changed_connection_refuses_before_dispatch(prepared, monkeypatch):
    _, digest = prepared
    monkeypatch.setattr(shares, "resolve_token", lambda: "different-test-token")
    monkeypatch.setattr(shares, "upload_payload", lambda *args: pytest.fail("must not disclose"))
    with pytest.raises(ValueError, match="connection changed"):
        shares.send("context", 7, "a" * 32, digest)


def test_completed_attempt_replays_same_receipt(prepared, monkeypatch):
    record, digest = prepared
    monkeypatch.setattr(shares, "upload_payload", lambda *args: "https://gist.github.com/test/one")
    first = shares.send("context", 7, "a" * 32, digest)
    monkeypatch.setattr(shares, "upload_payload", lambda *args: pytest.fail("must not resend"))
    assert shares.send("context", 7, "a" * 32, digest) == first
    assert record["state"] == "shared"


def test_review_digest_cannot_be_replaced(prepared, monkeypatch):
    record, digest = prepared
    record["payload"]["files"]["task.json"]["content"] = "unreviewed text"
    monkeypatch.setattr(shares, "upload_payload", lambda *args: pytest.fail("must not disclose"))
    with pytest.raises(ValueError, match="fingerprint"):
        shares.send("context", 7, "a" * 32, digest)


def test_rejected_attempt_cannot_be_resent_without_a_new_review(prepared, monkeypatch):
    record, digest = prepared
    record["state"] = "rejected"
    monkeypatch.setattr(shares, "upload_payload", lambda *args: pytest.fail("must not resend"))
    assert shares.send("context", 7, "a" * 32, digest)["outcome"] == "rejected"
