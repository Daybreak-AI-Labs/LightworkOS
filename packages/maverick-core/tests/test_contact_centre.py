"""Outside contact centre handoff: Zendesk tickets or a signed webhook.

Every outbound request is a fake here. The fake receives the exact URL, headers
and body the real transport would send, so no test needs a network or a key.
"""
from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from maverick import audit as audit_package
from maverick import config, contact_centre, webhook_subscriptions, webhooks
from maverick.audit.errors import AuditRefused

ZENDESK_TOKEN = "tok-SECRET-12345"  # pragma: allowlist secret
WEBHOOK_SECRET = "whsec-test-secret-value"  # pragma: allowlist secret
HANDOFF = "handoff-test-0123456789abcdef"
REAL_START = contact_centre._start
REAL_AUDIT_EVENT = audit_package.audit_event
MAX = webhook_subscriptions.MAX_ATTEMPTS

ZENDESK_CONFIG = f"""
[contact_centre]
provider = "zendesk"
zendesk_subdomain = "acme-support"
zendesk_email = "agent@acme.example"
zendesk_api_token = "{ZENDESK_TOKEN}"
dashboard_url = "https://lightwork.acme.example"
"""

WEBHOOK_CONFIG = f"""
[contact_centre]
provider = "webhook"
webhook_url = "https://hooks.acme.example/lightwork"
webhook_secret = "{WEBHOOK_SECRET}"
dashboard_url = "https://lightwork.acme.example"
"""


def _deliver_now(key):
    """The synchronous stand-in for ``_start``: deliver in this thread and report that a delivery started."""
    contact_centre.run_delivery(key)
    return True


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_CONTACT_CENTRE_ZENDESK_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_CONTACT_CENTRE_WEBHOOK_SECRET", raising=False)
    from maverick import audit
    monkeypatch.setattr(audit, "audit_event", lambda *a, **k: True)
    monkeypatch.setattr(contact_centre, "_sleep", lambda seconds: None)
    monkeypatch.setattr(contact_centre, "retry_delay", lambda attempts: 10.0)
    # Deliver synchronously in tests; one test restores the real background start.
    monkeypatch.setattr(contact_centre, "_start", _deliver_now)
    config.reset_config_cache()


def _configure(tmp_path: Path, body: str) -> None:
    (tmp_path / "config.toml").write_text(body, encoding="utf-8")
    config.reset_config_cache()


class Receiver:
    """A fake receiving system: a queue of results and a record of each request."""

    def __init__(self, *results):
        self.results = list(results)
        self.calls: list[tuple[str, bytes, dict]] = []

    def __call__(self, url, body, headers):
        self.calls.append((url, body, dict(headers)))
        return self.results.pop(0) if len(self.results) > 1 else self.results[0]


CREATED = (201, 9, '{"ticket":{"url":"https://acme-support.zendesk.com/api/v2/tickets/4242.json","id":4242}}', "")
REJECTED_AUTH = (401, 5, '{"error":"Couldn\'t authenticate you"}', "HTTP 401")
NOT_CONNECTED = (None, 3, "", webhooks.NotSent("could not connect"))
BUSY = (429, 5, "", "HTTP 429")


def _enqueue(messages=None, **overrides):
    if messages is None:
        messages = [("user", "My card was declined"), ("assistant", "I can help with that")]
    values = {
        "handoff_id": HANDOFF, "title": "Card declined", "reason": "Customer asked for a person",
        "requester_name": "Ana Ruiz", "requester_email": "ana@example.com", "messages": messages,
        "link": "https://lightwork.acme.example/conversations?goal=7",
    }
    values.update(overrides)
    if contact_centre.enqueue_handoff(**values) is None:
        return None
    return contact_centre.status_for(HANDOFF)


def _write_state(key: str, **fields) -> None:
    """Store one outbox entry as an earlier process would have left it."""
    with contact_centre._locked(create=True) as path:
        data = contact_centre._load(path)
        data[key] = {"key": key, "provider": "zendesk", "state": "sending", "attempts": 0,
                     "destination": "https://acme-support.zendesk.com/api/v2/tickets.json",
                     "next_attempt_at": 0.0, "reason": "", "ticket_id": "", "payload": {},
                     "created_at": 0.0, "updated_at": 0.0, **fields}
        contact_centre._save(path, data)


def _outbox_files(tmp_path: Path) -> list[Path]:
    return sorted(tmp_path.rglob("outbox.sealed"))


# ------------------------------------------------------------ off and configuration
def test_off_by_default_sends_nothing_and_keeps_no_outbox(tmp_path, monkeypatch):
    receiver = Receiver(CREATED)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    assert config.get_contact_centre()["provider"] == "off"
    assert _enqueue() is None
    assert receiver.calls == []
    assert _outbox_files(tmp_path) == []
    assert contact_centre.status_for(HANDOFF) is None


def test_unknown_provider_fails_closed_to_off(tmp_path):
    _configure(tmp_path, '[contact_centre]\nprovider = "salesforce"\n')
    assert config.get_contact_centre()["provider"] == "off"


@pytest.mark.parametrize("value,accepted", [
    ("acme", True), ("acme-support-1", True), ("a" * 63, True),
    ("Acme", False), ("-acme", False), ("acme.evil.com", False), ("a" * 64, False), ("acme/x", False),
])
def test_zendesk_subdomain_must_match_the_documented_shape(tmp_path, value, accepted):
    _configure(tmp_path, f'[contact_centre]\nprovider = "zendesk"\nzendesk_subdomain = "{value}"\n')
    expected = value if accepted else ""
    assert config.get_contact_centre()["zendesk_subdomain"] == expected


def test_webhook_address_must_be_https_without_credentials(tmp_path):
    _configure(tmp_path, '[contact_centre]\nprovider = "webhook"\nwebhook_url = "http://hooks.acme.example/x"\n')
    assert config.get_contact_centre()["webhook_url"] == ""
    _configure(tmp_path, '[contact_centre]\nprovider = "webhook"\nwebhook_url = "https://u:p@hooks.acme.example/x"\n')
    assert config.get_contact_centre()["webhook_url"] == ""
    _configure(tmp_path, '[contact_centre]\nprovider = "webhook"\nwebhook_url = "https://hooks.acme.example/x"\n')
    assert config.get_contact_centre()["webhook_url"] == "https://hooks.acme.example/x"


@pytest.mark.parametrize("address", [
    "https://hooks.acme.example:8443/lightwork", "https://hooks.acme.example:443/lightwork",
])
def test_webhook_address_accepts_any_secure_port(tmp_path, address):
    _configure(tmp_path, f'[contact_centre]\nprovider = "webhook"\nwebhook_url = "{address}"\n')
    assert config.get_contact_centre()["webhook_url"] == address


def test_webhook_address_with_an_invalid_port_reads_as_empty(tmp_path):
    _configure(tmp_path, '[contact_centre]\nprovider = "webhook"\nwebhook_url = "https://hooks.acme.example:99999/x"\n')
    assert config.get_contact_centre()["webhook_url"] == ""


def test_a_missing_token_waits_for_settings_and_sends_nothing(tmp_path, monkeypatch):
    _configure(tmp_path, '[contact_centre]\nprovider = "zendesk"\nzendesk_subdomain = "acme-support"\n'
                         'zendesk_email = "agent@acme.example"\n')
    receiver = Receiver(CREATED)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    status = _enqueue()
    assert status["state"] == "waiting" and status["label"] == "Waiting for Settings"
    assert "API token" in status["reason"]
    assert receiver.calls == []


def test_a_missing_subdomain_is_a_final_failure_that_sends_nothing(tmp_path, monkeypatch):
    _configure(tmp_path, '[contact_centre]\nprovider = "zendesk"\nzendesk_email = "agent@acme.example"\n')
    monkeypatch.setenv("MAVERICK_CONTACT_CENTRE_ZENDESK_TOKEN", ZENDESK_TOKEN)
    receiver = Receiver(CREATED)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    status = _enqueue()
    assert status["state"] == "failed"
    assert "subdomain" in status["reason"] and "Nothing was sent" in status["reason"]
    assert receiver.calls == []


def test_a_handoff_waiting_for_a_token_is_sent_once_the_token_is_set(tmp_path, monkeypatch):
    _configure(tmp_path, '[contact_centre]\nprovider = "zendesk"\nzendesk_subdomain = "acme-support"\n'
                         'zendesk_email = "agent@acme.example"\n')
    receiver = Receiver(CREATED)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    assert _enqueue()["state"] == "waiting"
    monkeypatch.setenv("MAVERICK_CONTACT_CENTRE_ZENDESK_TOKEN", ZENDESK_TOKEN)
    assert contact_centre.resume_pending() == 1
    status = contact_centre.status_for(HANDOFF)
    assert status["state"] == "sent" and status["ticket_id"] == "4242"
    assert len(receiver.calls) == 1


def test_a_waiting_handoff_is_not_sent_to_an_address_changed_after_it_was_queued(tmp_path, monkeypatch):
    _configure(tmp_path, '[contact_centre]\nprovider = "webhook"\nwebhook_url = "https://hooks.acme.example/one"\n')
    receiver = Receiver((200, 4, "ok", ""))
    monkeypatch.setattr(contact_centre, "_post", receiver)
    assert _enqueue()["state"] == "waiting"  # no signing secret yet
    _configure(tmp_path, '[contact_centre]\nprovider = "webhook"\nwebhook_url = "https://hooks.other.example/two"\n')
    monkeypatch.setenv("MAVERICK_CONTACT_CENTRE_WEBHOOK_SECRET", WEBHOOK_SECRET)
    assert contact_centre.resume_pending() == 1
    status = contact_centre.status_for(HANDOFF)
    assert status["state"] == "failed" and "changed" in status["reason"]
    assert receiver.calls == []


# ------------------------------------------------------------ Zendesk request
def test_zendesk_ticket_request_url_headers_and_payload(tmp_path, monkeypatch):
    _configure(tmp_path, ZENDESK_CONFIG)
    receiver = Receiver(CREATED)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    status = _enqueue()
    assert len(receiver.calls) == 1
    url, body, headers = receiver.calls[0]
    assert url == "https://acme-support.zendesk.com/api/v2/tickets.json"
    expected = base64.b64encode(f"agent@acme.example/token:{ZENDESK_TOKEN}".encode()).decode()
    assert headers["Authorization"] == "Basic " + expected
    assert headers["Content-Type"] == "application/json"
    ticket = json.loads(body)["ticket"]
    assert ticket["subject"] == "Card declined"
    assert "Customer asked for a person" in ticket["comment"]["body"]
    assert "My card was declined" in ticket["comment"]["body"]
    assert "https://lightwork.acme.example/conversations?goal=7" in ticket["comment"]["body"]
    assert ticket["tags"] == ["lightwork"]
    assert ticket["external_id"] == "handoff:" + HANDOFF
    assert ticket["requester"] == {"name": "Ana Ruiz", "email": "ana@example.com"}
    assert ZENDESK_TOKEN.encode() not in body
    assert status["state"] == "sent" and status["ticket_id"] == "4242"


def test_zendesk_requester_is_omitted_when_no_email_is_known(tmp_path, monkeypatch):
    _configure(tmp_path, ZENDESK_CONFIG)
    receiver = Receiver(CREATED)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    _enqueue(requester_email="")
    assert "requester" not in json.loads(receiver.calls[0][1])["ticket"]


def test_an_email_shaped_requester_is_sent_as_the_email_not_redacted(tmp_path, monkeypatch):
    _configure(tmp_path, ZENDESK_CONFIG)
    receiver = Receiver(CREATED)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    _enqueue(requester_name="ana@example.com", requester_email="ana@example.com")
    body = receiver.calls[0][1].decode("utf-8")
    ticket = json.loads(body)["ticket"]
    assert ticket["requester"] == {"name": "ana@example.com", "email": "ana@example.com"}
    assert "Customer: ana@example.com" in ticket["comment"]["body"]
    assert "[REDACTED" not in body


def test_only_the_last_configured_messages_are_sent_and_each_is_truncated(tmp_path, monkeypatch):
    _configure(tmp_path, ZENDESK_CONFIG.replace('dashboard_url', 'max_messages = 3\ndashboard_url'))
    receiver = Receiver(CREATED)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    messages = [("user", "first message"), ("user", "second message"), ("assistant", "third message"),
                ("user", "fourth message"), ("user", "x" * 5000)]
    _enqueue(messages=messages)
    comment = json.loads(receiver.calls[0][1])["ticket"]["comment"]["body"]
    assert "first message" not in comment and "second message" not in comment
    assert "third message" in comment and "fourth message" in comment
    assert "x" * 2000 in comment and "x" * 2001 not in comment


def test_personal_data_and_secrets_in_messages_are_redacted_before_sending(tmp_path, monkeypatch):
    _configure(tmp_path, ZENDESK_CONFIG)
    receiver = Receiver(CREATED)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    _enqueue(messages=[("user", "email jane.doe@example.org and key AKIAIOSFODNN7EXAMPLE")])  # pragma: allowlist secret
    comment = json.loads(receiver.calls[0][1])["ticket"]["comment"]["body"]
    assert "jane.doe@example.org" not in comment
    assert "AKIAIOSFODNN7EXAMPLE" not in comment  # pragma: allowlist secret


# ------------------------------------------------------------ signed webhook
def test_webhook_is_signed_with_the_repo_scheme_and_verifies(tmp_path, monkeypatch):
    _configure(tmp_path, WEBHOOK_CONFIG)
    receiver = Receiver((200, 4, "ok", ""))
    monkeypatch.setattr(contact_centre, "_post", receiver)
    status = _enqueue()
    url, body, headers = receiver.calls[0]
    assert url == "https://hooks.acme.example/lightwork"
    timestamp = headers["X-Lightwork-Timestamp"]
    signature = headers["X-Lightwork-Signature"]
    assert webhooks.verify_signature(body, signature, WEBHOOK_SECRET, timestamp=timestamp, max_age=300)
    assert not webhooks.verify_signature(body + b" ", signature, WEBHOOK_SECRET, timestamp=timestamp, max_age=300)
    assert not webhooks.verify_signature(body, signature, "another-secret", timestamp=timestamp, max_age=300)
    envelope = json.loads(body)
    assert envelope["event"] == "contact_centre.handoff"
    assert envelope["payload"]["reason"] == "Customer asked for a person"
    assert headers["X-Lightwork-Delivery"] == "cc_" + hashlib.sha256(("handoff:" + HANDOFF).encode()).hexdigest()[:32]
    assert WEBHOOK_SECRET.encode() not in body
    assert status["state"] == "sent"


def test_webhook_without_a_signing_secret_is_never_sent_unsigned(tmp_path, monkeypatch):
    _configure(tmp_path, '[contact_centre]\nprovider = "webhook"\nwebhook_url = "https://hooks.acme.example/x"\n')
    receiver = Receiver((200, 4, "ok", ""))
    monkeypatch.setattr(contact_centre, "_post", receiver)
    assert _enqueue()["state"] == "waiting"
    assert receiver.calls == []


def test_environment_secret_wins_over_the_saved_value(tmp_path, monkeypatch):
    _configure(tmp_path, ZENDESK_CONFIG)
    monkeypatch.setenv("MAVERICK_CONTACT_CENTRE_ZENDESK_TOKEN", "tok-FROM-ENV")  # pragma: allowlist secret
    receiver = Receiver(CREATED)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    _enqueue()
    expected = base64.b64encode(b"agent@acme.example/token:tok-FROM-ENV").decode()
    assert receiver.calls[0][2]["Authorization"] == "Basic " + expected


# ------------------------------------------------------------ retries and idempotency
def test_retries_back_off_then_one_ticket_is_never_duplicated(tmp_path, monkeypatch):
    _configure(tmp_path, ZENDESK_CONFIG)
    sleeps: list[float] = []
    monkeypatch.setattr(contact_centre, "_sleep", sleeps.append)
    monkeypatch.setattr(contact_centre, "retry_delay", lambda attempts: 10.0 * attempts)
    receiver = Receiver(NOT_CONNECTED, BUSY, CREATED)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    status = _enqueue()
    assert len(receiver.calls) == 3
    assert sleeps == [10.0, 20.0]
    assert status["state"] == "sent" and status["ticket_id"] == "4242"
    again = _enqueue()
    assert again["state"] == "sent"
    assert len(receiver.calls) == 3


def test_a_send_that_may_have_arrived_is_not_repeated(tmp_path, monkeypatch):
    _configure(tmp_path, ZENDESK_CONFIG)
    receiver = Receiver((None, 30, "", "ReadTimeout: timed out"), CREATED)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    status = _enqueue()
    assert status["state"] == "unknown"
    assert "not sent again" in status["reason"]
    assert len(receiver.calls) == 1
    contact_centre.run_delivery("handoff:" + HANDOFF)
    assert len(receiver.calls) == 1


def test_a_webhook_server_error_is_not_confirmed_and_never_repeated(tmp_path, monkeypatch):
    _configure(tmp_path, WEBHOOK_CONFIG)
    receiver = Receiver((503, 4, "busy", "HTTP 503"), (200, 4, "ok", ""))
    monkeypatch.setattr(contact_centre, "_post", receiver)
    status = _enqueue()
    assert status["state"] == "unknown"
    assert "not sent again" in status["reason"]
    assert len(receiver.calls) == 1
    contact_centre.run_delivery("handoff:" + HANDOFF)
    assert len(receiver.calls) == 1


def test_a_retried_webhook_keeps_its_delivery_id_and_signs_each_attempt(tmp_path, monkeypatch):
    _configure(tmp_path, WEBHOOK_CONFIG)
    receiver = Receiver(BUSY, (200, 4, "ok", ""))
    monkeypatch.setattr(contact_centre, "_post", receiver)
    status = _enqueue()
    assert status["state"] == "sent" and len(receiver.calls) == 2
    deliveries = {headers["X-Lightwork-Delivery"] for _url, _body, headers in receiver.calls}
    assert len(deliveries) == 1
    for _url, body, headers in receiver.calls:
        assert webhooks.verify_signature(body, headers["X-Lightwork-Signature"], WEBHOOK_SECRET,
                                         timestamp=headers["X-Lightwork-Timestamp"], max_age=300)


def test_rejected_credentials_fail_plainly_without_retry_or_leaking_the_token(tmp_path, monkeypatch, caplog):
    _configure(tmp_path, ZENDESK_CONFIG)
    receiver = Receiver(REJECTED_AUTH)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    with caplog.at_level("DEBUG"):
        status = _enqueue()
    assert status["state"] == "failed"
    assert "email or API token" in status["reason"]
    assert len(receiver.calls) == 1
    assert ZENDESK_TOKEN not in json.dumps(status)
    assert ZENDESK_TOKEN not in caplog.text


def test_exhausted_retries_end_as_failed_with_bounded_attempts(tmp_path, monkeypatch):
    _configure(tmp_path, ZENDESK_CONFIG)
    receiver = Receiver(NOT_CONNECTED)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    status = _enqueue()
    assert status["state"] == "failed"
    assert f"after {MAX} tries" in status["reason"]
    assert len(receiver.calls) == MAX


def test_address_guard_refusals_are_permanent_not_retried():
    outcome, reason, _ticket = contact_centre._classify(
        "zendesk", None, webhooks.NotSent("blocked by the address guard: private address"), "")
    assert outcome == "failed" and "address check" in reason
    outcome, _reason, _ticket = contact_centre._classify("zendesk", None, NOT_CONNECTED[3], "")
    assert outcome == "retry"


def test_default_transport_goes_through_the_address_guard_without_a_network_call():
    status, _latency, _snippet, error = contact_centre._post("https://127.0.0.1/hook", b"{}", {})
    assert status is None
    assert str(error).startswith("blocked")


def test_enterprise_egress_lock_blocks_the_send(tmp_path, monkeypatch):
    _configure(tmp_path, ZENDESK_CONFIG)
    from maverick import enterprise
    monkeypatch.setattr(enterprise, "enterprise_egress_denial", lambda url, tool="": "blocked by policy")
    receiver = Receiver(CREATED)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    assert _enqueue()["state"] == "failed"
    assert receiver.calls == []


# ------------------------------------------------------------ audit refusal stops the send
def _refuse_audit_records(monkeypatch):
    """The real audit_event runs; only its low-level record() is refused, as a compliance profile would."""
    def refuse(*args, **kwargs):
        raise AuditRefused("the compliance profile requires a signed audit log")
    monkeypatch.setattr(audit_package, "audit_event", REAL_AUDIT_EVENT)
    monkeypatch.setattr(audit_package, "record", refuse)


def test_an_audit_refusal_stops_the_handoff_before_anything_is_queued_or_sent(tmp_path, monkeypatch):
    _configure(tmp_path, ZENDESK_CONFIG)
    receiver = Receiver(CREATED)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    _refuse_audit_records(monkeypatch)
    with pytest.raises(AuditRefused):
        _enqueue()
    assert receiver.calls == []
    assert contact_centre.status_for(HANDOFF) is None


def test_an_audit_refusal_before_the_send_marks_it_failed_and_sends_nothing(tmp_path, monkeypatch):
    _configure(tmp_path, ZENDESK_CONFIG)
    receiver = Receiver(CREATED)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    monkeypatch.setattr(contact_centre, "_start", lambda key: None)  # queue it without delivering
    assert _enqueue()["state"] == "queued"
    _refuse_audit_records(monkeypatch)
    contact_centre.run_delivery("handoff:" + HANDOFF)
    assert receiver.calls == []
    status = contact_centre.status_for(HANDOFF)
    assert status["state"] == "failed"
    assert "audit log refused" in status["reason"]


def test_a_refused_record_of_a_completed_send_does_not_undo_the_send(tmp_path, monkeypatch):
    _configure(tmp_path, ZENDESK_CONFIG)
    receiver = Receiver(CREATED)

    def post_then_refuse(url, body, headers):
        result = receiver(url, body, headers)
        _refuse_audit_records(monkeypatch)  # the record of the outcome is refused after the send
        return result

    monkeypatch.setattr(contact_centre, "_post", post_then_refuse)
    status = _enqueue()
    assert status["state"] == "sent" and status["ticket_id"] == "4242"
    assert len(receiver.calls) == 1


# ------------------------------------------------------------ background, recovery, tenancy
def test_enqueue_returns_before_the_background_send_finishes(tmp_path, monkeypatch):
    _configure(tmp_path, ZENDESK_CONFIG)
    entered, gate = threading.Event(), threading.Event()

    def slow(url, body, headers):
        entered.set()
        gate.wait(5)
        return CREATED

    monkeypatch.setattr(contact_centre, "_post", slow)
    monkeypatch.setattr(contact_centre, "_start", REAL_START)
    first = contact_centre.enqueue_handoff(
        handoff_id=HANDOFF, title="Card declined", reason="Customer asked for a person",
        requester_name="Ana Ruiz", requester_email="ana@example.com",
        messages=[("user", "My card was declined")], link="")
    assert first["state"] == "queued"
    assert entered.wait(5)
    gate.set()
    deadline = time.time() + 5
    while time.time() < deadline:
        current = contact_centre.status_for(HANDOFF)
        if current and current["state"] == "sent":
            break
        time.sleep(0.02)
    assert contact_centre.status_for(HANDOFF)["state"] == "sent"


def test_interrupted_send_is_marked_unknown_on_resume_and_never_resent(tmp_path, monkeypatch):
    _configure(tmp_path, ZENDESK_CONFIG)
    receiver = Receiver(CREATED)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    _write_state("handoff:" + HANDOFF, state="sending", attempts=1)
    contact_centre.resume_pending()
    assert contact_centre.status_for(HANDOFF)["state"] == "unknown"
    assert receiver.calls == []


def test_restart_resumes_interrupted_handoffs_in_every_active_workspace(tmp_path, monkeypatch):
    from maverick.paths import reset_tenant, set_tenant
    from maverick.tenant import registry
    _configure(tmp_path, ZENDESK_CONFIG)
    monkeypatch.setattr(registry, "list_tenants", lambda: [SimpleNamespace(id="acme", active=True),
                                                           SimpleNamespace(id="retired", active=False)])
    token = set_tenant("acme")
    try:
        _write_state("handoff:" + HANDOFF, state="sending", attempts=1)
    finally:
        reset_tenant(token)
    receiver = Receiver(CREATED)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    assert contact_centre.resume_all_workspaces() == 0
    token = set_tenant("acme")
    try:
        assert contact_centre.status_for(HANDOFF)["state"] == "unknown"
    finally:
        reset_tenant(token)
    assert receiver.calls == []


def test_outbox_is_scoped_to_the_workspace(tmp_path, monkeypatch):
    _configure(tmp_path, ZENDESK_CONFIG)
    receiver = Receiver(CREATED)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    assert _enqueue()["state"] == "sent"
    assert [p for p in _outbox_files(tmp_path) if "acme" in str(p)]
    monkeypatch.setenv("MAVERICK_TENANT", "globex")
    assert contact_centre.status_for(HANDOFF) is None
    assert not [p for p in _outbox_files(tmp_path) if "globex" in str(p)]
    assert _enqueue()["state"] == "sent"
    assert len(receiver.calls) == 2  # the other workspace gets its own ticket, not the acme one


def test_status_and_stored_outbox_never_hold_the_token_or_destination_secret(tmp_path, monkeypatch):
    _configure(tmp_path, ZENDESK_CONFIG)
    receiver = Receiver(REJECTED_AUTH)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    _enqueue()
    status = contact_centre.status_for(HANDOFF)
    assert set(status) <= {"provider", "state", "label", "reason", "ticket_id", "updated_at"}
    for path in _outbox_files(tmp_path):
        assert ZENDESK_TOKEN.encode() not in path.read_bytes()


def test_conversation_link_opens_the_conversation_page_that_shows_the_handoff(tmp_path):
    _configure(tmp_path, ZENDESK_CONFIG)
    assert contact_centre.conversation_link(7) == "https://lightwork.acme.example/chat/goal/7"
    _configure(tmp_path, '[contact_centre]\nprovider = "zendesk"\n')
    assert contact_centre.conversation_link(7) == ""


# ------------------------------------------------------------ status that always reads
def _conversation_source(handoff_id=HANDOFF, actor="ana@example.com"):
    """A HumanConversations whose stored records are stubbed, so state() reads only the outbox for real."""
    from maverick.human_conversation_handoffs import HumanConversations
    session = {"id": handoff_id, "state": "waiting", "recipient": "agent@acme.example", "goal_id": 7,
               "owner": actor, "purpose": "Need a person", "expires_at": 0, "shared": {"title": "Card declined"},
               "source": "v1", "tasks": [], "messages": [], "duty_label": "Agent"}
    human = {"current": handoff_id, "sessions": {handoff_id: session}, "operations": {}}
    goal = SimpleNamespace(id=7, owner=actor, title="Card declined")
    root = SimpleNamespace(id=7, owner=actor)
    source = HumanConversations.__new__(HumanConversations)
    source.world, source.actor, source.metadata_only = object(), actor, False
    source.authorize = lambda goal, session, write: None
    source._load = lambda goal_id: (goal, root, None, {"revision": 1}, {}, human)
    source._authorized = lambda goal, root, human, write=False: session
    return source


def test_an_unreadable_outbox_never_breaks_the_conversation_status(tmp_path, monkeypatch):
    _configure(tmp_path, ZENDESK_CONFIG)
    receiver = Receiver(CREATED)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    assert _enqueue()["state"] == "sent"
    for path in _outbox_files(tmp_path):
        path.write_bytes(b"not sealed")
    status = contact_centre.status_for(HANDOFF)
    assert status["state"] == "unavailable" and status["label"] == "Status unavailable"
    assert "not affected" in status["reason"]
    view = _conversation_source().state(7)
    assert view["session"]["state"] == "waiting"
    assert view["contact_centre"]["state"] == "unavailable"
    assert len(receiver.calls) == 1


def test_a_handoff_whose_queueing_failed_is_shown_as_not_queued(tmp_path, monkeypatch):
    from maverick.chat_threads import ChatThreads
    _configure(tmp_path, ZENDESK_CONFIG)

    def full(**kwargs):
        raise contact_centre.OutboxFull("full")

    monkeypatch.setattr(contact_centre, "enqueue_handoff", full)
    monkeypatch.setattr(ChatThreads, "__init__", lambda self, world: None)
    monkeypatch.setattr(ChatThreads, "history", lambda self, goal_id, **kwargs: ([], False))
    source = _conversation_source()
    source._contact_centre_handoff({"shared": {"title": "Card declined"}, "purpose": "Need a person"},
                                   SimpleNamespace(id=7, title="Card declined"), HANDOFF)
    view = source.state(7)
    assert view["contact_centre"]["state"] == "not_recorded"
    assert view["contact_centre"]["label"] == "Not queued"
    assert "not affected" in view["contact_centre"]["reason"]


def test_no_status_row_is_shown_when_no_provider_is_set(tmp_path):
    _configure(tmp_path, "")
    assert _conversation_source().state(7)["contact_centre"] is None


def test_a_result_that_cannot_be_saved_is_shown_as_not_confirmed_not_as_sending(tmp_path, monkeypatch):
    _configure(tmp_path, ZENDESK_CONFIG)
    receiver = Receiver(CREATED)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    real_save, saves = contact_centre._save, []

    def failing_result_save(path, data):
        saves.append(1)
        if len(saves) == 3:  # 1: queued, 2: sending, 3: the result of the send
            raise OSError("disk full")
        return real_save(path, data)

    monkeypatch.setattr(contact_centre, "_save", failing_result_save)
    status = _enqueue()
    assert status["state"] == "unknown"
    assert "not sent again" in status["reason"]
    assert len(receiver.calls) == 1


def test_a_send_that_cannot_be_recorded_before_it_starts_is_not_sent(tmp_path, monkeypatch):
    _configure(tmp_path, ZENDESK_CONFIG)
    receiver = Receiver(CREATED)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    real_save, saves = contact_centre._save, []

    def failing_start_save(path, data):
        saves.append(1)
        if len(saves) == 2:  # the 'sending' record
            raise OSError("disk full")
        return real_save(path, data)

    monkeypatch.setattr(contact_centre, "_save", failing_start_save)
    status = _enqueue()
    assert status["state"] == "failed"
    assert receiver.calls == []


def test_a_send_that_stops_while_it_is_prepared_is_not_confirmed(tmp_path, monkeypatch):
    _configure(tmp_path, ZENDESK_CONFIG)
    receiver = Receiver(CREATED)
    monkeypatch.setattr(contact_centre, "_post", receiver)

    def broken(content, key):
        raise RuntimeError("prepared badly")

    monkeypatch.setattr(contact_centre, "_zendesk_body", broken)
    status = _enqueue()
    assert status["state"] == "unknown"
    assert receiver.calls == []


# ------------------------------------------------------------ the in-app handoff is not blocked
def test_queue_failure_never_blocks_the_in_app_handoff(tmp_path, monkeypatch, caplog):
    from maverick.chat_threads import ChatThreads
    from maverick.human_conversation_handoffs import HumanConversations

    def broken(**kwargs):
        raise RuntimeError("outbox unavailable")

    _configure(tmp_path, ZENDESK_CONFIG)
    monkeypatch.setattr(contact_centre, "enqueue_handoff", broken)
    monkeypatch.setattr(ChatThreads, "__init__", lambda self, world: None)
    monkeypatch.setattr(ChatThreads, "history", lambda self, goal_id, **kwargs: ([], False))
    source = HumanConversations.__new__(HumanConversations)
    source.world, source.actor = object(), "ana@example.com"
    goal = SimpleNamespace(id=7, title="Card declined")
    prepared = {"shared": {"title": "Card declined", "brief": "b", "saved_reply": ""}, "purpose": "Need a person"}
    with caplog.at_level("WARNING"):
        source._contact_centre_handoff(prepared, goal, "operation-session-id-0001")
    assert any("not queued" in record.getMessage() for record in caplog.records)
    assert "outbox unavailable" not in caplog.text  # only the exception type is logged


def test_the_handoff_passes_its_reviewed_title_reason_and_link_to_the_outbox(tmp_path, monkeypatch):
    from maverick.chat_threads import ChatThreads
    from maverick.human_conversation_handoffs import HumanConversations
    seen = {}
    _configure(tmp_path, ZENDESK_CONFIG)
    monkeypatch.setattr(contact_centre, "enqueue_handoff", lambda **kwargs: seen.update(kwargs) or {"state": "queued"})
    monkeypatch.setattr(ChatThreads, "__init__", lambda self, world: None)
    monkeypatch.setattr(ChatThreads, "history", lambda self, goal_id, **kwargs: ([SimpleNamespace(role="user", content="hi")], False))
    source = HumanConversations.__new__(HumanConversations)
    source.world, source.actor = object(), "ana@example.com"
    goal = SimpleNamespace(id=7, title="Card declined")
    prepared = {"shared": {"title": "Card declined", "brief": "b", "saved_reply": ""}, "purpose": "Need a person"}
    source._contact_centre_handoff(prepared, goal, "operation-session-id-0001")
    assert seen["handoff_id"] == "operation-session-id-0001"
    assert seen["title"] == "Card declined" and seen["reason"] == "Need a person"
    assert seen["requester_email"] == "ana@example.com"
    assert seen["messages"] == [("user", "hi")]
    assert seen["link"] == "https://lightwork.acme.example/chat/goal/7"


def test_a_settings_save_while_running_sends_a_waiting_handoff_without_a_restart(tmp_path, monkeypatch):
    from maverick.tenant import registry
    _configure(tmp_path, '[contact_centre]\nprovider = "zendesk"\nzendesk_subdomain = "acme-support"\n'
                         'zendesk_email = "agent@acme.example"\n')
    monkeypatch.setattr(registry, "list_tenants", list)
    receiver = Receiver(CREATED)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    monkeypatch.setattr(contact_centre, "_start", lambda key: None)  # queue it without delivering
    assert _enqueue()["state"] == "waiting"
    monkeypatch.setattr(contact_centre, "_start", _deliver_now)
    monkeypatch.setenv("MAVERICK_CONTACT_CENTRE_ZENDESK_TOKEN", ZENDESK_TOKEN)
    assert contact_centre.resume_all_workspaces(restarted=False) == 1
    status = contact_centre.status_for(HANDOFF)
    assert status["state"] == "sent" and status["ticket_id"] == "4242"
    assert len(receiver.calls) == 1


def test_a_settings_save_never_marks_a_send_in_flight_as_unconfirmed(tmp_path, monkeypatch):
    _configure(tmp_path, ZENDESK_CONFIG)
    receiver = Receiver(CREATED)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    _write_state("handoff:" + HANDOFF, state="sending", attempts=1)
    assert contact_centre.start_pending() == 0
    assert contact_centre.status_for(HANDOFF)["state"] == "sending"
    assert receiver.calls == []


def test_a_settings_save_starts_pending_handoffs_in_every_active_workspace(tmp_path, monkeypatch):
    from maverick.paths import reset_tenant, set_tenant
    from maverick.tenant import registry
    _configure(tmp_path, ZENDESK_CONFIG)
    monkeypatch.setattr(registry, "list_tenants", lambda: [SimpleNamespace(id="acme", active=True),
                                                           SimpleNamespace(id="retired", active=False)])
    receiver = Receiver(CREATED)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    monkeypatch.setattr(contact_centre, "_start", lambda key: None)  # queue it without delivering
    token = set_tenant("acme")
    try:
        assert _enqueue()["state"] == "queued"
    finally:
        reset_tenant(token)
    monkeypatch.setattr(contact_centre, "_start", _deliver_now)
    assert contact_centre.resume_all_workspaces(restarted=False) == 1
    token = set_tenant("acme")
    try:
        assert contact_centre.status_for(HANDOFF)["state"] == "sent"
    finally:
        reset_tenant(token)
    assert len(receiver.calls) == 1


def test_a_settings_save_during_a_waiting_attempt_is_checked_again_by_that_attempt(tmp_path, monkeypatch):
    _configure(tmp_path, ZENDESK_CONFIG.replace(f'zendesk_api_token = "{ZENDESK_TOKEN}"\n', ""))
    receiver = Receiver(CREATED)
    monkeypatch.setattr(contact_centre, "_post", receiver)
    monkeypatch.setattr(contact_centre, "_start", lambda key: False)  # queue it without delivering
    assert _enqueue()["state"] == "waiting"
    monkeypatch.setattr(contact_centre, "_start", REAL_START)
    real_run = contact_centre.run_delivery
    saved = []

    def run_then_save(key):
        real_run(key)  # the first attempt finds no token, records the wait and returns
        if not saved:
            # The token is saved while this thread still holds the handoff. The save must not be lost.
            monkeypatch.setenv("MAVERICK_CONTACT_CENTRE_ZENDESK_TOKEN", ZENDESK_TOKEN)
            saved.append(contact_centre.start_pending())

    monkeypatch.setattr(contact_centre, "run_delivery", run_then_save)
    REAL_START("handoff:" + HANDOFF)
    deadline = time.time() + 10
    while time.time() < deadline and contact_centre.status_for(HANDOFF)["state"] != "sent":
        time.sleep(0.01)
    assert saved == [0]  # the thread already held the handoff, so nothing new was started
    status = contact_centre.status_for(HANDOFF)
    assert status["state"] == "sent" and status["ticket_id"] == "4242"
    assert len(receiver.calls) == 1


def test_start_pending_counts_only_the_deliveries_it_starts(tmp_path, monkeypatch):
    _configure(tmp_path, ZENDESK_CONFIG)
    _write_state("handoff:" + HANDOFF, state="queued")
    monkeypatch.setattr(contact_centre, "_start", lambda key: False)  # a delivery thread already holds it
    assert contact_centre.start_pending() == 0
    monkeypatch.setattr(contact_centre, "_start", lambda key: True)
    assert contact_centre.start_pending() == 1


def test_a_delivery_that_stops_unexpectedly_frees_its_handoff(tmp_path, monkeypatch):
    _configure(tmp_path, ZENDESK_CONFIG)
    key = "handoff:" + HANDOFF

    def stop(_key):
        raise RuntimeError("stopped")

    monkeypatch.setattr(contact_centre, "run_delivery", stop)
    REAL_START(key)
    deadline = time.time() + 10
    while time.time() < deadline and key in contact_centre._active:
        time.sleep(0.01)
    assert key not in contact_centre._active
    assert key not in contact_centre._rescan

